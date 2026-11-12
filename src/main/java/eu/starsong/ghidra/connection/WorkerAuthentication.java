package eu.starsong.ghidra.connection;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import javax.security.auth.callback.ChoiceCallback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

/** Noninteractive native authentication. Secrets never enter a request or response object. */
public final class WorkerAuthentication {
    private static final ThreadLocal<Scope> ACTIVE = new ThreadLocal<>();
    private static final Map<String, String> BINDINGS = new HashMap<>();
    private static final java.util.Set<Scope> AUTH_SCOPES = new java.util.HashSet<>();
    private static Object authenticator;
    private static Method nativeGetAuthenticator;
    private static Method nativeSetAuthenticator;
    private static Method nativeGetUserName;
    private static String certificateStore;

    private WorkerAuthentication() {}

    public static <T> T call(Profile profile, Supplier<T> operation) {
        Scope previous = ACTIVE.get();
        if (previous != null && previous.profile.equals(profile)) return operation.get();
        var credentials = ConnectionProfiles.credentials(profile);
        Scope scope = new Scope(profile, credentials);
        ACTIVE.set(scope);
        try {
            if (!"none".equals(profile.auth())) {
                install();
                bind(scope);
                if ("pki".equals(profile.auth())) configureCertificate(scope);
                WorkerTLS.initialize();
                synchronized (AUTH_SCOPES) {
                    for (Scope other : AUTH_SCOPES) {
                        if ("ghidra".equals(profile.kind()) && "ghidra".equals(other.profile.kind())
                                && (!profile.auth().equals(other.profile.auth())
                                    || (URI.create(profile.endpoint()).getHost().equalsIgnoreCase(
                                            URI.create(other.profile.endpoint()).getHost())
                                        && !profile.credentialRef().equals(other.profile.credentialRef())))) {
                            throw new ConnectionException("CONNECTION_AUTH_REQUIRED", 409,
                                "Concurrent native authentication modes or identities require separate workers.");
                        }
                    }
                    AUTH_SCOPES.add(scope);
                }
            }
            return operation.get();
        } finally {
            synchronized (AUTH_SCOPES) {
                AUTH_SCOPES.remove(scope);
                credentials.close();
            }
            if (previous == null) ACTIVE.remove(); else ACTIVE.set(previous);
        }
    }

    /** Native pool identity includes the username, but never a password-bearing URL. */
    public static Object bsimServerInfo(Profile profile) {
        Scope scope = scope(profile);
        try {
            ClassLoader loader = WorkerAuthentication.class.getClassLoader();
            Class<?> info = Class.forName("ghidra.features.bsim.query.BSimServerInfo", true, loader);
            if ("h2".equals(profile.backend())) {
                return info.getConstructor(String.class).newInstance(profile.endpoint());
            }
            Class<?> type = Class.forName("ghidra.features.bsim.query.BSimServerInfo$DBType", true, loader);
            String name = "postgresql".equals(profile.backend()) ? "postgres" : "elastic";
            Object dbType = type.getField(name).get(null);
            URI uri = URI.create(profile.endpoint());
            return info.getConstructor(type, String.class, String.class, int.class, String.class)
                .newInstance(dbType, scope.credentials.username, uri.getHost(), uri.getPort(),
                    uri.getPath().substring(1));
        } catch (ReflectiveOperationException | IllegalArgumentException failed) {
            throw new ConnectionException("CONNECTION_FAILED", 503,
                "This Ghidra installation cannot construct the configured BSim client.");
        }
    }

    private static Scope scope(Profile profile) {
        Scope scope = ACTIVE.get();
        if (scope == null || !scope.profile.equals(profile)) throw new ConnectionException(
            "CONNECTION_AUTH_REQUIRED", 503, "The native operation has no worker authentication scope.");
        return scope;
    }

    public static void verifyRepositoryIdentity(Profile profile, String authenticatedUser) {
        if (!scope(profile).credentials.username.equals(authenticatedUser)) {
            throw new ConnectionException("CONNECTION_AUTH_FAILED", 401,
                "The native authenticated identity does not match the selected profile.");
        }
    }

    private static boolean mayUseDefaultUser(Scope scope) {
        try {
            return scope.credentials.username.equals(nativeGetUserName.invoke(null));
        } catch (ReflectiveOperationException failed) {
            return false;
        }
    }

    /** Native clients cache identities; changing one under a live checkout is not safe. */
    private static synchronized void bind(Scope scope) {
        URI uri = URI.create(scope.profile.endpoint());
        String key = scope.profile.kind() + ':' + uri.getHost() + ':' + effectivePort(uri);
        if ("postgresql".equals(scope.profile.backend())) {
            key += ':' + uri.getPath() + ':' + scope.credentials.username;
        }
        String previous = BINDINGS.get(key);
        if (previous == null && "ghidra".equals(scope.profile.kind())) {
            try {
                Class<?> client = Class.forName("ghidra.framework.client.ClientUtil");
                if (Boolean.TRUE.equals(client.getMethod("isConnected", String.class, int.class)
                        .invoke(null, uri.getHost(), effectivePort(uri)))) {
                    throw new ConnectionException("CONNECTION_AUTH_REQUIRED", 409,
                        "This Ghidra endpoint already has an unmanaged login. Use a dedicated worker.");
                }
            } catch (ReflectiveOperationException failed) {
                throw new ConnectionException("CONNECTION_FAILED", 503,
                    "This Ghidra installation has no compatible repository client.");
            }
        }
        if (previous == null) BINDINGS.put(key, scope.profile.credentialRef());
        if (previous != null && !previous.equals(scope.profile.credentialRef())) {
            throw new ConnectionException("CONNECTION_AUTH_REQUIRED", 409,
                "The native client already uses another credential for this endpoint. "
                    + "Use a separate worker identity, or restart the worker after credential rotation.");
        }
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() > 0) return uri.getPort();
        return switch (uri.getScheme()) {
            case "postgresql" -> 5432;
            case "elastic" -> 9200;
            case "https" -> 9200;
            case "ghidra" -> 13100;
            default -> -1;
        };
    }

    private static synchronized void install() {
        try {
            if (authenticator == null) {
                ClassLoader loader = WorkerAuthentication.class.getClassLoader();
                Class<?> api = Class.forName("ghidra.framework.client.ClientAuthenticator", true, loader);
                Class<?> client = Class.forName("ghidra.framework.client.ClientUtil", true, loader);
                nativeGetAuthenticator = client.getMethod("getClientAuthenticator");
                nativeSetAuthenticator = client.getMethod("setClientAuthenticator", api);
                nativeGetUserName = client.getMethod("getUserName");
                authenticator = Proxy.newProxyInstance(loader, new Class<?>[] { api },
                    (object, method, args) -> callback(object, method, args));
            }
            if (nativeGetAuthenticator.invoke(null) != authenticator) {
                nativeSetAuthenticator.invoke(null, authenticator);
            }
        } catch (ReflectiveOperationException | LinkageError failed) {
            throw new ConnectionException("CONNECTION_FAILED", 503,
                "This Ghidra installation has no compatible native authentication client.");
        }
    }

    private static Object callback(Object proxy, Method method, Object[] args) {
        // Ghidra GUI connections use a shared task pool. Leases are endpoint-bound,
        // temporary, and guarded through credential copying/removal; no thread inheritance.
        synchronized (AUTH_SCOPES) {
            Scope scope = ACTIVE.get();
            if (scope != null && !matchesCallback(scope, method.getName(), args)) scope = null;
            if (ACTIVE.get() == null) {
                for (Scope candidate : AUTH_SCOPES) {
                    if (!matchesCallback(candidate, method.getName(), args)) continue;
                    if (scope != null && !scope.profile.credentialRef().equals(candidate.profile.credentialRef())) {
                        return method.getReturnType() == boolean.class ? Boolean.FALSE : null;
                    }
                    scope = candidate;
                }
            }
            return dispatch(proxy, method, args, scope);
        }
    }

    private static boolean matchesCallback(Scope scope, String method, Object[] args) {
        String host = URI.create(scope.profile.endpoint()).getHost();
        return switch (method) {
            case "processPasswordCallbacks" -> {
                String server = String.valueOf(args[2]);
                if ("ghidra".equals(scope.profile.kind())) {
                    yield "Repository Server".equals(args[1]) && host.equalsIgnoreCase(server);
                }
                yield ACTIVE.get() == scope && bsimServerInfo(scope.profile).toString().equals(server);
            }
            case "processSSHSignatureCallbacks" ->
                "ghidra".equals(scope.profile.kind()) && host.equalsIgnoreCase(String.valueOf(args[0]));
            case "getKeyStorePassword" ->
                scope.credentials.keyStore != null
                    && scope.credentials.keyStore.toString().equals(String.valueOf(args[0]));
            case "isSSHKeyAvailable" -> "ssh".equals(scope.profile.auth());
            default -> true;
        };
    }

    private static Object dispatch(Object proxy, Method method, Object[] args, Scope scope) {
        switch (method.getName()) {
            case "toString": return "GhydraWorkerAuthenticator";
            case "hashCode": return System.identityHashCode(proxy);
            case "equals": return args != null && args.length == 1 && proxy == args[0];
            case "getAuthenticator": return HTTP_AUTHENTICATOR;
            case "promptForReconnect": return false;
            case "getNewPassword": return null;
            case "getKeyStorePassword":
                if (scope == null || !"pki".equals(scope.profile.auth())
                        || (args != null && args.length > 1 && Boolean.TRUE.equals(args[1]))) return null;
                return scope.credentials.keyStorePassword.clone();
            case "isSSHKeyAvailable":
                return scope != null && "ssh".equals(scope.profile.auth());
            case "processPasswordCallbacks":
                if (scope == null || !"password".equals(scope.profile.auth())
                        || (args[8] != null && !String.valueOf(args[8]).isBlank())) return false;
                NameCallback name = (NameCallback) args[4];
                if (name == null && "ghidra".equals(scope.profile.kind()) && !mayUseDefaultUser(scope)) return false;
                PasswordCallback password = (PasswordCallback) args[5];
                if (name != null) name.setName(scope.credentials.username);
                if (password != null) password.setPassword(scope.credentials.password);
                ChoiceCallback choice = (ChoiceCallback) args[6];
                if (choice != null) choice.setSelectedIndex(choice.getDefaultChoice());
                return true;
            case "processSSHSignatureCallbacks":
                if (scope == null || !"ssh".equals(scope.profile.auth())) return false;
                if (args[1] == null && !mayUseDefaultUser(scope)) return false;
                try {
                    if (args[1] != null) ((NameCallback) args[1]).setName(scope.credentials.username);
                    Class<?> manager = Class.forName("ghidra.framework.remote.security.SSHKeyManager");
                    Object key = manager.getMethod("getSSHPrivateKey", java.io.File.class)
                        .invoke(null, scope.credentials.keyStore.toFile());
                    args[2].getClass().getMethod("sign", Object.class).invoke(args[2], key);
                    return true;
                } catch (ReflectiveOperationException | RuntimeException failed) {
                    return false;
                }
            default:
                return method.getReturnType() == boolean.class ? Boolean.FALSE : null;
        }
    }

    private static final Authenticator HTTP_AUTHENTICATOR = new Authenticator() {
        @Override protected PasswordAuthentication getPasswordAuthentication() {
            Scope scope = ACTIVE.get();
            if (scope == null || !"password".equals(scope.profile.auth())
                    || getRequestorType() != RequestorType.SERVER
                    || !"https".equalsIgnoreCase(getRequestingProtocol())) return null;
            URI uri = URI.create(scope.profile.endpoint());
            if (!uri.getHost().equalsIgnoreCase(getRequestingHost())
                    || effectivePort(uri) != getRequestingPort()) return null;
            return new PasswordAuthentication(scope.credentials.username, scope.credentials.password);
        }
    };

    /** Ghidra's default certificate is process-wide: one certificate identity per worker. */
    private static synchronized void configureCertificate(Scope scope) {
        String path = scope.credentials.keyStore.toString();
        if (certificateStore != null) {
            if (!certificateStore.equals(path)) throw new ConnectionException(
                "CONNECTION_PROFILE_INVALID", 409,
                "Different certificate identities require separate Ghidra workers.");
            return;
        }
        try {
            Class<?> provider = Class.forName("ghidra.security.KeyStorePasswordProvider");
            Class<?> application = Class.forName("ghidra.net.ApplicationKeyManagerFactory");
            application.getMethod("setKeyStorePasswordProvider", provider).invoke(null, authenticator);
            Class<?> factory;
            try { factory = Class.forName("ghidra.net.DefaultKeyManagerFactory"); }
            catch (ClassNotFoundException older) { factory = application; }
            // Native headless SSL resets discard transient setters. Preserve only the
            // nonsecret identity path in this one-identity JVM, never a password or preference.
            String property = (String) factory.getField("KEYSTORE_PATH_PROPERTY").get(null);
            String existing = System.getProperty(property);
            if (existing != null && !existing.equals(path)) throw new ConnectionException(
                "CONNECTION_PROFILE_INVALID", 409,
                "Different certificate identities require separate Ghidra workers.");
            System.setProperty(property, path);
            boolean configured = Boolean.TRUE.equals(factory.getMethod("initialize").invoke(null));
            if (!configured) throw new ConnectionException("CONNECTION_AUTH_FAILED", 503,
                "The worker could not load the configured certificate identity.");
            Class<?> ssl = WorkerTLS.nativeInitializer();
            if (!Boolean.TRUE.equals(ssl.getMethod("initialize", boolean.class).invoke(null, true))) {
                throw new ConnectionException("CONNECTION_AUTH_FAILED", 503,
                    "The worker could not initialize certificate authentication.");
            }
            certificateStore = path;
        } catch (ReflectiveOperationException | LinkageError failed) {
            throw new ConnectionException("CONNECTION_AUTH_FAILED", 503,
                "This Ghidra installation cannot load the configured certificate identity.");
        }
    }

    private record Scope(Profile profile, ConnectionProfiles.Credentials credentials) {}
}
