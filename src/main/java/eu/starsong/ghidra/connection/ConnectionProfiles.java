package eu.starsong.ghidra.connection;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

/** Worker-owned policy and credential store; never part of the ordinary CLI configuration. */
public final class ConnectionProfiles {
    public static final String PROPERTY = "ghydra.connections.dir";
    public static final String ENV = "GHYDRA_CONNECTIONS_DIR";
    private static final int MAX_BYTES = 1024 * 1024;
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.-]{0,63}");
    private static final ThreadLocal<Profile> SELECTED = new ThreadLocal<>();
    private static final Object STORE_LOCK = new Object();
    private static final Set<PosixFilePermission> PRIVATE_FILE = Set.of(
        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    private static final Set<PosixFilePermission> PRIVATE_DIRECTORY = Set.of(
        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
        PosixFilePermission.OWNER_EXECUTE);

    private ConnectionProfiles() {}

    public static Path directory() {
        String value = System.getProperty(PROPERTY);
        if (value == null || value.isBlank()) value = System.getenv(ENV);
        if (value == null || value.isBlank()) return null;
        try {
            Path path = Path.of(value);
            if (!path.isAbsolute()) throw invalid();
            return path.normalize();
        } catch (RuntimeException failed) {
            throw invalid();
        }
    }

    public static boolean enabled() {
        String property = System.getProperty(PROPERTY);
        return (property != null && !property.isBlank())
            || ((property == null || property.isBlank()) && System.getenv(ENV) != null
                && !System.getenv(ENV).isBlank());
    }

    /** Only metadata safe for the agent. */
    public static List<Map<String, Object>> list() {
        if (!enabled()) return List.of();
        return locked(root -> {
            JsonObject profiles = manifest(root).getAsJsonObject("profiles");
            List<Map<String, Object>> result = new ArrayList<>();
            for (String id : profiles.keySet()) result.add(parse(id, profiles.get(id)).publicView());
            result.sort(java.util.Comparator.comparing(row -> String.valueOf(row.get("id"))));
            return result;
        });
    }

    public static Profile require(String id, String kind, String permission) {
        if (!enabled()) throw new ConnectionException("CONNECTIONS_DISABLED", 503,
            "This instance has no worker connection profiles configured.");
        if (id == null || id.isBlank()) throw new ConnectionException(
            "CONNECTION_PROFILE_REQUIRED", 400, "Select a worker connection profile.");
        if (!ID.matcher(id).matches()) throw invalid();
        return locked(root -> requireFrom(manifest(root), id, kind, permission));
    }

    public static Profile currentBsim() {
        Profile selected = SELECTED.get();
        if (selected != null && "bsim".equals(selected.kind())) return selected;
        return defaultBsim();
    }

    private static Profile defaultBsim() {
        if (!enabled()) return null;
        return locked(root -> {
            JsonObject data = manifest(root);
            String id = optional(data, "default_bsim");
            return id == null ? null : requireFrom(data, id, "bsim", null);
        });
    }

    /** Native callbacks and selection are request-scoped, not mutable JVM properties. */
    public static <T> T withProfile(String id, String kind, String permission,
            Function<Profile, T> operation) {
        Profile profile = (id == null || id.isBlank()) && "bsim".equals(kind)
            ? defaultBsim() : require(id, kind, permission);
        if (profile == null) return operation.apply(null); // existing local H2 configuration
        checkPermission(profile, permission);
        Profile previous = SELECTED.get();
        SELECTED.set(profile);
        try {
            return permission == null ? operation.apply(profile)
                : WorkerAuthentication.call(profile, () -> operation.apply(profile));
        } finally {
            if (previous == null) SELECTED.remove(); else SELECTED.set(previous);
        }
    }

    private static Profile requireFrom(JsonObject data, String id, String kind,
            String permission) {
        JsonElement entry = data.getAsJsonObject("profiles").get(id);
        if (entry == null) throw new ConnectionException("CONNECTION_PROFILE_NOT_FOUND", 404,
            "The selected worker connection profile does not exist.");
        Profile profile = parse(id, entry);
        if (kind != null && !kind.equals(profile.kind())) throw invalid();
        checkPermission(profile, permission);
        return profile;
    }

    private static void checkPermission(Profile profile, String permission) {
        if (permission != null && !profile.permissions().contains(permission)) {
            throw new ConnectionException("CONNECTION_PERMISSION_DENIED", 403,
                "The selected profile does not permit this operation.");
        }
    }

    private static Profile parse(String id, JsonElement value) {
        try {
            if (!ID.matcher(id).matches() || !value.isJsonObject()) throw invalid();
            JsonObject row = value.getAsJsonObject();
            String kind = text(row, "kind");
            String backend = text(row, "backend");
            String endpoint = text(row, "endpoint");
            String auth = text(row, "auth");
            String ref = optional(row, "credential_ref");
            Set<String> grants = new HashSet<>();
            for (JsonElement grant : row.getAsJsonArray("permissions")) {
                if (!grant.isJsonPrimitive() || !grant.getAsJsonPrimitive().isString()) throw invalid();
                if (!grants.add(grant.getAsString())) throw invalid();
            }
            Set<String> permitted;
            if ("bsim".equals(kind)) {
                permitted = Set.of("query", "ingest");
                if (!Set.of("h2", "postgresql", "elasticsearch").contains(backend)) throw invalid();
            } else if ("ghidra".equals(kind) && "ghidra".equals(backend)) {
                permitted = Set.of("read", "checkout", "checkin");
            } else throw invalid();
            if (grants.isEmpty() || !permitted.containsAll(grants)) throw invalid();
            if ("h2".equals(backend)) {
                if (!"none".equals(auth) || ref != null || !endpoint.startsWith("/")
                        || endpoint.length() > 4096 || endpoint.chars().anyMatch(c -> c < 32 || c == 127)
                        || endpoint.matches(".*[\\\\;?#%].*")) throw invalid();
                for (String component : endpoint.substring(1).split("/", -1)) {
                    if (component.isEmpty() || component.equals(".") || component.equals("..")) throw invalid();
                }
            } else {
                if (ref == null || !ID.matcher(ref).matches()) throw invalid();
                Set<String> modes = "ghidra".equals(backend) ? Set.of("password", "pki", "ssh")
                    : "postgresql".equals(backend) ? Set.of("password", "pki")
                    : Set.of("password");
                if (!modes.contains(auth)) throw invalid();
                if (endpoint.length() > 4096 || !endpoint.chars().allMatch(c -> c > 32 && c < 127)
                        || endpoint.matches(".*[\\\\%@?#].*")) throw invalid();
                URI uri = new URI(endpoint);
                String expected = "elasticsearch".equals(backend) ? "elastic" : backend;
                if (!expected.equals(uri.getScheme())
                        && !("elasticsearch".equals(backend) && "https".equals(uri.getScheme()))) throw invalid();
                if (uri.getHost() == null || uri.getHost().isBlank() || uri.getRawUserInfo() != null
                        || uri.getRawQuery() != null || uri.getRawFragment() != null
                        || uri.getPort() == 0 || uri.getPort() > 65535 || uri.getPort() < -1) throw invalid();
                String path = uri.getPath();
                if (path == null || !path.matches("/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
                        || path.equals("/.") || path.equals("/..")) throw invalid();
            }
            return new Profile(id, kind, backend, endpoint, auth, ref, grants);
        } catch (ConnectionException failure) {
            throw failure;
        } catch (Exception failure) {
            throw invalid();
        }
    }

    /** Read only under the native operation's private scope, never for catalog/status. */
    static Credentials credentials(Profile profile) {
        if ("none".equals(profile.auth())) return new Credentials("", new char[0], null, new char[0]);
        return locked(root -> {
            Profile current = requireFrom(manifest(root), profile.id(), profile.kind(), null);
            if (!current.equals(profile)) throw new ConnectionException("CONNECTION_AUTH_REQUIRED", 409,
                "The connection profile changed; start the operation again.");
            JsonObject data = document(root.resolve("credentials.json"));
            if (!data.has("credentials") || !data.get("credentials").isJsonObject()) throw invalid();
            JsonElement entry = data.getAsJsonObject("credentials").get(profile.credentialRef());
            if (entry == null || !entry.isJsonObject()) throw new ConnectionException(
                "CONNECTION_AUTH_REQUIRED", 503, "The worker credential is not configured.");
            JsonObject row = entry.getAsJsonObject();
            String username = text(row, "username");
            if (username.isBlank() || username.indexOf(':') >= 0
                    || username.chars().anyMatch(c -> c < 32 || c == 127)) throw invalid();
            if ("password".equals(profile.auth())) {
                String password = text(row, "password");
                if (password.isEmpty()) throw invalid();
                return new Credentials(username, password.toCharArray(), null, new char[0]);
            }
            String store = text(row, "key_store");
            Path key = Path.of(store);
            if (!key.isAbsolute()) throw unsafe();
            protect(key, false);
            String password = optional(row, "key_store_password");
            if ("ssh".equals(profile.auth()) && password != null && !password.isEmpty()) throw invalid();
            return new Credentials(username, new char[0], key,
                password == null ? new char[0] : password.toCharArray());
        });
    }

    static final class Credentials implements AutoCloseable {
        final String username;
        final char[] password;
        final Path keyStore;
        final char[] keyStorePassword;
        Credentials(String username, char[] password, Path keyStore, char[] keyStorePassword) {
            this.username = username;
            this.password = password;
            this.keyStore = keyStore;
            this.keyStorePassword = keyStorePassword;
        }
        @Override public void close() {
            Arrays.fill(password, '\0');
            Arrays.fill(keyStorePassword, '\0');
        }
        @Override public String toString() { return "WorkerCredentials[private]"; }
    }

    private static JsonObject manifest(Path root) {
        JsonObject data = document(root.resolve("profiles.json"));
        if (!data.has("profiles") || !data.get("profiles").isJsonObject()) throw invalid();
        return data;
    }

    private static JsonObject document(Path path) {
        protect(path, false);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            long size = channel.size();
            if (size < 2 || size > MAX_BYTES) throw invalid();
            ByteBuffer buffer = ByteBuffer.allocate((int) size);
            while (buffer.hasRemaining()) if (channel.read(buffer) < 0) throw invalid();
            JsonElement parsed = JsonParser.parseString(new String(buffer.array(), StandardCharsets.UTF_8));
            if (!parsed.isJsonObject()) throw invalid();
            JsonObject result = parsed.getAsJsonObject();
            if (!result.has("version") || !result.get("version").isJsonPrimitive()
                    || !result.get("version").getAsJsonPrimitive().isNumber()
                    || !"1".equals(result.get("version").getAsString())) throw invalid();
            return result;
        } catch (ConnectionException failure) {
            throw failure;
        } catch (Exception failed) {
            throw invalid();
        }
    }

    private interface StoreRead<T> { T read(Path root); }
    private static <T> T locked(StoreRead<T> operation) {
        synchronized (STORE_LOCK) {
            Path root = directory();
            if (root == null) throw new ConnectionException("CONNECTIONS_DISABLED", 503,
                "This instance has no worker connection profiles configured.");
            protect(root, true);
            Path lock = root.resolve(".lock");
            protect(lock, false);
            try (FileChannel channel = FileChannel.open(lock, StandardOpenOption.READ,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
                    FileLock ignored = channel.lock(0, Long.MAX_VALUE, true)) {
                return operation.read(root);
            } catch (ConnectionException failed) {
                throw failed;
            } catch (IOException failed) {
                throw unsafe();
            }
        }
    }

    /** Filesystem protections, not encryption, provide the worker's OS-principal boundary. */
    static void protect(Path path, boolean directory) {
        try {
            Path absolute = path.toAbsolutePath();
            var user = absolute.getFileSystem().getUserPrincipalLookupService()
                .lookupPrincipalByName(System.getProperty("user.name"));
            Path cursor = absolute.getRoot();
            for (Path component : absolute) {
                cursor = cursor.resolve(component);
                if (Files.isSymbolicLink(cursor)) throw unsafe();
                if (!cursor.equals(absolute)) {
                    var ancestor = Files.readAttributes(cursor, PosixFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);
                    int uid = ((Number) Files.getAttribute(cursor, "unix:uid", LinkOption.NOFOLLOW_LINKS)).intValue();
                    int mode = ((Number) Files.getAttribute(cursor, "unix:mode", LinkOption.NOFOLLOW_LINKS)).intValue();
                    if ((!ancestor.owner().equals(user) && uid != 0)
                            || ((mode & 0022) != 0 && !(uid == 0 && (mode & 01000) != 0))) throw unsafe();
                }
            }
            PosixFileAttributes attributes = Files.readAttributes(absolute,
                PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!attributes.owner().equals(user) || (directory ? !attributes.isDirectory()
                    : !attributes.isRegularFile()) || !attributes.permissions().equals(
                        directory ? PRIVATE_DIRECTORY : PRIVATE_FILE)) throw unsafe();
            if (!directory && ((Number) Files.getAttribute(absolute, "unix:nlink",
                    LinkOption.NOFOLLOW_LINKS)).intValue() != 1) throw unsafe();
        } catch (ConnectionException failure) {
            throw failure;
        } catch (Exception failed) {
            throw unsafe();
        }
    }

    private static String text(JsonObject row, String key) {
        String value = optional(row, key);
        if (value == null) throw invalid();
        return value;
    }
    private static String optional(JsonObject row, String key) {
        JsonElement value = row.get(key);
        if (value == null || value.isJsonNull()) return null;
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) throw invalid();
        return value.getAsString();
    }
    private static ConnectionException invalid() {
        return new ConnectionException("CONNECTION_PROFILE_INVALID", 400,
            "The worker connection configuration is invalid; ask its operator to repair it.");
    }
    private static ConnectionException unsafe() {
        return new ConnectionException("CONNECTION_STORE_UNSAFE", 503,
            "Connection storage requires worker-owned private POSIX files without symlinks.");
    }
}
