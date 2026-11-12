package eu.starsong.ghidra.connection;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.util.List;
import java.util.Map;
import javax.net.ssl.*;

/** Older Ghidra releases allow unverified TLS by default. Credential workers never do. */
public final class WorkerTLS {
    private static Provider provider;
    private WorkerTLS() {}

    public static synchronized void initialize() {
        if (!ConnectionProfiles.enabled()) return;
        try {
            if (provider == null) {
                Provider delegate = SSLContext.getInstance("TLS").getProvider();
                provider = new Provider("GhydraVerifiedTLS", "1.0", "Verified worker TLS") {
                    {
                        putService(new Service(this, "SSLContext", "TLS", VerifiedSpi.class.getName(),
                                List.of(), Map.of()) {
                            @Override public Object newInstance(Object parameter)
                                    throws java.security.NoSuchAlgorithmException {
                                return new VerifiedSpi(SSLContext.getInstance("TLS", delegate));
                            }
                        });
                    }
                };
                if (Security.insertProviderAt(provider, 1) < 0) throw new KeyManagementException();
                // Native socket factories restore this cached context on every construction.
                // Build that cache through our provider, not through an unverified default.
                Class<?> initializer = nativeInitializer();
                if (!Boolean.TRUE.equals(initializer.getMethod("initialize", boolean.class)
                        .invoke(null, true))) throw new KeyManagementException();
            }
            SSLContext context = SSLContext.getDefault();
            if (context.getProvider() != provider) throw new KeyManagementException();
            HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
        } catch (Exception | LinkageError failed) {
            throw new ConnectionException("CONNECTION_TLS_FAILED", 503,
                "The worker could not initialize verified TLS. Check its certificate configuration.");
        }
    }

    static Class<?> nativeInitializer() throws ClassNotFoundException {
        try { return Class.forName("ghidra.net.DefaultSSLContextInitializer"); }
        catch (ClassNotFoundException older) { return Class.forName("ghidra.net.SSLContextInitializer"); }
    }

    private static TrustManager[] trustManagers() throws Exception {
        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        String certificates = System.getProperty("ghidra.cacerts");
        if (certificates == null || certificates.isBlank()) {
            trust.init((KeyStore) null); // JVM trust store, never Ghidra's OpenTrustManager
        } else {
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, null);
            try (var input = Files.newInputStream(Path.of(certificates))) {
                int index = 0;
                for (var certificate : CertificateFactory.getInstance("X.509").generateCertificates(input)) {
                    store.setCertificateEntry("worker-ca-" + index++, certificate);
                }
                if (index == 0) throw new java.security.cert.CertificateException();
            }
            trust.init(store);
        }
        return trust.getTrustManagers();
    }


    private static final class VerifiedSpi extends SSLContextSpi {
        private final SSLContext delegate;
        private SSLSocketFactory sockets;
        VerifiedSpi(SSLContext delegate) {
            this.delegate = delegate;
        }
        @Override protected void engineInit(KeyManager[] keys, TrustManager[] ignored, SecureRandom random)
                throws KeyManagementException {
            try {
                delegate.init(keys, trustManagers(), random);
                sockets = null;
            } catch (Exception failed) {
                throw new KeyManagementException("Invalid worker certificate configuration");
            }
        }
        @Override protected synchronized SSLSocketFactory engineGetSocketFactory() {
            if (sockets == null) sockets = new VerifiedSockets(delegate.getSocketFactory());
            return sockets;
        }
        @Override protected SSLServerSocketFactory engineGetServerSocketFactory() { return delegate.getServerSocketFactory(); }
        @Override protected SSLEngine engineCreateSSLEngine() { return verify(delegate.createSSLEngine()); }
        @Override protected SSLEngine engineCreateSSLEngine(String host, int port) {
            return verify(delegate.createSSLEngine(host, port));
        }
        @Override protected SSLSessionContext engineGetServerSessionContext() { return delegate.getServerSessionContext(); }
        @Override protected SSLSessionContext engineGetClientSessionContext() { return delegate.getClientSessionContext(); }
        @Override protected SSLParameters engineGetDefaultSSLParameters() {
            SSLParameters parameters = delegate.getDefaultSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            return parameters;
        }
        @Override protected SSLParameters engineGetSupportedSSLParameters() { return delegate.getSupportedSSLParameters(); }
        private SSLEngine verify(SSLEngine engine) {
            SSLParameters parameters = engine.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            engine.setSSLParameters(parameters);
            return engine;
        }
    }

    private static final class VerifiedSockets extends SSLSocketFactory {
        private final SSLSocketFactory delegate;
        VerifiedSockets(SSLSocketFactory delegate) { this.delegate = delegate; }
        private Socket verify(Socket socket) {
            SSLSocket ssl = (SSLSocket) socket;
            SSLParameters parameters = ssl.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            ssl.setSSLParameters(parameters);
            return ssl;
        }
        @Override public String[] getDefaultCipherSuites() { return delegate.getDefaultCipherSuites(); }
        @Override public String[] getSupportedCipherSuites() { return delegate.getSupportedCipherSuites(); }
        @Override public Socket createSocket() throws IOException { return verify(delegate.createSocket()); }
        @Override public Socket createSocket(Socket socket, String host, int port, boolean close) throws IOException {
            return verify(delegate.createSocket(socket, host, port, close));
        }
        @Override public Socket createSocket(String host, int port) throws IOException {
            return verify(delegate.createSocket(host, port));
        }
        @Override public Socket createSocket(InetAddress host, int port) throws IOException {
            return verify(delegate.createSocket(host, port));
        }
        @Override public Socket createSocket(String host, int port, InetAddress local, int localPort) throws IOException {
            return verify(delegate.createSocket(host, port, local, localPort));
        }
        @Override public Socket createSocket(InetAddress host, int port, InetAddress local, int localPort) throws IOException {
            return verify(delegate.createSocket(host, port, local, localPort));
        }
    }
}
