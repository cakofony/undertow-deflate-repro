package net.ckozak.repro;

import com.google.common.io.ByteStreams;
import io.undertow.Handlers;
import io.undertow.Undertow;
import io.undertow.UndertowOptions;
import io.undertow.server.HandlerWrapper;
import io.undertow.server.handlers.PathHandler;
import io.undertow.server.handlers.encoding.ContentEncodingRepository;
import io.undertow.server.handlers.encoding.DeflateEncodingProvider;
import io.undertow.server.handlers.encoding.EncodingHandler;
import io.undertow.server.handlers.encoding.GzipEncodingProvider;
import io.undertow.servlet.Servlets;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.DeploymentManager;
import io.undertow.servlet.api.ServletContainer;
import io.undertow.servlet.util.ImmediateInstanceFactory;
import org.xnio.IoUtils;
import org.xnio.Options;
import org.xnio.Sequence;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.zip.Deflater;

public class Main {

    private static final String SERVER_KEY_STORE = "server.keystore";
    private static final String SERVER_TRUST_STORE = "server.truststore";
    private static final char[] STORE_PASSWORD = "password".toCharArray();

    private static KeyStore loadKeyStore(final String name) throws IOException {
        final InputStream stream = Main.class.getClassLoader().getResourceAsStream(name);
        if(stream == null) {
            throw new RuntimeException("Could not load keystore");
        }
        try {
            KeyStore loadedKeystore = KeyStore.getInstance("JKS");
            loadedKeystore.load(stream, STORE_PASSWORD);

            return loadedKeystore;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            throw new IOException(String.format("Unable to load KeyStore %s", name), e);
        } finally {
            IoUtils.safeClose(stream);
        }
    }

    private static SSLContext createSSLContext(final KeyStore keyStore, final KeyStore trustStore) throws IOException {
        KeyManager[] keyManagers;
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, STORE_PASSWORD);
            keyManagers = keyManagerFactory.getKeyManagers();
        } catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
            throw new IOException("Unable to initialise KeyManager[]", e);
        }

        TrustManager[] trustManagers = null;
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            trustManagers = trustManagerFactory.getTrustManagers();
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new IOException("Unable to initialise TrustManager[]", e);
        }

        SSLContext sslContext;
        try {
            sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(keyManagers, trustManagers, null);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IOException("Unable to create and initialise the SSLContext", e);
        }

        return sslContext;
    }

    public static void main(String[] args) throws Exception {
        final SSLContext serverContext = createSSLContext(loadKeyStore(SERVER_KEY_STORE), loadKeyStore(SERVER_TRUST_STORE));
        PathHandler handler = Handlers.path();
        HandlerWrapper compressionWrapper = wrapped -> new EncodingHandler(wrapped, new ContentEncodingRepository()
                .addEncodingHandler("gzip", new GzipEncodingProvider(Deflater.DEFAULT_COMPRESSION), 100)
                .addEncodingHandler("deflate", new DeflateEncodingProvider(Deflater.DEFAULT_COMPRESSION), 19)
 );
        Undertow.builder()
                .addHttpsListener(4443, "localhost", serverContext)
                .setSocketOption(Options.SSL_ENABLED_CIPHER_SUITES, Sequence.of(
                        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"))
                .setServerOption(UndertowOptions.ENABLE_HTTP2, true)
                .setHandler(handler)
                .build()
                .start();
        DeploymentInfo deploymentInfo = Servlets.deployment()
                .setDeploymentName("test")
                .setContextPath("/")
                .setClassLoader(Main.class.getClassLoader())
                .addOuterHandlerChainWrapper(compressionWrapper)
                .addServlet(Servlets.servlet("testServlet", TestServlet.class, new ImmediateInstanceFactory<>(new TestServlet())).addMapping("/*"));
        ServletContainer servletContainer = Servlets.defaultContainer();

        DeploymentManager manager = servletContainer.addDeployment(deploymentInfo);
        manager.deploy();

        handler.addPrefixPath("/", manager.start());
    }

    public static class TestServlet extends HttpServlet {

        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            try (InputStream inputStream = new FileInputStream(new File("files/gradle-4.2.1-bin.zip"))) {
                ByteStreams.copy(inputStream, resp.getOutputStream());
            }
        }
    }
}
