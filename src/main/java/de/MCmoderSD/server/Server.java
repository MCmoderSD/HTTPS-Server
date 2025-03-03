package de.MCmoderSD.server;

import com.fasterxml.jackson.databind.JsonNode;

import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsConfigurator;
import org.jetbrains.annotations.Nullable;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;

import java.util.Base64;

@SuppressWarnings("ALL")
public class Server {

    // Constants
    private static final String host = "0.0.0.0";
    private static final String tempDir = System.getProperty("java.io.tmpdir") + File.separator;

    // Constants
    protected final String hostname;
    protected final int port;
    protected final String proxy;

    // Attributes
    protected final HttpsServer server;

    public Server(String hostname, int port, @Nullable String proxy, JsonNode jksConfig, boolean hostNetwork) throws IOException, NoSuchAlgorithmException, KeyStoreException, InterruptedException, UnrecoverableKeyException, KeyManagementException, CertificateException {

        // Set hostname and port
        this.hostname = hostname.toLowerCase();
        this.port = port;
        this.proxy = proxy;

        // Create HTTPS server
        server = HttpsServer.create(new InetSocketAddress(hostNetwork ? host : hostname, port), 0);

        // Create SSL context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");

        // Generate KeyStore
        char[] password = jksConfig.get("password").asText().toCharArray();
        keyStore.load(generateKeyStore(
                        jksConfig.get("file").asText(),     // File name
                        password,                           // Password
                        jksConfig.get("validity").asInt(),  // Validity in days
                        jksConfig.get("CN").asText(),       // Common Name
                        jksConfig.get("OU").asText(),       // Organizational Unit
                        jksConfig.get("O").asText(),        // Organization
                        jksConfig.get("L").asText(),        // Locality
                        jksConfig.get("ST").asText(),       // State
                        jksConfig.get("C").asText()         // Country
                ), password
        );

        // Initialize KeyManagerFactory and SSLContext
        keyManagerFactory.init(keyStore, password);
        sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

        // Set HTTPS configurator
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                try {
                    SSLContext c = SSLContext.getDefault();
                    SSLEngine engine = c.createSSLEngine();
                    params.setNeedClientAuth(false);
                    params.setCipherSuites(engine.getEnabledCipherSuites());
                    params.setProtocols(engine.getEnabledProtocols());
                    SSLParameters defaultSSLParameters = c.getDefaultSSLParameters();
                    params.setSSLParameters(defaultSSLParameters);
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }
        });
    }

    public Server(String hostname, int port, @Nullable String proxy, String privKeyPath, String fullChainPath, boolean hostNetwork) throws IOException, NoSuchAlgorithmException, KeyStoreException, InvalidKeySpecException, CertificateException, UnrecoverableKeyException, KeyManagementException {

        // Set hostname and port
        this.hostname = hostname;
        this.port = port;
        this.proxy = proxy;

        // Create HTTPS server
        server = HttpsServer.create(new InetSocketAddress(hostNetwork ? host : hostname, port), 0);

        // Create SSL context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");

        // Load private key
        @SuppressWarnings("resource")
        byte[] keyBytes = new FileInputStream(privKeyPath).readAllBytes();
        String privateKeyPEM = new String(keyBytes, StandardCharsets.UTF_8)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        PrivateKey privKey = keyFactory.generatePrivate(keySpec);

        // Load certificate
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream(fullChainPath));

        // Load KeyStore
        keyStore.load(null, null);
        keyStore.setKeyEntry("alias", privKey, privateKeyPEM.toCharArray(), new Certificate[]{cert});

        // Initialize KeyManagerFactory and SSLContext
        keyManagerFactory.init(keyStore, privateKeyPEM.toCharArray());
        sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

        // Set HTTPS configurator
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                try {
                    SSLContext c = SSLContext.getDefault();
                    SSLEngine engine = c.createSSLEngine();
                    params.setNeedClientAuth(false);
                    params.setCipherSuites(engine.getEnabledCipherSuites());
                    params.setProtocols(engine.getEnabledProtocols());
                    SSLParameters defaultSSLParameters = c.getDefaultSSLParameters();
                    params.setSSLParameters(defaultSSLParameters);
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }
        });
    }

    public static InputStream generateKeyStore(String FN, char[] PW, int validity, String CN, String OU, String O, String L, String ST, String C) throws IOException, InterruptedException {

        // Delete existing keystore file
        for (String directory : new String[] {"", tempDir}) {
            File keystore = new File(directory + FN);
            boolean deleteSuccess = false;
            if (keystore.exists()) deleteSuccess = keystore.delete();
            if (!deleteSuccess) deleteSuccess = !keystore.exists();
            if (!deleteSuccess) throw new IOException("Error occurred. Could not delete file. File: " + keystore.getAbsolutePath());
        }

        // Generate new keystore file
        ProcessBuilder processBuilder = new ProcessBuilder("keytool",
                "-genkey",
                "-keyalg", "RSA",
                "-alias", "selfsigned",
                "-keystore", FN,
                "-storepass", new String(PW),
                "-validity", String.valueOf(validity),
                "-keysize", "4096",
                "-dname", "CN=%s, OU=%s, O=%s, L=%s, ST=%s, C=%s".formatted(CN, OU, O, L, ST, C));
        Process process = processBuilder.start(); // execute the command

        // Capture and print the output from the process
        var exitCode = process.waitFor();
        if (exitCode != 0) throw new IOException("Error occurred. Exit code: " + exitCode);

        // Move keystore file to temp directory
        File keystore = new File(FN);
        File destination = new File(tempDir + FN);
        Files.copy(keystore.toPath(), destination.toPath(), StandardCopyOption.REPLACE_EXISTING);
        if (!keystore.delete()) throw new IOException("Error occurred. Could not delete original file. File: " + keystore.getAbsolutePath());
        keystore = destination;

        // Return the keystore file as an InputStream
        FileInputStream inputStream = new FileInputStream(keystore);
        keystore.deleteOnExit(); // cleanup on exit
        return inputStream;
    }

    public void start() {
        server.start();
    }

    public void stop() {
        server.stop(0);
    }

    public void stop(int delay) {
        server.stop(delay);
    }

    public HttpsServer getHttpsServer() {
        return server;
    }

    public String getURL() {
        return proxy == null ? "https://" + "%s:%d".formatted(hostname, port) : proxy;
    }

    public String getHostname() {
        return hostname;
    }

    public int getPort() {
        return port;
    }

    public String getProxy() {
        return proxy;
    }
}