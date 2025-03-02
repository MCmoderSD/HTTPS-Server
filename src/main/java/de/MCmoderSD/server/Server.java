package de.MCmoderSD.server;

import com.fasterxml.jackson.databind.JsonNode;

import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsConfigurator;

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

/**
 * The Server class provides methods to create and manage an HTTPS server using Java's built-in libraries.
 * It can be configured with a key store for SSL/TLS encryption, and it handles server creation,
 * start/stop functionality, and URL generation.
 */
@SuppressWarnings("ALL")
public class Server {

    // Constants
    private static final String host = "0.0.0.0";
    private static final String tempDir = System.getProperty("java.io.tmpdir") + File.separator;

    // Constants
    protected final String hostname;
    protected final int port;

    // Attributes
    protected final HttpsServer server;

    /**
     * Constructor to initialize the server with a custom JKS configuration for SSL.
     *
     * @param hostname the hostname for the server
     * @param port the port number for the server
     * @param jksConfig the JSON node containing the JKS configuration parameters
     * @param hostNetwork whether to bind the server to the host network
     * @throws IOException if an I/O error occurs
     * @throws NoSuchAlgorithmException if the SSL/TLS algorithm is not available
     * @throws KeyStoreException if there's an issue with the KeyStore
     * @throws InterruptedException if the process is interrupted
     * @throws UnrecoverableKeyException if the private key cannot be recovered
     * @throws KeyManagementException if there's an error with key management
     * @throws CertificateException if there's an issue with the certificate
     */
    public Server(String hostname, int port, JsonNode jksConfig, boolean hostNetwork) throws IOException, NoSuchAlgorithmException, KeyStoreException, InterruptedException, UnrecoverableKeyException, KeyManagementException, CertificateException {

        // Set hostname and port
        this.hostname = hostname.toLowerCase();
        this.port = port;

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

    /**
     * Constructor to initialize the server with a private key and certificate for SSL.
     *
     * @param hostname the hostname for the server
     * @param port the port number for the server
     * @param privKeyPath the path to the private key file
     * @param fullChainPath the path to the certificate chain file
     * @param hostNetwork whether to bind the server to the host network
     * @throws IOException if an I/O error occurs
     * @throws NoSuchAlgorithmException if the SSL/TLS algorithm is not available
     * @throws KeyStoreException if there's an issue with the KeyStore
     * @throws InvalidKeySpecException if the key specification is invalid
     * @throws CertificateException if there's an issue with the certificate
     * @throws UnrecoverableKeyException if the private key cannot be recovered
     * @throws KeyManagementException if there's an error with key management
     */
    public Server(String hostname, int port, String privKeyPath, String fullChainPath, boolean hostNetwork) throws IOException, NoSuchAlgorithmException, KeyStoreException, InvalidKeySpecException, CertificateException, UnrecoverableKeyException, KeyManagementException {

        // Set hostname and port
        this.hostname = hostname;
        this.port = port;

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

    /**
     * Generates a KeyStore based on provided parameters.
     *
     * @param FN the filename for the KeyStore
     * @param PW the password for the KeyStore
     * @param validity the validity period of the certificate
     * @param CN the common name of the certificate
     * @param OU the organizational unit of the certificate
     * @param O the organization of the certificate
     * @param L the locality of the certificate
     * @param ST the state of the certificate
     * @param C the country of the certificate
     * @return an InputStream containing the generated KeyStore
     * @throws IOException if an I/O error occurs
     * @throws InterruptedException if the process is interrupted
     */
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

    /**
     * Starts the HTTPS server.
     */
    public void start() {
        server.start();
    }

    /**
     * Stops the HTTPS server immediately.
     */
    public void stop() {
        server.stop(0);
    }

    /**
     * Stops the HTTPS server after the specified delay.
     *
     * @param delay the delay (in seconds) before stopping the server
     */
    public void stop(int delay) {
        server.stop(delay);
    }

    /**
     * Returns the HttpsServer instance for this server.
     *
     * @return the HttpsServer instance
     */
    public HttpsServer getHttpsServer() {
        return server;
    }

    /**
     * Returns the URL of the server.
     *
     * @return the server URL
     */
    public String getURL() {
        return "https://" + hostname + ":" + port;
    }

    /**
     * Returns the hostname of the server.
     *
     * @return the hostname
     */
    public String getHostname() {
        return hostname;
    }

    /**
     * Returns the port of the server.
     *
     * @return the port number
     */
    public int getPort() {
        return port;
    }
}