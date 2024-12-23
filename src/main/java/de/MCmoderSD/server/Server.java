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
 * The Server class represents a secure HTTPS server that can be configured with a Java KeyStore (JKS)
 * or a private key and certificate chain. It provides functionality to start and stop the server,
 * along with access to its hostname, port, and underlying HttpsServer instance.
 */
@SuppressWarnings("ALL")
public class Server {

    // Constants
    private static final String tempDir = System.getProperty("java.io.tmpdir") + File.separator;

    // Constants
    protected final String hostname;
    protected final int port;

    // Attributes
    protected final HttpsServer server;

    /**
     * Constructs a Server instance using a JSON configuration for the JKS keystore.
     *
     * @param hostname   The hostname of the server.
     * @param port       The port on which the server will listen.
     * @param jksConfig  A JsonNode containing JKS configuration details.
     * @throws IOException                  If an I/O error occurs.
     * @throws NoSuchAlgorithmException     If the specified algorithm is not available.
     * @throws KeyStoreException            If a KeyStore error occurs.
     * @throws InterruptedException         If the operation is interrupted.
     * @throws UnrecoverableKeyException    If a key cannot be recovered.
     * @throws KeyManagementException       If an error occurs initializing the SSLContext.
     * @throws CertificateException         If an error occurs processing certificates.
     */
    public Server(String hostname, int port, JsonNode jksConfig) throws IOException, NoSuchAlgorithmException, KeyStoreException, InterruptedException, UnrecoverableKeyException, KeyManagementException, CertificateException {

        // Set hostname and port
        this.hostname = hostname.toLowerCase();
        this.port = port;

        // Create HTTPS server
        server = HttpsServer.create(new InetSocketAddress(hostname, port), 0);

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
     * Constructs a Server instance using PEM-encoded private key and certificate files.
     *
     * @param hostname       The hostname of the server.
     * @param port           The port on which the server will listen.
     * @param privKeyPath    Path to the private key file.
     * @param fullChainPath  Path to the full certificate chain file.
     * @throws IOException                  If an I/O error occurs.
     * @throws NoSuchAlgorithmException     If the specified algorithm is not available.
     * @throws KeyStoreException            If a KeyStore error occurs.
     * @throws InvalidKeySpecException      If the key specification is invalid.
     * @throws CertificateException         If an error occurs processing certificates.
     * @throws UnrecoverableKeyException    If a key cannot be recovered.
     * @throws KeyManagementException       If an error occurs initializing the SSLContext.
     */
    public Server(String hostname, int port, String privKeyPath, String fullChainPath) throws IOException, NoSuchAlgorithmException, KeyStoreException, InvalidKeySpecException, CertificateException, UnrecoverableKeyException, KeyManagementException {

        // Set hostname and port
        this.hostname = hostname;
        this.port = port;

        // Create HTTPS server
        server = HttpsServer.create(new InetSocketAddress(hostname, port), 0);

        // Create SSL context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
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
        FileInputStream certInputStream = new FileInputStream(fullChainPath);
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(certInputStream);
        certInputStream.close();

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
     * Generates a new keystore file with a self-signed certificate, moves it to a temporary directory,
     * and returns it as an {@link InputStream}.
     *
     * <p>This method creates a keystore file with the specified parameters, ensures any existing
     * keystore file with the same name is deleted, and uses the Java `keytool` utility to generate a new keystore.
     * After creation, the keystore is relocated to a temporary directory, and its {@link InputStream}
     * is returned for further processing.
     *
     * @param FN       the filename for the keystore file.
     * @param PW       the password for securing the keystore.
     * @param validity the validity period of the self-signed certificate, in days.
     * @param CN       the Common Name (CN) field for the distinguished name in the certificate.
     * @param OU       the Organizational Unit (OU) field for the distinguished name.
     * @param O        the Organization (O) field for the distinguished name.
     * @param L        the Locality (L) field for the distinguished name.
     * @param ST       the State (ST) field for the distinguished name.
     * @param C        the Country (C) field for the distinguished name.
     * @return an {@link InputStream} containing the keystore file data.
     * @throws IOException          if an I/O error occurs during file operations or process execution.
     * @throws InterruptedException if the `keytool` process is interrupted during execution.
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
     * Stops the HTTPS server with no delay.
     */
    public void stop() {
        server.stop(0);
    }

    /**
     * Stops the HTTPS server with a specified delay.
     *
     * @param delay The delay before the server is stopped (in seconds).
     */
    public void stop(int delay) {
        server.stop(delay);
    }

    /**
     * Returns the underlying HttpsServer instance.
     *
     * @return The HttpsServer instance.
     */
    public HttpsServer getHttpsServer() {
        return server;
    }

    /**
     * Returns the URL of the server.
     *
     * @return The URL.
     */
    public String getURL() {
        return "https://" + hostname + ":" + port;
    }

    /**
     * Returns the hostname of the server.
     *
     * @return The hostname.
     */
    public String getHostname() {
        return hostname;
    }

    /**
     * Returns the port of the server.
     *
     * @return The port number.
     */
    public int getPort() {
        return port;
    }
}