package de.MCmoderSD.server.cert;

import com.fasterxml.jackson.databind.JsonNode;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

@SuppressWarnings("ClassCanBeRecord")
public class CertManager {

    // Constants
    private static final String BC_PROVIDER = "BC";
    private static final String SIGNATURE_ALGORITHM = "SHA512withRSA";
    private static final String FINGERPRINT_ALGORITHM = "SHA-256";
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String SSL_PROTOCOL = "TLS";

    // Instance of Bouncy Castle provider and SecureRandom
    private static final SecureRandom RANDOM;
    static {
        RANDOM = new SecureRandom();
        if (Security.getProvider(BC_PROVIDER) == null) Security.addProvider(new BouncyCastleProvider());
    }

    // SSLContext
    private final SSLContext sslContext;

    // Constructor
    public CertManager(JsonNode config) {

        // Check Configuration
        if (config == null || config.isNull() || config.isEmpty()) throw new IllegalArgumentException("Certificate configuration cannot be null or empty");

        // Initialize SSLContext based on Certificate Type
        sslContext = switch (CertificateType.fromConfig(config)) {
            case PROVIDED -> useProvidedCertificate(config);
            case ACME_SIGNED -> useAcmeSigned(config.get("acmeSigned"));
            case SELF_SIGNED -> useSelfSigned(config.get("selfSigned"));
        };
    }

    private SSLContext useProvidedCertificate(JsonNode config) {
        return null; // ToDo: Implement loading provided certificate
    }

    private SSLContext useAcmeSigned(JsonNode config) {

        // Check ACME Config
        if (config == null || config.isNull() || config.isEmpty()) throw new IllegalArgumentException("Certificate configuration cannot be null or empty");



        return null; // ToDo: Implement ACME signed certificate
    }

    private SSLContext useSelfSigned(JsonNode config) {

        // Check Self-Signed Config
        if (config == null || config.isNull() || config.isEmpty()) throw new IllegalArgumentException("Self-signed certificate configuration cannot be null or empty");

        // Initialize Self-Signed Certificate
        SelfSignedCert selfSignedCert = new SelfSignedCert(config, RANDOM, BC_PROVIDER, SIGNATURE_ALGORITHM);

        // Load Key Password
        if (!config.has("keyPassword") || config.get("keyPassword") == null) throw new IllegalArgumentException("Key password is required in the configuration");
        String password = config.get("keyPassword").asText();
        if (password.isBlank()) throw new IllegalArgumentException("Key password cannot be empty");
        char[] keyPassword = password.toCharArray();

        // Obtain Private Key and Certificate
        KeyPair privateKey = selfSignedCert.getPrivateKey();
        X509Certificate certificate = selfSignedCert.getCertificate();

        // CHeck Private Key and Certificate
        if (privateKey == null || privateKey.getPrivate() == null || privateKey.getPublic() == null) throw new IllegalArgumentException("Private key cannot be null");
        if (certificate == null) throw new IllegalArgumentException("Certificate cannot be null");

        // Initialize SSLContext
        return initSSLContext(initKeyManager(privateKey.getPrivate(), certificate, keyPassword), initTrustManager(certificate));
    }

    // Initialize KeyManager
    private static KeyManager[] initKeyManager(PrivateKey privateKey, X509Certificate certificate, char[] keyPassword) {
        try {

            // Check inputs
            if (privateKey == null) throw new IllegalArgumentException("Private key cannot be null");
            if (certificate == null) throw new IllegalArgumentException("Certificate cannot be null");
            if (keyPassword == null || keyPassword.length == 0) throw new IllegalArgumentException("Key password cannot be null or empty");

            // Initialize KeyStore
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(null, null);
            keyStore.setKeyEntry(
                    HexFormat.of().formatHex(MessageDigest.getInstance(FINGERPRINT_ALGORITHM).digest(certificate.getEncoded())).toLowerCase(),
                    privateKey,
                    keyPassword,
                    new Certificate[] { certificate }
            );

            // Initialize KeyManagerFactory
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, keyPassword);
            return keyManagerFactory.getKeyManagers();

        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException("Error initializing KeyManagerFactory", e);
        }
    }

    // Initialize TrustManager
    private static TrustManager[] initTrustManager(X509Certificate certificate) {
        try {

            // Check input
            if (certificate == null) throw new IllegalArgumentException("Certificate cannot be null");

            // Initialize TrustStore
            KeyStore trustStore = KeyStore.getInstance(KEYSTORE_TYPE);
            trustStore.load(null, null);
            trustStore.setCertificateEntry(
                    HexFormat.of().formatHex(MessageDigest.getInstance(FINGERPRINT_ALGORITHM).digest(certificate.getEncoded())).toLowerCase(),
                    certificate
            );

            // Initialize TrustManagerFactory
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            return trustManagerFactory.getTrustManagers();

        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Error initializing TrustManagerFactory", e);
        }
    }

    // Initialize SSLContext
    private static SSLContext initSSLContext(KeyManager[] keyManager, TrustManager[] trustManager) {
        try {

            // Check inputs
            if (keyManager == null || keyManager.length == 0) throw new IllegalArgumentException("KeyManager cannot be null or empty");
            if (trustManager == null || trustManager.length == 0) throw new IllegalArgumentException("TrustManager cannot be null or empty");

            // Initialize SSLContext
            SSLContext sslContext = SSLContext.getInstance(SSL_PROTOCOL);
            sslContext.init(keyManager, trustManager, RANDOM);

            // Return SSLContext
            return sslContext;

        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException("Error initializing SSLContext", e);
        }
    }

    // Getter for SSLContext
    public SSLContext getSSLContext() {
        return sslContext;
    }

    private enum CertificateType {

        // Types
        PROVIDED,
        ACME_SIGNED,
        SELF_SIGNED;

        // Determine Certificate Type from Configuration
        public static CertificateType fromConfig(JsonNode config) {

            // Check Configuration
            if (config == null || config.isNull() || config.isEmpty()) throw new IllegalArgumentException("Certificate configuration cannot be null or empty");

            // Determine Certificate Type
            if (config.has("paths") && config.has("provided") && config.get("provided").asBoolean()) return PROVIDED;
            if (config.has("acmeSigned")) return ACME_SIGNED;
            if (config.has("selfSigned")) return SELF_SIGNED;

            // No valid certificate type found
            throw new IllegalArgumentException("No valid certificate configuration found");
        }
    }
}