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

public class CertManager {

    // Constants
    private static final String BC_PROVIDER = "BC";
    private static final String SIGNATURE_ALGORITHM = "SHA512withRSA";
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

        // Determine Certificate Type
        boolean provided = config.has("paths") && config.has("provided") && config.get("provided").asBoolean();	// 1. Priority: Provided Certificate
        boolean acmeSigned = config.has("acmeSigned") && !provided;                                             // 2. Priority: ACME Signed Certificate
        boolean selfSigned = config.has("selfSigned") && !provided && !acmeSigned;                              // 3. Priority: Self-Signed Certificate
        if (!provided && !acmeSigned && !selfSigned) throw new IllegalArgumentException("No valid certificate configuration found");

        // Initialize SSLContext based on Certificate Type
        SSLContext ssl = null;
        //if (provided) ssl = loadCertificate ToDo: Implement loading provided certificate
        //if (acmeSigned) ssl = useAcmeSigned(config.get("acmeSigned")); ToDo: Implement ACME signed certificate
        if (selfSigned) ssl = useSelfSigned(config.get("selfSigned"));

        // Final Check
        if (ssl != null) sslContext = ssl;
        else throw new IllegalStateException("Failed to initialize SSLContext");
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
        String alias = "selfsigned";
        var keyManagerFactory = initKeyManagerFactory(alias, privateKey, certificate, keyPassword);
        var trustManagerFactory = initTrustManagerFactory(alias, certificate);
        return initSSLContext(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers());
    }

    // 4. Initialize KeyManagerFactory with the KeyPair and Certificate
    private static KeyManagerFactory initKeyManagerFactory(String alias, KeyPair keyPair, X509Certificate certificate, char[] keyPassword) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(null, null);
            keyStore.setKeyEntry(alias, keyPair.getPrivate(), keyPassword, new Certificate[]{certificate});
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, keyPassword);
            return keyManagerFactory;
        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException("Error initializing KeyManagerFactory", e);
        }
    }

    // 5. Initialize TrustManagerFactory with the Certificate
    private static TrustManagerFactory initTrustManagerFactory(String alias, X509Certificate certificate) {
        try {
            KeyStore trustStore = KeyStore.getInstance(KEYSTORE_TYPE);
            trustStore.load(null, null);
            trustStore.setCertificateEntry(alias, certificate);
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            return trustManagerFactory;
        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Error initializing TrustManagerFactory", e);
        }
    }

    // 6. Initialize SSLContext with KeyManager and TrustManager
    private static SSLContext initSSLContext(KeyManager[] keyManager, TrustManager[] trustManager) {
        try {
            SSLContext sslContext = SSLContext.getInstance(SSL_PROTOCOL);
            sslContext.init(keyManager, trustManager, RANDOM);
            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException("Error initializing SSLContext", e);
        }
    }

    // Getter for SSLContext
    public SSLContext getSSLContext() {
        return sslContext;
    }
}