package de.MCmoderSD.server.cert;

import com.fasterxml.jackson.databind.JsonNode;
import de.MCmoderSD.server.enums.KeySize;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.shredzone.acme4j.util.KeyPairUtils;

import javax.net.ssl.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

import static de.MCmoderSD.server.enums.KeySize.RSA_4096;

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
    private final char[] keyPassword;
    private final KeyPair privateKey;
    private final X509Certificate certificate;
    private final SSLContext sslContext;

    // Constructor
    public CertManager(JsonNode config) {

        // Check Configuration
        if (config == null || config.isNull() || config.isEmpty()) throw new IllegalArgumentException("Certificate configuration cannot be null or empty");
        if (!config.has("keyPassword") || config.get("keyPassword").isNull()) throw new IllegalArgumentException("Key password is required in the configuration");

        // Load Key Password
        String password = config.get("keyPassword").asText();
        if (password.isBlank()) throw new IllegalArgumentException("Key password cannot be empty");
        keyPassword = password.toCharArray();

        // Declare Paths variables
        File privateKeyFile;
        File certificateFile;
        boolean privateKeyExists = false;
        boolean certificateExists = false;


        // Check if Paths were provided for a provided certificate
        boolean hasPaths = config.has("paths") && !config.get("paths").isNull() && !config.get("paths").isEmpty();
        boolean createIfMissing = hasPaths && config.has("createIfMissing") && !config.get("createIfMissing").isNull() && config.get("createIfMissing").asBoolean();

        if (hasPaths && !createIfMissing) // ToDo: Load existing certificate from paths
            throw new UnsupportedOperationException("Loading existing provided certificates is not yet implemented");
        else if (hasPaths) {

            // Check if files exist
            JsonNode paths = config.get("paths");
            if (!paths.has("privateKey") || paths.get("privateKey").isNull()) throw new IllegalArgumentException("Private key path is required");
            if (!paths.has("certificate") || paths.get("certificate").isNull()) throw new IllegalArgumentException("Certificate path is required");

            // Load Paths
            String privateKeyPath = paths.get("privateKey").asText();
            String certificatePath = paths.get("certificate").asText();

            // Check Paths
            if (privateKeyPath.isBlank()) throw new IllegalArgumentException("Private key path cannot be empty");
            if (certificatePath.isBlank()) throw new IllegalArgumentException("Certificate path cannot be empty");

            // Initialize Private Key and Certificate Files
            privateKeyFile = new File(privateKeyPath);
            certificateFile = new File(certificatePath);

            // Check if files exist and are readable
            privateKeyExists = privateKeyFile.exists() && privateKeyFile.isFile() && privateKeyFile.canRead();
            certificateExists = certificateFile.exists() && certificateFile.isFile() && certificateFile.canRead();
        }

        // Load Private Key and Certificate (if both files exist)
        if (hasPaths && privateKeyExists && certificateExists) // ToDo: Load existing certificate from paths
            throw new UnsupportedOperationException("Loading existing provided certificates is not yet implemented");

        // Load Key Size if provided
        KeySize keySize;
        if (!config.has("keySize") || config.get("keySize").isNull() || KeySize.isValidSize(config.get("keySize").asInt())) keySize = KeySize.getKeySize(config.get("keySize").asInt());
        else keySize = RSA_4096;

        // Load or Create Private Key
        if (hasPaths && privateKeyExists) // ToDo: Load existing private key from
            throw new UnsupportedOperationException("Loading existing private keys is not yet implemented");
        else privateKey = KeyPairUtils.createKeyPair(keySize.getSize());

        // Save Private Key if path provided and file does not exist
        if (hasPaths) // ToDo: Save private key to file
            System.out.println("Saving private keys is not yet implemented");

        // Initialize Certificate (using ACME or Self-Signed)
        if (config.has("acmeSigned") && !config.get("acmeSigned").isNull() && !config.get("acmeSigned").isEmpty()) certificate = useAcmeSigned(privateKey, config.get("acmeSigned"));
        else if (config.has("selfSigned") && !config.get("selfSigned").isNull() && !config.get("selfSigned").isEmpty()) certificate = useSelfSigned(privateKey, config.get("selfSigned"));
        else throw new IllegalArgumentException("Either 'acmeSigned' or 'selfSigned' configuration must be provided");

        // Save Certificate if path provided and file does not exist
        if (hasPaths && !certificateExists) // ToDo: Save certificate to file
            throw new UnsupportedOperationException("Saving certificates is not yet implemented");

        // Check Private Key and Certificate
        // ToDo check validity

        // Initialize SSLContext
        sslContext = initSSLContext(
                initKeyManager(privateKey.getPrivate(), certificate, keyPassword),
                initTrustManager(certificate)
        );
    }

    private X509Certificate useAcmeSigned(KeyPair privateKey, JsonNode config) {

        // Check ACME Config
        if (config == null || config.isNull() || config.isEmpty()) throw new IllegalArgumentException("Certificate configuration cannot be null or empty");
        if (!config.has("email") || config.get("email").isNull()) throw new IllegalArgumentException("Certificate email is required");
        if (!config.has("accountKey") || config.get("accountKey").isNull()) throw new IllegalArgumentException("ACME account key is required");
        if (!config.has("cloudflare") || config.get("cloudflare").isNull() || config.get("cloudflare").isEmpty()) throw new IllegalArgumentException("Cloudflare configuration is required");
        if (!config.has("domains") || config.get("domains").isNull() || config.get("domains").isEmpty() || !config.get("domains").isArray()) throw new IllegalArgumentException("At least one domain is required");

        // Load Cloudflare Config
        JsonNode cloudflare = config.get("cloudflare");
        if (!cloudflare.has("zoneId") || cloudflare.get("zoneId").isNull()) throw new IllegalArgumentException("Cloudflare zone ID is required");
        if (!cloudflare.has("apiToken") || cloudflare.get("apiToken").isNull()) throw new IllegalArgumentException("Cloudflare API token is required");

        // Load Email
        String email = config.get("email").asText();
        if (email.isBlank() || !email.contains("@") || email.contains(" ") || email.startsWith("@") || email.endsWith("@")) throw new IllegalArgumentException("Invalid email address");

        // Load Account Key
        String accountKeyPath = config.get("accountKey").asText();
        if (accountKeyPath.isBlank()) throw new IllegalArgumentException("ACME account key cannot be empty");
        File accountKeyFile = new File(accountKeyPath);
        boolean newAccount = !accountKeyFile.exists() || !accountKeyFile.isFile() || !accountKeyFile.canRead();

        // Load Zone ID and API Token
        String zoneId = cloudflare.get("zoneId").asText();
        String apiToken = cloudflare.get("apiToken").asText();

        // Check Zone ID and API Token
        if (zoneId.isBlank()) throw new IllegalArgumentException("Cloudflare zone ID cannot be empty");
        if (apiToken.isBlank()) throw new IllegalArgumentException("Cloudflare API token cannot be empty");

        // Load Domains
        JsonNode domainsList = config.get("domains");
        String[] domains = new String[domainsList.size()];
        for (var i = 0; i < domainsList.size(); i++) domains[i] = domainsList.get(i).asText();

        // Check Domains
        if (domains.length == 0) throw new IllegalArgumentException("At least one domain must be specified");
        for (var domain : domains) if (domain.isBlank()) throw new IllegalArgumentException("Domain names cannot be empty");

        // Check for debug mode
        boolean debug = config.has("debug") && !config.get("debug").isNull() && config.get("debug").asBoolean();

        // Load or Create Account Key Pair
        KeyPair accountKey;
        if (newAccount) accountKey = KeyPairUtils.createKeyPair(RSA_4096.getSize());
        else {
            try {
                accountKey = KeyPairUtils.readKeyPair(Files.newBufferedReader(accountKeyFile.toPath()));
            } catch (IOException e) {
                throw new RuntimeException("Failed to read ACME account key from file: " + accountKeyFile, e);
            }
        }

        // Initialize ACME
        ACME acme = new ACME(email, accountKey, zoneId, apiToken, debug);

        // Order Certificate
        X509Certificate certificate = acme.orderCertificate(privateKey, domains).getCertificate();

        // Check Private Key and Certificate
        if (privateKey == null || privateKey.getPrivate() == null || privateKey.getPublic() == null) throw new IllegalArgumentException("Private key cannot be null");
        if (certificate == null) throw new IllegalArgumentException("Certificate cannot be null");

        // Save Account Key if new
        if (newAccount) ACME.writeKeyPair(accountKey, accountKeyFile);

        // Return Certificate
        return certificate;
    }

    private X509Certificate useSelfSigned(KeyPair privateKey, JsonNode config) {

        // Check Private Key and Config
        if (privateKey == null || privateKey.getPrivate() == null || privateKey.getPublic() == null) throw new IllegalArgumentException("Private key cannot be null");
        if (config == null || config.isNull() || config.isEmpty()) throw new IllegalArgumentException("Self-signed certificate configuration cannot be null or empty");

        // Initialize Self-Signed Certificate
        SelfSignedCert selfSignedCert = new SelfSignedCert(privateKey, config, RANDOM, BC_PROVIDER, SIGNATURE_ALGORITHM);

        // Obtain Private Key and Certificate
        return selfSignedCert.getCertificate();
    }

    // Initialize KeyManager
    public static KeyManager[] initKeyManager(PrivateKey privateKey, X509Certificate certificate, char[] keyPassword) {
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
    public static TrustManager[] initTrustManager(X509Certificate certificate) {
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
    public static SSLContext initSSLContext(KeyManager[] keyManager, TrustManager[] trustManager) {
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
}