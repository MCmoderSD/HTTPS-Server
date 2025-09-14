package de.MCmoderSD.server.cert;

import com.fasterxml.jackson.databind.JsonNode;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.net.ssl.*;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;

import static java.util.Calendar.*;
import static org.bouncycastle.asn1.x509.Extension.*;
import static org.bouncycastle.asn1.x509.KeyUsage.*;
import static org.bouncycastle.asn1.x509.KeyPurposeId.*;
import static org.bouncycastle.asn1.x500.style.BCStyle.*;

public class CertManager {

    // Constants
    private static final String KEY_ALGORITHM = "RSA";
    private static final int KEY_SIZE = 4096;
    private static final String BC_PROVIDER = "BC";
    private static final String SIGNATURE_ALGORITHM = "SHA512withRSA";
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String CERT_ALIAS = "selfsigned";
    private static final String SSL_PROTOCOL = "TLS";


    // Instance of Bouncy Castle provider and SecureRandom
    private static final SecureRandom RANDOM;
    static {
        RANDOM = new SecureRandom();
        if (Security.getProvider(BC_PROVIDER) == null) Security.addProvider(new BouncyCastleProvider());
    }


    // Certificate configuration
    private final char[] keyPassword;       // Password for KeyStore
    private final long expirationMillis;    // Validity period in milliseconds

    // Attributes for the certificate subject
    private final String CN;            // Common Name
    private final String O;             // Organization
    private final String OU;            // Organizational Unit
    private final String L;             // Locality
    private final String ST;            // State or Province
    private final String C;             // Country (2-letter code)
    private final GeneralName[] SANs;   // Subject Alternative Names

    // SSLContext
    private final SSLContext sslContext;

    // Constructor
    public CertManager(JsonNode config) {

        // Load password and expiration from JSON config
        keyPassword = config.has("keyPassword") ? config.get("keyPassword").asText().toCharArray() : null;
        expirationMillis = config.has("expirationDays") ? config.get("expirationDays").asLong() * 24L * 60L * 60L * 1000L : 366 * 24L * 60L * 60L * 1000L;

        // Validate password and expiration
        if (keyPassword == null || keyPassword.length == 0) throw new IllegalArgumentException("Key password is required");
        if (expirationMillis <= 0 || expirationMillis > 366L * 24L * 60L * 60L * 1000L) throw new IllegalArgumentException("Expiration days must be between 1 and 366");

        // Load subject details from JSON config
        JsonNode subject = config.get("subject");
        CN = subject.has("commonName") ?            subject.get("commonName").asText()          : null;
        O  = subject.has("organization") ?          subject.get("organization").asText()        : null;
        OU = subject.has("organizationalUnit") ?    subject.get("organizationalUnit").asText()  : null;
        L  = subject.has("locality") ?              subject.get("locality").asText()            : null;
        ST = subject.has("state") ?                 subject.get("state").asText()               : null;
        C  = subject.has("country") ?               subject.get("country").asText()             : null;

        // Validate subject details
        if (CN == null || CN.isBlank()) throw new IllegalArgumentException("Common Name (CN) is required in the subject");
        if (C != null && C.length() != 2) throw new IllegalArgumentException("Country (C) must be a 2-letter code");

        // Load SANs from JSON config
        if (config.has("subjectAltNames")) SANs = parseSANs(config.get("subjectAltNames"));
        else SANs = new GeneralName[] {new GeneralName(GeneralName.dNSName, CN)};

        // Generate KeyPair, Build and Sign Certificate, Initialize KeyManager and TrustManager
        var keyPair = generateKeyPair();                                        // 1. Generate KeyPair
        var certBuilder = buildCert(keyPair.getPublic());                       // 2. Build the certificate
        var certificate = signCertificate(certBuilder, keyPair);                // 3. Sign the certificate
        var keyManagerFactory = initKeyManagerFactory(keyPair, certificate);    // 4. Initialize KeyManagerFactory
        var trustManagerFactory = initTrustManagerFactory(certificate);         // 5. Initialize TrustManagerFactory
        sslContext = initSSLContext(keyManagerFactory, trustManagerFactory);    // 6. Initialize SSLContext
    }

    // Parse SANs from JSON
    private GeneralName[] parseSANs(JsonNode san) {

        // Split the SAN into DNS and IP entries
        ArrayList<GeneralName> sanList = new ArrayList<>();
        JsonNode dnsEntries = san.has("dns") ? san.get("dns") : null;
        JsonNode ipEntries = san.has("ip") ? san.get("ip") : null;

        // Parse DNS entries
        if (dnsEntries != null && dnsEntries.isArray()) for (var i = 0; i < dnsEntries.size(); i++) {
            String dns = dnsEntries.get(i).asText();
            if (dns != null && !dns.isBlank()) sanList.add(new GeneralName(GeneralName.dNSName, dns));
        }

        // Parse IP entries
        if (ipEntries != null && ipEntries.isArray()) for (var i = 0; i < ipEntries.size(); i++) {
            String ip = ipEntries.get(i).asText();
            if (ip != null && !ip.isBlank()) sanList.add(new GeneralName(GeneralName.iPAddress, ip));
        }

        // Check if at least one SAN is provided
        if (sanList.isEmpty()) sanList.add(new GeneralName(GeneralName.dNSName, CN));

        // Convert to array and return
        return sanList.toArray(new GeneralName[0]);
    }

    // 1. Generate RSA KeyPair
    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
            keyPairGenerator.initialize(KEY_SIZE, RANDOM);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Error generating KeyPair", e);
        }
    }

    // 2. Build the X.509 Certificate
    private JcaX509v3CertificateBuilder buildCert(PublicKey publicKey) {

        // Build the subject
        X500NameBuilder subjectBuilder = new X500NameBuilder(INSTANCE);
        subjectBuilder.addRDN(BCStyle.CN, CN);                                      // Common Name
        if (O  != null  && !O.isBlank())    subjectBuilder.addRDN(BCStyle.O, O);    // Organization
        if (OU != null  && !OU.isBlank())   subjectBuilder.addRDN(BCStyle.OU, OU);  // Organizational Unit
        if (L  != null  && !L.isBlank())    subjectBuilder.addRDN(BCStyle.L, L);    // Locality
        if (ST != null  && !ST.isBlank())   subjectBuilder.addRDN(BCStyle.ST, ST);  // State or Province
        if (C != null   && !C.isBlank())    subjectBuilder.addRDN(BCStyle.C, C);    // Country (2-letter code)
        X500Name subject = subjectBuilder.build(); // Build

        // Generate a random positive serial number
        BigInteger serial;
        do serial = new BigInteger(160, RANDOM); // up to 160 bits
        while (serial.signum() <= 0); // must be positive

        // Set validity period
        Calendar calendar = Calendar.getInstance();
        calendar.add(DATE, 0);
        calendar.set(HOUR_OF_DAY, 0);
        calendar.set(MINUTE, 0);
        calendar.set(SECOND, 0);
        calendar.set(MILLISECOND, 0);
        Date validFrom = calendar.getTime();
        Date validTill = new Date(validFrom.getTime() + expirationMillis);

        // Create the certificate builder
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,                // issuer
                serial,                 // serial number
                validFrom,              // issued at
                validTill,              // expires at
                subject,                // subject
                publicKey               // public key
        );

        try {
            certBuilder.addExtension(basicConstraints, true, new BasicConstraints(false));
            certBuilder.addExtension(keyUsage, true, new KeyUsage(digitalSignature | keyEncipherment | keyAgreement));
            certBuilder.addExtension(extendedKeyUsage, false, new ExtendedKeyUsage(id_kp_serverAuth));
            certBuilder.addExtension(subjectAlternativeName, false, new GeneralNames(SANs));
        } catch (CertIOException e) {
            throw new RuntimeException("Error adding extensions to certificate", e);
        }

        // Return the certificate builder
        return certBuilder;
    }

    // 3. Sign the certificate with the private key
    private X509Certificate signCertificate(JcaX509v3CertificateBuilder certBuilder, KeyPair keyPair) {
        try {
            return new JcaX509CertificateConverter()
                    .setProvider(BC_PROVIDER)
                    .getCertificate(
                            certBuilder.build(
                                    new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                                            .setProvider(BC_PROVIDER)
                                            .build(keyPair.getPrivate())
                            )
                    );
        } catch (OperatorCreationException | CertificateException e) {
            throw new RuntimeException("Error signing certificate", e);
        }
    }

    // 4. Initialize KeyManagerFactory with the KeyPair and Certificate
    private KeyManagerFactory initKeyManagerFactory(KeyPair keyPair, X509Certificate certificate) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(null, null);
            keyStore.setKeyEntry(CERT_ALIAS, keyPair.getPrivate(), keyPassword, new Certificate[]{certificate});
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, keyPassword);
            return keyManagerFactory;
        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException("Error initializing KeyManagerFactory", e);
        }
    }

    // 5. Initialize TrustManagerFactory with the Certificate
    private TrustManagerFactory initTrustManagerFactory(X509Certificate certificate) {
        try {
            KeyStore trustStore = KeyStore.getInstance(KEYSTORE_TYPE);
            trustStore.load(null, null);
            trustStore.setCertificateEntry(CERT_ALIAS, certificate);
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            return trustManagerFactory;
        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Error initializing TrustManagerFactory", e);
        }
    }

    // 6. Initialize SSLContext with KeyManager and TrustManager
    private SSLContext initSSLContext(KeyManagerFactory keyManagerFactory, TrustManagerFactory trustManagerFactory) {
        try {
            SSLContext sslContext = SSLContext.getInstance(SSL_PROTOCOL);
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), RANDOM);
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