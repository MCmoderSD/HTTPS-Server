package de.MCmoderSD.server.cert;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.OperatorCreationException;

import tools.jackson.databind.JsonNode;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;

import static org.bouncycastle.asn1.x509.GeneralName.*;
import static org.bouncycastle.asn1.x500.style.BCStyle.*;
import static org.bouncycastle.asn1.x509.Extension.*;
import static org.bouncycastle.asn1.x509.KeyUsage.*;
import static org.bouncycastle.asn1.x509.KeyPurposeId.*;

import static java.util.Calendar.*;

@SuppressWarnings("unused")
public class SelfSigner {

    // Constants
    private final SecureRandom RANDOM;
    private final String BC_PROVIDER;
    private final String SIGNATURE_ALGORITHM;

    // Attributes for the certificate subject
    private final String CN;            // Common Name
    private final String O;             // Organization
    private final String OU;            // Organizational Unit
    private final String L;             // Locality
    private final String ST;            // State or Province
    private final String C;             // Country (2-letter code)
    private final GeneralName[] SANs;   // Subject Alternative Names

    // Attributes
    private final X509Certificate certificate;

    // Constructor
    public SelfSigner(KeyPair privateKey, JsonNode config, SecureRandom RANDOM, String BC_PROVIDER, String SIGNATURE_ALGORITHM) {

        // Check Constants
        if (RANDOM == null) throw new IllegalArgumentException("SecureRandom cannot be null");
        if (BC_PROVIDER == null || BC_PROVIDER.isBlank()) throw new IllegalArgumentException("BC_PROVIDER cannot be null or empty");
        if (SIGNATURE_ALGORITHM == null || SIGNATURE_ALGORITHM.isBlank()) throw new IllegalArgumentException("SIGNATURE_ALGORITHM cannot be null or empty");

        // Set constants
        this.RANDOM = RANDOM;
        this.BC_PROVIDER = BC_PROVIDER;
        this.SIGNATURE_ALGORITHM = SIGNATURE_ALGORITHM;

        // Check Configuration
        if (privateKey == null) throw new IllegalArgumentException("privateKey cannot be null");
        if (config == null || config.isNull() || config.isEmpty()) throw new IllegalArgumentException("Certificate configuration cannot be null or empty");

        // Load Expiration Days
        if (!config.has("expirationDays") || config.get("expirationDays").isNull() || !config.get("expirationDays").isNumber()) throw new IllegalArgumentException("Expiration days must be provided and be a valid long integer");
        var expirationMillis = config.get("expirationDays").asLong() * 24 * 60 * 60 * 1000; // Convert days to milliseconds
        if (expirationMillis <= 0 || expirationMillis > 366L * 24L * 60L * 60L * 1000L) throw new IllegalArgumentException("Expiration days must be between 1 and 366");

        // Load Subject Details
        JsonNode subject = config.get("subject");
        CN = subject.has("commonName") ?            subject.get("commonName").asString()            : null;
        O  = subject.has("organization") ?          subject.get("organization").asString()          : null;
        OU = subject.has("organizationalUnit") ?    subject.get("organizationalUnit").asString()    : null;
        L  = subject.has("locality") ?              subject.get("locality").asString()              : null;
        ST = subject.has("state") ?                 subject.get("state").asString()                 : null;
        C  = subject.has("country") ?               subject.get("country").asString()               : null;

        // Validate subject details
        if (CN == null || CN.isBlank()) throw new IllegalArgumentException("Common Name (CN) is required in the subject");
        if (C != null && C.length() != 2) throw new IllegalArgumentException("Country (C) must be a 2-letter code");

        // Load Subject Alternative Names (SANs)
        if (!config.has("subjectAltNames")) SANs = new GeneralName[] { new GeneralName(dNSName, CN) };
        else SANs = parseSANs(config.get("subjectAltNames"));

        // Build and sign the certificate
        certificate = signCertificate(buildCert(privateKey.getPublic(), expirationMillis), privateKey);
    }

    // Parse SANs from JSON
    private GeneralName[] parseSANs(JsonNode san) {

        // Check SAN node
        if (san == null || san.isNull() || san.isEmpty()) throw new IllegalArgumentException("Subject Alternative Names (SAN) cannot be null or empty");

        // Split the SAN into DNS and IP entries
        ArrayList<GeneralName> sanList = new ArrayList<>();
        JsonNode dnsEntries = san.has("dns") ? san.get("dns") : null;
        JsonNode ipEntries = san.has("ip") ? san.get("ip") : null;

        // Parse DNS entries
        if (dnsEntries != null && dnsEntries.isArray()) for (var i = 0; i < dnsEntries.size(); i++) {
            String dns = dnsEntries.get(i).asString();
            if (dns != null && !dns.isBlank()) sanList.add(new GeneralName(dNSName, dns));
        }

        // Parse IP entries
        if (ipEntries != null && ipEntries.isArray()) for (var i = 0; i < ipEntries.size(); i++) {
            String ip = ipEntries.get(i).asString();
            if (ip != null && !ip.isBlank()) sanList.add(new GeneralName(GeneralName.iPAddress, ip));
        }

        // Check if at least one SAN is provided
        if (sanList.isEmpty()) sanList.add(new GeneralName(dNSName, CN));

        // Convert to array and return
        return sanList.toArray(new GeneralName[0]);
    }

    // Build the X.509 Certificate
    private JcaX509v3CertificateBuilder buildCert(PublicKey publicKey, long expirationMillis) {

        // Check Inputs
        if (publicKey == null) throw new IllegalArgumentException("Public key cannot be null");
        if (expirationMillis <= 0) throw new IllegalArgumentException("Expiration milliseconds must be positive");

        // Build the subject
        X500NameBuilder subjectBuilder = new X500NameBuilder(INSTANCE);
        subjectBuilder.addRDN(BCStyle.CN, CN);                                      // Common Name
        if (O  != null  && !O.isBlank())    subjectBuilder.addRDN(BCStyle.O, O);    // Organization
        if (OU != null  && !OU.isBlank())   subjectBuilder.addRDN(BCStyle.OU, OU);  // Organizational Unit
        if (L  != null  && !L.isBlank())    subjectBuilder.addRDN(BCStyle.L, L);    // Locality
        if (ST != null  && !ST.isBlank())   subjectBuilder.addRDN(BCStyle.ST, ST);  // State or Province
        if (C != null   && !C.isBlank())    subjectBuilder.addRDN(BCStyle.C, C);    // Country (2-letter code)
        X500Name subject = subjectBuilder.build(); // Build

        // Generate a RANDOM positive serial number
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

    // Sign the certificate with the private key
    private X509Certificate signCertificate(JcaX509v3CertificateBuilder certBuilder, KeyPair privateKey) {
        try {

            // Check inputs
            if (certBuilder == null) throw new IllegalArgumentException("Certificate builder cannot be null");
            if (privateKey == null || privateKey.getPrivate() == null || privateKey.getPublic() == null) throw new IllegalArgumentException("Private key cannot be null");

            // Create a Content Signer
            var signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                    .setProvider(BC_PROVIDER)
                    .build(privateKey.getPrivate());

            // Build the certificate
            var cert = new JcaX509CertificateConverter()
                    .setProvider(BC_PROVIDER)
                    .getCertificate(certBuilder.build(signer));

            // Validate the certificate
            cert.verify(privateKey.getPublic());
            cert.checkValidity();

            // Return the signed certificate
            return cert;

        } catch (CertificateException | NoSuchAlgorithmException | SignatureException | OperatorCreationException | InvalidKeyException | NoSuchProviderException e) {
            throw new RuntimeException("Error signing certificate", e);
        }
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public X509Certificate[] getChain() {
        return new X509Certificate[] { certificate };
    }
}