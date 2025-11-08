package de.MCmoderSD.server.cert;

import de.MCmoderSD.server.enums.KeySize;

import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.PublicKey;
import java.security.KeyPair;

import static de.MCmoderSD.server.enums.KeySize.RSA_4096;

@SuppressWarnings({"unused", "UnusedReturnValue"})
public class CertUtil {

    // Constants
    private static final String CERTIFICATE_TYPE = "X.509";
    private static final KeySize DEFAULT_KEY_SIZE = RSA_4096;

    // Static KeyPair Methods
    public static KeyPair createKeyPair() {
        return createKeyPair(DEFAULT_KEY_SIZE);
    }

    public static KeyPair createKeyPair(KeySize keySize) {

        // Check Parameters
        if (keySize == null) throw new IllegalArgumentException("Key size must not be null");

        // Create KeyPair
        KeyPair keyPair = KeyPairUtils.createKeyPair(keySize.getSize());

        // Check KeyPair
        if (keyPair == null) throw new RuntimeException("KeyPair is null");

        // Return KeyPair
        return keyPair;
    }

    // Static IO Methods
    public static KeyPair loadKeyPair(File keyPairFile) {

        // Check Parameters
        if (keyPairFile == null) throw new IllegalArgumentException("KeyPair file must not be null");
        if (!keyPairFile.exists() || !keyPairFile.isFile() || !keyPairFile.canRead()) throw new IllegalArgumentException("KeyPair file does not exist or is not readable");

        // Load KeyPair
        KeyPair keyPair;
        try (var bufferedReader = Files.newBufferedReader(keyPairFile.toPath())) {
            keyPair = KeyPairUtils.readKeyPair(bufferedReader);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read key pair from file", e);
        }

        // Check KeyPair
        if (keyPair == null) throw new IllegalArgumentException("KeyPair is null");

        // Return KeyPair
        return keyPair;
    }

    public static File writeKeyPair(KeyPair keyPair, File keyPairFile) {

        // Check Parameters
        if (keyPair == null) throw new IllegalArgumentException("KeyPair must not be null");
        if (keyPairFile == null) throw new IllegalArgumentException("KeyPair file must not be null");

        // Create KeyPair File
        if (keyPairFile.exists()) throw new IllegalArgumentException("KeyPair file already exists");
        try {
            if (!keyPairFile.mkdirs()) throw new IOException("Failed to create directories for KeyPair file");
            if (!keyPairFile.createNewFile()) throw new IOException("Failed to create new KeyPair file");
        } catch (IOException e) {
            throw new RuntimeException("Failed to create KeyPair file", e);
        }

        // Write KeyPair to File
        try (var bufferedWriter = Files.newBufferedWriter(keyPairFile.toPath())) {
            KeyPairUtils.writeKeyPair(keyPair, bufferedWriter);
        } catch (IOException e) {
            throw new RuntimeException("Failed to write key pair to file", e);
        }

        // Check KeyPair File
        if (!keyPairFile.exists() || !keyPairFile.isFile()) throw new RuntimeException("KeyPair file does not exist after writing");

        // Return KeyPair File
        return keyPairFile;
    }

    public static X509Certificate loadCertificate(File certificateFile) {

        // Check Parameters
        if (certificateFile == null) throw new IllegalArgumentException("Certificate file must not be null");
        if (!certificateFile.exists() || !certificateFile.isFile() || !certificateFile.canRead()) throw new IllegalArgumentException("Certificate file does not exist or is not readable");

        try (var bis = new BufferedInputStream(new FileInputStream(certificateFile))) {

            // Initialize Certificate Factory
            CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);

            // Read Certificates
            var certificate = certificateFactory.generateCertificate(bis);
            if (certificate == null) throw new RuntimeException("No certificate found in file");

            // Return as X509Certificate
            return (X509Certificate) certificate;

        } catch (IOException | CertificateException e) {
            throw new RuntimeException("Failed to load certificate from file", e);
        }
    }

    public static X509Certificate[] loadCertificateChain(File certificateFile) {

        // Check Parameters
        if (certificateFile == null) throw new IllegalArgumentException("Certificate file must not be null");
        if (!certificateFile.exists() || !certificateFile.isFile() || !certificateFile.canRead()) throw new IllegalArgumentException("Certificate file does not exist or is not readable");

        try (var bis = new BufferedInputStream(new FileInputStream(certificateFile))) {

            // Initialize Certificate Factory
            CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);

            // Read Certificates
            var certificates = certificateFactory.generateCertificates(bis);
            if (certificates == null || certificates.isEmpty()) throw new RuntimeException("No certificates found in file");

            // Convert to X509Certificate array
            X509Certificate [] x509Certificates = new X509Certificate[certificates.size()];
            for (var i = 0; i < certificates.size(); i++) x509Certificates[i] = (X509Certificate) certificates.toArray()[i];
            return x509Certificates;

        } catch (IOException | CertificateException e) {
            throw new RuntimeException("Failed to load certificate from file", e);
        }
    }

    public static File writeCertificate(Certificate certificate, File certificateFile) {

        // Check Parameters
        if (certificate == null) throw new IllegalArgumentException("Certificate must not be null");
        if (certificateFile == null) throw new IllegalArgumentException("Certificate file must not be null");

        // Create Certificate File
        if (certificateFile.exists()) throw new IllegalArgumentException("Certificate file already exists");
        try {
            if (!certificateFile.mkdirs()) throw new IOException("Failed to create directories for Certificate file");
            if (!certificateFile.createNewFile()) throw new IOException("Failed to create new Certificate file");
        } catch (IOException e) {
            throw new RuntimeException("Failed to create Certificate file", e);
        }

        // Write Certificate to File
        try (var bufferedWriter = Files.newBufferedWriter(certificateFile.toPath())) {
            certificate.writeCertificate(bufferedWriter);
        } catch (IOException e) {
            throw new RuntimeException("Failed to write certificate to file", e);
        }

        // Check Certificate File
        if (!certificateFile.exists() || !certificateFile.isFile()) throw new RuntimeException("Certificate file does not exist after writing");

        // Return Certificate File
        return certificateFile;
    }

    public static File writeCSR(CSRBuilder csrBuilder, File csrFile) {

        // Check Parameters
        if (csrBuilder == null) throw new IllegalArgumentException("CSR Builder must not be null");
        if (csrFile == null) throw new IllegalArgumentException("CSR file must not be null");

        // Create CSR File
        if (csrFile.exists()) throw new IllegalArgumentException("CSR file already exists");
        try {
            if (!csrFile.mkdirs()) throw new IOException("Failed to create directories for CSR file");
            if (!csrFile.createNewFile()) throw new IOException("Failed to create new CSR file");
        } catch (IOException e) {
            throw new RuntimeException("Failed to create CSR file", e);
        }

        // Write CSR to File
        try (var bufferedWriter = Files.newBufferedWriter(csrFile.toPath())) {
            csrBuilder.write(bufferedWriter);
        } catch (IOException e) {
            throw new RuntimeException("Failed to write CSR to file", e);
        }

        // Check CSR File
        if (!csrFile.exists() || !csrFile.isFile()) throw new RuntimeException("CSR file does not exist after writing");

        // Return CSR File
        return csrFile;
    }

    public static boolean verifyCertificate(X509Certificate certificate, PublicKey publicKey) {

        // Check Parameters
        if (certificate == null) throw new IllegalArgumentException("Certificate must not be null");
        if (publicKey == null) throw new IllegalArgumentException("Public key must not be null");

        // Verify Certificate
        try {
            certificate.verify(publicKey);
        } catch (GeneralSecurityException e) {
            return false;
        }

        // If no exceptions were thrown, the certificate is valid
        return isCertificateValid(certificate);
    }

    public static boolean isCertificateValid(X509Certificate certificate) {

        // Check Parameters
        if (certificate == null) throw new IllegalArgumentException("Certificate must not be null");

        // Check Certificate Validity Period
        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            return false;
        }

        // If no exceptions were thrown, the certificate is valid
        return true;
    }
}