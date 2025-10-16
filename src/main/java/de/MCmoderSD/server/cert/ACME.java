package de.MCmoderSD.server.cert;

import de.MCmoderSD.cloudflare.core.CloudflareClient;
import de.MCmoderSD.cloudflare.objects.DnsRecord;
import de.MCmoderSD.server.enums.KeySize;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;

import static de.MCmoderSD.cloudflare.enums.RecordType.TXT;
import static de.MCmoderSD.server.enums.KeySize.RSA_4096;
import static org.shredzone.acme4j.Status.*;
import static org.shredzone.acme4j.challenge.Dns01Challenge.TYPE;

@SuppressWarnings({"unused", "BooleanMethodIsAlwaysInverted", "UnusedReturnValue", "DuplicateExpressions"})
public class ACME {

    // Constants
    private static final String PRODUCTION_SERVER_URL = "https://acme-v02.api.letsencrypt.org/directory";
    private static final String STAGING_SERVER_URL = "https://acme-staging-v02.api.letsencrypt.org/directory";
    private static final String CHALLENGE_PREFIX = "_acme-challenge.";
    private static final String WILDCARD_PREFIX = "*.";
    private static final String SPACE = " ";
    private static final String AT = "@";
    private static final int TTL = 60;

    // Credentials
    private final String email;
    private final KeyPair accountKey;

    // Attributes
    private final CloudflareClient cloudflareClient;
    private final Session session;
    private final Account account;
    private final boolean debug;

    // Constructors with CloudflareClient
    public ACME(String email, KeyPair accountKey, CloudflareClient cloudflareClient) {
        this(email, accountKey, cloudflareClient, false);
    }

    // Constructors with Zone ID and API Token
    public ACME(String email, KeyPair accountKey, String zoneId, String apiToken) {
        this(email, accountKey, zoneId, apiToken, false);
    }

    // Constructors with Zone ID and API Token and Debug
    public ACME(String email, KeyPair accountKey, String zoneId, String apiToken, boolean debug) {
        this(email, accountKey, new CloudflareClient(zoneId, apiToken), debug);
    }

    // Main Constructor
    public ACME(String email, KeyPair accountKey, CloudflareClient cloudflareClient, boolean debug) {

        // Check Parameters
        if (!validateEmail(email)) throw new IllegalArgumentException("Email must be a valid email address");
        if (accountKey == null) throw new IllegalArgumentException("Account Key must not be null");
        if (cloudflareClient == null) throw new IllegalArgumentException("Cloudflare Client must not be null");

        // Assign Parameters
        this.email = email;
        this.accountKey = accountKey;

        // Assign Attributes
        this.cloudflareClient = cloudflareClient;
        this.debug = debug;

        // Initialize ACME Session
        session = new Session(debug ? STAGING_SERVER_URL : PRODUCTION_SERVER_URL);
        if (debug) System.out.println("ACME Debug Mode enabled: Using Let's Encrypt Staging Server");

        try {

            // Initialize ACME Account
            account = new AccountBuilder()
                    .addEmail(email)
                    .useKeyPair(accountKey)
                    .agreeToTermsOfService()
                    .create(session);

            if (debug) System.out.println("ACME Created Account\n");

        } catch (AcmeException e) {
            throw new RuntimeException("Failed to create or retrieve ACME account", e);
        }
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // Validate Email Address
    private static boolean validateEmail(String email) {

        // Check Parameters
        if (email == null || email.isBlank()) return false;
        if (!email.contains(AT) || email.contains(SPACE)) return false;

        // Basic Email Validation
        return email.chars().filter(c -> c == AT.toCharArray()[0]).count() == 1;
    }

    // Normalize Domain
    private static String normalizeDomain(String domain) {

        // Check Parameters
        if (domain == null || domain.isBlank() || domain.contains(SPACE)) throw new IllegalArgumentException("Domain must be a valid domain");

        // Normalize Domain
        domain = domain.toLowerCase();
        if (domain.startsWith(WILDCARD_PREFIX)) return normalizeDomain(domain.substring(2));
        if (domain.startsWith(CHALLENGE_PREFIX)) return normalizeDomain(domain.substring(16));
        return domain;
    }

    // Create ACME Order
    private static Order createOrder(Account account, String... domains) {

        // Check Parameters
        if (account == null) throw new IllegalArgumentException("Account must not be null");
        if (domains == null || domains.length == 0) throw new IllegalArgumentException("At least one domain must be provided");
        for (var domain : domains) if (domain == null || domain.isBlank() || domain.contains(SPACE)) throw new IllegalArgumentException("Domain must be a valid domain");

        try {

            // Create Order
            return account.newOrder()
                    .domains(domains)
                    .create();

        } catch (AcmeException e) {
            throw new RuntimeException("Failed to create order for domains: " + String.join(", ", domains), e);
        }
    }

    // Create ACME DNS-01 TXT Record
    private DnsRecord createAcmeRecord(String domain, String digest) {

        // Check Parameters
        if (domain == null || domain.isBlank() || domain.contains(SPACE)) throw new IllegalArgumentException("Domain must be a valid domain");
        if (digest == null || digest.isBlank() || digest.contains(SPACE)) throw new IllegalArgumentException("Digest must be a valid digest");

        // Normalize Domain
        domain = normalizeDomain(domain);
        if (debug) System.out.println("ACME Normalized Domain for TXT record: " + domain);

        // Check for existing ACME TXT records and remove them
        HashSet<DnsRecord> records = cloudflareClient.getRecords();
        records.removeIf(dnsRecord -> !dnsRecord.getName().contains(CHALLENGE_PREFIX));
        records.forEach(cloudflareClient::deleteRecord);
        HashSet<String> recordIds = new HashSet<>(cloudflareClient.getRecordMap().keySet());
        for (var record : records) if (recordIds.contains(record.getId())) throw new RuntimeException("Failed to delete existing ACME TXT record for domain: " + domain);
        if (debug) System.out.println("ACME Deleted existing TXT records for domain: " + domain);


        // Create TXT record
        DnsRecord record = cloudflareClient.createRecord(DnsRecord.builder(TXT)
                .name(CHALLENGE_PREFIX + domain)
                .content(digest)
                .ttl(TTL)
                .buildJson()
        );

        // Check Record Creation
        var challengeRecord = cloudflareClient.getRecordMap().get(record.getId());
        if (challengeRecord == null) throw new RuntimeException("Failed to create ACME TXT record for domain: " + domain);
        if (!challengeRecord.getName().equals(CHALLENGE_PREFIX + domain) || !challengeRecord.getContent().equals(digest)) throw new RuntimeException("Created ACME TXT record does not match expected values for domain: " + domain);
        if (debug) System.out.println("ACME Created TXT record: " + challengeRecord.getName() + " -> " + challengeRecord.getContent());
        return challengeRecord;
    }

    // Delete ACME DNS-01 TXT Record
    private boolean deleteAcmeRecord(DnsRecord record) {

        // Check Parameters
        if (record == null) throw new IllegalArgumentException("Record must not be null");
        if (!record.getType().equals(TXT)) throw new IllegalArgumentException("Record must be a TXT record");

        // Delete Record
        return cloudflareClient.deleteRecord(record);
    }

    // Order Certificate for Domains
    public Certificate orderCertificate(KeyPair domainKey, String... domains) {

        // Check Parameters
        if (domainKey == null) throw new IllegalArgumentException("Domain key must not be null");
        if (domainKey.equals(accountKey)) throw new IllegalArgumentException("Account key must not be the same key");
        if (domains == null || domains.length == 0) throw new IllegalArgumentException("At least one domain must be provided");
        for (var domain : domains) if (domain == null || domain.isBlank() || domain.contains(SPACE)) throw new IllegalArgumentException("Domain must be a valid domain");


        if (debug) System.out.println("ACME Ordering Certificate for domains: " + String.join(", ", domains));


        // Normalize Domains
        domains = Arrays.stream(domains)
                .map(String::toLowerCase)                           // Convert to lowercase
                .distinct()                                         // Remove duplicates
                .sorted(Comparator.comparingInt(String::length))    // Sort by length (shortest first)
                .toArray(String[]::new);                            // Collect back to array


        if (debug) System.out.println("ACME Normalized Domains: " + String.join(", ", domains));


        // Check for wildcards
        boolean hasWildcard = Arrays.stream(domains).anyMatch(domain -> domain.startsWith(WILDCARD_PREFIX));
        if (hasWildcard) if (domains[0].startsWith(WILDCARD_PREFIX)) {

            // Only wildcard domain provided
            String baseDomain = domains[0].substring(2);
            if (baseDomain.chars().filter(c -> c == '.').count() != 1) throw new IllegalArgumentException("When using a wildcard domain, a base domain must also be provided");
            domains = new String[]{baseDomain, domains[0]};

        } else {

            // Multiple domains provided, only keep base and wildcard
            String wildcardDomain = Arrays.stream(domains).filter(d -> d.startsWith(WILDCARD_PREFIX)).findFirst().orElseThrow();
            domains = new String[]{domains[0], wildcardDomain};
        }


        if (debug) System.out.println("ACME Final Domains for Order: " + String.join(", ", domains));


        // Create Order
        Order order = createOrder(account, domains);
        if (order == null) throw new RuntimeException("Order is null");
        if (debug) System.out.println("ACME Created Order for domains: " + String.join(", ", domains));


        // Handle Authorizations
        var authorizations = order.getAuthorizations();
        if (debug) System.out.println("ACME Handling " + authorizations.size() + " Authorizations...\n");

        // Loop through Authorizations
        for (var authorization : authorizations) {

            // Check Authorization
            if (authorization == null) throw new RuntimeException("Authorization is null");

            // Get Domain from Authorization
            String domain = authorization.getIdentifier().getDomain();

            // Check if expired
            Instant expiry = authorization.getExpires().orElseGet(Instant::now);
            if (Instant.now().isAfter(expiry)) throw new RuntimeException("Authorization for domain " + domain + " has expired at " + expiry);

            // Skip if already valid
            if (debug && authorization.getStatus() == VALID) System.out.println("ACME Authorization for domain " + domain + " is already valid, skipping...\n");
            else if (debug) System.out.println("ACME Handling Authorization for domain: " + domain);
            if (authorization.getStatus() == VALID) continue;


            // Find DNS-01 Challenge and get Digest
            Challenge challenge = authorization.findChallenge(TYPE).orElseThrow(() -> new RuntimeException("No DNS-01 challenge found for domain: " + domain));
            if (challenge == null) throw new RuntimeException("DNS-01 challenge is null for domain: " + domain);
            String digest = ((Dns01Challenge) challenge).getDigest();
            if (digest == null || digest.isBlank()) throw new RuntimeException("Challenge digest is null or empty for domain: " + digest);


            // Create ACME TXT Record and wait for propagation
            DnsRecord acmeRecord = createAcmeRecord(domain, digest);
            var wait = new BigDecimal(TTL).multiply(BigDecimal.valueOf(5d / 4d)).movePointRight(3).toBigInteger().longValue();
            if (debug) System.out.println("ACME Waiting " + wait / 1000 + "ms for DNS propagation...");
            sleep(wait);


            // Trigger Challenge
            try {
                challenge.trigger();
                if (debug) System.out.println("ACME Triggered DNS-01 challenge for domain: " + domain);
            } catch (AcmeException e) {
                if (!deleteAcmeRecord(acmeRecord)) throw new RuntimeException("Failed to delete ACME TXT record after challenge trigger failure for domain: " + domain);
                throw new RuntimeException("Failed to trigger challenge for domain: " + domain, e);
            }


            try {
                do {
                    if (debug) System.out.println("ACME Polling for challenge status for domain: " + domain + "...");

                    // Fetch Challenge Status
                    try {
                        challenge.fetch();
                    } catch (AcmeException e) {
                        throw new RuntimeException("Failed to fetch challenge status for domain: " + domain, e);
                    }

                    // Check Challenge Status
                    Status status = challenge.getStatus();
                    switch (status) {
                        case INVALID -> throw new RuntimeException("Challenge for domain " + domain + " is invalid");
                        case REVOKED -> throw new RuntimeException("Challenge for domain " + domain + " has been revoked");
                        case DEACTIVATED -> throw new RuntimeException("Challenge for domain " + domain + " has been deactivated");
                        case EXPIRED -> throw new RuntimeException("Challenge for domain " + domain + " has expired");
                        case CANCELED -> throw new RuntimeException("Challenge for domain " + domain + " has been canceled");
                    }

                    // Break if order is valid or ready
                    if (status == READY || status == VALID) break;

                    // Wait before polling again
                    sleep(new BigDecimal(TTL).multiply(BigDecimal.valueOf(5d / 4d - 1d)).movePointRight(3).toBigInteger().longValue());

                } while (challenge.getStatus() == PENDING || challenge.getStatus() == PROCESSING || challenge.getStatus() != READY || challenge.getStatus() != VALID);
                if (debug) System.out.println("ACME Challenge for domain " + domain + " is now " + challenge.getStatus());

            } catch (RuntimeException e) {
                if (!deleteAcmeRecord(acmeRecord)) throw new RuntimeException("Failed to delete ACME TXT record after challenge polling failure for domain: " + domain);
                throw e;
            }


            // Delete ACME TXT Record
            if (!deleteAcmeRecord(acmeRecord)) throw new RuntimeException("Failed to delete ACME TXT record for domain: " + domain);
            if (debug) System.out.println("ACME Deleted TXT record: " + acmeRecord.getName() + " -> " + acmeRecord.getContent() + "\n");
        }


        // Create CSR Builder
        CSRBuilder csrBuilder = new CSRBuilder();
        for (var domain : domains) csrBuilder.addDomain(domain);
        csrBuilder.setCommonName(hasWildcard ? domains[1] : domains[0]);
        if (debug) System.out.println("ACME Created CSR Builder with domains: " + String.join(", ", domains));


        // Sign CSR with Domain Key Pair
        try {
            csrBuilder.sign(domainKey);
            if (debug) System.out.println("ACME Signed CSR with domain key");
        } catch (IOException e) {
            throw new RuntimeException("Failed to sign CSR", e);
        }


        // Build CSR
        byte[] csr;
        try {
            csr = csrBuilder.getEncoded();
            if (csr == null || csr.length == 0) throw new RuntimeException("CSR is null or empty");
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode CSR", e);
        }


        // Finalize Order
        try {
            order.execute(csr);
            if (debug) System.out.println("ACME Ordered CSR with domain key");
        } catch (AcmeException e) {
            throw new RuntimeException("Failed to execute order", e);
        }


        do {
            if (debug) System.out.println("ACME Polling for order status...");

            // Fetch Order Status
            try {
                order.fetch();
            } catch (AcmeException e) {
                throw new RuntimeException("Failed to fetch order status", e);
            }

            // Check Order Status
            Status status = order.getStatus();
            switch (status) {
                case INVALID -> throw new RuntimeException("Order is invalid");
                case REVOKED -> throw new RuntimeException("Order has been revoked");
                case DEACTIVATED -> throw new RuntimeException("Order has been deactivated");
                case EXPIRED -> throw new RuntimeException("Order has expired");
                case CANCELED -> throw new RuntimeException("Order has been canceled");
            }

            // Break if order is valid or ready
            if (status == VALID || status == READY) break;

            // Wait before polling again
            sleep(new BigDecimal(TTL).multiply(BigDecimal.valueOf(5d / 4d - 1d)).movePointRight(3).toBigInteger().longValue());

        } while (order.getStatus() == PENDING || order.getStatus() == PROCESSING || order.getStatus() != READY || order.getStatus() != VALID);
        if (debug) System.out.println("ACME Order is now " + order.getStatus());

        // Get Certificate
        Certificate certificate = order.getCertificate();
        if (certificate == null) throw new RuntimeException("Certificate is null");

        // Return Certificate
        return certificate;
    }

    // Static Utility Methods
    public static KeyPair createKeyPair() {
        return createKeyPair(RSA_4096);
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

    public static Certificate loadCertificate(File certificateFile) {

        // Check Parameters
        if (certificateFile == null) throw new IllegalArgumentException("Certificate file must not be null");
        if (!certificateFile.exists() || !certificateFile.isFile() || !certificateFile.canRead()) throw new IllegalArgumentException("Certificate file does not exist or is not readable");

        // ToDo Implement Certificate Loading
        throw new UnsupportedOperationException("Certificate loading not implemented yet");
    }

    public static File writeKeyPair(KeyPair keyPair, File keyPairFile) {

        // Check Parameters
        if (keyPair == null) throw new IllegalArgumentException("KeyPair must not be null");
        if (keyPairFile == null) throw new IllegalArgumentException("KeyPair file must not be null");

        // Create KeyPair File
        if (keyPairFile.exists()) throw new IllegalArgumentException("KeyPair file already exists");
        try {
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

    public static File writeCertificate(Certificate certificate, File certificateFile) {

        // Check Parameters
        if (certificate == null) throw new IllegalArgumentException("Certificate must not be null");
        if (certificateFile == null) throw new IllegalArgumentException("Certificate file must not be null");

        // Create Certificate File
        if (certificateFile.exists()) throw new IllegalArgumentException("Certificate file already exists");
        try {
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

    // Getters
    public String getEmail() {
        return email;
    }

    public KeyPair getAccountKey() {
        return accountKey;
    }

    public CloudflareClient getCloudflareClient() {
        return cloudflareClient;
    }

    public Session getSession() {
        return session;
    }

    public Account getAccount() {
        return account;
    }
}