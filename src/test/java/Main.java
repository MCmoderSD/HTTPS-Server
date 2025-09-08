import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import de.MCmoderSD.json.JsonUtility;
import de.MCmoderSD.server.Server;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

@SuppressWarnings("ALL")
public class Main {

    // Scanner for user input
    private static final Scanner scanner = new Scanner(System.in);

    // Main method
    public static void main(String[] args) {

        // Create a server with JKS configuration
        System.out.println("Creating a server with JKS configuration");
        Server jksServer = createJKSServer();

        // Start the server
        jksServer.start();
        System.out.println(jksServer.getURL() + "/example");

        // Add a handler to the server
        jksServer.getHttpsServer().createContext("/example", new ExampleHandler());

        // Wait for the user to stop the server
        System.out.println("Press enter to stop the server");
        scanner.nextLine();
        jksServer.stop();





        // Create a Server with SSL configuration
        System.out.println("Creating a server with SSL configuration");
        Server sslServer = createSSLServer();

        // Start the server
        sslServer.start();
        System.out.println(sslServer.getURL() + "/example");

        // Add a handler to the server
        sslServer.getHttpsServer().createContext("/example", new ExampleHandler());

        // Wait for the user to stop the server
        System.out.println("Press enter to stop the server");
        scanner.nextLine();
        sslServer.stop();
    }

    // Method to create a server with JKS configuration
    private static Server createJKSServer() {

        Server server = null;

        try {

            // Load the configuration from a file
            JsonNode config = JsonUtility.getInstance().load("/config.json");
            JsonNode jksConfig = config.get("JKS");
            boolean hostNetwork = config.get("host").asBoolean();

            // Create a server with JKS configuration
            server = new Server("localhost", 8000, null, jksConfig, hostNetwork);
        } catch (IOException | URISyntaxException | UnrecoverableKeyException | CertificateException | NoSuchAlgorithmException | KeyStoreException | InterruptedException | KeyManagementException e) {
            System.err.println("Failed to create server with JKS configuration: " + e.getMessage());
        }

        return server;
    }

    // Method to create a server with SSL configuration
    private static Server createSSLServer() {

        Server server = null;

        try {

            // Load the configuration from a file
            JsonNode config = JsonUtility.getInstance().load("/config.json");
            boolean hostNetwork = config.get("host").asBoolean();
            boolean hasProxy = config.has("proxy");

            // Load the SSL configuration
            JsonNode sslConfig = config.get("SSL");
            String fullchain = sslConfig.get("fullchain").asText();
            String privkey = sslConfig.get("privkey").asText();
            String proxy = hasProxy ? config.get("proxy").asText() : null;

            // Create a server with SSL configuration
            server = new Server("YourDomain.com", 8080, proxy, privkey, fullchain, hostNetwork);
        } catch (IOException | URISyntaxException | UnrecoverableKeyException | CertificateException | NoSuchAlgorithmException | KeyStoreException | InvalidKeySpecException | KeyManagementException e) {
            System.err.println("Failed to create server with SSL configuration: " + e.getMessage());
        }

        return server;
    }

    // Example of a http handler
    private static class ExampleHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "This is an example response";
            exchange.sendResponseHeaders(200, response.getBytes().length);
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }
}