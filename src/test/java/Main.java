import de.MCmoderSD.json.JsonUtility;
import de.MCmoderSD.server.core.Server;
import de.MCmoderSD.server.modules.HtmlModule;

import tools.jackson.databind.JsonNode;

import java.io.IOException;
import java.net.URISyntaxException;

@SuppressWarnings("ALL")
public class Main {

    public static void main(String[] args) throws IOException, URISyntaxException {

        // Load Configuration
        JsonNode config = JsonUtility.getInstance().load("/config.json");

        // Initialize Server
        Server server = new Server(config);

        // Start Server
        server.start();
        System.out.printf("Server started at https://%s:%d%s%n", server.getHost(), server.getHttpsPort(), server.getBaseUrl());

        // Initialize HTML Module
        HtmlModule htmlModule = new HtmlModule(server);
        htmlModule.mountHtml("/html/example.html", "/");
        System.out.println("Example HTML file mounted at /");
    }
}