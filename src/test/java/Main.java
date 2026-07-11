import de.MCmoderSD.json.JsonUtility;
import de.MCmoderSD.server.core.Server;
import de.MCmoderSD.server.modules.HtmlModule;

import static java.lang.IO.println;

void main() {

    // Load Configuration
    var config = JsonUtility.getInstance().loadResource("/config.json");

    // Initialize Server
    var server = new Server(config);

    // Start Server
    server.start();
    System.out.printf("Server started at https://%s:%d%s%n", server.getHost(), server.getHttpsPort(), server.getBaseUrl());

    // Initialize HTML Module
    var htmlModule = new HtmlModule(server);
    htmlModule.mountHtml("/html/example.html", "/");
    println("Example HTML file mounted at /");
}