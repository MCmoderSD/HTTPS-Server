package de.MCmoderSD.server.modules;

import de.MCmoderSD.server.core.Server;
import io.undertow.util.Headers;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.HashSet;

@SuppressWarnings({"unused", "ClassCanBeRecord"})
public class HtmlModule {

    // Constants
    public static final HashSet<String> EXTENSIONS = new HashSet<>() {{
        add(".html");
        add(".htm");
    }};

    // Attributes
    private final Server server;

    // Constructor
    public HtmlModule(Server server) {
        this.server = server;
    }

    public void mountHtml(String resourcePath, String urlPath) {

        // Validate inputs
        if (resourcePath == null || resourcePath.isBlank()) throw new IllegalArgumentException("Resource path cannot be null or empty");

        // Load HTML from resource
        try (InputStream stream = HtmlModule.class.getResourceAsStream(resourcePath)) {
            if (stream == null) throw new IllegalArgumentException("Resource not found: " + resourcePath);
            else mountHtml(stream.readAllBytes(), urlPath);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read resource: " + resourcePath, e);
        }
    }

    public void mountHtml(File file, String urlPath) {

        // Validate inputs
        if (file == null) throw new IllegalArgumentException("File cannot be null");
        if (!file.exists() || !file.isFile() || !file.canRead()) throw new IllegalArgumentException("File does not exist or is not readable: " + file);

        // Mount HTML file
        try {
            mountHtml(Files.readAllBytes(file.toPath()), urlPath);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read file: " + file, e);
        }
    }

    public void mountHtml(byte[] html, String urlPath) {

        // Validate inputs
        if (html == null || html.length == 0) throw new IllegalArgumentException("HTML content cannot be null or empty");   // Non-empty HTML
        if (urlPath == null || urlPath.isBlank()) throw new IllegalArgumentException("URL path cannot be null");            // Non-null URL path
        if (urlPath.contains(" ")) throw new IllegalArgumentException("URL path cannot contain spaces");                    // No spaces in URL path
        if (!urlPath.startsWith("/")) urlPath = "/" + urlPath;

        // Register handler to serve HTML content
        server.registerExactPath(urlPath, exchange -> {
            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/html; charset=UTF-8");
            exchange.getResponseSender().send(new String(html));
        });
    }
}