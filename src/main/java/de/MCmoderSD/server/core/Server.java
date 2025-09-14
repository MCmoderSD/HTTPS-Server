package de.MCmoderSD.server.core;

import com.fasterxml.jackson.databind.JsonNode;
import de.MCmoderSD.server.cert.CertManager;
import io.undertow.Handlers;
import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.server.handlers.PathHandler;

import javax.net.ssl.SSLContext;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import static java.util.logging.Level.OFF;

@SuppressWarnings({"unused", "FieldCanBeLocal"})
public class Server {

    // Constants
    private static final String DEFAULT_ROUTE = "0.0.0.0";
    private static final int DEFAULT_HTTP_PORT = 80;
    private static final int DEFAULT_HTTPS_PORT = 443;
    private static final String DEFAULT_BASE_URL = "/";

    // Configuration
    private final String host;
    private final int httpPort;
    private final int httpsPort;
    private final String baseUrl;

    // Attributes
    private final SSLContext sslContext;
    private final PathHandler pathHandler;
    private final Undertow undertow;

    // Constructor
    public Server(JsonNode config) {

        // Suppress Logging
        setLogLevel(OFF);

        // Load HTTPS Server Configuration
        host = config.path("host").asText(DEFAULT_ROUTE);
        httpPort = config.path("httpPort").asInt(DEFAULT_HTTP_PORT);
        httpsPort = config.path("httpsPort").asInt(DEFAULT_HTTPS_PORT);
        baseUrl = config.path("baseUrl").asText(DEFAULT_BASE_URL);

        // Validate Server Configuration
        if (httpPort < 1 || httpPort > 65535) throw new IllegalArgumentException("HTTP port must be between 1 and 65535");
        if (httpsPort < 1 || httpsPort > 65535) throw new IllegalArgumentException("HTTPS port must be between 1 and 65535");
        if (httpPort == httpsPort) throw new IllegalArgumentException("HTTP and HTTPS ports must be different");
        if (!baseUrl.startsWith("/")) throw new IllegalArgumentException("Base URL must start with '/'");

        // Obtain SSL Context
        sslContext = new CertManager(config.get("certificate")).getSSLContext();

        // Initialize Path Handler
        pathHandler = new PathHandler();

        // Build Undertow Server
        undertow = Undertow.builder()
                .addHttpListener(httpPort, host)
                .addHttpsListener(httpsPort, host, sslContext)
                .setHandler(Handlers.path().addPrefixPath(baseUrl, pathHandler))
                .build();
    }

    // Static Methods
    public static void setLogLevel(Level level) {
        LogManager.getLogManager().reset();
        Logger.getLogger("io.undertow").setLevel(level);
        Logger.getLogger("org.xnio").setLevel(level);
    }

    // Setter
    public void start() {
        undertow.start();
    }

    public void stop() {
        undertow.stop();
    }

    public void registerPrefixPath(String prefix, HttpHandler handler) {
        pathHandler.addPrefixPath(prefix, handler);
    }

    public void registerExactPath(String path, HttpHandler handler) {
        pathHandler.addExactPath(path, handler);
    }

    public void unregisterPrefixPath(String prefix) {
        pathHandler.removePrefixPath(prefix);
    }

    public void unregisterExactPath(String path) {
        pathHandler.removeExactPath(path);
    }

    // Getter
    public String getHost() {
        return host;
    }

    public int getHttpPort() {
        return httpPort;
    }

    public int getHttpsPort() {
        return httpsPort;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public PathHandler getPathHandler() {
        return pathHandler;
    }

    public Undertow getUndertow() {
        return undertow;
    }
}