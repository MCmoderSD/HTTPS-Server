package de.MCmoderSD.server.modules;

import de.MCmoderSD.server.Server;

import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.OutputStream;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The AudioBroadcast class manages the broadcasting of audio streams over HTTPS.
 * It provides methods to register and unregister broadcasts, as well as
 * serve audio, frontend, and version information to clients.
 */
@SuppressWarnings("ALL")
public class AudioBroadcast {

    // Constants
    private final String hostname;
    private final int port;

    // Attributes
    private final Server server;
    private final HashMap<String, HashSet<HttpContext>> serverContexts;
    private final HashMap<String, byte[]> audioFiles;
    private final HashMap<String, AtomicLong> versions;

    /**
     * Constructor for the AudioBroadcast class.
     *
     * @param server the server instance used for handling HTTPS requests.
     */
    public AudioBroadcast(Server server) {

        // Set Constants
        this.server = server;

        // Set Attributes
        hostname = server.getHostname();
        port = server.getPort();

        // Init Attributes
        serverContexts = new HashMap<>();
        audioFiles = new HashMap<>();
        versions = new HashMap<>();
    }

    /**
     * Registers a new audio broadcast.
     *
     * @param broadcastId the unique identifier for the broadcast.
     * @return a string describing the broadcast URL.
     */
    public String registerBroadcast(String broadcastId) {

        // Create Contexts
        HashSet<HttpContext> contexts = new HashSet<>();

        // Add Contexts
        contexts.add(server.getHttpsServer().createContext("/" + broadcastId, new FrontendHandler(broadcastId)));
        contexts.add(server.getHttpsServer().createContext("/audio/" + broadcastId, new AudioHandler(broadcastId)));
        contexts.add(server.getHttpsServer().createContext("/version/" + broadcastId, new VersionHandler(broadcastId)));

        // Add Contexts to Server
        serverContexts.put(broadcastId, contexts);

        // Return
        return String.format("Broadcast started on https://%s:%d/%s", hostname, port, broadcastId);
    }

    /**
     * Unregisters an existing broadcast.
     *
     * @param broadcastId the unique identifier for the broadcast.
     * @return true if the broadcast was successfully unregistered, false otherwise.
     */
    public boolean unregisterBroadcast(String broadcastId) {
        if (!serverContexts.containsKey(broadcastId)) return false;
        serverContexts.get(broadcastId).forEach(server.getHttpsServer()::removeContext);
        serverContexts.remove(broadcastId);
        audioFiles.remove(broadcastId);
        versions.remove(broadcastId);
        return true;
    }

    /**
     * Plays a given audio file for the specified broadcast.
     *
     * @param broadcastId the unique identifier for the broadcast.
     * @param audioData   the byte array representing the audio file.
     * @return true if the audio was successfully played, false otherwise.
     */
    public boolean play(String broadcastId, byte[] audioData) {
        if (!serverContexts.containsKey(broadcastId)) return false;
        audioFiles.put(broadcastId, audioData);
        versions.get(broadcastId).incrementAndGet();
        return true;
    }

    /**
     * Handler for serving the frontend page of the broadcast.
     */
    private class FrontendHandler implements HttpHandler {

        // Attributes
        private final String broadcastId;

        /**
         * Constructor for FrontendHandler.
         *
         * @param broadcastId the unique identifier for the broadcast.
         */
        public FrontendHandler(String broadcastId) {
            this.broadcastId = broadcastId;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {

            // Load HTML and JS
            String html = new String(Objects.requireNonNull(AudioBroadcast.class.getResourceAsStream("/web/pages/html/audio.html")).readAllBytes());
            String script = new String(Objects.requireNonNull(AudioBroadcast.class.getResourceAsStream("/web/scripts/js/audio.js")).readAllBytes());

            // Replace placeholders
            html = html
                    .replace("{SCRIPT}", "<script>\n" + script + "\n</script>")
                    .replace("{BROADCAST_ID}", broadcastId)
                    .replace("{HOSTNAME}", hostname)
                    .replace("{PORT}", String.valueOf(port));

            exchange.getResponseHeaders().set("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, html.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(html.getBytes());
            }
        }
    }

    /**
     * Handler for serving audio data for the broadcast.
     */
    private class AudioHandler implements HttpHandler {

        // Attributes
        private final String broadcastId;

        /**
         * Constructor for AudioHandler.
         *
         * @param broadcastId the unique identifier for the broadcast.
         */
        public AudioHandler(String broadcastId) {
            this.broadcastId = broadcastId;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "audio/wav");
            if (audioFiles.containsKey(broadcastId) && audioFiles.get(broadcastId) != null) {
                byte[] audioData = audioFiles.get(broadcastId);
                exchange.sendResponseHeaders(200, audioData.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(audioData);
                }
            } else {
                exchange.sendResponseHeaders(404, -1);
            }
        }
    }

    /**
     * Handler for serving version information of the broadcast.
     */
    private class VersionHandler implements HttpHandler {

        // Attributes
        private final String broadcastId;

        /**
         * Constructor for VersionHandler.
         *
         * @param broadcastId the unique identifier for the broadcast.
         */
        public VersionHandler(String broadcastId) {
            this.broadcastId = broadcastId;
            versions.put(broadcastId, new AtomicLong(0));
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String currentVersion = String.valueOf(versions.get(broadcastId).get());
            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            exchange.sendResponseHeaders(200, currentVersion.length());
            OutputStream os = exchange.getResponseBody();
            os.write(currentVersion.getBytes());
            os.close();
        }
    }

    /**
     * @return the hostname of the server.
     */
    public String getHostname() {
        return hostname;
    }

    /**
     * @return the port of the server.
     */
    public int getPort() {
        return port;
    }

    /**
     * @return the server instance.
     */
    public Server getServer() {
        return server;
    }

    /**
     * @return the map of audio files.
     */
    public HashMap<String, byte[]> getAudioFiles() {
        return audioFiles;
    }

    /**
     * @return the map of broadcast versions.
     */
    public HashMap<String, AtomicLong> getVersions() {
        return versions;
    }
}