# HTTPS-Server

## Description
**HTTPS-Server** is a simple Java HTTPS server built on top of Undertow, 
designed to serve static and dynamic content with built-in support for self-signed SSL certificates.
It provides HTTP and HTTPS support, automatic certificate generation via Bouncy Castle, and configurable routing and base URL handling. 
The server is intended to be run behind a reverse proxy such as Nginx, Apache, or HAProxy, making deployment straightforward.

## Key Features
- HTTP and HTTPS support
- Automatic self-signed certificate generation using Bouncy Castle
- Configurable host, HTTP/HTTPS ports, and base URL
- Path-based routing with prefix and exact matches
- Easy mounting of HTML files and custom handlers

> **Tip:** Designed for seamless operation behind a reverse proxy.

## Maven Integration
Add the Sonatype Nexus OSS repository to your `pom.xml`:
```xml
<repositories>
    <repository>
        <id>Nexus</id>
        <name>Sonatype Nexus</name>
        <url>https://mcmodersd.de/nexus/repository/maven-releases/</url>
    </repository>
</repositories>
```
Add the dependency:
```xml
<dependency>
    <groupId>de.MCmoderSD</groupId>
    <artifactId>HTTPS-Server</artifactId>
    <version>2.0.0</version>
</dependency>
```

## Configuration
The server is configured via a `config.json` file. 

Fields that are not specified will use defaults, except for required certificate information like `commonName` (CN) and `keyPassword`, which must always be provided. If `subjectAltNames` is not specified, only the CN will be used.

Here’s a sample configuration:
```json
{
  "host":"localhost",
  "httpPort":80,
  "httpsPort":443,
  "baseUrl":"/",

  "certificate":{
    "keyPassword":"Your Key Password",
    "expirationDays":366,

    "subject":{
      "commonName":"localhost",
      "organization":"Your Organization",
      "organizationalUnit":"Your Organizational Unit",
      "locality":"Your City",
      "state":"Your State",
      "country":"DE"
    },

    "subjectAltNames":{
      "dns":["localhost"],
      "ip":["127.0.0.1","::1"]
    }
  }
}
```

### Defaults
If not specified, the server will automatically use:

- `host`: `0.0.0.0` (bind to all interfaces)
- `httpPort`: `80` (default HTTP port)
- `httpsPort`: `443` (default HTTPS port)
- `baseUrl`: `/`
- `expirationDays`: `366`

Required fields that must be provided:
- `certificate.keyPassword`
- `certificate.subject.commonName` (CN)

Optional certificate subject fields (O, OU, L, ST, C) can be left empty.

### Configuration Fields
| Field           | Description                                                                             |
|-----------------|-----------------------------------------------------------------------------------------|
| host            | Server bind address                                                                     |
| httpPort        | Listening port for HTTP                                                                 |
| httpsPort       | Listening port for HTTPS                                                                |
| baseUrl         | Root path for all routes                                                                |
| certificate     | SSL certificate settings                                                                |
| keyPassword     | Password for the private key (required)                                                 |
| expirationDays  | Validity period of the certificate (max 366 days)                                       |
| subject         | Certificate subject information (CN required; O, OU, L, ST, C optional)                 |
| subjectAltNames | Alternative DNS names and IPs for the certificate (optional; defaults to using CN only) |

## Usage Example
```java
import com.fasterxml.jackson.databind.JsonNode;
import de.MCmoderSD.json.JsonUtility;
import de.MCmoderSD.server.core.Server;
import de.MCmoderSD.server.modules.HtmlModule;

import java.io.IOException;
import java.net.URISyntaxException;

@SuppressWarnings("ALL")
public class Main {

    public static void main(String[] args) throws IOException, URISyntaxException {

        // Load Configuration
        JsonNode config = JsonUtility.getInstance().load("/config.json");
        System.out.println("Configuration loaded: \n" + config.toPrettyString() + "\n");

        // Initialize Server
        Server server = new Server(config);

        // Start Server
        server.start();
        System.out.printf("Server started at https://%s:%d%s%n", server.getHost(), server.getHttpsPort(), server.getBaseUrl());

        // Initialize HTML Module
        HtmlModule htmlModule = new HtmlModule(server);
        htmlModule.mountHtml("/html/Example.html", "/");
        System.out.println("Example HTML file mounted at /");
    }
}
```