# HTTPS-Server

## Description
**HTTPS-Server** is a lightweight and configurable Java HTTPS server built on top of **Undertow**,
designed to serve static and dynamic content with built-in **SSL certificate management**.
It supports **HTTP**, **HTTPS**, and **automatic certificate handling** through the Let's Encrypt **ACME** protocol.
The server is ideal for use behind a reverse proxy like **Nginx**, **Apache**, or **HAProxy**, making deployment straightforward.

## Key Features
- HTTP and HTTPS support
- SSL certificate loading from PEM files
- Let's Encrypt ACME certificate management (DNS-01 via Cloudflare)
- Self-signed certificate generation
- Path-based routing with prefix and exact matches
- Easy HTML mounting and custom route handlers
- Configurable host, ports, and base URL

> **Tip:** Designed for seamless use behind a reverse proxy.

## SSL Certificate Management
You can choose between three modes:
1. **Provided Certificates** — Load existing private key and certificate (PEM files).
2. **Let's Encrypt (ACME)** — Automatically order certificates using DNS-01 via Cloudflare.
3. **Self-Signed** — Generate a self-signed certificate (useful behind a reverse proxy).

>**Note:** <br>
> This server does **not** automatically renew Let's Encrypt certificates. <br>
> When a certificate expires, it will throw an error. <br>
> You must delete the expired certificate files and allow the server to request a new one. <br>
> Be cautious not to exceed Let's Encrypt rate limits.

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
    <version>3.0.0</version>
</dependency>
```

## Configuration
The server is configured via a JSON configuration file. Example:
```json
{
  "host": "example.com",
  "httpPort": 8080,
  "httpsPort": 8000,
  "baseUrl": "/",

  "certificate": {
    "keyPassword": "Your Key Password",
    "keySize": 4096,

    "createIfMissing": true,
    "paths": {
      "privateKey": "path/to/your/private.pem",
      "certificate": "path/to/your/certificate.pem"
    },

    "acmeSigned": {
      "debug": true,
      "email": "Your@Email.com",
      "accountKey": "account.key",

      "cloudflare": {
        "zoneId": "Your Zone ID",
        "apiToken": "Your API Key"
      },

      "domains": [
        "example.com",
        "www.example.com"
      ]
    },

    "selfSigned": {
      "expirationDays": 366,

      "subject": {
        "commonName": "localhost",
        "organization": "Your Organization",
        "organizationalUnit": "Your Organizational Unit",
        "locality": "Your City",
        "state": "Your State",
        "country": "DE"
      },

      "subjectAltNames": {

        "dns": [
          "localhost"
        ],

        "ip": [
          "127.0.0.1",
          "::1"
        ]
      }
    }
  }
}
```

### Defaults
| Key         | Default   | Description            |
|-------------|-----------|------------------------|
| `host`      | `0.0.0.0` | Bind to all interfaces |
| `httpPort`  | `80`      | Default HTTP port      |
| `httpsPort` | `443`     | Default HTTPS port     |
| `baseUrl`   | `/`       | Root base path         |

### Certificate Options
- `keyPassword`: Required for loading/creating certificates.
- `keySize`: One of `2048`, `3072`, or `4096` (optional, defaults to `4096`).
- `createIfMissing`: Automatically create certificates if missing. (optional, defaults to `false`)
- `paths`: Specify PEM file locations for private key and certificate.
  - `privateKey`: Path to the private key PEM file. (e.g., `privkey.pem`)
  - `certificate`: Path to the certificate PEM file. (e.g., `fullchain.pem`)

> **Note:** If you don't want to save/load PEM files, you can omit the `paths` section.

#### ACME (Let's Encrypt)
- `debug`: Enable ACME debug logs. (optional, defaults to `false`)
- `email`: Email for ACME account registration.
- `accountKey`: Path for storing ACME account key.
- `cloudflare`: DNS-01 configuration using Cloudflare.
    - `zoneId`: Your Cloudflare Zone ID (see below).
    - `apiToken`: API token with DNS edit permissions (see below).
- `domains`: Domains to issue certificates for.

> **Tip:** You can issue wildcard certificates by prefixing a domain with `*.` (e.g., `*.example.com`).

##### How to Get Your Cloudflare Zone ID
1. Log in to your **Cloudflare Dashboard**.
2. Select your domain.
3. Scroll down to the **API** section on the **Overview** page.
4. Copy the **Zone ID** displayed there.

##### How to Create an API Token
1. Go to **My Profile → API Tokens** in Cloudflare.
2. Click **Create Token**.
3. Use the **Edit zone DNS** template or create a custom token with:
    - **Permissions:** `Zone → DNS → Edit` and `Zone → Zone → Read`
    - **Zone Resources:** Include **Specific Zone** (your domain)
4. Copy the generated **API Token** and store it securely.

#### Self-Signed
- `expirationDays`: Validity period (max 366 days).
- `subject`: Certificate subject details.
  - `commonName`: Your common name (e.g., `localhost`). (**required**)
  - `organization`: Your organization name. (optional)
  - `organizationalUnit`: Your organizational unit. (optional)
  - `locality`: Your city. (optional)
  - `state`: Your state. (optional)
  - `country`: Two-letter country code (e.g., `DE`). (optional)
- `subjectAltNames`: DNS and IP entries.

> Provide only what you need:
>
> - If using **provided PEM files**, skip `acmeSigned` and `selfSigned`.
> - If using **self-signed**, skip `acmeSigned`.
> - If using **ACME**, skip `selfSigned`.

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
```