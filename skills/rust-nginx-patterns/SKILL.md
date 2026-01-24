# Rust Nginx Security Patterns Skills

This skill provides patterns for generating security-hardened Nginx
configurations from Rust, including TLS hardening, rate limiting, WAF-like
protections, and integration with Rust backend services.

## Overview

Nginx security configuration covers:

- **TLS Hardening**: Modern cipher suites, HSTS, OCSP stapling
- **Rate Limiting**: Connection and request rate controls
- **Security Headers**: CSP, X-Frame-Options, etc.
- **Request Filtering**: Block malicious patterns
- **Upstream Security**: Secure proxy to backends

## /nginx-config

Generate a security-hardened Nginx configuration.

### Usage

```bash
/nginx-config
```

### What It Does

1. Generates secure nginx.conf
2. Creates server block templates
3. Configures TLS with modern settings
4. Sets up rate limiting
5. Adds security headers
6. Configures logging

---

## Nginx Configuration Generator

### Configuration Types

```rust
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct NginxConfig {
    pub global: GlobalConfig,
    pub http: HttpConfig,
    pub servers: Vec<ServerConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GlobalConfig {
    pub worker_processes: WorkerProcesses,
    pub worker_connections: u32,
    pub pid_file: PathBuf,
    pub error_log: LogConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerProcesses {
    Auto,
    Count(u32),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogConfig {
    pub path: PathBuf,
    pub level: LogLevel,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum LogLevel {
    Debug,
    Info,
    Notice,
    Warn,
    Error,
    Crit,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpConfig {
    pub access_log: LogConfig,
    pub sendfile: bool,
    pub tcp_nopush: bool,
    pub tcp_nodelay: bool,
    pub keepalive_timeout: u32,
    pub types_hash_max_size: u32,
    pub server_tokens: bool,
    pub client_max_body_size: String,
    pub rate_limits: Vec<RateLimitZone>,
    pub ssl: SslConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SslConfig {
    pub protocols: Vec<String>,
    pub ciphers: String,
    pub prefer_server_ciphers: bool,
    pub session_cache: String,
    pub session_timeout: String,
    pub stapling: bool,
    pub stapling_verify: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RateLimitZone {
    pub name: String,
    pub key: String,
    pub size: String,
    pub rate: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub server_name: Vec<String>,
    pub listen: Vec<ListenDirective>,
    pub root: Option<PathBuf>,
    pub ssl_certificate: Option<PathBuf>,
    pub ssl_certificate_key: Option<PathBuf>,
    pub locations: Vec<LocationConfig>,
    pub security_headers: SecurityHeaders,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListenDirective {
    pub port: u16,
    pub ssl: bool,
    pub http2: bool,
    pub default_server: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocationConfig {
    pub path: String,
    pub location_type: LocationType,
    pub proxy_pass: Option<String>,
    pub rate_limit: Option<String>,
    pub auth_basic: Option<String>,
    pub deny_patterns: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum LocationType {
    Exact,      // =
    Prefix,     // ^~
    Regex,      // ~
    RegexNoCase, // ~*
    Normal,     // (none)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityHeaders {
    pub hsts: Option<HstsConfig>,
    pub content_security_policy: Option<String>,
    pub x_frame_options: Option<String>,
    pub x_content_type_options: bool,
    pub x_xss_protection: Option<String>,
    pub referrer_policy: Option<String>,
    pub permissions_policy: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HstsConfig {
    pub max_age: u64,
    pub include_subdomains: bool,
    pub preload: bool,
}
```

### Configuration Builder

```rust
impl NginxConfig {
    pub fn secure_default() -> Self {
        Self {
            global: GlobalConfig {
                worker_processes: WorkerProcesses::Auto,
                worker_connections: 1024,
                pid_file: PathBuf::from("/run/nginx.pid"),
                error_log: LogConfig {
                    path: PathBuf::from("/var/log/nginx/error.log"),
                    level: LogLevel::Warn,
                },
            },
            http: HttpConfig {
                access_log: LogConfig {
                    path: PathBuf::from("/var/log/nginx/access.log"),
                    level: LogLevel::Info,
                },
                sendfile: true,
                tcp_nopush: true,
                tcp_nodelay: true,
                keepalive_timeout: 65,
                types_hash_max_size: 2048,
                server_tokens: false,  // Don't expose version
                client_max_body_size: "10M".to_string(),
                rate_limits: vec![
                    RateLimitZone {
                        name: "general".to_string(),
                        key: "$binary_remote_addr".to_string(),
                        size: "10m".to_string(),
                        rate: "10r/s".to_string(),
                    },
                    RateLimitZone {
                        name: "login".to_string(),
                        key: "$binary_remote_addr".to_string(),
                        size: "10m".to_string(),
                        rate: "1r/s".to_string(),
                    },
                ],
                ssl: SslConfig {
                    protocols: vec![
                        "TLSv1.2".to_string(),
                        "TLSv1.3".to_string(),
                    ],
                    ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384".to_string(),
                    prefer_server_ciphers: true,
                    session_cache: "shared:SSL:10m".to_string(),
                    session_timeout: "1d".to_string(),
                    stapling: true,
                    stapling_verify: true,
                },
            },
            servers: Vec::new(),
        }
    }

    pub fn add_server(&mut self, server: ServerConfig) {
        self.servers.push(server);
    }
}

impl ServerConfig {
    pub fn new(server_name: &str) -> Self {
        Self {
            server_name: vec![server_name.to_string()],
            listen: vec![
                ListenDirective {
                    port: 443,
                    ssl: true,
                    http2: true,
                    default_server: false,
                },
            ],
            root: None,
            ssl_certificate: None,
            ssl_certificate_key: None,
            locations: Vec::new(),
            security_headers: SecurityHeaders::strict(),
        }
    }

    pub fn with_ssl(mut self, cert: PathBuf, key: PathBuf) -> Self {
        self.ssl_certificate = Some(cert);
        self.ssl_certificate_key = Some(key);
        self
    }

    pub fn with_location(mut self, location: LocationConfig) -> Self {
        self.locations.push(location);
        self
    }
}

impl SecurityHeaders {
    pub fn strict() -> Self {
        Self {
            hsts: Some(HstsConfig {
                max_age: 31536000,  // 1 year
                include_subdomains: true,
                preload: true,
            }),
            content_security_policy: Some("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'".to_string()),
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: true,
            x_xss_protection: Some("1; mode=block".to_string()),
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            permissions_policy: Some("geolocation=(), microphone=(), camera=()".to_string()),
        }
    }
}
```

### Configuration Renderer

```rust
pub struct NginxRenderer;

impl NginxRenderer {
    pub fn render(config: &NginxConfig) -> String {
        let mut output = String::new();

        // Global context
        output.push_str(&Self::render_global(&config.global));
        output.push_str("\n");

        // Events block
        output.push_str(&format!(
            "events {{\n    worker_connections {};\n}}\n\n",
            config.global.worker_connections
        ));

        // HTTP block
        output.push_str("http {\n");
        output.push_str(&Self::render_http(&config.http));

        // Server blocks
        for server in &config.servers {
            output.push_str(&Self::render_server(server));
        }

        output.push_str("}\n");
        output
    }

    fn render_global(global: &GlobalConfig) -> String {
        let mut output = String::new();

        output.push_str(&match global.worker_processes {
            WorkerProcesses::Auto => "worker_processes auto;\n".to_string(),
            WorkerProcesses::Count(n) => format!("worker_processes {};\n", n),
        });

        output.push_str(&format!("pid {};\n", global.pid_file.display()));
        output.push_str(&format!(
            "error_log {} {};\n",
            global.error_log.path.display(),
            Self::log_level_str(&global.error_log.level)
        ));

        output
    }

    fn render_http(http: &HttpConfig) -> String {
        let mut output = String::new();

        // Basic settings
        output.push_str(&format!("    access_log {};\n", http.access_log.path.display()));
        output.push_str(&format!("    sendfile {};\n", if http.sendfile { "on" } else { "off" }));
        output.push_str(&format!("    tcp_nopush {};\n", if http.tcp_nopush { "on" } else { "off" }));
        output.push_str(&format!("    tcp_nodelay {};\n", if http.tcp_nodelay { "on" } else { "off" }));
        output.push_str(&format!("    keepalive_timeout {};\n", http.keepalive_timeout));
        output.push_str(&format!("    types_hash_max_size {};\n", http.types_hash_max_size));
        output.push_str(&format!("    server_tokens {};\n", if http.server_tokens { "on" } else { "off" }));
        output.push_str(&format!("    client_max_body_size {};\n", http.client_max_body_size));
        output.push_str("\n");

        // Include MIME types
        output.push_str("    include /etc/nginx/mime.types;\n");
        output.push_str("    default_type application/octet-stream;\n\n");

        // Rate limiting zones
        for zone in &http.rate_limits {
            output.push_str(&format!(
                "    limit_req_zone {} zone={}:{} rate={};\n",
                zone.key, zone.name, zone.size, zone.rate
            ));
        }
        output.push_str("\n");

        // SSL settings
        output.push_str(&Self::render_ssl(&http.ssl));
        output.push_str("\n");

        output
    }

    fn render_ssl(ssl: &SslConfig) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "    ssl_protocols {};\n",
            ssl.protocols.join(" ")
        ));
        output.push_str(&format!("    ssl_ciphers {};\n", ssl.ciphers));
        output.push_str(&format!(
            "    ssl_prefer_server_ciphers {};\n",
            if ssl.prefer_server_ciphers { "on" } else { "off" }
        ));
        output.push_str(&format!("    ssl_session_cache {};\n", ssl.session_cache));
        output.push_str(&format!("    ssl_session_timeout {};\n", ssl.session_timeout));

        if ssl.stapling {
            output.push_str("    ssl_stapling on;\n");
            output.push_str(&format!(
                "    ssl_stapling_verify {};\n",
                if ssl.stapling_verify { "on" } else { "off" }
            ));
        }

        output
    }

    fn render_server(server: &ServerConfig) -> String {
        let mut output = String::new();

        output.push_str("\n    server {\n");

        // Listen directives
        for listen in &server.listen {
            let mut directive = format!("        listen {}", listen.port);
            if listen.ssl {
                directive.push_str(" ssl");
            }
            if listen.http2 {
                directive.push_str(" http2");
            }
            if listen.default_server {
                directive.push_str(" default_server");
            }
            directive.push_str(";\n");
            output.push_str(&directive);
        }

        // Server name
        output.push_str(&format!(
            "        server_name {};\n",
            server.server_name.join(" ")
        ));

        // SSL certificates
        if let Some(cert) = &server.ssl_certificate {
            output.push_str(&format!("        ssl_certificate {};\n", cert.display()));
        }
        if let Some(key) = &server.ssl_certificate_key {
            output.push_str(&format!("        ssl_certificate_key {};\n", key.display()));
        }

        // Root
        if let Some(root) = &server.root {
            output.push_str(&format!("        root {};\n", root.display()));
        }

        output.push_str("\n");

        // Security headers
        output.push_str(&Self::render_security_headers(&server.security_headers));

        // Locations
        for location in &server.locations {
            output.push_str(&Self::render_location(location));
        }

        output.push_str("    }\n");
        output
    }

    fn render_security_headers(headers: &SecurityHeaders) -> String {
        let mut output = String::new();

        if let Some(hsts) = &headers.hsts {
            let mut hsts_value = format!("max-age={}", hsts.max_age);
            if hsts.include_subdomains {
                hsts_value.push_str("; includeSubDomains");
            }
            if hsts.preload {
                hsts_value.push_str("; preload");
            }
            output.push_str(&format!(
                "        add_header Strict-Transport-Security \"{}\" always;\n",
                hsts_value
            ));
        }

        if let Some(csp) = &headers.content_security_policy {
            output.push_str(&format!(
                "        add_header Content-Security-Policy \"{}\" always;\n",
                csp
            ));
        }

        if let Some(xfo) = &headers.x_frame_options {
            output.push_str(&format!(
                "        add_header X-Frame-Options \"{}\" always;\n",
                xfo
            ));
        }

        if headers.x_content_type_options {
            output.push_str("        add_header X-Content-Type-Options \"nosniff\" always;\n");
        }

        if let Some(xss) = &headers.x_xss_protection {
            output.push_str(&format!(
                "        add_header X-XSS-Protection \"{}\" always;\n",
                xss
            ));
        }

        if let Some(referrer) = &headers.referrer_policy {
            output.push_str(&format!(
                "        add_header Referrer-Policy \"{}\" always;\n",
                referrer
            ));
        }

        if let Some(permissions) = &headers.permissions_policy {
            output.push_str(&format!(
                "        add_header Permissions-Policy \"{}\" always;\n",
                permissions
            ));
        }

        output.push_str("\n");
        output
    }

    fn render_location(location: &LocationConfig) -> String {
        let mut output = String::new();

        let modifier = match location.location_type {
            LocationType::Exact => "= ",
            LocationType::Prefix => "^~ ",
            LocationType::Regex => "~ ",
            LocationType::RegexNoCase => "~* ",
            LocationType::Normal => "",
        };

        output.push_str(&format!("        location {}{} {{\n", modifier, location.path));

        // Rate limiting
        if let Some(zone) = &location.rate_limit {
            output.push_str(&format!("            limit_req zone={} burst=5 nodelay;\n", zone));
        }

        // Proxy pass
        if let Some(upstream) = &location.proxy_pass {
            output.push_str(&format!("            proxy_pass {};\n", upstream));
            output.push_str("            proxy_http_version 1.1;\n");
            output.push_str("            proxy_set_header Host $host;\n");
            output.push_str("            proxy_set_header X-Real-IP $remote_addr;\n");
            output.push_str("            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n");
            output.push_str("            proxy_set_header X-Forwarded-Proto $scheme;\n");
        }

        // Deny patterns
        for pattern in &location.deny_patterns {
            output.push_str(&format!("            if ($request_uri ~* \"{}\") {{ return 403; }}\n", pattern));
        }

        // Basic auth
        if let Some(realm) = &location.auth_basic {
            output.push_str(&format!("            auth_basic \"{}\";\n", realm));
            output.push_str("            auth_basic_user_file /etc/nginx/.htpasswd;\n");
        }

        output.push_str("        }\n\n");
        output
    }

    fn log_level_str(level: &LogLevel) -> &'static str {
        match level {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Notice => "notice",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
            LogLevel::Crit => "crit",
        }
    }
}
```

---

## Common Security Configurations

### Block Common Attack Patterns

```rust
impl LocationConfig {
    pub fn with_security_rules(mut self) -> Self {
        self.deny_patterns = vec![
            // SQL injection patterns
            r"union.*select".to_string(),
            r"insert.*into".to_string(),
            r"drop.*table".to_string(),

            // Path traversal
            r"\.\.".to_string(),
            r"%2e%2e".to_string(),

            // Common vulnerability scanners
            r"(sqlmap|nikto|nmap)".to_string(),

            // Shell injection
            r"(\||;|`|\$\()".to_string(),

            // Common backdoors
            r"(c99|r57|shell|cmd)\.php".to_string(),
        ];
        self
    }
}
```

### HTTPS Redirect Server

```rust
pub fn https_redirect_server() -> ServerConfig {
    ServerConfig {
        server_name: vec!["_".to_string()],
        listen: vec![
            ListenDirective {
                port: 80,
                ssl: false,
                http2: false,
                default_server: true,
            },
        ],
        root: None,
        ssl_certificate: None,
        ssl_certificate_key: None,
        locations: vec![
            LocationConfig {
                path: "/".to_string(),
                location_type: LocationType::Normal,
                proxy_pass: None,
                rate_limit: None,
                auth_basic: None,
                deny_patterns: Vec::new(),
            },
        ],
        security_headers: SecurityHeaders::default(),
    }
}
```

---

## Nginx Security Checklist

### TLS Configuration

- [ ] TLS 1.2+ only (no TLS 1.0/1.1)
- [ ] Strong cipher suites
- [ ] Perfect forward secrecy
- [ ] HSTS enabled with preload
- [ ] OCSP stapling enabled

### Headers

- [ ] Content-Security-Policy
- [ ] X-Frame-Options: DENY
- [ ] X-Content-Type-Options: nosniff
- [ ] Referrer-Policy
- [ ] Permissions-Policy

### Rate Limiting

- [ ] Global rate limits
- [ ] Stricter limits on auth endpoints
- [ ] Burst allowance configured

### General

- [ ] server_tokens off
- [ ] Version hidden
- [ ] Access logs enabled
- [ ] Error pages don't leak info

## Integration Points

This skill works well with:

- `/cert-rotate` - Certificate management
- `/gunicorn-config` - Backend configuration
