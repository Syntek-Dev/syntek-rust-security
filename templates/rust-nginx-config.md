# Rust Nginx Config Template

## Overview

Security-hardened Nginx configuration generator with TLS hardening, rate
limiting, and security headers.

## Project Structure

```
my-nginx-config/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── config.rs
│   ├── tls.rs
│   ├── headers.rs
│   └── rate_limit.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-nginx-config"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
```

## Core Implementation

### src/config.rs

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NginxConfig {
    pub server_name: String,
    pub listen_port: u16,
    pub ssl: SslConfig,
    pub locations: Vec<Location>,
    pub rate_limit: Option<RateLimitConfig>,
    pub security_headers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslConfig {
    pub certificate: String,
    pub certificate_key: String,
    pub protocols: Vec<String>,
    pub ciphers: String,
    pub prefer_server_ciphers: bool,
    pub session_timeout: String,
    pub stapling: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub path: String,
    pub proxy_pass: Option<String>,
    pub root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub zone: String,
    pub rate: String,
    pub burst: u32,
}

impl NginxConfig {
    pub fn generate(&self) -> String {
        let mut config = String::new();

        // Rate limit zone
        if let Some(rl) = &self.rate_limit {
            config.push_str(&format!(
                "limit_req_zone $binary_remote_addr zone={}:10m rate={};\n\n",
                rl.zone, rl.rate
            ));
        }

        config.push_str("server {\n");
        config.push_str(&format!("    listen {} ssl http2;\n", self.listen_port));
        config.push_str(&format!("    server_name {};\n\n", self.server_name));

        // SSL configuration
        config.push_str(&format!("    ssl_certificate {};\n", self.ssl.certificate));
        config.push_str(&format!("    ssl_certificate_key {};\n", self.ssl.certificate_key));
        config.push_str(&format!("    ssl_protocols {};\n", self.ssl.protocols.join(" ")));
        config.push_str(&format!("    ssl_ciphers {};\n", self.ssl.ciphers));
        config.push_str(&format!("    ssl_prefer_server_ciphers {};\n",
            if self.ssl.prefer_server_ciphers { "on" } else { "off" }));
        config.push_str(&format!("    ssl_session_timeout {};\n", self.ssl.session_timeout));

        if self.ssl.stapling {
            config.push_str("    ssl_stapling on;\n");
            config.push_str("    ssl_stapling_verify on;\n");
        }

        // Security headers
        if self.security_headers {
            config.push_str("\n    # Security headers\n");
            config.push_str("    add_header X-Frame-Options \"SAMEORIGIN\" always;\n");
            config.push_str("    add_header X-Content-Type-Options \"nosniff\" always;\n");
            config.push_str("    add_header X-XSS-Protection \"1; mode=block\" always;\n");
            config.push_str("    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n");
            config.push_str("    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n");
        }

        // Locations
        for location in &self.locations {
            config.push_str(&format!("\n    location {} {{\n", location.path));
            if let Some(proxy) = &location.proxy_pass {
                config.push_str(&format!("        proxy_pass {};\n", proxy));
                config.push_str("        proxy_set_header Host $host;\n");
                config.push_str("        proxy_set_header X-Real-IP $remote_addr;\n");
            }
            if let Some(root) = &location.root {
                config.push_str(&format!("        root {};\n", root));
            }
            if let Some(rl) = &self.rate_limit {
                config.push_str(&format!("        limit_req zone={} burst={} nodelay;\n", rl.zone, rl.burst));
            }
            config.push_str("    }\n");
        }

        config.push_str("}\n");
        config
    }
}

impl Default for SslConfig {
    fn default() -> Self {
        Self {
            certificate: "/etc/ssl/certs/server.crt".to_string(),
            certificate_key: "/etc/ssl/private/server.key".to_string(),
            protocols: vec!["TLSv1.2".to_string(), "TLSv1.3".to_string()],
            ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256".to_string(),
            prefer_server_ciphers: true,
            session_timeout: "1d".to_string(),
            stapling: true,
        }
    }
}
```

## Security Checklist

- [ ] TLS 1.2+ only
- [ ] Strong cipher suites
- [ ] Security headers enabled
- [ ] Rate limiting configured
- [ ] OCSP stapling enabled
