# Rust Gateway Security Template

## Overview

Internet gateway wrapper with HTTPS inspection, download scanning, phishing
detection, and content filtering.

## Project Structure

```
my-gateway-security/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── proxy/
│   │   ├── mod.rs
│   │   └── https.rs
│   ├── scanner/
│   │   └── mod.rs
│   ├── phishing/
│   │   └── mod.rs
│   └── filter/
│       └── mod.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-gateway-security"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1.40", features = ["full"] }
hyper = { version = "1.4", features = ["full"] }
reqwest = { version = "0.12", features = ["rustls-tls"] }
url = "2.5"
serde = { version = "1.0", features = ["derive"] }
tracing = "0.1"
dashmap = "6.0"
```

## Core Implementation

### src/phishing/mod.rs

```rust
use dashmap::DashSet;
use url::Url;
use std::sync::Arc;

pub struct PhishingDetector {
    known_phishing: Arc<DashSet<String>>,
    suspicious_patterns: Vec<String>,
}

impl PhishingDetector {
    pub fn new() -> Self {
        Self {
            known_phishing: Arc::new(DashSet::new()),
            suspicious_patterns: vec![
                "login".to_string(),
                "signin".to_string(),
                "account".to_string(),
                "secure".to_string(),
                "verify".to_string(),
            ],
        }
    }

    pub fn add_known_phishing(&self, domain: &str) {
        self.known_phishing.insert(domain.to_string());
    }

    pub fn check_url(&self, url: &str) -> PhishingResult {
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return PhishingResult::Invalid,
        };

        let domain = parsed.domain().unwrap_or("");

        // Check known phishing
        if self.known_phishing.contains(domain) {
            return PhishingResult::Blocked("Known phishing domain".to_string());
        }

        // Check suspicious patterns in URL
        let url_lower = url.to_lowercase();
        for pattern in &self.suspicious_patterns {
            if url_lower.contains(pattern) && self.looks_suspicious(domain) {
                return PhishingResult::Suspicious(format!("Suspicious pattern: {}", pattern));
            }
        }

        // Check for IP address URLs
        if parsed.host().map(|h| h.to_string()).unwrap_or_default()
            .parse::<std::net::IpAddr>().is_ok() {
            return PhishingResult::Suspicious("IP address URL".to_string());
        }

        PhishingResult::Safe
    }

    fn looks_suspicious(&self, domain: &str) -> bool {
        // Check for typosquatting patterns
        let suspicious_tlds = ["tk", "ml", "ga", "cf", "gq"];
        let parts: Vec<&str> = domain.split('.').collect();

        if let Some(tld) = parts.last() {
            if suspicious_tlds.contains(tld) {
                return true;
            }
        }

        // Check for excessive subdomains
        parts.len() > 4
    }
}

#[derive(Debug)]
pub enum PhishingResult {
    Safe,
    Suspicious(String),
    Blocked(String),
    Invalid,
}
```

### src/filter/mod.rs

```rust
use dashmap::DashSet;
use std::sync::Arc;

pub struct ContentFilter {
    blocked_domains: Arc<DashSet<String>>,
    blocked_categories: Arc<DashSet<String>>,
    allowed_domains: Arc<DashSet<String>>,
}

impl ContentFilter {
    pub fn new() -> Self {
        Self {
            blocked_domains: Arc::new(DashSet::new()),
            blocked_categories: Arc::new(DashSet::new()),
            allowed_domains: Arc::new(DashSet::new()),
        }
    }

    pub fn block_domain(&self, domain: &str) {
        self.blocked_domains.insert(domain.to_string());
    }

    pub fn allow_domain(&self, domain: &str) {
        self.allowed_domains.insert(domain.to_string());
    }

    pub fn should_block(&self, domain: &str) -> bool {
        // Whitelist takes priority
        if self.allowed_domains.contains(domain) {
            return false;
        }

        // Check blocklist
        if self.blocked_domains.contains(domain) {
            return true;
        }

        // Check parent domains
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 0..parts.len() {
            let parent = parts[i..].join(".");
            if self.blocked_domains.contains(&parent) {
                return true;
            }
        }

        false
    }
}
```

## Security Checklist

- [ ] HTTPS inspection configured
- [ ] Phishing database updated
- [ ] Content filtering enabled
- [ ] Download scanning active
- [ ] Audit logging enabled
