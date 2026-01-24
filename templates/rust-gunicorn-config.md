# Rust Gunicorn Config Template

## Overview

Secure Gunicorn + Uvicorn configuration generator for Django/FastAPI
applications.

## Project Structure

```
my-gunicorn-config/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── gunicorn.rs
│   └── uvicorn.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-gunicorn-config"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
```

## Core Implementation

### src/gunicorn.rs

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GunicornConfig {
    pub bind: String,
    pub workers: u32,
    pub worker_class: String,
    pub timeout: u32,
    pub keepalive: u32,
    pub max_requests: u32,
    pub max_requests_jitter: u32,
    pub preload_app: bool,
    pub user: Option<String>,
    pub group: Option<String>,
    pub umask: u32,
    pub secure_scheme_headers: bool,
}

impl GunicornConfig {
    pub fn generate_python(&self) -> String {
        let mut config = String::new();
        config.push_str("# Gunicorn configuration\n\n");
        config.push_str(&format!("bind = \"{}\"\n", self.bind));
        config.push_str(&format!("workers = {}\n", self.workers));
        config.push_str(&format!("worker_class = \"{}\"\n", self.worker_class));
        config.push_str(&format!("timeout = {}\n", self.timeout));
        config.push_str(&format!("keepalive = {}\n", self.keepalive));
        config.push_str(&format!("max_requests = {}\n", self.max_requests));
        config.push_str(&format!("max_requests_jitter = {}\n", self.max_requests_jitter));
        config.push_str(&format!("preload_app = {}\n", if self.preload_app { "True" } else { "False" }));

        if let Some(user) = &self.user {
            config.push_str(&format!("user = \"{}\"\n", user));
        }
        if let Some(group) = &self.group {
            config.push_str(&format!("group = \"{}\"\n", group));
        }

        config.push_str(&format!("umask = 0o{:o}\n", self.umask));

        if self.secure_scheme_headers {
            config.push_str("\n# Secure headers\n");
            config.push_str("forwarded_allow_ips = \"*\"\n");
            config.push_str("secure_scheme_headers = {\n");
            config.push_str("    \"X-FORWARDED-PROTOCOL\": \"ssl\",\n");
            config.push_str("    \"X-FORWARDED-PROTO\": \"https\",\n");
            config.push_str("    \"X-FORWARDED-SSL\": \"on\"\n");
            config.push_str("}\n");
        }

        // Security settings
        config.push_str("\n# Security\n");
        config.push_str("limit_request_line = 4094\n");
        config.push_str("limit_request_fields = 100\n");
        config.push_str("limit_request_field_size = 8190\n");

        config
    }
}

impl Default for GunicornConfig {
    fn default() -> Self {
        let cpu_count = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(2);

        Self {
            bind: "127.0.0.1:8000".to_string(),
            workers: cpu_count * 2 + 1,
            worker_class: "uvicorn.workers.UvicornWorker".to_string(),
            timeout: 30,
            keepalive: 5,
            max_requests: 1000,
            max_requests_jitter: 50,
            preload_app: true,
            user: None,
            group: None,
            umask: 0o007,
            secure_scheme_headers: true,
        }
    }
}
```

## Security Checklist

- [ ] Workers run as non-root
- [ ] Request limits configured
- [ ] Worker recycling enabled
- [ ] Secure scheme headers
- [ ] Timeout configured
