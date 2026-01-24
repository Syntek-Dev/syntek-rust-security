# Rust Redis Config Template

## Overview

Secure Redis/Valkey configuration generator with authentication, TLS, and ACL
support.

## Project Structure

```
my-redis-config/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── config.rs
│   └── acl.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-redis-config"
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
pub struct RedisConfig {
    pub bind: Vec<String>,
    pub port: u16,
    pub requirepass: Option<String>,
    pub tls: Option<TlsConfig>,
    pub maxmemory: String,
    pub maxmemory_policy: String,
    pub acl_users: Vec<AclUser>,
    pub protected_mode: bool,
    pub rename_commands: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub port: u16,
    pub cert_file: String,
    pub key_file: String,
    pub ca_cert_file: Option<String>,
    pub auth_clients: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclUser {
    pub name: String,
    pub enabled: bool,
    pub passwords: Vec<String>,
    pub commands: Vec<String>,
    pub keys: Vec<String>,
}

impl RedisConfig {
    pub fn generate(&self) -> String {
        let mut config = String::new();

        // Network
        config.push_str(&format!("bind {}\n", self.bind.join(" ")));
        config.push_str(&format!("port {}\n", self.port));
        config.push_str(&format!("protected-mode {}\n", if self.protected_mode { "yes" } else { "no" }));

        // TLS
        if let Some(tls) = &self.tls {
            config.push_str(&format!("\ntls-port {}\n", tls.port));
            config.push_str(&format!("tls-cert-file {}\n", tls.cert_file));
            config.push_str(&format!("tls-key-file {}\n", tls.key_file));
            if let Some(ca) = &tls.ca_cert_file {
                config.push_str(&format!("tls-ca-cert-file {}\n", ca));
            }
            config.push_str(&format!("tls-auth-clients {}\n", if tls.auth_clients { "yes" } else { "no" }));
        }

        // Authentication
        if let Some(pass) = &self.requirepass {
            config.push_str(&format!("\nrequirepass {}\n", pass));
        }

        // Memory
        config.push_str(&format!("\nmaxmemory {}\n", self.maxmemory));
        config.push_str(&format!("maxmemory-policy {}\n", self.maxmemory_policy));

        // Security - rename dangerous commands
        for (cmd, new_name) in &self.rename_commands {
            config.push_str(&format!("rename-command {} {}\n", cmd, new_name));
        }

        // ACL
        for user in &self.acl_users {
            let mut acl = format!("user {} ", user.name);
            acl.push_str(if user.enabled { "on " } else { "off " });
            for pass in &user.passwords {
                acl.push_str(&format!(">{} ", pass));
            }
            for cmd in &user.commands {
                acl.push_str(&format!("{} ", cmd));
            }
            for key in &user.keys {
                acl.push_str(&format!("~{} ", key));
            }
            config.push_str(&format!("{}\n", acl.trim()));
        }

        config
    }
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            bind: vec!["127.0.0.1".to_string()],
            port: 6379,
            requirepass: None,
            tls: None,
            maxmemory: "256mb".to_string(),
            maxmemory_policy: "allkeys-lru".to_string(),
            acl_users: vec![],
            protected_mode: true,
            rename_commands: vec![
                ("FLUSHALL".to_string(), "".to_string()),
                ("FLUSHDB".to_string(), "".to_string()),
                ("DEBUG".to_string(), "".to_string()),
                ("CONFIG".to_string(), "".to_string()),
            ],
        }
    }
}
```

## Security Checklist

- [ ] Protected mode enabled
- [ ] Authentication required
- [ ] TLS configured
- [ ] Dangerous commands disabled
- [ ] ACL users configured
- [ ] Memory limits set
