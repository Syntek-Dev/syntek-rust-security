# Rust SSH Wrapper Template

## Overview

This template provides a secure SSH access wrapper with comprehensive logging,
command filtering, session management, and audit trails. It acts as a proxy
between users and SSH servers, enforcing security policies.

**Target Use Cases:**

- SSH bastion/jump host implementation
- Command auditing and filtering
- Session recording and replay
- Access control enforcement
- Compliance logging

## Project Structure

```
my-ssh-wrapper/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── config.rs
│   ├── session/
│   │   ├── mod.rs
│   │   ├── manager.rs
│   │   └── recording.rs
│   ├── policy/
│   │   ├── mod.rs
│   │   ├── command_filter.rs
│   │   └── access_control.rs
│   ├── audit/
│   │   ├── mod.rs
│   │   └── logger.rs
│   └── error.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-ssh-wrapper"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"

[dependencies]
tokio = { version = "1.40", features = ["full"] }
russh = "0.44"
russh-keys = "0.44"
serde = { version = "1.0", features = ["derive"] }
toml = "0.8"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1.10", features = ["v4"] }
thiserror = "2.0"
anyhow = "1.0"
clap = { version = "4.5", features = ["derive"] }
regex = "1.11"

[profile.release]
lto = true
strip = true
```

## Core Implementation

### src/session/manager.rs

```rust
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Session {
    pub id: Uuid,
    pub user: String,
    pub source_ip: String,
    pub target_host: String,
    pub started_at: DateTime<Utc>,
    pub commands: Vec<CommandEntry>,
}

#[derive(Debug, Clone)]
pub struct CommandEntry {
    pub timestamp: DateTime<Utc>,
    pub command: String,
    pub allowed: bool,
}

pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<Uuid, Session>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_session(&self, user: &str, source_ip: &str, target: &str) -> Uuid {
        let session = Session {
            id: Uuid::new_v4(),
            user: user.to_string(),
            source_ip: source_ip.to_string(),
            target_host: target.to_string(),
            started_at: Utc::now(),
            commands: Vec::new(),
        };
        let id = session.id;
        self.sessions.write().await.insert(id, session);
        id
    }

    pub async fn log_command(&self, session_id: Uuid, command: &str, allowed: bool) {
        if let Some(session) = self.sessions.write().await.get_mut(&session_id) {
            session.commands.push(CommandEntry {
                timestamp: Utc::now(),
                command: command.to_string(),
                allowed,
            });
        }
    }

    pub async fn end_session(&self, session_id: Uuid) -> Option<Session> {
        self.sessions.write().await.remove(&session_id)
    }
}
```

### src/policy/command_filter.rs

```rust
use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct CommandPolicy {
    pub allowed_patterns: Vec<String>,
    pub denied_patterns: Vec<String>,
    pub deny_by_default: bool,
}

pub struct CommandFilter {
    allowed: Vec<Regex>,
    denied: Vec<Regex>,
    deny_by_default: bool,
}

impl CommandFilter {
    pub fn new(policy: &CommandPolicy) -> Self {
        Self {
            allowed: policy.allowed_patterns.iter()
                .filter_map(|p| Regex::new(p).ok())
                .collect(),
            denied: policy.denied_patterns.iter()
                .filter_map(|p| Regex::new(p).ok())
                .collect(),
            deny_by_default: policy.deny_by_default,
        }
    }

    pub fn is_allowed(&self, command: &str) -> bool {
        // Check denied first
        for pattern in &self.denied {
            if pattern.is_match(command) {
                return false;
            }
        }
        // Check allowed
        for pattern in &self.allowed {
            if pattern.is_match(command) {
                return true;
            }
        }
        !self.deny_by_default
    }
}
```

## Security Checklist

- [ ] All sessions logged with unique IDs
- [ ] Command filtering enforced
- [ ] Session recordings encrypted
- [ ] Access policies configured
- [ ] Audit logs tamper-evident
- [ ] Key authentication required
- [ ] Rate limiting enabled
