# Rust IDS Engine Template

## Overview

Intrusion detection system with Snort/Suricata-compatible rule parsing, alert
management, and blocking capabilities.

## Project Structure

```
my-ids-engine/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── rules/
│   │   ├── mod.rs
│   │   └── parser.rs
│   ├── engine.rs
│   └── alerts.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-ids-engine"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1.40", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
tracing = "0.1"
regex = "1.11"
chrono = "0.4"
```

## Core Implementation

### src/rules/parser.rs

```rust
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnortRule {
    pub action: Action,
    pub protocol: String,
    pub src_ip: String,
    pub src_port: String,
    pub direction: Direction,
    pub dst_ip: String,
    pub dst_port: String,
    pub options: RuleOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    Alert,
    Log,
    Pass,
    Drop,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Direction {
    ToServer,
    ToClient,
    Both,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleOptions {
    pub msg: Option<String>,
    pub sid: Option<u32>,
    pub rev: Option<u32>,
    pub content: Vec<String>,
    pub pcre: Option<String>,
    pub classtype: Option<String>,
    pub priority: Option<u32>,
}

pub fn parse_rule(line: &str) -> Option<SnortRule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    // Basic pattern: action protocol src_ip src_port direction dst_ip dst_port (options)
    let parts: Vec<&str> = line.splitn(8, ' ').collect();
    if parts.len() < 7 {
        return None;
    }

    let action = match parts[0] {
        "alert" => Action::Alert,
        "log" => Action::Log,
        "pass" => Action::Pass,
        "drop" => Action::Drop,
        "reject" => Action::Reject,
        _ => return None,
    };

    let direction = match parts[4] {
        "->" => Direction::ToServer,
        "<-" => Direction::ToClient,
        "<>" => Direction::Both,
        _ => Direction::ToServer,
    };

    let options = if parts.len() > 7 {
        parse_options(parts[7])
    } else {
        RuleOptions::default()
    };

    Some(SnortRule {
        action,
        protocol: parts[1].to_string(),
        src_ip: parts[2].to_string(),
        src_port: parts[3].to_string(),
        direction,
        dst_ip: parts[5].to_string(),
        dst_port: parts[6].to_string(),
        options,
    })
}

fn parse_options(opts: &str) -> RuleOptions {
    let mut options = RuleOptions::default();

    // Extract msg
    if let Some(caps) = Regex::new(r#"msg:\s*"([^"]+)""#).ok()
        .and_then(|re| re.captures(opts)) {
        options.msg = Some(caps[1].to_string());
    }

    // Extract sid
    if let Some(caps) = Regex::new(r"sid:\s*(\d+)").ok()
        .and_then(|re| re.captures(opts)) {
        options.sid = caps[1].parse().ok();
    }

    // Extract content
    for caps in Regex::new(r#"content:\s*"([^"]+)""#).ok()
        .map(|re| re.captures_iter(opts))
        .into_iter().flatten() {
        options.content.push(caps[1].to_string());
    }

    options
}
```

### src/alerts.rs

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: u64,
    pub timestamp: DateTime<Utc>,
    pub rule_sid: u32,
    pub message: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub severity: u32,
}

pub struct AlertManager {
    alerts: Arc<RwLock<VecDeque<Alert>>>,
    max_alerts: usize,
    next_id: Arc<RwLock<u64>>,
}

impl AlertManager {
    pub fn new(max_alerts: usize) -> Self {
        Self {
            alerts: Arc::new(RwLock::new(VecDeque::new())),
            max_alerts,
            next_id: Arc::new(RwLock::new(1)),
        }
    }

    pub async fn add_alert(&self, mut alert: Alert) {
        let mut id = self.next_id.write().await;
        alert.id = *id;
        *id += 1;
        drop(id);

        let mut alerts = self.alerts.write().await;
        if alerts.len() >= self.max_alerts {
            alerts.pop_front();
        }
        alerts.push_back(alert);
    }

    pub async fn get_recent(&self, count: usize) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        alerts.iter().rev().take(count).cloned().collect()
    }

    pub async fn get_by_severity(&self, min_severity: u32) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        alerts.iter().filter(|a| a.severity >= min_severity).cloned().collect()
    }
}
```

## Security Checklist

- [ ] Rules loaded from trusted source
- [ ] Alert rate limiting
- [ ] Log rotation configured
- [ ] Blocking rules tested
- [ ] Performance tuned
