# Rust Server Firewall Template

## Overview

This template provides Rust bindings for iptables/nftables firewall management
with a safe, type-checked API for managing firewall rules programmatically.

**Target Use Cases:**

- Dynamic firewall rule management
- Application-level firewalls
- Intrusion prevention systems
- Network security automation

## Project Structure

```
my-server-firewall/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── iptables/
│   │   ├── mod.rs
│   │   ├── chain.rs
│   │   ├── rule.rs
│   │   └── table.rs
│   ├── nftables/
│   │   ├── mod.rs
│   │   └── ruleset.rs
│   └── error.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-server-firewall"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"

[dependencies]
tokio = { version = "1.40", features = ["process"] }
serde = { version = "1.0", features = ["derive"] }
thiserror = "2.0"
tracing = "0.1"
ipnetwork = "0.20"
```

## Core Implementation

### src/iptables/rule.rs

```rust
use ipnetwork::IpNetwork;
use std::fmt;

#[derive(Debug, Clone)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    All,
}

#[derive(Debug, Clone)]
pub enum Action {
    Accept,
    Drop,
    Reject,
    Log,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub protocol: Protocol,
    pub source: Option<IpNetwork>,
    pub destination: Option<IpNetwork>,
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub action: Action,
    pub comment: Option<String>,
}

impl Rule {
    pub fn builder() -> RuleBuilder {
        RuleBuilder::default()
    }

    pub fn to_iptables_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        args.push("-p".to_string());
        args.push(match self.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
            Protocol::All => "all",
        }.to_string());

        if let Some(src) = &self.source {
            args.push("-s".to_string());
            args.push(src.to_string());
        }

        if let Some(dst) = &self.destination {
            args.push("-d".to_string());
            args.push(dst.to_string());
        }

        if let Some(port) = self.dest_port {
            args.push("--dport".to_string());
            args.push(port.to_string());
        }

        args.push("-j".to_string());
        args.push(match self.action {
            Action::Accept => "ACCEPT",
            Action::Drop => "DROP",
            Action::Reject => "REJECT",
            Action::Log => "LOG",
        }.to_string());

        args
    }
}

#[derive(Default)]
pub struct RuleBuilder {
    rule: Rule,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            protocol: Protocol::All,
            source: None,
            destination: None,
            source_port: None,
            dest_port: None,
            action: Action::Accept,
            comment: None,
        }
    }
}

impl RuleBuilder {
    pub fn protocol(mut self, proto: Protocol) -> Self {
        self.rule.protocol = proto;
        self
    }

    pub fn source(mut self, network: IpNetwork) -> Self {
        self.rule.source = Some(network);
        self
    }

    pub fn dest_port(mut self, port: u16) -> Self {
        self.rule.dest_port = Some(port);
        self
    }

    pub fn action(mut self, action: Action) -> Self {
        self.rule.action = action;
        self
    }

    pub fn build(self) -> Rule {
        self.rule
    }
}
```

### src/iptables/mod.rs

```rust
use crate::error::FirewallError;
use std::process::Command;
use tracing::{info, warn};

pub mod chain;
pub mod rule;
pub mod table;

pub use rule::{Action, Protocol, Rule};

pub struct IptablesManager;

impl IptablesManager {
    pub fn new() -> Self {
        Self
    }

    pub fn add_rule(&self, chain: &str, rule: &Rule) -> Result<(), FirewallError> {
        let mut args = vec!["-A".to_string(), chain.to_string()];
        args.extend(rule.to_iptables_args());

        let output = Command::new("iptables")
            .args(&args)
            .output()
            .map_err(|e| FirewallError::ExecutionError(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::RuleError(stderr.to_string()));
        }

        info!(chain = chain, "Added iptables rule");
        Ok(())
    }

    pub fn delete_rule(&self, chain: &str, rule: &Rule) -> Result<(), FirewallError> {
        let mut args = vec!["-D".to_string(), chain.to_string()];
        args.extend(rule.to_iptables_args());

        let output = Command::new("iptables")
            .args(&args)
            .output()
            .map_err(|e| FirewallError::ExecutionError(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::RuleError(stderr.to_string()));
        }

        info!(chain = chain, "Deleted iptables rule");
        Ok(())
    }

    pub fn list_rules(&self, chain: &str) -> Result<String, FirewallError> {
        let output = Command::new("iptables")
            .args(&["-L", chain, "-n", "-v"])
            .output()
            .map_err(|e| FirewallError::ExecutionError(e.to_string()))?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}
```

## Security Checklist

- [ ] Root privileges required for iptables
- [ ] Rules validated before application
- [ ] Audit logging for all changes
- [ ] Rollback capability for failed rules
- [ ] Default deny policy configured
- [ ] Rate limiting rules included
