# Rust Router Security Template

## Overview

Router security wrapper with deep packet inspection, IDS/IPS, traffic filtering,
and threat detection for DIY routers.

## Project Structure

```
my-router-security/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── packet/
│   │   ├── mod.rs
│   │   ├── capture.rs
│   │   └── inspect.rs
│   ├── filter/
│   │   ├── mod.rs
│   │   ├── ip.rs
│   │   └── domain.rs
│   ├── ids/
│   │   ├── mod.rs
│   │   └── rules.rs
│   └── config.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-router-security"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"

[dependencies]
tokio = { version = "1.40", features = ["full"] }
pnet = "0.35"
etherparse = "0.15"
serde = { version = "1.0", features = ["derive"] }
tracing = "0.1"
thiserror = "2.0"
dashmap = "6.0"
ipnetwork = "0.20"
```

## Core Implementation

### src/packet/inspect.rs

```rust
use etherparse::{SlicedPacket, InternetSlice, TransportSlice};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub payload_len: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

pub fn inspect_packet(data: &[u8]) -> Option<PacketInfo> {
    let packet = SlicedPacket::from_ethernet(data).ok()?;

    let (src_ip, dst_ip) = match packet.ip {
        Some(InternetSlice::Ipv4(ipv4, _)) => (
            Some(IpAddr::V4(ipv4.source_addr())),
            Some(IpAddr::V4(ipv4.destination_addr())),
        ),
        Some(InternetSlice::Ipv6(ipv6, _)) => (
            Some(IpAddr::V6(ipv6.source_addr())),
            Some(IpAddr::V6(ipv6.destination_addr())),
        ),
        None => (None, None),
    };

    let (src_port, dst_port, protocol) = match packet.transport {
        Some(TransportSlice::Tcp(tcp)) => (
            Some(tcp.source_port()),
            Some(tcp.destination_port()),
            Protocol::Tcp,
        ),
        Some(TransportSlice::Udp(udp)) => (
            Some(udp.source_port()),
            Some(udp.destination_port()),
            Protocol::Udp,
        ),
        Some(TransportSlice::Icmpv4(_)) | Some(TransportSlice::Icmpv6(_)) => {
            (None, None, Protocol::Icmp)
        }
        _ => (None, None, Protocol::Other(0)),
    };

    Some(PacketInfo {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        payload_len: packet.payload.len(),
    })
}
```

### src/filter/ip.rs

```rust
use dashmap::DashSet;
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::sync::Arc;

pub struct IpFilter {
    blocked_ips: Arc<DashSet<IpAddr>>,
    blocked_networks: Arc<DashSet<IpNetwork>>,
}

impl IpFilter {
    pub fn new() -> Self {
        Self {
            blocked_ips: Arc::new(DashSet::new()),
            blocked_networks: Arc::new(DashSet::new()),
        }
    }

    pub fn block_ip(&self, ip: IpAddr) {
        self.blocked_ips.insert(ip);
    }

    pub fn block_network(&self, network: IpNetwork) {
        self.blocked_networks.insert(network);
    }

    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        if self.blocked_ips.contains(ip) {
            return true;
        }
        for network in self.blocked_networks.iter() {
            if network.contains(*ip) {
                return true;
            }
        }
        false
    }

    pub fn unblock_ip(&self, ip: &IpAddr) {
        self.blocked_ips.remove(ip);
    }
}
```

### src/ids/rules.rs

```rust
use serde::{Deserialize, Serialize};
use crate::packet::PacketInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsRule {
    pub id: u32,
    pub name: String,
    pub action: Action,
    pub protocol: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub content: Option<String>,
    pub msg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    Alert,
    Drop,
    Pass,
}

pub struct RuleEngine {
    rules: Vec<IdsRule>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: IdsRule) {
        self.rules.push(rule);
    }

    pub fn check_packet(&self, packet: &PacketInfo, payload: &[u8]) -> Vec<&IdsRule> {
        self.rules.iter()
            .filter(|rule| self.matches_rule(rule, packet, payload))
            .collect()
    }

    fn matches_rule(&self, rule: &IdsRule, packet: &PacketInfo, payload: &[u8]) -> bool {
        // Check port
        if let Some(port) = rule.dst_port {
            if packet.dst_port != Some(port) {
                return false;
            }
        }

        // Check content signature
        if let Some(content) = &rule.content {
            if !payload.windows(content.len())
                .any(|w| w == content.as_bytes()) {
                return false;
            }
        }

        true
    }
}
```

## Security Checklist

- [ ] Packet inspection enabled
- [ ] IP blocklist configured
- [ ] IDS rules loaded
- [ ] Logging enabled
- [ ] Rate limiting active
