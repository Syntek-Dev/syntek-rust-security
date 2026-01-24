# Rust Deep Packet Inspection Engine Template

High-performance deep packet inspection library for protocol dissection and
traffic analysis.

## Project Structure

```
rust-dpi-engine/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── capture/
│   │   ├── mod.rs
│   │   ├── pcap.rs
│   │   └── af_packet.rs
│   ├── protocols/
│   │   ├── mod.rs
│   │   ├── ethernet.rs
│   │   ├── ip.rs
│   │   ├── tcp.rs
│   │   ├── udp.rs
│   │   ├── dns.rs
│   │   ├── http.rs
│   │   └── tls.rs
│   ├── inspection/
│   │   ├── mod.rs
│   │   ├── engine.rs
│   │   ├── rules.rs
│   │   └── patterns.rs
│   ├── flow/
│   │   ├── mod.rs
│   │   ├── tracker.rs
│   │   └── reassembly.rs
│   └── output/
│       ├── mod.rs
│       └── events.rs
└── rules/
    └── default.rules
```

## Cargo.toml

```toml
[package]
name = "rust-dpi-engine"
version = "0.1.0"
edition = "2021"
rust-version = "1.92"

[dependencies]
pcap = "2"
pnet = "0.35"
aho-corasick = "1"
regex = "1"
bytes = "1"
parking_lot = "0.12"
dashmap = "6"
tracing = "0.1"
thiserror = "2"
serde = { version = "1", features = ["derive"] }
crossbeam-channel = "0.5"
memchr = "2"
httparse = "1"

[features]
af_packet = []
```

## Core Implementation

### src/lib.rs

```rust
pub mod capture;
pub mod protocols;
pub mod inspection;
pub mod flow;
pub mod output;

pub use inspection::Engine;
pub use flow::FlowTracker;
pub use output::DpiEvent;
```

### src/protocols/mod.rs

```rust
pub mod ethernet;
pub mod ip;
pub mod tcp;
pub mod udp;
pub mod dns;
pub mod http;
pub mod tls;

use bytes::Bytes;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Packet too short")]
    TooShort,
    #[error("Invalid header")]
    InvalidHeader,
    #[error("Unsupported protocol")]
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Ethernet,
    IPv4,
    IPv6,
    TCP,
    UDP,
    ICMP,
    DNS,
    HTTP,
    HTTPS,
    TLS,
    Unknown(u16),
}

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub timestamp: std::time::SystemTime,
    pub layers: Vec<LayerInfo>,
    pub payload: Bytes,
}

#[derive(Debug, Clone)]
pub struct LayerInfo {
    pub protocol: Protocol,
    pub header_len: usize,
    pub data: LayerData,
}

#[derive(Debug, Clone)]
pub enum LayerData {
    Ethernet(ethernet::EthernetHeader),
    IPv4(ip::Ipv4Header),
    IPv6(ip::Ipv6Header),
    TCP(tcp::TcpHeader),
    UDP(udp::UdpHeader),
    DNS(dns::DnsInfo),
    HTTP(http::HttpInfo),
    TLS(tls::TlsInfo),
    Raw(Bytes),
}
```

### src/protocols/ip.rs

```rust
use bytes::Bytes;
use std::net::{Ipv4Addr, Ipv6Addr};
use super::ParseError;

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
}

impl Ipv4Header {
    pub fn parse(data: &[u8]) -> Result<(Self, usize), ParseError> {
        if data.len() < 20 {
            return Err(ParseError::TooShort);
        }

        let version_ihl = data[0];
        let version = version_ihl >> 4;
        let ihl = (version_ihl & 0x0F) as usize;

        if version != 4 {
            return Err(ParseError::InvalidHeader);
        }

        let header_len = ihl * 4;
        if data.len() < header_len {
            return Err(ParseError::TooShort);
        }

        let dscp_ecn = data[1];
        let total_length = u16::from_be_bytes([data[2], data[3]]);
        let identification = u16::from_be_bytes([data[4], data[5]]);
        let flags_fragment = u16::from_be_bytes([data[6], data[7]]);
        let flags = (flags_fragment >> 13) as u8;
        let fragment_offset = flags_fragment & 0x1FFF;
        let ttl = data[8];
        let protocol = data[9];
        let checksum = u16::from_be_bytes([data[10], data[11]]);
        let src_addr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst_addr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        Ok((Self {
            version,
            ihl: ihl as u8,
            dscp: dscp_ecn >> 2,
            ecn: dscp_ecn & 0x03,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            src_addr,
            dst_addr,
        }, header_len))
    }

    pub fn is_fragmented(&self) -> bool {
        self.flags & 0x01 != 0 || self.fragment_offset != 0
    }
}

#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_addr: Ipv6Addr,
    pub dst_addr: Ipv6Addr,
}

impl Ipv6Header {
    pub fn parse(data: &[u8]) -> Result<(Self, usize), ParseError> {
        if data.len() < 40 {
            return Err(ParseError::TooShort);
        }

        let version = data[0] >> 4;
        if version != 6 {
            return Err(ParseError::InvalidHeader);
        }

        let traffic_class = ((data[0] & 0x0F) << 4) | (data[1] >> 4);
        let flow_label = ((data[1] as u32 & 0x0F) << 16)
            | ((data[2] as u32) << 8)
            | (data[3] as u32);
        let payload_length = u16::from_be_bytes([data[4], data[5]]);
        let next_header = data[6];
        let hop_limit = data[7];

        let src_bytes: [u8; 16] = data[8..24].try_into().unwrap();
        let dst_bytes: [u8; 16] = data[24..40].try_into().unwrap();

        Ok((Self {
            version,
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            src_addr: Ipv6Addr::from(src_bytes),
            dst_addr: Ipv6Addr::from(dst_bytes),
        }, 40))
    }
}
```

### src/protocols/tcp.rs

```rust
use super::ParseError;

#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpHeader {
    pub fn parse(data: &[u8]) -> Result<(Self, usize), ParseError> {
        if data.len() < 20 {
            return Err(ParseError::TooShort);
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let data_offset = (data[12] >> 4) as usize;
        let header_len = data_offset * 4;

        if data.len() < header_len {
            return Err(ParseError::TooShort);
        }

        let flags_byte = data[13];
        let flags = TcpFlags {
            fin: flags_byte & 0x01 != 0,
            syn: flags_byte & 0x02 != 0,
            rst: flags_byte & 0x04 != 0,
            psh: flags_byte & 0x08 != 0,
            ack: flags_byte & 0x10 != 0,
            urg: flags_byte & 0x20 != 0,
            ece: flags_byte & 0x40 != 0,
            cwr: flags_byte & 0x80 != 0,
        };

        let window = u16::from_be_bytes([data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let urgent_ptr = u16::from_be_bytes([data[18], data[19]]);

        Ok((Self {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            data_offset: data_offset as u8,
            flags,
            window,
            checksum,
            urgent_ptr,
        }, header_len))
    }

    pub fn is_handshake(&self) -> bool {
        self.flags.syn && !self.flags.ack
    }

    pub fn is_handshake_ack(&self) -> bool {
        self.flags.syn && self.flags.ack
    }

    pub fn is_connection_end(&self) -> bool {
        self.flags.fin || self.flags.rst
    }
}
```

### src/protocols/http.rs

```rust
use bytes::Bytes;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct HttpInfo {
    pub is_request: bool,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub status_code: Option<u16>,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub host: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<usize>,
}

impl HttpInfo {
    pub fn parse(data: &[u8]) -> Option<Self> {
        let mut headers = [httparse::EMPTY_HEADER; 64];

        // Try parsing as request first
        let mut req = httparse::Request::new(&mut headers);
        if let Ok(httparse::Status::Complete(_)) = req.parse(data) {
            let header_map: HashMap<String, String> = req.headers.iter()
                .map(|h| (h.name.to_lowercase(), String::from_utf8_lossy(h.value).to_string()))
                .collect();

            return Some(Self {
                is_request: true,
                method: req.method.map(String::from),
                uri: req.path.map(String::from),
                status_code: None,
                version: format!("HTTP/1.{}", req.version.unwrap_or(1)),
                host: header_map.get("host").cloned(),
                content_type: header_map.get("content-type").cloned(),
                content_length: header_map.get("content-length")
                    .and_then(|v| v.parse().ok()),
                headers: header_map,
            });
        }

        // Try parsing as response
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut headers);
        if let Ok(httparse::Status::Complete(_)) = resp.parse(data) {
            let header_map: HashMap<String, String> = resp.headers.iter()
                .map(|h| (h.name.to_lowercase(), String::from_utf8_lossy(h.value).to_string()))
                .collect();

            return Some(Self {
                is_request: false,
                method: None,
                uri: None,
                status_code: resp.code,
                version: format!("HTTP/1.{}", resp.version.unwrap_or(1)),
                host: None,
                content_type: header_map.get("content-type").cloned(),
                content_length: header_map.get("content-length")
                    .and_then(|v| v.parse().ok()),
                headers: header_map,
            });
        }

        None
    }
}
```

### src/protocols/tls.rs

```rust
#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub record_type: TlsRecordType,
    pub version: TlsVersion,
    pub length: u16,
    pub handshake: Option<TlsHandshake>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsRecordType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Unknown(u8),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsVersion {
    Ssl3,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Unknown(u16),
}

#[derive(Debug, Clone)]
pub struct TlsHandshake {
    pub msg_type: TlsHandshakeType,
    pub client_hello: Option<ClientHello>,
    pub server_hello: Option<ServerHello>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsHandshakeType {
    ClientHello,
    ServerHello,
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone,
    CertificateVerify,
    ClientKeyExchange,
    Finished,
    Unknown(u8),
}

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub version: TlsVersion,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ServerHello {
    pub version: TlsVersion,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
}

impl TlsInfo {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }

        let record_type = match data[0] {
            20 => TlsRecordType::ChangeCipherSpec,
            21 => TlsRecordType::Alert,
            22 => TlsRecordType::Handshake,
            23 => TlsRecordType::ApplicationData,
            n => TlsRecordType::Unknown(n),
        };

        let version = Self::parse_version(u16::from_be_bytes([data[1], data[2]]));
        let length = u16::from_be_bytes([data[3], data[4]]);

        let handshake = if record_type == TlsRecordType::Handshake && data.len() > 5 {
            Self::parse_handshake(&data[5..])
        } else {
            None
        };

        Some(Self {
            record_type,
            version,
            length,
            handshake,
        })
    }

    fn parse_version(v: u16) -> TlsVersion {
        match v {
            0x0300 => TlsVersion::Ssl3,
            0x0301 => TlsVersion::Tls10,
            0x0302 => TlsVersion::Tls11,
            0x0303 => TlsVersion::Tls12,
            0x0304 => TlsVersion::Tls13,
            n => TlsVersion::Unknown(n),
        }
    }

    fn parse_handshake(data: &[u8]) -> Option<TlsHandshake> {
        if data.is_empty() {
            return None;
        }

        let msg_type = match data[0] {
            1 => TlsHandshakeType::ClientHello,
            2 => TlsHandshakeType::ServerHello,
            11 => TlsHandshakeType::Certificate,
            12 => TlsHandshakeType::ServerKeyExchange,
            13 => TlsHandshakeType::CertificateRequest,
            14 => TlsHandshakeType::ServerHelloDone,
            15 => TlsHandshakeType::CertificateVerify,
            16 => TlsHandshakeType::ClientKeyExchange,
            20 => TlsHandshakeType::Finished,
            n => TlsHandshakeType::Unknown(n),
        };

        let client_hello = if msg_type == TlsHandshakeType::ClientHello {
            Self::parse_client_hello(&data[4..])
        } else {
            None
        };

        Some(TlsHandshake {
            msg_type,
            client_hello,
            server_hello: None, // TODO: implement
        })
    }

    fn parse_client_hello(data: &[u8]) -> Option<ClientHello> {
        if data.len() < 38 {
            return None;
        }

        let version = Self::parse_version(u16::from_be_bytes([data[0], data[1]]));
        let mut random = [0u8; 32];
        random.copy_from_slice(&data[2..34]);

        let session_id_len = data[34] as usize;
        if data.len() < 35 + session_id_len {
            return None;
        }
        let session_id = data[35..35 + session_id_len].to_vec();

        let mut offset = 35 + session_id_len;
        if data.len() < offset + 2 {
            return None;
        }

        let cipher_suites_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        let cipher_suites: Vec<u16> = (0..cipher_suites_len / 2)
            .filter_map(|i| {
                let idx = offset + i * 2;
                if idx + 1 < data.len() {
                    Some(u16::from_be_bytes([data[idx], data[idx + 1]]))
                } else {
                    None
                }
            })
            .collect();

        // Parse SNI from extensions (simplified)
        let sni = Self::extract_sni(data);

        Some(ClientHello {
            version,
            random,
            session_id,
            cipher_suites,
            sni,
            alpn: Vec::new(),
        })
    }

    fn extract_sni(data: &[u8]) -> Option<String> {
        // Look for SNI extension (type 0x0000) in extensions
        let pattern = &[0x00, 0x00]; // SNI extension type

        for i in 0..data.len().saturating_sub(10) {
            if data[i..].starts_with(pattern) {
                // Found potential SNI, try to extract hostname
                let sni_offset = i + 9; // Skip extension header
                if sni_offset < data.len() {
                    let name_len = data.get(sni_offset.saturating_sub(2)..sni_offset)
                        .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)?;

                    if sni_offset + name_len <= data.len() {
                        if let Ok(name) = std::str::from_utf8(&data[sni_offset..sni_offset + name_len]) {
                            return Some(name.to_string());
                        }
                    }
                }
            }
        }

        None
    }
}
```

### src/inspection/engine.rs

```rust
use std::sync::Arc;
use bytes::Bytes;
use crossbeam_channel::{Sender, Receiver};
use parking_lot::RwLock;

use crate::protocols::{ParsedPacket, Protocol, LayerData};
use crate::flow::FlowTracker;
use crate::output::DpiEvent;
use super::rules::{Rule, RuleSet};
use super::patterns::PatternMatcher;

pub struct Engine {
    rules: Arc<RwLock<RuleSet>>,
    pattern_matcher: Arc<PatternMatcher>,
    flow_tracker: Arc<FlowTracker>,
    event_tx: Sender<DpiEvent>,
}

impl Engine {
    pub fn new(event_tx: Sender<DpiEvent>) -> Self {
        Self {
            rules: Arc::new(RwLock::new(RuleSet::new())),
            pattern_matcher: Arc::new(PatternMatcher::new()),
            flow_tracker: Arc::new(FlowTracker::new()),
            event_tx,
        }
    }

    pub fn load_rules(&self, rules: Vec<Rule>) {
        let mut rule_set = self.rules.write();
        for rule in rules {
            rule_set.add_rule(rule);
        }

        // Rebuild pattern matcher
        Arc::make_mut(&mut Arc::clone(&self.pattern_matcher))
            .build_from_rules(&rule_set);
    }

    pub fn inspect(&self, packet: &ParsedPacket) -> Vec<DpiEvent> {
        let mut events = Vec::new();

        // Extract flow key and update tracker
        if let Some(flow_key) = self.extract_flow_key(packet) {
            self.flow_tracker.update(&flow_key, packet);
        }

        // Protocol-specific inspection
        for layer in &packet.layers {
            match &layer.data {
                LayerData::HTTP(http) => {
                    events.extend(self.inspect_http(http, packet));
                }
                LayerData::TLS(tls) => {
                    events.extend(self.inspect_tls(tls, packet));
                }
                LayerData::DNS(dns) => {
                    events.extend(self.inspect_dns(dns, packet));
                }
                _ => {}
            }
        }

        // Pattern matching on payload
        if !packet.payload.is_empty() {
            let matches = self.pattern_matcher.scan(&packet.payload);
            for (rule_id, offset) in matches {
                if let Some(rule) = self.rules.read().get_rule(rule_id) {
                    events.push(DpiEvent::PatternMatch {
                        rule_name: rule.name.clone(),
                        rule_id,
                        offset,
                        severity: rule.severity,
                    });
                }
            }
        }

        // Send events
        for event in &events {
            let _ = self.event_tx.send(event.clone());
        }

        events
    }

    fn extract_flow_key(&self, packet: &ParsedPacket) -> Option<crate::flow::FlowKey> {
        let mut src_ip = None;
        let mut dst_ip = None;
        let mut src_port = 0u16;
        let mut dst_port = 0u16;
        let mut protocol = 0u8;

        for layer in &packet.layers {
            match &layer.data {
                LayerData::IPv4(ip) => {
                    src_ip = Some(std::net::IpAddr::V4(ip.src_addr));
                    dst_ip = Some(std::net::IpAddr::V4(ip.dst_addr));
                    protocol = ip.protocol;
                }
                LayerData::TCP(tcp) => {
                    src_port = tcp.src_port;
                    dst_port = tcp.dst_port;
                }
                LayerData::UDP(udp) => {
                    src_port = udp.src_port;
                    dst_port = udp.dst_port;
                }
                _ => {}
            }
        }

        Some(crate::flow::FlowKey {
            src_ip: src_ip?,
            dst_ip: dst_ip?,
            src_port,
            dst_port,
            protocol,
        })
    }

    fn inspect_http(
        &self,
        http: &crate::protocols::http::HttpInfo,
        _packet: &ParsedPacket,
    ) -> Vec<DpiEvent> {
        let mut events = Vec::new();

        if let Some(ref uri) = http.uri {
            // Check for suspicious patterns
            if uri.contains("..") || uri.contains("<script") {
                events.push(DpiEvent::Suspicious {
                    category: "http".into(),
                    message: format!("Suspicious URI: {}", uri),
                    severity: 7,
                });
            }
        }

        events
    }

    fn inspect_tls(
        &self,
        tls: &crate::protocols::tls::TlsInfo,
        _packet: &ParsedPacket,
    ) -> Vec<DpiEvent> {
        let mut events = Vec::new();

        if let Some(ref handshake) = tls.handshake {
            if let Some(ref client_hello) = handshake.client_hello {
                // Extract SNI for logging
                if let Some(ref sni) = client_hello.sni {
                    events.push(DpiEvent::TlsConnection {
                        sni: sni.clone(),
                        version: format!("{:?}", tls.version),
                    });
                }

                // Check for weak cipher suites
                for cipher in &client_hello.cipher_suites {
                    if Self::is_weak_cipher(*cipher) {
                        events.push(DpiEvent::Suspicious {
                            category: "tls".into(),
                            message: format!("Weak cipher offered: 0x{:04x}", cipher),
                            severity: 5,
                        });
                    }
                }
            }
        }

        events
    }

    fn inspect_dns(
        &self,
        dns: &crate::protocols::dns::DnsInfo,
        _packet: &ParsedPacket,
    ) -> Vec<DpiEvent> {
        let mut events = Vec::new();

        for query in &dns.queries {
            events.push(DpiEvent::DnsQuery {
                domain: query.name.clone(),
                query_type: query.qtype,
            });

            // Check for suspicious domain patterns
            if query.name.len() > 60 || Self::looks_like_dga(&query.name) {
                events.push(DpiEvent::Suspicious {
                    category: "dns".into(),
                    message: format!("Possible DGA domain: {}", query.name),
                    severity: 6,
                });
            }
        }

        events
    }

    fn is_weak_cipher(cipher: u16) -> bool {
        // Export ciphers, NULL ciphers, RC4, etc.
        matches!(cipher,
            0x0000..=0x001F | // NULL and export
            0x0040..=0x006F | // More export
            0x0084..=0x009F | // RC4
            0xC001..=0xC00F   // More weak ciphers
        )
    }

    fn looks_like_dga(domain: &str) -> bool {
        let parts: Vec<&str> = domain.split('.').collect();
        if let Some(name) = parts.first() {
            // High consonant ratio often indicates DGA
            let consonants: usize = name.chars()
                .filter(|c| "bcdfghjklmnpqrstvwxyz".contains(*c))
                .count();
            let ratio = consonants as f32 / name.len() as f32;

            // High entropy / random-looking
            ratio > 0.7 && name.len() > 10
        } else {
            false
        }
    }
}
```

### src/flow/tracker.rs

```rust
use std::net::IpAddr;
use std::time::{Duration, Instant};
use dashmap::DashMap;

use crate::protocols::ParsedPacket;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowState {
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub tcp_state: Option<TcpState>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpState {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    Closed,
}

pub struct FlowTracker {
    flows: DashMap<FlowKey, FlowState>,
    timeout: Duration,
}

impl FlowTracker {
    pub fn new() -> Self {
        Self {
            flows: DashMap::new(),
            timeout: Duration::from_secs(300),
        }
    }

    pub fn update(&self, key: &FlowKey, packet: &ParsedPacket) {
        let now = Instant::now();
        let payload_len = packet.payload.len() as u64;

        self.flows
            .entry(key.clone())
            .and_modify(|state| {
                state.packets_sent += 1;
                state.bytes_sent += payload_len;
                state.last_seen = now;
            })
            .or_insert_with(|| FlowState {
                packets_sent: 1,
                packets_recv: 0,
                bytes_sent: payload_len,
                bytes_recv: 0,
                first_seen: now,
                last_seen: now,
                tcp_state: None,
            });
    }

    pub fn get_flow(&self, key: &FlowKey) -> Option<FlowState> {
        self.flows.get(key).map(|r| r.value().clone())
    }

    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.flows.retain(|_, state| {
            now.duration_since(state.last_seen) < self.timeout
        });
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

impl Default for FlowTracker {
    fn default() -> Self {
        Self::new()
    }
}
```

### src/output/events.rs

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DpiEvent {
    PatternMatch {
        rule_name: String,
        rule_id: u32,
        offset: usize,
        severity: u8,
    },
    Suspicious {
        category: String,
        message: String,
        severity: u8,
    },
    TlsConnection {
        sni: String,
        version: String,
    },
    DnsQuery {
        domain: String,
        query_type: u16,
    },
    FlowCreated {
        src: String,
        dst: String,
        protocol: String,
    },
    FlowClosed {
        src: String,
        dst: String,
        bytes_total: u64,
        duration_ms: u64,
    },
}
```

## Security Checklist

- [ ] Validate all packet headers before parsing
- [ ] Implement packet size limits
- [ ] Handle malformed packets gracefully
- [ ] Protect against resource exhaustion (flow table limits)
- [ ] Use constant-time comparisons for signatures
- [ ] Implement rate limiting for alerts
- [ ] Sanitize logged data
- [ ] Handle IP fragmentation safely
- [ ] Implement TCP reassembly with limits
- [ ] Test with fuzzing (malformed packets)
