# Rust Network Inspection Skills

This skill provides patterns for deep packet inspection (DPI), protocol
dissection, and traffic analysis in Rust for network security appliances.

## Overview

Network inspection encompasses:

- **Packet Capture**: Raw network packet access
- **Protocol Dissection**: Parse network protocols
- **Traffic Analysis**: Flow tracking and statistics
- **Pattern Matching**: Detect malicious traffic
- **Bandwidth Control**: Rate limiting and QoS

## /dpi-setup

Initialize a deep packet inspection engine.

### Usage

```bash
/dpi-setup
```

### What It Does

1. Creates packet capture infrastructure
2. Implements protocol parsers
3. Sets up flow tracking
4. Configures pattern matching
5. Implements traffic statistics

---

## Packet Capture

### Packet Capture Engine

```rust
use pcap::{Capture, Device, Packet};
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct PacketCaptureEngine {
    interface: String,
    filter: Option<String>,
    promiscuous: bool,
    snaplen: i32,
}

impl PacketCaptureEngine {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
            filter: None,
            promiscuous: true,
            snaplen: 65535,
        }
    }

    pub fn with_filter(mut self, filter: &str) -> Self {
        self.filter = Some(filter.to_string());
        self
    }

    pub fn with_snaplen(mut self, snaplen: i32) -> Self {
        self.snaplen = snaplen;
        self
    }

    pub fn start_capture(
        &self,
        tx: mpsc::Sender<CapturedPacket>,
    ) -> Result<std::thread::JoinHandle<()>, Error> {
        let mut cap = Capture::from_device(self.interface.as_str())?
            .promisc(self.promiscuous)
            .snaplen(self.snaplen)
            .timeout(1000)
            .open()?;

        if let Some(filter) = &self.filter {
            cap.filter(filter, true)?;
        }

        let handle = std::thread::spawn(move || {
            while let Ok(packet) = cap.next_packet() {
                let captured = CapturedPacket {
                    timestamp: std::time::Instant::now(),
                    data: packet.data.to_vec(),
                    len: packet.header.len as usize,
                    caplen: packet.header.caplen as usize,
                };

                if tx.blocking_send(captured).is_err() {
                    break;
                }
            }
        });

        Ok(handle)
    }
}

#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub timestamp: std::time::Instant,
    pub data: Vec<u8>,
    pub len: usize,
    pub caplen: usize,
}
```

---

## Protocol Dissection

### Ethernet Frame Parser

```rust
#[derive(Debug, Clone)]
pub struct EthernetFrame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
    pub payload: Vec<u8>,
}

impl EthernetFrame {
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 14 {
            return Err(ParseError::TooShort);
        }

        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&data[0..6]);
        src_mac.copy_from_slice(&data[6..12]);

        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        let payload = data[14..].to_vec();

        Ok(Self {
            dst_mac,
            src_mac,
            ethertype,
            payload,
        })
    }

    pub fn is_ipv4(&self) -> bool {
        self.ethertype == 0x0800
    }

    pub fn is_ipv6(&self) -> bool {
        self.ethertype == 0x86DD
    }

    pub fn is_arp(&self) -> bool {
        self.ethertype == 0x0806
    }
}
```

### IPv4 Packet Parser

```rust
#[derive(Debug, Clone)]
pub struct Ipv4Packet {
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
    pub header_checksum: u16,
    pub src_ip: std::net::Ipv4Addr,
    pub dst_ip: std::net::Ipv4Addr,
    pub options: Vec<u8>,
    pub payload: Vec<u8>,
}

impl Ipv4Packet {
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 20 {
            return Err(ParseError::TooShort);
        }

        let version = (data[0] >> 4) & 0x0F;
        if version != 4 {
            return Err(ParseError::InvalidVersion);
        }

        let ihl = data[0] & 0x0F;
        let header_len = (ihl as usize) * 4;

        if data.len() < header_len {
            return Err(ParseError::TooShort);
        }

        let dscp = (data[1] >> 2) & 0x3F;
        let ecn = data[1] & 0x03;
        let total_length = u16::from_be_bytes([data[2], data[3]]);
        let identification = u16::from_be_bytes([data[4], data[5]]);
        let flags = (data[6] >> 5) & 0x07;
        let fragment_offset = u16::from_be_bytes([data[6] & 0x1F, data[7]]);
        let ttl = data[8];
        let protocol = data[9];
        let header_checksum = u16::from_be_bytes([data[10], data[11]]);

        let src_ip = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst_ip = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        let options = if header_len > 20 {
            data[20..header_len].to_vec()
        } else {
            Vec::new()
        };

        let payload = data[header_len..].to_vec();

        Ok(Self {
            version,
            ihl,
            dscp,
            ecn,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            header_checksum,
            src_ip,
            dst_ip,
            options,
            payload,
        })
    }

    pub fn is_tcp(&self) -> bool {
        self.protocol == 6
    }

    pub fn is_udp(&self) -> bool {
        self.protocol == 17
    }

    pub fn is_icmp(&self) -> bool {
        self.protocol == 1
    }
}
```

### TCP Segment Parser

```rust
#[derive(Debug, Clone)]
pub struct TcpSegment {
    pub src_port: u16,
    pub dst_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Vec<u8>,
    pub payload: Vec<u8>,
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

impl TcpSegment {
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 20 {
            return Err(ParseError::TooShort);
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let sequence = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let acknowledgment = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let data_offset = (data[12] >> 4) & 0x0F;
        let header_len = (data_offset as usize) * 4;

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
        let urgent_pointer = u16::from_be_bytes([data[18], data[19]]);

        let options = if header_len > 20 && data.len() >= header_len {
            data[20..header_len].to_vec()
        } else {
            Vec::new()
        };

        let payload = if data.len() > header_len {
            data[header_len..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            src_port,
            dst_port,
            sequence,
            acknowledgment,
            data_offset,
            flags,
            window,
            checksum,
            urgent_pointer,
            options,
            payload,
        })
    }
}
```

### UDP Datagram Parser

```rust
#[derive(Debug, Clone)]
pub struct UdpDatagram {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

impl UdpDatagram {
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 8 {
            return Err(ParseError::TooShort);
        }

        Ok(Self {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            length: u16::from_be_bytes([data[4], data[5]]),
            checksum: u16::from_be_bytes([data[6], data[7]]),
            payload: data[8..].to_vec(),
        })
    }
}
```

---

## Flow Tracking

```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub src_ip: std::net::IpAddr,
    pub dst_ip: std::net::IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

#[derive(Debug, Clone)]
pub struct FlowState {
    pub key: FlowKey,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub tcp_state: Option<TcpState>,
    pub flags: FlowFlags,
}

#[derive(Debug, Clone, Copy)]
pub enum TcpState {
    New,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

#[derive(Debug, Clone, Default)]
pub struct FlowFlags {
    pub suspicious: bool,
    pub blocked: bool,
    pub rate_limited: bool,
}

pub struct FlowTracker {
    flows: HashMap<FlowKey, FlowState>,
    idle_timeout: Duration,
    max_flows: usize,
}

impl FlowTracker {
    pub fn new(idle_timeout: Duration, max_flows: usize) -> Self {
        Self {
            flows: HashMap::new(),
            idle_timeout,
            max_flows,
        }
    }

    pub fn process_packet(&mut self, parsed: &ParsedPacket, direction: Direction) -> &mut FlowState {
        let key = self.make_flow_key(parsed, direction);

        let now = Instant::now();

        // Clean up old flows if we're at capacity
        if self.flows.len() >= self.max_flows {
            self.cleanup_idle_flows(now);
        }

        let flow = self.flows.entry(key.clone()).or_insert_with(|| FlowState {
            key: key.clone(),
            packets_sent: 0,
            packets_recv: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            first_seen: now,
            last_seen: now,
            tcp_state: if parsed.tcp.is_some() { Some(TcpState::New) } else { None },
            flags: FlowFlags::default(),
        });

        // Update flow statistics
        match direction {
            Direction::Outbound => {
                flow.packets_sent += 1;
                flow.bytes_sent += parsed.total_len as u64;
            }
            Direction::Inbound => {
                flow.packets_recv += 1;
                flow.bytes_recv += parsed.total_len as u64;
            }
        }
        flow.last_seen = now;

        // Update TCP state machine
        if let (Some(tcp), Some(ref mut state)) = (&parsed.tcp, &mut flow.tcp_state) {
            *state = self.update_tcp_state(*state, &tcp.flags, direction);
        }

        flow
    }

    fn make_flow_key(&self, parsed: &ParsedPacket, direction: Direction) -> FlowKey {
        let (src_ip, dst_ip, src_port, dst_port) = match direction {
            Direction::Outbound => (
                parsed.src_ip,
                parsed.dst_ip,
                parsed.src_port.unwrap_or(0),
                parsed.dst_port.unwrap_or(0),
            ),
            Direction::Inbound => (
                parsed.dst_ip,
                parsed.src_ip,
                parsed.dst_port.unwrap_or(0),
                parsed.src_port.unwrap_or(0),
            ),
        };

        FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: parsed.protocol,
        }
    }

    fn update_tcp_state(&self, current: TcpState, flags: &TcpFlags, direction: Direction) -> TcpState {
        match (current, flags.syn, flags.ack, flags.fin, flags.rst) {
            (TcpState::New, true, false, _, _) => TcpState::SynSent,
            (TcpState::SynSent, true, true, _, _) => TcpState::SynReceived,
            (TcpState::SynReceived, false, true, _, _) => TcpState::Established,
            (TcpState::Established, _, _, true, _) => TcpState::FinWait1,
            (_, _, _, _, true) => TcpState::Closed,  // RST
            _ => current,
        }
    }

    fn cleanup_idle_flows(&mut self, now: Instant) {
        self.flows.retain(|_, flow| {
            now.duration_since(flow.last_seen) < self.idle_timeout
        });
    }

    pub fn get_flow(&self, key: &FlowKey) -> Option<&FlowState> {
        self.flows.get(key)
    }

    pub fn mark_suspicious(&mut self, key: &FlowKey) {
        if let Some(flow) = self.flows.get_mut(key) {
            flow.flags.suspicious = true;
        }
    }

    pub fn mark_blocked(&mut self, key: &FlowKey) {
        if let Some(flow) = self.flows.get_mut(key) {
            flow.flags.blocked = true;
        }
    }

    pub fn get_statistics(&self) -> FlowStatistics {
        let mut stats = FlowStatistics::default();

        stats.total_flows = self.flows.len();
        for flow in self.flows.values() {
            stats.total_packets += flow.packets_sent + flow.packets_recv;
            stats.total_bytes += flow.bytes_sent + flow.bytes_recv;

            if flow.flags.suspicious {
                stats.suspicious_flows += 1;
            }
            if flow.flags.blocked {
                stats.blocked_flows += 1;
            }
        }

        stats
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Default)]
pub struct FlowStatistics {
    pub total_flows: usize,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub suspicious_flows: usize,
    pub blocked_flows: usize,
}
```

---

## Pattern Matching

```rust
use aho_corasick::AhoCorasick;

pub struct TrafficPatternMatcher {
    patterns: AhoCorasick,
    pattern_info: Vec<PatternInfo>,
}

#[derive(Debug, Clone)]
pub struct PatternInfo {
    pub name: String,
    pub severity: Severity,
    pub category: PatternCategory,
    pub description: String,
}

#[derive(Debug, Clone, Copy)]
pub enum PatternCategory {
    Malware,
    Exploit,
    Scanner,
    Spam,
    DataExfiltration,
    CommandAndControl,
}

impl TrafficPatternMatcher {
    pub fn new(patterns: Vec<(Vec<u8>, PatternInfo)>) -> Self {
        let (byte_patterns, info): (Vec<_>, Vec<_>) = patterns.into_iter().unzip();

        Self {
            patterns: AhoCorasick::builder()
                .build(&byte_patterns)
                .expect("Invalid patterns"),
            pattern_info: info,
        }
    }

    pub fn with_default_patterns() -> Self {
        let patterns = vec![
            // SQL injection patterns
            (b"UNION SELECT".to_vec(), PatternInfo {
                name: "SQL_INJECTION_UNION".to_string(),
                severity: Severity::High,
                category: PatternCategory::Exploit,
                description: "SQL injection UNION SELECT".to_string(),
            }),

            // Command injection
            (b"; /bin/".to_vec(), PatternInfo {
                name: "CMD_INJECTION_SHELL".to_string(),
                severity: Severity::Critical,
                category: PatternCategory::Exploit,
                description: "Command injection shell execution".to_string(),
            }),

            // Directory traversal
            (b"../../../".to_vec(), PatternInfo {
                name: "PATH_TRAVERSAL".to_string(),
                severity: Severity::High,
                category: PatternCategory::Exploit,
                description: "Directory traversal attempt".to_string(),
            }),

            // Malware beacons
            (b"POST /gate.php".to_vec(), PatternInfo {
                name: "MALWARE_BEACON".to_string(),
                severity: Severity::Critical,
                category: PatternCategory::CommandAndControl,
                description: "Possible malware beacon".to_string(),
            }),
        ];

        Self::new(patterns)
    }

    pub fn scan(&self, data: &[u8]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        for mat in self.patterns.find_iter(data) {
            matches.push(PatternMatch {
                pattern: self.pattern_info[mat.pattern().as_usize()].clone(),
                offset: mat.start(),
                length: mat.end() - mat.start(),
            });
        }

        matches
    }
}

#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub pattern: PatternInfo,
    pub offset: usize,
    pub length: usize,
}
```

---

## Deep Packet Inspector

```rust
pub struct DeepPacketInspector {
    flow_tracker: FlowTracker,
    pattern_matcher: TrafficPatternMatcher,
    rules: Vec<InspectionRule>,
}

pub struct InspectionRule {
    pub name: String,
    pub condition: Box<dyn Fn(&ParsedPacket, &FlowState) -> bool + Send + Sync>,
    pub action: InspectionAction,
}

pub enum InspectionAction {
    Allow,
    Block,
    Log,
    RateLimit(u32),
    Alert(String),
}

impl DeepPacketInspector {
    pub fn new() -> Self {
        Self {
            flow_tracker: FlowTracker::new(Duration::from_secs(300), 100000),
            pattern_matcher: TrafficPatternMatcher::with_default_patterns(),
            rules: Vec::new(),
        }
    }

    pub fn add_rule(&mut self, rule: InspectionRule) {
        self.rules.push(rule);
    }

    pub fn inspect(&mut self, packet: &CapturedPacket, direction: Direction) -> InspectionResult {
        // Parse packet
        let parsed = match self.parse_packet(&packet.data) {
            Ok(p) => p,
            Err(_) => return InspectionResult::allow(),
        };

        // Update flow tracking
        let flow = self.flow_tracker.process_packet(&parsed, direction);
        let flow_clone = flow.clone();

        // Pattern matching on payload
        let pattern_matches = self.pattern_matcher.scan(&parsed.payload);

        // Apply rules
        let mut result = InspectionResult::allow();

        for rule in &self.rules {
            if (rule.condition)(&parsed, &flow_clone) {
                match &rule.action {
                    InspectionAction::Block => {
                        result.blocked = true;
                        result.reason = Some(format!("Rule: {}", rule.name));
                        break;
                    }
                    InspectionAction::Log => {
                        result.log = true;
                    }
                    InspectionAction::Alert(msg) => {
                        result.alerts.push(msg.clone());
                    }
                    InspectionAction::RateLimit(limit) => {
                        result.rate_limit = Some(*limit);
                    }
                    InspectionAction::Allow => {}
                }
            }
        }

        // Check pattern matches
        if !pattern_matches.is_empty() {
            for pm in &pattern_matches {
                if pm.pattern.severity == Severity::Critical {
                    result.blocked = true;
                    result.reason = Some(format!("Pattern: {}", pm.pattern.name));
                }
                result.alerts.push(format!(
                    "Pattern match: {} at offset {}",
                    pm.pattern.name, pm.offset
                ));
            }
        }

        result.pattern_matches = pattern_matches;
        result
    }

    fn parse_packet(&self, data: &[u8]) -> Result<ParsedPacket, ParseError> {
        let eth = EthernetFrame::parse(data)?;

        if !eth.is_ipv4() {
            return Err(ParseError::UnsupportedProtocol);
        }

        let ip = Ipv4Packet::parse(&eth.payload)?;

        let (tcp, udp, src_port, dst_port) = if ip.is_tcp() {
            let tcp = TcpSegment::parse(&ip.payload)?;
            (Some(tcp.clone()), None, Some(tcp.src_port), Some(tcp.dst_port))
        } else if ip.is_udp() {
            let udp = UdpDatagram::parse(&ip.payload)?;
            (None, Some(udp.clone()), Some(udp.src_port), Some(udp.dst_port))
        } else {
            (None, None, None, None)
        };

        let payload = tcp.as_ref().map(|t| t.payload.clone())
            .or_else(|| udp.as_ref().map(|u| u.payload.clone()))
            .unwrap_or_default();

        Ok(ParsedPacket {
            src_ip: ip.src_ip.into(),
            dst_ip: ip.dst_ip.into(),
            src_port,
            dst_port,
            protocol: ip.protocol,
            tcp,
            udp,
            payload,
            total_len: data.len(),
        })
    }
}

#[derive(Debug)]
pub struct ParsedPacket {
    pub src_ip: std::net::IpAddr,
    pub dst_ip: std::net::IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: u8,
    pub tcp: Option<TcpSegment>,
    pub udp: Option<UdpDatagram>,
    pub payload: Vec<u8>,
    pub total_len: usize,
}

#[derive(Debug)]
pub struct InspectionResult {
    pub blocked: bool,
    pub reason: Option<String>,
    pub log: bool,
    pub alerts: Vec<String>,
    pub rate_limit: Option<u32>,
    pub pattern_matches: Vec<PatternMatch>,
}

impl InspectionResult {
    pub fn allow() -> Self {
        Self {
            blocked: false,
            reason: None,
            log: false,
            alerts: Vec::new(),
            rate_limit: None,
            pattern_matches: Vec::new(),
        }
    }
}
```

---

## Security Checklist

- [ ] Packet capture with appropriate permissions
- [ ] Protocol parsers handle malformed packets
- [ ] Flow tracking with memory limits
- [ ] Pattern database regularly updated
- [ ] Inspection results logged securely

## Recommended Crates

- **pcap**: Packet capture
- **aho-corasick**: Fast pattern matching
- **pnet**: Packet parsing utilities

## Integration Points

This skill works well with:

- `/ids-setup` - Intrusion detection rules
- `/threat-feeds-setup` - IP/domain blocklists
