//! Router Packet Filter Example
//!
//! Demonstrates a packet filtering system for DIY router security
//! with deep packet inspection and threat detection capabilities.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

/// Packet direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Unknown(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Protocol::Icmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            n => Protocol::Unknown(n),
        }
    }
}

/// Packet metadata extracted from network traffic
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub timestamp: Instant,
    pub direction: Direction,
    pub source_ip: IpAddr,
    pub dest_ip: IpAddr,
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub protocol: Protocol,
    pub payload_size: usize,
    pub flags: TcpFlags,
    pub interface: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

impl TcpFlags {
    pub fn from_byte(flags: u8) -> Self {
        Self {
            fin: flags & 0x01 != 0,
            syn: flags & 0x02 != 0,
            rst: flags & 0x04 != 0,
            psh: flags & 0x08 != 0,
            ack: flags & 0x10 != 0,
            urg: flags & 0x20 != 0,
        }
    }

    pub fn is_syn_only(&self) -> bool {
        self.syn && !self.ack && !self.fin && !self.rst
    }
}

/// Filter verdict
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    Reject,
    Log,
    RateLimit,
}

/// Filter rule
#[derive(Debug, Clone)]
pub struct FilterRule {
    pub id: u32,
    pub name: String,
    pub enabled: bool,
    pub priority: i32,
    pub direction: Option<Direction>,
    pub source_ips: Option<IpSet>,
    pub dest_ips: Option<IpSet>,
    pub source_ports: Option<PortSet>,
    pub dest_ports: Option<PortSet>,
    pub protocols: Option<HashSet<Protocol>>,
    pub verdict: Verdict,
    pub log: bool,
}

impl FilterRule {
    pub fn new(id: u32, name: &str, verdict: Verdict) -> Self {
        Self {
            id,
            name: name.to_string(),
            enabled: true,
            priority: 0,
            direction: None,
            source_ips: None,
            dest_ips: None,
            source_ports: None,
            dest_ports: None,
            protocols: None,
            verdict,
            log: false,
        }
    }

    pub fn with_direction(mut self, dir: Direction) -> Self {
        self.direction = Some(dir);
        self
    }

    pub fn with_source_ips(mut self, ips: IpSet) -> Self {
        self.source_ips = Some(ips);
        self
    }

    pub fn with_dest_ips(mut self, ips: IpSet) -> Self {
        self.dest_ips = Some(ips);
        self
    }

    pub fn with_dest_ports(mut self, ports: PortSet) -> Self {
        self.dest_ports = Some(ports);
        self
    }

    pub fn with_protocols(mut self, protocols: Vec<Protocol>) -> Self {
        self.protocols = Some(protocols.into_iter().collect());
        self
    }

    pub fn with_log(mut self) -> Self {
        self.log = true;
        self
    }

    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Check if packet matches this rule
    pub fn matches(&self, packet: &PacketInfo) -> bool {
        if !self.enabled {
            return false;
        }

        // Check direction
        if let Some(dir) = self.direction {
            if dir != packet.direction {
                return false;
            }
        }

        // Check source IP
        if let Some(ref ips) = self.source_ips {
            if !ips.contains(&packet.source_ip) {
                return false;
            }
        }

        // Check destination IP
        if let Some(ref ips) = self.dest_ips {
            if !ips.contains(&packet.dest_ip) {
                return false;
            }
        }

        // Check source port
        if let Some(ref ports) = self.source_ports {
            if let Some(port) = packet.source_port {
                if !ports.contains(port) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Check destination port
        if let Some(ref ports) = self.dest_ports {
            if let Some(port) = packet.dest_port {
                if !ports.contains(port) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Check protocol
        if let Some(ref protocols) = self.protocols {
            if !protocols.contains(&packet.protocol) {
                return false;
            }
        }

        true
    }
}

/// IP address set for matching
#[derive(Debug, Clone)]
pub struct IpSet {
    addresses: HashSet<IpAddr>,
    networks: Vec<(IpAddr, u8)>, // (network, prefix_len)
}

impl IpSet {
    pub fn new() -> Self {
        Self {
            addresses: HashSet::new(),
            networks: Vec::new(),
        }
    }

    pub fn add_address(&mut self, ip: IpAddr) {
        self.addresses.insert(ip);
    }

    pub fn add_network(&mut self, network: IpAddr, prefix_len: u8) {
        self.networks.push((network, prefix_len));
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        if self.addresses.contains(ip) {
            return true;
        }

        for (network, prefix_len) in &self.networks {
            if ip_in_network(ip, network, *prefix_len) {
                return true;
            }
        }

        false
    }
}

impl Default for IpSet {
    fn default() -> Self {
        Self::new()
    }
}

fn ip_in_network(ip: &IpAddr, network: &IpAddr, prefix_len: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let ip_bits = u32::from(*ip);
            let net_bits = u32::from(*net);
            let mask = if prefix_len >= 32 {
                u32::MAX
            } else {
                u32::MAX << (32 - prefix_len)
            };
            (ip_bits & mask) == (net_bits & mask)
        }
        _ => false, // Simplified - would handle IPv6 similarly
    }
}

/// Port set for matching
#[derive(Debug, Clone)]
pub struct PortSet {
    ports: HashSet<u16>,
    ranges: Vec<(u16, u16)>,
}

impl PortSet {
    pub fn new() -> Self {
        Self {
            ports: HashSet::new(),
            ranges: Vec::new(),
        }
    }

    pub fn add_port(&mut self, port: u16) {
        self.ports.insert(port);
    }

    pub fn add_range(&mut self, start: u16, end: u16) {
        self.ranges.push((start, end));
    }

    pub fn contains(&self, port: u16) -> bool {
        if self.ports.contains(&port) {
            return true;
        }

        for (start, end) in &self.ranges {
            if port >= *start && port <= *end {
                return true;
            }
        }

        false
    }
}

impl Default for PortSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Threat detection signatures
#[derive(Debug, Clone)]
pub struct ThreatSignature {
    pub id: u32,
    pub name: String,
    pub severity: ThreatSeverity,
    pub pattern: SignaturePattern,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub enum SignaturePattern {
    PortScan {
        threshold: u32,
        window_secs: u64,
    },
    SynFlood {
        threshold: u32,
        window_secs: u64,
    },
    BruteForce {
        port: u16,
        threshold: u32,
        window_secs: u64,
    },
    MaliciousPayload {
        pattern: Vec<u8>,
    },
}

/// Threat detection engine
pub struct ThreatDetector {
    signatures: Vec<ThreatSignature>,
    connection_tracker: HashMap<IpAddr, ConnectionStats>,
    detected_threats: Vec<DetectedThreat>,
}

#[derive(Debug, Clone, Default)]
struct ConnectionStats {
    syn_count: u32,
    port_count: HashSet<u16>,
    last_reset: Instant,
    connection_attempts: HashMap<u16, u32>,
}

#[derive(Debug, Clone)]
pub struct DetectedThreat {
    pub signature_id: u32,
    pub source_ip: IpAddr,
    pub timestamp: Instant,
    pub severity: ThreatSeverity,
    pub details: String,
}

impl Default for ThreatDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatDetector {
    pub fn new() -> Self {
        let mut detector = Self {
            signatures: Vec::new(),
            connection_tracker: HashMap::new(),
            detected_threats: Vec::new(),
        };

        // Add default signatures
        detector.add_signature(ThreatSignature {
            id: 1,
            name: "Port Scan Detection".to_string(),
            severity: ThreatSeverity::Medium,
            pattern: SignaturePattern::PortScan {
                threshold: 10,
                window_secs: 60,
            },
        });

        detector.add_signature(ThreatSignature {
            id: 2,
            name: "SYN Flood Detection".to_string(),
            severity: ThreatSeverity::High,
            pattern: SignaturePattern::SynFlood {
                threshold: 100,
                window_secs: 10,
            },
        });

        detector.add_signature(ThreatSignature {
            id: 3,
            name: "SSH Brute Force".to_string(),
            severity: ThreatSeverity::High,
            pattern: SignaturePattern::BruteForce {
                port: 22,
                threshold: 5,
                window_secs: 60,
            },
        });

        detector
    }

    pub fn add_signature(&mut self, sig: ThreatSignature) {
        self.signatures.push(sig);
    }

    /// Analyze packet for threats
    pub fn analyze(&mut self, packet: &PacketInfo) -> Vec<DetectedThreat> {
        let mut threats = Vec::new();

        // Get or create connection stats
        let stats = self
            .connection_tracker
            .entry(packet.source_ip)
            .or_insert_with(|| ConnectionStats {
                last_reset: Instant::now(),
                ..Default::default()
            });

        // Reset stats if window expired
        let elapsed = stats.last_reset.elapsed();
        if elapsed > Duration::from_secs(60) {
            *stats = ConnectionStats {
                last_reset: Instant::now(),
                ..Default::default()
            };
        }

        // Update stats
        if packet.flags.is_syn_only() {
            stats.syn_count += 1;
        }

        if let Some(port) = packet.dest_port {
            stats.port_count.insert(port);
            *stats.connection_attempts.entry(port).or_insert(0) += 1;
        }

        // Check signatures
        for sig in &self.signatures {
            if let Some(threat) = self.check_signature(sig, packet, stats) {
                threats.push(threat);
            }
        }

        // Store detected threats
        self.detected_threats.extend(threats.clone());

        threats
    }

    fn check_signature(
        &self,
        sig: &ThreatSignature,
        packet: &PacketInfo,
        stats: &ConnectionStats,
    ) -> Option<DetectedThreat> {
        match &sig.pattern {
            SignaturePattern::PortScan { threshold, .. } => {
                if stats.port_count.len() as u32 >= *threshold {
                    return Some(DetectedThreat {
                        signature_id: sig.id,
                        source_ip: packet.source_ip,
                        timestamp: Instant::now(),
                        severity: sig.severity,
                        details: format!(
                            "Port scan detected: {} ports scanned",
                            stats.port_count.len()
                        ),
                    });
                }
            }

            SignaturePattern::SynFlood { threshold, .. } => {
                if stats.syn_count >= *threshold {
                    return Some(DetectedThreat {
                        signature_id: sig.id,
                        source_ip: packet.source_ip,
                        timestamp: Instant::now(),
                        severity: sig.severity,
                        details: format!("SYN flood detected: {} SYN packets", stats.syn_count),
                    });
                }
            }

            SignaturePattern::BruteForce {
                port, threshold, ..
            } => {
                if let Some(&count) = stats.connection_attempts.get(port) {
                    if count >= *threshold {
                        return Some(DetectedThreat {
                            signature_id: sig.id,
                            source_ip: packet.source_ip,
                            timestamp: Instant::now(),
                            severity: sig.severity,
                            details: format!(
                                "Brute force detected on port {}: {} attempts",
                                port, count
                            ),
                        });
                    }
                }
            }

            SignaturePattern::MaliciousPayload { .. } => {
                // Would check payload content
            }
        }

        None
    }

    pub fn get_threats(&self) -> &[DetectedThreat] {
        &self.detected_threats
    }

    pub fn clear_threats(&mut self) {
        self.detected_threats.clear();
    }
}

/// Packet filter engine
pub struct PacketFilter {
    rules: Vec<FilterRule>,
    threat_detector: ThreatDetector,
    stats: FilterStats,
    auto_block: bool,
    blocked_ips: HashSet<IpAddr>,
}

#[derive(Debug, Clone, Default)]
pub struct FilterStats {
    pub packets_processed: u64,
    pub packets_accepted: u64,
    pub packets_dropped: u64,
    pub packets_rejected: u64,
    pub threats_detected: u64,
}

impl Default for PacketFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketFilter {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            threat_detector: ThreatDetector::new(),
            stats: FilterStats::default(),
            auto_block: true,
            blocked_ips: HashSet::new(),
        }
    }

    pub fn add_rule(&mut self, rule: FilterRule) {
        self.rules.push(rule);
        // Sort by priority
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    pub fn set_auto_block(&mut self, enabled: bool) {
        self.auto_block = enabled;
    }

    /// Process a packet through the filter
    pub fn process(&mut self, packet: &PacketInfo) -> Verdict {
        self.stats.packets_processed += 1;

        // Check if IP is auto-blocked
        if self.blocked_ips.contains(&packet.source_ip) {
            self.stats.packets_dropped += 1;
            return Verdict::Drop;
        }

        // Run threat detection
        let threats = self.threat_detector.analyze(packet);
        if !threats.is_empty() {
            self.stats.threats_detected += threats.len() as u64;

            // Auto-block high severity threats
            if self.auto_block {
                for threat in &threats {
                    if threat.severity == ThreatSeverity::High
                        || threat.severity == ThreatSeverity::Critical
                    {
                        self.blocked_ips.insert(threat.source_ip);
                    }
                }
            }
        }

        // Check filter rules
        for rule in &self.rules {
            if rule.matches(packet) {
                if rule.log {
                    println!(
                        "[FILTER] Rule '{}' matched: {:?} -> {:?}",
                        rule.name, packet.source_ip, packet.dest_ip
                    );
                }

                match &rule.verdict {
                    Verdict::Accept => {
                        self.stats.packets_accepted += 1;
                        return Verdict::Accept;
                    }
                    Verdict::Drop => {
                        self.stats.packets_dropped += 1;
                        return Verdict::Drop;
                    }
                    Verdict::Reject => {
                        self.stats.packets_rejected += 1;
                        return Verdict::Reject;
                    }
                    v => return v.clone(),
                }
            }
        }

        // Default: accept
        self.stats.packets_accepted += 1;
        Verdict::Accept
    }

    pub fn get_stats(&self) -> &FilterStats {
        &self.stats
    }

    pub fn get_blocked_ips(&self) -> &HashSet<IpAddr> {
        &self.blocked_ips
    }

    pub fn unblock_ip(&mut self, ip: &IpAddr) {
        self.blocked_ips.remove(ip);
    }
}

fn main() {
    println!("Router Packet Filter Example");
    println!("============================\n");

    // Create packet filter
    let mut filter = PacketFilter::new();

    // Add rules
    // Block known malicious IPs
    let mut blocked_ips = IpSet::new();
    blocked_ips.add_address("192.168.1.100".parse().unwrap());
    blocked_ips.add_network("10.0.0.0".parse().unwrap(), 8);

    filter.add_rule(
        FilterRule::new(1, "Block malicious IPs", Verdict::Drop)
            .with_source_ips(blocked_ips)
            .with_log()
            .with_priority(100),
    );

    // Allow established connections
    filter.add_rule(
        FilterRule::new(2, "Allow LAN", Verdict::Accept)
            .with_direction(Direction::Outbound)
            .with_priority(50),
    );

    // Allow SSH from specific network
    let mut admin_ips = IpSet::new();
    admin_ips.add_network("192.168.1.0".parse().unwrap(), 24);

    let mut ssh_ports = PortSet::new();
    ssh_ports.add_port(22);

    filter.add_rule(
        FilterRule::new(3, "Allow SSH from admin", Verdict::Accept)
            .with_source_ips(admin_ips)
            .with_dest_ports(ssh_ports)
            .with_protocols(vec![Protocol::Tcp])
            .with_priority(30),
    );

    // Test packets
    let packets = vec![
        PacketInfo {
            timestamp: Instant::now(),
            direction: Direction::Inbound,
            source_ip: "192.168.1.50".parse().unwrap(),
            dest_ip: "192.168.1.1".parse().unwrap(),
            source_port: Some(54321),
            dest_port: Some(22),
            protocol: Protocol::Tcp,
            payload_size: 100,
            flags: TcpFlags::from_byte(0x02), // SYN
            interface: "eth0".to_string(),
        },
        PacketInfo {
            timestamp: Instant::now(),
            direction: Direction::Inbound,
            source_ip: "192.168.1.100".parse().unwrap(), // Blocked IP
            dest_ip: "192.168.1.1".parse().unwrap(),
            source_port: Some(12345),
            dest_port: Some(80),
            protocol: Protocol::Tcp,
            payload_size: 200,
            flags: TcpFlags::from_byte(0x02),
            interface: "eth0".to_string(),
        },
        PacketInfo {
            timestamp: Instant::now(),
            direction: Direction::Inbound,
            source_ip: "10.0.0.50".parse().unwrap(), // In blocked network
            dest_ip: "192.168.1.1".parse().unwrap(),
            source_port: Some(11111),
            dest_port: Some(443),
            protocol: Protocol::Tcp,
            payload_size: 150,
            flags: TcpFlags::from_byte(0x02),
            interface: "eth0".to_string(),
        },
    ];

    println!("Processing packets:\n");

    for (i, packet) in packets.iter().enumerate() {
        let verdict = filter.process(packet);
        println!(
            "Packet {}: {:?} -> {:?} port {} = {:?}",
            i + 1,
            packet.source_ip,
            packet.dest_ip,
            packet.dest_port.unwrap_or(0),
            verdict
        );
    }

    // Print stats
    let stats = filter.get_stats();
    println!("\nFilter Statistics:");
    println!("  Processed: {}", stats.packets_processed);
    println!("  Accepted: {}", stats.packets_accepted);
    println!("  Dropped: {}", stats.packets_dropped);
    println!("  Rejected: {}", stats.packets_rejected);
    println!("  Threats detected: {}", stats.threats_detected);

    // Show blocked IPs
    println!("\nBlocked IPs: {:?}", filter.get_blocked_ips());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_set() {
        let mut set = IpSet::new();
        set.add_address("192.168.1.1".parse().unwrap());
        set.add_network("10.0.0.0".parse().unwrap(), 8);

        assert!(set.contains(&"192.168.1.1".parse().unwrap()));
        assert!(set.contains(&"10.0.0.1".parse().unwrap()));
        assert!(set.contains(&"10.255.255.255".parse().unwrap()));
        assert!(!set.contains(&"192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn test_port_set() {
        let mut set = PortSet::new();
        set.add_port(22);
        set.add_range(80, 90);

        assert!(set.contains(22));
        assert!(set.contains(80));
        assert!(set.contains(85));
        assert!(set.contains(90));
        assert!(!set.contains(91));
        assert!(!set.contains(23));
    }

    #[test]
    fn test_tcp_flags() {
        let flags = TcpFlags::from_byte(0x02);
        assert!(flags.syn);
        assert!(!flags.ack);
        assert!(flags.is_syn_only());

        let ack_flags = TcpFlags::from_byte(0x12);
        assert!(ack_flags.syn);
        assert!(ack_flags.ack);
        assert!(!ack_flags.is_syn_only());
    }

    #[test]
    fn test_filter_rule_matches() {
        let mut ips = IpSet::new();
        ips.add_address("192.168.1.1".parse().unwrap());

        let rule = FilterRule::new(1, "Test", Verdict::Drop)
            .with_source_ips(ips)
            .with_protocols(vec![Protocol::Tcp]);

        let packet = PacketInfo {
            timestamp: Instant::now(),
            direction: Direction::Inbound,
            source_ip: "192.168.1.1".parse().unwrap(),
            dest_ip: "10.0.0.1".parse().unwrap(),
            source_port: Some(1234),
            dest_port: Some(80),
            protocol: Protocol::Tcp,
            payload_size: 100,
            flags: TcpFlags::default(),
            interface: "eth0".to_string(),
        };

        assert!(rule.matches(&packet));
    }

    #[test]
    fn test_filter_rule_no_match() {
        let mut ips = IpSet::new();
        ips.add_address("192.168.1.1".parse().unwrap());

        let rule = FilterRule::new(1, "Test", Verdict::Drop).with_source_ips(ips);

        let packet = PacketInfo {
            timestamp: Instant::now(),
            direction: Direction::Inbound,
            source_ip: "192.168.1.2".parse().unwrap(),
            dest_ip: "10.0.0.1".parse().unwrap(),
            source_port: Some(1234),
            dest_port: Some(80),
            protocol: Protocol::Tcp,
            payload_size: 100,
            flags: TcpFlags::default(),
            interface: "eth0".to_string(),
        };

        assert!(!rule.matches(&packet));
    }

    #[test]
    fn test_packet_filter() {
        let mut filter = PacketFilter::new();

        let mut blocked = IpSet::new();
        blocked.add_address("1.2.3.4".parse().unwrap());

        filter.add_rule(FilterRule::new(1, "Block", Verdict::Drop).with_source_ips(blocked));

        let blocked_packet = PacketInfo {
            timestamp: Instant::now(),
            direction: Direction::Inbound,
            source_ip: "1.2.3.4".parse().unwrap(),
            dest_ip: "10.0.0.1".parse().unwrap(),
            source_port: Some(1234),
            dest_port: Some(80),
            protocol: Protocol::Tcp,
            payload_size: 100,
            flags: TcpFlags::default(),
            interface: "eth0".to_string(),
        };

        assert_eq!(filter.process(&blocked_packet), Verdict::Drop);
    }

    #[test]
    fn test_threat_detector() {
        let mut detector = ThreatDetector::new();

        // Simulate port scan
        for port in 1..=15 {
            let packet = PacketInfo {
                timestamp: Instant::now(),
                direction: Direction::Inbound,
                source_ip: "192.168.1.100".parse().unwrap(),
                dest_ip: "192.168.1.1".parse().unwrap(),
                source_port: Some(12345),
                dest_port: Some(port),
                protocol: Protocol::Tcp,
                payload_size: 0,
                flags: TcpFlags::from_byte(0x02),
                interface: "eth0".to_string(),
            };

            let threats = detector.analyze(&packet);
            if port >= 10 {
                assert!(
                    !threats.is_empty(),
                    "Should detect port scan at port {}",
                    port
                );
            }
        }
    }
}
