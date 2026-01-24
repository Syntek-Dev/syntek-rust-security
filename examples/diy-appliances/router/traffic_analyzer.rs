//! Traffic Analyzer
//!
//! Network traffic analysis for security monitoring and anomaly detection.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Protocol type
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    DNS,
    HTTP,
    HTTPS,
    SSH,
    FTP,
    SMTP,
    Unknown(u8),
}

impl Protocol {
    pub fn from_port(port: u16, is_tcp: bool) -> Self {
        match (port, is_tcp) {
            (53, _) => Self::DNS,
            (80, true) => Self::HTTP,
            (443, true) => Self::HTTPS,
            (22, true) => Self::SSH,
            (21, true) => Self::FTP,
            (25, true) => Self::SMTP,
            (_, true) => Self::TCP,
            (_, false) => Self::UDP,
        }
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::HTTPS | Self::SSH)
    }

    pub fn default_port(&self) -> Option<u16> {
        match self {
            Self::DNS => Some(53),
            Self::HTTP => Some(80),
            Self::HTTPS => Some(443),
            Self::SSH => Some(22),
            Self::FTP => Some(21),
            Self::SMTP => Some(25),
            _ => None,
        }
    }
}

/// Network flow identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}

impl FlowKey {
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }

    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol.clone(),
        }
    }
}

/// Network flow statistics
#[derive(Debug, Clone)]
pub struct FlowStats {
    pub key: FlowKey,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub flags: FlowFlags,
}

impl FlowStats {
    pub fn new(key: FlowKey) -> Self {
        let now = Instant::now();
        Self {
            key,
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            first_seen: now,
            last_seen: now,
            flags: FlowFlags::default(),
        }
    }

    pub fn add_packet(&mut self, bytes: u64, outbound: bool) {
        if outbound {
            self.packets_sent += 1;
            self.bytes_sent += bytes;
        } else {
            self.packets_received += 1;
            self.bytes_received += bytes;
        }
        self.last_seen = Instant::now();
    }

    pub fn total_packets(&self) -> u64 {
        self.packets_sent + self.packets_received
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_received
    }

    pub fn duration(&self) -> Duration {
        self.last_seen.duration_since(self.first_seen)
    }

    pub fn bytes_per_second(&self) -> f64 {
        let duration = self.duration().as_secs_f64();
        if duration > 0.0 {
            self.total_bytes() as f64 / duration
        } else {
            0.0
        }
    }

    pub fn is_idle(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() > timeout
    }
}

/// Flow flags
#[derive(Debug, Clone, Default)]
pub struct FlowFlags {
    pub syn_seen: bool,
    pub syn_ack_seen: bool,
    pub fin_seen: bool,
    pub rst_seen: bool,
    pub is_established: bool,
    pub is_suspicious: bool,
}

/// Traffic anomaly type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyType {
    PortScan,
    SynFlood,
    DnsAmplification,
    DataExfiltration,
    UnusualPort,
    HighBandwidth,
    RapidConnections,
    BeaconingBehavior,
    C2Communication,
    LateralMovement,
}

impl AnomalyType {
    pub fn severity(&self) -> Severity {
        match self {
            Self::PortScan => Severity::Medium,
            Self::SynFlood => Severity::High,
            Self::DnsAmplification => Severity::High,
            Self::DataExfiltration => Severity::Critical,
            Self::UnusualPort => Severity::Low,
            Self::HighBandwidth => Severity::Medium,
            Self::RapidConnections => Severity::Medium,
            Self::BeaconingBehavior => Severity::High,
            Self::C2Communication => Severity::Critical,
            Self::LateralMovement => Severity::High,
        }
    }

    pub fn description(&self) -> &str {
        match self {
            Self::PortScan => "Multiple connection attempts to different ports",
            Self::SynFlood => "High rate of SYN packets without completion",
            Self::DnsAmplification => "Unusual DNS query patterns indicating amplification",
            Self::DataExfiltration => "Large outbound data transfer to unusual destination",
            Self::UnusualPort => "Traffic on uncommonly used port",
            Self::HighBandwidth => "Abnormally high bandwidth consumption",
            Self::RapidConnections => "Rapid connection establishment pattern",
            Self::BeaconingBehavior => "Regular periodic connections (possible C2)",
            Self::C2Communication => "Pattern consistent with command and control",
            Self::LateralMovement => "Internal network scanning or propagation",
        }
    }
}

/// Severity level
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Detected anomaly
#[derive(Debug, Clone)]
pub struct Anomaly {
    pub anomaly_type: AnomalyType,
    pub severity: Severity,
    pub source_ip: IpAddr,
    pub target_ip: Option<IpAddr>,
    pub detected_at: Instant,
    pub evidence: String,
    pub recommended_action: String,
}

impl Anomaly {
    pub fn new(anomaly_type: AnomalyType, source_ip: IpAddr, evidence: impl Into<String>) -> Self {
        let recommended_action = match &anomaly_type {
            AnomalyType::PortScan => "Monitor and consider blocking source",
            AnomalyType::SynFlood => "Enable SYN cookies, rate limit source",
            AnomalyType::DnsAmplification => "Block source, verify DNS configuration",
            AnomalyType::DataExfiltration => "Investigate immediately, consider blocking",
            AnomalyType::UnusualPort => "Investigate traffic purpose",
            AnomalyType::HighBandwidth => "Identify application, apply QoS",
            AnomalyType::RapidConnections => "Rate limit source",
            AnomalyType::BeaconingBehavior => "Investigate host for malware",
            AnomalyType::C2Communication => "Isolate host immediately",
            AnomalyType::LateralMovement => "Segment network, investigate source",
        };

        Self {
            severity: anomaly_type.severity(),
            anomaly_type,
            source_ip,
            target_ip: None,
            detected_at: Instant::now(),
            evidence: evidence.into(),
            recommended_action: recommended_action.to_string(),
        }
    }

    pub fn with_target(mut self, target: IpAddr) -> Self {
        self.target_ip = Some(target);
        self
    }
}

/// Host statistics
#[derive(Debug, Clone)]
pub struct HostStats {
    pub ip: IpAddr,
    pub connections: u64,
    pub unique_ports: HashSet<u16>,
    pub unique_destinations: HashSet<IpAddr>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub connection_times: VecDeque<Instant>,
    pub last_seen: Instant,
}

use std::collections::HashSet;

impl HostStats {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            connections: 0,
            unique_ports: HashSet::new(),
            unique_destinations: HashSet::new(),
            bytes_in: 0,
            bytes_out: 0,
            connection_times: VecDeque::with_capacity(100),
            last_seen: Instant::now(),
        }
    }

    pub fn add_connection(&mut self, port: u16, dest: IpAddr) {
        self.connections += 1;
        self.unique_ports.insert(port);
        self.unique_destinations.insert(dest);
        self.connection_times.push_back(Instant::now());
        self.last_seen = Instant::now();

        // Keep only recent connections
        while self.connection_times.len() > 100 {
            self.connection_times.pop_front();
        }
    }

    pub fn connections_per_second(&self, window: Duration) -> f64 {
        let cutoff = Instant::now() - window;
        let recent = self
            .connection_times
            .iter()
            .filter(|&&t| t > cutoff)
            .count();
        recent as f64 / window.as_secs_f64()
    }
}

/// Traffic analyzer configuration
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    pub flow_timeout: Duration,
    pub port_scan_threshold: usize,
    pub syn_flood_rate: f64,
    pub high_bandwidth_threshold: u64,
    pub rapid_connection_rate: f64,
    pub beacon_detection_window: Duration,
    pub exfiltration_threshold: u64,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            flow_timeout: Duration::from_secs(300),
            port_scan_threshold: 10,
            syn_flood_rate: 100.0,
            high_bandwidth_threshold: 100 * 1024 * 1024, // 100 MB
            rapid_connection_rate: 50.0,
            beacon_detection_window: Duration::from_secs(3600),
            exfiltration_threshold: 50 * 1024 * 1024, // 50 MB
        }
    }
}

/// Traffic analyzer
pub struct TrafficAnalyzer {
    config: AnalyzerConfig,
    flows: HashMap<FlowKey, FlowStats>,
    hosts: HashMap<IpAddr, HostStats>,
    anomalies: Vec<Anomaly>,
    packets_analyzed: u64,
    bytes_analyzed: u64,
    start_time: Instant,
}

impl TrafficAnalyzer {
    pub fn new(config: AnalyzerConfig) -> Self {
        Self {
            config,
            flows: HashMap::new(),
            hosts: HashMap::new(),
            anomalies: Vec::new(),
            packets_analyzed: 0,
            bytes_analyzed: 0,
            start_time: Instant::now(),
        }
    }

    /// Process a packet
    pub fn process_packet(&mut self, packet: &PacketInfo) {
        self.packets_analyzed += 1;
        self.bytes_analyzed += packet.size as u64;

        // Update flow stats
        let flow_key = FlowKey::new(
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            packet.protocol.clone(),
        );

        let flow = self
            .flows
            .entry(flow_key.clone())
            .or_insert_with(|| FlowStats::new(flow_key));
        flow.add_packet(packet.size as u64, true);

        // Update TCP flags
        if let Some(tcp_flags) = &packet.tcp_flags {
            if tcp_flags.syn && !tcp_flags.ack {
                flow.flags.syn_seen = true;
            }
            if tcp_flags.syn && tcp_flags.ack {
                flow.flags.syn_ack_seen = true;
            }
            if tcp_flags.fin {
                flow.flags.fin_seen = true;
            }
            if tcp_flags.rst {
                flow.flags.rst_seen = true;
            }
            if flow.flags.syn_seen && flow.flags.syn_ack_seen {
                flow.flags.is_established = true;
            }
        }

        // Update host stats
        let host = self
            .hosts
            .entry(packet.src_ip)
            .or_insert_with(|| HostStats::new(packet.src_ip));
        host.add_connection(packet.dst_port, packet.dst_ip);
        host.bytes_out += packet.size as u64;

        // Run anomaly detection
        self.detect_anomalies(packet);
    }

    /// Detect anomalies
    fn detect_anomalies(&mut self, packet: &PacketInfo) {
        // Port scan detection
        if let Some(host) = self.hosts.get(&packet.src_ip) {
            if host.unique_ports.len() > self.config.port_scan_threshold {
                let anomaly = Anomaly::new(
                    AnomalyType::PortScan,
                    packet.src_ip,
                    format!(
                        "Host contacted {} unique ports in short timeframe",
                        host.unique_ports.len()
                    ),
                );
                self.add_anomaly(anomaly);
            }

            // Rapid connection detection
            let conn_rate = host.connections_per_second(Duration::from_secs(10));
            if conn_rate > self.config.rapid_connection_rate {
                let anomaly = Anomaly::new(
                    AnomalyType::RapidConnections,
                    packet.src_ip,
                    format!("{:.1} connections/sec", conn_rate),
                );
                self.add_anomaly(anomaly);
            }

            // Data exfiltration detection
            if host.bytes_out > self.config.exfiltration_threshold {
                let anomaly = Anomaly::new(
                    AnomalyType::DataExfiltration,
                    packet.src_ip,
                    format!(
                        "Large outbound transfer: {} MB",
                        host.bytes_out / (1024 * 1024)
                    ),
                );
                self.add_anomaly(anomaly);
            }
        }

        // Unusual port detection
        if packet.dst_port > 49151 || packet.dst_port == 0 {
            let anomaly = Anomaly::new(
                AnomalyType::UnusualPort,
                packet.src_ip,
                format!("Traffic on port {}", packet.dst_port),
            )
            .with_target(packet.dst_ip);
            self.add_anomaly(anomaly);
        }

        // SYN flood detection
        if let Some(tcp_flags) = &packet.tcp_flags {
            if tcp_flags.syn && !tcp_flags.ack {
                // Check SYN rate from this source
                if let Some(host) = self.hosts.get(&packet.src_ip) {
                    let syn_rate = host.connections_per_second(Duration::from_secs(1));
                    if syn_rate > self.config.syn_flood_rate {
                        let anomaly = Anomaly::new(
                            AnomalyType::SynFlood,
                            packet.src_ip,
                            format!("{:.1} SYN/sec", syn_rate),
                        )
                        .with_target(packet.dst_ip);
                        self.add_anomaly(anomaly);
                    }
                }
            }
        }

        // DNS amplification detection
        if packet.protocol == Protocol::DNS && packet.size > 512 {
            let anomaly = Anomaly::new(
                AnomalyType::DnsAmplification,
                packet.src_ip,
                format!("Large DNS response: {} bytes", packet.size),
            );
            self.add_anomaly(anomaly);
        }
    }

    fn add_anomaly(&mut self, anomaly: Anomaly) {
        // Deduplicate - don't add if same type from same source recently
        let dominated = self.anomalies.iter().any(|a| {
            a.anomaly_type == anomaly.anomaly_type
                && a.source_ip == anomaly.source_ip
                && a.detected_at.elapsed() < Duration::from_secs(60)
        });

        if !dominated {
            self.anomalies.push(anomaly);
        }
    }

    /// Clean up idle flows
    pub fn cleanup_idle_flows(&mut self) {
        self.flows
            .retain(|_, flow| !flow.is_idle(self.config.flow_timeout));
    }

    /// Get active flows
    pub fn active_flows(&self) -> Vec<&FlowStats> {
        self.flows.values().collect()
    }

    /// Get top talkers by bytes
    pub fn top_talkers(&self, limit: usize) -> Vec<(&IpAddr, u64)> {
        let mut talkers: Vec<_> = self
            .hosts
            .iter()
            .map(|(ip, stats)| (ip, stats.bytes_out + stats.bytes_in))
            .collect();

        talkers.sort_by(|a, b| b.1.cmp(&a.1));
        talkers.truncate(limit);
        talkers
    }

    /// Get recent anomalies
    pub fn recent_anomalies(&self, window: Duration) -> Vec<&Anomaly> {
        self.anomalies
            .iter()
            .filter(|a| a.detected_at.elapsed() < window)
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> AnalyzerStats {
        AnalyzerStats {
            packets_analyzed: self.packets_analyzed,
            bytes_analyzed: self.bytes_analyzed,
            active_flows: self.flows.len(),
            unique_hosts: self.hosts.len(),
            anomalies_detected: self.anomalies.len(),
            runtime: self.start_time.elapsed(),
        }
    }

    /// Generate report
    pub fn generate_report(&self) -> String {
        let stats = self.stats();
        let mut report = String::new();

        report.push_str("=== Traffic Analysis Report ===\n\n");

        report.push_str("Statistics:\n");
        report.push_str(&format!("  Packets analyzed: {}\n", stats.packets_analyzed));
        report.push_str(&format!(
            "  Bytes analyzed: {} MB\n",
            stats.bytes_analyzed / (1024 * 1024)
        ));
        report.push_str(&format!("  Active flows: {}\n", stats.active_flows));
        report.push_str(&format!("  Unique hosts: {}\n", stats.unique_hosts));
        report.push_str(&format!("  Runtime: {:?}\n\n", stats.runtime));

        report.push_str("Top Talkers:\n");
        for (ip, bytes) in self.top_talkers(5) {
            report.push_str(&format!("  {}: {} KB\n", ip, bytes / 1024));
        }

        report.push_str("\nRecent Anomalies:\n");
        for anomaly in self.recent_anomalies(Duration::from_secs(3600)) {
            report.push_str(&format!(
                "  [{:?}] {}: {} - {}\n",
                anomaly.severity,
                anomaly.source_ip,
                anomaly.anomaly_type.description(),
                anomaly.evidence
            ));
        }

        report
    }
}

impl Default for TrafficAnalyzer {
    fn default() -> Self {
        Self::new(AnalyzerConfig::default())
    }
}

/// Analyzer statistics
#[derive(Debug)]
pub struct AnalyzerStats {
    pub packets_analyzed: u64,
    pub bytes_analyzed: u64,
    pub active_flows: usize,
    pub unique_hosts: usize,
    pub anomalies_detected: usize,
    pub runtime: Duration,
}

/// Packet information
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub size: usize,
    pub tcp_flags: Option<TcpFlags>,
}

/// TCP flags
#[derive(Debug, Clone, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

fn main() {
    println!("=== Traffic Analyzer Demo ===\n");

    // Create analyzer
    let config = AnalyzerConfig {
        port_scan_threshold: 5,
        rapid_connection_rate: 10.0,
        ..Default::default()
    };
    let mut analyzer = TrafficAnalyzer::new(config);

    // Simulate some traffic
    let src_ip: IpAddr = "192.168.1.100".parse().unwrap();
    let dst_ip: IpAddr = "10.0.0.1".parse().unwrap();
    let ext_ip: IpAddr = "8.8.8.8".parse().unwrap();

    // Normal web traffic
    for i in 0..10 {
        let packet = PacketInfo {
            src_ip,
            dst_ip: ext_ip,
            src_port: 50000 + i,
            dst_port: 443,
            protocol: Protocol::HTTPS,
            size: 1500,
            tcp_flags: Some(TcpFlags {
                syn: i == 0,
                ack: i > 0,
                ..Default::default()
            }),
        };
        analyzer.process_packet(&packet);
    }

    // Simulate port scan
    println!("Simulating port scan...");
    for port in 1..20 {
        let packet = PacketInfo {
            src_ip: "10.0.0.50".parse().unwrap(),
            dst_ip,
            src_port: 45000,
            dst_port: port,
            protocol: Protocol::TCP,
            size: 60,
            tcp_flags: Some(TcpFlags {
                syn: true,
                ..Default::default()
            }),
        };
        analyzer.process_packet(&packet);
    }

    // DNS traffic
    let packet = PacketInfo {
        src_ip,
        dst_ip: ext_ip,
        src_port: 53,
        dst_port: 53,
        protocol: Protocol::DNS,
        size: 64,
        tcp_flags: None,
    };
    analyzer.process_packet(&packet);

    // Large DNS response (potential amplification)
    let packet = PacketInfo {
        src_ip: ext_ip,
        dst_ip: src_ip,
        src_port: 53,
        dst_port: 12345,
        protocol: Protocol::DNS,
        size: 4096,
        tcp_flags: None,
    };
    analyzer.process_packet(&packet);

    // Print report
    println!("{}", analyzer.generate_report());

    // Check specific anomalies
    println!("\n--- Anomaly Details ---");
    for anomaly in &analyzer.anomalies {
        println!("\nType: {:?}", anomaly.anomaly_type);
        println!("Severity: {:?}", anomaly.severity);
        println!("Source: {}", anomaly.source_ip);
        if let Some(target) = anomaly.target_ip {
            println!("Target: {}", target);
        }
        println!("Evidence: {}", anomaly.evidence);
        println!("Recommended: {}", anomaly.recommended_action);
    }

    // Show active flows
    println!("\n--- Active Flows ---");
    for flow in analyzer.active_flows().iter().take(5) {
        println!(
            "  {}:{} -> {}:{} ({:?}): {} pkts, {} bytes",
            flow.key.src_ip,
            flow.key.src_port,
            flow.key.dst_ip,
            flow.key.dst_port,
            flow.key.protocol,
            flow.total_packets(),
            flow.total_bytes()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_packet(src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> PacketInfo {
        PacketInfo {
            src_ip: src_ip.parse().unwrap(),
            dst_ip: dst_ip.parse().unwrap(),
            src_port,
            dst_port,
            protocol: Protocol::TCP,
            size: 100,
            tcp_flags: Some(TcpFlags::default()),
        }
    }

    #[test]
    fn test_protocol_from_port() {
        assert_eq!(Protocol::from_port(80, true), Protocol::HTTP);
        assert_eq!(Protocol::from_port(443, true), Protocol::HTTPS);
        assert_eq!(Protocol::from_port(22, true), Protocol::SSH);
        assert_eq!(Protocol::from_port(53, false), Protocol::DNS);
    }

    #[test]
    fn test_protocol_encrypted() {
        assert!(Protocol::HTTPS.is_encrypted());
        assert!(Protocol::SSH.is_encrypted());
        assert!(!Protocol::HTTP.is_encrypted());
    }

    #[test]
    fn test_flow_key() {
        let key = FlowKey::new(
            "192.168.1.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            12345,
            80,
            Protocol::TCP,
        );

        let reversed = key.reverse();
        assert_eq!(reversed.src_ip, key.dst_ip);
        assert_eq!(reversed.dst_ip, key.src_ip);
    }

    #[test]
    fn test_flow_stats() {
        let key = FlowKey::new(
            "192.168.1.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            12345,
            80,
            Protocol::TCP,
        );

        let mut stats = FlowStats::new(key);
        stats.add_packet(100, true);
        stats.add_packet(200, true);
        stats.add_packet(150, false);

        assert_eq!(stats.packets_sent, 2);
        assert_eq!(stats.packets_received, 1);
        assert_eq!(stats.bytes_sent, 300);
        assert_eq!(stats.bytes_received, 150);
        assert_eq!(stats.total_packets(), 3);
        assert_eq!(stats.total_bytes(), 450);
    }

    #[test]
    fn test_host_stats() {
        let mut stats = HostStats::new("192.168.1.1".parse().unwrap());

        stats.add_connection(80, "10.0.0.1".parse().unwrap());
        stats.add_connection(443, "10.0.0.2".parse().unwrap());
        stats.add_connection(80, "10.0.0.3".parse().unwrap());

        assert_eq!(stats.connections, 3);
        assert_eq!(stats.unique_ports.len(), 2);
        assert_eq!(stats.unique_destinations.len(), 3);
    }

    #[test]
    fn test_anomaly_creation() {
        let anomaly = Anomaly::new(
            AnomalyType::PortScan,
            "192.168.1.1".parse().unwrap(),
            "Test evidence",
        );

        assert_eq!(anomaly.severity, Severity::Medium);
        assert!(!anomaly.recommended_action.is_empty());
    }

    #[test]
    fn test_traffic_analyzer() {
        let mut analyzer = TrafficAnalyzer::default();

        let packet = make_packet("192.168.1.1", "10.0.0.1", 12345, 80);
        analyzer.process_packet(&packet);

        let stats = analyzer.stats();
        assert_eq!(stats.packets_analyzed, 1);
        assert_eq!(stats.active_flows, 1);
    }

    #[test]
    fn test_port_scan_detection() {
        let config = AnalyzerConfig {
            port_scan_threshold: 5,
            ..Default::default()
        };
        let mut analyzer = TrafficAnalyzer::new(config);

        // Simulate port scan
        for port in 1..10 {
            let packet = make_packet("192.168.1.1", "10.0.0.1", 12345, port);
            analyzer.process_packet(&packet);
        }

        // Should detect port scan
        let anomalies: Vec<_> = analyzer
            .anomalies
            .iter()
            .filter(|a| a.anomaly_type == AnomalyType::PortScan)
            .collect();

        assert!(!anomalies.is_empty());
    }

    #[test]
    fn test_unusual_port_detection() {
        let mut analyzer = TrafficAnalyzer::default();

        // Traffic on unusual port
        let packet = make_packet("192.168.1.1", "10.0.0.1", 12345, 55555);
        analyzer.process_packet(&packet);

        let has_unusual = analyzer
            .anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::UnusualPort);

        assert!(has_unusual);
    }

    #[test]
    fn test_top_talkers() {
        let mut analyzer = TrafficAnalyzer::default();

        // Add traffic from multiple hosts
        for i in 1..5 {
            for _ in 0..(i * 10) {
                let packet = make_packet(&format!("192.168.1.{}", i), "10.0.0.1", 12345, 80);
                analyzer.process_packet(&packet);
            }
        }

        let talkers = analyzer.top_talkers(3);
        assert_eq!(talkers.len(), 3);
        // Host 4 should be the top talker
    }

    #[test]
    fn test_flow_idle_detection() {
        let key = FlowKey::new(
            "192.168.1.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            12345,
            80,
            Protocol::TCP,
        );

        let stats = FlowStats::new(key);

        // Just created, should not be idle
        assert!(!stats.is_idle(Duration::from_secs(1)));
    }

    #[test]
    fn test_anomaly_severity() {
        assert!(AnomalyType::DataExfiltration.severity() > AnomalyType::UnusualPort.severity());
        assert!(AnomalyType::C2Communication.severity() == Severity::Critical);
    }

    #[test]
    fn test_dns_amplification_detection() {
        let mut analyzer = TrafficAnalyzer::default();

        let packet = PacketInfo {
            src_ip: "8.8.8.8".parse().unwrap(),
            dst_ip: "192.168.1.1".parse().unwrap(),
            src_port: 53,
            dst_port: 12345,
            protocol: Protocol::DNS,
            size: 4096, // Large DNS response
            tcp_flags: None,
        };

        analyzer.process_packet(&packet);

        let has_dns_amp = analyzer
            .anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::DnsAmplification);

        assert!(has_dns_amp);
    }
}
