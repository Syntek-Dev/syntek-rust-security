//! Deep Packet Inspection Engine
//!
//! Implements protocol dissection, pattern matching in network traffic,
//! and traffic analysis for security monitoring.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant, SystemTime};

/// Network packet representation
#[derive(Debug, Clone)]
pub struct Packet {
    /// Timestamp
    pub timestamp: SystemTime,
    /// Source IP
    pub src_ip: IpAddr,
    /// Destination IP
    pub dst_ip: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Protocol
    pub protocol: Protocol,
    /// Payload
    pub payload: Vec<u8>,
    /// Packet flags
    pub flags: PacketFlags,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Http,
    Https,
    Dns,
    Ssh,
    Ftp,
    Smtp,
    Unknown(u8),
}

#[derive(Debug, Clone, Default)]
pub struct PacketFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

/// DPI engine configuration
#[derive(Debug, Clone)]
pub struct DpiConfig {
    /// Enable protocol detection
    pub protocol_detection: bool,
    /// Enable content inspection
    pub content_inspection: bool,
    /// Maximum payload size to inspect
    pub max_payload_size: usize,
    /// Enable SSL/TLS inspection (requires CA)
    pub ssl_inspection: bool,
    /// Connection tracking timeout
    pub connection_timeout: Duration,
    /// Enable traffic statistics
    pub enable_stats: bool,
}

impl Default for DpiConfig {
    fn default() -> Self {
        Self {
            protocol_detection: true,
            content_inspection: true,
            max_payload_size: 65535,
            ssl_inspection: false,
            connection_timeout: Duration::from_secs(300),
            enable_stats: true,
        }
    }
}

/// Connection tracking entry
#[derive(Debug, Clone)]
pub struct Connection {
    /// Source IP
    pub src_ip: IpAddr,
    /// Destination IP
    pub dst_ip: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Protocol
    pub protocol: Protocol,
    /// Connection state
    pub state: ConnectionState,
    /// Bytes sent (client -> server)
    pub bytes_sent: u64,
    /// Bytes received (server -> client)
    pub bytes_received: u64,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Start time
    pub start_time: SystemTime,
    /// Last activity
    pub last_activity: SystemTime,
    /// Detected application
    pub application: Option<String>,
    /// Alerts for this connection
    pub alerts: Vec<DpiAlert>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    New,
    Established,
    Closing,
    Closed,
    TimedOut,
}

/// DPI alert
#[derive(Debug, Clone)]
pub struct DpiAlert {
    /// Alert timestamp
    pub timestamp: SystemTime,
    /// Alert type
    pub alert_type: AlertType,
    /// Severity
    pub severity: AlertSeverity,
    /// Description
    pub description: String,
    /// Matched pattern/rule
    pub rule_id: Option<String>,
    /// Payload excerpt
    pub payload_excerpt: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AlertType {
    MalwareSignature,
    SuspiciousTraffic,
    ProtocolAnomaly,
    DataExfiltration,
    CommandAndControl,
    PortScan,
    BruteForce,
    DnsAnomaly,
    PolicyViolation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Pattern for content matching
#[derive(Debug, Clone)]
pub struct ContentPattern {
    /// Pattern name
    pub name: String,
    /// Pattern bytes
    pub pattern: Vec<u8>,
    /// Pattern type
    pub pattern_type: PatternType,
    /// Alert type on match
    pub alert_type: AlertType,
    /// Severity
    pub severity: AlertSeverity,
    /// Protocols this pattern applies to
    pub protocols: Option<Vec<Protocol>>,
}

#[derive(Debug, Clone)]
pub enum PatternType {
    /// Exact byte sequence
    Exact,
    /// Regular expression
    Regex,
    /// Hex pattern with wildcards
    HexWildcard,
}

/// Deep Packet Inspection engine
pub struct DpiEngine {
    config: DpiConfig,
    /// Active connections
    connections: HashMap<ConnectionKey, Connection>,
    /// Content patterns
    patterns: Vec<ContentPattern>,
    /// Protocol signatures
    protocol_signatures: Vec<ProtocolSignature>,
    /// Statistics
    stats: DpiStats,
    /// Alerts
    alerts: Vec<DpiAlert>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConnectionKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
}

#[derive(Debug, Clone)]
struct ProtocolSignature {
    protocol: Protocol,
    port: Option<u16>,
    pattern: Vec<u8>,
    offset: usize,
}

#[derive(Debug, Default, Clone)]
pub struct DpiStats {
    pub packets_processed: u64,
    pub bytes_processed: u64,
    pub connections_tracked: u64,
    pub alerts_generated: u64,
    pub protocols_detected: HashMap<String, u64>,
    pub top_talkers: Vec<(IpAddr, u64)>,
}

impl DpiEngine {
    /// Create new DPI engine
    pub fn new(config: DpiConfig) -> Self {
        Self {
            config,
            connections: HashMap::new(),
            patterns: Self::load_default_patterns(),
            protocol_signatures: Self::load_protocol_signatures(),
            stats: DpiStats::default(),
            alerts: Vec::new(),
        }
    }

    fn load_default_patterns() -> Vec<ContentPattern> {
        vec![
            // EICAR test pattern
            ContentPattern {
                name: "EICAR-Test".to_string(),
                pattern: b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR".to_vec(),
                pattern_type: PatternType::Exact,
                alert_type: AlertType::MalwareSignature,
                severity: AlertSeverity::High,
                protocols: None,
            },
            // Shell command injection
            ContentPattern {
                name: "Shell-Injection".to_string(),
                pattern: b"; /bin/".to_vec(),
                pattern_type: PatternType::Exact,
                alert_type: AlertType::SuspiciousTraffic,
                severity: AlertSeverity::High,
                protocols: Some(vec![Protocol::Http]),
            },
            // SQL injection attempt
            ContentPattern {
                name: "SQL-Injection-Union".to_string(),
                pattern: b"UNION SELECT".to_vec(),
                pattern_type: PatternType::Exact,
                alert_type: AlertType::SuspiciousTraffic,
                severity: AlertSeverity::High,
                protocols: Some(vec![Protocol::Http]),
            },
            // Base64 encoded PowerShell
            ContentPattern {
                name: "Encoded-PowerShell".to_string(),
                pattern: b"powershell -e".to_vec(),
                pattern_type: PatternType::Exact,
                alert_type: AlertType::CommandAndControl,
                severity: AlertSeverity::Critical,
                protocols: None,
            },
            // Potential data exfiltration (large base64)
            ContentPattern {
                name: "Large-Base64".to_string(),
                pattern: b"base64,".to_vec(),
                pattern_type: PatternType::Exact,
                alert_type: AlertType::DataExfiltration,
                severity: AlertSeverity::Medium,
                protocols: Some(vec![Protocol::Http, Protocol::Https]),
            },
        ]
    }

    fn load_protocol_signatures() -> Vec<ProtocolSignature> {
        vec![
            // HTTP
            ProtocolSignature {
                protocol: Protocol::Http,
                port: Some(80),
                pattern: b"HTTP/".to_vec(),
                offset: 0,
            },
            ProtocolSignature {
                protocol: Protocol::Http,
                port: None,
                pattern: b"GET ".to_vec(),
                offset: 0,
            },
            ProtocolSignature {
                protocol: Protocol::Http,
                port: None,
                pattern: b"POST ".to_vec(),
                offset: 0,
            },
            // SSH
            ProtocolSignature {
                protocol: Protocol::Ssh,
                port: Some(22),
                pattern: b"SSH-".to_vec(),
                offset: 0,
            },
            // DNS
            ProtocolSignature {
                protocol: Protocol::Dns,
                port: Some(53),
                pattern: vec![],
                offset: 0,
            },
            // FTP
            ProtocolSignature {
                protocol: Protocol::Ftp,
                port: Some(21),
                pattern: b"220 ".to_vec(),
                offset: 0,
            },
            // SMTP
            ProtocolSignature {
                protocol: Protocol::Smtp,
                port: Some(25),
                pattern: b"EHLO".to_vec(),
                offset: 0,
            },
        ]
    }

    /// Process a packet
    pub fn process_packet(&mut self, packet: &Packet) -> Vec<DpiAlert> {
        let mut alerts = Vec::new();

        // Update statistics
        self.stats.packets_processed += 1;
        self.stats.bytes_processed += packet.payload.len() as u64;

        // Create connection key
        let key = ConnectionKey {
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            protocol: match packet.protocol {
                Protocol::Tcp => 6,
                Protocol::Udp => 17,
                Protocol::Icmp => 1,
                _ => 0,
            },
        };

        // Track connection
        let connection = self.connections.entry(key.clone()).or_insert_with(|| {
            self.stats.connections_tracked += 1;
            Connection {
                src_ip: packet.src_ip,
                dst_ip: packet.dst_ip,
                src_port: packet.src_port,
                dst_port: packet.dst_port,
                protocol: packet.protocol.clone(),
                state: ConnectionState::New,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                start_time: packet.timestamp,
                last_activity: packet.timestamp,
                application: None,
                alerts: Vec::new(),
            }
        });

        // Update connection state
        self.update_connection_state(connection, packet);

        // Protocol detection
        if self.config.protocol_detection {
            if let Some(protocol) = self.detect_protocol(packet) {
                connection.protocol = protocol.clone();
                connection.application = Some(format!("{:?}", protocol));

                *self
                    .stats
                    .protocols_detected
                    .entry(format!("{:?}", protocol))
                    .or_insert(0) += 1;
            }
        }

        // Content inspection
        if self.config.content_inspection && !packet.payload.is_empty() {
            alerts.extend(self.inspect_content(packet, connection));
        }

        // Protocol-specific analysis
        alerts.extend(self.analyze_protocol(packet, connection));

        // Store alerts
        for alert in &alerts {
            connection.alerts.push(alert.clone());
            self.alerts.push(alert.clone());
            self.stats.alerts_generated += 1;
        }

        alerts
    }

    fn update_connection_state(&self, connection: &mut Connection, packet: &Packet) {
        connection.last_activity = packet.timestamp;
        connection.packets_sent += 1;
        connection.bytes_sent += packet.payload.len() as u64;

        // TCP state tracking
        if packet.protocol == Protocol::Tcp {
            if packet.flags.syn && !packet.flags.ack {
                connection.state = ConnectionState::New;
            } else if packet.flags.syn && packet.flags.ack {
                connection.state = ConnectionState::Established;
            } else if packet.flags.fin || packet.flags.rst {
                connection.state = ConnectionState::Closing;
            }
        }
    }

    fn detect_protocol(&self, packet: &Packet) -> Option<Protocol> {
        // Check by well-known ports first
        for sig in &self.protocol_signatures {
            if let Some(port) = sig.port {
                if packet.dst_port == port || packet.src_port == port {
                    // Verify with pattern if available
                    if sig.pattern.is_empty() {
                        return Some(sig.protocol.clone());
                    }
                    if packet.payload.len() > sig.offset + sig.pattern.len() {
                        let slice = &packet.payload[sig.offset..sig.offset + sig.pattern.len()];
                        if slice == sig.pattern.as_slice() {
                            return Some(sig.protocol.clone());
                        }
                    }
                }
            }
        }

        // Check by payload pattern
        for sig in &self.protocol_signatures {
            if sig.port.is_none() && !sig.pattern.is_empty() {
                if packet.payload.len() > sig.offset + sig.pattern.len() {
                    let slice = &packet.payload[sig.offset..sig.offset + sig.pattern.len()];
                    if slice == sig.pattern.as_slice() {
                        return Some(sig.protocol.clone());
                    }
                }
            }
        }

        None
    }

    fn inspect_content(&self, packet: &Packet, _connection: &Connection) -> Vec<DpiAlert> {
        let mut alerts = Vec::new();

        // Check payload size limit
        let payload = if packet.payload.len() > self.config.max_payload_size {
            &packet.payload[..self.config.max_payload_size]
        } else {
            &packet.payload
        };

        // Pattern matching
        for pattern in &self.patterns {
            // Check protocol filter
            if let Some(ref protocols) = pattern.protocols {
                if !protocols.contains(&packet.protocol) {
                    continue;
                }
            }

            // Match pattern
            if self.match_pattern(payload, pattern) {
                alerts.push(DpiAlert {
                    timestamp: packet.timestamp,
                    alert_type: pattern.alert_type.clone(),
                    severity: pattern.severity.clone(),
                    description: format!("Pattern '{}' matched in payload", pattern.name),
                    rule_id: Some(pattern.name.clone()),
                    payload_excerpt: Some(payload[..payload.len().min(64)].to_vec()),
                });
            }
        }

        alerts
    }

    fn match_pattern(&self, payload: &[u8], pattern: &ContentPattern) -> bool {
        match pattern.pattern_type {
            PatternType::Exact => {
                // Case-insensitive search for text patterns
                let payload_lower: Vec<u8> =
                    payload.iter().map(|b| b.to_ascii_lowercase()).collect();
                let pattern_lower: Vec<u8> = pattern
                    .pattern
                    .iter()
                    .map(|b| b.to_ascii_lowercase())
                    .collect();

                payload_lower
                    .windows(pattern_lower.len())
                    .any(|window| window == pattern_lower.as_slice())
            }
            PatternType::Regex | PatternType::HexWildcard => {
                // Simplified - in production use regex crate
                false
            }
        }
    }

    fn analyze_protocol(&self, packet: &Packet, connection: &Connection) -> Vec<DpiAlert> {
        let mut alerts = Vec::new();

        match connection.protocol {
            Protocol::Dns => {
                alerts.extend(self.analyze_dns(packet));
            }
            Protocol::Http => {
                alerts.extend(self.analyze_http(packet));
            }
            Protocol::Ssh => {
                alerts.extend(self.analyze_ssh(packet, connection));
            }
            _ => {}
        }

        alerts
    }

    fn analyze_dns(&self, packet: &Packet) -> Vec<DpiAlert> {
        let mut alerts = Vec::new();

        if packet.payload.len() < 12 {
            return alerts;
        }

        // Simple DNS parsing
        let query_count = u16::from_be_bytes([packet.payload[4], packet.payload[5]]);

        // Check for DNS tunneling indicators
        if query_count > 10 {
            alerts.push(DpiAlert {
                timestamp: packet.timestamp,
                alert_type: AlertType::DnsAnomaly,
                severity: AlertSeverity::Medium,
                description: format!("Unusual DNS query count: {}", query_count),
                rule_id: Some("DNS-ANOMALY-QUERY-COUNT".to_string()),
                payload_excerpt: None,
            });
        }

        // Check for very long DNS names (potential tunneling)
        if packet.payload.len() > 200 {
            alerts.push(DpiAlert {
                timestamp: packet.timestamp,
                alert_type: AlertType::DnsAnomaly,
                severity: AlertSeverity::Medium,
                description: "Unusually large DNS packet (potential tunneling)".to_string(),
                rule_id: Some("DNS-ANOMALY-SIZE".to_string()),
                payload_excerpt: None,
            });
        }

        alerts
    }

    fn analyze_http(&self, packet: &Packet) -> Vec<DpiAlert> {
        let mut alerts = Vec::new();

        let payload_str = String::from_utf8_lossy(&packet.payload);

        // Check for suspicious User-Agent
        if payload_str.contains("User-Agent:") {
            let suspicious_agents = ["curl", "wget", "python-requests", "nikto", "sqlmap"];
            for agent in &suspicious_agents {
                if payload_str.to_lowercase().contains(agent) {
                    alerts.push(DpiAlert {
                        timestamp: packet.timestamp,
                        alert_type: AlertType::SuspiciousTraffic,
                        severity: AlertSeverity::Low,
                        description: format!("Suspicious User-Agent detected: {}", agent),
                        rule_id: Some("HTTP-SUSPICIOUS-UA".to_string()),
                        payload_excerpt: None,
                    });
                }
            }
        }

        // Check for directory traversal
        if payload_str.contains("../") || payload_str.contains("..\\") {
            alerts.push(DpiAlert {
                timestamp: packet.timestamp,
                alert_type: AlertType::SuspiciousTraffic,
                severity: AlertSeverity::High,
                description: "Directory traversal attempt detected".to_string(),
                rule_id: Some("HTTP-DIR-TRAVERSAL".to_string()),
                payload_excerpt: Some(packet.payload[..packet.payload.len().min(100)].to_vec()),
            });
        }

        alerts
    }

    fn analyze_ssh(&self, packet: &Packet, connection: &Connection) -> Vec<DpiAlert> {
        let mut alerts = Vec::new();

        // Check for potential brute force (many small packets)
        if connection.packets_sent > 50 && connection.bytes_sent / connection.packets_sent < 100 {
            alerts.push(DpiAlert {
                timestamp: packet.timestamp,
                alert_type: AlertType::BruteForce,
                severity: AlertSeverity::Medium,
                description: "Potential SSH brute force attack detected".to_string(),
                rule_id: Some("SSH-BRUTEFORCE".to_string()),
                payload_excerpt: None,
            });
        }

        alerts
    }

    /// Add custom content pattern
    pub fn add_pattern(&mut self, pattern: ContentPattern) {
        self.patterns.push(pattern);
    }

    /// Get connection by key
    pub fn get_connection(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
    ) -> Option<&Connection> {
        let key = ConnectionKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: 6, // TCP
        };
        self.connections.get(&key)
    }

    /// Get all active connections
    pub fn get_active_connections(&self) -> Vec<&Connection> {
        self.connections
            .values()
            .filter(|c| c.state == ConnectionState::Established)
            .collect()
    }

    /// Get statistics
    pub fn get_stats(&self) -> &DpiStats {
        &self.stats
    }

    /// Get recent alerts
    pub fn get_alerts(&self, count: usize) -> Vec<&DpiAlert> {
        self.alerts.iter().rev().take(count).collect()
    }

    /// Cleanup expired connections
    pub fn cleanup_connections(&mut self, max_age: Duration) {
        let now = SystemTime::now();

        self.connections.retain(|_, conn| {
            if let Ok(age) = now.duration_since(conn.last_activity) {
                age < max_age
            } else {
                true
            }
        });
    }

    /// Export statistics report
    pub fn export_report(&self) -> String {
        let mut report = String::new();
        report.push_str("=== DPI Engine Report ===\n\n");
        report.push_str(&format!(
            "Packets processed: {}\n",
            self.stats.packets_processed
        ));
        report.push_str(&format!(
            "Bytes processed: {}\n",
            self.stats.bytes_processed
        ));
        report.push_str(&format!(
            "Connections tracked: {}\n",
            self.stats.connections_tracked
        ));
        report.push_str(&format!(
            "Alerts generated: {}\n\n",
            self.stats.alerts_generated
        ));

        report.push_str("Protocol breakdown:\n");
        for (proto, count) in &self.stats.protocols_detected {
            report.push_str(&format!("  {}: {}\n", proto, count));
        }

        report
    }
}

/// Packet capture interface (simplified)
pub struct PacketCapture {
    /// Interface name
    interface: String,
    /// BPF filter
    filter: Option<String>,
    /// Captured packet count
    packet_count: u64,
}

impl PacketCapture {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
            filter: None,
            packet_count: 0,
        }
    }

    pub fn set_filter(&mut self, filter: &str) {
        self.filter = Some(filter.to_string());
    }

    /// Parse raw packet (simplified Ethernet/IP/TCP parsing)
    pub fn parse_packet(&self, raw: &[u8]) -> Option<Packet> {
        // Minimum Ethernet + IP + TCP header
        if raw.len() < 54 {
            return None;
        }

        // Skip Ethernet header (14 bytes)
        let ip_header = &raw[14..];

        // Parse IP header
        let version = (ip_header[0] >> 4) & 0x0F;
        if version != 4 {
            return None; // Only IPv4 for simplicity
        }

        let ihl = (ip_header[0] & 0x0F) as usize * 4;
        let protocol_num = ip_header[9];

        let src_ip = IpAddr::V4(Ipv4Addr::new(
            ip_header[12],
            ip_header[13],
            ip_header[14],
            ip_header[15],
        ));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(
            ip_header[16],
            ip_header[17],
            ip_header[18],
            ip_header[19],
        ));

        // Parse TCP/UDP header
        let transport_header = &ip_header[ihl..];
        if transport_header.len() < 8 {
            return None;
        }

        let src_port = u16::from_be_bytes([transport_header[0], transport_header[1]]);
        let dst_port = u16::from_be_bytes([transport_header[2], transport_header[3]]);

        let (protocol, flags, header_len) = if protocol_num == 6 {
            // TCP
            let data_offset = ((transport_header[12] >> 4) & 0x0F) as usize * 4;
            let flags = PacketFlags {
                syn: transport_header[13] & 0x02 != 0,
                ack: transport_header[13] & 0x10 != 0,
                fin: transport_header[13] & 0x01 != 0,
                rst: transport_header[13] & 0x04 != 0,
                psh: transport_header[13] & 0x08 != 0,
                urg: transport_header[13] & 0x20 != 0,
            };
            (Protocol::Tcp, flags, data_offset)
        } else if protocol_num == 17 {
            // UDP
            (Protocol::Udp, PacketFlags::default(), 8)
        } else {
            (Protocol::Unknown(protocol_num), PacketFlags::default(), 0)
        };

        let payload = if transport_header.len() > header_len {
            transport_header[header_len..].to_vec()
        } else {
            Vec::new()
        };

        Some(Packet {
            timestamp: SystemTime::now(),
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            payload,
            flags,
        })
    }
}

fn main() {
    println!("=== Deep Packet Inspection Engine Demo ===\n");

    // Create DPI engine
    let mut engine = DpiEngine::new(DpiConfig::default());

    // Add custom pattern
    engine.add_pattern(ContentPattern {
        name: "Custom-Alert".to_string(),
        pattern: b"MALICIOUS".to_vec(),
        pattern_type: PatternType::Exact,
        alert_type: AlertType::MalwareSignature,
        severity: AlertSeverity::High,
        protocols: None,
    });

    println!(
        "DPI engine initialized with {} patterns\n",
        engine.patterns.len()
    );

    // Simulate packet processing
    println!("Simulating packet processing:\n");

    // Normal HTTP request
    let http_packet = Packet {
        timestamp: SystemTime::now(),
        src_ip: "192.168.1.100".parse().unwrap(),
        dst_ip: "93.184.216.34".parse().unwrap(),
        src_port: 54321,
        dst_port: 80,
        protocol: Protocol::Tcp,
        payload: b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n".to_vec(),
        flags: PacketFlags {
            syn: false,
            ack: true,
            ..Default::default()
        },
    };

    let alerts = engine.process_packet(&http_packet);
    println!("1. Normal HTTP request: {} alerts", alerts.len());

    // HTTP with SQL injection
    let sqli_packet = Packet {
        timestamp: SystemTime::now(),
        src_ip: "10.0.0.50".parse().unwrap(),
        dst_ip: "192.168.1.10".parse().unwrap(),
        src_port: 45678,
        dst_port: 80,
        protocol: Protocol::Http,
        payload: b"GET /search?q=test' UNION SELECT * FROM users-- HTTP/1.1\r\n".to_vec(),
        flags: PacketFlags::default(),
    };

    let alerts = engine.process_packet(&sqli_packet);
    println!("2. SQL injection attempt: {} alerts", alerts.len());
    for alert in &alerts {
        println!("   - {:?}: {}", alert.severity, alert.description);
    }

    // Packet with malware signature
    let malware_packet = Packet {
        timestamp: SystemTime::now(),
        src_ip: "172.16.0.100".parse().unwrap(),
        dst_ip: "10.0.0.1".parse().unwrap(),
        src_port: 12345,
        dst_port: 443,
        protocol: Protocol::Tcp,
        payload: b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-test-payload".to_vec(),
        flags: PacketFlags::default(),
    };

    let alerts = engine.process_packet(&malware_packet);
    println!("3. Malware signature: {} alerts", alerts.len());
    for alert in &alerts {
        println!("   - {:?}: {}", alert.severity, alert.description);
    }

    // DNS packet with anomaly
    let dns_packet = Packet {
        timestamp: SystemTime::now(),
        src_ip: "192.168.1.50".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 53421,
        dst_port: 53,
        protocol: Protocol::Dns,
        // Malformed DNS with high query count
        payload: vec![0x00; 300], // Large DNS packet
        flags: PacketFlags::default(),
    };

    let alerts = engine.process_packet(&dns_packet);
    println!("4. Anomalous DNS: {} alerts", alerts.len());

    // Directory traversal attempt
    let traversal_packet = Packet {
        timestamp: SystemTime::now(),
        src_ip: "10.0.0.99".parse().unwrap(),
        dst_ip: "192.168.1.10".parse().unwrap(),
        src_port: 55555,
        dst_port: 80,
        protocol: Protocol::Http,
        payload: b"GET /../../etc/passwd HTTP/1.1\r\n".to_vec(),
        flags: PacketFlags::default(),
    };

    let alerts = engine.process_packet(&traversal_packet);
    println!("5. Directory traversal: {} alerts", alerts.len());
    for alert in &alerts {
        println!("   - {:?}: {}", alert.severity, alert.description);
    }

    // Display statistics
    println!("\n=== Statistics ===");
    let stats = engine.get_stats();
    println!("Packets processed: {}", stats.packets_processed);
    println!("Bytes processed: {}", stats.bytes_processed);
    println!("Connections tracked: {}", stats.connections_tracked);
    println!("Alerts generated: {}", stats.alerts_generated);
    println!("\nProtocol breakdown:");
    for (proto, count) in &stats.protocols_detected {
        println!("  {}: {}", proto, count);
    }

    // Show active connections
    println!(
        "\nActive connections: {}",
        engine.get_active_connections().len()
    );

    // Show recent alerts
    println!("\nRecent alerts:");
    for alert in engine.get_alerts(5) {
        println!(
            "  [{:?}] {:?}: {}",
            alert.severity, alert.alert_type, alert.description
        );
    }

    // Export report
    println!("\n{}", engine.export_report());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_packet(payload: &[u8]) -> Packet {
        Packet {
            timestamp: SystemTime::now(),
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: Protocol::Tcp,
            payload: payload.to_vec(),
            flags: PacketFlags::default(),
        }
    }

    #[test]
    fn test_pattern_matching() {
        let mut engine = DpiEngine::new(DpiConfig::default());

        let packet = create_test_packet(b"GET /test HTTP/1.1\r\nHost: example.com\r\n");
        let alerts = engine.process_packet(&packet);

        assert!(alerts.is_empty());
    }

    #[test]
    fn test_malware_detection() {
        let mut engine = DpiEngine::new(DpiConfig::default());

        let packet = create_test_packet(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR");
        let alerts = engine.process_packet(&packet);

        assert!(!alerts.is_empty());
        assert!(alerts
            .iter()
            .any(|a| a.alert_type == AlertType::MalwareSignature));
    }

    #[test]
    fn test_sql_injection_detection() {
        let mut engine = DpiEngine::new(DpiConfig::default());

        let mut packet = create_test_packet(b"GET /?id=1 UNION SELECT * FROM users");
        packet.protocol = Protocol::Http;

        let alerts = engine.process_packet(&packet);

        assert!(!alerts.is_empty());
        assert!(alerts
            .iter()
            .any(|a| a.alert_type == AlertType::SuspiciousTraffic));
    }

    #[test]
    fn test_protocol_detection() {
        let engine = DpiEngine::new(DpiConfig::default());

        let http_packet = create_test_packet(b"GET / HTTP/1.1\r\n");
        assert!(engine.detect_protocol(&http_packet).is_some());

        let ssh_packet = create_test_packet(b"SSH-2.0-OpenSSH_8.0");
        assert!(engine.detect_protocol(&ssh_packet).is_some());
    }

    #[test]
    fn test_connection_tracking() {
        let mut engine = DpiEngine::new(DpiConfig::default());

        let packet1 = Packet {
            timestamp: SystemTime::now(),
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: Protocol::Tcp,
            payload: b"SYN".to_vec(),
            flags: PacketFlags {
                syn: true,
                ..Default::default()
            },
        };

        engine.process_packet(&packet1);

        assert_eq!(engine.stats.connections_tracked, 1);
    }

    #[test]
    fn test_statistics() {
        let mut engine = DpiEngine::new(DpiConfig::default());

        for i in 0..10 {
            let packet = create_test_packet(&format!("test payload {}", i).as_bytes());
            engine.process_packet(&packet);
        }

        assert_eq!(engine.stats.packets_processed, 10);
    }

    #[test]
    fn test_custom_pattern() {
        let mut engine = DpiEngine::new(DpiConfig::default());

        engine.add_pattern(ContentPattern {
            name: "Test-Pattern".to_string(),
            pattern: b"CUSTOM_MALWARE".to_vec(),
            pattern_type: PatternType::Exact,
            alert_type: AlertType::MalwareSignature,
            severity: AlertSeverity::Critical,
            protocols: None,
        });

        let packet = create_test_packet(b"Contains CUSTOM_MALWARE signature");
        let alerts = engine.process_packet(&packet);

        assert!(!alerts.is_empty());
        assert!(alerts
            .iter()
            .any(|a| a.rule_id == Some("Test-Pattern".to_string())));
    }

    #[test]
    fn test_alert_severity_ordering() {
        assert!(AlertSeverity::Critical > AlertSeverity::High);
        assert!(AlertSeverity::High > AlertSeverity::Medium);
        assert!(AlertSeverity::Medium > AlertSeverity::Low);
        assert!(AlertSeverity::Low > AlertSeverity::Info);
    }
}
