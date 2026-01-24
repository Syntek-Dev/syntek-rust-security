//! Intrusion Detection System Engine
//!
//! Implements Snort/Suricata-compatible rule processing in Rust,
//! with alert handling, blocking capabilities, and traffic analysis.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// IDS rule definition (Snort-compatible format)
#[derive(Debug, Clone)]
pub struct IdsRule {
    /// Rule ID (SID)
    pub sid: u32,
    /// Rule revision
    pub rev: u32,
    /// Action
    pub action: RuleAction,
    /// Protocol
    pub protocol: RuleProtocol,
    /// Source address
    pub src_addr: AddressSpec,
    /// Source port
    pub src_port: PortSpec,
    /// Direction
    pub direction: Direction,
    /// Destination address
    pub dst_addr: AddressSpec,
    /// Destination port
    pub dst_port: PortSpec,
    /// Rule options
    pub options: RuleOptions,
    /// Classification
    pub classtype: Option<String>,
    /// Priority
    pub priority: u8,
    /// Enabled
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuleAction {
    Alert,
    Log,
    Pass,
    Drop,
    Reject,
    Sdrop, // Silent drop
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuleProtocol {
    Tcp,
    Udp,
    Icmp,
    Ip,
    Http,
    Dns,
    Tls,
    Any,
}

#[derive(Debug, Clone)]
pub enum AddressSpec {
    Any,
    Single(IpAddr),
    Cidr(IpAddr, u8),
    List(Vec<AddressSpec>),
    Negated(Box<AddressSpec>),
    Variable(String), // $HOME_NET, $EXTERNAL_NET, etc.
}

#[derive(Debug, Clone)]
pub enum PortSpec {
    Any,
    Single(u16),
    Range(u16, u16),
    List(Vec<PortSpec>),
    Negated(Box<PortSpec>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Direction {
    Unidirectional, // ->
    Bidirectional,  // <>
}

/// Rule options for matching
#[derive(Debug, Clone, Default)]
pub struct RuleOptions {
    /// Message to display
    pub msg: Option<String>,
    /// Content patterns
    pub content: Vec<ContentMatch>,
    /// PCRE patterns
    pub pcre: Vec<String>,
    /// Flow options
    pub flow: Option<FlowOptions>,
    /// Threshold options
    pub threshold: Option<ThresholdOptions>,
    /// Reference (CVE, URL, etc.)
    pub reference: Vec<String>,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ContentMatch {
    /// Pattern to match
    pub pattern: Vec<u8>,
    /// Case insensitive
    pub nocase: bool,
    /// Offset from start
    pub offset: Option<usize>,
    /// Search depth
    pub depth: Option<usize>,
    /// Distance from previous match
    pub distance: Option<i32>,
    /// Within N bytes of previous match
    pub within: Option<usize>,
    /// Negated match
    pub negated: bool,
    /// HTTP-specific modifiers
    pub http_modifier: Option<HttpModifier>,
}

#[derive(Debug, Clone)]
pub enum HttpModifier {
    HttpUri,
    HttpHeader,
    HttpCookie,
    HttpMethod,
    HttpStatCode,
    HttpStatMsg,
    HttpHost,
    HttpRawUri,
}

#[derive(Debug, Clone)]
pub struct FlowOptions {
    /// Established connection
    pub established: bool,
    /// To server
    pub to_server: bool,
    /// To client
    pub to_client: bool,
    /// Stream only
    pub stream_only: bool,
}

#[derive(Debug, Clone)]
pub struct ThresholdOptions {
    /// Threshold type
    pub threshold_type: ThresholdType,
    /// Track by source or destination
    pub track: TrackBy,
    /// Count threshold
    pub count: u32,
    /// Time window (seconds)
    pub seconds: u32,
}

#[derive(Debug, Clone)]
pub enum ThresholdType {
    Threshold,
    Limit,
    Both,
}

#[derive(Debug, Clone)]
pub enum TrackBy {
    BySrc,
    ByDst,
    ByRule,
}

/// IDS alert
#[derive(Debug, Clone)]
pub struct IdsAlert {
    /// Timestamp
    pub timestamp: SystemTime,
    /// Rule that triggered
    pub rule_sid: u32,
    /// Alert message
    pub message: String,
    /// Source IP
    pub src_ip: IpAddr,
    /// Destination IP
    pub dst_ip: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Protocol
    pub protocol: RuleProtocol,
    /// Classification
    pub classification: Option<String>,
    /// Priority
    pub priority: u8,
    /// Payload excerpt
    pub payload_excerpt: Option<Vec<u8>>,
    /// Action taken
    pub action: RuleAction,
}

/// IDS engine configuration
#[derive(Debug, Clone)]
pub struct IdsConfig {
    /// Home network definition
    pub home_net: Vec<AddressSpec>,
    /// External network definition
    pub external_net: AddressSpec,
    /// HTTP ports
    pub http_ports: PortSpec,
    /// DNS servers
    pub dns_servers: Vec<IpAddr>,
    /// Enable inline blocking
    pub inline_mode: bool,
    /// Maximum packet size to inspect
    pub max_packet_size: usize,
    /// Stream reassembly settings
    pub stream_reassembly: bool,
}

impl Default for IdsConfig {
    fn default() -> Self {
        Self {
            home_net: vec![
                AddressSpec::Cidr("10.0.0.0".parse().unwrap(), 8),
                AddressSpec::Cidr("172.16.0.0".parse().unwrap(), 12),
                AddressSpec::Cidr("192.168.0.0".parse().unwrap(), 16),
            ],
            external_net: AddressSpec::Any,
            http_ports: PortSpec::List(vec![
                PortSpec::Single(80),
                PortSpec::Single(443),
                PortSpec::Single(8080),
            ]),
            dns_servers: vec!["8.8.8.8".parse().unwrap()],
            inline_mode: false,
            max_packet_size: 65535,
            stream_reassembly: true,
        }
    }
}

/// IDS engine
pub struct IdsEngine {
    config: IdsConfig,
    /// Loaded rules
    rules: Vec<IdsRule>,
    /// Rule index by SID
    rules_by_sid: HashMap<u32, usize>,
    /// Threshold tracking
    thresholds: HashMap<ThresholdKey, ThresholdState>,
    /// Suppression list
    suppressions: Vec<Suppression>,
    /// Statistics
    stats: IdsStats,
    /// Generated alerts
    alerts: Vec<IdsAlert>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ThresholdKey {
    sid: u32,
    track_key: String,
}

#[derive(Debug, Clone)]
struct ThresholdState {
    count: u32,
    window_start: SystemTime,
    alerted: bool,
}

#[derive(Debug, Clone)]
pub struct Suppression {
    /// Rule SID to suppress
    pub sid: u32,
    /// Track by source or destination
    pub track: TrackBy,
    /// IP to suppress for
    pub ip: Option<IpAddr>,
}

#[derive(Debug, Default, Clone)]
pub struct IdsStats {
    pub packets_inspected: u64,
    pub bytes_inspected: u64,
    pub rules_matched: u64,
    pub alerts_generated: u64,
    pub packets_dropped: u64,
    pub rules_loaded: u64,
}

impl IdsEngine {
    /// Create new IDS engine
    pub fn new(config: IdsConfig) -> Self {
        Self {
            config,
            rules: Vec::new(),
            rules_by_sid: HashMap::new(),
            thresholds: HashMap::new(),
            suppressions: Vec::new(),
            stats: IdsStats::default(),
            alerts: Vec::new(),
        }
    }

    /// Load rule from Snort rule string
    pub fn load_rule(&mut self, rule_str: &str) -> Result<u32, String> {
        let rule = self.parse_rule(rule_str)?;
        let sid = rule.sid;

        let index = self.rules.len();
        self.rules.push(rule);
        self.rules_by_sid.insert(sid, index);
        self.stats.rules_loaded += 1;

        Ok(sid)
    }

    fn parse_rule(&self, rule_str: &str) -> Result<IdsRule, String> {
        // Simplified Snort rule parser
        let rule_str = rule_str.trim();

        if rule_str.is_empty() || rule_str.starts_with('#') {
            return Err("Empty or comment line".to_string());
        }

        // Parse action
        let parts: Vec<&str> = rule_str.splitn(2, ' ').collect();
        if parts.len() < 2 {
            return Err("Invalid rule format".to_string());
        }

        let action = match parts[0].to_lowercase().as_str() {
            "alert" => RuleAction::Alert,
            "log" => RuleAction::Log,
            "pass" => RuleAction::Pass,
            "drop" => RuleAction::Drop,
            "reject" => RuleAction::Reject,
            "sdrop" => RuleAction::Sdrop,
            _ => return Err(format!("Unknown action: {}", parts[0])),
        };

        // Parse header
        let remaining = parts[1];
        let header_end = remaining.find('(').unwrap_or(remaining.len());
        let header = &remaining[..header_end].trim();

        let header_parts: Vec<&str> = header.split_whitespace().collect();
        if header_parts.len() < 6 {
            return Err("Invalid header format".to_string());
        }

        let protocol = match header_parts[0].to_lowercase().as_str() {
            "tcp" => RuleProtocol::Tcp,
            "udp" => RuleProtocol::Udp,
            "icmp" => RuleProtocol::Icmp,
            "ip" => RuleProtocol::Ip,
            "http" => RuleProtocol::Http,
            "dns" => RuleProtocol::Dns,
            "tls" => RuleProtocol::Tls,
            _ => RuleProtocol::Any,
        };

        let src_addr = self.parse_address(header_parts[1])?;
        let src_port = self.parse_port(header_parts[2])?;

        let direction = match header_parts[3] {
            "->" => Direction::Unidirectional,
            "<>" => Direction::Bidirectional,
            _ => return Err(format!("Invalid direction: {}", header_parts[3])),
        };

        let dst_addr = self.parse_address(header_parts[4])?;
        let dst_port = self.parse_port(header_parts[5])?;

        // Parse options
        let options = if let Some(start) = remaining.find('(') {
            let end = remaining.rfind(')').unwrap_or(remaining.len());
            let opts_str = &remaining[start + 1..end];
            self.parse_options(opts_str)?
        } else {
            RuleOptions::default()
        };

        // Extract SID from options
        let sid = options
            .metadata
            .get("sid")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let rev = options
            .metadata
            .get("rev")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let priority = options
            .metadata
            .get("priority")
            .and_then(|s| s.parse().ok())
            .unwrap_or(3);

        let classtype = options.metadata.get("classtype").cloned();

        Ok(IdsRule {
            sid,
            rev,
            action,
            protocol,
            src_addr,
            src_port,
            direction,
            dst_addr,
            dst_port,
            options,
            classtype,
            priority,
            enabled: true,
        })
    }

    fn parse_address(&self, addr_str: &str) -> Result<AddressSpec, String> {
        let addr_str = addr_str.trim();

        if addr_str == "any" {
            return Ok(AddressSpec::Any);
        }

        if addr_str.starts_with('$') {
            return Ok(AddressSpec::Variable(addr_str.to_string()));
        }

        if addr_str.starts_with('!') {
            let inner = self.parse_address(&addr_str[1..])?;
            return Ok(AddressSpec::Negated(Box::new(inner)));
        }

        if addr_str.contains('/') {
            let parts: Vec<&str> = addr_str.split('/').collect();
            if parts.len() == 2 {
                let ip: IpAddr = parts[0]
                    .parse()
                    .map_err(|_| format!("Invalid IP: {}", parts[0]))?;
                let prefix: u8 = parts[1]
                    .parse()
                    .map_err(|_| format!("Invalid prefix: {}", parts[1]))?;
                return Ok(AddressSpec::Cidr(ip, prefix));
            }
        }

        let ip: IpAddr = addr_str
            .parse()
            .map_err(|_| format!("Invalid address: {}", addr_str))?;
        Ok(AddressSpec::Single(ip))
    }

    fn parse_port(&self, port_str: &str) -> Result<PortSpec, String> {
        let port_str = port_str.trim();

        if port_str == "any" {
            return Ok(PortSpec::Any);
        }

        if port_str.starts_with('!') {
            let inner = self.parse_port(&port_str[1..])?;
            return Ok(PortSpec::Negated(Box::new(inner)));
        }

        if port_str.contains(':') {
            let parts: Vec<&str> = port_str.split(':').collect();
            if parts.len() == 2 {
                let start: u16 = parts[0].parse().unwrap_or(0);
                let end: u16 = parts[1].parse().unwrap_or(65535);
                return Ok(PortSpec::Range(start, end));
            }
        }

        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("Invalid port: {}", port_str))?;
        Ok(PortSpec::Single(port))
    }

    fn parse_options(&self, opts_str: &str) -> Result<RuleOptions, String> {
        let mut options = RuleOptions::default();
        let mut metadata = HashMap::new();

        // Split options by semicolon
        for opt in opts_str.split(';') {
            let opt = opt.trim();
            if opt.is_empty() {
                continue;
            }

            // Split key:value
            if let Some(colon_pos) = opt.find(':') {
                let key = opt[..colon_pos].trim();
                let value = opt[colon_pos + 1..].trim().trim_matches('"');

                match key {
                    "msg" => options.msg = Some(value.to_string()),
                    "content" => {
                        options.content.push(ContentMatch {
                            pattern: self.parse_content_pattern(value),
                            nocase: false,
                            offset: None,
                            depth: None,
                            distance: None,
                            within: None,
                            negated: value.starts_with('!'),
                            http_modifier: None,
                        });
                    }
                    "pcre" => options.pcre.push(value.to_string()),
                    "sid" => {
                        metadata.insert("sid".to_string(), value.to_string());
                    }
                    "rev" => {
                        metadata.insert("rev".to_string(), value.to_string());
                    }
                    "classtype" => {
                        metadata.insert("classtype".to_string(), value.to_string());
                    }
                    "priority" => {
                        metadata.insert("priority".to_string(), value.to_string());
                    }
                    "reference" => options.reference.push(value.to_string()),
                    _ => {
                        metadata.insert(key.to_string(), value.to_string());
                    }
                }
            } else {
                // Flag-style options
                match opt {
                    "nocase" => {
                        if let Some(last) = options.content.last_mut() {
                            last.nocase = true;
                        }
                    }
                    "http_uri" => {
                        if let Some(last) = options.content.last_mut() {
                            last.http_modifier = Some(HttpModifier::HttpUri);
                        }
                    }
                    "http_header" => {
                        if let Some(last) = options.content.last_mut() {
                            last.http_modifier = Some(HttpModifier::HttpHeader);
                        }
                    }
                    _ => {}
                }
            }
        }

        options.metadata = metadata;
        Ok(options)
    }

    fn parse_content_pattern(&self, pattern_str: &str) -> Vec<u8> {
        let pattern_str = pattern_str.trim().trim_matches('"');
        let mut result = Vec::new();
        let mut chars = pattern_str.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '|' {
                // Hex mode
                let mut hex_str = String::new();
                while let Some(&next) = chars.peek() {
                    if next == '|' {
                        chars.next();
                        break;
                    }
                    if !next.is_whitespace() {
                        hex_str.push(next);
                    }
                    chars.next();
                }

                // Parse hex bytes
                for chunk in hex_str.as_bytes().chunks(2) {
                    if chunk.len() == 2 {
                        if let Ok(byte) = u8::from_str_radix(&String::from_utf8_lossy(chunk), 16) {
                            result.push(byte);
                        }
                    }
                }
            } else {
                result.push(c as u8);
            }
        }

        result
    }

    /// Inspect a packet
    pub fn inspect_packet(&mut self, packet: &PacketData) -> Vec<IdsAlert> {
        let mut alerts = Vec::new();

        self.stats.packets_inspected += 1;
        self.stats.bytes_inspected += packet.payload.len() as u64;

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            // Check protocol match
            if !self.protocol_matches(&rule.protocol, &packet.protocol) {
                continue;
            }

            // Check address match
            if !self.address_matches(&rule.src_addr, &packet.src_ip) {
                continue;
            }
            if !self.address_matches(&rule.dst_addr, &packet.dst_ip) {
                continue;
            }

            // Check port match
            if !self.port_matches(&rule.src_port, packet.src_port) {
                continue;
            }
            if !self.port_matches(&rule.dst_port, packet.dst_port) {
                continue;
            }

            // Check content match
            if !self.content_matches(&rule.options, &packet.payload) {
                continue;
            }

            // Rule matched!
            self.stats.rules_matched += 1;

            // Check threshold
            if let Some(ref threshold) = rule.options.threshold {
                if !self.check_threshold(rule.sid, threshold, packet) {
                    continue;
                }
            }

            // Check suppression
            if self.is_suppressed(rule.sid, packet) {
                continue;
            }

            // Generate alert
            let alert = IdsAlert {
                timestamp: SystemTime::now(),
                rule_sid: rule.sid,
                message: rule
                    .options
                    .msg
                    .clone()
                    .unwrap_or_else(|| format!("Rule {} matched", rule.sid)),
                src_ip: packet.src_ip,
                dst_ip: packet.dst_ip,
                src_port: packet.src_port,
                dst_port: packet.dst_port,
                protocol: rule.protocol.clone(),
                classification: rule.classtype.clone(),
                priority: rule.priority,
                payload_excerpt: Some(packet.payload[..packet.payload.len().min(64)].to_vec()),
                action: rule.action.clone(),
            };

            self.stats.alerts_generated += 1;

            // Handle action
            match rule.action {
                RuleAction::Drop | RuleAction::Reject | RuleAction::Sdrop => {
                    self.stats.packets_dropped += 1;
                }
                _ => {}
            }

            self.alerts.push(alert.clone());
            alerts.push(alert);
        }

        alerts
    }

    fn protocol_matches(&self, rule_proto: &RuleProtocol, packet_proto: &RuleProtocol) -> bool {
        matches!(
            (rule_proto, packet_proto),
            (RuleProtocol::Any, _) |
            (RuleProtocol::Ip, _) |
            (a, b) if a == b
        )
    }

    fn address_matches(&self, spec: &AddressSpec, ip: &IpAddr) -> bool {
        match spec {
            AddressSpec::Any => true,
            AddressSpec::Single(addr) => addr == ip,
            AddressSpec::Cidr(network, prefix) => self.ip_in_cidr(ip, network, *prefix),
            AddressSpec::List(specs) => specs.iter().any(|s| self.address_matches(s, ip)),
            AddressSpec::Negated(inner) => !self.address_matches(inner, ip),
            AddressSpec::Variable(var) => {
                // Resolve variable
                match var.as_str() {
                    "$HOME_NET" => self
                        .config
                        .home_net
                        .iter()
                        .any(|s| self.address_matches(s, ip)),
                    "$EXTERNAL_NET" => self.address_matches(&self.config.external_net, ip),
                    _ => true,
                }
            }
        }
    }

    fn ip_in_cidr(&self, ip: &IpAddr, network: &IpAddr, prefix: u8) -> bool {
        match (ip, network) {
            (IpAddr::V4(ip), IpAddr::V4(net)) => {
                let ip_bits = u32::from_be_bytes(ip.octets());
                let net_bits = u32::from_be_bytes(net.octets());
                let mask = !0u32 << (32 - prefix);
                (ip_bits & mask) == (net_bits & mask)
            }
            _ => false, // Simplified - IPv6 not handled
        }
    }

    fn port_matches(&self, spec: &PortSpec, port: u16) -> bool {
        match spec {
            PortSpec::Any => true,
            PortSpec::Single(p) => *p == port,
            PortSpec::Range(start, end) => port >= *start && port <= *end,
            PortSpec::List(specs) => specs.iter().any(|s| self.port_matches(s, port)),
            PortSpec::Negated(inner) => !self.port_matches(inner, port),
        }
    }

    fn content_matches(&self, options: &RuleOptions, payload: &[u8]) -> bool {
        if options.content.is_empty() {
            return true;
        }

        for content in &options.content {
            let pattern = if content.nocase {
                content
                    .pattern
                    .iter()
                    .map(|b| b.to_ascii_lowercase())
                    .collect::<Vec<_>>()
            } else {
                content.pattern.clone()
            };

            let search_payload = if content.nocase {
                payload
                    .iter()
                    .map(|b| b.to_ascii_lowercase())
                    .collect::<Vec<_>>()
            } else {
                payload.to_vec()
            };

            let found = search_payload
                .windows(pattern.len())
                .any(|window| window == pattern.as_slice());

            if content.negated {
                if found {
                    return false;
                }
            } else if !found {
                return false;
            }
        }

        true
    }

    fn check_threshold(
        &mut self,
        sid: u32,
        threshold: &ThresholdOptions,
        packet: &PacketData,
    ) -> bool {
        let track_key = match threshold.track {
            TrackBy::BySrc => packet.src_ip.to_string(),
            TrackBy::ByDst => packet.dst_ip.to_string(),
            TrackBy::ByRule => sid.to_string(),
        };

        let key = ThresholdKey { sid, track_key };
        let now = SystemTime::now();

        let state = self.thresholds.entry(key).or_insert(ThresholdState {
            count: 0,
            window_start: now,
            alerted: false,
        });

        // Check if window has expired
        let window_duration = Duration::from_secs(threshold.seconds as u64);
        if let Ok(elapsed) = now.duration_since(state.window_start) {
            if elapsed >= window_duration {
                state.count = 0;
                state.window_start = now;
                state.alerted = false;
            }
        }

        state.count += 1;

        match threshold.threshold_type {
            ThresholdType::Threshold => {
                if state.count >= threshold.count && !state.alerted {
                    state.alerted = true;
                    true
                } else {
                    false
                }
            }
            ThresholdType::Limit => state.count <= threshold.count,
            ThresholdType::Both => {
                state.count >= threshold.count && state.count <= threshold.count * 2
            }
        }
    }

    fn is_suppressed(&self, sid: u32, packet: &PacketData) -> bool {
        for supp in &self.suppressions {
            if supp.sid != sid {
                continue;
            }

            if let Some(ref ip) = supp.ip {
                match supp.track {
                    TrackBy::BySrc if &packet.src_ip == ip => return true,
                    TrackBy::ByDst if &packet.dst_ip == ip => return true,
                    _ => {}
                }
            } else {
                return true;
            }
        }
        false
    }

    /// Add suppression
    pub fn add_suppression(&mut self, suppression: Suppression) {
        self.suppressions.push(suppression);
    }

    /// Enable/disable rule
    pub fn set_rule_enabled(&mut self, sid: u32, enabled: bool) {
        if let Some(&index) = self.rules_by_sid.get(&sid) {
            if let Some(rule) = self.rules.get_mut(index) {
                rule.enabled = enabled;
            }
        }
    }

    /// Get rule by SID
    pub fn get_rule(&self, sid: u32) -> Option<&IdsRule> {
        self.rules_by_sid
            .get(&sid)
            .and_then(|&index| self.rules.get(index))
    }

    /// Get all rules
    pub fn get_rules(&self) -> &[IdsRule] {
        &self.rules
    }

    /// Get statistics
    pub fn get_stats(&self) -> &IdsStats {
        &self.stats
    }

    /// Get recent alerts
    pub fn get_alerts(&self, count: usize) -> Vec<&IdsAlert> {
        self.alerts.iter().rev().take(count).collect()
    }

    /// Export rules to Snort format
    pub fn export_rules(&self) -> String {
        let mut output = String::new();
        output.push_str("# Exported IDS rules\n\n");

        for rule in &self.rules {
            output.push_str(&format!(
                "{} {} {} {} {} {} {} ({}) \n",
                match rule.action {
                    RuleAction::Alert => "alert",
                    RuleAction::Log => "log",
                    RuleAction::Pass => "pass",
                    RuleAction::Drop => "drop",
                    RuleAction::Reject => "reject",
                    RuleAction::Sdrop => "sdrop",
                },
                match rule.protocol {
                    RuleProtocol::Tcp => "tcp",
                    RuleProtocol::Udp => "udp",
                    RuleProtocol::Icmp => "icmp",
                    _ => "ip",
                },
                match &rule.src_addr {
                    AddressSpec::Any => "any".to_string(),
                    AddressSpec::Single(ip) => ip.to_string(),
                    _ => "any".to_string(),
                },
                match rule.src_port {
                    PortSpec::Any => "any".to_string(),
                    PortSpec::Single(p) => p.to_string(),
                    _ => "any".to_string(),
                },
                if rule.direction == Direction::Bidirectional {
                    "<>"
                } else {
                    "->"
                },
                match &rule.dst_addr {
                    AddressSpec::Any => "any".to_string(),
                    AddressSpec::Single(ip) => ip.to_string(),
                    _ => "any".to_string(),
                },
                match rule.dst_port {
                    PortSpec::Any => "any".to_string(),
                    PortSpec::Single(p) => p.to_string(),
                    _ => "any".to_string(),
                },
                rule.options.msg.as_deref().unwrap_or("No message"),
            ));
        }

        output
    }
}

/// Packet data for inspection
#[derive(Debug, Clone)]
pub struct PacketData {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: RuleProtocol,
    pub payload: Vec<u8>,
}

fn main() {
    println!("=== IDS Engine Demo ===\n");

    // Create IDS engine
    let mut engine = IdsEngine::new(IdsConfig::default());

    // Load sample rules
    let rules = [
        r#"alert tcp any any -> any 80 (msg:"HTTP GET Request"; content:"GET "; sid:1000001; rev:1;)"#,
        r#"alert tcp any any -> any any (msg:"SQL Injection Attempt"; content:"UNION SELECT"; nocase; sid:1000002; rev:1; classtype:web-application-attack; priority:1;)"#,
        r#"alert tcp any any -> any 22 (msg:"SSH Connection"; content:"SSH-"; sid:1000003; rev:1;)"#,
        r#"drop tcp any any -> any any (msg:"Malware Signature EICAR"; content:"|58 35 4F 21 50 25|"; sid:1000004; rev:1; priority:1;)"#,
        r#"alert udp any any -> any 53 (msg:"DNS Query"; sid:1000005; rev:1;)"#,
    ];

    for rule in &rules {
        match engine.load_rule(rule) {
            Ok(sid) => println!("Loaded rule SID: {}", sid),
            Err(e) => println!("Failed to load rule: {}", e),
        }
    }

    println!(
        "\nTotal rules loaded: {}\n",
        engine.get_stats().rules_loaded
    );

    // Test packet inspection
    println!("Testing packet inspection:\n");

    // Normal HTTP request
    let http_packet = PacketData {
        src_ip: "192.168.1.100".parse().unwrap(),
        dst_ip: "93.184.216.34".parse().unwrap(),
        src_port: 54321,
        dst_port: 80,
        protocol: RuleProtocol::Tcp,
        payload: b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
    };

    let alerts = engine.inspect_packet(&http_packet);
    println!("1. HTTP GET request: {} alerts", alerts.len());
    for alert in &alerts {
        println!("   - [SID:{}] {}", alert.rule_sid, alert.message);
    }

    // SQL injection attempt
    let sqli_packet = PacketData {
        src_ip: "10.0.0.50".parse().unwrap(),
        dst_ip: "192.168.1.10".parse().unwrap(),
        src_port: 45678,
        dst_port: 80,
        protocol: RuleProtocol::Tcp,
        payload: b"GET /search?id=1' UNION SELECT * FROM users-- HTTP/1.1\r\n".to_vec(),
    };

    let alerts = engine.inspect_packet(&sqli_packet);
    println!("2. SQL injection: {} alerts", alerts.len());
    for alert in &alerts {
        println!(
            "   - [SID:{}] {} (Priority: {})",
            alert.rule_sid, alert.message, alert.priority
        );
    }

    // SSH connection
    let ssh_packet = PacketData {
        src_ip: "192.168.1.50".parse().unwrap(),
        dst_ip: "192.168.1.1".parse().unwrap(),
        src_port: 55555,
        dst_port: 22,
        protocol: RuleProtocol::Tcp,
        payload: b"SSH-2.0-OpenSSH_8.4p1\r\n".to_vec(),
    };

    let alerts = engine.inspect_packet(&ssh_packet);
    println!("3. SSH connection: {} alerts", alerts.len());

    // Malware signature (should be dropped)
    let malware_packet = PacketData {
        src_ip: "10.0.0.99".parse().unwrap(),
        dst_ip: "192.168.1.10".parse().unwrap(),
        src_port: 12345,
        dst_port: 443,
        protocol: RuleProtocol::Tcp,
        payload: b"X5O!P%@AP".to_vec(), // Start of EICAR
    };

    let alerts = engine.inspect_packet(&malware_packet);
    println!("4. Malware signature: {} alerts", alerts.len());
    for alert in &alerts {
        println!(
            "   - [SID:{}] {} (Action: {:?})",
            alert.rule_sid, alert.message, alert.action
        );
    }

    // Display statistics
    println!("\n=== IDS Statistics ===");
    let stats = engine.get_stats();
    println!("Packets inspected: {}", stats.packets_inspected);
    println!("Bytes inspected: {}", stats.bytes_inspected);
    println!("Rules matched: {}", stats.rules_matched);
    println!("Alerts generated: {}", stats.alerts_generated);
    println!("Packets dropped: {}", stats.packets_dropped);

    // Show recent alerts
    println!("\n=== Recent Alerts ===");
    for alert in engine.get_alerts(5) {
        println!(
            "[{}] SID:{} - {} ({}:{} -> {}:{})",
            alert.priority,
            alert.rule_sid,
            alert.message,
            alert.src_ip,
            alert.src_port,
            alert.dst_ip,
            alert.dst_port,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_parsing() {
        let engine = IdsEngine::new(IdsConfig::default());

        let rule_str =
            r#"alert tcp any any -> any 80 (msg:"Test rule"; content:"test"; sid:1; rev:1;)"#;
        let rule = engine.parse_rule(rule_str).unwrap();

        assert_eq!(rule.action, RuleAction::Alert);
        assert_eq!(rule.protocol, RuleProtocol::Tcp);
        assert!(matches!(rule.src_addr, AddressSpec::Any));
        assert!(matches!(rule.dst_port, PortSpec::Single(80)));
    }

    #[test]
    fn test_content_matching() {
        let mut engine = IdsEngine::new(IdsConfig::default());

        let rule_str =
            r#"alert tcp any any -> any any (msg:"Test"; content:"malware"; sid:1; rev:1;)"#;
        engine.load_rule(rule_str).unwrap();

        let packet = PacketData {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: RuleProtocol::Tcp,
            payload: b"This contains malware signature".to_vec(),
        };

        let alerts = engine.inspect_packet(&packet);
        assert!(!alerts.is_empty());
    }

    #[test]
    fn test_nocase_matching() {
        let mut engine = IdsEngine::new(IdsConfig::default());

        let rule_str =
            r#"alert tcp any any -> any any (msg:"Test"; content:"TEST"; nocase; sid:1; rev:1;)"#;
        engine.load_rule(rule_str).unwrap();

        let packet = PacketData {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: RuleProtocol::Tcp,
            payload: b"this is a test".to_vec(),
        };

        let alerts = engine.inspect_packet(&packet);
        assert!(!alerts.is_empty());
    }

    #[test]
    fn test_port_matching() {
        let engine = IdsEngine::new(IdsConfig::default());

        assert!(engine.port_matches(&PortSpec::Any, 80));
        assert!(engine.port_matches(&PortSpec::Single(80), 80));
        assert!(!engine.port_matches(&PortSpec::Single(80), 443));
        assert!(engine.port_matches(&PortSpec::Range(80, 443), 100));
        assert!(!engine.port_matches(&PortSpec::Range(80, 443), 8080));
    }

    #[test]
    fn test_address_matching() {
        let engine = IdsEngine::new(IdsConfig::default());

        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        assert!(engine.address_matches(&AddressSpec::Any, &ip));
        assert!(engine.address_matches(&AddressSpec::Cidr("192.168.1.0".parse().unwrap(), 24), &ip));
        assert!(!engine.address_matches(&AddressSpec::Cidr("10.0.0.0".parse().unwrap(), 8), &ip));
    }

    #[test]
    fn test_rule_enable_disable() {
        let mut engine = IdsEngine::new(IdsConfig::default());

        let rule_str = r#"alert tcp any any -> any any (msg:"Test"; sid:100; rev:1;)"#;
        engine.load_rule(rule_str).unwrap();

        assert!(engine.get_rule(100).unwrap().enabled);

        engine.set_rule_enabled(100, false);
        assert!(!engine.get_rule(100).unwrap().enabled);
    }

    #[test]
    fn test_suppression() {
        let mut engine = IdsEngine::new(IdsConfig::default());

        engine.add_suppression(Suppression {
            sid: 1,
            track: TrackBy::BySrc,
            ip: Some("192.168.1.100".parse().unwrap()),
        });

        let packet = PacketData {
            src_ip: "192.168.1.100".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: RuleProtocol::Tcp,
            payload: vec![],
        };

        assert!(engine.is_suppressed(1, &packet));
        assert!(!engine.is_suppressed(2, &packet));
    }
}
