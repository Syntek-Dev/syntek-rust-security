//! Intrusion Detection System (IDS) Engine
//!
//! Rust-based IDS engine with Snort/Suricata-compatible rule parsing,
//! pattern matching, alert generation, and network traffic analysis.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Protocol types for rule matching
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Ip,
    Any,
}

impl Protocol {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            "icmp" => Some(Protocol::Icmp),
            "ip" => Some(Protocol::Ip),
            "any" => Some(Protocol::Any),
            _ => None,
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::Ip => write!(f, "ip"),
            Protocol::Any => write!(f, "any"),
        }
    }
}

/// Rule action types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Alert,
    Log,
    Pass,
    Drop,
    Reject,
    SdropDrop,
}

impl RuleAction {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "alert" => Some(RuleAction::Alert),
            "log" => Some(RuleAction::Log),
            "pass" => Some(RuleAction::Pass),
            "drop" => Some(RuleAction::Drop),
            "reject" => Some(RuleAction::Reject),
            "sdrop" => Some(RuleAction::SdropDrop),
            _ => None,
        }
    }
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn from_priority(priority: u8) -> Self {
        match priority {
            1 => Severity::Critical,
            2 => Severity::High,
            3 => Severity::Medium,
            _ => Severity::Low,
        }
    }
}

/// Network address specification
#[derive(Debug, Clone)]
pub enum NetworkAddress {
    Any,
    Ip(IpAddr),
    Cidr(IpAddr, u8),
    Variable(String),
    Negated(Box<NetworkAddress>),
    List(Vec<NetworkAddress>),
}

impl NetworkAddress {
    pub fn matches(&self, addr: &IpAddr) -> bool {
        match self {
            NetworkAddress::Any => true,
            NetworkAddress::Ip(ip) => ip == addr,
            NetworkAddress::Cidr(network, prefix) => Self::cidr_matches(network, *prefix, addr),
            NetworkAddress::Variable(_) => true, // Would be resolved at runtime
            NetworkAddress::Negated(inner) => !inner.matches(addr),
            NetworkAddress::List(addrs) => addrs.iter().any(|a| a.matches(addr)),
        }
    }

    fn cidr_matches(network: &IpAddr, prefix: u8, addr: &IpAddr) -> bool {
        match (network, addr) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let net_bits = u32::from_be_bytes(net.octets());
                let ip_bits = u32::from_be_bytes(ip.octets());
                let mask = !0u32 << (32 - prefix);
                (net_bits & mask) == (ip_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let net_bits = u128::from_be_bytes(net.octets());
                let ip_bits = u128::from_be_bytes(ip.octets());
                let mask = !0u128 << (128 - prefix);
                (net_bits & mask) == (ip_bits & mask)
            }
            _ => false,
        }
    }
}

/// Port specification
#[derive(Debug, Clone)]
pub enum PortSpec {
    Any,
    Single(u16),
    Range(u16, u16),
    List(Vec<PortSpec>),
    Negated(Box<PortSpec>),
}

impl PortSpec {
    pub fn matches(&self, port: u16) -> bool {
        match self {
            PortSpec::Any => true,
            PortSpec::Single(p) => *p == port,
            PortSpec::Range(start, end) => port >= *start && port <= *end,
            PortSpec::List(ports) => ports.iter().any(|p| p.matches(port)),
            PortSpec::Negated(inner) => !inner.matches(port),
        }
    }
}

/// Direction of traffic flow
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ToServer,      // ->
    ToClient,      // <-
    Bidirectional, // <>
}

/// Content match options
#[derive(Debug, Clone)]
pub struct ContentMatch {
    pub pattern: Vec<u8>,
    pub nocase: bool,
    pub offset: Option<usize>,
    pub depth: Option<usize>,
    pub distance: Option<i32>,
    pub within: Option<usize>,
    pub fast_pattern: bool,
    pub negated: bool,
}

impl ContentMatch {
    pub fn new(pattern: Vec<u8>) -> Self {
        Self {
            pattern,
            nocase: false,
            offset: None,
            depth: None,
            distance: None,
            within: None,
            fast_pattern: false,
            negated: false,
        }
    }

    pub fn matches(&self, data: &[u8], last_match_end: Option<usize>) -> Option<usize> {
        let search_start = match (self.offset, self.distance, last_match_end) {
            (Some(offset), _, _) => offset,
            (_, Some(distance), Some(end)) => {
                if distance >= 0 {
                    end + distance as usize
                } else {
                    end.saturating_sub((-distance) as usize)
                }
            }
            _ => 0,
        };

        let search_end = match (self.depth, self.within, last_match_end) {
            (Some(depth), _, _) => Some(search_start + depth),
            (_, Some(within), _) => Some(search_start + within),
            _ => None,
        };

        let search_data = if let Some(end) = search_end {
            &data[search_start..end.min(data.len())]
        } else if search_start < data.len() {
            &data[search_start..]
        } else {
            return None;
        };

        let pattern = if self.nocase {
            self.pattern.to_ascii_lowercase()
        } else {
            self.pattern.clone()
        };

        let data_to_search = if self.nocase {
            search_data.to_ascii_lowercase()
        } else {
            search_data.to_vec()
        };

        // Simple pattern search
        for i in 0..=data_to_search.len().saturating_sub(pattern.len()) {
            if &data_to_search[i..i + pattern.len()] == pattern.as_slice() {
                let found = !self.negated;
                if found {
                    return Some(search_start + i + pattern.len());
                }
            }
        }

        if self.negated {
            Some(0)
        } else {
            None
        }
    }
}

/// PCRE (regex) match options
#[derive(Debug, Clone)]
pub struct PcreMatch {
    pub pattern: String,
    pub nocase: bool,
    pub multiline: bool,
    pub dotall: bool,
    pub relative: bool,
    pub negated: bool,
}

/// Byte test operation
#[derive(Debug, Clone)]
pub struct ByteTest {
    pub bytes: usize,
    pub operator: String,
    pub value: u64,
    pub offset: usize,
    pub relative: bool,
    pub big_endian: bool,
    pub string: bool,
    pub hex: bool,
    pub dec: bool,
    pub oct: bool,
}

/// Flow options
#[derive(Debug, Clone)]
pub struct FlowOptions {
    pub established: bool,
    pub not_established: bool,
    pub stateless: bool,
    pub to_client: bool,
    pub to_server: bool,
    pub from_client: bool,
    pub from_server: bool,
    pub no_stream: bool,
    pub only_stream: bool,
}

impl Default for FlowOptions {
    fn default() -> Self {
        Self {
            established: false,
            not_established: false,
            stateless: false,
            to_client: false,
            to_server: false,
            from_client: false,
            from_server: false,
            no_stream: false,
            only_stream: false,
        }
    }
}

/// Threshold configuration
#[derive(Debug, Clone)]
pub struct ThresholdConfig {
    pub threshold_type: ThresholdType,
    pub track_by: TrackBy,
    pub count: u32,
    pub seconds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdType {
    Limit,
    Threshold,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackBy {
    Source,
    Destination,
    Both,
}

/// Complete IDS rule
#[derive(Debug, Clone)]
pub struct IdsRule {
    pub id: u32,
    pub revision: u32,
    pub action: RuleAction,
    pub protocol: Protocol,
    pub src_addr: NetworkAddress,
    pub src_port: PortSpec,
    pub direction: Direction,
    pub dst_addr: NetworkAddress,
    pub dst_port: PortSpec,
    pub message: String,
    pub content_matches: Vec<ContentMatch>,
    pub pcre_matches: Vec<PcreMatch>,
    pub byte_tests: Vec<ByteTest>,
    pub flow: Option<FlowOptions>,
    pub threshold: Option<ThresholdConfig>,
    pub classtype: Option<String>,
    pub priority: u8,
    pub references: Vec<(String, String)>,
    pub metadata: HashMap<String, String>,
    pub enabled: bool,
}

impl IdsRule {
    pub fn new(id: u32, action: RuleAction, protocol: Protocol) -> Self {
        Self {
            id,
            revision: 1,
            action,
            protocol,
            src_addr: NetworkAddress::Any,
            src_port: PortSpec::Any,
            direction: Direction::ToServer,
            dst_addr: NetworkAddress::Any,
            dst_port: PortSpec::Any,
            message: String::new(),
            content_matches: vec![],
            pcre_matches: vec![],
            byte_tests: vec![],
            flow: None,
            threshold: None,
            classtype: None,
            priority: 3,
            references: vec![],
            metadata: HashMap::new(),
            enabled: true,
        }
    }

    pub fn severity(&self) -> Severity {
        Severity::from_priority(self.priority)
    }
}

/// Packet data for analysis
#[derive(Debug, Clone)]
pub struct Packet {
    pub timestamp: SystemTime,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub payload: Vec<u8>,
    pub tcp_flags: Option<u8>,
    pub packet_len: usize,
    pub flow_id: u64,
}

impl Packet {
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
        payload: Vec<u8>,
    ) -> Self {
        let packet_len = payload.len();
        Self {
            timestamp: SystemTime::now(),
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            payload,
            tcp_flags: None,
            packet_len,
            flow_id: Self::compute_flow_id(&src_ip, &dst_ip, src_port, dst_port, protocol),
        }
    }

    fn compute_flow_id(
        src_ip: &IpAddr,
        dst_ip: &IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
    ) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        // Use sorted IPs for bidirectional flow tracking
        if src_ip < dst_ip {
            src_ip.hash(&mut hasher);
            dst_ip.hash(&mut hasher);
            src_port.hash(&mut hasher);
            dst_port.hash(&mut hasher);
        } else {
            dst_ip.hash(&mut hasher);
            src_ip.hash(&mut hasher);
            dst_port.hash(&mut hasher);
            src_port.hash(&mut hasher);
        }
        (protocol as u8).hash(&mut hasher);
        hasher.finish()
    }
}

/// Alert generated by the IDS
#[derive(Debug, Clone)]
pub struct Alert {
    pub id: u64,
    pub timestamp: SystemTime,
    pub rule_id: u32,
    pub rule_revision: u32,
    pub message: String,
    pub severity: Severity,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub action_taken: RuleAction,
    pub classtype: Option<String>,
    pub references: Vec<(String, String)>,
    pub payload_excerpt: Vec<u8>,
}

impl Alert {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"id":{},"timestamp":"{}","rule_id":{},"message":"{}","severity":"{}","src":"{}:{}","dst":"{}:{}","protocol":"{}","action":"{:?}"}}"#,
            self.id,
            self.timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            self.rule_id,
            self.message,
            match self.severity {
                Severity::Low => "low",
                Severity::Medium => "medium",
                Severity::High => "high",
                Severity::Critical => "critical",
            },
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.protocol,
            self.action_taken,
        )
    }
}

/// Flow tracking state
#[derive(Debug)]
pub struct FlowState {
    pub flow_id: u64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub state: ConnectionState,
    pub packets_to_server: u64,
    pub packets_to_client: u64,
    pub bytes_to_server: u64,
    pub bytes_to_client: u64,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    New,
    Established,
    Closing,
    Closed,
    Timeout,
}

/// Threshold tracking
#[derive(Debug)]
struct ThresholdTracker {
    counts: HashMap<(u32, String), VecDeque<Instant>>, // (rule_id, track_key) -> timestamps
}

impl ThresholdTracker {
    fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    fn should_alert(&mut self, rule_id: u32, track_key: &str, config: &ThresholdConfig) -> bool {
        let key = (rule_id, track_key.to_string());
        let now = Instant::now();
        let window = Duration::from_secs(config.seconds as u64);

        let timestamps = self.counts.entry(key).or_insert_with(VecDeque::new);

        // Remove old timestamps
        while let Some(front) = timestamps.front() {
            if now.duration_since(*front) > window {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        timestamps.push_back(now);
        let count = timestamps.len() as u32;

        match config.threshold_type {
            ThresholdType::Limit => count <= config.count,
            ThresholdType::Threshold => {
                count >= config.count && (count - config.count) % config.count == 0
            }
            ThresholdType::Both => count >= config.count && count <= config.count,
        }
    }
}

/// Statistics for the IDS engine
#[derive(Debug, Default, Clone)]
pub struct IdsStats {
    pub packets_processed: u64,
    pub bytes_processed: u64,
    pub alerts_generated: u64,
    pub packets_dropped: u64,
    pub rules_matched: u64,
    pub flows_tracked: u64,
    pub start_time: Option<Instant>,
}

impl IdsStats {
    pub fn packets_per_second(&self) -> f64 {
        if let Some(start) = self.start_time {
            let elapsed = start.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                return self.packets_processed as f64 / elapsed;
            }
        }
        0.0
    }
}

/// Main IDS Engine
pub struct IdsEngine {
    rules: Vec<IdsRule>,
    rules_by_protocol: HashMap<Protocol, Vec<usize>>,
    flows: Arc<RwLock<HashMap<u64, FlowState>>>,
    threshold_tracker: Arc<RwLock<ThresholdTracker>>,
    alert_counter: Arc<RwLock<u64>>,
    stats: Arc<RwLock<IdsStats>>,
    config: IdsConfig,
}

/// IDS configuration
#[derive(Debug, Clone)]
pub struct IdsConfig {
    pub home_net: Vec<NetworkAddress>,
    pub external_net: Vec<NetworkAddress>,
    pub flow_timeout: Duration,
    pub max_flows: usize,
    pub payload_excerpt_size: usize,
    pub alert_log_path: Option<String>,
    pub drop_on_match: bool,
}

impl Default for IdsConfig {
    fn default() -> Self {
        Self {
            home_net: vec![NetworkAddress::Any],
            external_net: vec![NetworkAddress::Any],
            flow_timeout: Duration::from_secs(3600),
            max_flows: 100_000,
            payload_excerpt_size: 256,
            alert_log_path: None,
            drop_on_match: false,
        }
    }
}

impl IdsEngine {
    pub fn new(config: IdsConfig) -> Self {
        let mut stats = IdsStats::default();
        stats.start_time = Some(Instant::now());

        Self {
            rules: vec![],
            rules_by_protocol: HashMap::new(),
            flows: Arc::new(RwLock::new(HashMap::new())),
            threshold_tracker: Arc::new(RwLock::new(ThresholdTracker::new())),
            alert_counter: Arc::new(RwLock::new(0)),
            stats: Arc::new(RwLock::new(stats)),
            config,
        }
    }

    /// Add a rule to the engine
    pub fn add_rule(&mut self, rule: IdsRule) {
        let rule_idx = self.rules.len();
        let protocol = rule.protocol;

        self.rules.push(rule);

        // Index by protocol
        self.rules_by_protocol
            .entry(protocol)
            .or_insert_with(Vec::new)
            .push(rule_idx);

        // Also add to "any" protocol index
        if protocol != Protocol::Any {
            self.rules_by_protocol
                .entry(Protocol::Any)
                .or_insert_with(Vec::new)
                .push(rule_idx);
        }
    }

    /// Load rules from Snort/Suricata format
    pub fn load_rules(&mut self, rules_text: &str) -> Result<usize, String> {
        let mut loaded = 0;

        for line in rules_text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(rule) = self.parse_rule(line) {
                self.add_rule(rule);
                loaded += 1;
            }
        }

        Ok(loaded)
    }

    /// Parse a single rule line
    fn parse_rule(&self, line: &str) -> Option<IdsRule> {
        // Simplified rule parser - real implementation would be more robust
        let parts: Vec<&str> = line.splitn(2, '(').collect();
        if parts.len() != 2 {
            return None;
        }

        let header = parts[0].trim();
        let options = parts[1].trim_end_matches(')');

        let header_parts: Vec<&str> = header.split_whitespace().collect();
        if header_parts.len() < 7 {
            return None;
        }

        let action = RuleAction::from_str(header_parts[0])?;
        let protocol = Protocol::from_str(header_parts[1])?;

        let mut rule = IdsRule::new(0, action, protocol);

        // Parse options
        for opt in options.split(';') {
            let opt = opt.trim();
            if opt.is_empty() {
                continue;
            }

            if let Some(colon_idx) = opt.find(':') {
                let key = opt[..colon_idx].trim();
                let value = opt[colon_idx + 1..].trim();

                match key {
                    "sid" => {
                        rule.id = value.parse().unwrap_or(0);
                    }
                    "rev" => {
                        rule.revision = value.parse().unwrap_or(1);
                    }
                    "msg" => {
                        rule.message = value.trim_matches('"').to_string();
                    }
                    "content" => {
                        let pattern = value.trim_matches('"');
                        let bytes = Self::parse_content_pattern(pattern);
                        rule.content_matches.push(ContentMatch::new(bytes));
                    }
                    "classtype" => {
                        rule.classtype = Some(value.to_string());
                    }
                    "priority" => {
                        rule.priority = value.parse().unwrap_or(3);
                    }
                    "reference" => {
                        if let Some(comma_idx) = value.find(',') {
                            let ref_type = value[..comma_idx].trim();
                            let ref_value = value[comma_idx + 1..].trim();
                            rule.references
                                .push((ref_type.to_string(), ref_value.to_string()));
                        }
                    }
                    _ => {}
                }
            }
        }

        if rule.id > 0 {
            Some(rule)
        } else {
            None
        }
    }

    fn parse_content_pattern(pattern: &str) -> Vec<u8> {
        let mut result = vec![];
        let mut chars = pattern.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '|' {
                // Hex content
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
                // Parse hex pairs
                let mut hex_iter = hex_str.chars();
                while let (Some(h1), Some(h2)) = (hex_iter.next(), hex_iter.next()) {
                    if let Ok(byte) = u8::from_str_radix(&format!("{}{}", h1, h2), 16) {
                        result.push(byte);
                    }
                }
            } else {
                result.push(c as u8);
            }
        }

        result
    }

    /// Process a packet and return any alerts
    pub fn process_packet(&self, packet: &Packet) -> Vec<Alert> {
        let mut alerts = vec![];

        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.packets_processed += 1;
            stats.bytes_processed += packet.packet_len as u64;
        }

        // Update flow tracking
        self.update_flow(packet);

        // Get applicable rules
        let rule_indices = self.get_applicable_rules(packet.protocol);

        for &idx in &rule_indices {
            let rule = &self.rules[idx];

            if !rule.enabled {
                continue;
            }

            if self.matches_rule(rule, packet) {
                // Check threshold
                let should_alert = if let Some(threshold) = &rule.threshold {
                    let track_key = match threshold.track_by {
                        TrackBy::Source => packet.src_ip.to_string(),
                        TrackBy::Destination => packet.dst_ip.to_string(),
                        TrackBy::Both => format!("{}:{}", packet.src_ip, packet.dst_ip),
                    };

                    self.threshold_tracker
                        .write()
                        .unwrap()
                        .should_alert(rule.id, &track_key, threshold)
                } else {
                    true
                };

                if should_alert {
                    let alert = self.generate_alert(rule, packet);
                    alerts.push(alert);

                    {
                        let mut stats = self.stats.write().unwrap();
                        stats.alerts_generated += 1;
                        stats.rules_matched += 1;
                    }
                }
            }
        }

        alerts
    }

    fn get_applicable_rules(&self, protocol: Protocol) -> Vec<usize> {
        let mut indices = vec![];

        if let Some(protocol_rules) = self.rules_by_protocol.get(&protocol) {
            indices.extend(protocol_rules.iter());
        }

        if protocol != Protocol::Any {
            if let Some(any_rules) = self.rules_by_protocol.get(&Protocol::Any) {
                indices.extend(any_rules.iter());
            }
        }

        // Deduplicate
        let set: HashSet<_> = indices.into_iter().collect();
        set.into_iter().collect()
    }

    fn matches_rule(&self, rule: &IdsRule, packet: &Packet) -> bool {
        // Check protocol
        if rule.protocol != Protocol::Any && rule.protocol != packet.protocol {
            return false;
        }

        // Check source address
        if !rule.src_addr.matches(&packet.src_ip) {
            return false;
        }

        // Check source port
        if !rule.src_port.matches(packet.src_port) {
            return false;
        }

        // Check destination address
        if !rule.dst_addr.matches(&packet.dst_ip) {
            return false;
        }

        // Check destination port
        if !rule.dst_port.matches(packet.dst_port) {
            return false;
        }

        // Check content matches
        let mut last_match_end = None;
        for content in &rule.content_matches {
            match content.matches(&packet.payload, last_match_end) {
                Some(end) => last_match_end = Some(end),
                None => return false,
            }
        }

        // Check flow options if specified
        if let Some(flow_opts) = &rule.flow {
            let flow = self.get_flow(packet.flow_id);
            if let Some(flow) = flow {
                if flow_opts.established && flow.state != ConnectionState::Established {
                    return false;
                }
                if flow_opts.not_established && flow.state == ConnectionState::Established {
                    return false;
                }
            }
        }

        true
    }

    fn update_flow(&self, packet: &Packet) {
        let mut flows = self.flows.write().unwrap();

        if let Some(flow) = flows.get_mut(&packet.flow_id) {
            flow.last_seen = Instant::now();

            if packet.src_ip == flow.src_ip {
                flow.packets_to_server += 1;
                flow.bytes_to_server += packet.packet_len as u64;
            } else {
                flow.packets_to_client += 1;
                flow.bytes_to_client += packet.packet_len as u64;
            }

            // Update state based on TCP flags
            if let Some(flags) = packet.tcp_flags {
                flow.state = Self::update_tcp_state(flow.state, flags);
            }
        } else {
            // New flow
            if flows.len() >= self.config.max_flows {
                // Evict oldest flow
                let oldest = flows
                    .iter()
                    .min_by_key(|(_, f)| f.last_seen)
                    .map(|(k, _)| *k);
                if let Some(key) = oldest {
                    flows.remove(&key);
                }
            }

            flows.insert(
                packet.flow_id,
                FlowState {
                    flow_id: packet.flow_id,
                    src_ip: packet.src_ip,
                    dst_ip: packet.dst_ip,
                    src_port: packet.src_port,
                    dst_port: packet.dst_port,
                    protocol: packet.protocol,
                    state: ConnectionState::New,
                    packets_to_server: 1,
                    packets_to_client: 0,
                    bytes_to_server: packet.packet_len as u64,
                    bytes_to_client: 0,
                    first_seen: Instant::now(),
                    last_seen: Instant::now(),
                },
            );

            let mut stats = self.stats.write().unwrap();
            stats.flows_tracked += 1;
        }
    }

    fn get_flow(&self, flow_id: u64) -> Option<FlowState> {
        self.flows.read().unwrap().get(&flow_id).cloned()
    }

    fn update_tcp_state(current: ConnectionState, flags: u8) -> ConnectionState {
        const SYN: u8 = 0x02;
        const FIN: u8 = 0x01;
        const RST: u8 = 0x04;
        const ACK: u8 = 0x10;

        match (current, flags & (SYN | FIN | RST | ACK)) {
            (ConnectionState::New, f) if f & SYN != 0 => ConnectionState::New,
            (ConnectionState::New, f) if f & ACK != 0 => ConnectionState::Established,
            (ConnectionState::Established, f) if f & FIN != 0 => ConnectionState::Closing,
            (_, f) if f & RST != 0 => ConnectionState::Closed,
            (ConnectionState::Closing, f) if f & ACK != 0 => ConnectionState::Closed,
            (state, _) => state,
        }
    }

    fn generate_alert(&self, rule: &IdsRule, packet: &Packet) -> Alert {
        let alert_id = {
            let mut counter = self.alert_counter.write().unwrap();
            *counter += 1;
            *counter
        };

        let excerpt_len = self.config.payload_excerpt_size.min(packet.payload.len());
        let payload_excerpt = packet.payload[..excerpt_len].to_vec();

        Alert {
            id: alert_id,
            timestamp: packet.timestamp,
            rule_id: rule.id,
            rule_revision: rule.revision,
            message: rule.message.clone(),
            severity: rule.severity(),
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            protocol: packet.protocol,
            action_taken: rule.action,
            classtype: rule.classtype.clone(),
            references: rule.references.clone(),
            payload_excerpt,
        }
    }

    /// Get current statistics
    pub fn stats(&self) -> IdsStats {
        self.stats.read().unwrap().clone()
    }

    /// Get number of loaded rules
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get rules by classtype
    pub fn rules_by_classtype(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for rule in &self.rules {
            let classtype = rule.classtype.clone().unwrap_or_else(|| "unknown".into());
            *counts.entry(classtype).or_insert(0) += 1;
        }
        counts
    }
}

fn main() {
    println!("Intrusion Detection System (IDS) Engine\n");

    // Create IDS engine
    let config = IdsConfig::default();
    let mut engine = IdsEngine::new(config);

    // Add some example rules
    let rules_text = r#"
# Example Snort-compatible rules
alert tcp any any -> any 80 (msg:"HTTP GET Request"; content:"GET "; sid:1000001; rev:1; classtype:web-application-activity; priority:3;)
alert tcp any any -> any 80 (msg:"SQL Injection Attempt"; content:"UNION SELECT"; nocase; sid:1000002; rev:1; classtype:web-application-attack; priority:1;)
alert tcp any any -> any 22 (msg:"SSH Connection"; content:"SSH-"; sid:1000003; rev:1; classtype:misc-activity; priority:4;)
alert icmp any any -> any any (msg:"ICMP Ping"; sid:1000004; rev:1; classtype:misc-activity; priority:4;)
alert tcp any any -> any 3306 (msg:"MySQL Connection"; content:"|0a|"; sid:1000005; rev:1; classtype:protocol-command-decode; priority:3;)
"#;

    match engine.load_rules(rules_text) {
        Ok(count) => println!("Loaded {} rules", count),
        Err(e) => println!("Error loading rules: {}", e),
    }

    // Simulate some packets
    let packets = vec![
        Packet::new(
            "192.168.1.100".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            54321,
            80,
            Protocol::Tcp,
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        ),
        Packet::new(
            "192.168.1.100".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            54322,
            80,
            Protocol::Tcp,
            b"GET /search?q=' UNION SELECT * FROM users-- HTTP/1.1\r\n".to_vec(),
        ),
        Packet::new(
            "192.168.1.100".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            54323,
            22,
            Protocol::Tcp,
            b"SSH-2.0-OpenSSH_8.9\r\n".to_vec(),
        ),
    ];

    println!("\nProcessing {} packets...\n", packets.len());

    for packet in &packets {
        let alerts = engine.process_packet(packet);

        for alert in alerts {
            println!(
                "ALERT [{}]: {} (Rule {})",
                match alert.severity {
                    Severity::Critical => "CRITICAL",
                    Severity::High => "HIGH",
                    Severity::Medium => "MEDIUM",
                    Severity::Low => "LOW",
                },
                alert.message,
                alert.rule_id
            );
            println!("  Source: {}:{}", alert.src_ip, alert.src_port);
            println!("  Dest:   {}:{}", alert.dst_ip, alert.dst_port);
            println!("  JSON:   {}\n", alert.to_json());
        }
    }

    // Print statistics
    let stats = engine.stats();
    println!("\n=== IDS Statistics ===");
    println!("Packets processed: {}", stats.packets_processed);
    println!("Bytes processed: {}", stats.bytes_processed);
    println!("Alerts generated: {}", stats.alerts_generated);
    println!("Rules matched: {}", stats.rules_matched);
    println!("Flows tracked: {}", stats.flows_tracked);
    println!("Packets/second: {:.2}", stats.packets_per_second());

    println!("\nRules by classtype:");
    for (classtype, count) in engine.rules_by_classtype() {
        println!("  {}: {}", classtype, count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_from_str() {
        assert_eq!(Protocol::from_str("tcp"), Some(Protocol::Tcp));
        assert_eq!(Protocol::from_str("UDP"), Some(Protocol::Udp));
        assert_eq!(Protocol::from_str("any"), Some(Protocol::Any));
        assert_eq!(Protocol::from_str("invalid"), None);
    }

    #[test]
    fn test_severity_from_priority() {
        assert_eq!(Severity::from_priority(1), Severity::Critical);
        assert_eq!(Severity::from_priority(2), Severity::High);
        assert_eq!(Severity::from_priority(3), Severity::Medium);
        assert_eq!(Severity::from_priority(4), Severity::Low);
    }

    #[test]
    fn test_network_address_matches() {
        let addr = NetworkAddress::Any;
        assert!(addr.matches(&"192.168.1.1".parse().unwrap()));

        let addr = NetworkAddress::Ip("192.168.1.1".parse().unwrap());
        assert!(addr.matches(&"192.168.1.1".parse().unwrap()));
        assert!(!addr.matches(&"192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn test_port_spec_matches() {
        assert!(PortSpec::Any.matches(80));
        assert!(PortSpec::Single(80).matches(80));
        assert!(!PortSpec::Single(80).matches(443));
        assert!(PortSpec::Range(1, 1024).matches(80));
        assert!(!PortSpec::Range(1, 1024).matches(8080));
    }

    #[test]
    fn test_content_match() {
        let content = ContentMatch::new(b"GET ".to_vec());
        let data = b"GET /index.html HTTP/1.1";
        assert!(content.matches(data, None).is_some());

        let data = b"POST /api HTTP/1.1";
        assert!(content.matches(data, None).is_none());
    }

    #[test]
    fn test_content_match_nocase() {
        let mut content = ContentMatch::new(b"select".to_vec());
        content.nocase = true;

        let data = b"UNION SELECT * FROM users";
        assert!(content.matches(data, None).is_some());
    }

    #[test]
    fn test_ids_rule_creation() {
        let rule = IdsRule::new(1001, RuleAction::Alert, Protocol::Tcp);
        assert_eq!(rule.id, 1001);
        assert_eq!(rule.action, RuleAction::Alert);
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert!(rule.enabled);
    }

    #[test]
    fn test_packet_creation() {
        let packet = Packet::new(
            "192.168.1.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            12345,
            80,
            Protocol::Tcp,
            b"test payload".to_vec(),
        );

        assert_eq!(packet.src_port, 12345);
        assert_eq!(packet.dst_port, 80);
        assert_eq!(packet.protocol, Protocol::Tcp);
    }

    #[test]
    fn test_ids_engine_creation() {
        let config = IdsConfig::default();
        let engine = IdsEngine::new(config);
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn test_add_rule() {
        let mut engine = IdsEngine::new(IdsConfig::default());
        let rule = IdsRule::new(1001, RuleAction::Alert, Protocol::Tcp);
        engine.add_rule(rule);
        assert_eq!(engine.rule_count(), 1);
    }

    #[test]
    fn test_load_rules() {
        let mut engine = IdsEngine::new(IdsConfig::default());
        let rules = r#"
alert tcp any any -> any 80 (msg:"Test Rule"; sid:1001; rev:1;)
"#;
        let count = engine.load_rules(rules).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_process_packet_with_match() {
        let mut engine = IdsEngine::new(IdsConfig::default());

        let mut rule = IdsRule::new(1001, RuleAction::Alert, Protocol::Tcp);
        rule.dst_port = PortSpec::Single(80);
        rule.content_matches
            .push(ContentMatch::new(b"GET ".to_vec()));
        rule.message = "HTTP GET".into();
        engine.add_rule(rule);

        let packet = Packet::new(
            "192.168.1.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            12345,
            80,
            Protocol::Tcp,
            b"GET /index.html".to_vec(),
        );

        let alerts = engine.process_packet(&packet);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, 1001);
    }

    #[test]
    fn test_alert_to_json() {
        let alert = Alert {
            id: 1,
            timestamp: SystemTime::UNIX_EPOCH,
            rule_id: 1001,
            rule_revision: 1,
            message: "Test Alert".into(),
            severity: Severity::High,
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: Protocol::Tcp,
            action_taken: RuleAction::Alert,
            classtype: None,
            references: vec![],
            payload_excerpt: vec![],
        };

        let json = alert.to_json();
        assert!(json.contains("Test Alert"));
        assert!(json.contains("1001"));
    }

    #[test]
    fn test_stats() {
        let engine = IdsEngine::new(IdsConfig::default());
        let stats = engine.stats();
        assert_eq!(stats.packets_processed, 0);
        assert_eq!(stats.alerts_generated, 0);
    }
}
