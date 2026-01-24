//! Snort/Suricata Compatible Rules Engine
//!
//! This example demonstrates a Rust implementation of an IDS/IPS
//! rules engine compatible with Snort and Suricata rule formats,
//! including pattern matching, protocol analysis, and alert generation.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// Rule Types
// ============================================================================

/// IDS rule action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Generate alert only
    Alert,
    /// Log packet
    Log,
    /// Block/drop packet
    Drop,
    /// Reject with RST/ICMP
    Reject,
    /// Pass without further inspection
    Pass,
}

impl RuleAction {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "alert" => Some(RuleAction::Alert),
            "log" => Some(RuleAction::Log),
            "drop" => Some(RuleAction::Drop),
            "reject" => Some(RuleAction::Reject),
            "pass" => Some(RuleAction::Pass),
            _ => None,
        }
    }
}

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleAction::Alert => write!(f, "alert"),
            RuleAction::Log => write!(f, "log"),
            RuleAction::Drop => write!(f, "drop"),
            RuleAction::Reject => write!(f, "reject"),
            RuleAction::Pass => write!(f, "pass"),
        }
    }
}

/// Protocol specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Ip,
    Http,
    Dns,
    Tls,
    Ssh,
    Ftp,
    Smtp,
}

impl Protocol {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            "icmp" => Some(Protocol::Icmp),
            "ip" => Some(Protocol::Ip),
            "http" => Some(Protocol::Http),
            "dns" => Some(Protocol::Dns),
            "tls" | "ssl" => Some(Protocol::Tls),
            "ssh" => Some(Protocol::Ssh),
            "ftp" => Some(Protocol::Ftp),
            "smtp" => Some(Protocol::Smtp),
            _ => None,
        }
    }
}

/// Network address specification
#[derive(Debug, Clone)]
pub enum NetworkAddress {
    Any,
    Single(IpAddr),
    Cidr(IpAddr, u8),
    List(Vec<NetworkAddress>),
    Variable(String),
    Negated(Box<NetworkAddress>),
}

impl NetworkAddress {
    pub fn matches(&self, addr: IpAddr) -> bool {
        match self {
            NetworkAddress::Any => true,
            NetworkAddress::Single(a) => *a == addr,
            NetworkAddress::Cidr(network, prefix) => Self::cidr_match(*network, *prefix, addr),
            NetworkAddress::List(addrs) => addrs.iter().any(|a| a.matches(addr)),
            NetworkAddress::Variable(_) => true, // Would be resolved at runtime
            NetworkAddress::Negated(inner) => !inner.matches(addr),
        }
    }

    fn cidr_match(network: IpAddr, prefix: u8, addr: IpAddr) -> bool {
        match (network, addr) {
            (IpAddr::V4(net), IpAddr::V4(a)) => {
                let net_bits = u32::from(net);
                let addr_bits = u32::from(a);
                let mask = if prefix >= 32 {
                    u32::MAX
                } else {
                    u32::MAX << (32 - prefix)
                };
                (net_bits & mask) == (addr_bits & mask)
            }
            _ => false, // Simplified - would handle IPv6
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

/// Direction of traffic
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Source to destination only
    Unidirectional,
    /// Both directions
    Bidirectional,
}

// ============================================================================
// Rule Options
// ============================================================================

/// Content matching option
#[derive(Debug, Clone)]
pub struct ContentMatch {
    /// Pattern to match
    pub pattern: Vec<u8>,
    /// Is this a negated match
    pub negated: bool,
    /// Case insensitive
    pub nocase: bool,
    /// Offset from start
    pub offset: Option<usize>,
    /// Search depth
    pub depth: Option<usize>,
    /// Distance from previous match
    pub distance: Option<isize>,
    /// Within N bytes of previous match
    pub within: Option<usize>,
    /// Match in specific buffer
    pub buffer: ContentBuffer,
    /// Fast pattern (for prefiltering)
    pub fast_pattern: bool,
}

impl ContentMatch {
    pub fn new(pattern: &[u8]) -> Self {
        Self {
            pattern: pattern.to_vec(),
            negated: false,
            nocase: false,
            offset: None,
            depth: None,
            distance: None,
            within: None,
            buffer: ContentBuffer::Payload,
            fast_pattern: false,
        }
    }

    pub fn negated(mut self) -> Self {
        self.negated = true;
        self
    }

    pub fn nocase(mut self) -> Self {
        self.nocase = true;
        self
    }

    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    pub fn depth(mut self, depth: usize) -> Self {
        self.depth = Some(depth);
        self
    }

    pub fn in_buffer(mut self, buffer: ContentBuffer) -> Self {
        self.buffer = buffer;
        self
    }

    pub fn fast_pattern(mut self) -> Self {
        self.fast_pattern = true;
        self
    }
}

/// Content buffer types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentBuffer {
    Payload,
    HttpUri,
    HttpHeader,
    HttpCookie,
    HttpMethod,
    HttpUserAgent,
    HttpHost,
    HttpBody,
    DnsQuery,
    TlsSni,
    FileData,
}

/// PCRE (regex) matching option
#[derive(Debug, Clone)]
pub struct PcreMatch {
    pub pattern: String,
    pub modifiers: Vec<PcreModifier>,
    pub negated: bool,
}

/// PCRE modifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcreModifier {
    CaseInsensitive, // i
    Multiline,       // m
    DotAll,          // s
    Extended,        // x
    Anchored,        // A
    Ungreedy,        // U
    Relative,        // R
    RawBytes,        // B
}

/// Byte test option
#[derive(Debug, Clone)]
pub struct ByteTest {
    pub bytes: usize,
    pub operator: ByteOperator,
    pub value: u64,
    pub offset: isize,
    pub relative: bool,
    pub endian: Endian,
    pub string: bool,
    pub base: NumericBase,
}

/// Byte operators
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOperator {
    Equal,
    NotEqual,
    LessThan,
    GreaterThan,
    LessEqual,
    GreaterEqual,
    BitwiseAnd,
    BitwiseOr,
}

/// Endianness
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Big,
    Little,
}

/// Numeric base
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericBase {
    Decimal,
    Hexadecimal,
    Octal,
}

/// Flow options
#[derive(Debug, Clone)]
pub struct FlowOptions {
    pub to_client: bool,
    pub to_server: bool,
    pub established: bool,
    pub stateless: bool,
    pub no_stream: bool,
    pub only_stream: bool,
}

impl Default for FlowOptions {
    fn default() -> Self {
        Self {
            to_client: false,
            to_server: false,
            established: false,
            stateless: false,
            no_stream: false,
            only_stream: false,
        }
    }
}

/// Threshold/rate limiting
#[derive(Debug, Clone)]
pub struct Threshold {
    pub threshold_type: ThresholdType,
    pub track: TrackBy,
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

// ============================================================================
// IDS Rule
// ============================================================================

/// Complete IDS rule
#[derive(Debug, Clone)]
pub struct IdsRule {
    /// Rule ID (sid)
    pub sid: u32,
    /// Revision number
    pub rev: u32,
    /// Rule action
    pub action: RuleAction,
    /// Protocol
    pub protocol: Protocol,
    /// Source address
    pub src_addr: NetworkAddress,
    /// Source port
    pub src_port: PortSpec,
    /// Direction
    pub direction: Direction,
    /// Destination address
    pub dst_addr: NetworkAddress,
    /// Destination port
    pub dst_port: PortSpec,
    /// Alert message
    pub msg: String,
    /// Content matches
    pub content: Vec<ContentMatch>,
    /// PCRE matches
    pub pcre: Vec<PcreMatch>,
    /// Byte tests
    pub byte_tests: Vec<ByteTest>,
    /// Flow options
    pub flow: Option<FlowOptions>,
    /// Threshold
    pub threshold: Option<Threshold>,
    /// Classification
    pub classtype: Option<String>,
    /// Priority (1-4, 1 highest)
    pub priority: u8,
    /// Reference URLs/CVEs
    pub references: Vec<(String, String)>,
    /// Metadata
    pub metadata: HashMap<String, String>,
    /// Enabled status
    pub enabled: bool,
}

impl IdsRule {
    pub fn builder() -> IdsRuleBuilder {
        IdsRuleBuilder::new()
    }

    /// Convert to Snort rule format
    pub fn to_snort(&self) -> String {
        let mut rule = format!(
            "{} {} {} {} {} {} {} (",
            self.action,
            format!("{:?}", self.protocol).to_lowercase(),
            self.format_address(&self.src_addr),
            self.format_port(&self.src_port),
            if self.direction == Direction::Bidirectional {
                "<>"
            } else {
                "->"
            },
            self.format_address(&self.dst_addr),
            self.format_port(&self.dst_port),
        );

        let mut options = vec![format!("msg:\"{}\";", self.msg)];

        // Content options
        for content in &self.content {
            let mut opt = if content
                .pattern
                .iter()
                .all(|b| b.is_ascii_graphic() && *b != b'"')
            {
                format!("content:\"{}\";", String::from_utf8_lossy(&content.pattern))
            } else {
                let hex: String = content
                    .pattern
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("content:|{}|;", hex)
            };

            if content.nocase {
                opt.push_str(" nocase;");
            }
            if let Some(offset) = content.offset {
                opt.push_str(&format!(" offset:{};", offset));
            }
            if let Some(depth) = content.depth {
                opt.push_str(&format!(" depth:{};", depth));
            }
            if content.fast_pattern {
                opt.push_str(" fast_pattern;");
            }

            options.push(opt);
        }

        // PCRE options
        for pcre in &self.pcre {
            options.push(format!("pcre:\"{}\";", pcre.pattern));
        }

        // Flow options
        if let Some(flow) = &self.flow {
            let mut flow_parts = vec![];
            if flow.established {
                flow_parts.push("established");
            }
            if flow.to_client {
                flow_parts.push("to_client");
            }
            if flow.to_server {
                flow_parts.push("to_server");
            }
            if !flow_parts.is_empty() {
                options.push(format!("flow:{};", flow_parts.join(",")));
            }
        }

        // Threshold
        if let Some(thresh) = &self.threshold {
            let type_str = match thresh.threshold_type {
                ThresholdType::Limit => "limit",
                ThresholdType::Threshold => "threshold",
                ThresholdType::Both => "both",
            };
            let track_str = match thresh.track {
                TrackBy::Source => "by_src",
                TrackBy::Destination => "by_dst",
                TrackBy::Both => "by_both",
            };
            options.push(format!(
                "threshold:type {}, track {}, count {}, seconds {};",
                type_str, track_str, thresh.count, thresh.seconds
            ));
        }

        // Classification
        if let Some(classtype) = &self.classtype {
            options.push(format!("classtype:{};", classtype));
        }

        // Priority
        options.push(format!("priority:{};", self.priority));

        // References
        for (ref_type, ref_value) in &self.references {
            options.push(format!("reference:{},{};", ref_type, ref_value));
        }

        // SID and REV
        options.push(format!("sid:{};", self.sid));
        options.push(format!("rev:{};", self.rev));

        rule.push_str(&options.join(" "));
        rule.push(')');

        rule
    }

    fn format_address(&self, addr: &NetworkAddress) -> String {
        match addr {
            NetworkAddress::Any => "any".to_string(),
            NetworkAddress::Single(ip) => ip.to_string(),
            NetworkAddress::Cidr(ip, prefix) => format!("{}/{}", ip, prefix),
            NetworkAddress::Variable(name) => format!("${}", name),
            NetworkAddress::List(addrs) => {
                let formatted: Vec<String> = addrs.iter().map(|a| self.format_address(a)).collect();
                format!("[{}]", formatted.join(","))
            }
            NetworkAddress::Negated(inner) => format!("!{}", self.format_address(inner)),
        }
    }

    fn format_port(&self, port: &PortSpec) -> String {
        match port {
            PortSpec::Any => "any".to_string(),
            PortSpec::Single(p) => p.to_string(),
            PortSpec::Range(start, end) => format!("{}:{}", start, end),
            PortSpec::List(ports) => {
                let formatted: Vec<String> = ports.iter().map(|p| self.format_port(p)).collect();
                format!("[{}]", formatted.join(","))
            }
            PortSpec::Negated(inner) => format!("!{}", self.format_port(inner)),
        }
    }
}

/// IDS rule builder
pub struct IdsRuleBuilder {
    rule: IdsRule,
}

impl IdsRuleBuilder {
    pub fn new() -> Self {
        Self {
            rule: IdsRule {
                sid: 0,
                rev: 1,
                action: RuleAction::Alert,
                protocol: Protocol::Tcp,
                src_addr: NetworkAddress::Any,
                src_port: PortSpec::Any,
                direction: Direction::Unidirectional,
                dst_addr: NetworkAddress::Any,
                dst_port: PortSpec::Any,
                msg: String::new(),
                content: Vec::new(),
                pcre: Vec::new(),
                byte_tests: Vec::new(),
                flow: None,
                threshold: None,
                classtype: None,
                priority: 3,
                references: Vec::new(),
                metadata: HashMap::new(),
                enabled: true,
            },
        }
    }

    pub fn sid(mut self, sid: u32) -> Self {
        self.rule.sid = sid;
        self
    }

    pub fn rev(mut self, rev: u32) -> Self {
        self.rule.rev = rev;
        self
    }

    pub fn action(mut self, action: RuleAction) -> Self {
        self.rule.action = action;
        self
    }

    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.rule.protocol = protocol;
        self
    }

    pub fn src(mut self, addr: NetworkAddress, port: PortSpec) -> Self {
        self.rule.src_addr = addr;
        self.rule.src_port = port;
        self
    }

    pub fn dst(mut self, addr: NetworkAddress, port: PortSpec) -> Self {
        self.rule.dst_addr = addr;
        self.rule.dst_port = port;
        self
    }

    pub fn bidirectional(mut self) -> Self {
        self.rule.direction = Direction::Bidirectional;
        self
    }

    pub fn msg(mut self, msg: &str) -> Self {
        self.rule.msg = msg.to_string();
        self
    }

    pub fn content(mut self, content: ContentMatch) -> Self {
        self.rule.content.push(content);
        self
    }

    pub fn pcre(mut self, pattern: &str, modifiers: Vec<PcreModifier>) -> Self {
        self.rule.pcre.push(PcreMatch {
            pattern: pattern.to_string(),
            modifiers,
            negated: false,
        });
        self
    }

    pub fn flow(mut self, flow: FlowOptions) -> Self {
        self.rule.flow = Some(flow);
        self
    }

    pub fn threshold(mut self, threshold: Threshold) -> Self {
        self.rule.threshold = Some(threshold);
        self
    }

    pub fn classtype(mut self, classtype: &str) -> Self {
        self.rule.classtype = Some(classtype.to_string());
        self
    }

    pub fn priority(mut self, priority: u8) -> Self {
        self.rule.priority = priority;
        self
    }

    pub fn reference(mut self, ref_type: &str, ref_value: &str) -> Self {
        self.rule
            .references
            .push((ref_type.to_string(), ref_value.to_string()));
        self
    }

    pub fn metadata(mut self, key: &str, value: &str) -> Self {
        self.rule
            .metadata
            .insert(key.to_string(), value.to_string());
        self
    }

    pub fn build(self) -> IdsRule {
        self.rule
    }
}

impl Default for IdsRuleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Rule Engine
// ============================================================================

/// Packet data for matching
#[derive(Debug, Clone)]
pub struct Packet {
    pub timestamp: SystemTime,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub payload: Vec<u8>,
    pub http_uri: Option<String>,
    pub http_headers: HashMap<String, String>,
    pub dns_query: Option<String>,
    pub tls_sni: Option<String>,
    pub flow_id: u64,
    pub is_to_server: bool,
}

impl Packet {
    pub fn new() -> Self {
        Self {
            timestamp: SystemTime::now(),
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            protocol: Protocol::Tcp,
            payload: Vec::new(),
            http_uri: None,
            http_headers: HashMap::new(),
            dns_query: None,
            tls_sni: None,
            flow_id: 0,
            is_to_server: true,
        }
    }
}

impl Default for Packet {
    fn default() -> Self {
        Self::new()
    }
}

/// Alert generated by rule match
#[derive(Debug, Clone)]
pub struct Alert {
    pub timestamp: SystemTime,
    pub rule_sid: u32,
    pub rule_rev: u32,
    pub action: RuleAction,
    pub message: String,
    pub classification: Option<String>,
    pub priority: u8,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub matched_content: Vec<String>,
}

/// Flow tracking for stateful inspection
#[derive(Debug)]
pub struct FlowState {
    pub flow_id: u64,
    pub established: bool,
    pub packets_to_server: u32,
    pub packets_to_client: u32,
    pub bytes_to_server: u64,
    pub bytes_to_client: u64,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

/// Threshold state for rate limiting
#[derive(Debug)]
struct ThresholdState {
    count: u32,
    window_start: Instant,
}

/// IDS rules engine
pub struct RulesEngine {
    rules: Vec<IdsRule>,
    /// Flow states
    flows: HashMap<u64, FlowState>,
    /// Threshold states per rule/address
    thresholds: HashMap<(u32, IpAddr), ThresholdState>,
    /// Statistics
    stats: EngineStats,
}

/// Engine statistics
#[derive(Debug, Default)]
pub struct EngineStats {
    pub packets_processed: u64,
    pub rules_checked: u64,
    pub alerts_generated: u64,
    pub packets_dropped: u64,
    pub processing_time_us: u64,
}

impl RulesEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            flows: HashMap::new(),
            thresholds: HashMap::new(),
            stats: EngineStats::default(),
        }
    }

    /// Add a rule
    pub fn add_rule(&mut self, rule: IdsRule) {
        self.rules.push(rule);
    }

    /// Load rules from Snort format
    pub fn load_rules(&mut self, rules_text: &str) -> Result<usize, RuleParseError> {
        let mut loaded = 0;

        for line in rules_text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(rule) = self.parse_rule(line)? {
                self.rules.push(rule);
                loaded += 1;
            }
        }

        Ok(loaded)
    }

    fn parse_rule(&self, line: &str) -> Result<Option<IdsRule>, RuleParseError> {
        // Simplified parser - real implementation would be more robust
        let parts: Vec<&str> = line.splitn(8, ' ').collect();
        if parts.len() < 7 {
            return Err(RuleParseError::InvalidFormat);
        }

        let action = RuleAction::from_str(parts[0]).ok_or(RuleParseError::InvalidAction)?;

        let protocol = Protocol::from_str(parts[1]).ok_or(RuleParseError::InvalidProtocol)?;

        // Parse options
        let options_start = line.find('(');
        let options_end = line.rfind(')');

        let mut rule = IdsRule::builder().action(action).protocol(protocol);

        if let (Some(start), Some(end)) = (options_start, options_end) {
            let options = &line[start + 1..end];
            rule = self.parse_options(rule, options)?;
        }

        Ok(Some(rule.build()))
    }

    fn parse_options(
        &self,
        mut builder: IdsRuleBuilder,
        options: &str,
    ) -> Result<IdsRuleBuilder, RuleParseError> {
        for opt in options.split(';') {
            let opt = opt.trim();
            if opt.is_empty() {
                continue;
            }

            let (key, value) = if let Some(colon_pos) = opt.find(':') {
                (&opt[..colon_pos], Some(opt[colon_pos + 1..].trim()))
            } else {
                (opt, None)
            };

            builder = match key {
                "msg" => {
                    let msg = value.unwrap_or("").trim_matches('"');
                    builder.msg(msg)
                }
                "sid" => {
                    let sid: u32 = value
                        .unwrap_or("0")
                        .parse()
                        .map_err(|_| RuleParseError::InvalidSid)?;
                    builder.sid(sid)
                }
                "rev" => {
                    let rev: u32 = value.unwrap_or("1").parse().unwrap_or(1);
                    builder.rev(rev)
                }
                "priority" => {
                    let priority: u8 = value.unwrap_or("3").parse().unwrap_or(3);
                    builder.priority(priority)
                }
                "classtype" => builder.classtype(value.unwrap_or("")),
                "content" => {
                    let content_str = value.unwrap_or("");
                    let pattern = content_str.trim_matches('"').as_bytes().to_vec();
                    builder.content(ContentMatch::new(&pattern))
                }
                _ => builder,
            };
        }

        Ok(builder)
    }

    /// Process a packet through all rules
    pub fn process_packet(&mut self, packet: &Packet) -> Vec<Alert> {
        let start = Instant::now();
        let mut alerts = Vec::new();

        self.stats.packets_processed += 1;

        // Update flow state
        self.update_flow(packet);

        // Check each enabled rule
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            self.stats.rules_checked += 1;

            if self.matches_rule(rule, packet) {
                // Check threshold
                if self.check_threshold(rule, packet) {
                    if let Some(alert) = self.generate_alert(rule, packet) {
                        alerts.push(alert);
                        self.stats.alerts_generated += 1;

                        if rule.action == RuleAction::Drop || rule.action == RuleAction::Reject {
                            self.stats.packets_dropped += 1;
                        }
                    }
                }
            }
        }

        self.stats.processing_time_us += start.elapsed().as_micros() as u64;

        alerts
    }

    fn update_flow(&mut self, packet: &Packet) {
        let flow = self
            .flows
            .entry(packet.flow_id)
            .or_insert_with(|| FlowState {
                flow_id: packet.flow_id,
                established: false,
                packets_to_server: 0,
                packets_to_client: 0,
                bytes_to_server: 0,
                bytes_to_client: 0,
                first_seen: Instant::now(),
                last_seen: Instant::now(),
            });

        flow.last_seen = Instant::now();

        if packet.is_to_server {
            flow.packets_to_server += 1;
            flow.bytes_to_server += packet.payload.len() as u64;
        } else {
            flow.packets_to_client += 1;
            flow.bytes_to_client += packet.payload.len() as u64;
        }

        // Simple established detection (would be more sophisticated in practice)
        if flow.packets_to_server > 0 && flow.packets_to_client > 0 {
            flow.established = true;
        }
    }

    fn matches_rule(&self, rule: &IdsRule, packet: &Packet) -> bool {
        // Check address/port
        if !rule.src_addr.matches(packet.src_ip) {
            return false;
        }
        if !rule.dst_addr.matches(packet.dst_ip) {
            return false;
        }
        if !rule.src_port.matches(packet.src_port) {
            return false;
        }
        if !rule.dst_port.matches(packet.dst_port) {
            return false;
        }

        // Check flow options
        if let Some(flow_opts) = &rule.flow {
            if let Some(flow_state) = self.flows.get(&packet.flow_id) {
                if flow_opts.established && !flow_state.established {
                    return false;
                }
            }
            if flow_opts.to_server && !packet.is_to_server {
                return false;
            }
            if flow_opts.to_client && packet.is_to_server {
                return false;
            }
        }

        // Check content matches
        for content in &rule.content {
            if !self.matches_content(content, packet) {
                return content.negated; // Negated match inverts result
            }
        }

        true
    }

    fn matches_content(&self, content: &ContentMatch, packet: &Packet) -> bool {
        let data = match content.buffer {
            ContentBuffer::Payload => &packet.payload,
            ContentBuffer::HttpUri => {
                return packet
                    .http_uri
                    .as_ref()
                    .map(|u| self.pattern_match(&content.pattern, u.as_bytes(), content))
                    .unwrap_or(false);
            }
            ContentBuffer::DnsQuery => {
                return packet
                    .dns_query
                    .as_ref()
                    .map(|q| self.pattern_match(&content.pattern, q.as_bytes(), content))
                    .unwrap_or(false);
            }
            ContentBuffer::TlsSni => {
                return packet
                    .tls_sni
                    .as_ref()
                    .map(|s| self.pattern_match(&content.pattern, s.as_bytes(), content))
                    .unwrap_or(false);
            }
            _ => &packet.payload,
        };

        self.pattern_match(&content.pattern, data, content)
    }

    fn pattern_match(&self, pattern: &[u8], data: &[u8], opts: &ContentMatch) -> bool {
        let start = opts.offset.unwrap_or(0);
        let end = opts.depth.map(|d| start + d).unwrap_or(data.len());

        if start >= data.len() || end > data.len() {
            return false;
        }

        let search_data = &data[start..end];

        if opts.nocase {
            // Case-insensitive search
            let pattern_lower: Vec<u8> = pattern.iter().map(|b| b.to_ascii_lowercase()).collect();
            let data_lower: Vec<u8> = search_data.iter().map(|b| b.to_ascii_lowercase()).collect();

            self.find_pattern(&pattern_lower, &data_lower)
        } else {
            self.find_pattern(pattern, search_data)
        }
    }

    fn find_pattern(&self, pattern: &[u8], data: &[u8]) -> bool {
        if pattern.is_empty() || data.len() < pattern.len() {
            return pattern.is_empty();
        }

        // Simple search - could use Boyer-Moore, Aho-Corasick, etc.
        for i in 0..=(data.len() - pattern.len()) {
            if &data[i..i + pattern.len()] == pattern {
                return true;
            }
        }

        false
    }

    fn check_threshold(&mut self, rule: &IdsRule, packet: &Packet) -> bool {
        let threshold = match &rule.threshold {
            Some(t) => t,
            None => return true,
        };

        let track_addr = match threshold.track {
            TrackBy::Source => packet.src_ip,
            TrackBy::Destination => packet.dst_ip,
            TrackBy::Both => packet.src_ip, // Simplified
        };

        let key = (rule.sid, track_addr);
        let now = Instant::now();
        let window = Duration::from_secs(threshold.seconds as u64);

        let state = self
            .thresholds
            .entry(key)
            .or_insert_with(|| ThresholdState {
                count: 0,
                window_start: now,
            });

        // Reset window if expired
        if now.duration_since(state.window_start) > window {
            state.count = 0;
            state.window_start = now;
        }

        state.count += 1;

        match threshold.threshold_type {
            ThresholdType::Limit => state.count <= threshold.count,
            ThresholdType::Threshold => state.count == threshold.count,
            ThresholdType::Both => state.count <= threshold.count && state.count >= 1,
        }
    }

    fn generate_alert(&self, rule: &IdsRule, packet: &Packet) -> Option<Alert> {
        Some(Alert {
            timestamp: packet.timestamp,
            rule_sid: rule.sid,
            rule_rev: rule.rev,
            action: rule.action,
            message: rule.msg.clone(),
            classification: rule.classtype.clone(),
            priority: rule.priority,
            src_ip: packet.src_ip,
            src_port: packet.src_port,
            dst_ip: packet.dst_ip,
            dst_port: packet.dst_port,
            protocol: rule.protocol,
            matched_content: rule
                .content
                .iter()
                .map(|c| String::from_utf8_lossy(&c.pattern).to_string())
                .collect(),
        })
    }

    /// Get statistics
    pub fn stats(&self) -> &EngineStats {
        &self.stats
    }

    /// Get all loaded rules
    pub fn rules(&self) -> &[IdsRule] {
        &self.rules
    }

    /// Clean up old flow states
    pub fn cleanup_flows(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.flows
            .retain(|_, flow| now.duration_since(flow.last_seen) < max_age);
    }
}

impl Default for RulesEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Rule parsing error
#[derive(Debug)]
pub enum RuleParseError {
    InvalidFormat,
    InvalidAction,
    InvalidProtocol,
    InvalidSid,
    InvalidOption(String),
}

impl fmt::Display for RuleParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleParseError::InvalidFormat => write!(f, "Invalid rule format"),
            RuleParseError::InvalidAction => write!(f, "Invalid action"),
            RuleParseError::InvalidProtocol => write!(f, "Invalid protocol"),
            RuleParseError::InvalidSid => write!(f, "Invalid SID"),
            RuleParseError::InvalidOption(opt) => write!(f, "Invalid option: {}", opt),
        }
    }
}

impl std::error::Error for RuleParseError {}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== Snort/Suricata Compatible Rules Engine ===\n");

    // Example 1: Create a rule programmatically
    println!("1. Creating IDS Rule:");
    let sql_injection_rule = IdsRule::builder()
        .sid(1000001)
        .rev(1)
        .action(RuleAction::Alert)
        .protocol(Protocol::Http)
        .src(NetworkAddress::Any, PortSpec::Any)
        .dst(NetworkAddress::Any, PortSpec::Single(80))
        .msg("SQL Injection Attempt")
        .content(ContentMatch::new(b"UNION SELECT").nocase())
        .content(ContentMatch::new(b"--").offset(0))
        .flow(FlowOptions {
            to_server: true,
            established: true,
            ..Default::default()
        })
        .classtype("web-application-attack")
        .priority(1)
        .reference("cve", "2023-12345")
        .build();

    println!("   Rule SID: {}", sql_injection_rule.sid);
    println!("   Message: {}", sql_injection_rule.msg);
    println!("   Snort format:\n   {}", sql_injection_rule.to_snort());

    // Example 2: XSS detection rule
    println!("\n2. XSS Detection Rule:");
    let xss_rule = IdsRule::builder()
        .sid(1000002)
        .action(RuleAction::Drop)
        .protocol(Protocol::Http)
        .src(NetworkAddress::Any, PortSpec::Any)
        .dst(NetworkAddress::Any, PortSpec::Range(80, 443))
        .msg("XSS Attack Detected")
        .content(ContentMatch::new(b"<script>").nocase().fast_pattern())
        .content(ContentMatch::new(b"</script>").nocase())
        .threshold(Threshold {
            threshold_type: ThresholdType::Limit,
            track: TrackBy::Source,
            count: 5,
            seconds: 60,
        })
        .classtype("web-application-attack")
        .priority(1)
        .build();

    println!("   {}", xss_rule.to_snort());

    // Example 3: Initialize engine and add rules
    println!("\n3. Rules Engine:");
    let mut engine = RulesEngine::new();
    engine.add_rule(sql_injection_rule);
    engine.add_rule(xss_rule);

    // Add malware rule
    engine.add_rule(
        IdsRule::builder()
            .sid(1000003)
            .action(RuleAction::Alert)
            .protocol(Protocol::Tcp)
            .msg("Potential Malware C2 Beacon")
            .content(ContentMatch::new(b"\x00\x00\x00\x01"))
            .content(ContentMatch::new(b"BEACON"))
            .priority(2)
            .build(),
    );

    println!("   Loaded {} rules", engine.rules().len());

    // Example 4: Process a packet
    println!("\n4. Processing Packets:");

    let mut malicious_packet = Packet::new();
    malicious_packet.src_ip = "10.0.0.50".parse().unwrap();
    malicious_packet.dst_ip = "192.168.1.100".parse().unwrap();
    malicious_packet.src_port = 54321;
    malicious_packet.dst_port = 80;
    malicious_packet.payload = b"GET /search?q=1' UNION SELECT * FROM users-- HTTP/1.1".to_vec();
    malicious_packet.is_to_server = true;

    let alerts = engine.process_packet(&malicious_packet);
    for alert in &alerts {
        println!(
            "   ALERT: {} [SID:{}] Priority:{}",
            alert.message, alert.rule_sid, alert.priority
        );
        println!(
            "      From: {}:{} -> {}:{}",
            alert.src_ip, alert.src_port, alert.dst_ip, alert.dst_port
        );
    }

    // Example 5: Clean packet
    println!("\n5. Clean Packet:");
    let mut clean_packet = Packet::new();
    clean_packet.payload = b"GET /index.html HTTP/1.1".to_vec();
    clean_packet.dst_port = 80;
    clean_packet.is_to_server = true;

    let alerts = engine.process_packet(&clean_packet);
    println!("   Alerts generated: {}", alerts.len());

    // Example 6: Load rules from text
    println!("\n6. Loading Rules from Text:");
    let rule_text = r#"
# Example Snort rules
alert tcp any any -> any 22 (msg:"SSH Connection"; sid:1000010; rev:1;)
alert tcp any any -> any 3306 (msg:"MySQL Connection"; sid:1000011; rev:1; priority:2;)
drop tcp any any -> any any (msg:"Known Malware Port"; content:"MALWARE"; sid:1000012; rev:1; priority:1;)
"#;

    let loaded = engine.load_rules(rule_text).unwrap();
    println!("   Loaded {} additional rules", loaded);
    println!("   Total rules: {}", engine.rules().len());

    // Example 7: Engine statistics
    println!("\n7. Engine Statistics:");
    let stats = engine.stats();
    println!("   Packets processed: {}", stats.packets_processed);
    println!("   Rules checked: {}", stats.rules_checked);
    println!("   Alerts generated: {}", stats.alerts_generated);
    println!("   Processing time: {}µs", stats.processing_time_us);

    // Example 8: DNS tunneling detection
    println!("\n8. DNS Tunneling Rule:");
    let dns_rule = IdsRule::builder()
        .sid(1000020)
        .action(RuleAction::Alert)
        .protocol(Protocol::Dns)
        .msg("Potential DNS Tunneling")
        .content(ContentMatch::new(b"").in_buffer(ContentBuffer::DnsQuery))
        .threshold(Threshold {
            threshold_type: ThresholdType::Threshold,
            track: TrackBy::Source,
            count: 100,
            seconds: 60,
        })
        .classtype("attempted-recon")
        .priority(2)
        .build();
    println!("   {}", dns_rule.to_snort());

    println!("\n=== Rules Engine Complete ===");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_action_from_str() {
        assert_eq!(RuleAction::from_str("alert"), Some(RuleAction::Alert));
        assert_eq!(RuleAction::from_str("DROP"), Some(RuleAction::Drop));
        assert_eq!(RuleAction::from_str("invalid"), None);
    }

    #[test]
    fn test_protocol_from_str() {
        assert_eq!(Protocol::from_str("tcp"), Some(Protocol::Tcp));
        assert_eq!(Protocol::from_str("HTTP"), Some(Protocol::Http));
    }

    #[test]
    fn test_network_address_any() {
        let addr = NetworkAddress::Any;
        assert!(addr.matches("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_network_address_single() {
        let addr = NetworkAddress::Single("192.168.1.1".parse().unwrap());
        assert!(addr.matches("192.168.1.1".parse().unwrap()));
        assert!(!addr.matches("192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn test_network_address_cidr() {
        let addr = NetworkAddress::Cidr("10.0.0.0".parse().unwrap(), 8);
        assert!(addr.matches("10.1.2.3".parse().unwrap()));
        assert!(!addr.matches("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_port_spec_any() {
        let port = PortSpec::Any;
        assert!(port.matches(80));
        assert!(port.matches(443));
    }

    #[test]
    fn test_port_spec_range() {
        let port = PortSpec::Range(80, 443);
        assert!(port.matches(80));
        assert!(port.matches(200));
        assert!(port.matches(443));
        assert!(!port.matches(79));
        assert!(!port.matches(444));
    }

    #[test]
    fn test_content_match_creation() {
        let content = ContentMatch::new(b"test").nocase().offset(10).depth(100);

        assert!(content.nocase);
        assert_eq!(content.offset, Some(10));
        assert_eq!(content.depth, Some(100));
    }

    #[test]
    fn test_rule_builder() {
        let rule = IdsRule::builder()
            .sid(123)
            .rev(2)
            .action(RuleAction::Drop)
            .msg("Test rule")
            .priority(1)
            .build();

        assert_eq!(rule.sid, 123);
        assert_eq!(rule.rev, 2);
        assert_eq!(rule.action, RuleAction::Drop);
        assert_eq!(rule.msg, "Test rule");
        assert_eq!(rule.priority, 1);
    }

    #[test]
    fn test_rule_to_snort() {
        let rule = IdsRule::builder()
            .sid(1000)
            .action(RuleAction::Alert)
            .protocol(Protocol::Tcp)
            .msg("Test Alert")
            .build();

        let snort = rule.to_snort();
        assert!(snort.contains("alert tcp"));
        assert!(snort.contains("msg:\"Test Alert\""));
        assert!(snort.contains("sid:1000"));
    }

    #[test]
    fn test_engine_add_rule() {
        let mut engine = RulesEngine::new();
        engine.add_rule(IdsRule::builder().sid(1).build());
        engine.add_rule(IdsRule::builder().sid(2).build());

        assert_eq!(engine.rules().len(), 2);
    }

    #[test]
    fn test_engine_process_matching_packet() {
        let mut engine = RulesEngine::new();
        engine.add_rule(
            IdsRule::builder()
                .sid(1)
                .msg("Test Match")
                .content(ContentMatch::new(b"MALWARE"))
                .build(),
        );

        let mut packet = Packet::new();
        packet.payload = b"This contains MALWARE signature".to_vec();

        let alerts = engine.process_packet(&packet);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].message, "Test Match");
    }

    #[test]
    fn test_engine_no_match() {
        let mut engine = RulesEngine::new();
        engine.add_rule(
            IdsRule::builder()
                .sid(1)
                .content(ContentMatch::new(b"SPECIFIC"))
                .build(),
        );

        let mut packet = Packet::new();
        packet.payload = b"Clean packet data".to_vec();

        let alerts = engine.process_packet(&packet);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_case_insensitive_match() {
        let mut engine = RulesEngine::new();
        engine.add_rule(
            IdsRule::builder()
                .sid(1)
                .content(ContentMatch::new(b"SELECT").nocase())
                .build(),
        );

        let mut packet = Packet::new();
        packet.payload = b"select * from users".to_vec();

        let alerts = engine.process_packet(&packet);
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn test_port_matching() {
        let mut engine = RulesEngine::new();
        engine.add_rule(
            IdsRule::builder()
                .sid(1)
                .dst(NetworkAddress::Any, PortSpec::Single(80))
                .content(ContentMatch::new(b"HTTP"))
                .build(),
        );

        let mut packet = Packet::new();
        packet.dst_port = 80;
        packet.payload = b"HTTP/1.1".to_vec();

        let alerts = engine.process_packet(&packet);
        assert_eq!(alerts.len(), 1);

        // Wrong port
        packet.dst_port = 443;
        let alerts = engine.process_packet(&packet);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_threshold_limit() {
        let mut engine = RulesEngine::new();
        engine.add_rule(
            IdsRule::builder()
                .sid(1)
                .threshold(Threshold {
                    threshold_type: ThresholdType::Limit,
                    track: TrackBy::Source,
                    count: 2,
                    seconds: 60,
                })
                .build(),
        );

        let packet = Packet::new();

        // First two should generate alerts
        let alerts = engine.process_packet(&packet);
        assert_eq!(alerts.len(), 1);

        let alerts = engine.process_packet(&packet);
        assert_eq!(alerts.len(), 1);

        // Third should be suppressed
        let alerts = engine.process_packet(&packet);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_flow_options() {
        let mut engine = RulesEngine::new();
        engine.add_rule(
            IdsRule::builder()
                .sid(1)
                .flow(FlowOptions {
                    to_server: true,
                    ..Default::default()
                })
                .build(),
        );

        let mut packet = Packet::new();
        packet.is_to_server = true;

        let alerts = engine.process_packet(&packet);
        assert_eq!(alerts.len(), 1);

        packet.is_to_server = false;
        let alerts = engine.process_packet(&packet);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_statistics() {
        let mut engine = RulesEngine::new();
        engine.add_rule(IdsRule::builder().sid(1).build());

        let packet = Packet::new();
        engine.process_packet(&packet);
        engine.process_packet(&packet);

        let stats = engine.stats();
        assert_eq!(stats.packets_processed, 2);
        assert_eq!(stats.rules_checked, 2);
    }

    #[test]
    fn test_flow_cleanup() {
        let mut engine = RulesEngine::new();
        let packet = Packet::new();
        engine.process_packet(&packet);

        assert_eq!(engine.flows.len(), 1);

        engine.cleanup_flows(Duration::from_secs(0));
        assert_eq!(engine.flows.len(), 0);
    }
}
