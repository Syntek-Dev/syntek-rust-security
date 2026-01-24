# Rust Intrusion Detection Skills

This skill provides patterns for building IDS/IPS systems in Rust with
Snort/Suricata-compatible rule processing, alert handling, and response
mechanisms.

## Overview

Intrusion detection encompasses:

- **Rule Engine**: Parse and match Snort/Suricata rules
- **Signature Matching**: Content and pattern detection
- **Protocol Analysis**: State-aware inspection
- **Alert Management**: Classification and prioritization
- **Response Actions**: Block, log, or rate-limit

## /ids-setup

Initialize an intrusion detection system.

### Usage

```bash
/ids-setup
```

### What It Does

1. Creates rule engine infrastructure
2. Implements Snort-compatible rule parsing
3. Sets up alert management
4. Configures response actions
5. Implements logging

---

## Snort Rule Parser

### Rule Types

```rust
#[derive(Debug, Clone)]
pub struct SnortRule {
    pub action: RuleAction,
    pub protocol: Protocol,
    pub src_network: NetworkSpec,
    pub src_port: PortSpec,
    pub direction: Direction,
    pub dst_network: NetworkSpec,
    pub dst_port: PortSpec,
    pub options: Vec<RuleOption>,
}

#[derive(Debug, Clone, Copy)]
pub enum RuleAction {
    Alert,
    Log,
    Pass,
    Drop,
    Reject,
    Sdrop,
}

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Ip,
    Http,
    Dns,
    Tls,
}

#[derive(Debug, Clone)]
pub enum NetworkSpec {
    Any,
    Ip(std::net::IpAddr),
    Cidr(ipnet::IpNet),
    Variable(String),
    Not(Box<NetworkSpec>),
    List(Vec<NetworkSpec>),
}

#[derive(Debug, Clone)]
pub enum PortSpec {
    Any,
    Single(u16),
    Range(u16, u16),
    Not(Box<PortSpec>),
    List(Vec<PortSpec>),
}

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Unidirectional,  // ->
    Bidirectional,   // <>
}

#[derive(Debug, Clone)]
pub enum RuleOption {
    // Metadata
    Msg(String),
    Sid(u32),
    Rev(u32),
    Classtype(String),
    Priority(u8),
    Metadata(Vec<(String, String)>),
    Reference(String, String),

    // Content matching
    Content(ContentMatch),
    Pcre(String),
    ByteTest(ByteTest),
    ByteJump(ByteJump),

    // Payload detection
    Dsize(Comparison, usize),
    Isdataat(usize, bool),  // bool = relative

    // Flow options
    Flow(FlowOptions),
    Flowbits(FlowbitOp, String),

    // Protocol-specific
    HttpUri,
    HttpHeader,
    HttpMethod,
    HttpCookie,
    HttpClientBody,

    // Thresholds
    Threshold(ThresholdSpec),
    Detection(DetectionFilter),
}

#[derive(Debug, Clone)]
pub struct ContentMatch {
    pub pattern: Vec<u8>,
    pub negated: bool,
    pub nocase: bool,
    pub offset: Option<usize>,
    pub depth: Option<usize>,
    pub distance: Option<i32>,
    pub within: Option<usize>,
    pub fast_pattern: bool,
}

#[derive(Debug, Clone)]
pub struct ByteTest {
    pub bytes: usize,
    pub operator: Comparison,
    pub value: u64,
    pub offset: usize,
    pub relative: bool,
    pub endian: Endian,
}

#[derive(Debug, Clone, Copy)]
pub enum Comparison {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}

#[derive(Debug, Clone)]
pub struct FlowOptions {
    pub to_client: bool,
    pub to_server: bool,
    pub from_client: bool,
    pub from_server: bool,
    pub established: bool,
    pub stateless: bool,
}

#[derive(Debug, Clone)]
pub struct ThresholdSpec {
    pub threshold_type: ThresholdType,
    pub track: TrackBy,
    pub count: u32,
    pub seconds: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum ThresholdType {
    Limit,
    Threshold,
    Both,
}

#[derive(Debug, Clone, Copy)]
pub enum TrackBy {
    BySrc,
    ByDst,
}
```

### Rule Parser

```rust
pub struct RuleParser;

impl RuleParser {
    pub fn parse(rule_text: &str) -> Result<SnortRule, ParseError> {
        let rule_text = rule_text.trim();

        // Skip comments and empty lines
        if rule_text.is_empty() || rule_text.starts_with('#') {
            return Err(ParseError::EmptyOrComment);
        }

        // Split into header and options
        let (header, options) = Self::split_rule(rule_text)?;

        // Parse header
        let parts: Vec<&str> = header.split_whitespace().collect();
        if parts.len() < 7 {
            return Err(ParseError::InvalidHeader);
        }

        let action = Self::parse_action(parts[0])?;
        let protocol = Self::parse_protocol(parts[1])?;
        let src_network = Self::parse_network(parts[2])?;
        let src_port = Self::parse_port(parts[3])?;
        let direction = Self::parse_direction(parts[4])?;
        let dst_network = Self::parse_network(parts[5])?;
        let dst_port = Self::parse_port(parts[6])?;

        // Parse options
        let options = Self::parse_options(&options)?;

        Ok(SnortRule {
            action,
            protocol,
            src_network,
            src_port,
            direction,
            dst_network,
            dst_port,
            options,
        })
    }

    fn split_rule(rule: &str) -> Result<(String, String), ParseError> {
        let paren_start = rule.find('(')
            .ok_or(ParseError::MissingOptions)?;
        let paren_end = rule.rfind(')')
            .ok_or(ParseError::UnclosedOptions)?;

        let header = rule[..paren_start].trim().to_string();
        let options = rule[paren_start + 1..paren_end].to_string();

        Ok((header, options))
    }

    fn parse_action(s: &str) -> Result<RuleAction, ParseError> {
        match s.to_lowercase().as_str() {
            "alert" => Ok(RuleAction::Alert),
            "log" => Ok(RuleAction::Log),
            "pass" => Ok(RuleAction::Pass),
            "drop" => Ok(RuleAction::Drop),
            "reject" => Ok(RuleAction::Reject),
            "sdrop" => Ok(RuleAction::Sdrop),
            _ => Err(ParseError::InvalidAction(s.to_string())),
        }
    }

    fn parse_protocol(s: &str) -> Result<Protocol, ParseError> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            "icmp" => Ok(Protocol::Icmp),
            "ip" => Ok(Protocol::Ip),
            "http" => Ok(Protocol::Http),
            "dns" => Ok(Protocol::Dns),
            "tls" => Ok(Protocol::Tls),
            _ => Err(ParseError::InvalidProtocol(s.to_string())),
        }
    }

    fn parse_network(s: &str) -> Result<NetworkSpec, ParseError> {
        if s == "any" {
            return Ok(NetworkSpec::Any);
        }

        if s.starts_with('$') {
            return Ok(NetworkSpec::Variable(s[1..].to_string()));
        }

        if s.starts_with('!') {
            let inner = Self::parse_network(&s[1..])?;
            return Ok(NetworkSpec::Not(Box::new(inner)));
        }

        if s.starts_with('[') && s.ends_with(']') {
            let inner = &s[1..s.len() - 1];
            let parts: Result<Vec<_>, _> = inner.split(',')
                .map(|p| Self::parse_network(p.trim()))
                .collect();
            return Ok(NetworkSpec::List(parts?));
        }

        if s.contains('/') {
            let net: ipnet::IpNet = s.parse()
                .map_err(|_| ParseError::InvalidNetwork(s.to_string()))?;
            return Ok(NetworkSpec::Cidr(net));
        }

        let ip: std::net::IpAddr = s.parse()
            .map_err(|_| ParseError::InvalidNetwork(s.to_string()))?;
        Ok(NetworkSpec::Ip(ip))
    }

    fn parse_port(s: &str) -> Result<PortSpec, ParseError> {
        if s == "any" {
            return Ok(PortSpec::Any);
        }

        if s.starts_with('!') {
            let inner = Self::parse_port(&s[1..])?;
            return Ok(PortSpec::Not(Box::new(inner)));
        }

        if s.contains(':') {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() == 2 {
                let start = parts[0].parse().unwrap_or(0);
                let end = parts[1].parse().unwrap_or(65535);
                return Ok(PortSpec::Range(start, end));
            }
        }

        let port: u16 = s.parse()
            .map_err(|_| ParseError::InvalidPort(s.to_string()))?;
        Ok(PortSpec::Single(port))
    }

    fn parse_direction(s: &str) -> Result<Direction, ParseError> {
        match s {
            "->" => Ok(Direction::Unidirectional),
            "<>" => Ok(Direction::Bidirectional),
            _ => Err(ParseError::InvalidDirection(s.to_string())),
        }
    }

    fn parse_options(options_str: &str) -> Result<Vec<RuleOption>, ParseError> {
        let mut options = Vec::new();

        // Split by semicolon, handling quoted strings
        let parts = Self::split_options(options_str);

        for part in parts {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            if let Some(opt) = Self::parse_single_option(part)? {
                options.push(opt);
            }
        }

        Ok(options)
    }

    fn parse_single_option(opt: &str) -> Result<Option<RuleOption>, ParseError> {
        let colon_pos = opt.find(':');
        let (keyword, value) = if let Some(pos) = colon_pos {
            (&opt[..pos], Some(opt[pos + 1..].trim()))
        } else {
            (opt, None)
        };

        match keyword.trim().to_lowercase().as_str() {
            "msg" => {
                let msg = value.ok_or(ParseError::MissingValue("msg"))?
                    .trim_matches('"').to_string();
                Ok(Some(RuleOption::Msg(msg)))
            }
            "sid" => {
                let sid: u32 = value.ok_or(ParseError::MissingValue("sid"))?
                    .parse().map_err(|_| ParseError::InvalidSid)?;
                Ok(Some(RuleOption::Sid(sid)))
            }
            "rev" => {
                let rev: u32 = value.ok_or(ParseError::MissingValue("rev"))?
                    .parse().map_err(|_| ParseError::InvalidRev)?;
                Ok(Some(RuleOption::Rev(rev)))
            }
            "classtype" => {
                let ct = value.ok_or(ParseError::MissingValue("classtype"))?.to_string();
                Ok(Some(RuleOption::Classtype(ct)))
            }
            "priority" => {
                let pri: u8 = value.ok_or(ParseError::MissingValue("priority"))?
                    .parse().map_err(|_| ParseError::InvalidPriority)?;
                Ok(Some(RuleOption::Priority(pri)))
            }
            "content" => {
                let content = Self::parse_content(value.ok_or(ParseError::MissingValue("content"))?)?;
                Ok(Some(RuleOption::Content(content)))
            }
            "pcre" => {
                let pcre = value.ok_or(ParseError::MissingValue("pcre"))?
                    .trim_matches('"').to_string();
                Ok(Some(RuleOption::Pcre(pcre)))
            }
            "flow" => {
                let flow = Self::parse_flow(value.ok_or(ParseError::MissingValue("flow"))?)?;
                Ok(Some(RuleOption::Flow(flow)))
            }
            "http_uri" | "http.uri" => Ok(Some(RuleOption::HttpUri)),
            "http_header" | "http.header" => Ok(Some(RuleOption::HttpHeader)),
            "http_method" | "http.method" => Ok(Some(RuleOption::HttpMethod)),
            _ => Ok(None),  // Unknown option, skip
        }
    }

    fn parse_content(value: &str) -> Result<ContentMatch, ParseError> {
        let value = value.trim();
        let negated = value.starts_with('!');
        let value = if negated { &value[1..] } else { value };

        // Parse the pattern (handle hex escapes)
        let pattern = Self::parse_pattern(value.trim_matches('"'))?;

        Ok(ContentMatch {
            pattern,
            negated,
            nocase: false,  // Set by modifier
            offset: None,
            depth: None,
            distance: None,
            within: None,
            fast_pattern: false,
        })
    }

    fn parse_pattern(s: &str) -> Result<Vec<u8>, ParseError> {
        let mut result = Vec::new();
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '|' {
                // Hex-encoded section
                let mut hex_str = String::new();
                while let Some(&c) = chars.peek() {
                    if c == '|' {
                        chars.next();
                        break;
                    }
                    if !c.is_whitespace() {
                        hex_str.push(c);
                    }
                    chars.next();
                }
                for chunk in hex_str.as_bytes().chunks(2) {
                    if chunk.len() == 2 {
                        let hex = std::str::from_utf8(chunk).unwrap();
                        if let Ok(byte) = u8::from_str_radix(hex, 16) {
                            result.push(byte);
                        }
                    }
                }
            } else {
                result.push(c as u8);
            }
        }

        Ok(result)
    }

    fn parse_flow(value: &str) -> Result<FlowOptions, ParseError> {
        let mut flow = FlowOptions {
            to_client: false,
            to_server: false,
            from_client: false,
            from_server: false,
            established: false,
            stateless: false,
        };

        for part in value.split(',') {
            match part.trim() {
                "to_client" => flow.to_client = true,
                "to_server" => flow.to_server = true,
                "from_client" => flow.from_client = true,
                "from_server" => flow.from_server = true,
                "established" => flow.established = true,
                "stateless" => flow.stateless = true,
                _ => {}
            }
        }

        Ok(flow)
    }

    fn split_options(s: &str) -> Vec<String> {
        let mut parts = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut escape_next = false;

        for c in s.chars() {
            if escape_next {
                current.push(c);
                escape_next = false;
                continue;
            }

            match c {
                '\\' => {
                    escape_next = true;
                    current.push(c);
                }
                '"' => {
                    in_quotes = !in_quotes;
                    current.push(c);
                }
                ';' if !in_quotes => {
                    parts.push(current.clone());
                    current.clear();
                }
                _ => current.push(c),
            }
        }

        if !current.is_empty() {
            parts.push(current);
        }

        parts
    }
}
```

---

## Rule Matching Engine

```rust
pub struct RuleEngine {
    rules: Vec<SnortRule>,
    content_matcher: ContentMatcher,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            content_matcher: ContentMatcher::new(),
        }
    }

    pub fn load_rules(&mut self, path: &std::path::Path) -> Result<usize, Error> {
        let content = std::fs::read_to_string(path)?;
        let mut loaded = 0;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            match RuleParser::parse(line) {
                Ok(rule) => {
                    self.add_rule(rule);
                    loaded += 1;
                }
                Err(e) => {
                    tracing::warn!("Failed to parse rule: {:?}", e);
                }
            }
        }

        Ok(loaded)
    }

    pub fn add_rule(&mut self, rule: SnortRule) {
        // Add content patterns to fast matcher
        for opt in &rule.options {
            if let RuleOption::Content(content) = opt {
                if content.fast_pattern || content.pattern.len() >= 4 {
                    self.content_matcher.add_pattern(&content.pattern);
                }
            }
        }

        self.rules.push(rule);
    }

    pub fn match_packet(&self, packet: &ParsedPacket, flow: &FlowState) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        // Pre-filter with content matcher
        let potential_matches: std::collections::HashSet<usize> =
            self.content_matcher.find_matches(&packet.payload)
                .into_iter()
                .collect();

        for (idx, rule) in self.rules.iter().enumerate() {
            // Quick checks first
            if !self.protocol_matches(rule, packet) {
                continue;
            }

            if !self.network_matches(rule, packet) {
                continue;
            }

            if !self.port_matches(rule, packet) {
                continue;
            }

            // Check options
            if self.options_match(rule, packet, flow) {
                matches.push(RuleMatch {
                    rule: rule.clone(),
                    timestamp: std::time::Instant::now(),
                    packet_info: PacketInfo::from(packet),
                });
            }
        }

        matches
    }

    fn protocol_matches(&self, rule: &SnortRule, packet: &ParsedPacket) -> bool {
        match rule.protocol {
            Protocol::Ip => true,
            Protocol::Tcp => packet.protocol == 6,
            Protocol::Udp => packet.protocol == 17,
            Protocol::Icmp => packet.protocol == 1,
            _ => true,  // Application protocols checked in options
        }
    }

    fn network_matches(&self, rule: &SnortRule, packet: &ParsedPacket) -> bool {
        self.network_spec_matches(&rule.src_network, packet.src_ip) &&
        self.network_spec_matches(&rule.dst_network, packet.dst_ip)
    }

    fn network_spec_matches(&self, spec: &NetworkSpec, ip: std::net::IpAddr) -> bool {
        match spec {
            NetworkSpec::Any => true,
            NetworkSpec::Ip(rule_ip) => *rule_ip == ip,
            NetworkSpec::Cidr(net) => net.contains(&ip),
            NetworkSpec::Not(inner) => !self.network_spec_matches(inner, ip),
            NetworkSpec::List(list) => list.iter().any(|s| self.network_spec_matches(s, ip)),
            NetworkSpec::Variable(_) => true,  // Would need variable resolution
        }
    }

    fn port_matches(&self, rule: &SnortRule, packet: &ParsedPacket) -> bool {
        let src_port = packet.src_port.unwrap_or(0);
        let dst_port = packet.dst_port.unwrap_or(0);

        self.port_spec_matches(&rule.src_port, src_port) &&
        self.port_spec_matches(&rule.dst_port, dst_port)
    }

    fn port_spec_matches(&self, spec: &PortSpec, port: u16) -> bool {
        match spec {
            PortSpec::Any => true,
            PortSpec::Single(p) => *p == port,
            PortSpec::Range(start, end) => port >= *start && port <= *end,
            PortSpec::Not(inner) => !self.port_spec_matches(inner, port),
            PortSpec::List(list) => list.iter().any(|s| self.port_spec_matches(s, port)),
        }
    }

    fn options_match(&self, rule: &SnortRule, packet: &ParsedPacket, flow: &FlowState) -> bool {
        for opt in &rule.options {
            match opt {
                RuleOption::Content(content) => {
                    if !self.content_matches(content, &packet.payload) {
                        return false;
                    }
                }
                RuleOption::Flow(flow_opts) => {
                    if !self.flow_matches(flow_opts, flow) {
                        return false;
                    }
                }
                RuleOption::Dsize(cmp, size) => {
                    if !self.compare(*cmp, packet.payload.len(), *size) {
                        return false;
                    }
                }
                RuleOption::Pcre(pattern) => {
                    let re = regex::bytes::Regex::new(pattern).ok();
                    if let Some(re) = re {
                        if !re.is_match(&packet.payload) {
                            return false;
                        }
                    }
                }
                _ => {}  // Other options
            }
        }
        true
    }

    fn content_matches(&self, content: &ContentMatch, data: &[u8]) -> bool {
        let pattern = if content.nocase {
            content.pattern.to_ascii_lowercase()
        } else {
            content.pattern.clone()
        };

        let search_data = if content.nocase {
            data.to_ascii_lowercase()
        } else {
            data.to_vec()
        };

        let found = search_data.windows(pattern.len())
            .any(|window| window == pattern.as_slice());

        if content.negated { !found } else { found }
    }

    fn flow_matches(&self, opts: &FlowOptions, flow: &FlowState) -> bool {
        if opts.established {
            match flow.tcp_state {
                Some(TcpState::Established) => true,
                _ => false,
            }
        } else {
            true
        }
    }

    fn compare(&self, cmp: Comparison, a: usize, b: usize) -> bool {
        match cmp {
            Comparison::Eq => a == b,
            Comparison::Ne => a != b,
            Comparison::Lt => a < b,
            Comparison::Le => a <= b,
            Comparison::Gt => a > b,
            Comparison::Ge => a >= b,
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule: SnortRule,
    pub timestamp: std::time::Instant,
    pub packet_info: PacketInfo,
}

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub src_ip: std::net::IpAddr,
    pub dst_ip: std::net::IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: u8,
}
```

---

## Alert Management

```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct AlertManager {
    alerts: Vec<Alert>,
    thresholds: HashMap<u32, ThresholdState>,  // sid -> state
    suppressed: HashMap<u32, Instant>,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub sid: u32,
    pub priority: u8,
    pub classtype: String,
    pub message: String,
    pub src_ip: std::net::IpAddr,
    pub dst_ip: std::net::IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
}

struct ThresholdState {
    count: u32,
    window_start: Instant,
}

impl AlertManager {
    pub fn new() -> Self {
        Self {
            alerts: Vec::new(),
            thresholds: HashMap::new(),
            suppressed: HashMap::new(),
        }
    }

    pub fn process_match(&mut self, rule_match: &RuleMatch) -> Option<Alert> {
        let sid = self.get_sid(&rule_match.rule);

        // Check suppression
        if let Some(until) = self.suppressed.get(&sid) {
            if Instant::now() < *until {
                return None;
            }
            self.suppressed.remove(&sid);
        }

        // Check thresholds
        if let Some(threshold) = self.get_threshold(&rule_match.rule) {
            if !self.check_threshold(sid, &threshold) {
                return None;
            }
        }

        // Create alert
        let alert = Alert {
            timestamp: chrono::Utc::now(),
            sid,
            priority: self.get_priority(&rule_match.rule),
            classtype: self.get_classtype(&rule_match.rule),
            message: self.get_message(&rule_match.rule),
            src_ip: rule_match.packet_info.src_ip,
            dst_ip: rule_match.packet_info.dst_ip,
            src_port: rule_match.packet_info.src_port,
            dst_port: rule_match.packet_info.dst_port,
            protocol: self.protocol_name(rule_match.packet_info.protocol),
        };

        self.alerts.push(alert.clone());
        Some(alert)
    }

    fn check_threshold(&mut self, sid: u32, threshold: &ThresholdSpec) -> bool {
        let now = Instant::now();
        let state = self.thresholds.entry(sid).or_insert(ThresholdState {
            count: 0,
            window_start: now,
        });

        // Check if window expired
        if now.duration_since(state.window_start) > Duration::from_secs(threshold.seconds as u64) {
            state.count = 0;
            state.window_start = now;
        }

        state.count += 1;

        match threshold.threshold_type {
            ThresholdType::Limit => state.count <= threshold.count,
            ThresholdType::Threshold => state.count >= threshold.count,
            ThresholdType::Both => state.count >= threshold.count && state.count <= threshold.count + 1,
        }
    }

    fn get_sid(&self, rule: &SnortRule) -> u32 {
        for opt in &rule.options {
            if let RuleOption::Sid(sid) = opt {
                return *sid;
            }
        }
        0
    }

    fn get_priority(&self, rule: &SnortRule) -> u8 {
        for opt in &rule.options {
            if let RuleOption::Priority(p) = opt {
                return *p;
            }
        }
        3  // Default priority
    }

    fn get_classtype(&self, rule: &SnortRule) -> String {
        for opt in &rule.options {
            if let RuleOption::Classtype(ct) = opt {
                return ct.clone();
            }
        }
        "unknown".to_string()
    }

    fn get_message(&self, rule: &SnortRule) -> String {
        for opt in &rule.options {
            if let RuleOption::Msg(msg) = opt {
                return msg.clone();
            }
        }
        "No message".to_string()
    }

    fn get_threshold(&self, rule: &SnortRule) -> Option<ThresholdSpec> {
        for opt in &rule.options {
            if let RuleOption::Threshold(t) = opt {
                return Some(t.clone());
            }
        }
        None
    }

    fn protocol_name(&self, proto: u8) -> String {
        match proto {
            1 => "ICMP".to_string(),
            6 => "TCP".to_string(),
            17 => "UDP".to_string(),
            _ => format!("{}", proto),
        }
    }

    pub fn get_recent_alerts(&self, count: usize) -> Vec<&Alert> {
        self.alerts.iter().rev().take(count).collect()
    }
}
```

---

## Security Checklist

- [ ] Rules from trusted sources (ET, Snort)
- [ ] Rule updates regularly applied
- [ ] Threshold tuning for environment
- [ ] False positive tracking
- [ ] Alert logging and retention
- [ ] Response actions tested

## Recommended Crates

- **regex**: PCRE-like patterns
- **aho-corasick**: Multi-pattern matching
- **ipnet**: CIDR network handling

## Integration Points

This skill works well with:

- `/dpi-setup` - Packet inspection
- `/threat-feeds-setup` - Rule updates
