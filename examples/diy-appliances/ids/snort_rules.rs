//! Snort-Compatible IDS Rules Engine Example
//!
//! Demonstrates a Rust implementation of a Snort-compatible intrusion
//! detection system rules engine for DIY security appliances.

use std::collections::HashMap;
use std::net::IpAddr;

/// Snort rule action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Alert,
    Log,
    Pass,
    Drop,
    Reject,
}

impl RuleAction {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "alert" => Some(RuleAction::Alert),
            "log" => Some(RuleAction::Log),
            "pass" => Some(RuleAction::Pass),
            "drop" => Some(RuleAction::Drop),
            "reject" => Some(RuleAction::Reject),
            _ => None,
        }
    }
}

/// Protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Ip,
}

impl Protocol {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            "icmp" => Some(Protocol::Icmp),
            "ip" => Some(Protocol::Ip),
            _ => None,
        }
    }
}

/// IP address specification (supports CIDR and variables)
#[derive(Debug, Clone)]
pub enum IpSpec {
    Any,
    Address(IpAddr),
    Network { addr: IpAddr, prefix: u8 },
    Variable(String),
    Negated(Box<IpSpec>),
    List(Vec<IpSpec>),
}

impl IpSpec {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();

        if s == "any" {
            return Some(IpSpec::Any);
        }

        if s.starts_with('!') {
            return IpSpec::parse(&s[1..]).map(|spec| IpSpec::Negated(Box::new(spec)));
        }

        if s.starts_with('$') {
            return Some(IpSpec::Variable(s[1..].to_string()));
        }

        if s.contains('/') {
            let parts: Vec<&str> = s.split('/').collect();
            if parts.len() == 2 {
                if let (Ok(addr), Ok(prefix)) = (parts[0].parse(), parts[1].parse()) {
                    return Some(IpSpec::Network { addr, prefix });
                }
            }
        }

        s.parse().ok().map(IpSpec::Address)
    }

    pub fn matches(&self, ip: &IpAddr, variables: &HashMap<String, Vec<IpAddr>>) -> bool {
        match self {
            IpSpec::Any => true,
            IpSpec::Address(addr) => ip == addr,
            IpSpec::Network { addr, prefix } => ip_in_network(ip, addr, *prefix),
            IpSpec::Variable(name) => variables
                .get(name)
                .map(|addrs| addrs.contains(ip))
                .unwrap_or(false),
            IpSpec::Negated(spec) => !spec.matches(ip, variables),
            IpSpec::List(specs) => specs.iter().any(|s| s.matches(ip, variables)),
        }
    }
}

fn ip_in_network(ip: &IpAddr, network: &IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let ip_bits = u32::from(*ip);
            let net_bits = u32::from(*net);
            let mask = if prefix >= 32 {
                u32::MAX
            } else {
                u32::MAX << (32 - prefix)
            };
            (ip_bits & mask) == (net_bits & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let ip_bits = u128::from(*ip);
            let net_bits = u128::from(*net);
            let mask = if prefix >= 128 {
                u128::MAX
            } else {
                u128::MAX << (128 - prefix)
            };
            (ip_bits & mask) == (net_bits & mask)
        }
        _ => false,
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
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();

        if s == "any" {
            return Some(PortSpec::Any);
        }

        if s.starts_with('!') {
            return PortSpec::parse(&s[1..]).map(|spec| PortSpec::Negated(Box::new(spec)));
        }

        if s.contains(':') {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() == 2 {
                let start = if parts[0].is_empty() {
                    0
                } else {
                    parts[0].parse().ok()?
                };
                let end = if parts[1].is_empty() {
                    65535
                } else {
                    parts[1].parse().ok()?
                };
                return Some(PortSpec::Range(start, end));
            }
        }

        s.parse().ok().map(PortSpec::Single)
    }

    pub fn matches(&self, port: u16) -> bool {
        match self {
            PortSpec::Any => true,
            PortSpec::Single(p) => port == *p,
            PortSpec::Range(start, end) => port >= *start && port <= *end,
            PortSpec::List(specs) => specs.iter().any(|s| s.matches(port)),
            PortSpec::Negated(spec) => !spec.matches(port),
        }
    }
}

/// Rule option types
#[derive(Debug, Clone)]
pub enum RuleOption {
    Msg(String),
    Sid(u32),
    Rev(u32),
    Classtype(String),
    Priority(u32),
    Content {
        pattern: Vec<u8>,
        nocase: bool,
        offset: Option<usize>,
        depth: Option<usize>,
    },
    Pcre(String),
    Flow {
        to_server: bool,
        to_client: bool,
        established: bool,
    },
    Threshold {
        track: ThresholdTrack,
        count: u32,
        seconds: u32,
    },
    Reference {
        ref_type: String,
        ref_id: String,
    },
    Metadata(HashMap<String, String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdTrack {
    BySrc,
    ByDst,
}

/// Snort rule
#[derive(Debug, Clone)]
pub struct SnortRule {
    pub action: RuleAction,
    pub protocol: Protocol,
    pub src_ip: IpSpec,
    pub src_port: PortSpec,
    pub direction: Direction,
    pub dst_ip: IpSpec,
    pub dst_port: PortSpec,
    pub options: Vec<RuleOption>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Unidirectional, // ->
    Bidirectional,  // <>
}

impl SnortRule {
    pub fn new(
        action: RuleAction,
        protocol: Protocol,
        src_ip: IpSpec,
        src_port: PortSpec,
        direction: Direction,
        dst_ip: IpSpec,
        dst_port: PortSpec,
    ) -> Self {
        Self {
            action,
            protocol,
            src_ip,
            src_port,
            direction,
            dst_ip,
            dst_port,
            options: Vec::new(),
        }
    }

    pub fn add_option(&mut self, option: RuleOption) {
        self.options.push(option);
    }

    pub fn sid(&self) -> Option<u32> {
        for opt in &self.options {
            if let RuleOption::Sid(id) = opt {
                return Some(*id);
            }
        }
        None
    }

    pub fn msg(&self) -> Option<&str> {
        for opt in &self.options {
            if let RuleOption::Msg(msg) = opt {
                return Some(msg);
            }
        }
        None
    }

    /// Parse a Snort rule from string
    pub fn parse(rule_str: &str) -> Result<Self, ParseError> {
        let rule_str = rule_str.trim();

        // Find the options section
        let paren_start = rule_str.find('(').ok_or(ParseError::InvalidFormat)?;
        let header = &rule_str[..paren_start].trim();
        let options_str = &rule_str[paren_start..];

        // Parse header
        let parts: Vec<&str> = header.split_whitespace().collect();
        if parts.len() < 7 {
            return Err(ParseError::InvalidFormat);
        }

        let action = RuleAction::from_str(parts[0]).ok_or(ParseError::InvalidAction)?;
        let protocol = Protocol::from_str(parts[1]).ok_or(ParseError::InvalidProtocol)?;
        let src_ip = IpSpec::parse(parts[2]).ok_or(ParseError::InvalidIp)?;
        let src_port = PortSpec::parse(parts[3]).ok_or(ParseError::InvalidPort)?;

        let direction = match parts[4] {
            "->" => Direction::Unidirectional,
            "<>" => Direction::Bidirectional,
            _ => return Err(ParseError::InvalidDirection),
        };

        let dst_ip = IpSpec::parse(parts[5]).ok_or(ParseError::InvalidIp)?;
        let dst_port = PortSpec::parse(parts[6]).ok_or(ParseError::InvalidPort)?;

        let mut rule = Self::new(
            action, protocol, src_ip, src_port, direction, dst_ip, dst_port,
        );

        // Parse options
        let options = Self::parse_options(options_str)?;
        rule.options = options;

        Ok(rule)
    }

    fn parse_options(options_str: &str) -> Result<Vec<RuleOption>, ParseError> {
        let mut options = Vec::new();

        // Remove parentheses
        let content = options_str.trim_start_matches('(').trim_end_matches(')');

        // Split by semicolon
        for opt_str in content.split(';') {
            let opt_str = opt_str.trim();
            if opt_str.is_empty() {
                continue;
            }

            // Parse option
            if let Some(colon_pos) = opt_str.find(':') {
                let key = &opt_str[..colon_pos].trim();
                let value = &opt_str[colon_pos + 1..].trim();

                match *key {
                    "msg" => {
                        let msg = value.trim_matches('"').to_string();
                        options.push(RuleOption::Msg(msg));
                    }
                    "sid" => {
                        if let Ok(sid) = value.parse() {
                            options.push(RuleOption::Sid(sid));
                        }
                    }
                    "rev" => {
                        if let Ok(rev) = value.parse() {
                            options.push(RuleOption::Rev(rev));
                        }
                    }
                    "classtype" => {
                        options.push(RuleOption::Classtype(value.to_string()));
                    }
                    "priority" => {
                        if let Ok(pri) = value.parse() {
                            options.push(RuleOption::Priority(pri));
                        }
                    }
                    "content" => {
                        let pattern = parse_content_pattern(value);
                        options.push(RuleOption::Content {
                            pattern,
                            nocase: false,
                            offset: None,
                            depth: None,
                        });
                    }
                    "pcre" => {
                        options.push(RuleOption::Pcre(value.trim_matches('"').to_string()));
                    }
                    _ => {}
                }
            }
        }

        Ok(options)
    }

    /// Convert rule to Snort format string
    pub fn to_string(&self) -> String {
        let action = match self.action {
            RuleAction::Alert => "alert",
            RuleAction::Log => "log",
            RuleAction::Pass => "pass",
            RuleAction::Drop => "drop",
            RuleAction::Reject => "reject",
        };

        let protocol = match self.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
            Protocol::Ip => "ip",
        };

        let direction = match self.direction {
            Direction::Unidirectional => "->",
            Direction::Bidirectional => "<>",
        };

        let mut rule = format!(
            "{} {} {} {} {} {} {} (",
            action,
            protocol,
            ip_spec_to_string(&self.src_ip),
            port_spec_to_string(&self.src_port),
            direction,
            ip_spec_to_string(&self.dst_ip),
            port_spec_to_string(&self.dst_port),
        );

        for opt in &self.options {
            rule.push_str(&option_to_string(opt));
            rule.push_str("; ");
        }

        rule.push(')');
        rule
    }
}

fn ip_spec_to_string(spec: &IpSpec) -> String {
    match spec {
        IpSpec::Any => "any".to_string(),
        IpSpec::Address(addr) => addr.to_string(),
        IpSpec::Network { addr, prefix } => format!("{}/{}", addr, prefix),
        IpSpec::Variable(name) => format!("${}", name),
        IpSpec::Negated(inner) => format!("!{}", ip_spec_to_string(inner)),
        IpSpec::List(specs) => {
            let items: Vec<String> = specs.iter().map(ip_spec_to_string).collect();
            format!("[{}]", items.join(","))
        }
    }
}

fn port_spec_to_string(spec: &PortSpec) -> String {
    match spec {
        PortSpec::Any => "any".to_string(),
        PortSpec::Single(p) => p.to_string(),
        PortSpec::Range(start, end) => format!("{}:{}", start, end),
        PortSpec::List(specs) => {
            let items: Vec<String> = specs.iter().map(port_spec_to_string).collect();
            format!("[{}]", items.join(","))
        }
        PortSpec::Negated(inner) => format!("!{}", port_spec_to_string(inner)),
    }
}

fn option_to_string(opt: &RuleOption) -> String {
    match opt {
        RuleOption::Msg(msg) => format!("msg:\"{}\"", msg),
        RuleOption::Sid(sid) => format!("sid:{}", sid),
        RuleOption::Rev(rev) => format!("rev:{}", rev),
        RuleOption::Classtype(ct) => format!("classtype:{}", ct),
        RuleOption::Priority(pri) => format!("priority:{}", pri),
        RuleOption::Content { pattern, .. } => {
            let hex: String = pattern.iter().map(|b| format!("{:02X}", b)).collect();
            format!("content:\"|{}|\"", hex)
        }
        RuleOption::Pcre(pcre) => format!("pcre:\"{}\"", pcre),
        _ => String::new(),
    }
}

fn parse_content_pattern(value: &str) -> Vec<u8> {
    let value = value.trim_matches('"');

    // Check for hex content |XX XX|
    if value.starts_with('|') && value.ends_with('|') {
        let hex = value.trim_matches('|');
        return hex
            .split_whitespace()
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect();
    }

    // Plain text content
    value.as_bytes().to_vec()
}

#[derive(Debug)]
pub enum ParseError {
    InvalidFormat,
    InvalidAction,
    InvalidProtocol,
    InvalidIp,
    InvalidPort,
    InvalidDirection,
}

/// IDS alert
#[derive(Debug, Clone)]
pub struct IdsAlert {
    pub rule_sid: u32,
    pub message: String,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub timestamp: std::time::SystemTime,
}

/// Snort rules engine
pub struct RulesEngine {
    rules: Vec<SnortRule>,
    variables: HashMap<String, Vec<IpAddr>>,
}

impl Default for RulesEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RulesEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            variables: HashMap::new(),
        }
    }

    pub fn add_rule(&mut self, rule: SnortRule) {
        self.rules.push(rule);
    }

    pub fn set_variable(&mut self, name: &str, addresses: Vec<IpAddr>) {
        self.variables.insert(name.to_string(), addresses);
    }

    pub fn load_rules(&mut self, rules_text: &str) -> Result<usize, ParseError> {
        let mut count = 0;

        for line in rules_text.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse and add rule
            if let Ok(rule) = SnortRule::parse(line) {
                self.rules.push(rule);
                count += 1;
            }
        }

        Ok(count)
    }

    /// Check packet against all rules
    pub fn check_packet(
        &self,
        src_ip: &IpAddr,
        dst_ip: &IpAddr,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        protocol: Protocol,
        payload: Option<&[u8]>,
    ) -> Vec<IdsAlert> {
        let mut alerts = Vec::new();

        for rule in &self.rules {
            if self.rule_matches(rule, src_ip, dst_ip, src_port, dst_port, protocol, payload) {
                if rule.action == RuleAction::Alert || rule.action == RuleAction::Drop {
                    alerts.push(IdsAlert {
                        rule_sid: rule.sid().unwrap_or(0),
                        message: rule.msg().unwrap_or("Unknown").to_string(),
                        src_ip: *src_ip,
                        dst_ip: *dst_ip,
                        src_port,
                        dst_port,
                        protocol,
                        timestamp: std::time::SystemTime::now(),
                    });
                }
            }
        }

        alerts
    }

    fn rule_matches(
        &self,
        rule: &SnortRule,
        src_ip: &IpAddr,
        dst_ip: &IpAddr,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        protocol: Protocol,
        payload: Option<&[u8]>,
    ) -> bool {
        // Check protocol
        if rule.protocol != Protocol::Ip && rule.protocol != protocol {
            return false;
        }

        // Check IPs
        let ip_match = rule.src_ip.matches(src_ip, &self.variables)
            && rule.dst_ip.matches(dst_ip, &self.variables);

        let reverse_ip_match = rule.direction == Direction::Bidirectional
            && rule.src_ip.matches(dst_ip, &self.variables)
            && rule.dst_ip.matches(src_ip, &self.variables);

        if !ip_match && !reverse_ip_match {
            return false;
        }

        // Check ports
        if let Some(sp) = src_port {
            if !rule.src_port.matches(sp) {
                return false;
            }
        }

        if let Some(dp) = dst_port {
            if !rule.dst_port.matches(dp) {
                return false;
            }
        }

        // Check content options
        if let Some(data) = payload {
            for opt in &rule.options {
                if let RuleOption::Content { pattern, .. } = opt {
                    if !data.windows(pattern.len()).any(|w| w == pattern.as_slice()) {
                        return false;
                    }
                }
            }
        }

        true
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

fn main() {
    println!("Snort-Compatible IDS Rules Engine Example");
    println!("==========================================\n");

    // Create rules engine
    let mut engine = RulesEngine::new();

    // Set variables
    engine.set_variable("HOME_NET", vec!["192.168.1.0".parse().unwrap()]);
    engine.set_variable("EXTERNAL_NET", vec!["0.0.0.0".parse().unwrap()]);

    // Add rules
    let rules_text = r#"
# SSH brute force detection
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; sid:1000001; rev:1; classtype:attempted-admin;)

# SQL injection detection
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt"; content:"|27|OR|27|"; sid:1000002; rev:1;)

# ICMP ping flood
alert icmp any any -> $HOME_NET any (msg:"ICMP Flood"; sid:1000003; rev:1;)
"#;

    let count = engine.load_rules(rules_text).unwrap();
    println!("Loaded {} rules\n", count);

    // Test packets
    let test_cases = vec![
        (
            "192.168.1.100",
            "192.168.1.1",
            Some(12345),
            Some(22),
            Protocol::Tcp,
            None,
        ),
        (
            "10.0.0.1",
            "192.168.1.1",
            Some(54321),
            Some(80),
            Protocol::Tcp,
            Some(b"' OR '1'='1".as_slice()),
        ),
        ("8.8.8.8", "192.168.1.1", None, None, Protocol::Icmp, None),
    ];

    println!("Testing packets:");
    for (src, dst, sport, dport, proto, payload) in test_cases {
        let src_ip: IpAddr = src.parse().unwrap();
        let dst_ip: IpAddr = dst.parse().unwrap();

        let alerts = engine.check_packet(&src_ip, &dst_ip, sport, dport, proto, payload);

        println!("\n  {} -> {} ({:?})", src, dst, proto);
        if alerts.is_empty() {
            println!("    No alerts");
        } else {
            for alert in alerts {
                println!("    ALERT [SID:{}]: {}", alert.rule_sid, alert.message);
            }
        }
    }

    // Parse and display a rule
    println!("\n\nRule Parsing Example:");
    let rule_str =
        r#"alert tcp any any -> 192.168.1.0/24 80 (msg:"HTTP Traffic"; sid:1000010; rev:1;)"#;

    match SnortRule::parse(rule_str) {
        Ok(rule) => {
            println!("  Original: {}", rule_str);
            println!("  Parsed:");
            println!("    Action: {:?}", rule.action);
            println!("    Protocol: {:?}", rule.protocol);
            println!("    SID: {:?}", rule.sid());
            println!("    Message: {:?}", rule.msg());
        }
        Err(e) => println!("  Parse error: {:?}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_spec_any() {
        let spec = IpSpec::Any;
        let variables = HashMap::new();
        assert!(spec.matches(&"192.168.1.1".parse().unwrap(), &variables));
    }

    #[test]
    fn test_ip_spec_address() {
        let spec = IpSpec::Address("192.168.1.1".parse().unwrap());
        let variables = HashMap::new();
        assert!(spec.matches(&"192.168.1.1".parse().unwrap(), &variables));
        assert!(!spec.matches(&"192.168.1.2".parse().unwrap(), &variables));
    }

    #[test]
    fn test_ip_spec_network() {
        let spec = IpSpec::Network {
            addr: "192.168.1.0".parse().unwrap(),
            prefix: 24,
        };
        let variables = HashMap::new();
        assert!(spec.matches(&"192.168.1.100".parse().unwrap(), &variables));
        assert!(!spec.matches(&"192.168.2.1".parse().unwrap(), &variables));
    }

    #[test]
    fn test_port_spec_range() {
        let spec = PortSpec::Range(80, 443);
        assert!(spec.matches(80));
        assert!(spec.matches(443));
        assert!(spec.matches(200));
        assert!(!spec.matches(79));
        assert!(!spec.matches(444));
    }

    #[test]
    fn test_rule_parse() {
        let rule_str = r#"alert tcp any any -> any 80 (msg:"Test"; sid:1;)"#;
        let rule = SnortRule::parse(rule_str).unwrap();

        assert_eq!(rule.action, RuleAction::Alert);
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert_eq!(rule.sid(), Some(1));
        assert_eq!(rule.msg(), Some("Test"));
    }

    #[test]
    fn test_engine_basic() {
        let mut engine = RulesEngine::new();

        let mut rule = SnortRule::new(
            RuleAction::Alert,
            Protocol::Tcp,
            IpSpec::Any,
            PortSpec::Any,
            Direction::Unidirectional,
            IpSpec::Any,
            PortSpec::Single(80),
        );
        rule.add_option(RuleOption::Sid(1));
        rule.add_option(RuleOption::Msg("HTTP".to_string()));

        engine.add_rule(rule);

        let alerts = engine.check_packet(
            &"10.0.0.1".parse().unwrap(),
            &"192.168.1.1".parse().unwrap(),
            Some(12345),
            Some(80),
            Protocol::Tcp,
            None,
        );

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_sid, 1);
    }

    #[test]
    fn test_content_matching() {
        let mut engine = RulesEngine::new();

        let mut rule = SnortRule::new(
            RuleAction::Alert,
            Protocol::Tcp,
            IpSpec::Any,
            PortSpec::Any,
            Direction::Unidirectional,
            IpSpec::Any,
            PortSpec::Any,
        );
        rule.add_option(RuleOption::Sid(1));
        rule.add_option(RuleOption::Content {
            pattern: b"EVIL".to_vec(),
            nocase: false,
            offset: None,
            depth: None,
        });

        engine.add_rule(rule);

        // Should match
        let alerts = engine.check_packet(
            &"10.0.0.1".parse().unwrap(),
            &"192.168.1.1".parse().unwrap(),
            Some(12345),
            Some(80),
            Protocol::Tcp,
            Some(b"This contains EVIL content"),
        );
        assert_eq!(alerts.len(), 1);

        // Should not match
        let alerts = engine.check_packet(
            &"10.0.0.1".parse().unwrap(),
            &"192.168.1.1".parse().unwrap(),
            Some(12345),
            Some(80),
            Protocol::Tcp,
            Some(b"This is safe content"),
        );
        assert_eq!(alerts.len(), 0);
    }
}
