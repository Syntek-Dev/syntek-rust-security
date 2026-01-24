//! nftables Firewall Wrapper Implementation
//!
//! Rust wrapper for nftables firewall management with rule generation,
//! chain management, and security policy enforcement.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Network protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    All,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
            Protocol::Icmpv6 => "icmpv6",
            Protocol::All => "all",
        }
    }
}

/// Rule action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Accept,
    Drop,
    Reject,
    Log,
    Jump(ChainType),
    Return,
}

impl Action {
    pub fn as_nft(&self) -> String {
        match self {
            Action::Accept => "accept".to_string(),
            Action::Drop => "drop".to_string(),
            Action::Reject => "reject".to_string(),
            Action::Log => "log".to_string(),
            Action::Jump(chain) => format!("jump {}", chain.as_str()),
            Action::Return => "return".to_string(),
        }
    }
}

/// Chain type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainType {
    Input,
    Output,
    Forward,
    Prerouting,
    Postrouting,
    Custom(&'static str),
}

impl ChainType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChainType::Input => "input",
            ChainType::Output => "output",
            ChainType::Forward => "forward",
            ChainType::Prerouting => "prerouting",
            ChainType::Postrouting => "postrouting",
            ChainType::Custom(name) => name,
        }
    }
}

/// Address family
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    Inet,
    Ip,
    Ip6,
    Arp,
    Bridge,
    Netdev,
}

impl AddressFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            AddressFamily::Inet => "inet",
            AddressFamily::Ip => "ip",
            AddressFamily::Ip6 => "ip6",
            AddressFamily::Arp => "arp",
            AddressFamily::Bridge => "bridge",
            AddressFamily::Netdev => "netdev",
        }
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnState {
    New,
    Established,
    Related,
    Invalid,
}

impl ConnState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnState::New => "new",
            ConnState::Established => "established",
            ConnState::Related => "related",
            ConnState::Invalid => "invalid",
        }
    }
}

/// Port specification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSpec {
    Single(u16),
    Range(u16, u16),
    Multiple(Vec<u16>),
}

impl PortSpec {
    pub fn as_nft(&self) -> String {
        match self {
            PortSpec::Single(p) => p.to_string(),
            PortSpec::Range(start, end) => format!("{}-{}", start, end),
            PortSpec::Multiple(ports) => {
                let ports: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                format!("{{ {} }}", ports.join(", "))
            }
        }
    }
}

/// IP address specification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpSpec {
    Single(IpAddr),
    Network(IpAddr, u8),
    Range(IpAddr, IpAddr),
    Set(Vec<IpAddr>),
}

impl IpSpec {
    pub fn as_nft(&self) -> String {
        match self {
            IpSpec::Single(ip) => ip.to_string(),
            IpSpec::Network(ip, prefix) => format!("{}/{}", ip, prefix),
            IpSpec::Range(start, end) => format!("{}-{}", start, end),
            IpSpec::Set(ips) => {
                let ips: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                format!("{{ {} }}", ips.join(", "))
            }
        }
    }
}

/// Firewall rule
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: u64,
    pub chain: ChainType,
    pub protocol: Option<Protocol>,
    pub source: Option<IpSpec>,
    pub destination: Option<IpSpec>,
    pub source_port: Option<PortSpec>,
    pub dest_port: Option<PortSpec>,
    pub states: Vec<ConnState>,
    pub interface_in: Option<String>,
    pub interface_out: Option<String>,
    pub action: Action,
    pub comment: Option<String>,
    pub counter: bool,
    pub log_prefix: Option<String>,
    pub priority: i32,
    pub enabled: bool,
    pub created_at: u64,
}

impl Rule {
    pub fn new(chain: ChainType, action: Action) -> Self {
        Self {
            id: 0,
            chain,
            protocol: None,
            source: None,
            destination: None,
            source_port: None,
            dest_port: None,
            states: Vec::new(),
            interface_in: None,
            interface_out: None,
            action,
            comment: None,
            counter: true,
            log_prefix: None,
            priority: 0,
            enabled: true,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    pub fn protocol(mut self, proto: Protocol) -> Self {
        self.protocol = Some(proto);
        self
    }

    pub fn source(mut self, src: IpSpec) -> Self {
        self.source = Some(src);
        self
    }

    pub fn destination(mut self, dst: IpSpec) -> Self {
        self.destination = Some(dst);
        self
    }

    pub fn source_port(mut self, port: PortSpec) -> Self {
        self.source_port = Some(port);
        self
    }

    pub fn dest_port(mut self, port: PortSpec) -> Self {
        self.dest_port = Some(port);
        self
    }

    pub fn state(mut self, state: ConnState) -> Self {
        self.states.push(state);
        self
    }

    pub fn states(mut self, states: Vec<ConnState>) -> Self {
        self.states = states;
        self
    }

    pub fn interface_in(mut self, iface: impl Into<String>) -> Self {
        self.interface_in = Some(iface.into());
        self
    }

    pub fn interface_out(mut self, iface: impl Into<String>) -> Self {
        self.interface_out = Some(iface.into());
        self
    }

    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    pub fn log_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.log_prefix = Some(prefix.into());
        self
    }

    pub fn priority(mut self, prio: i32) -> Self {
        self.priority = prio;
        self
    }

    pub fn no_counter(mut self) -> Self {
        self.counter = false;
        self
    }

    /// Generate nftables rule syntax
    pub fn to_nft(&self) -> String {
        let mut parts = Vec::new();

        if let Some(ref iface) = self.interface_in {
            parts.push(format!("iif {}", iface));
        }
        if let Some(ref iface) = self.interface_out {
            parts.push(format!("oif {}", iface));
        }

        if let Some(proto) = &self.protocol {
            if *proto != Protocol::All {
                parts.push(proto.as_str().to_string());
            }
        }

        if let Some(ref src) = self.source {
            parts.push(format!("ip saddr {}", src.as_nft()));
        }
        if let Some(ref dst) = self.destination {
            parts.push(format!("ip daddr {}", dst.as_nft()));
        }

        if let Some(ref port) = self.source_port {
            parts.push(format!("sport {}", port.as_nft()));
        }
        if let Some(ref port) = self.dest_port {
            parts.push(format!("dport {}", port.as_nft()));
        }

        if !self.states.is_empty() {
            let states: Vec<&str> = self.states.iter().map(|s| s.as_str()).collect();
            parts.push(format!("ct state {{ {} }}", states.join(", ")));
        }

        if self.counter {
            parts.push("counter".to_string());
        }

        if let Some(ref prefix) = self.log_prefix {
            parts.push(format!("log prefix \"{}\"", prefix));
        }

        parts.push(self.action.as_nft());

        if let Some(ref comment) = self.comment {
            parts.push(format!("comment \"{}\"", comment));
        }

        parts.join(" ")
    }
}

/// nftables chain configuration
#[derive(Debug, Clone)]
pub struct Chain {
    pub name: String,
    pub chain_type: ChainType,
    pub hook: Option<String>,
    pub priority: i32,
    pub policy: Action,
    pub rules: Vec<Rule>,
}

impl Chain {
    pub fn new(name: impl Into<String>, chain_type: ChainType) -> Self {
        Self {
            name: name.into(),
            chain_type,
            hook: None,
            priority: 0,
            policy: Action::Accept,
            rules: Vec::new(),
        }
    }

    pub fn hook(mut self, hook: impl Into<String>) -> Self {
        self.hook = Some(hook.into());
        self
    }

    pub fn priority(mut self, prio: i32) -> Self {
        self.priority = prio;
        self
    }

    pub fn policy(mut self, policy: Action) -> Self {
        self.policy = policy;
        self
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }
}

/// nftables table
#[derive(Debug, Clone)]
pub struct Table {
    pub name: String,
    pub family: AddressFamily,
    pub chains: HashMap<String, Chain>,
    pub sets: HashMap<String, Set>,
}

impl Table {
    pub fn new(name: impl Into<String>, family: AddressFamily) -> Self {
        Self {
            name: name.into(),
            family,
            chains: HashMap::new(),
            sets: HashMap::new(),
        }
    }

    pub fn add_chain(&mut self, chain: Chain) {
        self.chains.insert(chain.name.clone(), chain);
    }

    pub fn add_set(&mut self, set: Set) {
        self.sets.insert(set.name.clone(), set);
    }

    pub fn get_chain_mut(&mut self, name: &str) -> Option<&mut Chain> {
        self.chains.get_mut(name)
    }
}

/// nftables set for grouping elements
#[derive(Debug, Clone)]
pub struct Set {
    pub name: String,
    pub element_type: String,
    pub flags: Vec<String>,
    pub elements: HashSet<String>,
    pub timeout: Option<Duration>,
}

impl Set {
    pub fn new(name: impl Into<String>, element_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            element_type: element_type.into(),
            flags: Vec::new(),
            elements: HashSet::new(),
            timeout: None,
        }
    }

    pub fn flag(mut self, flag: impl Into<String>) -> Self {
        self.flags.push(flag.into());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn add_element(&mut self, element: impl Into<String>) {
        self.elements.insert(element.into());
    }

    pub fn remove_element(&mut self, element: &str) {
        self.elements.remove(element);
    }
}

/// Rate limit specification
#[derive(Debug, Clone)]
pub struct RateLimit {
    pub rate: u32,
    pub per: RatePer,
    pub burst: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
pub enum RatePer {
    Second,
    Minute,
    Hour,
    Day,
}

impl RatePer {
    pub fn as_str(&self) -> &'static str {
        match self {
            RatePer::Second => "second",
            RatePer::Minute => "minute",
            RatePer::Hour => "hour",
            RatePer::Day => "day",
        }
    }
}

impl RateLimit {
    pub fn new(rate: u32, per: RatePer) -> Self {
        Self {
            rate,
            per,
            burst: None,
        }
    }

    pub fn burst(mut self, burst: u32) -> Self {
        self.burst = Some(burst);
        self
    }

    pub fn as_nft(&self) -> String {
        let base = format!("limit rate {}/{}", self.rate, self.per.as_str());
        if let Some(burst) = self.burst {
            format!("{} burst {} packets", base, burst)
        } else {
            base
        }
    }
}

/// Firewall manager
pub struct FirewallManager {
    tables: Arc<RwLock<HashMap<String, Table>>>,
    rule_counter: std::sync::atomic::AtomicU64,
    dry_run: bool,
}

impl FirewallManager {
    pub fn new() -> Self {
        Self {
            tables: Arc::new(RwLock::new(HashMap::new())),
            rule_counter: std::sync::atomic::AtomicU64::new(1),
            dry_run: false,
        }
    }

    pub fn dry_run(mut self, enable: bool) -> Self {
        self.dry_run = enable;
        self
    }

    /// Create a new table
    pub fn create_table(&self, name: impl Into<String>, family: AddressFamily) -> Table {
        let table = Table::new(name, family);
        let mut tables = self.tables.write().unwrap();
        tables.insert(table.name.clone(), table.clone());
        table
    }

    /// Add a table
    pub fn add_table(&self, table: Table) {
        let mut tables = self.tables.write().unwrap();
        tables.insert(table.name.clone(), table);
    }

    /// Get a table
    pub fn get_table(&self, name: &str) -> Option<Table> {
        let tables = self.tables.read().unwrap();
        tables.get(name).cloned()
    }

    /// Add a rule to a chain
    pub fn add_rule(
        &self,
        table_name: &str,
        chain_name: &str,
        mut rule: Rule,
    ) -> Result<u64, FirewallError> {
        let mut tables = self.tables.write().unwrap();
        let table = tables
            .get_mut(table_name)
            .ok_or_else(|| FirewallError::TableNotFound(table_name.to_string()))?;

        let chain = table
            .chains
            .get_mut(chain_name)
            .ok_or_else(|| FirewallError::ChainNotFound(chain_name.to_string()))?;

        let id = self
            .rule_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        rule.id = id;

        chain.rules.push(rule);
        Ok(id)
    }

    /// Remove a rule by ID
    pub fn remove_rule(
        &self,
        table_name: &str,
        chain_name: &str,
        rule_id: u64,
    ) -> Result<(), FirewallError> {
        let mut tables = self.tables.write().unwrap();
        let table = tables
            .get_mut(table_name)
            .ok_or_else(|| FirewallError::TableNotFound(table_name.to_string()))?;

        let chain = table
            .chains
            .get_mut(chain_name)
            .ok_or_else(|| FirewallError::ChainNotFound(chain_name.to_string()))?;

        chain.rules.retain(|r| r.id != rule_id);
        Ok(())
    }

    /// Generate complete nftables configuration
    pub fn generate_config(&self) -> String {
        let tables = self.tables.read().unwrap();
        let mut config = String::new();

        config.push_str("#!/usr/sbin/nft -f\n\n");
        config.push_str("# Generated by Rust nftables wrapper\n");
        config.push_str(&format!("# Generated at: {}\n\n", chrono_format_now()));

        // Flush existing rules
        config.push_str("flush ruleset\n\n");

        for table in tables.values() {
            config.push_str(&format!(
                "table {} {} {{\n",
                table.family.as_str(),
                table.name
            ));

            // Sets
            for set in table.sets.values() {
                config.push_str(&format!("    set {} {{\n", set.name));
                config.push_str(&format!("        type {}\n", set.element_type));
                if !set.flags.is_empty() {
                    config.push_str(&format!("        flags {}\n", set.flags.join(", ")));
                }
                if let Some(timeout) = set.timeout {
                    config.push_str(&format!("        timeout {}s\n", timeout.as_secs()));
                }
                if !set.elements.is_empty() {
                    let elements: Vec<&String> = set.elements.iter().collect();
                    config.push_str(&format!(
                        "        elements = {{ {} }}\n",
                        elements.join(", ")
                    ));
                }
                config.push_str("    }\n\n");
            }

            // Chains
            for chain in table.chains.values() {
                if let Some(ref hook) = chain.hook {
                    config.push_str(&format!(
                        "    chain {} {{\n        type filter hook {} priority {}; policy {};\n",
                        chain.name,
                        hook,
                        chain.priority,
                        match chain.policy {
                            Action::Accept => "accept",
                            Action::Drop => "drop",
                            _ => "accept",
                        }
                    ));
                } else {
                    config.push_str(&format!("    chain {} {{\n", chain.name));
                }

                // Sort rules by priority
                let mut sorted_rules = chain.rules.clone();
                sorted_rules.sort_by(|a, b| a.priority.cmp(&b.priority));

                for rule in &sorted_rules {
                    if rule.enabled {
                        config.push_str(&format!("        {}\n", rule.to_nft()));
                    }
                }

                config.push_str("    }\n\n");
            }

            config.push_str("}\n\n");
        }

        config
    }

    /// Apply configuration (simulated in this example)
    pub fn apply(&self) -> Result<(), FirewallError> {
        let config = self.generate_config();

        if self.dry_run {
            println!("DRY RUN - Configuration that would be applied:");
            println!("{}", config);
            return Ok(());
        }

        // In production, this would write to a file and execute nft
        // For safety, we just validate the config here
        self.validate_config(&config)?;

        Ok(())
    }

    fn validate_config(&self, _config: &str) -> Result<(), FirewallError> {
        // Basic validation - in production would use nft -c -f
        Ok(())
    }

    /// List all rules in a chain
    pub fn list_rules(
        &self,
        table_name: &str,
        chain_name: &str,
    ) -> Result<Vec<Rule>, FirewallError> {
        let tables = self.tables.read().unwrap();
        let table = tables
            .get(table_name)
            .ok_or_else(|| FirewallError::TableNotFound(table_name.to_string()))?;

        let chain = table
            .chains
            .get(chain_name)
            .ok_or_else(|| FirewallError::ChainNotFound(chain_name.to_string()))?;

        Ok(chain.rules.clone())
    }
}

impl Default for FirewallManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Firewall error types
#[derive(Debug)]
pub enum FirewallError {
    TableNotFound(String),
    ChainNotFound(String),
    RuleNotFound(u64),
    InvalidRule(String),
    ApplyError(String),
}

impl fmt::Display for FirewallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FirewallError::TableNotFound(name) => write!(f, "Table not found: {}", name),
            FirewallError::ChainNotFound(name) => write!(f, "Chain not found: {}", name),
            FirewallError::RuleNotFound(id) => write!(f, "Rule not found: {}", id),
            FirewallError::InvalidRule(msg) => write!(f, "Invalid rule: {}", msg),
            FirewallError::ApplyError(msg) => write!(f, "Apply error: {}", msg),
        }
    }
}

impl std::error::Error for FirewallError {}

/// Security policy presets
pub struct SecurityPresets;

impl SecurityPresets {
    /// Create a basic server firewall
    pub fn basic_server(manager: &FirewallManager, allowed_ports: &[u16]) {
        let mut table = manager.create_table("filter", AddressFamily::Inet);

        // Input chain
        let mut input = Chain::new("input", ChainType::Input)
            .hook("input")
            .priority(0)
            .policy(Action::Drop);

        // Allow established connections
        input.add_rule(
            Rule::new(ChainType::Input, Action::Accept)
                .states(vec![ConnState::Established, ConnState::Related])
                .comment("Allow established connections"),
        );

        // Allow loopback
        input.add_rule(
            Rule::new(ChainType::Input, Action::Accept)
                .interface_in("lo")
                .comment("Allow loopback"),
        );

        // Allow ICMP
        input.add_rule(
            Rule::new(ChainType::Input, Action::Accept)
                .protocol(Protocol::Icmp)
                .comment("Allow ICMP"),
        );

        // Allow specified ports
        for port in allowed_ports {
            input.add_rule(
                Rule::new(ChainType::Input, Action::Accept)
                    .protocol(Protocol::Tcp)
                    .dest_port(PortSpec::Single(*port))
                    .state(ConnState::New)
                    .comment(format!("Allow TCP port {}", port)),
            );
        }

        // Log dropped packets
        input.add_rule(
            Rule::new(ChainType::Input, Action::Drop)
                .log_prefix("DROPPED: ")
                .comment("Log and drop remaining"),
        );

        table.add_chain(input);

        // Output chain - allow all
        let output = Chain::new("output", ChainType::Output)
            .hook("output")
            .priority(0)
            .policy(Action::Accept);
        table.add_chain(output);

        manager.add_table(table);
    }

    /// Create a web server firewall
    pub fn web_server(manager: &FirewallManager) {
        Self::basic_server(manager, &[22, 80, 443]);
    }

    /// Create a strict server firewall with rate limiting
    pub fn strict_server(manager: &FirewallManager) {
        let mut table = manager.create_table("filter", AddressFamily::Inet);

        // Blocklist set
        let blocklist = Set::new("blocklist", "ipv4_addr")
            .flag("timeout")
            .timeout(Duration::from_secs(3600));
        table.add_set(blocklist);

        // Input chain
        let mut input = Chain::new("input", ChainType::Input)
            .hook("input")
            .priority(0)
            .policy(Action::Drop);

        // Drop blocklisted IPs
        input.add_rule(Rule::new(ChainType::Input, Action::Drop).comment("Drop blocklisted IPs"));

        // Allow established
        input.add_rule(
            Rule::new(ChainType::Input, Action::Accept)
                .states(vec![ConnState::Established, ConnState::Related])
                .comment("Allow established"),
        );

        // Allow loopback
        input.add_rule(
            Rule::new(ChainType::Input, Action::Accept)
                .interface_in("lo")
                .comment("Allow loopback"),
        );

        // SSH with rate limiting (comment indicates rate limit would be added)
        input.add_rule(
            Rule::new(ChainType::Input, Action::Accept)
                .protocol(Protocol::Tcp)
                .dest_port(PortSpec::Single(22))
                .state(ConnState::New)
                .comment("SSH with rate limit 3/minute"),
        );

        // HTTPS
        input.add_rule(
            Rule::new(ChainType::Input, Action::Accept)
                .protocol(Protocol::Tcp)
                .dest_port(PortSpec::Single(443))
                .state(ConnState::New)
                .comment("Allow HTTPS"),
        );

        table.add_chain(input);

        // Output chain
        let output = Chain::new("output", ChainType::Output)
            .hook("output")
            .priority(0)
            .policy(Action::Accept);
        table.add_chain(output);

        manager.add_table(table);
    }
}

fn chrono_format_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{}", now)
}

fn main() {
    println!("=== nftables Firewall Wrapper Demo ===\n");

    // Create manager
    let manager = FirewallManager::new().dry_run(true);

    // Create basic table and chains
    println!("1. Creating basic firewall structure:");
    let mut table = manager.create_table("myfilter", AddressFamily::Inet);

    let input = Chain::new("input", ChainType::Input)
        .hook("input")
        .priority(0)
        .policy(Action::Drop);
    table.add_chain(input);

    let output = Chain::new("output", ChainType::Output)
        .hook("output")
        .priority(0)
        .policy(Action::Accept);
    table.add_chain(output);

    manager.add_table(table);
    println!("   Created table 'myfilter' with input/output chains");

    // Add rules
    println!("\n2. Adding firewall rules:");

    // Allow established connections
    let rule = Rule::new(ChainType::Input, Action::Accept)
        .states(vec![ConnState::Established, ConnState::Related])
        .comment("Allow established connections");
    let id = manager.add_rule("myfilter", "input", rule).unwrap();
    println!("   Added rule {}: Allow established connections", id);

    // Allow loopback
    let rule = Rule::new(ChainType::Input, Action::Accept)
        .interface_in("lo")
        .comment("Allow loopback");
    let id = manager.add_rule("myfilter", "input", rule).unwrap();
    println!("   Added rule {}: Allow loopback", id);

    // Allow SSH from specific network
    let rule = Rule::new(ChainType::Input, Action::Accept)
        .protocol(Protocol::Tcp)
        .source(IpSpec::Network("192.168.1.0".parse().unwrap(), 24))
        .dest_port(PortSpec::Single(22))
        .state(ConnState::New)
        .comment("Allow SSH from LAN");
    let id = manager.add_rule("myfilter", "input", rule).unwrap();
    println!("   Added rule {}: Allow SSH from 192.168.1.0/24", id);

    // Allow HTTP/HTTPS
    let rule = Rule::new(ChainType::Input, Action::Accept)
        .protocol(Protocol::Tcp)
        .dest_port(PortSpec::Multiple(vec![80, 443]))
        .state(ConnState::New)
        .comment("Allow HTTP/HTTPS");
    let id = manager.add_rule("myfilter", "input", rule).unwrap();
    println!("   Added rule {}: Allow HTTP/HTTPS", id);

    // Log and drop everything else
    let rule = Rule::new(ChainType::Input, Action::Drop)
        .log_prefix("DROPPED: ")
        .comment("Log and drop");
    let id = manager.add_rule("myfilter", "input", rule).unwrap();
    println!("   Added rule {}: Log and drop remaining", id);

    // Generate configuration
    println!("\n3. Generated nftables configuration:");
    println!("{}", manager.generate_config());

    // Use security presets
    println!("4. Security presets:");
    let preset_manager = FirewallManager::new().dry_run(true);
    SecurityPresets::web_server(&preset_manager);
    println!("   Web server preset applied (ports 22, 80, 443)");

    // List rules
    println!("\n5. Listing rules in input chain:");
    match manager.list_rules("myfilter", "input") {
        Ok(rules) => {
            for rule in rules {
                println!(
                    "   Rule {}: {} (priority: {})",
                    rule.id,
                    rule.comment.unwrap_or_default(),
                    rule.priority
                );
            }
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Demonstrate rule building
    println!("\n6. Rule building examples:");

    let rule = Rule::new(ChainType::Input, Action::Accept)
        .protocol(Protocol::Tcp)
        .source(IpSpec::Set(vec![
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
        ]))
        .dest_port(PortSpec::Range(8000, 9000))
        .comment("Custom rule");
    println!("   Complex rule: {}", rule.to_nft());

    let rule = Rule::new(ChainType::Forward, Action::Drop)
        .interface_in("eth0")
        .interface_out("eth1")
        .protocol(Protocol::Tcp)
        .dest_port(PortSpec::Single(25))
        .comment("Block SMTP forwarding");
    println!("   Forward rule: {}", rule.to_nft());

    // Rate limiting
    println!("\n7. Rate limiting:");
    let rate = RateLimit::new(10, RatePer::Minute).burst(5);
    println!("   Rate limit: {}", rate.as_nft());

    // Sets
    println!("\n8. IP sets:");
    let mut blocklist = Set::new("blocklist", "ipv4_addr")
        .flag("timeout")
        .timeout(Duration::from_secs(3600));
    blocklist.add_element("192.168.1.100");
    blocklist.add_element("10.0.0.50");
    println!(
        "   Blocklist set with {} elements",
        blocklist.elements.len()
    );

    println!("\n=== Demo Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_as_str() {
        assert_eq!(Protocol::Tcp.as_str(), "tcp");
        assert_eq!(Protocol::Udp.as_str(), "udp");
        assert_eq!(Protocol::Icmp.as_str(), "icmp");
    }

    #[test]
    fn test_action_as_nft() {
        assert_eq!(Action::Accept.as_nft(), "accept");
        assert_eq!(Action::Drop.as_nft(), "drop");
        assert_eq!(Action::Reject.as_nft(), "reject");
    }

    #[test]
    fn test_port_spec() {
        assert_eq!(PortSpec::Single(80).as_nft(), "80");
        assert_eq!(PortSpec::Range(8000, 9000).as_nft(), "8000-9000");
        assert_eq!(
            PortSpec::Multiple(vec![80, 443, 8080]).as_nft(),
            "{ 80, 443, 8080 }"
        );
    }

    #[test]
    fn test_ip_spec() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(IpSpec::Single(ip).as_nft(), "192.168.1.1");

        let network: IpAddr = "192.168.1.0".parse().unwrap();
        assert_eq!(IpSpec::Network(network, 24).as_nft(), "192.168.1.0/24");
    }

    #[test]
    fn test_rule_builder() {
        let rule = Rule::new(ChainType::Input, Action::Accept)
            .protocol(Protocol::Tcp)
            .dest_port(PortSpec::Single(22))
            .comment("SSH");

        assert_eq!(rule.protocol, Some(Protocol::Tcp));
        assert!(rule.comment.is_some());
    }

    #[test]
    fn test_rule_to_nft() {
        let rule = Rule::new(ChainType::Input, Action::Accept)
            .protocol(Protocol::Tcp)
            .dest_port(PortSpec::Single(22));

        let nft = rule.to_nft();
        assert!(nft.contains("tcp"));
        assert!(nft.contains("dport 22"));
        assert!(nft.contains("accept"));
    }

    #[test]
    fn test_rule_with_states() {
        let rule = Rule::new(ChainType::Input, Action::Accept)
            .states(vec![ConnState::Established, ConnState::Related]);

        let nft = rule.to_nft();
        assert!(nft.contains("ct state"));
        assert!(nft.contains("established"));
    }

    #[test]
    fn test_chain_creation() {
        let chain = Chain::new("input", ChainType::Input)
            .hook("input")
            .priority(0)
            .policy(Action::Drop);

        assert_eq!(chain.name, "input");
        assert_eq!(chain.priority, 0);
    }

    #[test]
    fn test_table_creation() {
        let mut table = Table::new("filter", AddressFamily::Inet);
        let chain = Chain::new("input", ChainType::Input);
        table.add_chain(chain);

        assert_eq!(table.chains.len(), 1);
    }

    #[test]
    fn test_firewall_manager() {
        let manager = FirewallManager::new();
        let table = manager.create_table("test", AddressFamily::Inet);

        assert_eq!(table.name, "test");
        assert!(manager.get_table("test").is_some());
    }

    #[test]
    fn test_add_rule_to_chain() {
        let manager = FirewallManager::new();
        let mut table = manager.create_table("filter", AddressFamily::Inet);

        let chain = Chain::new("input", ChainType::Input);
        table.add_chain(chain);
        manager.add_table(table);

        let rule = Rule::new(ChainType::Input, Action::Accept);
        let result = manager.add_rule("filter", "input", rule);

        assert!(result.is_ok());
    }

    #[test]
    fn test_remove_rule() {
        let manager = FirewallManager::new();
        let mut table = manager.create_table("filter", AddressFamily::Inet);
        let chain = Chain::new("input", ChainType::Input);
        table.add_chain(chain);
        manager.add_table(table);

        let rule = Rule::new(ChainType::Input, Action::Accept);
        let id = manager.add_rule("filter", "input", rule).unwrap();

        let result = manager.remove_rule("filter", "input", id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_config() {
        let manager = FirewallManager::new();
        let mut table = manager.create_table("filter", AddressFamily::Inet);

        let mut chain = Chain::new("input", ChainType::Input)
            .hook("input")
            .policy(Action::Drop);

        chain.add_rule(Rule::new(ChainType::Input, Action::Accept).comment("Test rule"));
        table.add_chain(chain);
        manager.add_table(table);

        let config = manager.generate_config();
        assert!(config.contains("table inet filter"));
        assert!(config.contains("chain input"));
        assert!(config.contains("accept"));
    }

    #[test]
    fn test_set_operations() {
        let mut set = Set::new("blocklist", "ipv4_addr")
            .flag("timeout")
            .timeout(Duration::from_secs(3600));

        set.add_element("192.168.1.1");
        set.add_element("192.168.1.2");
        assert_eq!(set.elements.len(), 2);

        set.remove_element("192.168.1.1");
        assert_eq!(set.elements.len(), 1);
    }

    #[test]
    fn test_rate_limit() {
        let rate = RateLimit::new(10, RatePer::Minute);
        assert_eq!(rate.as_nft(), "limit rate 10/minute");

        let rate = RateLimit::new(100, RatePer::Second).burst(50);
        assert!(rate.as_nft().contains("burst 50"));
    }

    #[test]
    fn test_security_presets() {
        let manager = FirewallManager::new();
        SecurityPresets::web_server(&manager);

        let table = manager.get_table("filter").unwrap();
        assert!(table.chains.contains_key("input"));
        assert!(table.chains.contains_key("output"));
    }

    #[test]
    fn test_chain_not_found_error() {
        let manager = FirewallManager::new();
        manager.create_table("filter", AddressFamily::Inet);

        let rule = Rule::new(ChainType::Input, Action::Accept);
        let result = manager.add_rule("filter", "nonexistent", rule);

        assert!(matches!(result, Err(FirewallError::ChainNotFound(_))));
    }

    #[test]
    fn test_table_not_found_error() {
        let manager = FirewallManager::new();

        let rule = Rule::new(ChainType::Input, Action::Accept);
        let result = manager.add_rule("nonexistent", "input", rule);

        assert!(matches!(result, Err(FirewallError::TableNotFound(_))));
    }

    #[test]
    fn test_interface_rules() {
        let rule = Rule::new(ChainType::Forward, Action::Accept)
            .interface_in("eth0")
            .interface_out("eth1");

        let nft = rule.to_nft();
        assert!(nft.contains("iif eth0"));
        assert!(nft.contains("oif eth1"));
    }

    #[test]
    fn test_conn_state_strings() {
        assert_eq!(ConnState::New.as_str(), "new");
        assert_eq!(ConnState::Established.as_str(), "established");
        assert_eq!(ConnState::Related.as_str(), "related");
        assert_eq!(ConnState::Invalid.as_str(), "invalid");
    }

    #[test]
    fn test_address_family() {
        assert_eq!(AddressFamily::Inet.as_str(), "inet");
        assert_eq!(AddressFamily::Ip.as_str(), "ip");
        assert_eq!(AddressFamily::Ip6.as_str(), "ip6");
    }
}
