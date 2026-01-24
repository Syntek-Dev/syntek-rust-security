//! nftables Firewall Rules Generator Example
//!
//! Demonstrates generating and managing nftables firewall rules
//! in Rust for secure server configurations.

use std::collections::HashSet;
use std::net::IpAddr;

/// IP version for rules
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    Ipv4,
    Ipv6,
    Both,
}

/// Protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Chain type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainType {
    Filter,
    Nat,
    Route,
}

impl ChainType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChainType::Filter => "filter",
            ChainType::Nat => "nat",
            ChainType::Route => "route",
        }
    }
}

/// Hook point for chains
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    Prerouting,
    Input,
    Forward,
    Output,
    Postrouting,
}

impl Hook {
    pub fn as_str(&self) -> &'static str {
        match self {
            Hook::Prerouting => "prerouting",
            Hook::Input => "input",
            Hook::Forward => "forward",
            Hook::Output => "output",
            Hook::Postrouting => "postrouting",
        }
    }
}

/// Rule action
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Accept,
    Drop,
    Reject,
    Log { prefix: String, level: u8 },
    Counter,
    Masquerade,
    Dnat { to: String },
    Snat { to: String },
    Jump { target: String },
    Return,
}

impl Action {
    pub fn to_nft(&self) -> String {
        match self {
            Action::Accept => "accept".to_string(),
            Action::Drop => "drop".to_string(),
            Action::Reject => "reject".to_string(),
            Action::Log { prefix, level } => format!("log prefix \"{}\" level {}", prefix, level),
            Action::Counter => "counter".to_string(),
            Action::Masquerade => "masquerade".to_string(),
            Action::Dnat { to } => format!("dnat to {}", to),
            Action::Snat { to } => format!("snat to {}", to),
            Action::Jump { target } => format!("jump {}", target),
            Action::Return => "return".to_string(),
        }
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Firewall rule
#[derive(Debug, Clone)]
pub struct Rule {
    pub protocol: Option<Protocol>,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub sport: Option<PortSpec>,
    pub dport: Option<PortSpec>,
    pub iif: Option<String>,
    pub oif: Option<String>,
    pub states: Vec<ConnState>,
    pub actions: Vec<Action>,
    pub comment: Option<String>,
}

/// Port specification
#[derive(Debug, Clone)]
pub enum PortSpec {
    Single(u16),
    Range(u16, u16),
    List(Vec<u16>),
}

impl PortSpec {
    pub fn to_nft(&self) -> String {
        match self {
            PortSpec::Single(p) => p.to_string(),
            PortSpec::Range(start, end) => format!("{}-{}", start, end),
            PortSpec::List(ports) => {
                let strs: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                format!("{{ {} }}", strs.join(", "))
            }
        }
    }
}

impl Rule {
    pub fn new() -> Self {
        Self {
            protocol: None,
            source: None,
            destination: None,
            sport: None,
            dport: None,
            iif: None,
            oif: None,
            states: Vec::new(),
            actions: Vec::new(),
            comment: None,
        }
    }

    pub fn protocol(mut self, proto: Protocol) -> Self {
        self.protocol = Some(proto);
        self
    }

    pub fn source(mut self, addr: &str) -> Self {
        self.source = Some(addr.to_string());
        self
    }

    pub fn destination(mut self, addr: &str) -> Self {
        self.destination = Some(addr.to_string());
        self
    }

    pub fn sport(mut self, port: PortSpec) -> Self {
        self.sport = Some(port);
        self
    }

    pub fn dport(mut self, port: PortSpec) -> Self {
        self.dport = Some(port);
        self
    }

    pub fn iif(mut self, interface: &str) -> Self {
        self.iif = Some(interface.to_string());
        self
    }

    pub fn oif(mut self, interface: &str) -> Self {
        self.oif = Some(interface.to_string());
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

    pub fn action(mut self, action: Action) -> Self {
        self.actions.push(action);
        self
    }

    pub fn comment(mut self, comment: &str) -> Self {
        self.comment = Some(comment.to_string());
        self
    }

    /// Generate nftables rule string
    pub fn to_nft(&self) -> String {
        let mut parts = Vec::new();

        if let Some(ref iif) = self.iif {
            parts.push(format!("iif {}", iif));
        }

        if let Some(ref oif) = self.oif {
            parts.push(format!("oif {}", oif));
        }

        if let Some(ref src) = self.source {
            parts.push(format!("ip saddr {}", src));
        }

        if let Some(ref dst) = self.destination {
            parts.push(format!("ip daddr {}", dst));
        }

        if let Some(proto) = self.protocol {
            if proto != Protocol::All {
                parts.push(proto.as_str().to_string());
            }
        }

        if let Some(ref sport) = self.sport {
            parts.push(format!("sport {}", sport.to_nft()));
        }

        if let Some(ref dport) = self.dport {
            parts.push(format!("dport {}", dport.to_nft()));
        }

        if !self.states.is_empty() {
            let states: Vec<&str> = self.states.iter().map(|s| s.as_str()).collect();
            parts.push(format!("ct state {{ {} }}", states.join(", ")));
        }

        for action in &self.actions {
            parts.push(action.to_nft());
        }

        if let Some(ref comment) = self.comment {
            parts.push(format!("comment \"{}\"", comment));
        }

        parts.join(" ")
    }
}

impl Default for Rule {
    fn default() -> Self {
        Self::new()
    }
}

/// Chain definition
#[derive(Debug, Clone)]
pub struct Chain {
    pub name: String,
    pub chain_type: ChainType,
    pub hook: Hook,
    pub priority: i32,
    pub policy: Option<Action>,
    pub rules: Vec<Rule>,
}

impl Chain {
    pub fn new(name: &str, chain_type: ChainType, hook: Hook, priority: i32) -> Self {
        Self {
            name: name.to_string(),
            chain_type,
            hook,
            priority,
            policy: None,
            rules: Vec::new(),
        }
    }

    pub fn with_policy(mut self, policy: Action) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    pub fn to_nft(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("    chain {} {{\n", self.name));

        output.push_str(&format!(
            "        type {} hook {} priority {}",
            self.chain_type.as_str(),
            self.hook.as_str(),
            self.priority
        ));

        if let Some(ref policy) = self.policy {
            output.push_str(&format!("; policy {}", policy.to_nft()));
        }

        output.push_str("\n");

        for rule in &self.rules {
            output.push_str(&format!("        {}\n", rule.to_nft()));
        }

        output.push_str("    }\n");

        output
    }
}

/// Table definition
#[derive(Debug, Clone)]
pub struct Table {
    pub name: String,
    pub family: String, // inet, ip, ip6, arp, bridge, netdev
    pub chains: Vec<Chain>,
}

impl Table {
    pub fn new(name: &str, family: &str) -> Self {
        Self {
            name: name.to_string(),
            family: family.to_string(),
            chains: Vec::new(),
        }
    }

    pub fn add_chain(&mut self, chain: Chain) {
        self.chains.push(chain);
    }

    pub fn to_nft(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("table {} {} {{\n", self.family, self.name));

        for chain in &self.chains {
            output.push_str(&chain.to_nft());
        }

        output.push_str("}\n");

        output
    }
}

/// Firewall ruleset generator
pub struct FirewallConfig {
    tables: Vec<Table>,
    trusted_ips: HashSet<String>,
    blocked_ips: HashSet<String>,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallConfig {
    pub fn new() -> Self {
        Self {
            tables: Vec::new(),
            trusted_ips: HashSet::new(),
            blocked_ips: HashSet::new(),
        }
    }

    pub fn add_trusted_ip(&mut self, ip: &str) {
        self.trusted_ips.insert(ip.to_string());
    }

    pub fn add_blocked_ip(&mut self, ip: &str) {
        self.blocked_ips.insert(ip.to_string());
    }

    /// Generate a basic secure server firewall
    pub fn generate_server_firewall(&mut self, allowed_ports: &[u16]) -> &mut Self {
        let mut table = Table::new("firewall", "inet");

        // Input chain
        let mut input =
            Chain::new("input", ChainType::Filter, Hook::Input, 0).with_policy(Action::Drop);

        // Allow loopback
        input.add_rule(
            Rule::new()
                .iif("lo")
                .action(Action::Accept)
                .comment("Allow loopback"),
        );

        // Allow established connections
        input.add_rule(
            Rule::new()
                .states(vec![ConnState::Established, ConnState::Related])
                .action(Action::Accept)
                .comment("Allow established"),
        );

        // Drop invalid
        input.add_rule(
            Rule::new()
                .state(ConnState::Invalid)
                .action(Action::Drop)
                .comment("Drop invalid"),
        );

        // Block specific IPs
        for ip in &self.blocked_ips {
            input.add_rule(
                Rule::new()
                    .source(ip)
                    .action(Action::Drop)
                    .comment("Blocked IP"),
            );
        }

        // Allow ICMP
        input.add_rule(
            Rule::new()
                .protocol(Protocol::Icmp)
                .action(Action::Accept)
                .comment("Allow ICMP"),
        );

        input.add_rule(
            Rule::new()
                .protocol(Protocol::Icmpv6)
                .action(Action::Accept)
                .comment("Allow ICMPv6"),
        );

        // Allow specified ports
        for port in allowed_ports {
            input.add_rule(
                Rule::new()
                    .protocol(Protocol::Tcp)
                    .dport(PortSpec::Single(*port))
                    .state(ConnState::New)
                    .action(Action::Accept)
                    .comment(&format!("Allow TCP port {}", port)),
            );
        }

        // Log dropped packets
        input.add_rule(
            Rule::new()
                .action(Action::Log {
                    prefix: "DROPPED: ".to_string(),
                    level: 4,
                })
                .action(Action::Counter),
        );

        table.add_chain(input);

        // Forward chain
        let forward =
            Chain::new("forward", ChainType::Filter, Hook::Forward, 0).with_policy(Action::Drop);
        table.add_chain(forward);

        // Output chain
        let output =
            Chain::new("output", ChainType::Filter, Hook::Output, 0).with_policy(Action::Accept);
        table.add_chain(output);

        self.tables.push(table);
        self
    }

    /// Generate rules for a web server
    pub fn add_web_server_rules(&mut self) -> &mut Self {
        // Find or create firewall table
        if self.tables.is_empty() {
            self.generate_server_firewall(&[22]);
        }

        // Add HTTP/HTTPS ports
        if let Some(table) = self.tables.first_mut() {
            if let Some(input) = table.chains.iter_mut().find(|c| c.name == "input") {
                // Insert web rules before the log rule
                let log_idx = input.rules.len().saturating_sub(1);

                input.rules.insert(
                    log_idx,
                    Rule::new()
                        .protocol(Protocol::Tcp)
                        .dport(PortSpec::Single(80))
                        .state(ConnState::New)
                        .action(Action::Accept)
                        .comment("Allow HTTP"),
                );

                input.rules.insert(
                    log_idx + 1,
                    Rule::new()
                        .protocol(Protocol::Tcp)
                        .dport(PortSpec::Single(443))
                        .state(ConnState::New)
                        .action(Action::Accept)
                        .comment("Allow HTTPS"),
                );
            }
        }

        self
    }

    /// Generate complete ruleset
    pub fn to_nft(&self) -> String {
        let mut output = String::new();
        output.push_str("#!/usr/sbin/nft -f\n\n");
        output.push_str("# Generated by syntek-rust-security\n");
        output.push_str("# Flush existing rules\n");
        output.push_str("flush ruleset\n\n");

        for table in &self.tables {
            output.push_str(&table.to_nft());
            output.push('\n');
        }

        output
    }
}

fn main() {
    println!("nftables Firewall Rules Generator Example");
    println!("==========================================\n");

    // Create firewall configuration
    let mut firewall = FirewallConfig::new();

    // Add blocked IPs
    firewall.add_blocked_ip("192.168.1.100");
    firewall.add_blocked_ip("10.0.0.50");

    // Generate server firewall with SSH
    firewall.generate_server_firewall(&[22]);

    // Add web server rules
    firewall.add_web_server_rules();

    // Generate and print ruleset
    let ruleset = firewall.to_nft();
    println!("Generated nftables ruleset:\n");
    println!("{}", ruleset);

    // Individual rule examples
    println!("\nIndividual Rule Examples:");
    println!("=========================\n");

    let rate_limit = Rule::new()
        .protocol(Protocol::Tcp)
        .dport(PortSpec::Single(22))
        .state(ConnState::New)
        .action(Action::Log {
            prefix: "SSH: ".to_string(),
            level: 4,
        })
        .action(Action::Accept)
        .comment("SSH with logging");
    println!("SSH with logging: {}\n", rate_limit.to_nft());

    let port_range = Rule::new()
        .protocol(Protocol::Tcp)
        .dport(PortSpec::Range(8000, 8999))
        .action(Action::Accept)
        .comment("Allow port range");
    println!("Port range: {}\n", port_range.to_nft());

    let multi_port = Rule::new()
        .protocol(Protocol::Tcp)
        .dport(PortSpec::List(vec![80, 443, 8080]))
        .action(Action::Accept)
        .comment("Multiple ports");
    println!("Multiple ports: {}", multi_port.to_nft());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_spec_single() {
        let spec = PortSpec::Single(443);
        assert_eq!(spec.to_nft(), "443");
    }

    #[test]
    fn test_port_spec_range() {
        let spec = PortSpec::Range(8000, 8999);
        assert_eq!(spec.to_nft(), "8000-8999");
    }

    #[test]
    fn test_port_spec_list() {
        let spec = PortSpec::List(vec![80, 443, 8080]);
        assert_eq!(spec.to_nft(), "{ 80, 443, 8080 }");
    }

    #[test]
    fn test_action_to_nft() {
        assert_eq!(Action::Accept.to_nft(), "accept");
        assert_eq!(Action::Drop.to_nft(), "drop");
        assert_eq!(
            Action::Log {
                prefix: "TEST: ".to_string(),
                level: 4
            }
            .to_nft(),
            "log prefix \"TEST: \" level 4"
        );
    }

    #[test]
    fn test_simple_rule() {
        let rule = Rule::new()
            .protocol(Protocol::Tcp)
            .dport(PortSpec::Single(22))
            .action(Action::Accept);

        let nft = rule.to_nft();
        assert!(nft.contains("tcp"));
        assert!(nft.contains("dport 22"));
        assert!(nft.contains("accept"));
    }

    #[test]
    fn test_rule_with_states() {
        let rule = Rule::new()
            .states(vec![ConnState::Established, ConnState::Related])
            .action(Action::Accept);

        let nft = rule.to_nft();
        assert!(nft.contains("ct state"));
        assert!(nft.contains("established"));
        assert!(nft.contains("related"));
    }

    #[test]
    fn test_chain_generation() {
        let mut chain =
            Chain::new("input", ChainType::Filter, Hook::Input, 0).with_policy(Action::Drop);

        chain.add_rule(Rule::new().action(Action::Accept));

        let nft = chain.to_nft();
        assert!(nft.contains("chain input"));
        assert!(nft.contains("type filter"));
        assert!(nft.contains("hook input"));
        assert!(nft.contains("policy drop"));
    }

    #[test]
    fn test_table_generation() {
        let mut table = Table::new("firewall", "inet");
        let chain = Chain::new("input", ChainType::Filter, Hook::Input, 0);
        table.add_chain(chain);

        let nft = table.to_nft();
        assert!(nft.contains("table inet firewall"));
    }

    #[test]
    fn test_firewall_config() {
        let mut firewall = FirewallConfig::new();
        firewall.add_blocked_ip("1.2.3.4");
        firewall.generate_server_firewall(&[22, 80]);

        let ruleset = firewall.to_nft();
        assert!(ruleset.contains("flush ruleset"));
        assert!(ruleset.contains("dport 22"));
        assert!(ruleset.contains("dport 80"));
    }

    #[test]
    fn test_web_server_rules() {
        let mut firewall = FirewallConfig::new();
        firewall.generate_server_firewall(&[22]);
        firewall.add_web_server_rules();

        let ruleset = firewall.to_nft();
        assert!(ruleset.contains("dport 80"));
        assert!(ruleset.contains("dport 443"));
    }
}
