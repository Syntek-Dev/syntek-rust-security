//! Router Security Traffic Filter
//!
//! Implements network-level traffic filtering with IP/domain blocking,
//! bandwidth throttling, and connection tracking for suspicious traffic.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant, SystemTime};

/// Traffic filter configuration
#[derive(Debug, Clone)]
pub struct FilterConfig {
    /// Enable IP-based blocking
    pub ip_blocking: bool,
    /// Enable domain blocking
    pub domain_blocking: bool,
    /// Enable rate limiting
    pub rate_limiting: bool,
    /// Enable connection tracking
    pub connection_tracking: bool,
    /// Maximum connections per source IP
    pub max_connections_per_ip: u32,
    /// Default bandwidth limit (bytes/sec, 0 = unlimited)
    pub default_bandwidth_limit: u64,
    /// Suspicious traffic throttle rate (bytes/sec)
    pub suspicious_throttle_rate: u64,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            ip_blocking: true,
            domain_blocking: true,
            rate_limiting: true,
            connection_tracking: true,
            max_connections_per_ip: 100,
            default_bandwidth_limit: 0,
            suspicious_throttle_rate: 10 * 1024, // 10 KB/s
        }
    }
}

/// Filter action
#[derive(Debug, Clone, PartialEq)]
pub enum FilterAction {
    Allow,
    Block,
    Throttle(u64), // bytes per second
    Log,
    Redirect(String),
}

/// Filter rule
#[derive(Debug, Clone)]
pub struct FilterRule {
    /// Rule ID
    pub id: u32,
    /// Rule name
    pub name: String,
    /// Source IP matcher
    pub src_ip: IpMatcher,
    /// Destination IP matcher
    pub dst_ip: IpMatcher,
    /// Port matcher
    pub port: PortMatcher,
    /// Protocol
    pub protocol: ProtocolMatcher,
    /// Action
    pub action: FilterAction,
    /// Priority (higher = checked first)
    pub priority: u32,
    /// Enable logging
    pub log: bool,
    /// Hit count
    pub hits: u64,
    /// Enabled
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub enum IpMatcher {
    Any,
    Single(IpAddr),
    Cidr(IpAddr, u8),
    Range(IpAddr, IpAddr),
    List(Vec<IpAddr>),
    Blocklist, // Use global blocklist
}

#[derive(Debug, Clone)]
pub enum PortMatcher {
    Any,
    Single(u16),
    Range(u16, u16),
    List(Vec<u16>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolMatcher {
    Any,
    Tcp,
    Udp,
    Icmp,
}

/// Connection state
#[derive(Debug, Clone)]
pub struct ConnectionState {
    /// Source IP
    pub src_ip: IpAddr,
    /// Destination IP
    pub dst_ip: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Protocol
    pub protocol: ProtocolMatcher,
    /// State
    pub state: TcpState,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Packets sent
    pub packets_sent: u64,
    /// Start time
    pub start_time: Instant,
    /// Last activity
    pub last_activity: Instant,
    /// Suspicious flag
    pub suspicious: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TcpState {
    New,
    SynSent,
    SynReceived,
    Established,
    FinWait,
    CloseWait,
    Closed,
}

/// Rate limiter for an IP
#[derive(Debug, Clone)]
struct RateLimiter {
    /// Tokens available
    tokens: f64,
    /// Last update time
    last_update: Instant,
    /// Token rate (per second)
    rate: f64,
    /// Bucket size
    bucket_size: f64,
}

impl RateLimiter {
    fn new(rate: f64, bucket_size: f64) -> Self {
        Self {
            tokens: bucket_size,
            last_update: Instant::now(),
            rate,
            bucket_size,
        }
    }

    fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.bucket_size);
        self.last_update = now;
    }
}

/// Traffic filter engine
pub struct TrafficFilter {
    config: FilterConfig,
    /// Filter rules
    rules: Vec<FilterRule>,
    /// IP blocklist
    ip_blocklist: HashSet<IpAddr>,
    /// Domain blocklist
    domain_blocklist: HashSet<String>,
    /// Active connections
    connections: HashMap<ConnectionKey, ConnectionState>,
    /// Connection count per IP
    connections_per_ip: HashMap<IpAddr, u32>,
    /// Rate limiters per IP
    rate_limiters: HashMap<IpAddr, RateLimiter>,
    /// Suspicious IPs (auto-detected)
    suspicious_ips: HashSet<IpAddr>,
    /// Statistics
    stats: FilterStats,
    /// Recent events for anomaly detection
    recent_events: VecDeque<TrafficEvent>,
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
struct TrafficEvent {
    timestamp: Instant,
    src_ip: IpAddr,
    event_type: EventType,
}

#[derive(Debug, Clone)]
enum EventType {
    Connection,
    BlockedAttempt,
    SuspiciousActivity,
}

#[derive(Debug, Default, Clone)]
pub struct FilterStats {
    pub packets_processed: u64,
    pub packets_allowed: u64,
    pub packets_blocked: u64,
    pub packets_throttled: u64,
    pub bytes_processed: u64,
    pub connections_tracked: u64,
    pub suspicious_ips_detected: u64,
}

impl TrafficFilter {
    /// Create new traffic filter
    pub fn new(config: FilterConfig) -> Self {
        Self {
            config,
            rules: Vec::new(),
            ip_blocklist: HashSet::new(),
            domain_blocklist: HashSet::new(),
            connections: HashMap::new(),
            connections_per_ip: HashMap::new(),
            rate_limiters: HashMap::new(),
            suspicious_ips: HashSet::new(),
            stats: FilterStats::default(),
            recent_events: VecDeque::with_capacity(10000),
        }
    }

    /// Add filter rule
    pub fn add_rule(&mut self, rule: FilterRule) {
        self.rules.push(rule);
        // Sort by priority (descending)
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Add IP to blocklist
    pub fn block_ip(&mut self, ip: IpAddr) {
        self.ip_blocklist.insert(ip);
    }

    /// Remove IP from blocklist
    pub fn unblock_ip(&mut self, ip: &IpAddr) {
        self.ip_blocklist.remove(ip);
    }

    /// Add domain to blocklist
    pub fn block_domain(&mut self, domain: String) {
        self.domain_blocklist.insert(domain.to_lowercase());
    }

    /// Load blocklist from file content
    pub fn load_ip_blocklist(&mut self, content: &str) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Handle CIDR notation - just take the first IP for simplicity
            let ip_str = line.split('/').next().unwrap_or(line);
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                self.ip_blocklist.insert(ip);
            }
        }
    }

    /// Process a packet
    pub fn process_packet(&mut self, packet: &PacketInfo) -> FilterResult {
        self.stats.packets_processed += 1;
        self.stats.bytes_processed += packet.size as u64;

        // Record event for anomaly detection
        self.record_event(packet.src_ip, EventType::Connection);

        // Check IP blocklist first
        if self.config.ip_blocking && self.ip_blocklist.contains(&packet.src_ip) {
            self.stats.packets_blocked += 1;
            return FilterResult {
                action: FilterAction::Block,
                rule_id: None,
                reason: Some("IP in blocklist".to_string()),
            };
        }

        // Check connection limits
        if self.config.connection_tracking {
            let conn_count = self
                .connections_per_ip
                .get(&packet.src_ip)
                .copied()
                .unwrap_or(0);
            if conn_count >= self.config.max_connections_per_ip {
                self.mark_suspicious(&packet.src_ip);
                self.stats.packets_blocked += 1;
                return FilterResult {
                    action: FilterAction::Block,
                    rule_id: None,
                    reason: Some("Connection limit exceeded".to_string()),
                };
            }
        }

        // Check if IP is suspicious
        if self.suspicious_ips.contains(&packet.src_ip) {
            self.stats.packets_throttled += 1;
            return FilterResult {
                action: FilterAction::Throttle(self.config.suspicious_throttle_rate),
                rule_id: None,
                reason: Some("Suspicious IP - throttled".to_string()),
            };
        }

        // Check rate limiting
        if self.config.rate_limiting {
            let limiter = self.rate_limiters.entry(packet.src_ip).or_insert_with(|| {
                RateLimiter::new(
                    1000.0, // 1000 packets/sec default
                    5000.0, // Burst of 5000
                )
            });

            if !limiter.try_consume(1.0) {
                self.stats.packets_throttled += 1;
                return FilterResult {
                    action: FilterAction::Throttle(self.config.suspicious_throttle_rate),
                    rule_id: None,
                    reason: Some("Rate limit exceeded".to_string()),
                };
            }
        }

        // Check rules
        for rule in &mut self.rules {
            if !rule.enabled {
                continue;
            }

            if self.rule_matches(rule, packet) {
                rule.hits += 1;

                let result = FilterResult {
                    action: rule.action.clone(),
                    rule_id: Some(rule.id),
                    reason: Some(rule.name.clone()),
                };

                match &rule.action {
                    FilterAction::Block => self.stats.packets_blocked += 1,
                    FilterAction::Throttle(_) => self.stats.packets_throttled += 1,
                    FilterAction::Allow => self.stats.packets_allowed += 1,
                    _ => {}
                }

                return result;
            }
        }

        // Default allow
        self.stats.packets_allowed += 1;

        // Track connection
        if self.config.connection_tracking {
            self.track_connection(packet);
        }

        FilterResult {
            action: FilterAction::Allow,
            rule_id: None,
            reason: None,
        }
    }

    fn rule_matches(&self, rule: &FilterRule, packet: &PacketInfo) -> bool {
        // Check source IP
        if !self.ip_matches(&rule.src_ip, &packet.src_ip) {
            return false;
        }

        // Check destination IP
        if !self.ip_matches(&rule.dst_ip, &packet.dst_ip) {
            return false;
        }

        // Check port
        if !self.port_matches(&rule.port, packet.dst_port) {
            return false;
        }

        // Check protocol
        if !self.protocol_matches(&rule.protocol, &packet.protocol) {
            return false;
        }

        true
    }

    fn ip_matches(&self, matcher: &IpMatcher, ip: &IpAddr) -> bool {
        match matcher {
            IpMatcher::Any => true,
            IpMatcher::Single(addr) => addr == ip,
            IpMatcher::Cidr(network, prefix) => self.ip_in_cidr(ip, network, *prefix),
            IpMatcher::Range(start, end) => {
                // Simplified range check for IPv4
                ip >= start && ip <= end
            }
            IpMatcher::List(list) => list.contains(ip),
            IpMatcher::Blocklist => self.ip_blocklist.contains(ip),
        }
    }

    fn ip_in_cidr(&self, ip: &IpAddr, network: &IpAddr, prefix: u8) -> bool {
        match (ip, network) {
            (IpAddr::V4(ip), IpAddr::V4(net)) => {
                let ip_bits = u32::from_be_bytes(ip.octets());
                let net_bits = u32::from_be_bytes(net.octets());
                let mask = if prefix == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix)
                };
                (ip_bits & mask) == (net_bits & mask)
            }
            _ => false,
        }
    }

    fn port_matches(&self, matcher: &PortMatcher, port: u16) -> bool {
        match matcher {
            PortMatcher::Any => true,
            PortMatcher::Single(p) => *p == port,
            PortMatcher::Range(start, end) => port >= *start && port <= *end,
            PortMatcher::List(list) => list.contains(&port),
        }
    }

    fn protocol_matches(&self, matcher: &ProtocolMatcher, protocol: &ProtocolMatcher) -> bool {
        matches!(
            (matcher, protocol),
            (ProtocolMatcher::Any, _) | (a, b) if a == b
        )
    }

    fn track_connection(&mut self, packet: &PacketInfo) {
        let key = ConnectionKey {
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            protocol: match packet.protocol {
                ProtocolMatcher::Tcp => 6,
                ProtocolMatcher::Udp => 17,
                ProtocolMatcher::Icmp => 1,
                ProtocolMatcher::Any => 0,
            },
        };

        let now = Instant::now();

        self.connections.entry(key).or_insert_with(|| {
            // Increment connection count for source IP
            *self.connections_per_ip.entry(packet.src_ip).or_insert(0) += 1;
            self.stats.connections_tracked += 1;

            ConnectionState {
                src_ip: packet.src_ip,
                dst_ip: packet.dst_ip,
                src_port: packet.src_port,
                dst_port: packet.dst_port,
                protocol: packet.protocol.clone(),
                state: TcpState::New,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                start_time: now,
                last_activity: now,
                suspicious: false,
            }
        });

        if let Some(conn) = self.connections.get_mut(&key) {
            conn.last_activity = now;
            conn.packets_sent += 1;
            conn.bytes_sent += packet.size as u64;
        }
    }

    fn record_event(&mut self, src_ip: IpAddr, event_type: EventType) {
        let event = TrafficEvent {
            timestamp: Instant::now(),
            src_ip,
            event_type,
        };

        self.recent_events.push_back(event);

        // Keep only recent events
        while self.recent_events.len() > 10000 {
            self.recent_events.pop_front();
        }

        // Check for anomalies
        self.detect_anomalies(&src_ip);
    }

    fn detect_anomalies(&mut self, src_ip: &IpAddr) {
        let now = Instant::now();
        let window = Duration::from_secs(10);

        // Count events from this IP in the last 10 seconds
        let count = self
            .recent_events
            .iter()
            .filter(|e| e.src_ip == *src_ip && now.duration_since(e.timestamp) < window)
            .count();

        // If more than 500 events in 10 seconds, mark as suspicious
        if count > 500 {
            self.mark_suspicious(src_ip);
        }
    }

    fn mark_suspicious(&mut self, ip: &IpAddr) {
        if self.suspicious_ips.insert(*ip) {
            self.stats.suspicious_ips_detected += 1;
        }
    }

    /// Remove expired connections
    pub fn cleanup_connections(&mut self, max_idle: Duration) {
        let now = Instant::now();

        let expired: Vec<ConnectionKey> = self
            .connections
            .iter()
            .filter(|(_, conn)| now.duration_since(conn.last_activity) > max_idle)
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired {
            if let Some(conn) = self.connections.remove(&key) {
                if let Some(count) = self.connections_per_ip.get_mut(&conn.src_ip) {
                    *count = count.saturating_sub(1);
                }
            }
        }
    }

    /// Clear suspicious IPs (periodic reset)
    pub fn clear_suspicious_ips(&mut self) {
        self.suspicious_ips.clear();
    }

    /// Get statistics
    pub fn get_stats(&self) -> &FilterStats {
        &self.stats
    }

    /// Get active connections
    pub fn get_connections(&self) -> Vec<&ConnectionState> {
        self.connections.values().collect()
    }

    /// Get top talkers (IPs by connection count)
    pub fn get_top_talkers(&self, limit: usize) -> Vec<(IpAddr, u32)> {
        let mut talkers: Vec<_> = self
            .connections_per_ip
            .iter()
            .map(|(ip, count)| (*ip, *count))
            .collect();
        talkers.sort_by(|a, b| b.1.cmp(&a.1));
        talkers.truncate(limit);
        talkers
    }

    /// Export firewall rules (iptables format)
    pub fn export_iptables(&self) -> String {
        let mut output = String::new();
        output.push_str("# Auto-generated iptables rules\n");
        output.push_str("*filter\n");
        output.push_str(":INPUT DROP [0:0]\n");
        output.push_str(":FORWARD DROP [0:0]\n");
        output.push_str(":OUTPUT ACCEPT [0:0]\n\n");

        // Allow loopback
        output.push_str("-A INPUT -i lo -j ACCEPT\n");
        output.push_str("-A OUTPUT -o lo -j ACCEPT\n\n");

        // Allow established connections
        output.push_str("-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n\n");

        // Block IPs from blocklist
        output.push_str("# Blocked IPs\n");
        for ip in &self.ip_blocklist {
            output.push_str(&format!("-A INPUT -s {} -j DROP\n", ip));
        }

        output.push_str("\nCOMMIT\n");
        output
    }
}

/// Packet information
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: ProtocolMatcher,
    pub size: u32,
}

/// Filter result
#[derive(Debug, Clone)]
pub struct FilterResult {
    pub action: FilterAction,
    pub rule_id: Option<u32>,
    pub reason: Option<String>,
}

fn main() {
    println!("=== Router Traffic Filter Demo ===\n");

    // Create filter
    let mut filter = TrafficFilter::new(FilterConfig::default());

    // Add blocklist
    filter.load_ip_blocklist(
        r#"
# Malicious IPs
192.0.2.1
192.0.2.2
198.51.100.0/24
"#,
    );

    // Add rules
    filter.add_rule(FilterRule {
        id: 1,
        name: "Block SSH from external".to_string(),
        src_ip: IpMatcher::Any,
        dst_ip: IpMatcher::Any,
        port: PortMatcher::Single(22),
        protocol: ProtocolMatcher::Tcp,
        action: FilterAction::Block,
        priority: 100,
        log: true,
        hits: 0,
        enabled: true,
    });

    filter.add_rule(FilterRule {
        id: 2,
        name: "Allow HTTP/HTTPS".to_string(),
        src_ip: IpMatcher::Any,
        dst_ip: IpMatcher::Any,
        port: PortMatcher::List(vec![80, 443]),
        protocol: ProtocolMatcher::Tcp,
        action: FilterAction::Allow,
        priority: 50,
        log: false,
        hits: 0,
        enabled: true,
    });

    filter.add_rule(FilterRule {
        id: 3,
        name: "Throttle suspicious ranges".to_string(),
        src_ip: IpMatcher::Cidr("10.0.0.0".parse().unwrap(), 8),
        dst_ip: IpMatcher::Any,
        port: PortMatcher::Any,
        protocol: ProtocolMatcher::Any,
        action: FilterAction::Throttle(1024),
        priority: 25,
        log: true,
        hits: 0,
        enabled: true,
    });

    println!("Filter configured with {} rules\n", filter.rules.len());

    // Test packets
    let test_packets = vec![
        PacketInfo {
            src_ip: "8.8.8.8".parse().unwrap(),
            dst_ip: "192.168.1.100".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: ProtocolMatcher::Tcp,
            size: 1500,
        },
        PacketInfo {
            src_ip: "192.0.2.1".parse().unwrap(), // Blocked IP
            dst_ip: "192.168.1.100".parse().unwrap(),
            src_port: 54321,
            dst_port: 443,
            protocol: ProtocolMatcher::Tcp,
            size: 500,
        },
        PacketInfo {
            src_ip: "203.0.113.50".parse().unwrap(),
            dst_ip: "192.168.1.100".parse().unwrap(),
            src_port: 22222,
            dst_port: 22, // SSH - blocked by rule
            protocol: ProtocolMatcher::Tcp,
            size: 100,
        },
        PacketInfo {
            src_ip: "10.0.0.50".parse().unwrap(), // Throttled range
            dst_ip: "192.168.1.100".parse().unwrap(),
            src_port: 33333,
            dst_port: 8080,
            protocol: ProtocolMatcher::Tcp,
            size: 2000,
        },
    ];

    println!("Processing test packets:\n");

    for (i, packet) in test_packets.iter().enumerate() {
        let result = filter.process_packet(packet);
        println!(
            "{}. Packet from {}:{} -> {}:{}",
            i + 1,
            packet.src_ip,
            packet.src_port,
            packet.dst_ip,
            packet.dst_port
        );
        println!("   Action: {:?}", result.action);
        if let Some(reason) = result.reason {
            println!("   Reason: {}", reason);
        }
        println!();
    }

    // Display statistics
    println!("=== Filter Statistics ===");
    let stats = filter.get_stats();
    println!("Packets processed: {}", stats.packets_processed);
    println!("Packets allowed: {}", stats.packets_allowed);
    println!("Packets blocked: {}", stats.packets_blocked);
    println!("Packets throttled: {}", stats.packets_throttled);
    println!("Connections tracked: {}", stats.connections_tracked);

    // Top talkers
    println!("\nTop talkers:");
    for (ip, count) in filter.get_top_talkers(5) {
        println!("  {} - {} connections", ip, count);
    }

    // Export iptables
    println!("\n=== Generated iptables rules ===");
    println!("{}", filter.export_iptables());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_blocklist() {
        let mut filter = TrafficFilter::new(FilterConfig::default());
        filter.block_ip("192.0.2.1".parse().unwrap());

        let packet = PacketInfo {
            src_ip: "192.0.2.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: ProtocolMatcher::Tcp,
            size: 100,
        };

        let result = filter.process_packet(&packet);
        assert_eq!(result.action, FilterAction::Block);
    }

    #[test]
    fn test_rule_matching() {
        let mut filter = TrafficFilter::new(FilterConfig::default());

        filter.add_rule(FilterRule {
            id: 1,
            name: "Block SSH".to_string(),
            src_ip: IpMatcher::Any,
            dst_ip: IpMatcher::Any,
            port: PortMatcher::Single(22),
            protocol: ProtocolMatcher::Tcp,
            action: FilterAction::Block,
            priority: 100,
            log: false,
            hits: 0,
            enabled: true,
        });

        let packet = PacketInfo {
            src_ip: "8.8.8.8".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 54321,
            dst_port: 22,
            protocol: ProtocolMatcher::Tcp,
            size: 100,
        };

        let result = filter.process_packet(&packet);
        assert_eq!(result.action, FilterAction::Block);
        assert_eq!(result.rule_id, Some(1));
    }

    #[test]
    fn test_cidr_matching() {
        let filter = TrafficFilter::new(FilterConfig::default());

        let network: IpAddr = "192.168.0.0".parse().unwrap();
        let ip_in: IpAddr = "192.168.1.100".parse().unwrap();
        let ip_out: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(filter.ip_in_cidr(&ip_in, &network, 16));
        assert!(!filter.ip_in_cidr(&ip_out, &network, 16));
    }

    #[test]
    fn test_port_matching() {
        let filter = TrafficFilter::new(FilterConfig::default());

        assert!(filter.port_matches(&PortMatcher::Any, 80));
        assert!(filter.port_matches(&PortMatcher::Single(80), 80));
        assert!(!filter.port_matches(&PortMatcher::Single(80), 443));
        assert!(filter.port_matches(&PortMatcher::Range(80, 443), 100));
        assert!(filter.port_matches(&PortMatcher::List(vec![80, 443]), 443));
    }

    #[test]
    fn test_connection_tracking() {
        let mut filter = TrafficFilter::new(FilterConfig::default());

        let packet = PacketInfo {
            src_ip: "192.168.1.100".parse().unwrap(),
            dst_ip: "8.8.8.8".parse().unwrap(),
            src_port: 54321,
            dst_port: 443,
            protocol: ProtocolMatcher::Tcp,
            size: 100,
        };

        filter.process_packet(&packet);

        assert_eq!(filter.get_connections().len(), 1);
        assert_eq!(filter.stats.connections_tracked, 1);
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(10.0, 100.0);

        // Should allow initial burst
        for _ in 0..100 {
            assert!(limiter.try_consume(1.0));
        }

        // Should deny after bucket empty
        assert!(!limiter.try_consume(1.0));
    }

    #[test]
    fn test_filter_priority() {
        let mut filter = TrafficFilter::new(FilterConfig::default());

        filter.add_rule(FilterRule {
            id: 1,
            name: "Low priority allow".to_string(),
            src_ip: IpMatcher::Any,
            dst_ip: IpMatcher::Any,
            port: PortMatcher::Single(80),
            protocol: ProtocolMatcher::Tcp,
            action: FilterAction::Allow,
            priority: 10,
            log: false,
            hits: 0,
            enabled: true,
        });

        filter.add_rule(FilterRule {
            id: 2,
            name: "High priority block".to_string(),
            src_ip: IpMatcher::Any,
            dst_ip: IpMatcher::Any,
            port: PortMatcher::Single(80),
            protocol: ProtocolMatcher::Tcp,
            action: FilterAction::Block,
            priority: 100,
            log: false,
            hits: 0,
            enabled: true,
        });

        let packet = PacketInfo {
            src_ip: "8.8.8.8".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: ProtocolMatcher::Tcp,
            size: 100,
        };

        let result = filter.process_packet(&packet);
        assert_eq!(result.action, FilterAction::Block);
        assert_eq!(result.rule_id, Some(2)); // High priority rule matched
    }
}
