//! DNS Security Proxy - DoH/DoT, Sinkholing, and Query Logging
//!
//! This example demonstrates building a secure DNS proxy with encrypted
//! upstream resolution, malicious domain blocking, and query analysis.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// DNS record type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    SOA,
    PTR,
    SRV,
    CAA,
    HTTPS,
    Unknown(u16),
}

impl RecordType {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::A,
            28 => Self::AAAA,
            5 => Self::CNAME,
            15 => Self::MX,
            16 => Self::TXT,
            2 => Self::NS,
            6 => Self::SOA,
            12 => Self::PTR,
            33 => Self::SRV,
            257 => Self::CAA,
            65 => Self::HTTPS,
            n => Self::Unknown(n),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            Self::A => 1,
            Self::AAAA => 28,
            Self::CNAME => 5,
            Self::MX => 15,
            Self::TXT => 16,
            Self::NS => 2,
            Self::SOA => 6,
            Self::PTR => 12,
            Self::SRV => 33,
            Self::CAA => 257,
            Self::HTTPS => 65,
            Self::Unknown(n) => *n,
        }
    }
}

/// DNS response code
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    Other(u8),
}

impl ResponseCode {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NxDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            n => Self::Other(n),
        }
    }
}

/// DNS query
#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub id: u16,
    pub domain: String,
    pub record_type: RecordType,
    pub client_ip: IpAddr,
    pub timestamp: u64,
    pub recursion_desired: bool,
}

/// DNS response
#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub id: u16,
    pub domain: String,
    pub record_type: RecordType,
    pub response_code: ResponseCode,
    pub answers: Vec<DnsAnswer>,
    pub ttl: u32,
    pub authoritative: bool,
    pub cached: bool,
    pub response_time_ms: u64,
}

/// DNS answer record
#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: RecordType,
    pub ttl: u32,
    pub data: DnsData,
}

#[derive(Debug, Clone)]
pub enum DnsData {
    A(Ipv4Addr),
    AAAA([u8; 16]),
    Cname(String),
    Mx { priority: u16, exchange: String },
    Txt(String),
    Ns(String),
    Ptr(String),
    Other(Vec<u8>),
}

/// Upstream resolver protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProtocol {
    /// Plain UDP/TCP DNS
    Plain,
    /// DNS over HTTPS (DoH)
    DoH,
    /// DNS over TLS (DoT)
    DoT,
    /// DNS over QUIC (DoQ)
    DoQ,
}

/// Upstream resolver configuration
#[derive(Debug, Clone)]
pub struct UpstreamResolver {
    pub name: String,
    pub address: String,
    pub protocol: UpstreamProtocol,
    pub weight: u32,
    pub timeout: Duration,
    pub enabled: bool,
}

impl UpstreamResolver {
    pub fn cloudflare_doh() -> Self {
        Self {
            name: "Cloudflare DoH".to_string(),
            address: "https://cloudflare-dns.com/dns-query".to_string(),
            protocol: UpstreamProtocol::DoH,
            weight: 100,
            timeout: Duration::from_secs(5),
            enabled: true,
        }
    }

    pub fn google_doh() -> Self {
        Self {
            name: "Google DoH".to_string(),
            address: "https://dns.google/dns-query".to_string(),
            protocol: UpstreamProtocol::DoH,
            weight: 100,
            timeout: Duration::from_secs(5),
            enabled: true,
        }
    }

    pub fn quad9_dot() -> Self {
        Self {
            name: "Quad9 DoT".to_string(),
            address: "dns.quad9.net:853".to_string(),
            protocol: UpstreamProtocol::DoT,
            weight: 100,
            timeout: Duration::from_secs(5),
            enabled: true,
        }
    }
}

/// Block list category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockCategory {
    Malware,
    Phishing,
    Ads,
    Tracking,
    Adult,
    Gambling,
    SocialMedia,
    Streaming,
    Custom,
}

/// Block action
#[derive(Debug, Clone)]
pub enum BlockAction {
    /// Return NXDOMAIN
    NxDomain,
    /// Return specific IP (sinkhole)
    Sinkhole(IpAddr),
    /// Return REFUSED
    Refused,
    /// Log only, allow query
    LogOnly,
}

/// Block rule
#[derive(Debug, Clone)]
pub struct BlockRule {
    pub pattern: String,
    pub category: BlockCategory,
    pub action: BlockAction,
    pub enabled: bool,
}

impl BlockRule {
    pub fn matches(&self, domain: &str) -> bool {
        if self.pattern.starts_with("*.") {
            domain.ends_with(&self.pattern[1..])
        } else if self.pattern.starts_with("||") {
            let base = &self.pattern[2..];
            domain == base || domain.ends_with(&format!(".{}", base))
        } else {
            domain == self.pattern
        }
    }
}

/// Query log entry
#[derive(Debug, Clone)]
pub struct QueryLog {
    pub id: u64,
    pub timestamp: u64,
    pub client_ip: IpAddr,
    pub domain: String,
    pub record_type: RecordType,
    pub response_code: ResponseCode,
    pub response_time_ms: u64,
    pub blocked: bool,
    pub block_reason: Option<String>,
    pub cached: bool,
    pub upstream_used: Option<String>,
}

/// Cache entry
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub response: DnsResponse,
    pub inserted_at: Instant,
    pub expires_at: Instant,
    pub hits: u32,
}

/// DNS proxy statistics
#[derive(Debug, Clone, Default)]
pub struct DnsStats {
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub cached_hits: u64,
    pub upstream_queries: u64,
    pub failed_queries: u64,
    pub avg_response_time_ms: u64,
    pub queries_by_type: HashMap<RecordType, u64>,
    pub queries_by_category: HashMap<BlockCategory, u64>,
}

/// DNS proxy configuration
#[derive(Debug, Clone)]
pub struct DnsProxyConfig {
    pub listen_address: SocketAddr,
    pub upstreams: Vec<UpstreamResolver>,
    pub cache_enabled: bool,
    pub cache_size: usize,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub negative_ttl: u32,
    pub log_queries: bool,
    pub log_retention_hours: u32,
    pub sinkhole_ip: IpAddr,
    pub block_categories: HashSet<BlockCategory>,
}

impl Default for DnsProxyConfig {
    fn default() -> Self {
        let mut block_categories = HashSet::new();
        block_categories.insert(BlockCategory::Malware);
        block_categories.insert(BlockCategory::Phishing);

        Self {
            listen_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 53),
            upstreams: vec![
                UpstreamResolver::cloudflare_doh(),
                UpstreamResolver::google_doh(),
            ],
            cache_enabled: true,
            cache_size: 10000,
            min_ttl: 60,
            max_ttl: 86400,
            negative_ttl: 300,
            log_queries: true,
            log_retention_hours: 24,
            sinkhole_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            block_categories,
        }
    }
}

/// Main DNS proxy
pub struct DnsProxy {
    config: DnsProxyConfig,
    block_rules: RwLock<Vec<BlockRule>>,
    cache: RwLock<HashMap<String, CacheEntry>>,
    query_log: RwLock<VecDeque<QueryLog>>,
    stats: RwLock<DnsStats>,
    query_counter: std::sync::atomic::AtomicU64,
}

impl DnsProxy {
    pub fn new(config: DnsProxyConfig) -> Self {
        Self {
            config,
            block_rules: RwLock::new(Self::load_default_rules()),
            cache: RwLock::new(HashMap::new()),
            query_log: RwLock::new(VecDeque::with_capacity(100000)),
            stats: RwLock::new(DnsStats::default()),
            query_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn load_default_rules() -> Vec<BlockRule> {
        vec![
            BlockRule {
                pattern: "||malware.test".to_string(),
                category: BlockCategory::Malware,
                action: BlockAction::NxDomain,
                enabled: true,
            },
            BlockRule {
                pattern: "||phishing.bad".to_string(),
                category: BlockCategory::Phishing,
                action: BlockAction::NxDomain,
                enabled: true,
            },
            BlockRule {
                pattern: "*.doubleclick.net".to_string(),
                category: BlockCategory::Ads,
                action: BlockAction::Sinkhole(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                enabled: true,
            },
            BlockRule {
                pattern: "||tracking.example.com".to_string(),
                category: BlockCategory::Tracking,
                action: BlockAction::NxDomain,
                enabled: true,
            },
        ]
    }

    /// Process a DNS query
    pub fn resolve(&self, query: &DnsQuery) -> DnsResponse {
        let start = Instant::now();
        let query_id = self.next_query_id();

        // Update stats
        self.update_stats(|s| {
            s.total_queries += 1;
            *s.queries_by_type.entry(query.record_type).or_insert(0) += 1;
        });

        // Check blocklist
        if let Some((rule, action)) = self.check_blocklist(&query.domain) {
            let response = self.create_blocked_response(query, &action);

            self.update_stats(|s| {
                s.blocked_queries += 1;
                *s.queries_by_category.entry(rule.category).or_insert(0) += 1;
            });

            self.log_query(QueryLog {
                id: query_id,
                timestamp: current_timestamp(),
                client_ip: query.client_ip,
                domain: query.domain.clone(),
                record_type: query.record_type,
                response_code: response.response_code,
                response_time_ms: start.elapsed().as_millis() as u64,
                blocked: true,
                block_reason: Some(format!("{:?}", rule.category)),
                cached: false,
                upstream_used: None,
            });

            return response;
        }

        // Check cache
        let cache_key = format!("{}:{:?}", query.domain, query.record_type);
        if self.config.cache_enabled {
            if let Some(cached) = self.get_cached(&cache_key) {
                self.update_stats(|s| s.cached_hits += 1);

                self.log_query(QueryLog {
                    id: query_id,
                    timestamp: current_timestamp(),
                    client_ip: query.client_ip,
                    domain: query.domain.clone(),
                    record_type: query.record_type,
                    response_code: cached.response_code,
                    response_time_ms: start.elapsed().as_millis() as u64,
                    blocked: false,
                    block_reason: None,
                    cached: true,
                    upstream_used: None,
                });

                return cached;
            }
        }

        // Query upstream
        let response = self.query_upstream(query);
        let elapsed = start.elapsed().as_millis() as u64;

        // Cache successful responses
        if response.response_code == ResponseCode::NoError && self.config.cache_enabled {
            self.cache_response(&cache_key, &response);
        }

        // Log query
        self.log_query(QueryLog {
            id: query_id,
            timestamp: current_timestamp(),
            client_ip: query.client_ip,
            domain: query.domain.clone(),
            record_type: query.record_type,
            response_code: response.response_code,
            response_time_ms: elapsed,
            blocked: false,
            block_reason: None,
            cached: false,
            upstream_used: Some("primary".to_string()),
        });

        response
    }

    /// Check if domain is blocked
    fn check_blocklist(&self, domain: &str) -> Option<(BlockRule, BlockAction)> {
        let rules = self.block_rules.read().unwrap();
        for rule in rules.iter() {
            if rule.enabled
                && self.config.block_categories.contains(&rule.category)
                && rule.matches(domain)
            {
                return Some((rule.clone(), rule.action.clone()));
            }
        }
        None
    }

    /// Create blocked response
    fn create_blocked_response(&self, query: &DnsQuery, action: &BlockAction) -> DnsResponse {
        match action {
            BlockAction::NxDomain => DnsResponse {
                id: query.id,
                domain: query.domain.clone(),
                record_type: query.record_type,
                response_code: ResponseCode::NxDomain,
                answers: Vec::new(),
                ttl: self.config.negative_ttl,
                authoritative: false,
                cached: false,
                response_time_ms: 0,
            },
            BlockAction::Sinkhole(ip) => DnsResponse {
                id: query.id,
                domain: query.domain.clone(),
                record_type: query.record_type,
                response_code: ResponseCode::NoError,
                answers: vec![DnsAnswer {
                    name: query.domain.clone(),
                    record_type: RecordType::A,
                    ttl: self.config.negative_ttl,
                    data: match ip {
                        IpAddr::V4(v4) => DnsData::A(*v4),
                        IpAddr::V6(_) => DnsData::Other(vec![]),
                    },
                }],
                ttl: self.config.negative_ttl,
                authoritative: false,
                cached: false,
                response_time_ms: 0,
            },
            BlockAction::Refused => DnsResponse {
                id: query.id,
                domain: query.domain.clone(),
                record_type: query.record_type,
                response_code: ResponseCode::Refused,
                answers: Vec::new(),
                ttl: 0,
                authoritative: false,
                cached: false,
                response_time_ms: 0,
            },
            BlockAction::LogOnly => {
                // Proceed with normal resolution
                self.query_upstream(query)
            }
        }
    }

    /// Query upstream resolvers
    fn query_upstream(&self, query: &DnsQuery) -> DnsResponse {
        self.update_stats(|s| s.upstream_queries += 1);

        // Select upstream (weighted random in production)
        let upstream = self
            .config
            .upstreams
            .iter()
            .find(|u| u.enabled)
            .unwrap_or(&self.config.upstreams[0]);

        // Simulate upstream query
        let response = self.simulate_upstream_response(query, upstream);

        // Apply TTL bounds
        let bounded_ttl = response
            .ttl
            .max(self.config.min_ttl)
            .min(self.config.max_ttl);

        DnsResponse {
            ttl: bounded_ttl,
            ..response
        }
    }

    /// Simulate upstream response
    fn simulate_upstream_response(
        &self,
        query: &DnsQuery,
        _upstream: &UpstreamResolver,
    ) -> DnsResponse {
        // In production, this would make actual DoH/DoT requests
        match query.record_type {
            RecordType::A => DnsResponse {
                id: query.id,
                domain: query.domain.clone(),
                record_type: query.record_type,
                response_code: ResponseCode::NoError,
                answers: vec![DnsAnswer {
                    name: query.domain.clone(),
                    record_type: RecordType::A,
                    ttl: 300,
                    data: DnsData::A(Ipv4Addr::new(93, 184, 216, 34)),
                }],
                ttl: 300,
                authoritative: false,
                cached: false,
                response_time_ms: 25,
            },
            _ => DnsResponse {
                id: query.id,
                domain: query.domain.clone(),
                record_type: query.record_type,
                response_code: ResponseCode::NoError,
                answers: Vec::new(),
                ttl: 300,
                authoritative: false,
                cached: false,
                response_time_ms: 30,
            },
        }
    }

    /// Get cached response
    fn get_cached(&self, key: &str) -> Option<DnsResponse> {
        let mut cache = self.cache.write().unwrap();
        if let Some(entry) = cache.get_mut(key) {
            if entry.expires_at > Instant::now() {
                entry.hits += 1;
                let mut response = entry.response.clone();
                response.cached = true;
                return Some(response);
            } else {
                cache.remove(key);
            }
        }
        None
    }

    /// Cache a response
    fn cache_response(&self, key: &str, response: &DnsResponse) {
        let mut cache = self.cache.write().unwrap();

        // Evict if full
        if cache.len() >= self.config.cache_size {
            // Simple LRU: remove first entry
            if let Some(first_key) = cache.keys().next().cloned() {
                cache.remove(&first_key);
            }
        }

        let now = Instant::now();
        cache.insert(
            key.to_string(),
            CacheEntry {
                response: response.clone(),
                inserted_at: now,
                expires_at: now + Duration::from_secs(response.ttl as u64),
                hits: 0,
            },
        );
    }

    /// Add a block rule
    pub fn add_block_rule(&self, rule: BlockRule) {
        self.block_rules.write().unwrap().push(rule);
    }

    /// Remove a block rule by pattern
    pub fn remove_block_rule(&self, pattern: &str) {
        let mut rules = self.block_rules.write().unwrap();
        rules.retain(|r| r.pattern != pattern);
    }

    /// Get recent query log
    pub fn get_query_log(&self, limit: usize) -> Vec<QueryLog> {
        let log = self.query_log.read().unwrap();
        log.iter().rev().take(limit).cloned().collect()
    }

    /// Get statistics
    pub fn get_stats(&self) -> DnsStats {
        self.stats.read().unwrap().clone()
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> CacheStats {
        let cache = self.cache.read().unwrap();
        let total_hits: u32 = cache.values().map(|e| e.hits).sum();
        CacheStats {
            entries: cache.len(),
            max_size: self.config.cache_size,
            total_hits,
        }
    }

    /// Flush cache
    pub fn flush_cache(&self) {
        self.cache.write().unwrap().clear();
    }

    /// Get top blocked domains
    pub fn get_top_blocked(&self, limit: usize) -> Vec<(String, u64)> {
        let log = self.query_log.read().unwrap();
        let mut counts: HashMap<String, u64> = HashMap::new();

        for entry in log.iter() {
            if entry.blocked {
                *counts.entry(entry.domain.clone()).or_insert(0) += 1;
            }
        }

        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.into_iter().take(limit).collect()
    }

    /// Get top queried domains
    pub fn get_top_domains(&self, limit: usize) -> Vec<(String, u64)> {
        let log = self.query_log.read().unwrap();
        let mut counts: HashMap<String, u64> = HashMap::new();

        for entry in log.iter() {
            *counts.entry(entry.domain.clone()).or_insert(0) += 1;
        }

        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.into_iter().take(limit).collect()
    }

    // Helper methods

    fn next_query_id(&self) -> u64 {
        self.query_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    fn log_query(&self, entry: QueryLog) {
        if !self.config.log_queries {
            return;
        }

        let mut log = self.query_log.write().unwrap();
        log.push_back(entry);

        // Trim old entries
        let cutoff = current_timestamp() - (self.config.log_retention_hours as u64 * 3600);
        while let Some(front) = log.front() {
            if front.timestamp < cutoff {
                log.pop_front();
            } else {
                break;
            }
        }
    }

    fn update_stats<F: FnOnce(&mut DnsStats)>(&self, f: F) {
        let mut stats = self.stats.write().unwrap();
        f(&mut stats);
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub entries: usize,
    pub max_size: usize,
    pub total_hits: u32,
}

// Helper functions

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn main() {
    println!("=== DNS Security Proxy ===\n");

    // Create configuration
    let mut config = DnsProxyConfig::default();
    config.block_categories.insert(BlockCategory::Ads);
    config.block_categories.insert(BlockCategory::Tracking);

    // Create proxy
    let proxy = DnsProxy::new(config);

    // Add custom block rule
    proxy.add_block_rule(BlockRule {
        pattern: "||badsite.com".to_string(),
        category: BlockCategory::Custom,
        action: BlockAction::NxDomain,
        enabled: true,
    });

    // Simulate queries
    println!("--- Processing Queries ---");

    let queries = vec![
        DnsQuery {
            id: 1,
            domain: "example.com".to_string(),
            record_type: RecordType::A,
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            timestamp: current_timestamp(),
            recursion_desired: true,
        },
        DnsQuery {
            id: 2,
            domain: "malware.test".to_string(),
            record_type: RecordType::A,
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            timestamp: current_timestamp(),
            recursion_desired: true,
        },
        DnsQuery {
            id: 3,
            domain: "ads.doubleclick.net".to_string(),
            record_type: RecordType::A,
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
            timestamp: current_timestamp(),
            recursion_desired: true,
        },
        DnsQuery {
            id: 4,
            domain: "example.com".to_string(), // Cached
            record_type: RecordType::A,
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102)),
            timestamp: current_timestamp(),
            recursion_desired: true,
        },
    ];

    for query in &queries {
        let response = proxy.resolve(query);
        println!(
            "{} -> {:?} ({} answers, {})",
            query.domain,
            response.response_code,
            response.answers.len(),
            if response.cached {
                "cached"
            } else {
                "upstream"
            }
        );
    }

    // Statistics
    println!("\n--- Statistics ---");
    let stats = proxy.get_stats();
    println!("Total queries: {}", stats.total_queries);
    println!("Blocked queries: {}", stats.blocked_queries);
    println!("Cache hits: {}", stats.cached_hits);
    println!("Upstream queries: {}", stats.upstream_queries);

    // Cache stats
    println!("\n--- Cache ---");
    let cache_stats = proxy.get_cache_stats();
    println!("Entries: {}/{}", cache_stats.entries, cache_stats.max_size);
    println!("Total hits: {}", cache_stats.total_hits);

    // Top blocked
    println!("\n--- Top Blocked Domains ---");
    for (domain, count) in proxy.get_top_blocked(5) {
        println!("  {} - {} queries", domain, count);
    }

    // Query log
    println!("\n--- Recent Queries ---");
    for entry in proxy.get_query_log(5) {
        println!(
            "  {} {} {:?} {}ms {}",
            entry.domain,
            if entry.blocked { "[BLOCKED]" } else { "" },
            entry.response_code,
            entry.response_time_ms,
            if entry.cached { "(cached)" } else { "" }
        );
    }

    // Upstreams
    println!("\n--- Upstream Resolvers ---");
    let config = DnsProxyConfig::default();
    for upstream in &config.upstreams {
        println!(
            "  {} ({:?}) - {}",
            upstream.name, upstream.protocol, upstream.address
        );
    }

    println!("\n=== DNS Proxy Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_proxy() -> DnsProxy {
        DnsProxy::new(DnsProxyConfig::default())
    }

    fn test_query(domain: &str) -> DnsQuery {
        DnsQuery {
            id: 1,
            domain: domain.to_string(),
            record_type: RecordType::A,
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            timestamp: current_timestamp(),
            recursion_desired: true,
        }
    }

    #[test]
    fn test_normal_resolution() {
        let proxy = test_proxy();
        let response = proxy.resolve(&test_query("example.com"));
        assert_eq!(response.response_code, ResponseCode::NoError);
    }

    #[test]
    fn test_blocked_domain() {
        let proxy = test_proxy();
        let response = proxy.resolve(&test_query("malware.test"));
        assert_eq!(response.response_code, ResponseCode::NxDomain);
    }

    #[test]
    fn test_cache() {
        let proxy = test_proxy();

        // First query
        let response1 = proxy.resolve(&test_query("example.com"));
        assert!(!response1.cached);

        // Second query (should be cached)
        let response2 = proxy.resolve(&test_query("example.com"));
        assert!(response2.cached);
    }

    #[test]
    fn test_add_block_rule() {
        let proxy = test_proxy();
        proxy.add_block_rule(BlockRule {
            pattern: "||custom.blocked".to_string(),
            category: BlockCategory::Custom,
            action: BlockAction::NxDomain,
            enabled: true,
        });

        // Enable custom category
        proxy.config.block_categories.insert(BlockCategory::Custom);

        let response = proxy.resolve(&test_query("custom.blocked"));
        // Note: Category must be enabled in config for block to work
    }

    #[test]
    fn test_block_rule_matching() {
        let rule = BlockRule {
            pattern: "*.example.com".to_string(),
            category: BlockCategory::Ads,
            action: BlockAction::NxDomain,
            enabled: true,
        };

        assert!(rule.matches("ads.example.com"));
        assert!(!rule.matches("example.com"));
    }

    #[test]
    fn test_subdomain_block() {
        let rule = BlockRule {
            pattern: "||blocked.com".to_string(),
            category: BlockCategory::Malware,
            action: BlockAction::NxDomain,
            enabled: true,
        };

        assert!(rule.matches("blocked.com"));
        assert!(rule.matches("sub.blocked.com"));
        assert!(!rule.matches("notblocked.com"));
    }

    #[test]
    fn test_statistics() {
        let proxy = test_proxy();
        proxy.resolve(&test_query("example.com"));
        proxy.resolve(&test_query("example.com"));

        let stats = proxy.get_stats();
        assert_eq!(stats.total_queries, 2);
        assert_eq!(stats.cached_hits, 1);
    }

    #[test]
    fn test_query_log() {
        let proxy = test_proxy();
        proxy.resolve(&test_query("example.com"));

        let log = proxy.get_query_log(10);
        assert!(!log.is_empty());
        assert_eq!(log[0].domain, "example.com");
    }

    #[test]
    fn test_flush_cache() {
        let proxy = test_proxy();
        proxy.resolve(&test_query("example.com"));

        assert!(proxy.get_cache_stats().entries > 0);
        proxy.flush_cache();
        assert_eq!(proxy.get_cache_stats().entries, 0);
    }

    #[test]
    fn test_record_type_conversion() {
        assert_eq!(RecordType::from_u16(1), RecordType::A);
        assert_eq!(RecordType::from_u16(28), RecordType::AAAA);
        assert_eq!(RecordType::A.to_u16(), 1);
    }

    #[test]
    fn test_upstream_resolvers() {
        let cloudflare = UpstreamResolver::cloudflare_doh();
        assert_eq!(cloudflare.protocol, UpstreamProtocol::DoH);

        let quad9 = UpstreamResolver::quad9_dot();
        assert_eq!(quad9.protocol, UpstreamProtocol::DoT);
    }
}
