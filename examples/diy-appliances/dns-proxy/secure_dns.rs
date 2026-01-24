//! Secure DNS Proxy
//!
//! DNS proxy with security features:
//! - DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) upstream
//! - Malicious domain blocking (sinkholing)
//! - Query logging and analysis
//! - Ad/tracker blocking
//! - Response caching

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// DNS Types
// ============================================================================

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
    SVCB,
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
            64 => Self::SVCB,
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
            Self::SVCB => 64,
            Self::Unknown(n) => *n,
        }
    }
}

/// DNS query
#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub id: u16,
    pub name: String,
    pub record_type: RecordType,
    pub client_addr: String,
    pub timestamp: u64,
}

/// DNS response
#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub id: u16,
    pub name: String,
    pub record_type: RecordType,
    pub ttl: u32,
    pub answers: Vec<DnsAnswer>,
    pub response_code: ResponseCode,
    pub cached: bool,
}

#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: RecordType,
    pub ttl: u32,
    pub data: AnswerData,
}

#[derive(Debug, Clone)]
pub enum AnswerData {
    A(IpAddr),
    AAAA(IpAddr),
    Cname(String),
    Mx { priority: u16, exchange: String },
    Txt(String),
    Other(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ResponseCode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    Other(u8),
}

// ============================================================================
// Blocklists
// ============================================================================

/// Domain blocklist manager
pub struct BlocklistManager {
    /// Exact domain matches
    exact_blocks: RwLock<HashSet<String>>,
    /// Wildcard blocks (subdomains)
    wildcard_blocks: RwLock<HashSet<String>>,
    /// Regex patterns (expensive, use sparingly)
    regex_patterns: RwLock<Vec<(String, regex_lite::Regex)>>,
    /// Whitelist (overrides blocks)
    whitelist: RwLock<HashSet<String>>,
    /// Block categories
    categories: RwLock<HashMap<String, HashSet<String>>>,
}

// Simple regex implementation for demo
mod regex_lite {
    pub struct Regex {
        pattern: String,
    }

    impl Regex {
        pub fn new(pattern: &str) -> Result<Self, &'static str> {
            Ok(Self {
                pattern: pattern.to_string(),
            })
        }

        pub fn is_match(&self, text: &str) -> bool {
            // Very simplified matching
            if self.pattern.starts_with(".*") {
                let suffix = &self.pattern[2..];
                text.ends_with(suffix)
            } else if self.pattern.ends_with(".*") {
                let prefix = &self.pattern[..self.pattern.len() - 2];
                text.starts_with(prefix)
            } else {
                text.contains(&self.pattern)
            }
        }
    }
}

impl BlocklistManager {
    pub fn new() -> Self {
        Self {
            exact_blocks: RwLock::new(HashSet::new()),
            wildcard_blocks: RwLock::new(HashSet::new()),
            regex_patterns: RwLock::new(Vec::new()),
            whitelist: RwLock::new(HashSet::new()),
            categories: RwLock::new(HashMap::new()),
        }
    }

    /// Add domains to blocklist
    pub fn add_blocked_domains(&self, domains: &[&str]) {
        let mut blocks = self.exact_blocks.write().unwrap();
        for domain in domains {
            blocks.insert(domain.to_lowercase());
        }
    }

    /// Add wildcard blocks (blocks domain and all subdomains)
    pub fn add_wildcard_blocks(&self, domains: &[&str]) {
        let mut blocks = self.wildcard_blocks.write().unwrap();
        for domain in domains {
            blocks.insert(domain.to_lowercase());
        }
    }

    /// Add to whitelist
    pub fn add_whitelist(&self, domains: &[&str]) {
        let mut whitelist = self.whitelist.write().unwrap();
        for domain in domains {
            whitelist.insert(domain.to_lowercase());
        }
    }

    /// Load blocklist from category
    pub fn load_category(&self, category: &str, domains: Vec<String>) {
        let mut categories = self.categories.write().unwrap();
        categories.insert(category.to_string(), domains.into_iter().collect());

        // Also add to main blocklist
        let blocks = categories.get(category).unwrap();
        let mut exact = self.exact_blocks.write().unwrap();
        exact.extend(blocks.clone());
    }

    /// Check if domain is blocked
    pub fn is_blocked(&self, domain: &str) -> Option<BlockReason> {
        let domain_lower = domain.to_lowercase();

        // Check whitelist first
        {
            let whitelist = self.whitelist.read().unwrap();
            if whitelist.contains(&domain_lower) {
                return None;
            }
        }

        // Check exact match
        {
            let blocks = self.exact_blocks.read().unwrap();
            if blocks.contains(&domain_lower) {
                return Some(BlockReason::ExactMatch);
            }
        }

        // Check wildcard (suffix match)
        {
            let wildcards = self.wildcard_blocks.read().unwrap();
            for wildcard in wildcards.iter() {
                if domain_lower == *wildcard || domain_lower.ends_with(&format!(".{}", wildcard)) {
                    return Some(BlockReason::WildcardMatch(wildcard.clone()));
                }
            }
        }

        // Check regex patterns
        {
            let patterns = self.regex_patterns.read().unwrap();
            for (name, regex) in patterns.iter() {
                if regex.is_match(&domain_lower) {
                    return Some(BlockReason::RegexMatch(name.clone()));
                }
            }
        }

        None
    }

    /// Get statistics
    pub fn stats(&self) -> BlocklistStats {
        BlocklistStats {
            exact_count: self.exact_blocks.read().unwrap().len(),
            wildcard_count: self.wildcard_blocks.read().unwrap().len(),
            regex_count: self.regex_patterns.read().unwrap().len(),
            whitelist_count: self.whitelist.read().unwrap().len(),
        }
    }
}

impl Default for BlocklistManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub enum BlockReason {
    ExactMatch,
    WildcardMatch(String),
    RegexMatch(String),
    Category(String),
}

#[derive(Debug)]
pub struct BlocklistStats {
    pub exact_count: usize,
    pub wildcard_count: usize,
    pub regex_count: usize,
    pub whitelist_count: usize,
}

// ============================================================================
// DNS Cache
// ============================================================================

/// Cached DNS response
#[derive(Debug, Clone)]
struct CacheEntry {
    response: DnsResponse,
    expires_at: Instant,
    hits: u64,
}

/// DNS cache with TTL
pub struct DnsCache {
    entries: Mutex<HashMap<(String, RecordType), CacheEntry>>,
    max_entries: usize,
    min_ttl: Duration,
    max_ttl: Duration,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries,
            min_ttl: Duration::from_secs(60),
            max_ttl: Duration::from_secs(86400),
        }
    }

    /// Get cached response
    pub fn get(&self, name: &str, record_type: RecordType) -> Option<DnsResponse> {
        let mut entries = self.entries.lock().unwrap();
        let key = (name.to_lowercase(), record_type);

        if let Some(entry) = entries.get_mut(&key) {
            if Instant::now() < entry.expires_at {
                entry.hits += 1;
                let mut response = entry.response.clone();
                response.cached = true;
                return Some(response);
            } else {
                entries.remove(&key);
            }
        }
        None
    }

    /// Store response in cache
    pub fn put(&self, response: &DnsResponse) {
        let mut entries = self.entries.lock().unwrap();

        // Evict if full
        if entries.len() >= self.max_entries {
            // Remove oldest/least used entry
            if let Some(key) = entries
                .iter()
                .min_by_key(|(_, v)| (v.hits, v.expires_at))
                .map(|(k, _)| k.clone())
            {
                entries.remove(&key);
            }
        }

        let ttl = Duration::from_secs(response.ttl as u64)
            .max(self.min_ttl)
            .min(self.max_ttl);

        let key = (response.name.to_lowercase(), response.record_type);
        entries.insert(
            key,
            CacheEntry {
                response: response.clone(),
                expires_at: Instant::now() + ttl,
                hits: 0,
            },
        );
    }

    /// Clear all cached entries
    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let entries = self.entries.lock().unwrap();
        CacheStats {
            entries: entries.len(),
            total_hits: entries.values().map(|e| e.hits).sum(),
        }
    }
}

#[derive(Debug)]
pub struct CacheStats {
    pub entries: usize,
    pub total_hits: u64,
}

// ============================================================================
// Query Logging
// ============================================================================

/// Query log entry
#[derive(Debug, Clone)]
pub struct QueryLog {
    pub timestamp: u64,
    pub client: String,
    pub query_name: String,
    pub query_type: RecordType,
    pub response_code: ResponseCode,
    pub blocked: bool,
    pub block_reason: Option<String>,
    pub cached: bool,
    pub upstream: Option<String>,
    pub duration_us: u64,
}

impl QueryLog {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"timestamp":{},"client":"{}","query":"{}","type":{:?},"rcode":"{:?}","blocked":{},"cached":{},"duration_us":{}}}"#,
            self.timestamp,
            self.client,
            self.query_name,
            self.query_type,
            self.response_code,
            self.blocked,
            self.cached,
            self.duration_us,
        )
    }
}

/// Query logger
pub struct QueryLogger {
    logs: Mutex<Vec<QueryLog>>,
    max_logs: usize,
    /// Query counts by domain
    domain_counts: Mutex<HashMap<String, u64>>,
    /// Blocked query counts
    blocked_counts: Mutex<HashMap<String, u64>>,
}

impl QueryLogger {
    pub fn new(max_logs: usize) -> Self {
        Self {
            logs: Mutex::new(Vec::with_capacity(max_logs)),
            max_logs,
            domain_counts: Mutex::new(HashMap::new()),
            blocked_counts: Mutex::new(HashMap::new()),
        }
    }

    pub fn log(&self, entry: QueryLog) {
        // Update domain counts
        {
            let mut counts = self.domain_counts.lock().unwrap();
            *counts.entry(entry.query_name.clone()).or_default() += 1;
        }

        // Update blocked counts
        if entry.blocked {
            let mut counts = self.blocked_counts.lock().unwrap();
            *counts.entry(entry.query_name.clone()).or_default() += 1;
        }

        // Store log entry
        let mut logs = self.logs.lock().unwrap();
        if logs.len() >= self.max_logs {
            logs.remove(0);
        }
        logs.push(entry);
    }

    pub fn recent(&self, count: usize) -> Vec<QueryLog> {
        self.logs
            .lock()
            .unwrap()
            .iter()
            .rev()
            .take(count)
            .cloned()
            .collect()
    }

    /// Get top queried domains
    pub fn top_domains(&self, count: usize) -> Vec<(String, u64)> {
        let counts = self.domain_counts.lock().unwrap();
        let mut sorted: Vec<_> = counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(count);
        sorted
    }

    /// Get top blocked domains
    pub fn top_blocked(&self, count: usize) -> Vec<(String, u64)> {
        let counts = self.blocked_counts.lock().unwrap();
        let mut sorted: Vec<_> = counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(count);
        sorted
    }
}

// ============================================================================
// Upstream Resolvers
// ============================================================================

/// Upstream DNS resolver configuration
#[derive(Debug, Clone)]
pub struct UpstreamResolver {
    pub name: String,
    pub resolver_type: ResolverType,
    pub address: String,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ResolverType {
    /// Plain DNS (UDP/TCP port 53)
    Plain,
    /// DNS-over-TLS (port 853)
    DoT,
    /// DNS-over-HTTPS
    DoH,
    /// DNS-over-QUIC
    DoQ,
}

impl UpstreamResolver {
    pub fn cloudflare_doh() -> Self {
        Self {
            name: "Cloudflare DoH".to_string(),
            resolver_type: ResolverType::DoH,
            address: "https://cloudflare-dns.com/dns-query".to_string(),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn google_doh() -> Self {
        Self {
            name: "Google DoH".to_string(),
            resolver_type: ResolverType::DoH,
            address: "https://dns.google/dns-query".to_string(),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn quad9_dot() -> Self {
        Self {
            name: "Quad9 DoT".to_string(),
            resolver_type: ResolverType::DoT,
            address: "dns.quad9.net:853".to_string(),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn local() -> Self {
        Self {
            name: "Local".to_string(),
            resolver_type: ResolverType::Plain,
            address: "127.0.0.1:53".to_string(),
            timeout: Duration::from_secs(2),
        }
    }
}

// ============================================================================
// DNS Proxy
// ============================================================================

/// DNS proxy configuration
#[derive(Debug, Clone)]
pub struct DnsProxyConfig {
    /// Listen address
    pub listen_addr: String,
    /// Listen port
    pub listen_port: u16,
    /// Enable DNS-over-HTTPS server
    pub enable_doh: bool,
    /// Enable DNS-over-TLS server
    pub enable_dot: bool,
    /// Sinkhole IP for blocked domains
    pub sinkhole_ipv4: IpAddr,
    pub sinkhole_ipv6: IpAddr,
    /// Cache configuration
    pub cache_size: usize,
    /// Query log size
    pub log_size: usize,
}

impl Default for DnsProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0".to_string(),
            listen_port: 53,
            enable_doh: false,
            enable_dot: false,
            sinkhole_ipv4: "0.0.0.0".parse().unwrap(),
            sinkhole_ipv6: "::".parse().unwrap(),
            cache_size: 10000,
            log_size: 100000,
        }
    }
}

/// Complete DNS proxy
pub struct DnsProxy {
    config: DnsProxyConfig,
    blocklist: Arc<BlocklistManager>,
    cache: Arc<DnsCache>,
    logger: Arc<QueryLogger>,
    upstreams: Vec<UpstreamResolver>,
}

impl DnsProxy {
    pub fn new(config: DnsProxyConfig) -> Self {
        Self {
            cache: Arc::new(DnsCache::new(config.cache_size)),
            logger: Arc::new(QueryLogger::new(config.log_size)),
            blocklist: Arc::new(BlocklistManager::new()),
            upstreams: vec![
                UpstreamResolver::cloudflare_doh(),
                UpstreamResolver::quad9_dot(),
            ],
            config,
        }
    }

    /// Handle a DNS query
    pub fn handle_query(&self, query: &DnsQuery) -> DnsResponse {
        let start = Instant::now();

        // Check blocklist
        if let Some(reason) = self.blocklist.is_blocked(&query.name) {
            let response = self.create_sinkhole_response(query);

            self.logger.log(QueryLog {
                timestamp: current_timestamp(),
                client: query.client_addr.clone(),
                query_name: query.name.clone(),
                query_type: query.record_type,
                response_code: ResponseCode::NoError,
                blocked: true,
                block_reason: Some(format!("{:?}", reason)),
                cached: false,
                upstream: None,
                duration_us: start.elapsed().as_micros() as u64,
            });

            return response;
        }

        // Check cache
        if let Some(cached) = self.cache.get(&query.name, query.record_type) {
            self.logger.log(QueryLog {
                timestamp: current_timestamp(),
                client: query.client_addr.clone(),
                query_name: query.name.clone(),
                query_type: query.record_type,
                response_code: cached.response_code,
                blocked: false,
                block_reason: None,
                cached: true,
                upstream: None,
                duration_us: start.elapsed().as_micros() as u64,
            });

            return cached;
        }

        // Forward to upstream
        let (response, upstream_name) = self.forward_to_upstream(query);

        // Cache the response
        if response.response_code == ResponseCode::NoError {
            self.cache.put(&response);
        }

        self.logger.log(QueryLog {
            timestamp: current_timestamp(),
            client: query.client_addr.clone(),
            query_name: query.name.clone(),
            query_type: query.record_type,
            response_code: response.response_code,
            blocked: false,
            block_reason: None,
            cached: false,
            upstream: Some(upstream_name),
            duration_us: start.elapsed().as_micros() as u64,
        });

        response
    }

    fn create_sinkhole_response(&self, query: &DnsQuery) -> DnsResponse {
        let answer_data = match query.record_type {
            RecordType::A => AnswerData::A(self.config.sinkhole_ipv4),
            RecordType::AAAA => AnswerData::AAAA(self.config.sinkhole_ipv6),
            _ => AnswerData::Other(vec![]),
        };

        DnsResponse {
            id: query.id,
            name: query.name.clone(),
            record_type: query.record_type,
            ttl: 300,
            answers: vec![DnsAnswer {
                name: query.name.clone(),
                record_type: query.record_type,
                ttl: 300,
                data: answer_data,
            }],
            response_code: ResponseCode::NoError,
            cached: false,
        }
    }

    fn forward_to_upstream(&self, query: &DnsQuery) -> (DnsResponse, String) {
        // Simulate upstream resolution
        let upstream = &self.upstreams[0];

        // In production, this would actually send the query
        let response = DnsResponse {
            id: query.id,
            name: query.name.clone(),
            record_type: query.record_type,
            ttl: 300,
            answers: vec![DnsAnswer {
                name: query.name.clone(),
                record_type: query.record_type,
                ttl: 300,
                data: AnswerData::A("93.184.216.34".parse().unwrap()),
            }],
            response_code: ResponseCode::NoError,
            cached: false,
        };

        (response, upstream.name.clone())
    }

    /// Get blocklist manager
    pub fn blocklist(&self) -> Arc<BlocklistManager> {
        Arc::clone(&self.blocklist)
    }

    /// Get query logger
    pub fn logger(&self) -> Arc<QueryLogger> {
        Arc::clone(&self.logger)
    }

    /// Get cache
    pub fn cache(&self) -> Arc<DnsCache> {
        Arc::clone(&self.cache)
    }

    /// Get statistics
    pub fn stats(&self) -> ProxyStats {
        let cache_stats = self.cache.stats();
        let blocklist_stats = self.blocklist.stats();

        ProxyStats {
            cache_entries: cache_stats.entries,
            cache_hits: cache_stats.total_hits,
            blocklist_domains: blocklist_stats.exact_count + blocklist_stats.wildcard_count,
        }
    }
}

#[derive(Debug)]
pub struct ProxyStats {
    pub cache_entries: usize,
    pub cache_hits: u64,
    pub blocklist_domains: usize,
}

// ============================================================================
// Utilities
// ============================================================================

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ============================================================================
// Main and Tests
// ============================================================================

fn main() {
    println!("Secure DNS Proxy Example\n");

    // Create DNS proxy
    let config = DnsProxyConfig {
        listen_addr: "0.0.0.0".to_string(),
        listen_port: 5353,
        sinkhole_ipv4: "0.0.0.0".parse().unwrap(),
        ..Default::default()
    };

    let proxy = DnsProxy::new(config);

    // Configure blocklists
    println!("=== Configuring Blocklists ===\n");

    // Add ad/tracker domains
    proxy.blocklist().add_blocked_domains(&[
        "ads.example.com",
        "tracker.example.com",
        "analytics.example.com",
    ]);

    // Add malicious domains
    proxy
        .blocklist()
        .add_wildcard_blocks(&["malware.com", "phishing.net"]);

    // Whitelist legitimate domains
    proxy.blocklist().add_whitelist(&[
        "safe.malware.com", // False positive
    ]);

    println!("Blocklist stats: {:?}\n", proxy.blocklist().stats());

    // Process some queries
    println!("=== Processing Queries ===\n");

    let queries = vec![
        DnsQuery {
            id: 1,
            name: "www.example.com".to_string(),
            record_type: RecordType::A,
            client_addr: "192.168.1.100".to_string(),
            timestamp: current_timestamp(),
        },
        DnsQuery {
            id: 2,
            name: "ads.example.com".to_string(),
            record_type: RecordType::A,
            client_addr: "192.168.1.100".to_string(),
            timestamp: current_timestamp(),
        },
        DnsQuery {
            id: 3,
            name: "evil.malware.com".to_string(),
            record_type: RecordType::A,
            client_addr: "192.168.1.101".to_string(),
            timestamp: current_timestamp(),
        },
        DnsQuery {
            id: 4,
            name: "safe.malware.com".to_string(),
            record_type: RecordType::A,
            client_addr: "192.168.1.102".to_string(),
            timestamp: current_timestamp(),
        },
        DnsQuery {
            id: 5,
            name: "www.example.com".to_string(), // Cached
            record_type: RecordType::A,
            client_addr: "192.168.1.103".to_string(),
            timestamp: current_timestamp(),
        },
    ];

    for query in &queries {
        let response = proxy.handle_query(query);
        println!("Query: {} ({:?})", query.name, query.record_type);
        println!("  Response: {:?}", response.response_code);
        println!("  Cached: {}", response.cached);
        if !response.answers.is_empty() {
            println!("  Answer: {:?}", response.answers[0].data);
        }
        println!();
    }

    // Show statistics
    println!("=== Statistics ===\n");
    println!("Proxy stats: {:?}", proxy.stats());
    println!("Cache stats: {:?}", proxy.cache().stats());

    // Show query logs
    println!("\n=== Recent Query Logs ===\n");
    for log in proxy.logger().recent(10) {
        println!("  {}", log.to_json());
    }

    // Top domains
    println!("\n=== Top Queried Domains ===");
    for (domain, count) in proxy.logger().top_domains(5) {
        println!("  {} - {} queries", domain, count);
    }

    // Top blocked
    println!("\n=== Top Blocked Domains ===");
    for (domain, count) in proxy.logger().top_blocked(5) {
        println!("  {} - {} blocks", domain, count);
    }

    // Available upstreams
    println!("\n=== Available Upstream Resolvers ===");
    let upstreams = [
        UpstreamResolver::cloudflare_doh(),
        UpstreamResolver::google_doh(),
        UpstreamResolver::quad9_dot(),
    ];
    for upstream in &upstreams {
        println!(
            "  {} ({:?}) - {}",
            upstream.name, upstream.resolver_type, upstream.address
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocklist_exact_match() {
        let blocklist = BlocklistManager::new();
        blocklist.add_blocked_domains(&["blocked.com"]);

        assert!(blocklist.is_blocked("blocked.com").is_some());
        assert!(blocklist.is_blocked("notblocked.com").is_none());
    }

    #[test]
    fn test_blocklist_wildcard() {
        let blocklist = BlocklistManager::new();
        blocklist.add_wildcard_blocks(&["malware.com"]);

        assert!(blocklist.is_blocked("malware.com").is_some());
        assert!(blocklist.is_blocked("sub.malware.com").is_some());
        assert!(blocklist.is_blocked("safe.com").is_none());
    }

    #[test]
    fn test_whitelist_override() {
        let blocklist = BlocklistManager::new();
        blocklist.add_wildcard_blocks(&["example.com"]);
        blocklist.add_whitelist(&["safe.example.com"]);

        assert!(blocklist.is_blocked("evil.example.com").is_some());
        assert!(blocklist.is_blocked("safe.example.com").is_none());
    }

    #[test]
    fn test_cache() {
        let cache = DnsCache::new(100);

        let response = DnsResponse {
            id: 1,
            name: "test.com".to_string(),
            record_type: RecordType::A,
            ttl: 300,
            answers: vec![],
            response_code: ResponseCode::NoError,
            cached: false,
        };

        cache.put(&response);

        let cached = cache.get("test.com", RecordType::A);
        assert!(cached.is_some());
        assert!(cached.unwrap().cached);
    }

    #[test]
    fn test_cache_miss() {
        let cache = DnsCache::new(100);
        assert!(cache.get("notcached.com", RecordType::A).is_none());
    }

    #[test]
    fn test_record_type_conversion() {
        assert_eq!(RecordType::A.to_u16(), 1);
        assert_eq!(RecordType::from_u16(1), RecordType::A);
        assert_eq!(RecordType::AAAA.to_u16(), 28);
    }

    #[test]
    fn test_upstream_resolvers() {
        let cf = UpstreamResolver::cloudflare_doh();
        assert_eq!(cf.resolver_type, ResolverType::DoH);

        let q9 = UpstreamResolver::quad9_dot();
        assert_eq!(q9.resolver_type, ResolverType::DoT);
    }

    #[test]
    fn test_proxy_blocked_query() {
        let proxy = DnsProxy::new(DnsProxyConfig::default());
        proxy.blocklist().add_blocked_domains(&["blocked.test"]);

        let query = DnsQuery {
            id: 1,
            name: "blocked.test".to_string(),
            record_type: RecordType::A,
            client_addr: "127.0.0.1".to_string(),
            timestamp: 0,
        };

        let response = proxy.handle_query(&query);
        // Should return sinkhole response
        assert_eq!(response.response_code, ResponseCode::NoError);
    }

    #[test]
    fn test_query_logger() {
        let logger = QueryLogger::new(100);

        logger.log(QueryLog {
            timestamp: 0,
            client: "127.0.0.1".to_string(),
            query_name: "test.com".to_string(),
            query_type: RecordType::A,
            response_code: ResponseCode::NoError,
            blocked: false,
            block_reason: None,
            cached: false,
            upstream: Some("Test".to_string()),
            duration_us: 100,
        });

        let recent = logger.recent(10);
        assert_eq!(recent.len(), 1);

        let top = logger.top_domains(10);
        assert_eq!(top[0].0, "test.com");
    }
}
