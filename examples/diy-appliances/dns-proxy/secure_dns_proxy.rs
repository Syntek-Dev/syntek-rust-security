//! Secure DNS Proxy with DoH/DoT Support
//!
//! This example demonstrates a secure DNS proxy implementation with DNS-over-HTTPS
//! (DoH) and DNS-over-TLS (DoT) support, DNS sinkholing for malicious domains,
//! query logging, and ad/tracker blocking capabilities.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// DNS Record Types
// ============================================================================

/// DNS record type
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    PTR,
    SOA,
    TXT,
    SRV,
    CAA,
    HTTPS,
    SVCB,
    Unknown(u16),
}

impl RecordType {
    pub fn from_u16(val: u16) -> Self {
        match val {
            1 => RecordType::A,
            28 => RecordType::AAAA,
            5 => RecordType::CNAME,
            15 => RecordType::MX,
            2 => RecordType::NS,
            12 => RecordType::PTR,
            6 => RecordType::SOA,
            16 => RecordType::TXT,
            33 => RecordType::SRV,
            257 => RecordType::CAA,
            65 => RecordType::HTTPS,
            64 => RecordType::SVCB,
            other => RecordType::Unknown(other),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::AAAA => 28,
            RecordType::CNAME => 5,
            RecordType::MX => 15,
            RecordType::NS => 2,
            RecordType::PTR => 12,
            RecordType::SOA => 6,
            RecordType::TXT => 16,
            RecordType::SRV => 33,
            RecordType::CAA => 257,
            RecordType::HTTPS => 65,
            RecordType::SVCB => 64,
            RecordType::Unknown(n) => *n,
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::Unknown(n) => write!(f, "TYPE{}", n),
            _ => write!(f, "{:?}", self),
        }
    }
}

/// DNS response code
#[derive(Clone, Debug, PartialEq)]
pub enum ResponseCode {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
    YXDomain,
    YXRRSet,
    NXRRSet,
    NotAuth,
    NotZone,
    Unknown(u8),
}

impl ResponseCode {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormErr,
            2 => ResponseCode::ServFail,
            3 => ResponseCode::NXDomain,
            4 => ResponseCode::NotImp,
            5 => ResponseCode::Refused,
            6 => ResponseCode::YXDomain,
            7 => ResponseCode::YXRRSet,
            8 => ResponseCode::NXRRSet,
            9 => ResponseCode::NotAuth,
            10 => ResponseCode::NotZone,
            other => ResponseCode::Unknown(other),
        }
    }
}

// ============================================================================
// DNS Query and Response
// ============================================================================

/// DNS query
#[derive(Clone, Debug)]
pub struct DnsQuery {
    pub id: u16,
    pub name: String,
    pub record_type: RecordType,
    pub class: u16,
    pub recursion_desired: bool,
    pub client_ip: IpAddr,
    pub timestamp: SystemTime,
    pub edns: Option<EdnsOptions>,
}

/// EDNS options
#[derive(Clone, Debug)]
pub struct EdnsOptions {
    pub udp_payload_size: u16,
    pub dnssec_ok: bool,
    pub client_subnet: Option<ClientSubnet>,
}

#[derive(Clone, Debug)]
pub struct ClientSubnet {
    pub family: u16,
    pub source_prefix: u8,
    pub scope_prefix: u8,
    pub address: Vec<u8>,
}

/// DNS response
#[derive(Clone, Debug)]
pub struct DnsResponse {
    pub id: u16,
    pub response_code: ResponseCode,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_available: bool,
    pub answers: Vec<DnsRecord>,
    pub authority: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
    pub response_time: Duration,
}

/// DNS record
#[derive(Clone, Debug)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: RecordType,
    pub class: u16,
    pub ttl: u32,
    pub data: RecordData,
}

/// Record data variants
#[derive(Clone, Debug)]
pub enum RecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    MX {
        preference: u16,
        exchange: String,
    },
    NS(String),
    PTR(String),
    TXT(Vec<String>),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    CAA {
        flags: u8,
        tag: String,
        value: String,
    },
    Unknown(Vec<u8>),
}

// ============================================================================
// Upstream DNS Providers
// ============================================================================

/// Upstream DNS provider
#[derive(Clone, Debug)]
pub struct UpstreamProvider {
    pub name: String,
    pub provider_type: ProviderType,
    pub endpoints: Vec<String>,
    pub priority: u8,
    pub weight: u16,
    pub health_check_interval: Duration,
    pub timeout: Duration,
    pub is_healthy: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProviderType {
    Dns, // Traditional UDP/TCP DNS
    DoT, // DNS-over-TLS
    DoH, // DNS-over-HTTPS
    DoQ, // DNS-over-QUIC
}

impl UpstreamProvider {
    pub fn cloudflare_doh() -> Self {
        Self {
            name: "Cloudflare DoH".to_string(),
            provider_type: ProviderType::DoH,
            endpoints: vec![
                "https://cloudflare-dns.com/dns-query".to_string(),
                "https://1.1.1.1/dns-query".to_string(),
            ],
            priority: 1,
            weight: 100,
            health_check_interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            is_healthy: true,
        }
    }

    pub fn cloudflare_dot() -> Self {
        Self {
            name: "Cloudflare DoT".to_string(),
            provider_type: ProviderType::DoT,
            endpoints: vec!["1.1.1.1:853".to_string(), "1.0.0.1:853".to_string()],
            priority: 2,
            weight: 100,
            health_check_interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            is_healthy: true,
        }
    }

    pub fn google_doh() -> Self {
        Self {
            name: "Google DoH".to_string(),
            provider_type: ProviderType::DoH,
            endpoints: vec!["https://dns.google/dns-query".to_string()],
            priority: 2,
            weight: 50,
            health_check_interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            is_healthy: true,
        }
    }

    pub fn quad9_doh() -> Self {
        Self {
            name: "Quad9 DoH".to_string(),
            provider_type: ProviderType::DoH,
            endpoints: vec!["https://dns.quad9.net/dns-query".to_string()],
            priority: 3,
            weight: 50,
            health_check_interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            is_healthy: true,
        }
    }
}

// ============================================================================
// Blocklists and Filtering
// ============================================================================

/// Domain blocklist
#[derive(Clone, Debug)]
pub struct Blocklist {
    pub name: String,
    pub source: BlocklistSource,
    pub domains: HashSet<String>,
    pub last_updated: SystemTime,
    pub update_interval: Duration,
    pub enabled: bool,
}

#[derive(Clone, Debug)]
pub enum BlocklistSource {
    Url(String),
    File(String),
    Builtin,
    Custom,
}

impl Blocklist {
    pub fn ads_trackers() -> Self {
        let mut domains = HashSet::new();
        // Sample ad/tracker domains
        for domain in &[
            "googleadservices.com",
            "doubleclick.net",
            "googlesyndication.com",
            "googletagmanager.com",
            "google-analytics.com",
            "facebook.com/tr",
            "connect.facebook.net",
            "analytics.twitter.com",
            "ads.linkedin.com",
            "ad.doubleclick.net",
            "pagead2.googlesyndication.com",
            "adservice.google.com",
            "adsymptotic.com",
            "adnxs.com",
            "adsrvr.org",
            "advertising.com",
            "taboola.com",
            "outbrain.com",
            "criteo.com",
            "moatads.com",
        ] {
            domains.insert(domain.to_string());
        }

        Self {
            name: "Ads & Trackers".to_string(),
            source: BlocklistSource::Builtin,
            domains,
            last_updated: SystemTime::now(),
            update_interval: Duration::from_secs(86400),
            enabled: true,
        }
    }

    pub fn malware() -> Self {
        let mut domains = HashSet::new();
        // Sample malware domains (for demonstration)
        for domain in &[
            "malware.example.com",
            "phishing.example.net",
            "ransomware.example.org",
            "c2.badactor.com",
            "exploit-kit.example.com",
        ] {
            domains.insert(domain.to_string());
        }

        Self {
            name: "Malware".to_string(),
            source: BlocklistSource::Builtin,
            domains,
            last_updated: SystemTime::now(),
            update_interval: Duration::from_secs(3600),
            enabled: true,
        }
    }

    pub fn contains(&self, domain: &str) -> bool {
        if !self.enabled {
            return false;
        }

        // Check exact match
        if self.domains.contains(domain) {
            return true;
        }

        // Check parent domains
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 0..parts.len() {
            let parent = parts[i..].join(".");
            if self.domains.contains(&parent) {
                return true;
            }
        }

        false
    }
}

/// Allowlist for whitelisted domains
#[derive(Clone, Debug, Default)]
pub struct Allowlist {
    pub domains: HashSet<String>,
}

impl Allowlist {
    pub fn contains(&self, domain: &str) -> bool {
        self.domains.contains(domain)
    }

    pub fn add(&mut self, domain: &str) {
        self.domains.insert(domain.to_string());
    }
}

/// Block action
#[derive(Clone, Debug, PartialEq)]
pub enum BlockAction {
    NXDomain,         // Return NXDOMAIN
    Refused,          // Return REFUSED
    Sinkhole(IpAddr), // Return sinkhole IP
    NoData,           // Return NODATA (empty answer)
    Custom(DnsResponse),
}

impl Default for BlockAction {
    fn default() -> Self {
        BlockAction::NXDomain
    }
}

// ============================================================================
// DNS Cache
// ============================================================================

/// DNS cache entry
#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub response: DnsResponse,
    pub inserted_at: SystemTime,
    pub expires_at: SystemTime,
    pub hit_count: u64,
}

impl CacheEntry {
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }

    pub fn remaining_ttl(&self) -> u32 {
        let now = SystemTime::now();
        if now > self.expires_at {
            0
        } else {
            self.expires_at
                .duration_since(now)
                .unwrap_or_default()
                .as_secs() as u32
        }
    }
}

/// DNS cache
pub struct DnsCache {
    entries: Arc<RwLock<HashMap<String, CacheEntry>>>,
    max_size: usize,
    min_ttl: u32,
    max_ttl: u32,
    stats: CacheStats,
}

#[derive(Default)]
pub struct CacheStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: AtomicU64,
}

impl DnsCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            max_size,
            min_ttl: 60,
            max_ttl: 86400,
            stats: CacheStats::default(),
        }
    }

    pub fn cache_key(name: &str, record_type: &RecordType) -> String {
        format!("{}:{}", name.to_lowercase(), record_type)
    }

    pub fn get(&self, name: &str, record_type: &RecordType) -> Option<DnsResponse> {
        let key = Self::cache_key(name, record_type);
        let entries = self.entries.read().unwrap();

        if let Some(entry) = entries.get(&key) {
            if !entry.is_expired() {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);

                // Adjust TTLs in response
                let mut response = entry.response.clone();
                let remaining = entry.remaining_ttl();
                for record in &mut response.answers {
                    record.ttl = remaining;
                }

                return Some(response);
            }
        }

        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn put(&self, name: &str, record_type: &RecordType, response: &DnsResponse) {
        if response.answers.is_empty() {
            return;
        }

        // Calculate TTL
        let min_ttl = response
            .answers
            .iter()
            .map(|r| r.ttl)
            .min()
            .unwrap_or(self.min_ttl)
            .max(self.min_ttl)
            .min(self.max_ttl);

        let key = Self::cache_key(name, record_type);
        let now = SystemTime::now();

        let entry = CacheEntry {
            response: response.clone(),
            inserted_at: now,
            expires_at: now + Duration::from_secs(min_ttl as u64),
            hit_count: 0,
        };

        let mut entries = self.entries.write().unwrap();

        // Evict if necessary
        if entries.len() >= self.max_size {
            self.evict_expired(&mut entries);

            if entries.len() >= self.max_size {
                // Evict least used
                if let Some(lru_key) = entries
                    .iter()
                    .min_by_key(|(_, e)| e.hit_count)
                    .map(|(k, _)| k.clone())
                {
                    entries.remove(&lru_key);
                    self.stats.evictions.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        entries.insert(key, entry);
    }

    fn evict_expired(&self, entries: &mut HashMap<String, CacheEntry>) {
        let expired: Vec<_> = entries
            .iter()
            .filter(|(_, e)| e.is_expired())
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired {
            entries.remove(&key);
            self.stats.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn stats(&self) -> (u64, u64, u64, usize) {
        let entries = self.entries.read().unwrap();
        (
            self.stats.hits.load(Ordering::Relaxed),
            self.stats.misses.load(Ordering::Relaxed),
            self.stats.evictions.load(Ordering::Relaxed),
            entries.len(),
        )
    }

    pub fn clear(&self) {
        let mut entries = self.entries.write().unwrap();
        entries.clear();
    }
}

// ============================================================================
// Query Logging
// ============================================================================

/// Query log entry
#[derive(Clone, Debug)]
pub struct QueryLogEntry {
    pub id: u64,
    pub timestamp: SystemTime,
    pub client_ip: IpAddr,
    pub query_name: String,
    pub query_type: RecordType,
    pub response_code: ResponseCode,
    pub response_time: Duration,
    pub upstream: Option<String>,
    pub cached: bool,
    pub blocked: bool,
    pub block_reason: Option<String>,
}

/// Query logger
pub struct QueryLogger {
    entries: Arc<RwLock<Vec<QueryLogEntry>>>,
    max_entries: usize,
    next_id: AtomicU64,
}

impl QueryLogger {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
            max_entries,
            next_id: AtomicU64::new(1),
        }
    }

    pub fn log(&self, entry: QueryLogEntry) {
        let mut entries = self.entries.write().unwrap();

        if entries.len() >= self.max_entries {
            entries.remove(0);
        }

        entries.push(entry);
    }

    pub fn log_query(
        &self,
        query: &DnsQuery,
        response: &DnsResponse,
        upstream: Option<&str>,
        cached: bool,
        blocked: bool,
        block_reason: Option<&str>,
    ) {
        let entry = QueryLogEntry {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            timestamp: SystemTime::now(),
            client_ip: query.client_ip,
            query_name: query.name.clone(),
            query_type: query.record_type.clone(),
            response_code: response.response_code.clone(),
            response_time: response.response_time,
            upstream: upstream.map(String::from),
            cached,
            blocked,
            block_reason: block_reason.map(String::from),
        };

        self.log(entry);
    }

    pub fn get_recent(&self, count: usize) -> Vec<QueryLogEntry> {
        let entries = self.entries.read().unwrap();
        entries.iter().rev().take(count).cloned().collect()
    }

    pub fn get_stats(&self) -> QueryStats {
        let entries = self.entries.read().unwrap();

        let total = entries.len() as u64;
        let blocked = entries.iter().filter(|e| e.blocked).count() as u64;
        let cached = entries.iter().filter(|e| e.cached).count() as u64;

        let mut by_type: HashMap<RecordType, u64> = HashMap::new();
        let mut by_response: HashMap<String, u64> = HashMap::new();
        let mut top_domains: HashMap<String, u64> = HashMap::new();
        let mut top_blocked: HashMap<String, u64> = HashMap::new();

        for entry in entries.iter() {
            *by_type.entry(entry.query_type.clone()).or_insert(0) += 1;
            *by_response
                .entry(format!("{:?}", entry.response_code))
                .or_insert(0) += 1;
            *top_domains.entry(entry.query_name.clone()).or_insert(0) += 1;

            if entry.blocked {
                *top_blocked.entry(entry.query_name.clone()).or_insert(0) += 1;
            }
        }

        let avg_response_time = if !entries.is_empty() {
            let total_time: u128 = entries.iter().map(|e| e.response_time.as_micros()).sum();
            Duration::from_micros((total_time / entries.len() as u128) as u64)
        } else {
            Duration::ZERO
        };

        QueryStats {
            total_queries: total,
            blocked_queries: blocked,
            cached_queries: cached,
            by_type,
            by_response,
            top_domains: top_domains
                .into_iter()
                .collect::<Vec<_>>()
                .into_iter()
                .take(10)
                .collect(),
            top_blocked: top_blocked
                .into_iter()
                .collect::<Vec<_>>()
                .into_iter()
                .take(10)
                .collect(),
            avg_response_time,
        }
    }
}

#[derive(Debug)]
pub struct QueryStats {
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub cached_queries: u64,
    pub by_type: HashMap<RecordType, u64>,
    pub by_response: HashMap<String, u64>,
    pub top_domains: Vec<(String, u64)>,
    pub top_blocked: Vec<(String, u64)>,
    pub avg_response_time: Duration,
}

// ============================================================================
// DNS Proxy
// ============================================================================

/// DNS proxy configuration
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub listen_address: String,
    pub listen_port: u16,
    pub upstreams: Vec<UpstreamProvider>,
    pub blocklists: Vec<Blocklist>,
    pub allowlist: Allowlist,
    pub block_action: BlockAction,
    pub cache_size: usize,
    pub log_queries: bool,
    pub enable_dnssec: bool,
    pub enable_ecs: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_address: "127.0.0.1".to_string(),
            listen_port: 53,
            upstreams: vec![
                UpstreamProvider::cloudflare_doh(),
                UpstreamProvider::google_doh(),
            ],
            blocklists: vec![Blocklist::ads_trackers(), Blocklist::malware()],
            allowlist: Allowlist::default(),
            block_action: BlockAction::NXDomain,
            cache_size: 10000,
            log_queries: true,
            enable_dnssec: true,
            enable_ecs: false,
        }
    }
}

/// DNS proxy server
pub struct DnsProxy {
    config: ProxyConfig,
    cache: DnsCache,
    logger: QueryLogger,
    stats: ProxyStats,
}

#[derive(Default)]
pub struct ProxyStats {
    pub queries_total: AtomicU64,
    pub queries_blocked: AtomicU64,
    pub queries_cached: AtomicU64,
    pub queries_forwarded: AtomicU64,
    pub upstream_errors: AtomicU64,
}

impl DnsProxy {
    pub fn new(config: ProxyConfig) -> Self {
        let cache_size = config.cache_size;
        Self {
            config,
            cache: DnsCache::new(cache_size),
            logger: QueryLogger::new(10000),
            stats: ProxyStats::default(),
        }
    }

    /// Handle a DNS query
    pub fn handle_query(&self, query: &DnsQuery) -> DnsResponse {
        self.stats.queries_total.fetch_add(1, Ordering::Relaxed);
        let start = SystemTime::now();

        // Check allowlist first
        if self.config.allowlist.contains(&query.name) {
            return self.forward_query(query);
        }

        // Check blocklists
        for blocklist in &self.config.blocklists {
            if blocklist.contains(&query.name) {
                self.stats.queries_blocked.fetch_add(1, Ordering::Relaxed);

                let response = self.create_blocked_response(query);

                if self.config.log_queries {
                    self.logger.log_query(
                        query,
                        &response,
                        None,
                        false,
                        true,
                        Some(&blocklist.name),
                    );
                }

                return response;
            }
        }

        // Check cache
        if let Some(cached) = self.cache.get(&query.name, &query.record_type) {
            self.stats.queries_cached.fetch_add(1, Ordering::Relaxed);

            let mut response = cached;
            response.id = query.id;
            response.response_time = start.elapsed().unwrap_or_default();

            if self.config.log_queries {
                self.logger
                    .log_query(query, &response, None, true, false, None);
            }

            return response;
        }

        // Forward to upstream
        self.forward_query(query)
    }

    fn forward_query(&self, query: &DnsQuery) -> DnsResponse {
        self.stats.queries_forwarded.fetch_add(1, Ordering::Relaxed);
        let start = SystemTime::now();

        // Select upstream (simplified - would use health checks and load balancing)
        let upstream = self
            .config
            .upstreams
            .iter()
            .filter(|u| u.is_healthy)
            .min_by_key(|u| u.priority)
            .or_else(|| self.config.upstreams.first());

        let upstream_name = upstream.map(|u| u.name.as_str());

        // Simulate upstream query (in real implementation, would make actual DNS query)
        let response = self.simulate_upstream_query(query, start);

        // Cache the response
        if response.response_code == ResponseCode::NoError && !response.answers.is_empty() {
            self.cache.put(&query.name, &query.record_type, &response);
        }

        if self.config.log_queries {
            self.logger
                .log_query(query, &response, upstream_name, false, false, None);
        }

        response
    }

    fn create_blocked_response(&self, query: &DnsQuery) -> DnsResponse {
        match &self.config.block_action {
            BlockAction::NXDomain => DnsResponse {
                id: query.id,
                response_code: ResponseCode::NXDomain,
                authoritative: false,
                truncated: false,
                recursion_available: true,
                answers: vec![],
                authority: vec![],
                additional: vec![],
                response_time: Duration::from_micros(100),
            },
            BlockAction::Refused => DnsResponse {
                id: query.id,
                response_code: ResponseCode::Refused,
                authoritative: false,
                truncated: false,
                recursion_available: true,
                answers: vec![],
                authority: vec![],
                additional: vec![],
                response_time: Duration::from_micros(100),
            },
            BlockAction::Sinkhole(ip) => {
                let record = match (ip, &query.record_type) {
                    (IpAddr::V4(ipv4), RecordType::A) => Some(DnsRecord {
                        name: query.name.clone(),
                        record_type: RecordType::A,
                        class: 1,
                        ttl: 300,
                        data: RecordData::A(*ipv4),
                    }),
                    (IpAddr::V6(ipv6), RecordType::AAAA) => Some(DnsRecord {
                        name: query.name.clone(),
                        record_type: RecordType::AAAA,
                        class: 1,
                        ttl: 300,
                        data: RecordData::AAAA(*ipv6),
                    }),
                    _ => None,
                };

                DnsResponse {
                    id: query.id,
                    response_code: ResponseCode::NoError,
                    authoritative: false,
                    truncated: false,
                    recursion_available: true,
                    answers: record.into_iter().collect(),
                    authority: vec![],
                    additional: vec![],
                    response_time: Duration::from_micros(100),
                }
            }
            BlockAction::NoData => DnsResponse {
                id: query.id,
                response_code: ResponseCode::NoError,
                authoritative: false,
                truncated: false,
                recursion_available: true,
                answers: vec![],
                authority: vec![],
                additional: vec![],
                response_time: Duration::from_micros(100),
            },
            BlockAction::Custom(response) => {
                let mut resp = response.clone();
                resp.id = query.id;
                resp
            }
        }
    }

    fn simulate_upstream_query(&self, query: &DnsQuery, start: SystemTime) -> DnsResponse {
        // Simulate DNS response (in real implementation, would query upstream)
        let answers = match query.record_type {
            RecordType::A => vec![DnsRecord {
                name: query.name.clone(),
                record_type: RecordType::A,
                class: 1,
                ttl: 300,
                data: RecordData::A(Ipv4Addr::new(93, 184, 216, 34)),
            }],
            RecordType::AAAA => vec![DnsRecord {
                name: query.name.clone(),
                record_type: RecordType::AAAA,
                class: 1,
                ttl: 300,
                data: RecordData::AAAA(Ipv6Addr::new(
                    0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
                )),
            }],
            _ => vec![],
        };

        DnsResponse {
            id: query.id,
            response_code: ResponseCode::NoError,
            authoritative: false,
            truncated: false,
            recursion_available: true,
            answers,
            authority: vec![],
            additional: vec![],
            response_time: start.elapsed().unwrap_or_default() + Duration::from_millis(10),
        }
    }

    pub fn get_stats(&self) -> ProxyStatsSummary {
        let (cache_hits, cache_misses, cache_evictions, cache_size) = self.cache.stats();
        let query_stats = self.logger.get_stats();

        ProxyStatsSummary {
            queries_total: self.stats.queries_total.load(Ordering::Relaxed),
            queries_blocked: self.stats.queries_blocked.load(Ordering::Relaxed),
            queries_cached: self.stats.queries_cached.load(Ordering::Relaxed),
            queries_forwarded: self.stats.queries_forwarded.load(Ordering::Relaxed),
            upstream_errors: self.stats.upstream_errors.load(Ordering::Relaxed),
            cache_hits,
            cache_misses,
            cache_evictions,
            cache_size,
            query_stats,
        }
    }
}

#[derive(Debug)]
pub struct ProxyStatsSummary {
    pub queries_total: u64,
    pub queries_blocked: u64,
    pub queries_cached: u64,
    pub queries_forwarded: u64,
    pub upstream_errors: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_evictions: u64,
    pub cache_size: usize,
    pub query_stats: QueryStats,
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== Secure DNS Proxy with DoH/DoT Support ===\n");

    // Create proxy configuration
    let mut config = ProxyConfig::default();
    config.block_action = BlockAction::Sinkhole(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));

    // Add custom allowlist
    config.allowlist.add("example.com");
    config.allowlist.add("trusted.net");

    let proxy = DnsProxy::new(config);

    // Display configuration
    println!("1. Proxy Configuration");
    println!("─────────────────────────────────────────────────────────────────────────");
    println!(
        "  Listen: {}:{}",
        proxy.config.listen_address, proxy.config.listen_port
    );
    println!("  Upstreams:");
    for upstream in &proxy.config.upstreams {
        println!("    - {} ({:?})", upstream.name, upstream.provider_type);
    }
    println!("  Blocklists:");
    for blocklist in &proxy.config.blocklists {
        println!(
            "    - {} ({} domains)",
            blocklist.name,
            blocklist.domains.len()
        );
    }
    println!("  Block action: {:?}", proxy.config.block_action);
    println!("  Cache size: {}", proxy.config.cache_size);
    println!();

    // Test queries
    println!("2. Query Processing");
    println!("─────────────────────────────────────────────────────────────────────────");

    let test_queries = vec![
        ("example.com", RecordType::A, "Normal query (allowed)"),
        (
            "google-analytics.com",
            RecordType::A,
            "Blocked (ads/trackers)",
        ),
        ("malware.example.com", RecordType::A, "Blocked (malware)"),
        ("safe-domain.org", RecordType::A, "Normal query"),
        ("doubleclick.net", RecordType::A, "Blocked (ads)"),
        ("example.com", RecordType::A, "Cached query"),
        ("cloudflare.com", RecordType::AAAA, "IPv6 query"),
    ];

    for (domain, record_type, description) in test_queries {
        let query = DnsQuery {
            id: rand_id(),
            name: domain.to_string(),
            record_type: record_type.clone(),
            class: 1,
            recursion_desired: true,
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            timestamp: SystemTime::now(),
            edns: None,
        };

        let response = proxy.handle_query(&query);

        let status = match response.response_code {
            ResponseCode::NoError => "✓",
            ResponseCode::NXDomain | ResponseCode::Refused => "✗",
            _ => "?",
        };

        println!(
            "  {} {} {} ({}) - {:?} in {:?}",
            status,
            domain,
            record_type,
            description,
            response.response_code,
            response.response_time
        );

        if !response.answers.is_empty() {
            for answer in &response.answers {
                let data = match &answer.data {
                    RecordData::A(ip) => format!("{}", ip),
                    RecordData::AAAA(ip) => format!("{}", ip),
                    RecordData::CNAME(name) => name.clone(),
                    _ => "...".to_string(),
                };
                println!(
                    "      {} -> {} (TTL: {})",
                    answer.record_type, data, answer.ttl
                );
            }
        }
    }
    println!();

    // Display statistics
    println!("3. Proxy Statistics");
    println!("─────────────────────────────────────────────────────────────────────────");

    let stats = proxy.get_stats();

    println!("  Queries:");
    println!("    Total:     {}", stats.queries_total);
    println!(
        "    Blocked:   {} ({:.1}%)",
        stats.queries_blocked,
        (stats.queries_blocked as f64 / stats.queries_total.max(1) as f64) * 100.0
    );
    println!(
        "    Cached:    {} ({:.1}%)",
        stats.queries_cached,
        (stats.queries_cached as f64 / stats.queries_total.max(1) as f64) * 100.0
    );
    println!("    Forwarded: {}", stats.queries_forwarded);
    println!();

    println!("  Cache:");
    println!("    Size:      {}", stats.cache_size);
    println!("    Hits:      {}", stats.cache_hits);
    println!("    Misses:    {}", stats.cache_misses);
    println!(
        "    Hit rate:  {:.1}%",
        (stats.cache_hits as f64 / (stats.cache_hits + stats.cache_misses).max(1) as f64) * 100.0
    );
    println!();

    println!("  Query Types:");
    for (qtype, count) in &stats.query_stats.by_type {
        println!("    {}: {}", qtype, count);
    }
    println!();

    // Recent queries
    println!("4. Recent Queries");
    println!("─────────────────────────────────────────────────────────────────────────");

    for entry in proxy.logger.get_recent(5) {
        let blocked_marker = if entry.blocked { "🚫" } else { "  " };
        let cached_marker = if entry.cached { "💾" } else { "  " };

        println!(
            "  {} {} {} {} ({:?}) - {:?}",
            blocked_marker,
            cached_marker,
            entry.query_name,
            entry.query_type,
            entry.response_code,
            entry.response_time
        );
    }

    println!("\n=== Secure DNS Proxy Demo Complete ===");
}

fn rand_id() -> u16 {
    use std::time::UNIX_EPOCH;
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        % 65536) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_conversion() {
        assert_eq!(RecordType::from_u16(1), RecordType::A);
        assert_eq!(RecordType::from_u16(28), RecordType::AAAA);
        assert_eq!(RecordType::A.to_u16(), 1);
        assert_eq!(RecordType::AAAA.to_u16(), 28);
    }

    #[test]
    fn test_blocklist_contains() {
        let blocklist = Blocklist::ads_trackers();

        assert!(blocklist.contains("googleadservices.com"));
        assert!(blocklist.contains("sub.googleadservices.com"));
        assert!(!blocklist.contains("google.com"));
        assert!(!blocklist.contains("example.com"));
    }

    #[test]
    fn test_allowlist() {
        let mut allowlist = Allowlist::default();
        allowlist.add("example.com");

        assert!(allowlist.contains("example.com"));
        assert!(!allowlist.contains("other.com"));
    }

    #[test]
    fn test_dns_cache() {
        let cache = DnsCache::new(100);

        let response = DnsResponse {
            id: 1,
            response_code: ResponseCode::NoError,
            authoritative: false,
            truncated: false,
            recursion_available: true,
            answers: vec![DnsRecord {
                name: "example.com".to_string(),
                record_type: RecordType::A,
                class: 1,
                ttl: 300,
                data: RecordData::A(Ipv4Addr::new(93, 184, 216, 34)),
            }],
            authority: vec![],
            additional: vec![],
            response_time: Duration::from_millis(10),
        };

        cache.put("example.com", &RecordType::A, &response);

        let cached = cache.get("example.com", &RecordType::A);
        assert!(cached.is_some());

        let not_cached = cache.get("other.com", &RecordType::A);
        assert!(not_cached.is_none());
    }

    #[test]
    fn test_cache_key() {
        let key = DnsCache::cache_key("EXAMPLE.COM", &RecordType::A);
        assert_eq!(key, "example.com:A");
    }

    #[test]
    fn test_upstream_providers() {
        let cf = UpstreamProvider::cloudflare_doh();
        assert_eq!(cf.provider_type, ProviderType::DoH);
        assert!(!cf.endpoints.is_empty());

        let google = UpstreamProvider::google_doh();
        assert_eq!(google.provider_type, ProviderType::DoH);
    }

    #[test]
    fn test_proxy_blocked_query() {
        let config = ProxyConfig::default();
        let proxy = DnsProxy::new(config);

        let query = DnsQuery {
            id: 1,
            name: "googleadservices.com".to_string(),
            record_type: RecordType::A,
            class: 1,
            recursion_desired: true,
            client_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            timestamp: SystemTime::now(),
            edns: None,
        };

        let response = proxy.handle_query(&query);
        assert_eq!(response.response_code, ResponseCode::NXDomain);
    }

    #[test]
    fn test_proxy_allowed_query() {
        let mut config = ProxyConfig::default();
        config.allowlist.add("allowed.com");
        let proxy = DnsProxy::new(config);

        let query = DnsQuery {
            id: 1,
            name: "allowed.com".to_string(),
            record_type: RecordType::A,
            class: 1,
            recursion_desired: true,
            client_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            timestamp: SystemTime::now(),
            edns: None,
        };

        let response = proxy.handle_query(&query);
        assert_eq!(response.response_code, ResponseCode::NoError);
    }

    #[test]
    fn test_query_logger() {
        let logger = QueryLogger::new(100);

        let entry = QueryLogEntry {
            id: 1,
            timestamp: SystemTime::now(),
            client_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            query_name: "example.com".to_string(),
            query_type: RecordType::A,
            response_code: ResponseCode::NoError,
            response_time: Duration::from_millis(10),
            upstream: Some("Cloudflare".to_string()),
            cached: false,
            blocked: false,
            block_reason: None,
        };

        logger.log(entry);

        let recent = logger.get_recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].query_name, "example.com");
    }

    #[test]
    fn test_cache_entry_expiry() {
        let entry = CacheEntry {
            response: DnsResponse {
                id: 1,
                response_code: ResponseCode::NoError,
                authoritative: false,
                truncated: false,
                recursion_available: true,
                answers: vec![],
                authority: vec![],
                additional: vec![],
                response_time: Duration::ZERO,
            },
            inserted_at: SystemTime::now(),
            expires_at: SystemTime::now() + Duration::from_secs(300),
            hit_count: 0,
        };

        assert!(!entry.is_expired());
        assert!(entry.remaining_ttl() > 0);
    }
}
