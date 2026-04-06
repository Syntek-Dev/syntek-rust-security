# DNS Security Builder Agent

## Role

Sonnet-based agent for building Rust DNS security proxies with DNS-over-HTTPS
(DoH) and DNS-over-TLS (DoT) support, DNS sinkholing for malicious domains,
query logging and analysis, and ad/tracker blocking at the network level.

## Required Reading

Before writing, reviewing, or modifying any code, read these documents from the
target project's `.claude/` directory:

| Document | Purpose |
| -------- | ------- |
| **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)** | Coding standards, error handling, naming, unsafe code |
| **[SECURITY.md](.claude/SECURITY.md)** | Memory safety, cryptographic standards, secrets management |
| **[TESTING.md](.claude/TESTING.md)** | Testing guide — cargo test, mockall, proptest, cargo-fuzz |
| **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)** | Dev workflow, tooling, git conventions, release process |
| **[ARCHITECTURE-PATTERNS.md](.claude/ARCHITECTURE-PATTERNS.md)** | Service layer, workspace structure, async patterns |
| **[PERFORMANCE.md](.claude/PERFORMANCE.md)** | Benchmarking, profiling, async performance, caching |

## Capabilities

- DNS-over-HTTPS (DoH) proxy implementation
- DNS-over-TLS (DoT) proxy implementation
- DNS sinkholing for malicious domains
- Blocklist management (malware, ads, trackers)
- Query logging and analytics
- Response caching with TTL management
- DNSSEC validation
- Custom DNS filtering rules
- Domain categorization
- Query rate limiting

## Implementation Patterns

### Core DNS Proxy Server

```rust
use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// DNS proxy configuration
#[derive(Debug, Clone)]
pub struct DnsProxyConfig {
    pub listen_addr: SocketAddr,
    pub listen_addr_tcp: SocketAddr,
    pub doh_upstream: String,
    pub dot_upstream: SocketAddr,
    pub dot_server_name: String,
    pub upstream_mode: UpstreamMode,
    pub enable_caching: bool,
    pub cache_size: usize,
    pub cache_min_ttl: u32,
    pub cache_max_ttl: u32,
    pub enable_dnssec: bool,
    pub enable_logging: bool,
    pub log_path: std::path::PathBuf,
    pub blocklist_paths: Vec<std::path::PathBuf>,
    pub sinkhole_ip: std::net::IpAddr,
    pub rate_limit_qps: u32,
}

#[derive(Debug, Clone)]
pub enum UpstreamMode {
    DoH,
    DoT,
    Traditional,
    Hybrid, // Try DoH, fallback to DoT
}

impl Default for DnsProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:53".parse().unwrap(),
            listen_addr_tcp: "0.0.0.0:53".parse().unwrap(),
            doh_upstream: "https://cloudflare-dns.com/dns-query".to_string(),
            dot_upstream: "1.1.1.1:853".parse().unwrap(),
            dot_server_name: "cloudflare-dns.com".to_string(),
            upstream_mode: UpstreamMode::DoH,
            enable_caching: true,
            cache_size: 10000,
            cache_min_ttl: 60,
            cache_max_ttl: 86400,
            enable_dnssec: true,
            enable_logging: true,
            log_path: std::path::PathBuf::from("/var/log/dns-proxy/queries.log"),
            blocklist_paths: vec![
                std::path::PathBuf::from("/etc/dns-proxy/blocklists/malware.txt"),
                std::path::PathBuf::from("/etc/dns-proxy/blocklists/ads.txt"),
            ],
            sinkhole_ip: "0.0.0.0".parse().unwrap(),
            rate_limit_qps: 1000,
        }
    }
}

/// DNS query record type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    A = 1,
    AAAA = 28,
    CNAME = 5,
    MX = 15,
    TXT = 16,
    NS = 2,
    SOA = 6,
    PTR = 12,
    SRV = 33,
    HTTPS = 65,
    Unknown(u16),
}

impl From<u16> for RecordType {
    fn from(value: u16) -> Self {
        match value {
            1 => RecordType::A,
            28 => RecordType::AAAA,
            5 => RecordType::CNAME,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            2 => RecordType::NS,
            6 => RecordType::SOA,
            12 => RecordType::PTR,
            33 => RecordType::SRV,
            65 => RecordType::HTTPS,
            n => RecordType::Unknown(n),
        }
    }
}

/// DNS query representation
#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub id: u16,
    pub domain: String,
    pub record_type: RecordType,
    pub client_addr: SocketAddr,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub raw_packet: Vec<u8>,
}

/// DNS response representation
#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub id: u16,
    pub domain: String,
    pub record_type: RecordType,
    pub answers: Vec<DnsAnswer>,
    pub ttl: u32,
    pub response_code: ResponseCode,
    pub raw_packet: Vec<u8>,
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
    A(std::net::Ipv4Addr),
    AAAA(std::net::Ipv6Addr),
    CNAME(String),
    MX { priority: u16, exchange: String },
    TXT(String),
    NS(String),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, Copy)]
pub enum ResponseCode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5,
}

/// Main DNS proxy server
pub struct DnsProxy {
    config: DnsProxyConfig,
    cache: Arc<RwLock<DnsCache>>,
    blocklist: Arc<RwLock<Blocklist>>,
    doh_client: DoHClient,
    dot_client: DoTClient,
    logger: Arc<QueryLogger>,
    rate_limiter: Arc<RateLimiter>,
    stats: Arc<RwLock<ProxyStats>>,
}

impl DnsProxy {
    pub async fn new(config: DnsProxyConfig) -> Result<Self, DnsProxyError> {
        let cache = DnsCache::new(config.cache_size);
        let blocklist = Blocklist::load(&config.blocklist_paths).await?;
        let doh_client = DoHClient::new(&config.doh_upstream)?;
        let dot_client = DoTClient::new(
            config.dot_upstream,
            &config.dot_server_name,
        ).await?;
        let logger = QueryLogger::new(&config.log_path).await?;
        let rate_limiter = RateLimiter::new(config.rate_limit_qps);

        Ok(Self {
            config,
            cache: Arc::new(RwLock::new(cache)),
            blocklist: Arc::new(RwLock::new(blocklist)),
            doh_client,
            dot_client,
            logger: Arc::new(logger),
            rate_limiter: Arc::new(rate_limiter),
            stats: Arc::new(RwLock::new(ProxyStats::default())),
        })
    }

    /// Start the DNS proxy server
    pub async fn run(&self) -> Result<(), DnsProxyError> {
        let udp_socket = UdpSocket::bind(self.config.listen_addr).await?;
        tracing::info!("DNS proxy listening on UDP {}", self.config.listen_addr);

        let mut buf = [0u8; 512];

        loop {
            let (len, client_addr) = udp_socket.recv_from(&mut buf).await?;
            let packet = buf[..len].to_vec();

            // Clone necessary state for async task
            let proxy = self.clone_for_task();
            let socket = udp_socket.clone();

            tokio::spawn(async move {
                match proxy.handle_query(packet, client_addr).await {
                    Ok(response) => {
                        if let Err(e) = socket.send_to(&response, client_addr).await {
                            tracing::error!("Failed to send response: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Query handling error: {}", e);
                    }
                }
            });
        }
    }

    fn clone_for_task(&self) -> DnsProxyTask {
        DnsProxyTask {
            config: self.config.clone(),
            cache: Arc::clone(&self.cache),
            blocklist: Arc::clone(&self.blocklist),
            doh_client: self.doh_client.clone(),
            dot_client: self.dot_client.clone(),
            logger: Arc::clone(&self.logger),
            rate_limiter: Arc::clone(&self.rate_limiter),
            stats: Arc::clone(&self.stats),
        }
    }
}

/// Task handler for individual DNS queries
struct DnsProxyTask {
    config: DnsProxyConfig,
    cache: Arc<RwLock<DnsCache>>,
    blocklist: Arc<RwLock<Blocklist>>,
    doh_client: DoHClient,
    dot_client: DoTClient,
    logger: Arc<QueryLogger>,
    rate_limiter: Arc<RateLimiter>,
    stats: Arc<RwLock<ProxyStats>>,
}

impl DnsProxyTask {
    async fn handle_query(
        &self,
        packet: Vec<u8>,
        client_addr: SocketAddr,
    ) -> Result<Vec<u8>, DnsProxyError> {
        // Parse query
        let query = self.parse_query(&packet, client_addr)?;

        // Rate limiting
        if !self.rate_limiter.check(client_addr.ip()).await {
            return self.create_refused_response(&query);
        }

        // Log query
        if self.config.enable_logging {
            self.logger.log_query(&query).await;
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_queries += 1;
        }

        // Check blocklist
        if self.blocklist.read().await.is_blocked(&query.domain) {
            tracing::debug!("Blocked domain: {}", query.domain);
            let mut stats = self.stats.write().await;
            stats.blocked_queries += 1;
            return self.create_sinkhole_response(&query);
        }

        // Check cache
        if self.config.enable_caching {
            if let Some(cached) = self.cache.read().await.get(&query.domain, query.record_type) {
                let mut stats = self.stats.write().await;
                stats.cache_hits += 1;
                return Ok(self.adapt_cached_response(&cached, &query));
            }
        }

        // Forward to upstream
        let response = self.forward_query(&query).await?;

        // Cache response
        if self.config.enable_caching && response.response_code as u8 == 0 {
            let ttl = self.calculate_cache_ttl(&response);
            self.cache.write().await.insert(
                query.domain.clone(),
                query.record_type,
                response.clone(),
                ttl,
            );
        }

        // Log response
        if self.config.enable_logging {
            self.logger.log_response(&query, &response).await;
        }

        Ok(response.raw_packet)
    }

    fn parse_query(&self, packet: &[u8], client_addr: SocketAddr) -> Result<DnsQuery, DnsProxyError> {
        if packet.len() < 12 {
            return Err(DnsProxyError::InvalidPacket("Too short".to_string()));
        }

        let id = u16::from_be_bytes([packet[0], packet[1]]);

        // Parse question section
        let (domain, record_type, _offset) = self.parse_question(&packet[12..])?;

        Ok(DnsQuery {
            id,
            domain,
            record_type,
            client_addr,
            timestamp: chrono::Utc::now(),
            raw_packet: packet.to_vec(),
        })
    }

    fn parse_question(&self, data: &[u8]) -> Result<(String, RecordType, usize), DnsProxyError> {
        let mut domain_parts = Vec::new();
        let mut offset = 0;

        loop {
            if offset >= data.len() {
                return Err(DnsProxyError::InvalidPacket("Truncated domain".to_string()));
            }

            let len = data[offset] as usize;
            if len == 0 {
                offset += 1;
                break;
            }

            if offset + 1 + len > data.len() {
                return Err(DnsProxyError::InvalidPacket("Invalid label length".to_string()));
            }

            let label = std::str::from_utf8(&data[offset + 1..offset + 1 + len])
                .map_err(|_| DnsProxyError::InvalidPacket("Invalid UTF-8".to_string()))?;
            domain_parts.push(label.to_string());
            offset += 1 + len;
        }

        if offset + 4 > data.len() {
            return Err(DnsProxyError::InvalidPacket("Missing type/class".to_string()));
        }

        let record_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 4; // Skip type and class

        Ok((domain_parts.join("."), RecordType::from(record_type), offset))
    }

    async fn forward_query(&self, query: &DnsQuery) -> Result<DnsResponse, DnsProxyError> {
        match self.config.upstream_mode {
            UpstreamMode::DoH => {
                self.doh_client.query(&query.raw_packet).await
            }
            UpstreamMode::DoT => {
                self.dot_client.query(&query.raw_packet).await
            }
            UpstreamMode::Traditional => {
                // Traditional DNS forwarding
                self.forward_traditional(query).await
            }
            UpstreamMode::Hybrid => {
                // Try DoH first, fallback to DoT
                match self.doh_client.query(&query.raw_packet).await {
                    Ok(resp) => Ok(resp),
                    Err(_) => self.dot_client.query(&query.raw_packet).await,
                }
            }
        }
    }

    async fn forward_traditional(&self, query: &DnsQuery) -> Result<DnsResponse, DnsProxyError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(&query.raw_packet, "1.1.1.1:53").await?;

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            socket.recv_from(&mut buf),
        ).await??;

        self.parse_response(&buf[..len])
    }

    fn parse_response(&self, packet: &[u8]) -> Result<DnsResponse, DnsProxyError> {
        // Simplified response parsing
        let id = u16::from_be_bytes([packet[0], packet[1]]);
        let response_code = match packet[3] & 0x0F {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormErr,
            2 => ResponseCode::ServFail,
            3 => ResponseCode::NXDomain,
            4 => ResponseCode::NotImp,
            _ => ResponseCode::Refused,
        };

        Ok(DnsResponse {
            id,
            domain: String::new(), // Would need full parsing
            record_type: RecordType::A,
            answers: Vec::new(),
            ttl: 300,
            response_code,
            raw_packet: packet.to_vec(),
        })
    }

    fn create_sinkhole_response(&self, query: &DnsQuery) -> Result<Vec<u8>, DnsProxyError> {
        let mut response = query.raw_packet.clone();

        // Set QR bit (response), set answer count to 1
        response[2] |= 0x80; // QR = 1
        response[6] = 0x00;
        response[7] = 0x01; // ANCOUNT = 1

        // Add answer section with sinkhole IP
        let answer = match self.config.sinkhole_ip {
            std::net::IpAddr::V4(ip) => {
                let mut ans = Vec::new();
                ans.extend_from_slice(&[0xC0, 0x0C]); // Pointer to domain name
                ans.extend_from_slice(&1u16.to_be_bytes()); // Type A
                ans.extend_from_slice(&1u16.to_be_bytes()); // Class IN
                ans.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
                ans.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
                ans.extend_from_slice(&ip.octets()); // IP address
                ans
            }
            std::net::IpAddr::V6(ip) => {
                let mut ans = Vec::new();
                ans.extend_from_slice(&[0xC0, 0x0C]); // Pointer to domain name
                ans.extend_from_slice(&28u16.to_be_bytes()); // Type AAAA
                ans.extend_from_slice(&1u16.to_be_bytes()); // Class IN
                ans.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
                ans.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
                ans.extend_from_slice(&ip.octets()); // IP address
                ans
            }
        };

        response.extend_from_slice(&answer);
        Ok(response)
    }

    fn create_refused_response(&self, query: &DnsQuery) -> Result<Vec<u8>, DnsProxyError> {
        let mut response = query.raw_packet.clone();
        response[2] |= 0x80; // QR = 1
        response[3] = (response[3] & 0xF0) | 0x05; // RCODE = REFUSED
        Ok(response)
    }

    fn adapt_cached_response(&self, cached: &DnsResponse, query: &DnsQuery) -> Vec<u8> {
        let mut response = cached.raw_packet.clone();
        // Update transaction ID to match query
        response[0] = (query.id >> 8) as u8;
        response[1] = query.id as u8;
        response
    }

    fn calculate_cache_ttl(&self, response: &DnsResponse) -> u32 {
        let ttl = response.ttl;
        ttl.max(self.config.cache_min_ttl).min(self.config.cache_max_ttl)
    }
}
```

### DNS-over-HTTPS (DoH) Client

```rust
use reqwest::Client;

/// DNS-over-HTTPS client
#[derive(Clone)]
pub struct DoHClient {
    client: Client,
    endpoint: String,
}

impl DoHClient {
    pub fn new(endpoint: &str) -> Result<Self, DnsProxyError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?;

        Ok(Self {
            client,
            endpoint: endpoint.to_string(),
        })
    }

    pub async fn query(&self, dns_packet: &[u8]) -> Result<DnsResponse, DnsProxyError> {
        // Encode DNS packet as base64url for GET request
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(dns_packet);

        let url = format!("{}?dns={}", self.endpoint, encoded);

        let response = self.client
            .get(&url)
            .header("Accept", "application/dns-message")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(DnsProxyError::UpstreamError(
                format!("DoH error: {}", response.status())
            ));
        }

        let bytes = response.bytes().await?;
        self.parse_response(&bytes)
    }

    /// POST method for larger queries
    pub async fn query_post(&self, dns_packet: &[u8]) -> Result<DnsResponse, DnsProxyError> {
        let response = self.client
            .post(&self.endpoint)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(dns_packet.to_vec())
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(DnsProxyError::UpstreamError(
                format!("DoH POST error: {}", response.status())
            ));
        }

        let bytes = response.bytes().await?;
        self.parse_response(&bytes)
    }

    fn parse_response(&self, packet: &[u8]) -> Result<DnsResponse, DnsProxyError> {
        if packet.len() < 12 {
            return Err(DnsProxyError::InvalidPacket("Response too short".to_string()));
        }

        let id = u16::from_be_bytes([packet[0], packet[1]]);
        let response_code = match packet[3] & 0x0F {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormErr,
            2 => ResponseCode::ServFail,
            3 => ResponseCode::NXDomain,
            4 => ResponseCode::NotImp,
            _ => ResponseCode::Refused,
        };

        Ok(DnsResponse {
            id,
            domain: String::new(),
            record_type: RecordType::A,
            answers: Vec::new(),
            ttl: 300, // Would need full parsing
            response_code,
            raw_packet: packet.to_vec(),
        })
    }
}
```

### DNS-over-TLS (DoT) Client

```rust
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, rustls};
use std::sync::Arc;

/// DNS-over-TLS client
#[derive(Clone)]
pub struct DoTClient {
    upstream: SocketAddr,
    server_name: String,
    tls_config: Arc<rustls::ClientConfig>,
}

impl DoTClient {
    pub async fn new(upstream: SocketAddr, server_name: &str) -> Result<Self, DnsProxyError> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Self {
            upstream,
            server_name: server_name.to_string(),
            tls_config: Arc::new(tls_config),
        })
    }

    pub async fn query(&self, dns_packet: &[u8]) -> Result<DnsResponse, DnsProxyError> {
        // Connect to upstream
        let stream = TcpStream::connect(self.upstream).await?;

        // Establish TLS
        let connector = TlsConnector::from(Arc::clone(&self.tls_config));
        let server_name = rustls::pki_types::ServerName::try_from(self.server_name.clone())
            .map_err(|_| DnsProxyError::TlsError("Invalid server name".to_string()))?;

        let mut tls_stream = connector.connect(server_name, stream).await?;

        // DNS over TCP requires 2-byte length prefix
        let len = (dns_packet.len() as u16).to_be_bytes();

        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        tls_stream.write_all(&len).await?;
        tls_stream.write_all(dns_packet).await?;
        tls_stream.flush().await?;

        // Read response length
        let mut len_buf = [0u8; 2];
        tls_stream.read_exact(&mut len_buf).await?;
        let response_len = u16::from_be_bytes(len_buf) as usize;

        // Read response
        let mut response = vec![0u8; response_len];
        tls_stream.read_exact(&mut response).await?;

        self.parse_response(&response)
    }

    fn parse_response(&self, packet: &[u8]) -> Result<DnsResponse, DnsProxyError> {
        if packet.len() < 12 {
            return Err(DnsProxyError::InvalidPacket("Response too short".to_string()));
        }

        let id = u16::from_be_bytes([packet[0], packet[1]]);
        let response_code = match packet[3] & 0x0F {
            0 => ResponseCode::NoError,
            _ => ResponseCode::ServFail,
        };

        Ok(DnsResponse {
            id,
            domain: String::new(),
            record_type: RecordType::A,
            answers: Vec::new(),
            ttl: 300,
            response_code,
            raw_packet: packet.to_vec(),
        })
    }
}
```

### Blocklist Management

```rust
use std::collections::HashSet;

/// Domain blocklist manager
pub struct Blocklist {
    blocked_domains: HashSet<String>,
    blocked_patterns: Vec<regex::Regex>,
    categories: HashMap<String, HashSet<String>>,
}

impl Blocklist {
    pub async fn load(paths: &[std::path::PathBuf]) -> Result<Self, DnsProxyError> {
        let mut blocked_domains = HashSet::new();
        let mut categories = HashMap::new();

        for path in paths {
            if !path.exists() {
                tracing::warn!("Blocklist not found: {}", path.display());
                continue;
            }

            let content = tokio::fs::read_to_string(path).await?;
            let category = path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();

            let mut category_domains = HashSet::new();

            for line in content.lines() {
                let line = line.trim();

                // Skip comments and empty lines
                if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                    continue;
                }

                // Handle various blocklist formats
                let domain = if line.starts_with("0.0.0.0 ") || line.starts_with("127.0.0.1 ") {
                    // hosts file format
                    line.split_whitespace().nth(1)
                } else if line.starts_with("||") && line.ends_with("^") {
                    // AdBlock format: ||domain.com^
                    Some(&line[2..line.len()-1])
                } else {
                    // Plain domain
                    Some(line)
                };

                if let Some(domain) = domain {
                    let domain = domain.to_lowercase();
                    blocked_domains.insert(domain.clone());
                    category_domains.insert(domain);
                }
            }

            tracing::info!(
                "Loaded {} domains from {} ({})",
                category_domains.len(),
                path.display(),
                category
            );
            categories.insert(category, category_domains);
        }

        Ok(Self {
            blocked_domains,
            blocked_patterns: Vec::new(),
            categories,
        })
    }

    pub fn is_blocked(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        // Exact match
        if self.blocked_domains.contains(&domain_lower) {
            return true;
        }

        // Subdomain match (e.g., if ads.example.com is queried and example.com is blocked)
        let parts: Vec<&str> = domain_lower.split('.').collect();
        for i in 0..parts.len() {
            let parent = parts[i..].join(".");
            if self.blocked_domains.contains(&parent) {
                return true;
            }
        }

        // Pattern match
        for pattern in &self.blocked_patterns {
            if pattern.is_match(&domain_lower) {
                return true;
            }
        }

        false
    }

    pub fn get_category(&self, domain: &str) -> Option<&str> {
        let domain_lower = domain.to_lowercase();

        for (category, domains) in &self.categories {
            if domains.contains(&domain_lower) {
                return Some(category);
            }
        }
        None
    }

    pub fn add_domain(&mut self, domain: &str, category: &str) {
        let domain_lower = domain.to_lowercase();
        self.blocked_domains.insert(domain_lower.clone());

        self.categories
            .entry(category.to_string())
            .or_default()
            .insert(domain_lower);
    }

    pub fn remove_domain(&mut self, domain: &str) {
        let domain_lower = domain.to_lowercase();
        self.blocked_domains.remove(&domain_lower);

        for domains in self.categories.values_mut() {
            domains.remove(&domain_lower);
        }
    }

    pub fn stats(&self) -> BlocklistStats {
        BlocklistStats {
            total_domains: self.blocked_domains.len(),
            categories: self.categories.iter()
                .map(|(k, v)| (k.clone(), v.len()))
                .collect(),
        }
    }
}

#[derive(Debug)]
pub struct BlocklistStats {
    pub total_domains: usize,
    pub categories: HashMap<String, usize>,
}
```

### DNS Cache

```rust
use std::time::{Duration, Instant};

/// DNS response cache with TTL
pub struct DnsCache {
    entries: HashMap<CacheKey, CacheEntry>,
    max_size: usize,
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct CacheKey {
    domain: String,
    record_type: u16,
}

struct CacheEntry {
    response: DnsResponse,
    expires_at: Instant,
    hits: u64,
}

impl DnsCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_size,
        }
    }

    pub fn get(&self, domain: &str, record_type: RecordType) -> Option<DnsResponse> {
        let key = CacheKey {
            domain: domain.to_lowercase(),
            record_type: record_type as u16,
        };

        self.entries.get(&key).and_then(|entry| {
            if Instant::now() < entry.expires_at {
                Some(entry.response.clone())
            } else {
                None
            }
        })
    }

    pub fn insert(
        &mut self,
        domain: String,
        record_type: RecordType,
        response: DnsResponse,
        ttl: u32,
    ) {
        // Evict expired entries if at capacity
        if self.entries.len() >= self.max_size {
            self.evict_expired();
        }

        // If still at capacity, evict least used
        if self.entries.len() >= self.max_size {
            self.evict_least_used();
        }

        let key = CacheKey {
            domain: domain.to_lowercase(),
            record_type: record_type as u16,
        };

        let entry = CacheEntry {
            response,
            expires_at: Instant::now() + Duration::from_secs(ttl as u64),
            hits: 0,
        };

        self.entries.insert(key, entry);
    }

    fn evict_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.expires_at > now);
    }

    fn evict_least_used(&mut self) {
        if let Some(key) = self.entries.iter()
            .min_by_key(|(_, entry)| entry.hits)
            .map(|(k, _)| k.clone())
        {
            self.entries.remove(&key);
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn stats(&self) -> CacheStats {
        let now = Instant::now();
        let valid_entries = self.entries.values()
            .filter(|e| e.expires_at > now)
            .count();

        CacheStats {
            total_entries: self.entries.len(),
            valid_entries,
            expired_entries: self.entries.len() - valid_entries,
        }
    }
}

#[derive(Debug)]
pub struct CacheStats {
    pub total_entries: usize,
    pub valid_entries: usize,
    pub expired_entries: usize,
}
```

### Query Logger

```rust
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

/// DNS query logger
pub struct QueryLogger {
    file: tokio::sync::Mutex<tokio::fs::File>,
}

impl QueryLogger {
    pub async fn new(path: &std::path::Path) -> Result<Self, DnsProxyError> {
        // Ensure directory exists
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;

        Ok(Self {
            file: tokio::sync::Mutex::new(file),
        })
    }

    pub async fn log_query(&self, query: &DnsQuery) {
        let log_entry = format!(
            "{}\tQUERY\t{}\t{}\t{:?}\n",
            query.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
            query.client_addr,
            query.domain,
            query.record_type,
        );

        let mut file = self.file.lock().await;
        let _ = file.write_all(log_entry.as_bytes()).await;
    }

    pub async fn log_response(&self, query: &DnsQuery, response: &DnsResponse) {
        let log_entry = format!(
            "{}\tRESPONSE\t{}\t{}\t{:?}\t{:?}\n",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            query.client_addr,
            query.domain,
            query.record_type,
            response.response_code,
        );

        let mut file = self.file.lock().await;
        let _ = file.write_all(log_entry.as_bytes()).await;
    }

    pub async fn log_blocked(&self, query: &DnsQuery, category: &str) {
        let log_entry = format!(
            "{}\tBLOCKED\t{}\t{}\t{}\n",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            query.client_addr,
            query.domain,
            category,
        );

        let mut file = self.file.lock().await;
        let _ = file.write_all(log_entry.as_bytes()).await;
    }
}
```

## Output Format

```json
{
  "dns_proxy_status": {
    "uptime_seconds": 86400,
    "listen_address": "0.0.0.0:53",
    "upstream_mode": "DoH",
    "upstream_endpoint": "https://cloudflare-dns.com/dns-query"
  },
  "statistics": {
    "total_queries": 1542876,
    "blocked_queries": 45231,
    "cache_hits": 876543,
    "cache_hit_rate": 0.568,
    "average_response_time_ms": 12.5
  },
  "blocklist_stats": {
    "total_domains": 234567,
    "categories": {
      "malware": 15432,
      "ads": 189234,
      "trackers": 29901
    }
  },
  "cache_stats": {
    "total_entries": 8765,
    "valid_entries": 8432,
    "expired_entries": 333
  },
  "top_blocked_domains": [
    { "domain": "ads.doubleclick.net", "count": 12345, "category": "ads" },
    { "domain": "tracking.example.com", "count": 8765, "category": "trackers" }
  ],
  "top_queried_domains": [
    { "domain": "google.com", "count": 45678 },
    { "domain": "cloudflare.com", "count": 23456 }
  ]
}
```

## Success Criteria

1. DoH client successfully queries upstream resolvers
2. DoT client establishes TLS connections correctly
3. DNS packets are parsed and rebuilt accurately
4. Blocklists load from multiple formats (hosts, AdBlock)
5. Sinkhole responses return correct DNS format
6. Cache improves response times significantly
7. Query logging captures all DNS activity
8. Rate limiting prevents abuse
9. Subdomain blocking works for blocked parent domains
10. DNSSEC validation prevents spoofed responses
