# Rust DNS Proxy Template

Secure DNS proxy with DoH/DoT support, sinkholing, and query analysis.

## Project Structure

```
rust-dns-proxy/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── server/
│   │   ├── mod.rs
│   │   ├── udp.rs
│   │   ├── tcp.rs
│   │   └── listener.rs
│   ├── protocol/
│   │   ├── mod.rs
│   │   ├── dns.rs
│   │   ├── doh.rs
│   │   └── dot.rs
│   ├── resolver/
│   │   ├── mod.rs
│   │   ├── upstream.rs
│   │   └── cache.rs
│   ├── filtering/
│   │   ├── mod.rs
│   │   ├── blocklist.rs
│   │   ├── sinkhole.rs
│   │   └── categories.rs
│   ├── logging/
│   │   ├── mod.rs
│   │   └── query_log.rs
│   └── config.rs
└── blocklists/
    └── default.txt
```

## Cargo.toml

```toml
[package]
name = "rust-dns-proxy"
version = "0.1.0"
edition = "2021"
rust-version = "1.92"

[dependencies]
tokio = { version = "1", features = ["full"] }
trust-dns-proto = "0.24"
trust-dns-resolver = "0.24"
rustls = "0.23"
webpki-roots = "0.26"
bytes = "1"
lru = "0.12"
parking_lot = "0.12"
serde = { version = "1", features = ["derive"] }
toml = "0.8"
tracing = "0.1"
tracing-subscriber = "0.3"
thiserror = "2"
anyhow = "1"
hyper = { version = "1", features = ["http1", "http2", "server"] }
hyper-util = { version = "0.1", features = ["tokio"] }
base64 = "0.22"
```

## Core Implementation

### src/lib.rs

```rust
pub mod server;
pub mod protocol;
pub mod resolver;
pub mod filtering;
pub mod logging;
pub mod config;

pub use config::Config;
```

### src/protocol/dns.rs

```rust
use bytes::{Bytes, BytesMut, BufMut};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("Invalid DNS message")]
    InvalidMessage,
    #[error("Message too short")]
    TooShort,
    #[error("Invalid label")]
    InvalidLabel,
}

#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authority: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl DnsMessage {
    pub fn parse(data: &[u8]) -> Result<Self, DnsError> {
        if data.len() < 12 {
            return Err(DnsError::TooShort);
        }

        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
        let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
        let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

        let mut offset = 12;
        let mut questions = Vec::with_capacity(qdcount);

        for _ in 0..qdcount {
            let (name, new_offset) = Self::parse_name(data, offset)?;
            offset = new_offset;

            if offset + 4 > data.len() {
                return Err(DnsError::TooShort);
            }

            let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;

            questions.push(DnsQuestion { name, qtype, qclass });
        }

        // Parse answers, authority, and additional sections similarly
        let answers = Self::parse_records(data, &mut offset, ancount)?;
        let authority = Self::parse_records(data, &mut offset, nscount)?;
        let additional = Self::parse_records(data, &mut offset, arcount)?;

        Ok(Self {
            id,
            flags,
            questions,
            answers,
            authority,
            additional,
        })
    }

    fn parse_name(data: &[u8], mut offset: usize) -> Result<(String, usize), DnsError> {
        let mut name = String::new();
        let mut jumped = false;
        let mut jump_offset = 0;

        loop {
            if offset >= data.len() {
                return Err(DnsError::TooShort);
            }

            let len = data[offset] as usize;

            if len == 0 {
                if !jumped {
                    offset += 1;
                }
                break;
            }

            // Compression pointer
            if len & 0xC0 == 0xC0 {
                if offset + 1 >= data.len() {
                    return Err(DnsError::TooShort);
                }
                let pointer = ((len & 0x3F) << 8) | data[offset + 1] as usize;
                if !jumped {
                    jump_offset = offset + 2;
                }
                jumped = true;
                offset = pointer;
                continue;
            }

            offset += 1;
            if offset + len > data.len() {
                return Err(DnsError::TooShort);
            }

            if !name.is_empty() {
                name.push('.');
            }

            let label = std::str::from_utf8(&data[offset..offset + len])
                .map_err(|_| DnsError::InvalidLabel)?;
            name.push_str(label);
            offset += len;
        }

        let final_offset = if jumped { jump_offset } else { offset };
        Ok((name, final_offset))
    }

    fn parse_records(
        data: &[u8],
        offset: &mut usize,
        count: usize,
    ) -> Result<Vec<DnsRecord>, DnsError> {
        let mut records = Vec::with_capacity(count);

        for _ in 0..count {
            let (name, new_offset) = Self::parse_name(data, *offset)?;
            *offset = new_offset;

            if *offset + 10 > data.len() {
                return Err(DnsError::TooShort);
            }

            let rtype = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
            let rclass = u16::from_be_bytes([data[*offset + 2], data[*offset + 3]]);
            let ttl = u32::from_be_bytes([
                data[*offset + 4], data[*offset + 5],
                data[*offset + 6], data[*offset + 7],
            ]);
            let rdlen = u16::from_be_bytes([data[*offset + 8], data[*offset + 9]]) as usize;
            *offset += 10;

            if *offset + rdlen > data.len() {
                return Err(DnsError::TooShort);
            }

            let rdata = data[*offset..*offset + rdlen].to_vec();
            *offset += rdlen;

            records.push(DnsRecord { name, rtype, rclass, ttl, rdata });
        }

        Ok(records)
    }

    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(512);

        buf.put_u16(self.id);
        buf.put_u16(self.flags);
        buf.put_u16(self.questions.len() as u16);
        buf.put_u16(self.answers.len() as u16);
        buf.put_u16(self.authority.len() as u16);
        buf.put_u16(self.additional.len() as u16);

        for q in &self.questions {
            Self::write_name(&mut buf, &q.name);
            buf.put_u16(q.qtype);
            buf.put_u16(q.qclass);
        }

        for record in self.answers.iter()
            .chain(self.authority.iter())
            .chain(self.additional.iter())
        {
            Self::write_name(&mut buf, &record.name);
            buf.put_u16(record.rtype);
            buf.put_u16(record.rclass);
            buf.put_u32(record.ttl);
            buf.put_u16(record.rdata.len() as u16);
            buf.put_slice(&record.rdata);
        }

        buf.freeze()
    }

    fn write_name(buf: &mut BytesMut, name: &str) {
        for label in name.split('.') {
            buf.put_u8(label.len() as u8);
            buf.put_slice(label.as_bytes());
        }
        buf.put_u8(0);
    }

    /// Create NXDOMAIN response (sinkhole)
    pub fn sinkhole_response(query: &DnsMessage) -> Self {
        Self {
            id: query.id,
            flags: 0x8183, // Response, NXDOMAIN
            questions: query.questions.clone(),
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    /// Create response with sinkhole IP
    pub fn sinkhole_ip_response(query: &DnsMessage, ip: std::net::Ipv4Addr) -> Self {
        let answers = query.questions.iter()
            .filter(|q| q.qtype == 1) // A record
            .map(|q| DnsRecord {
                name: q.name.clone(),
                rtype: 1,
                rclass: 1,
                ttl: 300,
                rdata: ip.octets().to_vec(),
            })
            .collect();

        Self {
            id: query.id,
            flags: 0x8180, // Response, No error
            questions: query.questions.clone(),
            answers,
            authority: vec![],
            additional: vec![],
        }
    }
}
```

### src/filtering/blocklist.rs

```rust
use std::collections::HashSet;
use std::path::Path;
use tokio::fs;
use tracing::{info, warn};

pub struct Blocklist {
    domains: HashSet<String>,
    wildcards: Vec<String>,
}

impl Blocklist {
    pub fn new() -> Self {
        Self {
            domains: HashSet::new(),
            wildcards: Vec::new(),
        }
    }

    pub async fn load_from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path).await?;
        let mut blocklist = Self::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with("*.") {
                blocklist.wildcards.push(line[2..].to_lowercase());
            } else {
                blocklist.domains.insert(line.to_lowercase());
            }
        }

        info!(
            "Loaded {} domains and {} wildcards",
            blocklist.domains.len(),
            blocklist.wildcards.len()
        );

        Ok(blocklist)
    }

    pub async fn load_from_url(url: &str) -> anyhow::Result<Self> {
        let response = reqwest::get(url).await?.text().await?;
        let mut blocklist = Self::new();

        for line in response.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }

            // Handle hosts file format: 0.0.0.0 domain.com
            let domain = if line.starts_with("0.0.0.0") || line.starts_with("127.0.0.1") {
                line.split_whitespace().nth(1).unwrap_or("")
            } else {
                line
            };

            if !domain.is_empty() && domain != "localhost" {
                blocklist.domains.insert(domain.to_lowercase());
            }
        }

        info!("Loaded {} domains from {}", blocklist.domains.len(), url);
        Ok(blocklist)
    }

    pub fn is_blocked(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        // Exact match
        if self.domains.contains(&domain_lower) {
            return true;
        }

        // Wildcard match
        for wildcard in &self.wildcards {
            if domain_lower.ends_with(wildcard) {
                return true;
            }
        }

        // Check parent domains
        let mut parts: Vec<&str> = domain_lower.split('.').collect();
        while parts.len() > 1 {
            parts.remove(0);
            let parent = parts.join(".");
            if self.domains.contains(&parent) {
                return true;
            }
        }

        false
    }

    pub fn add_domain(&mut self, domain: &str) {
        self.domains.insert(domain.to_lowercase());
    }

    pub fn remove_domain(&mut self, domain: &str) {
        self.domains.remove(&domain.to_lowercase());
    }

    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }
}

impl Default for Blocklist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let mut blocklist = Blocklist::new();
        blocklist.add_domain("malware.com");

        assert!(blocklist.is_blocked("malware.com"));
        assert!(!blocklist.is_blocked("safe.com"));
    }

    #[test]
    fn test_subdomain_blocked() {
        let mut blocklist = Blocklist::new();
        blocklist.add_domain("malware.com");

        assert!(blocklist.is_blocked("sub.malware.com"));
        assert!(blocklist.is_blocked("deep.sub.malware.com"));
    }
}
```

### src/resolver/cache.rs

```rust
use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use crate::protocol::dns::DnsMessage;

struct CacheEntry {
    message: DnsMessage,
    expires: Instant,
}

pub struct DnsCache {
    cache: Mutex<LruCache<String, CacheEntry>>,
    min_ttl: u32,
    max_ttl: u32,
}

impl DnsCache {
    pub fn new(capacity: usize, min_ttl: u32, max_ttl: u32) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::MIN),
            )),
            min_ttl,
            max_ttl,
        }
    }

    pub fn get(&self, query: &DnsMessage) -> Option<DnsMessage> {
        let key = self.cache_key(query);
        let mut cache = self.cache.lock();

        if let Some(entry) = cache.get(&key) {
            if entry.expires > Instant::now() {
                let mut response = entry.message.clone();
                response.id = query.id;

                // Update TTLs based on remaining time
                let remaining = entry.expires.duration_since(Instant::now()).as_secs() as u32;
                for answer in &mut response.answers {
                    answer.ttl = remaining.max(1);
                }

                return Some(response);
            } else {
                cache.pop(&key);
            }
        }

        None
    }

    pub fn put(&self, query: &DnsMessage, response: &DnsMessage) {
        let key = self.cache_key(query);

        // Calculate TTL from response
        let ttl = response.answers.iter()
            .map(|r| r.ttl)
            .min()
            .unwrap_or(300)
            .clamp(self.min_ttl, self.max_ttl);

        let entry = CacheEntry {
            message: response.clone(),
            expires: Instant::now() + Duration::from_secs(ttl as u64),
        };

        self.cache.lock().put(key, entry);
    }

    fn cache_key(&self, query: &DnsMessage) -> String {
        query.questions.iter()
            .map(|q| format!("{}:{}:{}", q.name, q.qtype, q.qclass))
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn clear(&self) {
        self.cache.lock().clear();
    }

    pub fn len(&self) -> usize {
        self.cache.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
```

### src/protocol/doh.rs

```rust
use bytes::Bytes;
use hyper::{Request, Response, body::Incoming, StatusCode};
use http_body_util::Full;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::protocol::dns::DnsMessage;

pub struct DohHandler {
    resolver: std::sync::Arc<crate::resolver::Resolver>,
}

impl DohHandler {
    pub fn new(resolver: std::sync::Arc<crate::resolver::Resolver>) -> Self {
        Self { resolver }
    }

    pub async fn handle(&self, req: Request<Incoming>) -> Response<Full<Bytes>> {
        let result = match *req.method() {
            hyper::Method::GET => self.handle_get(req).await,
            hyper::Method::POST => self.handle_post(req).await,
            _ => {
                return Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Full::new(Bytes::new()))
                    .unwrap();
            }
        };

        match result {
            Ok(response) => Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/dns-message")
                .body(Full::new(response))
                .unwrap(),
            Err(e) => {
                tracing::error!("DoH error: {}", e);
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from(e.to_string())))
                    .unwrap()
            }
        }
    }

    async fn handle_get(&self, req: Request<Incoming>) -> anyhow::Result<Bytes> {
        let query_string = req.uri().query().unwrap_or("");
        let dns_param = query_string
            .split('&')
            .find_map(|p| {
                let mut parts = p.splitn(2, '=');
                match (parts.next(), parts.next()) {
                    (Some("dns"), Some(value)) => Some(value),
                    _ => None,
                }
            })
            .ok_or_else(|| anyhow::anyhow!("Missing dns parameter"))?;

        let query_bytes = URL_SAFE_NO_PAD.decode(dns_param)?;
        self.resolve(&query_bytes).await
    }

    async fn handle_post(&self, req: Request<Incoming>) -> anyhow::Result<Bytes> {
        use http_body_util::BodyExt;

        let body = req.collect().await?.to_bytes();
        self.resolve(&body).await
    }

    async fn resolve(&self, query_bytes: &[u8]) -> anyhow::Result<Bytes> {
        let query = DnsMessage::parse(query_bytes)?;
        let response = self.resolver.resolve(query).await?;
        Ok(response.serialize())
    }
}
```

### src/server/udp.rs

```rust
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{info, error, debug};

use crate::resolver::Resolver;
use crate::protocol::dns::DnsMessage;
use crate::filtering::Blocklist;
use crate::logging::QueryLogger;

pub struct UdpServer {
    socket: UdpSocket,
    resolver: Arc<Resolver>,
    blocklist: Arc<Blocklist>,
    logger: Arc<QueryLogger>,
    sinkhole_ip: Option<std::net::Ipv4Addr>,
}

impl UdpServer {
    pub async fn bind(
        addr: SocketAddr,
        resolver: Arc<Resolver>,
        blocklist: Arc<Blocklist>,
        logger: Arc<QueryLogger>,
        sinkhole_ip: Option<std::net::Ipv4Addr>,
    ) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        info!("DNS UDP server listening on {}", addr);

        Ok(Self {
            socket,
            resolver,
            blocklist,
            logger,
            sinkhole_ip,
        })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let mut buf = vec![0u8; 512];

        loop {
            let (len, src) = self.socket.recv_from(&mut buf).await?;
            let data = buf[..len].to_vec();

            let resolver = Arc::clone(&self.resolver);
            let blocklist = Arc::clone(&self.blocklist);
            let logger = Arc::clone(&self.logger);
            let socket = self.socket.try_clone()?;
            let sinkhole_ip = self.sinkhole_ip;

            tokio::spawn(async move {
                if let Err(e) = Self::handle_query(
                    &data, src, &socket, &resolver, &blocklist, &logger, sinkhole_ip
                ).await {
                    error!("Error handling query from {}: {}", src, e);
                }
            });
        }
    }

    async fn handle_query(
        data: &[u8],
        src: SocketAddr,
        socket: &UdpSocket,
        resolver: &Resolver,
        blocklist: &Blocklist,
        logger: &QueryLogger,
        sinkhole_ip: Option<std::net::Ipv4Addr>,
    ) -> anyhow::Result<()> {
        let query = DnsMessage::parse(data)?;

        let domain = query.questions.first()
            .map(|q| q.name.as_str())
            .unwrap_or("");

        // Log the query
        logger.log_query(src, domain, query.questions.first().map(|q| q.qtype).unwrap_or(0));

        // Check blocklist
        let response = if blocklist.is_blocked(domain) {
            debug!("Blocked query for {} from {}", domain, src);
            logger.log_blocked(src, domain);

            match sinkhole_ip {
                Some(ip) => DnsMessage::sinkhole_ip_response(&query, ip),
                None => DnsMessage::sinkhole_response(&query),
            }
        } else {
            resolver.resolve(query).await?
        };

        let response_bytes = response.serialize();
        socket.send_to(&response_bytes, src).await?;

        Ok(())
    }
}
```

### src/main.rs

```rust
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber;

mod config;
mod filtering;
mod logging;
mod protocol;
mod resolver;
mod server;

use config::Config;
use filtering::Blocklist;
use logging::QueryLogger;
use resolver::Resolver;
use server::UdpServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = Config::load("config.toml").await?;
    info!("Loaded configuration");

    // Initialize components
    let blocklist = Arc::new(
        Blocklist::load_from_file(&config.blocklist_path).await
            .unwrap_or_else(|_| Blocklist::new())
    );
    info!("Loaded {} blocked domains", blocklist.domain_count());

    let logger = Arc::new(QueryLogger::new(&config.log_path)?);

    let resolver = Arc::new(Resolver::new(
        config.upstream_servers.clone(),
        config.cache_size,
    ).await?);

    // Start UDP server
    let addr: SocketAddr = config.listen_addr.parse()?;
    let server = UdpServer::bind(
        addr,
        resolver,
        blocklist,
        logger,
        config.sinkhole_ip,
    ).await?;

    info!("DNS proxy started on {}", addr);
    server.run().await
}
```

## Security Checklist

- [ ] Validate all DNS messages before processing
- [ ] Implement query rate limiting per client
- [ ] Use DoH/DoT for upstream queries
- [ ] Sanitize domain names in logs
- [ ] Implement DNSSEC validation
- [ ] Protect against DNS amplification attacks
- [ ] Limit recursion depth for compression pointers
- [ ] Implement query timeout handling
- [ ] Use secure random for transaction IDs
- [ ] Monitor for DNS tunneling attempts
