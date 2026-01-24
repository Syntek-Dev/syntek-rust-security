# Rust DNS Security Skills

This skill provides patterns for building secure DNS proxies in Rust with
DoH/DoT support, DNS sinkholing, query logging, and malicious domain blocking.

## Overview

DNS security encompasses:

- **DoH/DoT**: Encrypted DNS protocols
- **Sinkholing**: Block malicious domains
- **Query Logging**: Audit trail and analytics
- **Filtering**: Ad/tracker blocking
- **Caching**: Performance and privacy

## /dns-proxy-setup

Initialize a secure DNS proxy.

### Usage

```bash
/dns-proxy-setup
```

### What It Does

1. Creates DNS proxy infrastructure
2. Implements DoH/DoT clients
3. Sets up domain blocking
4. Configures query logging
5. Implements caching

---

## DNS Message Parsing

### DNS Message Types

```rust
#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authority: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
}

#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: DnsFlags,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct DnsFlags {
    pub qr: bool,       // Query/Response
    pub opcode: u8,     // Operation code
    pub aa: bool,       // Authoritative
    pub tc: bool,       // Truncated
    pub rd: bool,       // Recursion desired
    pub ra: bool,       // Recursion available
    pub z: u8,          // Reserved
    pub rcode: u8,      // Response code
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: DnsType,
    pub qclass: DnsClass,
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: DnsType,
    pub rclass: DnsClass,
    pub ttl: u32,
    pub rdata: RData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    HTTPS = 65,
    ANY = 255,
}

#[derive(Debug, Clone, Copy)]
pub enum DnsClass {
    IN = 1,
    CH = 3,
    HS = 4,
    ANY = 255,
}

#[derive(Debug, Clone)]
pub enum RData {
    A(std::net::Ipv4Addr),
    AAAA(std::net::Ipv6Addr),
    CNAME(String),
    MX { preference: u16, exchange: String },
    NS(String),
    TXT(String),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Unknown(Vec<u8>),
}
```

### DNS Parser

```rust
pub struct DnsParser;

impl DnsParser {
    pub fn parse(data: &[u8]) -> Result<DnsMessage, ParseError> {
        if data.len() < 12 {
            return Err(ParseError::TooShort);
        }

        let header = Self::parse_header(data)?;
        let mut offset = 12;

        let mut questions = Vec::new();
        for _ in 0..header.qdcount {
            let (question, new_offset) = Self::parse_question(data, offset)?;
            questions.push(question);
            offset = new_offset;
        }

        let mut answers = Vec::new();
        for _ in 0..header.ancount {
            let (record, new_offset) = Self::parse_record(data, offset)?;
            answers.push(record);
            offset = new_offset;
        }

        let mut authority = Vec::new();
        for _ in 0..header.nscount {
            let (record, new_offset) = Self::parse_record(data, offset)?;
            authority.push(record);
            offset = new_offset;
        }

        let mut additional = Vec::new();
        for _ in 0..header.arcount {
            let (record, new_offset) = Self::parse_record(data, offset)?;
            additional.push(record);
            offset = new_offset;
        }

        Ok(DnsMessage {
            header,
            questions,
            answers,
            authority,
            additional,
        })
    }

    fn parse_header(data: &[u8]) -> Result<DnsHeader, ParseError> {
        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags_raw = u16::from_be_bytes([data[2], data[3]]);

        let flags = DnsFlags {
            qr: (flags_raw >> 15) & 1 == 1,
            opcode: ((flags_raw >> 11) & 0xF) as u8,
            aa: (flags_raw >> 10) & 1 == 1,
            tc: (flags_raw >> 9) & 1 == 1,
            rd: (flags_raw >> 8) & 1 == 1,
            ra: (flags_raw >> 7) & 1 == 1,
            z: ((flags_raw >> 4) & 0x7) as u8,
            rcode: (flags_raw & 0xF) as u8,
        };

        Ok(DnsHeader {
            id,
            flags,
            qdcount: u16::from_be_bytes([data[4], data[5]]),
            ancount: u16::from_be_bytes([data[6], data[7]]),
            nscount: u16::from_be_bytes([data[8], data[9]]),
            arcount: u16::from_be_bytes([data[10], data[11]]),
        })
    }

    fn parse_name(data: &[u8], mut offset: usize) -> Result<(String, usize), ParseError> {
        let mut name = String::new();
        let mut jumped = false;
        let mut original_offset = offset;

        loop {
            if offset >= data.len() {
                return Err(ParseError::InvalidName);
            }

            let len = data[offset] as usize;

            if len == 0 {
                if !jumped {
                    original_offset = offset + 1;
                }
                break;
            }

            // Check for compression pointer
            if len & 0xC0 == 0xC0 {
                if offset + 1 >= data.len() {
                    return Err(ParseError::InvalidName);
                }
                let pointer = ((len & 0x3F) << 8) | (data[offset + 1] as usize);
                if !jumped {
                    original_offset = offset + 2;
                }
                offset = pointer;
                jumped = true;
                continue;
            }

            offset += 1;
            if offset + len > data.len() {
                return Err(ParseError::InvalidName);
            }

            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&String::from_utf8_lossy(&data[offset..offset + len]));
            offset += len;
        }

        Ok((name, original_offset))
    }

    fn parse_question(data: &[u8], offset: usize) -> Result<(DnsQuestion, usize), ParseError> {
        let (name, mut offset) = Self::parse_name(data, offset)?;

        if offset + 4 > data.len() {
            return Err(ParseError::TooShort);
        }

        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);

        Ok((
            DnsQuestion {
                name,
                qtype: DnsType::from_u16(qtype),
                qclass: DnsClass::from_u16(qclass),
            },
            offset + 4,
        ))
    }

    fn parse_record(data: &[u8], offset: usize) -> Result<(DnsRecord, usize), ParseError> {
        let (name, mut offset) = Self::parse_name(data, offset)?;

        if offset + 10 > data.len() {
            return Err(ParseError::TooShort);
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let ttl = u32::from_be_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;

        offset += 10;

        if offset + rdlength > data.len() {
            return Err(ParseError::TooShort);
        }

        let rdata = Self::parse_rdata(data, offset, rdlength, DnsType::from_u16(rtype))?;

        Ok((
            DnsRecord {
                name,
                rtype: DnsType::from_u16(rtype),
                rclass: DnsClass::from_u16(rclass),
                ttl,
                rdata,
            },
            offset + rdlength,
        ))
    }

    fn parse_rdata(data: &[u8], offset: usize, len: usize, rtype: DnsType) -> Result<RData, ParseError> {
        match rtype {
            DnsType::A if len == 4 => {
                Ok(RData::A(std::net::Ipv4Addr::new(
                    data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
                )))
            }
            DnsType::AAAA if len == 16 => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&data[offset..offset + 16]);
                Ok(RData::AAAA(std::net::Ipv6Addr::from(bytes)))
            }
            DnsType::CNAME | DnsType::NS | DnsType::PTR => {
                let (name, _) = Self::parse_name(data, offset)?;
                Ok(RData::CNAME(name))
            }
            _ => Ok(RData::Unknown(data[offset..offset + len].to_vec())),
        }
    }
}

impl DnsType {
    fn from_u16(value: u16) -> Self {
        match value {
            1 => DnsType::A,
            2 => DnsType::NS,
            5 => DnsType::CNAME,
            6 => DnsType::SOA,
            12 => DnsType::PTR,
            15 => DnsType::MX,
            16 => DnsType::TXT,
            28 => DnsType::AAAA,
            33 => DnsType::SRV,
            65 => DnsType::HTTPS,
            255 => DnsType::ANY,
            _ => DnsType::ANY,
        }
    }
}

impl DnsClass {
    fn from_u16(value: u16) -> Self {
        match value {
            1 => DnsClass::IN,
            3 => DnsClass::CH,
            4 => DnsClass::HS,
            255 => DnsClass::ANY,
            _ => DnsClass::IN,
        }
    }
}
```

---

## DoH Client

```rust
use reqwest::Client;

pub struct DohClient {
    client: Client,
    server_url: String,
}

impl DohClient {
    pub fn new(server_url: &str) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            server_url: server_url.to_string(),
        }
    }

    pub async fn query(&self, message: &DnsMessage) -> Result<DnsMessage, Error> {
        let wire = DnsSerializer::serialize(message)?;

        // DoH POST request
        let response = self.client
            .post(&self.server_url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(wire)
            .send()
            .await
            .map_err(Error::HttpRequest)?;

        if !response.status().is_success() {
            return Err(Error::HttpStatus(response.status().as_u16()));
        }

        let body = response.bytes().await.map_err(Error::HttpRequest)?;
        DnsParser::parse(&body).map_err(Error::DnsParse)
    }

    pub async fn query_domain(&self, domain: &str, qtype: DnsType) -> Result<DnsMessage, Error> {
        let message = DnsMessage::query(domain, qtype);
        self.query(&message).await
    }
}

impl DnsMessage {
    pub fn query(domain: &str, qtype: DnsType) -> Self {
        use rand::Rng;

        Self {
            header: DnsHeader {
                id: rand::thread_rng().gen(),
                flags: DnsFlags {
                    qr: false,
                    opcode: 0,
                    aa: false,
                    tc: false,
                    rd: true,
                    ra: false,
                    z: 0,
                    rcode: 0,
                },
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![DnsQuestion {
                name: domain.to_string(),
                qtype,
                qclass: DnsClass::IN,
            }],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }
}
```

---

## DoT Client

```rust
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub struct DotClient {
    server: String,
    port: u16,
    tls_config: Arc<rustls::ClientConfig>,
}

impl DotClient {
    pub fn new(server: &str, port: u16) -> Result<Self, Error> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            })
        );

        let tls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Self {
            server: server.to_string(),
            port,
            tls_config: Arc::new(tls_config),
        })
    }

    pub async fn query(&self, message: &DnsMessage) -> Result<DnsMessage, Error> {
        let wire = DnsSerializer::serialize(message)?;

        // Connect
        let tcp = TcpStream::connect(format!("{}:{}", self.server, self.port))
            .await
            .map_err(Error::TcpConnect)?;

        let connector = TlsConnector::from(self.tls_config.clone());
        let server_name = rustls::ServerName::try_from(self.server.as_str())
            .map_err(|_| Error::InvalidServerName)?;

        let mut tls = connector.connect(server_name, tcp)
            .await
            .map_err(Error::TlsConnect)?;

        // DNS over TLS uses a 2-byte length prefix
        let len_prefix = (wire.len() as u16).to_be_bytes();
        tokio::io::AsyncWriteExt::write_all(&mut tls, &len_prefix).await?;
        tokio::io::AsyncWriteExt::write_all(&mut tls, &wire).await?;

        // Read response
        let mut len_buf = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut tls, &mut len_buf).await?;
        let response_len = u16::from_be_bytes(len_buf) as usize;

        let mut response_buf = vec![0u8; response_len];
        tokio::io::AsyncReadExt::read_exact(&mut tls, &mut response_buf).await?;

        DnsParser::parse(&response_buf).map_err(Error::DnsParse)
    }
}
```

---

## DNS Sinkhole

```rust
use std::collections::HashSet;

pub struct DnsSinkhole {
    blocked_domains: HashSet<String>,
    blocked_patterns: Vec<regex::Regex>,
    sinkhole_ip: std::net::Ipv4Addr,
    sinkhole_ipv6: std::net::Ipv6Addr,
}

impl DnsSinkhole {
    pub fn new() -> Self {
        Self {
            blocked_domains: HashSet::new(),
            blocked_patterns: Vec::new(),
            sinkhole_ip: std::net::Ipv4Addr::new(0, 0, 0, 0),
            sinkhole_ipv6: std::net::Ipv6Addr::UNSPECIFIED,
        }
    }

    pub fn with_sinkhole_ip(mut self, ip: std::net::Ipv4Addr) -> Self {
        self.sinkhole_ip = ip;
        self
    }

    pub fn load_blocklist(&mut self, path: &std::path::Path) -> Result<usize, Error> {
        let content = std::fs::read_to_string(path)?;
        let mut count = 0;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Handle various blocklist formats
            let domain = if line.starts_with("0.0.0.0 ") || line.starts_with("127.0.0.1 ") {
                line.split_whitespace().nth(1)
            } else if line.starts_with("||") && line.ends_with("^") {
                // AdBlock format
                Some(&line[2..line.len() - 1])
            } else {
                Some(line)
            };

            if let Some(domain) = domain {
                let domain = domain.trim().to_lowercase();
                if !domain.is_empty() && domain != "localhost" {
                    self.blocked_domains.insert(domain);
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    pub fn add_pattern(&mut self, pattern: &str) -> Result<(), Error> {
        let re = regex::Regex::new(pattern).map_err(Error::InvalidPattern)?;
        self.blocked_patterns.push(re);
        Ok(())
    }

    pub fn should_block(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        // Check exact match
        if self.blocked_domains.contains(&domain_lower) {
            return true;
        }

        // Check parent domains
        let parts: Vec<&str> = domain_lower.split('.').collect();
        for i in 1..parts.len() {
            let parent = parts[i..].join(".");
            if self.blocked_domains.contains(&parent) {
                return true;
            }
        }

        // Check patterns
        for pattern in &self.blocked_patterns {
            if pattern.is_match(&domain_lower) {
                return true;
            }
        }

        false
    }

    pub fn create_sinkhole_response(&self, query: &DnsMessage) -> DnsMessage {
        let mut response = query.clone();
        response.header.flags.qr = true;
        response.header.flags.aa = true;
        response.header.flags.ra = true;
        response.header.ancount = query.questions.len() as u16;

        for question in &query.questions {
            let rdata = match question.qtype {
                DnsType::A => RData::A(self.sinkhole_ip),
                DnsType::AAAA => RData::AAAA(self.sinkhole_ipv6),
                _ => continue,
            };

            response.answers.push(DnsRecord {
                name: question.name.clone(),
                rtype: question.qtype,
                rclass: question.qclass,
                ttl: 300,
                rdata,
            });
        }

        response
    }
}
```

---

## DNS Proxy Server

```rust
use tokio::net::UdpSocket;
use std::sync::Arc;

pub struct DnsProxy {
    sinkhole: DnsSinkhole,
    upstream: Arc<dyn DnsUpstream + Send + Sync>,
    cache: DnsCache,
    logger: DnsQueryLogger,
}

#[async_trait::async_trait]
pub trait DnsUpstream {
    async fn query(&self, message: &DnsMessage) -> Result<DnsMessage, Error>;
}

impl DnsProxy {
    pub fn new(
        sinkhole: DnsSinkhole,
        upstream: Arc<dyn DnsUpstream + Send + Sync>,
    ) -> Self {
        Self {
            sinkhole,
            upstream,
            cache: DnsCache::new(Duration::from_secs(300)),
            logger: DnsQueryLogger::new(),
        }
    }

    pub async fn run(&self, bind_addr: &str) -> Result<(), Error> {
        let socket = UdpSocket::bind(bind_addr).await?;
        tracing::info!("DNS proxy listening on {}", bind_addr);

        let mut buf = vec![0u8; 512];

        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            let data = buf[..len].to_vec();
            let socket = socket.clone();

            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) = this.handle_query(&socket, &data, src).await {
                    tracing::error!("Error handling query from {}: {}", src, e);
                }
            });
        }
    }

    async fn handle_query(
        &self,
        socket: &UdpSocket,
        data: &[u8],
        src: std::net::SocketAddr,
    ) -> Result<(), Error> {
        let query = DnsParser::parse(data)?;

        // Log query
        let domain = query.questions.first()
            .map(|q| q.name.as_str())
            .unwrap_or("unknown");

        self.logger.log_query(src.ip(), domain, query.questions.first().map(|q| q.qtype));

        // Check sinkhole
        if self.sinkhole.should_block(domain) {
            tracing::debug!("Blocking domain: {}", domain);
            let response = self.sinkhole.create_sinkhole_response(&query);
            let response_data = DnsSerializer::serialize(&response)?;
            socket.send_to(&response_data, src).await?;
            return Ok(());
        }

        // Check cache
        if let Some(cached) = self.cache.get(domain, query.questions.first().map(|q| q.qtype)) {
            let mut response = cached;
            response.header.id = query.header.id;
            let response_data = DnsSerializer::serialize(&response)?;
            socket.send_to(&response_data, src).await?;
            return Ok(());
        }

        // Forward to upstream
        let response = self.upstream.query(&query).await?;

        // Cache response
        if !response.answers.is_empty() {
            let ttl = response.answers.iter()
                .map(|r| r.ttl)
                .min()
                .unwrap_or(300);
            self.cache.put(domain, query.questions.first().map(|q| q.qtype), response.clone(), ttl);
        }

        let response_data = DnsSerializer::serialize(&response)?;
        socket.send_to(&response_data, src).await?;

        Ok(())
    }
}
```

---

## DNS Query Logger

```rust
use std::sync::Arc;
use chrono::{DateTime, Utc};

pub struct DnsQueryLogger {
    logs: Arc<parking_lot::RwLock<Vec<QueryLog>>>,
    max_entries: usize,
}

#[derive(Debug, Clone)]
pub struct QueryLog {
    pub timestamp: DateTime<Utc>,
    pub client_ip: std::net::IpAddr,
    pub domain: String,
    pub query_type: Option<DnsType>,
    pub blocked: bool,
    pub response_time_ms: Option<u64>,
}

impl DnsQueryLogger {
    pub fn new() -> Self {
        Self {
            logs: Arc::new(parking_lot::RwLock::new(Vec::new())),
            max_entries: 10000,
        }
    }

    pub fn log_query(&self, client: std::net::IpAddr, domain: &str, qtype: Option<DnsType>) {
        let log = QueryLog {
            timestamp: Utc::now(),
            client_ip: client,
            domain: domain.to_string(),
            query_type: qtype,
            blocked: false,
            response_time_ms: None,
        };

        let mut logs = self.logs.write();
        if logs.len() >= self.max_entries {
            logs.remove(0);
        }
        logs.push(log);
    }

    pub fn get_recent(&self, count: usize) -> Vec<QueryLog> {
        let logs = self.logs.read();
        logs.iter().rev().take(count).cloned().collect()
    }

    pub fn get_top_domains(&self, count: usize) -> Vec<(String, usize)> {
        let logs = self.logs.read();
        let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        for log in logs.iter() {
            *counts.entry(log.domain.clone()).or_insert(0) += 1;
        }

        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.into_iter().take(count).collect()
    }
}
```

---

## Security Checklist

- [ ] DoH/DoT for upstream queries
- [ ] Blocklists regularly updated
- [ ] Query logging with retention policy
- [ ] Rate limiting per client
- [ ] DNSSEC validation (optional)
- [ ] Cache poisoning protection

## Recommended Crates

- **tokio**: Async runtime
- **reqwest**: HTTP client (DoH)
- **tokio-rustls**: TLS (DoT)
- **trust-dns**: Alternative DNS library

## Integration Points

This skill works well with:

- `/threat-feeds-setup` - Domain blocklists
- `/firewall-setup` - Network filtering
