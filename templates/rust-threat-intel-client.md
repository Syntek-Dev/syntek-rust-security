# Rust Threat Intelligence Client Template

Client for integrating threat intelligence feeds including IP/domain blocklists
and IOC matching.

## Project Structure

```
rust-threat-intel-client/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── feeds/
│   │   ├── mod.rs
│   │   ├── provider.rs
│   │   ├── abuse_ch.rs
│   │   ├── spamhaus.rs
│   │   └── custom.rs
│   ├── ioc/
│   │   ├── mod.rs
│   │   ├── ip.rs
│   │   ├── domain.rs
│   │   ├── hash.rs
│   │   └── matcher.rs
│   ├── storage/
│   │   ├── mod.rs
│   │   └── database.rs
│   ├── api/
│   │   ├── mod.rs
│   │   └── server.rs
│   └── config.rs
└── feeds.toml
```

## Cargo.toml

```toml
[package]
name = "rust-threat-intel-client"
version = "0.1.0"
edition = "2021"
rust-version = "1.92"

[dependencies]
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["json", "gzip"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
chrono = { version = "0.4", features = ["serde"] }
ipnetwork = "0.20"
rusqlite = { version = "0.32", features = ["bundled"] }
tracing = "0.1"
tracing-subscriber = "0.3"
thiserror = "2"
anyhow = "1"
axum = "0.7"
tokio-cron-scheduler = "0.13"
sha2 = "0.10"
hex = "0.4"
```

## Core Implementation

### src/lib.rs

```rust
pub mod feeds;
pub mod ioc;
pub mod storage;
pub mod api;
pub mod config;

pub use config::Config;
pub use ioc::{Ioc, IocType, IocMatcher};
```

### src/ioc/mod.rs

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod ip;
pub mod domain;
pub mod hash;
pub mod matcher;

pub use matcher::IocMatcher;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum IocType {
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Md5,
    Sha1,
    Sha256,
    Email,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    pub value: String,
    pub ioc_type: IocType,
    pub source: String,
    pub tags: Vec<String>,
    pub confidence: u8,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub description: Option<String>,
}

impl Ioc {
    pub fn new(value: String, ioc_type: IocType, source: String) -> Self {
        let now = Utc::now();
        Self {
            value,
            ioc_type,
            source,
            tags: Vec::new(),
            confidence: 50,
            first_seen: now,
            last_seen: now,
            description: None,
        }
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence.min(100);
        self
    }
}
```

### src/ioc/matcher.rs

```rust
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use ipnetwork::IpNetwork;
use parking_lot::RwLock;

use super::{Ioc, IocType};

pub struct IocMatcher {
    ips: RwLock<HashSet<IpAddr>>,
    ip_networks: RwLock<Vec<IpNetwork>>,
    domains: RwLock<HashSet<String>>,
    domain_suffixes: RwLock<Vec<String>>,
    hashes: RwLock<HashMap<String, IocType>>,
}

impl IocMatcher {
    pub fn new() -> Self {
        Self {
            ips: RwLock::new(HashSet::new()),
            ip_networks: RwLock::new(Vec::new()),
            domains: RwLock::new(HashSet::new()),
            domain_suffixes: RwLock::new(Vec::new()),
            hashes: RwLock::new(HashMap::new()),
        }
    }

    pub fn add_ioc(&self, ioc: &Ioc) {
        match ioc.ioc_type {
            IocType::Ipv4 | IocType::Ipv6 => {
                if let Ok(ip) = ioc.value.parse::<IpAddr>() {
                    self.ips.write().insert(ip);
                } else if let Ok(network) = ioc.value.parse::<IpNetwork>() {
                    self.ip_networks.write().push(network);
                }
            }
            IocType::Domain => {
                let domain = ioc.value.to_lowercase();
                if domain.starts_with("*.") {
                    self.domain_suffixes.write().push(domain[1..].to_string());
                } else {
                    self.domains.write().insert(domain);
                }
            }
            IocType::Md5 | IocType::Sha1 | IocType::Sha256 => {
                self.hashes.write().insert(
                    ioc.value.to_lowercase(),
                    ioc.ioc_type.clone(),
                );
            }
            _ => {}
        }
    }

    pub fn match_ip(&self, ip: IpAddr) -> bool {
        // Check exact match
        if self.ips.read().contains(&ip) {
            return true;
        }

        // Check network ranges
        for network in self.ip_networks.read().iter() {
            if network.contains(ip) {
                return true;
            }
        }

        false
    }

    pub fn match_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        // Exact match
        if self.domains.read().contains(&domain_lower) {
            return true;
        }

        // Suffix match
        for suffix in self.domain_suffixes.read().iter() {
            if domain_lower.ends_with(suffix) {
                return true;
            }
        }

        // Check parent domains
        let parts: Vec<&str> = domain_lower.split('.').collect();
        for i in 1..parts.len() {
            let parent = parts[i..].join(".");
            if self.domains.read().contains(&parent) {
                return true;
            }
        }

        false
    }

    pub fn match_hash(&self, hash: &str) -> Option<IocType> {
        self.hashes.read().get(&hash.to_lowercase()).cloned()
    }

    pub fn clear(&self) {
        self.ips.write().clear();
        self.ip_networks.write().clear();
        self.domains.write().clear();
        self.domain_suffixes.write().clear();
        self.hashes.write().clear();
    }

    pub fn stats(&self) -> MatcherStats {
        MatcherStats {
            ips: self.ips.read().len(),
            networks: self.ip_networks.read().len(),
            domains: self.domains.read().len(),
            domain_suffixes: self.domain_suffixes.read().len(),
            hashes: self.hashes.read().len(),
        }
    }
}

impl Default for IocMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MatcherStats {
    pub ips: usize,
    pub networks: usize,
    pub domains: usize,
    pub domain_suffixes: usize,
    pub hashes: usize,
}
```

### src/feeds/provider.rs

```rust
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ioc::Ioc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedConfig {
    pub name: String,
    pub url: String,
    pub format: FeedFormat,
    pub update_interval_hours: u32,
    pub enabled: bool,
    pub tags: Vec<String>,
    pub confidence: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FeedFormat {
    PlainList,
    Csv,
    Json,
    Stix,
}

#[derive(Debug, Clone)]
pub struct FeedResult {
    pub feed_name: String,
    pub iocs: Vec<Ioc>,
    pub fetched_at: DateTime<Utc>,
    pub success: bool,
    pub error: Option<String>,
}

#[async_trait]
pub trait FeedProvider: Send + Sync {
    fn name(&self) -> &str;
    async fn fetch(&self) -> anyhow::Result<Vec<Ioc>>;
    fn update_interval(&self) -> std::time::Duration;
}

pub struct GenericFeedProvider {
    config: FeedConfig,
    client: reqwest::Client,
}

impl GenericFeedProvider {
    pub fn new(config: FeedConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    async fn fetch_plain_list(&self, content: &str) -> Vec<Ioc> {
        content.lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|line| {
                let value = line.split_whitespace().next()?.to_string();
                let ioc_type = Self::detect_type(&value)?;
                Some(Ioc::new(value, ioc_type, self.config.name.clone())
                    .with_tags(self.config.tags.clone())
                    .with_confidence(self.config.confidence))
            })
            .collect()
    }

    fn detect_type(value: &str) -> Option<crate::ioc::IocType> {
        use crate::ioc::IocType;

        if value.parse::<std::net::Ipv4Addr>().is_ok() {
            Some(IocType::Ipv4)
        } else if value.parse::<std::net::Ipv6Addr>().is_ok() {
            Some(IocType::Ipv6)
        } else if value.contains('/') && value.parse::<ipnetwork::IpNetwork>().is_ok() {
            Some(IocType::Ipv4) // Network range
        } else if value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(IocType::Md5)
        } else if value.len() == 40 && value.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(IocType::Sha1)
        } else if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(IocType::Sha256)
        } else if value.contains('.') && !value.contains('/') {
            Some(IocType::Domain)
        } else {
            None
        }
    }
}

#[async_trait]
impl FeedProvider for GenericFeedProvider {
    fn name(&self) -> &str {
        &self.config.name
    }

    async fn fetch(&self) -> anyhow::Result<Vec<Ioc>> {
        let response = self.client
            .get(&self.config.url)
            .send()
            .await?
            .text()
            .await?;

        let iocs = match self.config.format {
            FeedFormat::PlainList => self.fetch_plain_list(&response).await,
            FeedFormat::Csv => self.fetch_plain_list(&response).await, // Simplified
            FeedFormat::Json => serde_json::from_str(&response)?,
            FeedFormat::Stix => vec![], // TODO: Implement STIX parser
        };

        Ok(iocs)
    }

    fn update_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.config.update_interval_hours as u64 * 3600)
    }
}
```

### src/feeds/abuse_ch.rs

```rust
use async_trait::async_trait;
use serde::Deserialize;

use crate::ioc::{Ioc, IocType};
use super::provider::FeedProvider;

pub struct FeodoTrackerFeed {
    client: reqwest::Client,
}

impl FeodoTrackerFeed {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct FeodoEntry {
    ip_address: String,
    port: Option<u16>,
    status: String,
    hostname: Option<String>,
    as_number: Option<u32>,
    as_name: Option<String>,
    country: Option<String>,
    first_seen: Option<String>,
    last_online: Option<String>,
    malware: String,
}

#[async_trait]
impl FeedProvider for FeodoTrackerFeed {
    fn name(&self) -> &str {
        "feodo-tracker"
    }

    async fn fetch(&self) -> anyhow::Result<Vec<Ioc>> {
        let url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json";
        let response: Vec<FeodoEntry> = self.client
            .get(url)
            .send()
            .await?
            .json()
            .await?;

        let iocs = response.into_iter()
            .filter(|e| e.status == "online")
            .map(|entry| {
                Ioc::new(entry.ip_address, IocType::Ipv4, "feodo-tracker".into())
                    .with_tags(vec!["botnet".into(), entry.malware])
                    .with_confidence(90)
            })
            .collect();

        Ok(iocs)
    }

    fn update_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(3600) // 1 hour
    }
}

pub struct URLhausFeed {
    client: reqwest::Client,
}

impl URLhausFeed {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl FeedProvider for URLhausFeed {
    fn name(&self) -> &str {
        "urlhaus"
    }

    async fn fetch(&self) -> anyhow::Result<Vec<Ioc>> {
        let url = "https://urlhaus.abuse.ch/downloads/text_online/";
        let response = self.client
            .get(url)
            .send()
            .await?
            .text()
            .await?;

        let iocs = response.lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|url| {
                Ioc::new(url.to_string(), IocType::Url, "urlhaus".into())
                    .with_tags(vec!["malware-distribution".into()])
                    .with_confidence(85)
            })
            .collect();

        Ok(iocs)
    }

    fn update_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(300) // 5 minutes
    }
}
```

### src/storage/database.rs

```rust
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use std::path::Path;
use parking_lot::Mutex;

use crate::ioc::{Ioc, IocType};

pub struct IocDatabase {
    conn: Mutex<Connection>,
}

impl IocDatabase {
    pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;

        conn.execute_batch(r#"
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY,
                value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                source TEXT NOT NULL,
                tags TEXT,
                confidence INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                description TEXT,
                UNIQUE(value, ioc_type, source)
            );

            CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
            CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
            CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source);

            CREATE TABLE IF NOT EXISTS feed_status (
                feed_name TEXT PRIMARY KEY,
                last_update TEXT,
                ioc_count INTEGER,
                success INTEGER,
                error TEXT
            );
        "#)?;

        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn upsert_ioc(&self, ioc: &Ioc) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            r#"INSERT INTO iocs (value, ioc_type, source, tags, confidence, first_seen, last_seen, description)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
               ON CONFLICT(value, ioc_type, source) DO UPDATE SET
                   last_seen = ?7,
                   confidence = MAX(confidence, ?5)"#,
            params![
                ioc.value,
                format!("{:?}", ioc.ioc_type).to_lowercase(),
                ioc.source,
                serde_json::to_string(&ioc.tags)?,
                ioc.confidence,
                ioc.first_seen.to_rfc3339(),
                ioc.last_seen.to_rfc3339(),
                ioc.description,
            ],
        )?;
        Ok(())
    }

    pub fn bulk_upsert(&self, iocs: &[Ioc]) -> anyhow::Result<usize> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let mut count = 0;

        for ioc in iocs {
            tx.execute(
                r#"INSERT INTO iocs (value, ioc_type, source, tags, confidence, first_seen, last_seen, description)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                   ON CONFLICT(value, ioc_type, source) DO UPDATE SET
                       last_seen = ?7"#,
                params![
                    ioc.value,
                    format!("{:?}", ioc.ioc_type).to_lowercase(),
                    ioc.source,
                    serde_json::to_string(&ioc.tags).unwrap_or_default(),
                    ioc.confidence,
                    ioc.first_seen.to_rfc3339(),
                    ioc.last_seen.to_rfc3339(),
                    ioc.description,
                ],
            )?;
            count += 1;
        }

        tx.commit()?;
        Ok(count)
    }

    pub fn lookup(&self, value: &str) -> anyhow::Result<Vec<Ioc>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT value, ioc_type, source, tags, confidence, first_seen, last_seen, description
             FROM iocs WHERE value = ?1"
        )?;

        let iocs = stmt.query_map([value], |row| {
            Ok(Ioc {
                value: row.get(0)?,
                ioc_type: Self::parse_ioc_type(&row.get::<_, String>(1)?),
                source: row.get(2)?,
                tags: serde_json::from_str(&row.get::<_, String>(3)?).unwrap_or_default(),
                confidence: row.get(4)?,
                first_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>(5)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                last_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                description: row.get(7)?,
            })
        })?
        .filter_map(Result::ok)
        .collect();

        Ok(iocs)
    }

    fn parse_ioc_type(s: &str) -> IocType {
        match s {
            "ipv4" => IocType::Ipv4,
            "ipv6" => IocType::Ipv6,
            "domain" => IocType::Domain,
            "url" => IocType::Url,
            "md5" => IocType::Md5,
            "sha1" => IocType::Sha1,
            "sha256" => IocType::Sha256,
            "email" => IocType::Email,
            _ => IocType::Domain,
        }
    }

    pub fn update_feed_status(
        &self,
        feed_name: &str,
        ioc_count: usize,
        success: bool,
        error: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            r#"INSERT INTO feed_status (feed_name, last_update, ioc_count, success, error)
               VALUES (?1, ?2, ?3, ?4, ?5)
               ON CONFLICT(feed_name) DO UPDATE SET
                   last_update = ?2, ioc_count = ?3, success = ?4, error = ?5"#,
            params![
                feed_name,
                Utc::now().to_rfc3339(),
                ioc_count as i64,
                success as i32,
                error,
            ],
        )?;
        Ok(())
    }

    pub fn get_all_iocs(&self) -> anyhow::Result<Vec<Ioc>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT value, ioc_type, source, tags, confidence, first_seen, last_seen, description FROM iocs"
        )?;

        let iocs = stmt.query_map([], |row| {
            Ok(Ioc {
                value: row.get(0)?,
                ioc_type: Self::parse_ioc_type(&row.get::<_, String>(1)?),
                source: row.get(2)?,
                tags: serde_json::from_str(&row.get::<_, String>(3)?).unwrap_or_default(),
                confidence: row.get(4)?,
                first_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>(5)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                last_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                description: row.get(7)?,
            })
        })?
        .filter_map(Result::ok)
        .collect();

        Ok(iocs)
    }
}
```

### src/main.rs

```rust
use std::sync::Arc;
use tracing::info;

mod config;
mod feeds;
mod ioc;
mod storage;
mod api;

use feeds::provider::{FeedProvider, GenericFeedProvider};
use feeds::abuse_ch::{FeodoTrackerFeed, URLhausFeed};
use ioc::IocMatcher;
use storage::IocDatabase;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = config::Config::load("feeds.toml").await?;

    // Initialize database
    let db = Arc::new(IocDatabase::open(&config.database_path)?);
    info!("Opened database at {}", config.database_path);

    // Initialize matcher
    let matcher = Arc::new(IocMatcher::new());

    // Load existing IOCs into matcher
    for ioc in db.get_all_iocs()? {
        matcher.add_ioc(&ioc);
    }
    info!("Loaded IOCs: {:?}", matcher.stats());

    // Create feed providers
    let feeds: Vec<Box<dyn FeedProvider>> = vec![
        Box::new(FeodoTrackerFeed::new()),
        Box::new(URLhausFeed::new()),
    ];

    // Add custom feeds from config
    for feed_config in &config.feeds {
        if feed_config.enabled {
            feeds.push(Box::new(GenericFeedProvider::new(feed_config.clone())));
        }
    }

    // Initial fetch
    for feed in &feeds {
        match feed.fetch().await {
            Ok(iocs) => {
                let count = db.bulk_upsert(&iocs)?;
                for ioc in &iocs {
                    matcher.add_ioc(ioc);
                }
                db.update_feed_status(feed.name(), count, true, None)?;
                info!("Fetched {} IOCs from {}", count, feed.name());
            }
            Err(e) => {
                db.update_feed_status(feed.name(), 0, false, Some(&e.to_string()))?;
                tracing::error!("Failed to fetch {}: {}", feed.name(), e);
            }
        }
    }

    info!("Matcher stats: {:?}", matcher.stats());

    // Start API server
    api::start_server(config.api_listen.parse()?, db, matcher).await
}
```

## Security Checklist

- [ ] Validate IOC formats before storing
- [ ] Rate limit feed fetches to avoid bans
- [ ] Use HTTPS for all feed URLs
- [ ] Implement feed authentication where required
- [ ] Sanitize IOC values before database insertion
- [ ] Set appropriate timeouts for feed fetches
- [ ] Handle feed unavailability gracefully
- [ ] Log all IOC matches for audit
- [ ] Implement IOC expiration/aging
- [ ] Protect API endpoints with authentication
