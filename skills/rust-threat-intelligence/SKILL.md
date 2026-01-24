# Rust Threat Intelligence Skills

This skill provides patterns for integrating threat intelligence feeds in Rust,
including IP/domain blocklists, indicators of compromise (IOCs), and threat feed
management.

## Overview

Threat intelligence encompasses:

- **IP Blocklists**: Malicious IP addresses
- **Domain Blocklists**: Malicious/phishing domains
- **IOC Matching**: Indicators of compromise
- **Feed Management**: Updates and synchronization
- **Reputation Scoring**: Threat severity assessment

## /threat-feeds-setup

Configure threat intelligence feed integration.

### Usage

```bash
/threat-feeds-setup
```

### What It Does

1. Creates feed manager infrastructure
2. Implements feed parsers
3. Sets up automatic updates
4. Configures IOC database
5. Implements reputation scoring

---

## Threat Feed Types

### Feed Configuration

```rust
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeed {
    pub name: String,
    pub feed_type: FeedType,
    pub source: FeedSource,
    pub update_interval: std::time::Duration,
    pub enabled: bool,
    pub confidence: f32,  // 0.0 - 1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedType {
    IpBlocklist,
    DomainBlocklist,
    UrlBlocklist,
    HashBlocklist,
    Yara,
    Stix,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedSource {
    Http { url: String, auth: Option<FeedAuth> },
    File { path: PathBuf },
    Git { repo: String, branch: String, path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedAuth {
    ApiKey { header: String, key: String },
    Basic { username: String, password: String },
    Bearer { token: String },
}

#[derive(Debug, Clone)]
pub struct ThreatIndicator {
    pub indicator_type: IndicatorType,
    pub value: String,
    pub source: String,
    pub confidence: f32,
    pub severity: Severity,
    pub tags: Vec<String>,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub expiration: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndicatorType {
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Md5,
    Sha1,
    Sha256,
    Email,
    Filename,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}
```

---

## Feed Parser

```rust
pub trait FeedParser: Send + Sync {
    fn parse(&self, content: &str) -> Result<Vec<ThreatIndicator>, Error>;
    fn feed_type(&self) -> FeedType;
}

pub struct PlainTextIpParser {
    source_name: String,
    default_confidence: f32,
    default_severity: Severity,
}

impl PlainTextIpParser {
    pub fn new(source_name: &str) -> Self {
        Self {
            source_name: source_name.to_string(),
            default_confidence: 0.7,
            default_severity: Severity::Medium,
        }
    }
}

impl FeedParser for PlainTextIpParser {
    fn parse(&self, content: &str) -> Result<Vec<ThreatIndicator>, Error> {
        let mut indicators = Vec::new();
        let now = chrono::Utc::now();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            // Extract IP (handle various formats)
            let ip = if line.contains('\t') {
                line.split('\t').next()
            } else if line.contains(' ') {
                line.split_whitespace().next()
            } else {
                Some(line)
            };

            if let Some(ip) = ip {
                let ip = ip.trim();

                // Validate IP
                if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                    let indicator_type = match addr {
                        std::net::IpAddr::V4(_) => IndicatorType::Ipv4,
                        std::net::IpAddr::V6(_) => IndicatorType::Ipv6,
                    };

                    indicators.push(ThreatIndicator {
                        indicator_type,
                        value: ip.to_string(),
                        source: self.source_name.clone(),
                        confidence: self.default_confidence,
                        severity: self.default_severity,
                        tags: Vec::new(),
                        first_seen: now,
                        last_seen: now,
                        expiration: Some(now + chrono::Duration::days(7)),
                    });
                }
            }
        }

        Ok(indicators)
    }

    fn feed_type(&self) -> FeedType {
        FeedType::IpBlocklist
    }
}

pub struct DomainListParser {
    source_name: String,
    default_confidence: f32,
}

impl FeedParser for DomainListParser {
    fn parse(&self, content: &str) -> Result<Vec<ThreatIndicator>, Error> {
        let mut indicators = Vec::new();
        let now = chrono::Utc::now();

        for line in content.lines() {
            let line = line.trim().to_lowercase();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Handle hosts file format (127.0.0.1 domain.com)
            let domain = if line.starts_with("127.0.0.1") || line.starts_with("0.0.0.0") {
                line.split_whitespace().nth(1)
            } else if line.starts_with("||") && line.ends_with("^") {
                // AdBlock format
                Some(&line[2..line.len() - 1])
            } else {
                Some(line.as_str())
            };

            if let Some(domain) = domain {
                let domain = domain.trim();

                // Basic domain validation
                if domain.contains('.') && !domain.contains(' ') && domain != "localhost" {
                    indicators.push(ThreatIndicator {
                        indicator_type: IndicatorType::Domain,
                        value: domain.to_string(),
                        source: self.source_name.clone(),
                        confidence: self.default_confidence,
                        severity: Severity::Medium,
                        tags: Vec::new(),
                        first_seen: now,
                        last_seen: now,
                        expiration: Some(now + chrono::Duration::days(7)),
                    });
                }
            }
        }

        Ok(indicators)
    }

    fn feed_type(&self) -> FeedType {
        FeedType::DomainBlocklist
    }
}

pub struct CsvParser {
    source_name: String,
    indicator_column: usize,
    indicator_type: IndicatorType,
    has_header: bool,
}

impl FeedParser for CsvParser {
    fn parse(&self, content: &str) -> Result<Vec<ThreatIndicator>, Error> {
        let mut indicators = Vec::new();
        let now = chrono::Utc::now();

        let mut lines = content.lines();

        if self.has_header {
            lines.next();  // Skip header
        }

        for line in lines {
            let columns: Vec<&str> = line.split(',').collect();

            if let Some(value) = columns.get(self.indicator_column) {
                let value = value.trim().trim_matches('"');

                if !value.is_empty() {
                    indicators.push(ThreatIndicator {
                        indicator_type: self.indicator_type,
                        value: value.to_string(),
                        source: self.source_name.clone(),
                        confidence: 0.7,
                        severity: Severity::Medium,
                        tags: Vec::new(),
                        first_seen: now,
                        last_seen: now,
                        expiration: Some(now + chrono::Duration::days(7)),
                    });
                }
            }
        }

        Ok(indicators)
    }

    fn feed_type(&self) -> FeedType {
        match self.indicator_type {
            IndicatorType::Ipv4 | IndicatorType::Ipv6 => FeedType::IpBlocklist,
            IndicatorType::Domain => FeedType::DomainBlocklist,
            IndicatorType::Url => FeedType::UrlBlocklist,
            _ => FeedType::HashBlocklist,
        }
    }
}
```

---

## Threat Intelligence Database

```rust
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use parking_lot::RwLock;

pub struct ThreatDatabase {
    ipv4_indicators: Arc<RwLock<HashMap<std::net::Ipv4Addr, ThreatIndicator>>>,
    ipv6_indicators: Arc<RwLock<HashMap<std::net::Ipv6Addr, ThreatIndicator>>>,
    domain_indicators: Arc<RwLock<HashMap<String, ThreatIndicator>>>,
    hash_indicators: Arc<RwLock<HashMap<String, ThreatIndicator>>>,
    url_indicators: Arc<RwLock<HashSet<String>>>,
}

impl ThreatDatabase {
    pub fn new() -> Self {
        Self {
            ipv4_indicators: Arc::new(RwLock::new(HashMap::new())),
            ipv6_indicators: Arc::new(RwLock::new(HashMap::new())),
            domain_indicators: Arc::new(RwLock::new(HashMap::new())),
            hash_indicators: Arc::new(RwLock::new(HashMap::new())),
            url_indicators: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub fn add_indicator(&self, indicator: ThreatIndicator) {
        match indicator.indicator_type {
            IndicatorType::Ipv4 => {
                if let Ok(ip) = indicator.value.parse::<std::net::Ipv4Addr>() {
                    self.ipv4_indicators.write().insert(ip, indicator);
                }
            }
            IndicatorType::Ipv6 => {
                if let Ok(ip) = indicator.value.parse::<std::net::Ipv6Addr>() {
                    self.ipv6_indicators.write().insert(ip, indicator);
                }
            }
            IndicatorType::Domain => {
                self.domain_indicators.write().insert(indicator.value.to_lowercase(), indicator);
            }
            IndicatorType::Md5 | IndicatorType::Sha1 | IndicatorType::Sha256 => {
                self.hash_indicators.write().insert(indicator.value.to_lowercase(), indicator);
            }
            IndicatorType::Url => {
                self.url_indicators.write().insert(indicator.value.clone());
            }
            _ => {}
        }
    }

    pub fn add_indicators(&self, indicators: Vec<ThreatIndicator>) {
        for indicator in indicators {
            self.add_indicator(indicator);
        }
    }

    pub fn check_ip(&self, ip: std::net::IpAddr) -> Option<ThreatIndicator> {
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                self.ipv4_indicators.read().get(&ipv4).cloned()
            }
            std::net::IpAddr::V6(ipv6) => {
                self.ipv6_indicators.read().get(&ipv6).cloned()
            }
        }
    }

    pub fn check_domain(&self, domain: &str) -> Option<ThreatIndicator> {
        let domain = domain.to_lowercase();
        let domains = self.domain_indicators.read();

        // Check exact match
        if let Some(indicator) = domains.get(&domain) {
            return Some(indicator.clone());
        }

        // Check parent domains
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let parent = parts[i..].join(".");
            if let Some(indicator) = domains.get(&parent) {
                return Some(indicator.clone());
            }
        }

        None
    }

    pub fn check_hash(&self, hash: &str) -> Option<ThreatIndicator> {
        self.hash_indicators.read().get(&hash.to_lowercase()).cloned()
    }

    pub fn check_url(&self, url: &str) -> bool {
        self.url_indicators.read().contains(url)
    }

    pub fn cleanup_expired(&self) {
        let now = chrono::Utc::now();

        self.ipv4_indicators.write().retain(|_, v| {
            v.expiration.map(|exp| exp > now).unwrap_or(true)
        });

        self.ipv6_indicators.write().retain(|_, v| {
            v.expiration.map(|exp| exp > now).unwrap_or(true)
        });

        self.domain_indicators.write().retain(|_, v| {
            v.expiration.map(|exp| exp > now).unwrap_or(true)
        });

        self.hash_indicators.write().retain(|_, v| {
            v.expiration.map(|exp| exp > now).unwrap_or(true)
        });
    }

    pub fn statistics(&self) -> DatabaseStats {
        DatabaseStats {
            ipv4_count: self.ipv4_indicators.read().len(),
            ipv6_count: self.ipv6_indicators.read().len(),
            domain_count: self.domain_indicators.read().len(),
            hash_count: self.hash_indicators.read().len(),
            url_count: self.url_indicators.read().len(),
        }
    }
}

#[derive(Debug)]
pub struct DatabaseStats {
    pub ipv4_count: usize,
    pub ipv6_count: usize,
    pub domain_count: usize,
    pub hash_count: usize,
    pub url_count: usize,
}
```

---

## Feed Manager

```rust
use reqwest::Client;
use tokio::time::{interval, Duration};

pub struct FeedManager {
    feeds: Vec<ThreatFeed>,
    database: Arc<ThreatDatabase>,
    parsers: HashMap<String, Box<dyn FeedParser>>,
    http_client: Client,
}

impl FeedManager {
    pub fn new(database: Arc<ThreatDatabase>) -> Self {
        Self {
            feeds: Vec::new(),
            database,
            parsers: HashMap::new(),
            http_client: Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("Failed to build HTTP client"),
        }
    }

    pub fn add_feed(&mut self, feed: ThreatFeed, parser: Box<dyn FeedParser>) {
        self.parsers.insert(feed.name.clone(), parser);
        self.feeds.push(feed);
    }

    pub fn add_default_feeds(&mut self) {
        // EmergingThreats compromised IPs
        self.add_feed(
            ThreatFeed {
                name: "et-compromised".to_string(),
                feed_type: FeedType::IpBlocklist,
                source: FeedSource::Http {
                    url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt".to_string(),
                    auth: None,
                },
                update_interval: Duration::from_secs(3600),
                enabled: true,
                confidence: 0.8,
            },
            Box::new(PlainTextIpParser::new("et-compromised")),
        );

        // Abuse.ch URLhaus
        self.add_feed(
            ThreatFeed {
                name: "urlhaus".to_string(),
                feed_type: FeedType::DomainBlocklist,
                source: FeedSource::Http {
                    url: "https://urlhaus.abuse.ch/downloads/hostfile/".to_string(),
                    auth: None,
                },
                update_interval: Duration::from_secs(3600),
                enabled: true,
                confidence: 0.9,
            },
            Box::new(DomainListParser {
                source_name: "urlhaus".to_string(),
                default_confidence: 0.9,
            }),
        );

        // Spamhaus DROP
        self.add_feed(
            ThreatFeed {
                name: "spamhaus-drop".to_string(),
                feed_type: FeedType::IpBlocklist,
                source: FeedSource::Http {
                    url: "https://www.spamhaus.org/drop/drop.txt".to_string(),
                    auth: None,
                },
                update_interval: Duration::from_secs(3600 * 12),
                enabled: true,
                confidence: 0.95,
            },
            Box::new(PlainTextIpParser::new("spamhaus-drop")),
        );
    }

    pub async fn update_all(&self) -> Result<UpdateReport, Error> {
        let mut report = UpdateReport::default();

        for feed in &self.feeds {
            if !feed.enabled {
                continue;
            }

            match self.update_feed(feed).await {
                Ok(count) => {
                    report.successful_feeds += 1;
                    report.total_indicators += count;
                    tracing::info!("Updated feed '{}': {} indicators", feed.name, count);
                }
                Err(e) => {
                    report.failed_feeds += 1;
                    report.errors.push((feed.name.clone(), e.to_string()));
                    tracing::error!("Failed to update feed '{}': {}", feed.name, e);
                }
            }
        }

        // Cleanup expired indicators
        self.database.cleanup_expired();

        Ok(report)
    }

    async fn update_feed(&self, feed: &ThreatFeed) -> Result<usize, Error> {
        let content = match &feed.source {
            FeedSource::Http { url, auth } => {
                self.fetch_http(url, auth.as_ref()).await?
            }
            FeedSource::File { path } => {
                tokio::fs::read_to_string(path).await?
            }
            FeedSource::Git { .. } => {
                return Err(Error::UnsupportedSource("git".to_string()));
            }
        };

        let parser = self.parsers.get(&feed.name)
            .ok_or(Error::NoParser(feed.name.clone()))?;

        let indicators = parser.parse(&content)?;
        let count = indicators.len();

        self.database.add_indicators(indicators);

        Ok(count)
    }

    async fn fetch_http(&self, url: &str, auth: Option<&FeedAuth>) -> Result<String, Error> {
        let mut request = self.http_client.get(url);

        if let Some(auth) = auth {
            request = match auth {
                FeedAuth::ApiKey { header, key } => {
                    request.header(header, key)
                }
                FeedAuth::Basic { username, password } => {
                    request.basic_auth(username, Some(password))
                }
                FeedAuth::Bearer { token } => {
                    request.bearer_auth(token)
                }
            };
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            return Err(Error::HttpError(response.status().as_u16()));
        }

        response.text().await.map_err(Error::from)
    }

    pub async fn run_update_loop(self: Arc<Self>) {
        let mut ticker = interval(Duration::from_secs(3600));

        loop {
            ticker.tick().await;

            if let Err(e) = self.update_all().await {
                tracing::error!("Feed update failed: {}", e);
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct UpdateReport {
    pub successful_feeds: usize,
    pub failed_feeds: usize,
    pub total_indicators: usize,
    pub errors: Vec<(String, String)>,
}
```

---

## Reputation Scoring

```rust
pub struct ReputationScorer {
    database: Arc<ThreatDatabase>,
    weights: ReputationWeights,
}

#[derive(Debug, Clone)]
pub struct ReputationWeights {
    pub source_confidence: f32,
    pub recency: f32,
    pub severity: f32,
    pub multiple_sources: f32,
}

impl Default for ReputationWeights {
    fn default() -> Self {
        Self {
            source_confidence: 0.3,
            recency: 0.2,
            severity: 0.3,
            multiple_sources: 0.2,
        }
    }
}

#[derive(Debug)]
pub struct ReputationResult {
    pub score: f32,  // 0.0 (clean) to 1.0 (malicious)
    pub category: ReputationCategory,
    pub indicators: Vec<ThreatIndicator>,
    pub details: String,
}

#[derive(Debug, Clone, Copy)]
pub enum ReputationCategory {
    Clean,
    Suspicious,
    Malicious,
    Critical,
}

impl ReputationScorer {
    pub fn new(database: Arc<ThreatDatabase>) -> Self {
        Self {
            database,
            weights: ReputationWeights::default(),
        }
    }

    pub fn score_ip(&self, ip: std::net::IpAddr) -> ReputationResult {
        if let Some(indicator) = self.database.check_ip(ip) {
            self.score_indicator(&indicator)
        } else {
            ReputationResult {
                score: 0.0,
                category: ReputationCategory::Clean,
                indicators: Vec::new(),
                details: "No threat indicators found".to_string(),
            }
        }
    }

    pub fn score_domain(&self, domain: &str) -> ReputationResult {
        if let Some(indicator) = self.database.check_domain(domain) {
            self.score_indicator(&indicator)
        } else {
            ReputationResult {
                score: 0.0,
                category: ReputationCategory::Clean,
                indicators: Vec::new(),
                details: "No threat indicators found".to_string(),
            }
        }
    }

    fn score_indicator(&self, indicator: &ThreatIndicator) -> ReputationResult {
        let mut score = 0.0;

        // Source confidence
        score += indicator.confidence * self.weights.source_confidence;

        // Recency
        let age = chrono::Utc::now().signed_duration_since(indicator.last_seen);
        let recency_score = if age.num_days() < 1 {
            1.0
        } else if age.num_days() < 7 {
            0.8
        } else if age.num_days() < 30 {
            0.5
        } else {
            0.2
        };
        score += recency_score * self.weights.recency;

        // Severity
        let severity_score = match indicator.severity {
            Severity::Critical => 1.0,
            Severity::High => 0.8,
            Severity::Medium => 0.5,
            Severity::Low => 0.3,
            Severity::Unknown => 0.1,
        };
        score += severity_score * self.weights.severity;

        let category = if score >= 0.8 {
            ReputationCategory::Critical
        } else if score >= 0.6 {
            ReputationCategory::Malicious
        } else if score >= 0.3 {
            ReputationCategory::Suspicious
        } else {
            ReputationCategory::Clean
        };

        ReputationResult {
            score,
            category,
            indicators: vec![indicator.clone()],
            details: format!(
                "Source: {}, Confidence: {:.2}, Severity: {:?}",
                indicator.source, indicator.confidence, indicator.severity
            ),
        }
    }
}
```

---

## Security Checklist

- [ ] Feeds from trusted sources
- [ ] Feed updates automated
- [ ] Expired indicators cleaned
- [ ] Database backed up
- [ ] API keys secured
- [ ] Rate limiting on lookups

## Recommended Crates

- **reqwest**: HTTP client
- **parking_lot**: Fast locks
- **chrono**: Date/time
- **ipnet**: IP network handling

## Integration Points

This skill works well with:

- `/dns-proxy-setup` - Domain blocking
- `/dpi-setup` - IP blocking
- `/ids-setup` - Rule updates
