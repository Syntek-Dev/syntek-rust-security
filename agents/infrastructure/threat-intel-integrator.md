# Threat Intelligence Integrator Agent

## Role

Sonnet-based agent for building Rust threat intelligence integration systems
that aggregate, normalize, and distribute indicators of compromise (IOCs) from
multiple threat feeds, blocklists, and intelligence sources for use in security
appliances.

## Capabilities

- Multiple threat feed integration (commercial and open source)
- IOC normalization and deduplication
- IP/domain/hash blocklist management
- STIX/TAXII feed consumption
- Threat scoring and confidence levels
- Feed freshness monitoring
- Local IOC database management
- Export to various security tools
- False positive tracking
- Feed source prioritization

## Implementation Patterns

### Core Threat Intel Platform

```rust
use std::net::IpAddr;
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};

/// Threat intelligence configuration
#[derive(Debug, Clone)]
pub struct ThreatIntelConfig {
    pub database_path: std::path::PathBuf,
    pub feeds: Vec<FeedConfig>,
    pub update_interval_hours: u32,
    pub max_age_days: u32,
    pub min_confidence: f64,
    pub enable_stix_taxii: bool,
    pub taxii_servers: Vec<TaxiiServer>,
    pub export_formats: Vec<ExportFormat>,
    pub api_listen_addr: std::net::SocketAddr,
}

#[derive(Debug, Clone)]
pub struct FeedConfig {
    pub name: String,
    pub url: String,
    pub feed_type: FeedType,
    pub format: FeedFormat,
    pub auth: Option<FeedAuth>,
    pub update_interval_hours: u32,
    pub confidence_multiplier: f64,
    pub enabled: bool,
    pub categories: Vec<ThreatCategory>,
}

#[derive(Debug, Clone)]
pub enum FeedType {
    IpBlocklist,
    DomainBlocklist,
    UrlBlocklist,
    HashBlocklist,
    Mixed,
    StixTaxii,
}

#[derive(Debug, Clone)]
pub enum FeedFormat {
    PlainText,
    Csv,
    Json,
    StixBundle,
    Custom(String),
}

#[derive(Debug, Clone)]
pub enum FeedAuth {
    None,
    ApiKey { header: String, key: String },
    BasicAuth { username: String, password: String },
    Bearer { token: String },
}

#[derive(Debug, Clone)]
pub struct TaxiiServer {
    pub name: String,
    pub discovery_url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub collections: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum ExportFormat {
    Json,
    Csv,
    SnortRules,
    SuricataRules,
    HostsFile,
    NginxDeny,
    NftablesSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreatCategory {
    Malware,
    Phishing,
    Botnet,
    CnC,          // Command and Control
    Ransomware,
    Spam,
    Scanner,
    Tor,
    Vpn,
    Proxy,
    Ads,
    Tracking,
    Cryptominer,
    Exploit,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            database_path: std::path::PathBuf::from("/var/lib/threat-intel/iocs.db"),
            feeds: Self::default_feeds(),
            update_interval_hours: 1,
            max_age_days: 30,
            min_confidence: 0.5,
            enable_stix_taxii: false,
            taxii_servers: Vec::new(),
            export_formats: vec![ExportFormat::Json, ExportFormat::HostsFile],
            api_listen_addr: "127.0.0.1:8080".parse().unwrap(),
        }
    }
}

impl ThreatIntelConfig {
    fn default_feeds() -> Vec<FeedConfig> {
        vec![
            FeedConfig {
                name: "Abuse.ch Feodo Tracker".to_string(),
                url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt".to_string(),
                feed_type: FeedType::IpBlocklist,
                format: FeedFormat::PlainText,
                auth: None,
                update_interval_hours: 1,
                confidence_multiplier: 0.95,
                enabled: true,
                categories: vec![ThreatCategory::Botnet, ThreatCategory::CnC],
            },
            FeedConfig {
                name: "URLhaus".to_string(),
                url: "https://urlhaus.abuse.ch/downloads/csv/".to_string(),
                feed_type: FeedType::UrlBlocklist,
                format: FeedFormat::Csv,
                auth: None,
                update_interval_hours: 1,
                confidence_multiplier: 0.9,
                enabled: true,
                categories: vec![ThreatCategory::Malware],
            },
            FeedConfig {
                name: "MalwareBazaar".to_string(),
                url: "https://bazaar.abuse.ch/export/txt/sha256/recent/".to_string(),
                feed_type: FeedType::HashBlocklist,
                format: FeedFormat::PlainText,
                auth: None,
                update_interval_hours: 6,
                confidence_multiplier: 0.95,
                enabled: true,
                categories: vec![ThreatCategory::Malware],
            },
            FeedConfig {
                name: "Emerging Threats Compromised IPs".to_string(),
                url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt".to_string(),
                feed_type: FeedType::IpBlocklist,
                format: FeedFormat::PlainText,
                auth: None,
                update_interval_hours: 24,
                confidence_multiplier: 0.85,
                enabled: true,
                categories: vec![ThreatCategory::Botnet],
            },
            FeedConfig {
                name: "Phishing Database".to_string(),
                url: "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt".to_string(),
                feed_type: FeedType::DomainBlocklist,
                format: FeedFormat::PlainText,
                auth: None,
                update_interval_hours: 12,
                confidence_multiplier: 0.8,
                enabled: true,
                categories: vec![ThreatCategory::Phishing],
            },
        ]
    }
}

/// Indicator of Compromise
#[derive(Debug, Clone)]
pub struct Ioc {
    pub id: String,
    pub ioc_type: IocType,
    pub value: String,
    pub confidence: f64,
    pub severity: Severity,
    pub categories: HashSet<ThreatCategory>,
    pub sources: Vec<IocSource>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
    pub false_positive_reports: u32,
    pub active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IocType {
    IpAddress,
    Domain,
    Url,
    Sha256,
    Sha1,
    Md5,
    Email,
    FileName,
    Registry,
    Mutex,
}

#[derive(Debug, Clone, Copy)]
pub enum Severity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[derive(Debug, Clone)]
pub struct IocSource {
    pub feed_name: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub confidence: f64,
    pub raw_data: Option<String>,
}

/// Main threat intelligence platform
pub struct ThreatIntelPlatform {
    config: ThreatIntelConfig,
    database: Arc<RwLock<IocDatabase>>,
    feed_manager: Arc<FeedManager>,
    exporter: Arc<Exporter>,
    stats: Arc<RwLock<PlatformStats>>,
}

impl ThreatIntelPlatform {
    pub async fn new(config: ThreatIntelConfig) -> Result<Self, ThreatIntelError> {
        let database = IocDatabase::open(&config.database_path).await?;
        let feed_manager = FeedManager::new(&config.feeds);
        let exporter = Exporter::new(&config.export_formats);

        Ok(Self {
            config,
            database: Arc::new(RwLock::new(database)),
            feed_manager: Arc::new(feed_manager),
            exporter: Arc::new(exporter),
            stats: Arc::new(RwLock::new(PlatformStats::default())),
        })
    }

    /// Start the platform (feed updates, API server)
    pub async fn run(&self) -> Result<(), ThreatIntelError> {
        // Start feed update loop
        let update_handle = self.start_feed_updates();

        // Start API server
        let api_handle = self.start_api_server();

        // Start cleanup task
        let cleanup_handle = self.start_cleanup_task();

        // Wait for all tasks
        tokio::select! {
            result = update_handle => result?,
            result = api_handle => result?,
            result = cleanup_handle => result?,
        }

        Ok(())
    }

    fn start_feed_updates(&self) -> tokio::task::JoinHandle<Result<(), ThreatIntelError>> {
        let config = self.config.clone();
        let database = Arc::clone(&self.database);
        let feed_manager = Arc::clone(&self.feed_manager);
        let stats = Arc::clone(&self.stats);

        tokio::spawn(async move {
            loop {
                for feed_config in &config.feeds {
                    if !feed_config.enabled {
                        continue;
                    }

                    tracing::info!("Updating feed: {}", feed_config.name);

                    match feed_manager.fetch_feed(feed_config).await {
                        Ok(iocs) => {
                            let count = iocs.len();
                            let mut db = database.write().await;

                            for ioc in iocs {
                                db.upsert_ioc(ioc).await?;
                            }

                            let mut s = stats.write().await;
                            s.feeds_updated += 1;
                            s.total_iocs_processed += count as u64;

                            tracing::info!("Feed {} updated: {} IOCs", feed_config.name, count);
                        }
                        Err(e) => {
                            tracing::error!("Failed to update feed {}: {}", feed_config.name, e);
                            let mut s = stats.write().await;
                            s.feed_errors += 1;
                        }
                    }
                }

                tokio::time::sleep(std::time::Duration::from_secs(
                    config.update_interval_hours as u64 * 3600
                )).await;
            }
        })
    }

    fn start_api_server(&self) -> tokio::task::JoinHandle<Result<(), ThreatIntelError>> {
        let config = self.config.clone();
        let database = Arc::clone(&self.database);
        let exporter = Arc::clone(&self.exporter);
        let stats = Arc::clone(&self.stats);

        tokio::spawn(async move {
            // Simple HTTP API for IOC lookups
            use tokio::net::TcpListener;
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let listener = TcpListener::bind(config.api_listen_addr).await?;
            tracing::info!("Threat Intel API listening on {}", config.api_listen_addr);

            loop {
                let (mut socket, _) = listener.accept().await?;
                let db = Arc::clone(&database);
                let exp = Arc::clone(&exporter);
                let st = Arc::clone(&stats);

                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = socket.read(&mut buf).await?;
                    let request = String::from_utf8_lossy(&buf[..n]);

                    let response = Self::handle_api_request(&request, &db, &exp, &st).await;

                    socket.write_all(response.as_bytes()).await?;
                    socket.flush().await?;

                    Ok::<(), ThreatIntelError>(())
                });
            }
        })
    }

    async fn handle_api_request(
        request: &str,
        database: &Arc<RwLock<IocDatabase>>,
        exporter: &Arc<Exporter>,
        stats: &Arc<RwLock<PlatformStats>>,
    ) -> String {
        // Parse simple HTTP request
        let lines: Vec<&str> = request.lines().collect();
        if lines.is_empty() {
            return Self::http_response(400, "Bad Request");
        }

        let parts: Vec<&str> = lines[0].split_whitespace().collect();
        if parts.len() < 2 {
            return Self::http_response(400, "Bad Request");
        }

        let method = parts[0];
        let path = parts[1];

        match (method, path) {
            ("GET", "/health") => {
                Self::http_response(200, r#"{"status":"healthy"}"#)
            }
            ("GET", "/stats") => {
                let s = stats.read().await;
                let json = serde_json::to_string(&*s).unwrap_or_default();
                Self::http_response(200, &json)
            }
            ("GET", path) if path.starts_with("/lookup/ip/") => {
                let ip = &path[11..];
                let db = database.read().await;
                if let Some(ioc) = db.lookup_ip(ip).await {
                    let json = serde_json::to_string(&IocResponse::from(&ioc)).unwrap_or_default();
                    Self::http_response(200, &json)
                } else {
                    Self::http_response(404, r#"{"found":false}"#)
                }
            }
            ("GET", path) if path.starts_with("/lookup/domain/") => {
                let domain = &path[15..];
                let db = database.read().await;
                if let Some(ioc) = db.lookup_domain(domain).await {
                    let json = serde_json::to_string(&IocResponse::from(&ioc)).unwrap_or_default();
                    Self::http_response(200, &json)
                } else {
                    Self::http_response(404, r#"{"found":false}"#)
                }
            }
            ("GET", path) if path.starts_with("/export/") => {
                let format = &path[8..];
                let db = database.read().await;
                let iocs = db.get_active_iocs().await;

                let content = match format {
                    "json" => exporter.export_json(&iocs),
                    "hosts" => exporter.export_hosts(&iocs),
                    "snort" => exporter.export_snort(&iocs),
                    "suricata" => exporter.export_suricata(&iocs),
                    "nginx" => exporter.export_nginx(&iocs),
                    "nftables" => exporter.export_nftables(&iocs),
                    _ => return Self::http_response(400, "Unknown format"),
                };

                Self::http_response(200, &content)
            }
            _ => {
                Self::http_response(404, "Not Found")
            }
        }
    }

    fn http_response(status: u16, body: &str) -> String {
        let status_text = match status {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Unknown",
        };

        format!(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status,
            status_text,
            body.len(),
            body
        )
    }

    fn start_cleanup_task(&self) -> tokio::task::JoinHandle<Result<(), ThreatIntelError>> {
        let max_age_days = self.config.max_age_days;
        let database = Arc::clone(&self.database);

        tokio::spawn(async move {
            loop {
                // Run cleanup daily
                tokio::time::sleep(std::time::Duration::from_secs(86400)).await;

                let cutoff = Utc::now() - chrono::Duration::days(max_age_days as i64);
                let mut db = database.write().await;
                let removed = db.remove_old_iocs(cutoff).await?;

                tracing::info!("Cleaned up {} old IOCs", removed);
            }
        })
    }

    /// Manual IOC lookup
    pub async fn lookup(&self, value: &str) -> Option<Ioc> {
        let db = self.database.read().await;

        // Try different IOC types
        if let Ok(ip) = value.parse::<IpAddr>() {
            return db.lookup_ip(&ip.to_string()).await;
        }

        if value.contains('.') && !value.contains('/') {
            if let Some(ioc) = db.lookup_domain(value).await {
                return Some(ioc);
            }
        }

        if value.len() == 64 {
            return db.lookup_hash(value).await;
        }

        None
    }

    /// Check if an IP is malicious
    pub async fn is_malicious_ip(&self, ip: &IpAddr) -> bool {
        let db = self.database.read().await;
        if let Some(ioc) = db.lookup_ip(&ip.to_string()).await {
            ioc.active && ioc.confidence >= self.config.min_confidence
        } else {
            false
        }
    }

    /// Check if a domain is malicious
    pub async fn is_malicious_domain(&self, domain: &str) -> bool {
        let db = self.database.read().await;

        // Check exact match
        if let Some(ioc) = db.lookup_domain(domain).await {
            if ioc.active && ioc.confidence >= self.config.min_confidence {
                return true;
            }
        }

        // Check parent domains
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            if let Some(ioc) = db.lookup_domain(&parent).await {
                if ioc.active && ioc.confidence >= self.config.min_confidence {
                    return true;
                }
            }
        }

        false
    }
}

#[derive(Debug, Default, serde::Serialize)]
pub struct PlatformStats {
    pub feeds_updated: u64,
    pub feed_errors: u64,
    pub total_iocs_processed: u64,
    pub active_iocs: u64,
    pub last_update: Option<DateTime<Utc>>,
}

#[derive(serde::Serialize)]
struct IocResponse {
    found: bool,
    ioc_type: String,
    value: String,
    confidence: f64,
    severity: String,
    categories: Vec<String>,
    first_seen: String,
    last_seen: String,
    sources: Vec<String>,
}

impl From<&Ioc> for IocResponse {
    fn from(ioc: &Ioc) -> Self {
        Self {
            found: true,
            ioc_type: format!("{:?}", ioc.ioc_type),
            value: ioc.value.clone(),
            confidence: ioc.confidence,
            severity: format!("{:?}", ioc.severity),
            categories: ioc.categories.iter().map(|c| format!("{:?}", c)).collect(),
            first_seen: ioc.first_seen.to_rfc3339(),
            last_seen: ioc.last_seen.to_rfc3339(),
            sources: ioc.sources.iter().map(|s| s.feed_name.clone()).collect(),
        }
    }
}
```

### Feed Manager

```rust
/// Feed fetching and parsing manager
pub struct FeedManager {
    client: reqwest::Client,
}

impl FeedManager {
    pub fn new(_feeds: &[FeedConfig]) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    pub async fn fetch_feed(&self, config: &FeedConfig) -> Result<Vec<Ioc>, ThreatIntelError> {
        // Build request with auth
        let mut request = self.client.get(&config.url);

        match &config.auth {
            Some(FeedAuth::ApiKey { header, key }) => {
                request = request.header(header, key);
            }
            Some(FeedAuth::BasicAuth { username, password }) => {
                request = request.basic_auth(username, Some(password));
            }
            Some(FeedAuth::Bearer { token }) => {
                request = request.bearer_auth(token);
            }
            None => {}
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            return Err(ThreatIntelError::FeedError(
                format!("HTTP {}", response.status())
            ));
        }

        let content = response.text().await?;

        // Parse based on format
        match config.format {
            FeedFormat::PlainText => self.parse_plaintext(&content, config),
            FeedFormat::Csv => self.parse_csv(&content, config),
            FeedFormat::Json => self.parse_json(&content, config),
            FeedFormat::StixBundle => self.parse_stix(&content, config),
            FeedFormat::Custom(ref parser) => self.parse_custom(&content, parser, config),
        }
    }

    fn parse_plaintext(&self, content: &str, config: &FeedConfig) -> Result<Vec<Ioc>, ThreatIntelError> {
        let mut iocs = Vec::new();
        let now = Utc::now();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            let value = line.to_string();
            let ioc_type = self.detect_ioc_type(&value, &config.feed_type);

            if let Some(ioc_type) = ioc_type {
                let ioc = Ioc {
                    id: self.generate_ioc_id(&value, ioc_type),
                    ioc_type,
                    value,
                    confidence: config.confidence_multiplier,
                    severity: self.categories_to_severity(&config.categories),
                    categories: config.categories.iter().cloned().collect(),
                    sources: vec![IocSource {
                        feed_name: config.name.clone(),
                        first_seen: now,
                        last_seen: now,
                        confidence: config.confidence_multiplier,
                        raw_data: None,
                    }],
                    first_seen: now,
                    last_seen: now,
                    last_updated: now,
                    metadata: HashMap::new(),
                    false_positive_reports: 0,
                    active: true,
                };

                iocs.push(ioc);
            }
        }

        Ok(iocs)
    }

    fn parse_csv(&self, content: &str, config: &FeedConfig) -> Result<Vec<Ioc>, ThreatIntelError> {
        let mut iocs = Vec::new();
        let now = Utc::now();

        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .from_reader(content.as_bytes());

        for result in reader.records() {
            let record = match result {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Try to extract IOC value from first non-date column
            let value = record.get(0)
                .or_else(|| record.get(1))
                .map(|s| s.to_string());

            if let Some(value) = value {
                if value.starts_with('#') || value.is_empty() {
                    continue;
                }

                let ioc_type = self.detect_ioc_type(&value, &config.feed_type);

                if let Some(ioc_type) = ioc_type {
                    let ioc = Ioc {
                        id: self.generate_ioc_id(&value, ioc_type),
                        ioc_type,
                        value,
                        confidence: config.confidence_multiplier,
                        severity: self.categories_to_severity(&config.categories),
                        categories: config.categories.iter().cloned().collect(),
                        sources: vec![IocSource {
                            feed_name: config.name.clone(),
                            first_seen: now,
                            last_seen: now,
                            confidence: config.confidence_multiplier,
                            raw_data: Some(record.as_slice().to_string()),
                        }],
                        first_seen: now,
                        last_seen: now,
                        last_updated: now,
                        metadata: HashMap::new(),
                        false_positive_reports: 0,
                        active: true,
                    };

                    iocs.push(ioc);
                }
            }
        }

        Ok(iocs)
    }

    fn parse_json(&self, content: &str, config: &FeedConfig) -> Result<Vec<Ioc>, ThreatIntelError> {
        let mut iocs = Vec::new();
        let now = Utc::now();

        // Try to parse as array of objects or single object with array field
        let json: serde_json::Value = serde_json::from_str(content)
            .map_err(|e| ThreatIntelError::ParseError(e.to_string()))?;

        let items = if json.is_array() {
            json.as_array().unwrap().clone()
        } else if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
            data.clone()
        } else if let Some(results) = json.get("results").and_then(|r| r.as_array()) {
            results.clone()
        } else {
            vec![json]
        };

        for item in items {
            // Try common field names for IOC values
            let value = item.get("ip")
                .or_else(|| item.get("domain"))
                .or_else(|| item.get("url"))
                .or_else(|| item.get("hash"))
                .or_else(|| item.get("sha256"))
                .or_else(|| item.get("indicator"))
                .or_else(|| item.get("ioc"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            if let Some(value) = value {
                let ioc_type = self.detect_ioc_type(&value, &config.feed_type);

                if let Some(ioc_type) = ioc_type {
                    let confidence = item.get("confidence")
                        .and_then(|c| c.as_f64())
                        .map(|c| c / 100.0) // Normalize 0-100 to 0-1
                        .unwrap_or(config.confidence_multiplier);

                    let ioc = Ioc {
                        id: self.generate_ioc_id(&value, ioc_type),
                        ioc_type,
                        value,
                        confidence,
                        severity: self.categories_to_severity(&config.categories),
                        categories: config.categories.iter().cloned().collect(),
                        sources: vec![IocSource {
                            feed_name: config.name.clone(),
                            first_seen: now,
                            last_seen: now,
                            confidence,
                            raw_data: Some(item.to_string()),
                        }],
                        first_seen: now,
                        last_seen: now,
                        last_updated: now,
                        metadata: HashMap::new(),
                        false_positive_reports: 0,
                        active: true,
                    };

                    iocs.push(ioc);
                }
            }
        }

        Ok(iocs)
    }

    fn parse_stix(&self, content: &str, config: &FeedConfig) -> Result<Vec<Ioc>, ThreatIntelError> {
        let mut iocs = Vec::new();
        let now = Utc::now();

        let bundle: serde_json::Value = serde_json::from_str(content)
            .map_err(|e| ThreatIntelError::ParseError(e.to_string()))?;

        let objects = bundle.get("objects")
            .and_then(|o| o.as_array())
            .ok_or_else(|| ThreatIntelError::ParseError("No objects in STIX bundle".to_string()))?;

        for obj in objects {
            let obj_type = obj.get("type").and_then(|t| t.as_str());

            if obj_type != Some("indicator") {
                continue;
            }

            // Parse STIX indicator pattern
            if let Some(pattern) = obj.get("pattern").and_then(|p| p.as_str()) {
                if let Some((ioc_type, value)) = self.parse_stix_pattern(pattern) {
                    let confidence = obj.get("confidence")
                        .and_then(|c| c.as_f64())
                        .map(|c| c / 100.0)
                        .unwrap_or(config.confidence_multiplier);

                    let ioc = Ioc {
                        id: obj.get("id")
                            .and_then(|i| i.as_str())
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| self.generate_ioc_id(&value, ioc_type)),
                        ioc_type,
                        value,
                        confidence,
                        severity: self.categories_to_severity(&config.categories),
                        categories: config.categories.iter().cloned().collect(),
                        sources: vec![IocSource {
                            feed_name: config.name.clone(),
                            first_seen: now,
                            last_seen: now,
                            confidence,
                            raw_data: Some(obj.to_string()),
                        }],
                        first_seen: now,
                        last_seen: now,
                        last_updated: now,
                        metadata: HashMap::new(),
                        false_positive_reports: 0,
                        active: true,
                    };

                    iocs.push(ioc);
                }
            }
        }

        Ok(iocs)
    }

    fn parse_stix_pattern(&self, pattern: &str) -> Option<(IocType, String)> {
        // Parse STIX 2.x patterns like:
        // [ipv4-addr:value = '192.168.1.1']
        // [domain-name:value = 'evil.com']
        // [file:hashes.SHA-256 = 'abc123...']

        let pattern = pattern.trim().trim_matches(|c| c == '[' || c == ']');

        let parts: Vec<&str> = pattern.split('=').collect();
        if parts.len() != 2 {
            return None;
        }

        let type_part = parts[0].trim();
        let value = parts[1].trim().trim_matches('\'').trim_matches('"').to_string();

        let ioc_type = if type_part.contains("ipv4-addr") || type_part.contains("ipv6-addr") {
            IocType::IpAddress
        } else if type_part.contains("domain-name") {
            IocType::Domain
        } else if type_part.contains("url") {
            IocType::Url
        } else if type_part.contains("SHA-256") || type_part.contains("sha256") {
            IocType::Sha256
        } else if type_part.contains("SHA-1") || type_part.contains("sha1") {
            IocType::Sha1
        } else if type_part.contains("MD5") || type_part.contains("md5") {
            IocType::Md5
        } else if type_part.contains("email") {
            IocType::Email
        } else {
            return None;
        };

        Some((ioc_type, value))
    }

    fn parse_custom(&self, _content: &str, _parser: &str, _config: &FeedConfig) -> Result<Vec<Ioc>, ThreatIntelError> {
        // Custom parser would be implemented based on parser specification
        Err(ThreatIntelError::ParseError("Custom parsers not implemented".to_string()))
    }

    fn detect_ioc_type(&self, value: &str, feed_type: &FeedType) -> Option<IocType> {
        match feed_type {
            FeedType::IpBlocklist => {
                if value.parse::<IpAddr>().is_ok() {
                    return Some(IocType::IpAddress);
                }
                // Check for CIDR notation
                if value.contains('/') {
                    let parts: Vec<&str> = value.split('/').collect();
                    if parts.len() == 2 && parts[0].parse::<IpAddr>().is_ok() {
                        return Some(IocType::IpAddress);
                    }
                }
                None
            }
            FeedType::DomainBlocklist => {
                if value.contains('.') && !value.contains('/') && !value.parse::<IpAddr>().is_ok() {
                    Some(IocType::Domain)
                } else {
                    None
                }
            }
            FeedType::UrlBlocklist => {
                if value.starts_with("http://") || value.starts_with("https://") {
                    Some(IocType::Url)
                } else {
                    None
                }
            }
            FeedType::HashBlocklist => {
                match value.len() {
                    64 if value.chars().all(|c| c.is_ascii_hexdigit()) => Some(IocType::Sha256),
                    40 if value.chars().all(|c| c.is_ascii_hexdigit()) => Some(IocType::Sha1),
                    32 if value.chars().all(|c| c.is_ascii_hexdigit()) => Some(IocType::Md5),
                    _ => None,
                }
            }
            FeedType::Mixed | FeedType::StixTaxii => {
                // Auto-detect type
                if value.parse::<IpAddr>().is_ok() {
                    return Some(IocType::IpAddress);
                }
                if value.starts_with("http://") || value.starts_with("https://") {
                    return Some(IocType::Url);
                }
                if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(IocType::Sha256);
                }
                if value.len() == 40 && value.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(IocType::Sha1);
                }
                if value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(IocType::Md5);
                }
                if value.contains('.') && !value.contains('/') {
                    return Some(IocType::Domain);
                }
                None
            }
        }
    }

    fn generate_ioc_id(&self, value: &str, ioc_type: IocType) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}:{}", ioc_type, value));
        format!("ioc-{}", hex::encode(&hasher.finalize()[..8]))
    }

    fn categories_to_severity(&self, categories: &[ThreatCategory]) -> Severity {
        if categories.contains(&ThreatCategory::Ransomware) ||
           categories.contains(&ThreatCategory::CnC) ||
           categories.contains(&ThreatCategory::Exploit) {
            Severity::Critical
        } else if categories.contains(&ThreatCategory::Malware) ||
                  categories.contains(&ThreatCategory::Botnet) {
            Severity::High
        } else if categories.contains(&ThreatCategory::Phishing) ||
                  categories.contains(&ThreatCategory::Cryptominer) {
            Severity::Medium
        } else {
            Severity::Low
        }
    }
}
```

### IOC Database

```rust
/// SQLite-based IOC database
pub struct IocDatabase {
    conn: tokio_rusqlite::Connection,
}

impl IocDatabase {
    pub async fn open(path: &std::path::Path) -> Result<Self, ThreatIntelError> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let conn = tokio_rusqlite::Connection::open(path).await?;

        // Initialize schema
        conn.call(|conn| {
            conn.execute_batch(r#"
                CREATE TABLE IF NOT EXISTS iocs (
                    id TEXT PRIMARY KEY,
                    ioc_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity INTEGER NOT NULL,
                    categories TEXT NOT NULL,
                    sources TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    last_updated TEXT NOT NULL,
                    metadata TEXT NOT NULL,
                    false_positive_reports INTEGER NOT NULL,
                    active INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
                CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
                CREATE INDEX IF NOT EXISTS idx_iocs_active ON iocs(active);
                CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen);
            "#)?;
            Ok(())
        }).await?;

        Ok(Self { conn })
    }

    pub async fn upsert_ioc(&mut self, ioc: Ioc) -> Result<(), ThreatIntelError> {
        let categories_json = serde_json::to_string(&ioc.categories.iter().collect::<Vec<_>>())?;
        let sources_json = serde_json::to_string(&ioc.sources)?;
        let metadata_json = serde_json::to_string(&ioc.metadata)?;

        self.conn.call(move |conn| {
            // Check if IOC exists
            let existing: Option<(String, String, String)> = conn.query_row(
                "SELECT confidence, sources, first_seen FROM iocs WHERE id = ?",
                [&ioc.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).ok();

            if let Some((_, existing_sources, existing_first_seen)) = existing {
                // Update existing IOC
                let mut all_sources: Vec<IocSource> = serde_json::from_str(&existing_sources)?;
                all_sources.extend(ioc.sources.clone());

                // Deduplicate sources by feed name
                let mut seen_feeds = HashSet::new();
                all_sources.retain(|s| seen_feeds.insert(s.feed_name.clone()));

                let all_sources_json = serde_json::to_string(&all_sources)?;

                // Calculate aggregate confidence
                let avg_confidence: f64 = all_sources.iter()
                    .map(|s| s.confidence)
                    .sum::<f64>() / all_sources.len() as f64;

                conn.execute(
                    r#"UPDATE iocs SET
                        confidence = ?,
                        sources = ?,
                        last_seen = ?,
                        last_updated = ?,
                        active = 1
                    WHERE id = ?"#,
                    rusqlite::params![
                        avg_confidence,
                        all_sources_json,
                        ioc.last_seen.to_rfc3339(),
                        ioc.last_updated.to_rfc3339(),
                        ioc.id,
                    ],
                )?;
            } else {
                // Insert new IOC
                conn.execute(
                    r#"INSERT INTO iocs
                        (id, ioc_type, value, confidence, severity, categories,
                         sources, first_seen, last_seen, last_updated, metadata,
                         false_positive_reports, active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
                    rusqlite::params![
                        ioc.id,
                        format!("{:?}", ioc.ioc_type),
                        ioc.value,
                        ioc.confidence,
                        ioc.severity as i32,
                        categories_json,
                        sources_json,
                        ioc.first_seen.to_rfc3339(),
                        ioc.last_seen.to_rfc3339(),
                        ioc.last_updated.to_rfc3339(),
                        metadata_json,
                        ioc.false_positive_reports,
                        ioc.active as i32,
                    ],
                )?;
            }

            Ok(())
        }).await?;

        Ok(())
    }

    pub async fn lookup_ip(&self, ip: &str) -> Option<Ioc> {
        self.lookup_by_value(ip, "IpAddress").await
    }

    pub async fn lookup_domain(&self, domain: &str) -> Option<Ioc> {
        self.lookup_by_value(domain, "Domain").await
    }

    pub async fn lookup_hash(&self, hash: &str) -> Option<Ioc> {
        // Try all hash types
        for ioc_type in ["Sha256", "Sha1", "Md5"] {
            if let Some(ioc) = self.lookup_by_value(hash, ioc_type).await {
                return Some(ioc);
            }
        }
        None
    }

    async fn lookup_by_value(&self, value: &str, ioc_type: &str) -> Option<Ioc> {
        let value = value.to_lowercase();
        let ioc_type = ioc_type.to_string();

        self.conn.call(move |conn| {
            let row = conn.query_row(
                "SELECT * FROM iocs WHERE value = ? AND ioc_type = ? AND active = 1",
                [&value, &ioc_type],
                |row| Self::row_to_ioc(row),
            ).ok();

            Ok(row)
        }).await.ok().flatten()
    }

    pub async fn get_active_iocs(&self) -> Vec<Ioc> {
        self.conn.call(|conn| {
            let mut stmt = conn.prepare("SELECT * FROM iocs WHERE active = 1")?;
            let rows = stmt.query_map([], |row| Self::row_to_ioc(row))?;

            Ok(rows.filter_map(|r| r.ok()).collect())
        }).await.unwrap_or_default()
    }

    pub async fn remove_old_iocs(&mut self, cutoff: DateTime<Utc>) -> Result<usize, ThreatIntelError> {
        let cutoff_str = cutoff.to_rfc3339();

        let count = self.conn.call(move |conn| {
            conn.execute(
                "DELETE FROM iocs WHERE last_seen < ?",
                [&cutoff_str],
            )
        }).await?;

        Ok(count)
    }

    fn row_to_ioc(row: &rusqlite::Row) -> rusqlite::Result<Ioc> {
        let categories_json: String = row.get(5)?;
        let sources_json: String = row.get(6)?;
        let metadata_json: String = row.get(10)?;
        let ioc_type_str: String = row.get(1)?;

        let ioc_type = match ioc_type_str.as_str() {
            "IpAddress" => IocType::IpAddress,
            "Domain" => IocType::Domain,
            "Url" => IocType::Url,
            "Sha256" => IocType::Sha256,
            "Sha1" => IocType::Sha1,
            "Md5" => IocType::Md5,
            "Email" => IocType::Email,
            _ => IocType::IpAddress,
        };

        let severity: i32 = row.get(4)?;
        let severity = match severity {
            1 => Severity::Low,
            2 => Severity::Medium,
            3 => Severity::High,
            4 => Severity::Critical,
            _ => Severity::Medium,
        };

        Ok(Ioc {
            id: row.get(0)?,
            ioc_type,
            value: row.get(2)?,
            confidence: row.get(3)?,
            severity,
            categories: serde_json::from_str(&categories_json).unwrap_or_default(),
            sources: serde_json::from_str(&sources_json).unwrap_or_default(),
            first_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            last_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            last_updated: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            metadata: serde_json::from_str(&metadata_json).unwrap_or_default(),
            false_positive_reports: row.get(11)?,
            active: row.get::<_, i32>(12)? != 0,
        })
    }
}
```

### Exporter

```rust
/// Export IOCs to various formats
pub struct Exporter {
    formats: Vec<ExportFormat>,
}

impl Exporter {
    pub fn new(formats: &[ExportFormat]) -> Self {
        Self {
            formats: formats.to_vec(),
        }
    }

    pub fn export_json(&self, iocs: &[Ioc]) -> String {
        let export: Vec<serde_json::Value> = iocs.iter()
            .map(|ioc| serde_json::json!({
                "type": format!("{:?}", ioc.ioc_type),
                "value": ioc.value,
                "confidence": ioc.confidence,
                "severity": format!("{:?}", ioc.severity),
                "categories": ioc.categories.iter().map(|c| format!("{:?}", c)).collect::<Vec<_>>(),
                "first_seen": ioc.first_seen.to_rfc3339(),
                "last_seen": ioc.last_seen.to_rfc3339(),
            }))
            .collect();

        serde_json::to_string_pretty(&export).unwrap_or_default()
    }

    pub fn export_hosts(&self, iocs: &[Ioc]) -> String {
        let mut output = String::from("# Threat Intelligence Blocklist\n");
        output.push_str(&format!("# Generated: {}\n\n", Utc::now().to_rfc3339()));

        for ioc in iocs {
            match ioc.ioc_type {
                IocType::Domain => {
                    output.push_str(&format!("0.0.0.0 {}\n", ioc.value));
                }
                IocType::IpAddress => {
                    // Can't block IPs via hosts file
                }
                _ => {}
            }
        }

        output
    }

    pub fn export_snort(&self, iocs: &[Ioc]) -> String {
        let mut output = String::from("# Snort rules generated from threat intelligence\n\n");
        let mut sid = 9000000;

        for ioc in iocs {
            match ioc.ioc_type {
                IocType::IpAddress => {
                    output.push_str(&format!(
                        r#"alert ip {} any -> any any (msg:"Threat Intel - Malicious IP {}"; sid:{}; rev:1;)
"#,
                        ioc.value, ioc.value, sid
                    ));
                    sid += 1;
                }
                IocType::Domain => {
                    output.push_str(&format!(
                        r#"alert dns any any -> any any (msg:"Threat Intel - Malicious Domain {}"; dns.query; content:"{}"; nocase; sid:{}; rev:1;)
"#,
                        ioc.value, ioc.value, sid
                    ));
                    sid += 1;
                }
                _ => {}
            }
        }

        output
    }

    pub fn export_suricata(&self, iocs: &[Ioc]) -> String {
        // Suricata rules are similar to Snort
        self.export_snort(iocs)
    }

    pub fn export_nginx(&self, iocs: &[Ioc]) -> String {
        let mut output = String::from("# Nginx deny rules from threat intelligence\n\n");

        for ioc in iocs {
            if let IocType::IpAddress = ioc.ioc_type {
                output.push_str(&format!("deny {};\n", ioc.value));
            }
        }

        output
    }

    pub fn export_nftables(&self, iocs: &[Ioc]) -> String {
        let mut ipv4_addrs = Vec::new();
        let mut ipv6_addrs = Vec::new();

        for ioc in iocs {
            if let IocType::IpAddress = ioc.ioc_type {
                if ioc.value.contains(':') {
                    ipv6_addrs.push(&ioc.value);
                } else {
                    ipv4_addrs.push(&ioc.value);
                }
            }
        }

        let mut output = String::from("# nftables set from threat intelligence\n\n");

        output.push_str("define threat_intel_ipv4 = {\n");
        for (i, ip) in ipv4_addrs.iter().enumerate() {
            if i < ipv4_addrs.len() - 1 {
                output.push_str(&format!("    {},\n", ip));
            } else {
                output.push_str(&format!("    {}\n", ip));
            }
        }
        output.push_str("}\n\n");

        if !ipv6_addrs.is_empty() {
            output.push_str("define threat_intel_ipv6 = {\n");
            for (i, ip) in ipv6_addrs.iter().enumerate() {
                if i < ipv6_addrs.len() - 1 {
                    output.push_str(&format!("    {},\n", ip));
                } else {
                    output.push_str(&format!("    {}\n", ip));
                }
            }
            output.push_str("}\n");
        }

        output
    }
}
```

## Output Format

```json
{
  "platform_status": {
    "uptime_seconds": 86400,
    "api_endpoint": "http://127.0.0.1:8080"
  },
  "statistics": {
    "feeds_updated": 48,
    "feed_errors": 2,
    "total_iocs_processed": 1234567,
    "active_iocs": 345678,
    "last_update": "2026-01-22T14:00:00Z"
  },
  "feeds": [
    {
      "name": "Abuse.ch Feodo Tracker",
      "status": "healthy",
      "last_update": "2026-01-22T14:00:00Z",
      "ioc_count": 1234,
      "categories": ["Botnet", "CnC"]
    }
  ],
  "ioc_breakdown": {
    "by_type": {
      "IpAddress": 123456,
      "Domain": 189234,
      "Url": 12345,
      "Sha256": 20643
    },
    "by_category": {
      "Malware": 150000,
      "Phishing": 80000,
      "Botnet": 50000,
      "CnC": 30000,
      "Ads": 35678
    }
  },
  "export_formats_available": [
    "json",
    "hosts",
    "snort",
    "suricata",
    "nginx",
    "nftables"
  ]
}
```

## Success Criteria

1. Multiple feed formats parse correctly (plaintext, CSV, JSON, STIX)
2. IOC deduplication works across feeds
3. Confidence scores aggregate properly from multiple sources
4. STIX/TAXII feeds integrate successfully
5. Database queries are fast (< 10ms for lookups)
6. Export formats are valid for target applications
7. Feed updates run reliably on schedule
8. API provides quick IOC lookups
9. Old IOCs are cleaned up automatically
10. False positive tracking reduces noise over time
