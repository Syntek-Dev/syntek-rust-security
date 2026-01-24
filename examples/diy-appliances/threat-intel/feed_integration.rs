//! Threat Intelligence Feed Integration
//!
//! Implements integration with threat intelligence feeds for IP/domain blocklists,
//! Indicators of Compromise (IOCs), and threat data enrichment.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// Threat intelligence feed configuration
#[derive(Debug, Clone)]
pub struct FeedConfig {
    /// Feed name
    pub name: String,
    /// Feed URL
    pub url: String,
    /// Feed type
    pub feed_type: FeedType,
    /// Update interval
    pub update_interval: Duration,
    /// Authentication (API key, etc.)
    pub auth: Option<FeedAuth>,
    /// Whether feed is enabled
    pub enabled: bool,
    /// Feed priority (higher = more trusted)
    pub priority: u32,
}

#[derive(Debug, Clone)]
pub enum FeedType {
    /// IP address blocklist
    IpBlocklist,
    /// Domain blocklist
    DomainBlocklist,
    /// URL blocklist
    UrlBlocklist,
    /// File hash (IOC) list
    HashList,
    /// STIX/TAXII feed
    Stix,
    /// YARA rules
    YaraRules,
    /// Combined/mixed format
    Combined,
}

#[derive(Debug, Clone)]
pub enum FeedAuth {
    ApiKey(String),
    BasicAuth { username: String, password: String },
    BearerToken(String),
    None,
}

/// Indicator of Compromise
#[derive(Debug, Clone)]
pub struct IoC {
    /// Indicator value
    pub value: String,
    /// Indicator type
    pub ioc_type: IoCType,
    /// Threat type
    pub threat_type: Option<ThreatType>,
    /// Confidence score (0-100)
    pub confidence: u8,
    /// Severity
    pub severity: Severity,
    /// Source feed
    pub source: String,
    /// First seen timestamp
    pub first_seen: SystemTime,
    /// Last seen timestamp
    pub last_seen: SystemTime,
    /// Expiration time
    pub expires: Option<SystemTime>,
    /// Additional context/tags
    pub tags: Vec<String>,
    /// Related IoCs
    pub related: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IoCType {
    IPv4,
    IPv6,
    Domain,
    Url,
    Md5,
    Sha1,
    Sha256,
    Email,
    Filename,
    Registry,
    Mutex,
    UserAgent,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThreatType {
    Malware,
    Phishing,
    Botnet,
    C2,
    Spam,
    Scanner,
    Bruteforce,
    Exploit,
    Ransomware,
    Apt,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

/// Threat intelligence manager
pub struct ThreatIntelManager {
    /// Configured feeds
    feeds: Vec<FeedConfig>,
    /// IP blocklist (IPv4 and IPv6)
    ip_blocklist: HashSet<IpAddr>,
    /// Domain blocklist
    domain_blocklist: HashSet<String>,
    /// URL blocklist
    url_blocklist: HashSet<String>,
    /// Hash blocklist (SHA256)
    hash_blocklist: HashSet<String>,
    /// Full IoC database
    ioc_database: HashMap<String, IoC>,
    /// Statistics
    stats: ThreatIntelStats,
    /// Last update timestamps per feed
    last_updates: HashMap<String, SystemTime>,
}

#[derive(Debug, Default, Clone)]
pub struct ThreatIntelStats {
    pub total_iocs: u64,
    pub ip_indicators: u64,
    pub domain_indicators: u64,
    pub hash_indicators: u64,
    pub url_indicators: u64,
    pub feeds_configured: u64,
    pub feeds_active: u64,
    pub last_update: Option<SystemTime>,
    pub lookups_performed: u64,
    pub threats_matched: u64,
}

impl ThreatIntelManager {
    /// Create new threat intel manager
    pub fn new() -> Self {
        Self {
            feeds: Vec::new(),
            ip_blocklist: HashSet::new(),
            domain_blocklist: HashSet::new(),
            url_blocklist: HashSet::new(),
            hash_blocklist: HashSet::new(),
            ioc_database: HashMap::new(),
            stats: ThreatIntelStats::default(),
            last_updates: HashMap::new(),
        }
    }

    /// Add a threat feed
    pub fn add_feed(&mut self, config: FeedConfig) {
        self.stats.feeds_configured += 1;
        if config.enabled {
            self.stats.feeds_active += 1;
        }
        self.feeds.push(config);
    }

    /// Add well-known feeds
    pub fn add_default_feeds(&mut self) {
        // AbuseIPDB
        self.add_feed(FeedConfig {
            name: "AbuseIPDB".to_string(),
            url: "https://api.abuseipdb.com/api/v2/blacklist".to_string(),
            feed_type: FeedType::IpBlocklist,
            update_interval: Duration::from_secs(86400), // Daily
            auth: None,                                  // Requires API key
            enabled: false,
            priority: 80,
        });

        // Spamhaus DROP
        self.add_feed(FeedConfig {
            name: "Spamhaus-DROP".to_string(),
            url: "https://www.spamhaus.org/drop/drop.txt".to_string(),
            feed_type: FeedType::IpBlocklist,
            update_interval: Duration::from_secs(43200), // 12 hours
            auth: None,
            enabled: true,
            priority: 90,
        });

        // PhishTank
        self.add_feed(FeedConfig {
            name: "PhishTank".to_string(),
            url: "https://data.phishtank.com/data/online-valid.json".to_string(),
            feed_type: FeedType::UrlBlocklist,
            update_interval: Duration::from_secs(3600), // Hourly
            auth: None,
            enabled: true,
            priority: 85,
        });

        // MalwareBazaar
        self.add_feed(FeedConfig {
            name: "MalwareBazaar".to_string(),
            url: "https://bazaar.abuse.ch/export/txt/sha256/recent/".to_string(),
            feed_type: FeedType::HashList,
            update_interval: Duration::from_secs(3600),
            auth: None,
            enabled: true,
            priority: 95,
        });

        // URLhaus
        self.add_feed(FeedConfig {
            name: "URLhaus".to_string(),
            url: "https://urlhaus.abuse.ch/downloads/text_recent/".to_string(),
            feed_type: FeedType::UrlBlocklist,
            update_interval: Duration::from_secs(1800), // 30 minutes
            auth: None,
            enabled: true,
            priority: 90,
        });
    }

    /// Add IoC to database
    pub fn add_ioc(&mut self, ioc: IoC) {
        // Add to appropriate blocklist
        match ioc.ioc_type {
            IoCType::IPv4 | IoCType::IPv6 => {
                if let Ok(ip) = ioc.value.parse::<IpAddr>() {
                    self.ip_blocklist.insert(ip);
                    self.stats.ip_indicators += 1;
                }
            }
            IoCType::Domain => {
                self.domain_blocklist.insert(ioc.value.to_lowercase());
                self.stats.domain_indicators += 1;
            }
            IoCType::Url => {
                self.url_blocklist.insert(ioc.value.clone());
                self.stats.url_indicators += 1;
            }
            IoCType::Sha256 | IoCType::Sha1 | IoCType::Md5 => {
                self.hash_blocklist.insert(ioc.value.to_lowercase());
                self.stats.hash_indicators += 1;
            }
            _ => {}
        }

        // Add to full database
        self.ioc_database.insert(ioc.value.clone(), ioc);
        self.stats.total_iocs += 1;
    }

    /// Check if IP is malicious
    pub fn check_ip(&mut self, ip: &IpAddr) -> Option<ThreatMatch> {
        self.stats.lookups_performed += 1;

        if self.ip_blocklist.contains(ip) {
            self.stats.threats_matched += 1;

            // Get full IoC details if available
            let ioc = self.ioc_database.get(&ip.to_string());

            Some(ThreatMatch {
                indicator: ip.to_string(),
                indicator_type: if ip.is_ipv4() {
                    IoCType::IPv4
                } else {
                    IoCType::IPv6
                },
                threat_type: ioc.and_then(|i| i.threat_type.clone()),
                confidence: ioc.map(|i| i.confidence).unwrap_or(50),
                severity: ioc.map(|i| i.severity.clone()).unwrap_or(Severity::Medium),
                source: ioc
                    .map(|i| i.source.clone())
                    .unwrap_or_else(|| "Unknown".to_string()),
                tags: ioc.map(|i| i.tags.clone()).unwrap_or_default(),
            })
        } else {
            None
        }
    }

    /// Check if domain is malicious
    pub fn check_domain(&mut self, domain: &str) -> Option<ThreatMatch> {
        self.stats.lookups_performed += 1;

        let domain_lower = domain.to_lowercase();

        // Check exact match
        if self.domain_blocklist.contains(&domain_lower) {
            self.stats.threats_matched += 1;
            return self.create_domain_match(&domain_lower);
        }

        // Check parent domains
        let parts: Vec<&str> = domain_lower.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            if self.domain_blocklist.contains(&parent) {
                self.stats.threats_matched += 1;
                return self.create_domain_match(&parent);
            }
        }

        None
    }

    fn create_domain_match(&self, domain: &str) -> Option<ThreatMatch> {
        let ioc = self.ioc_database.get(domain);

        Some(ThreatMatch {
            indicator: domain.to_string(),
            indicator_type: IoCType::Domain,
            threat_type: ioc.and_then(|i| i.threat_type.clone()),
            confidence: ioc.map(|i| i.confidence).unwrap_or(50),
            severity: ioc.map(|i| i.severity.clone()).unwrap_or(Severity::Medium),
            source: ioc
                .map(|i| i.source.clone())
                .unwrap_or_else(|| "Unknown".to_string()),
            tags: ioc.map(|i| i.tags.clone()).unwrap_or_default(),
        })
    }

    /// Check if URL is malicious
    pub fn check_url(&mut self, url: &str) -> Option<ThreatMatch> {
        self.stats.lookups_performed += 1;

        if self.url_blocklist.contains(url) {
            self.stats.threats_matched += 1;

            let ioc = self.ioc_database.get(url);

            return Some(ThreatMatch {
                indicator: url.to_string(),
                indicator_type: IoCType::Url,
                threat_type: ioc.and_then(|i| i.threat_type.clone()),
                confidence: ioc.map(|i| i.confidence).unwrap_or(50),
                severity: ioc.map(|i| i.severity.clone()).unwrap_or(Severity::High),
                source: ioc
                    .map(|i| i.source.clone())
                    .unwrap_or_else(|| "Unknown".to_string()),
                tags: ioc.map(|i| i.tags.clone()).unwrap_or_default(),
            });
        }

        // Also check domain from URL
        if let Some(domain) = extract_domain_from_url(url) {
            return self.check_domain(&domain);
        }

        None
    }

    /// Check if file hash is malicious
    pub fn check_hash(&mut self, hash: &str) -> Option<ThreatMatch> {
        self.stats.lookups_performed += 1;

        let hash_lower = hash.to_lowercase();

        if self.hash_blocklist.contains(&hash_lower) {
            self.stats.threats_matched += 1;

            let ioc = self.ioc_database.get(&hash_lower);

            // Determine hash type
            let hash_type = match hash.len() {
                32 => IoCType::Md5,
                40 => IoCType::Sha1,
                64 => IoCType::Sha256,
                _ => IoCType::Sha256,
            };

            return Some(ThreatMatch {
                indicator: hash_lower,
                indicator_type: hash_type,
                threat_type: ioc.and_then(|i| i.threat_type.clone()),
                confidence: ioc.map(|i| i.confidence).unwrap_or(90),
                severity: ioc
                    .map(|i| i.severity.clone())
                    .unwrap_or(Severity::Critical),
                source: ioc
                    .map(|i| i.source.clone())
                    .unwrap_or_else(|| "Unknown".to_string()),
                tags: ioc.map(|i| i.tags.clone()).unwrap_or_default(),
            });
        }

        None
    }

    /// Bulk check multiple indicators
    pub fn bulk_check(&mut self, indicators: &[String]) -> Vec<ThreatMatch> {
        let mut matches = Vec::new();

        for indicator in indicators {
            // Try to determine indicator type and check
            if let Ok(ip) = indicator.parse::<IpAddr>() {
                if let Some(m) = self.check_ip(&ip) {
                    matches.push(m);
                }
            } else if indicator.contains("://") {
                if let Some(m) = self.check_url(indicator) {
                    matches.push(m);
                }
            } else if indicator.len() == 64 && indicator.chars().all(|c| c.is_ascii_hexdigit()) {
                if let Some(m) = self.check_hash(indicator) {
                    matches.push(m);
                }
            } else if indicator.contains('.') {
                if let Some(m) = self.check_domain(indicator) {
                    matches.push(m);
                }
            }
        }

        matches
    }

    /// Parse IP blocklist (plain text, one IP per line)
    pub fn parse_ip_blocklist(&mut self, content: &str, source: &str) {
        let now = SystemTime::now();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            // Handle CIDR notation (simplified - just use first IP)
            let ip_str = line.split('/').next().unwrap_or(line);
            let ip_str = ip_str.split(';').next().unwrap_or(ip_str).trim();

            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                self.add_ioc(IoC {
                    value: ip.to_string(),
                    ioc_type: if ip.is_ipv4() {
                        IoCType::IPv4
                    } else {
                        IoCType::IPv6
                    },
                    threat_type: None,
                    confidence: 70,
                    severity: Severity::Medium,
                    source: source.to_string(),
                    first_seen: now,
                    last_seen: now,
                    expires: Some(now + Duration::from_secs(86400 * 7)), // 7 days
                    tags: Vec::new(),
                    related: Vec::new(),
                });
            }
        }
    }

    /// Parse domain blocklist
    pub fn parse_domain_blocklist(&mut self, content: &str, source: &str) {
        let now = SystemTime::now();

        for line in content.lines() {
            let line = line.trim().to_lowercase();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Handle hosts file format (0.0.0.0 domain or 127.0.0.1 domain)
            let domain = if line.starts_with("0.0.0.0") || line.starts_with("127.0.0.1") {
                line.split_whitespace().nth(1).unwrap_or(&line)
            } else {
                &line
            };

            if !domain.is_empty() && domain.contains('.') {
                self.add_ioc(IoC {
                    value: domain.to_string(),
                    ioc_type: IoCType::Domain,
                    threat_type: None,
                    confidence: 70,
                    severity: Severity::Medium,
                    source: source.to_string(),
                    first_seen: now,
                    last_seen: now,
                    expires: Some(now + Duration::from_secs(86400 * 7)),
                    tags: Vec::new(),
                    related: Vec::new(),
                });
            }
        }
    }

    /// Parse hash list (SHA256, one per line)
    pub fn parse_hash_list(&mut self, content: &str, source: &str) {
        let now = SystemTime::now();

        for line in content.lines() {
            let hash = line.trim().to_lowercase();

            if hash.is_empty() || hash.starts_with('#') {
                continue;
            }

            // Validate hash format
            if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
                self.add_ioc(IoC {
                    value: hash,
                    ioc_type: IoCType::Sha256,
                    threat_type: Some(ThreatType::Malware),
                    confidence: 90,
                    severity: Severity::Critical,
                    source: source.to_string(),
                    first_seen: now,
                    last_seen: now,
                    expires: None, // Hashes don't expire
                    tags: vec!["malware".to_string()],
                    related: Vec::new(),
                });
            }
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> &ThreatIntelStats {
        &self.stats
    }

    /// Get list of configured feeds
    pub fn get_feeds(&self) -> &[FeedConfig] {
        &self.feeds
    }

    /// Export blocklist for firewall
    pub fn export_ip_blocklist(&self) -> String {
        let mut output = String::new();
        output.push_str("# Auto-generated IP blocklist\n");
        output.push_str(&format!("# Generated: {:?}\n", SystemTime::now()));
        output.push_str(&format!("# Total IPs: {}\n\n", self.ip_blocklist.len()));

        for ip in &self.ip_blocklist {
            output.push_str(&format!("{}\n", ip));
        }

        output
    }

    /// Export domain blocklist for DNS sinkholing
    pub fn export_domain_blocklist(&self) -> String {
        let mut output = String::new();
        output.push_str("# Auto-generated domain blocklist\n");
        output.push_str(&format!(
            "# Total domains: {}\n\n",
            self.domain_blocklist.len()
        ));

        for domain in &self.domain_blocklist {
            output.push_str(&format!("0.0.0.0 {}\n", domain));
        }

        output
    }

    /// Remove expired IoCs
    pub fn cleanup_expired(&mut self) {
        let now = SystemTime::now();

        self.ioc_database.retain(|_, ioc| {
            if let Some(expires) = ioc.expires {
                expires > now
            } else {
                true
            }
        });

        // Rebuild blocklists
        self.rebuild_blocklists();
    }

    fn rebuild_blocklists(&mut self) {
        self.ip_blocklist.clear();
        self.domain_blocklist.clear();
        self.url_blocklist.clear();
        self.hash_blocklist.clear();

        self.stats.ip_indicators = 0;
        self.stats.domain_indicators = 0;
        self.stats.url_indicators = 0;
        self.stats.hash_indicators = 0;

        for ioc in self.ioc_database.values() {
            match ioc.ioc_type {
                IoCType::IPv4 | IoCType::IPv6 => {
                    if let Ok(ip) = ioc.value.parse::<IpAddr>() {
                        self.ip_blocklist.insert(ip);
                        self.stats.ip_indicators += 1;
                    }
                }
                IoCType::Domain => {
                    self.domain_blocklist.insert(ioc.value.to_lowercase());
                    self.stats.domain_indicators += 1;
                }
                IoCType::Url => {
                    self.url_blocklist.insert(ioc.value.clone());
                    self.stats.url_indicators += 1;
                }
                IoCType::Sha256 | IoCType::Sha1 | IoCType::Md5 => {
                    self.hash_blocklist.insert(ioc.value.to_lowercase());
                    self.stats.hash_indicators += 1;
                }
                _ => {}
            }
        }

        self.stats.total_iocs = self.ioc_database.len() as u64;
    }
}

/// Threat match result
#[derive(Debug, Clone)]
pub struct ThreatMatch {
    pub indicator: String,
    pub indicator_type: IoCType,
    pub threat_type: Option<ThreatType>,
    pub confidence: u8,
    pub severity: Severity,
    pub source: String,
    pub tags: Vec<String>,
}

impl ThreatMatch {
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 80
    }

    pub fn is_critical(&self) -> bool {
        self.severity == Severity::Critical
    }
}

/// Extract domain from URL
fn extract_domain_from_url(url: &str) -> Option<String> {
    let url = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");

    let domain = url.split('/').next()?;
    let domain = domain.split(':').next()?;

    if domain.is_empty() {
        None
    } else {
        Some(domain.to_lowercase())
    }
}

/// STIX/TAXII client for enterprise feeds
pub struct StixClient {
    /// TAXII server URL
    pub server_url: String,
    /// API credentials
    pub credentials: Option<FeedAuth>,
    /// Collection ID
    pub collection_id: Option<String>,
}

impl StixClient {
    pub fn new(server_url: String) -> Self {
        Self {
            server_url,
            credentials: None,
            collection_id: None,
        }
    }

    /// Parse STIX 2.1 bundle (simplified)
    pub fn parse_stix_bundle(&self, json: &str) -> Vec<IoC> {
        let mut iocs = Vec::new();
        let now = SystemTime::now();

        // Very simplified STIX parsing - in production use stix2 crate
        // Looking for indicator patterns

        // This is a demo - real implementation would properly parse JSON
        if json.contains("\"type\":\"indicator\"") {
            // Extract basic patterns
            for line in json.lines() {
                if line.contains("ipv4-addr") {
                    // Parse IP indicator
                    if let Some(ip) = extract_ip_from_stix(line) {
                        iocs.push(IoC {
                            value: ip,
                            ioc_type: IoCType::IPv4,
                            threat_type: None,
                            confidence: 80,
                            severity: Severity::Medium,
                            source: "STIX".to_string(),
                            first_seen: now,
                            last_seen: now,
                            expires: None,
                            tags: Vec::new(),
                            related: Vec::new(),
                        });
                    }
                } else if line.contains("domain-name") {
                    if let Some(domain) = extract_domain_from_stix(line) {
                        iocs.push(IoC {
                            value: domain,
                            ioc_type: IoCType::Domain,
                            threat_type: None,
                            confidence: 80,
                            severity: Severity::Medium,
                            source: "STIX".to_string(),
                            first_seen: now,
                            last_seen: now,
                            expires: None,
                            tags: Vec::new(),
                            related: Vec::new(),
                        });
                    }
                }
            }
        }

        iocs
    }
}

fn extract_ip_from_stix(_line: &str) -> Option<String> {
    // Simplified - would parse actual STIX pattern
    None
}

fn extract_domain_from_stix(_line: &str) -> Option<String> {
    // Simplified - would parse actual STIX pattern
    None
}

fn main() {
    println!("=== Threat Intelligence Feed Integration Demo ===\n");

    // Create threat intel manager
    let mut manager = ThreatIntelManager::new();

    // Add default feeds
    manager.add_default_feeds();
    println!("Configured {} threat feeds", manager.get_feeds().len());

    // Simulate loading IP blocklist
    let ip_blocklist = r#"
# Spamhaus DROP list
# Last updated: 2024-01-01
192.0.2.1
198.51.100.0/24
203.0.113.50
2001:db8::1
"#;
    manager.parse_ip_blocklist(ip_blocklist, "Spamhaus-DROP");

    // Simulate loading domain blocklist
    let domain_blocklist = r#"
# Malicious domains
malware-download.com
phishing-site.net
0.0.0.0 evil-domain.org
127.0.0.1 bad-actor.io
"#;
    manager.parse_domain_blocklist(domain_blocklist, "Custom");

    // Simulate loading hash list
    let hash_list = r#"
# Known malware SHA256 hashes
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
"#;
    manager.parse_hash_list(hash_list, "MalwareBazaar");

    // Display statistics
    let stats = manager.get_stats();
    println!("\nThreat Intelligence Statistics:");
    println!("  Total IoCs: {}", stats.total_iocs);
    println!("  IP indicators: {}", stats.ip_indicators);
    println!("  Domain indicators: {}", stats.domain_indicators);
    println!("  Hash indicators: {}", stats.hash_indicators);

    // Test lookups
    println!("\nPerforming threat lookups:");

    // Check known malicious IP
    let test_ip: IpAddr = "192.0.2.1".parse().unwrap();
    if let Some(threat) = manager.check_ip(&test_ip) {
        println!("  IP {}: THREAT DETECTED", test_ip);
        println!("    - Severity: {:?}", threat.severity);
        println!("    - Source: {}", threat.source);
    }

    // Check clean IP
    let clean_ip: IpAddr = "8.8.8.8".parse().unwrap();
    if manager.check_ip(&clean_ip).is_none() {
        println!("  IP {}: Clean", clean_ip);
    }

    // Check malicious domain
    if let Some(threat) = manager.check_domain("malware-download.com") {
        println!("  Domain malware-download.com: THREAT DETECTED");
        println!("    - Severity: {:?}", threat.severity);
    }

    // Check subdomain of malicious domain
    if let Some(threat) = manager.check_domain("sub.evil-domain.org") {
        println!("  Domain sub.evil-domain.org: THREAT DETECTED (parent domain)");
        println!("    - Matched: {}", threat.indicator);
    }

    // Check malicious URL
    if let Some(threat) = manager.check_url("https://phishing-site.net/login.php") {
        println!("  URL https://phishing-site.net/login.php: THREAT DETECTED");
        println!("    - Type: {:?}", threat.indicator_type);
    }

    // Check malicious hash
    let malware_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    if let Some(threat) = manager.check_hash(malware_hash) {
        println!("  Hash {}: THREAT DETECTED", &malware_hash[..16]);
        println!("    - Severity: {:?}", threat.severity);
        println!("    - Confidence: {}%", threat.confidence);
    }

    // Bulk check
    println!("\nBulk checking multiple indicators:");
    let indicators = vec![
        "192.0.2.1".to_string(),
        "8.8.8.8".to_string(),
        "malware-download.com".to_string(),
        "google.com".to_string(),
    ];
    let matches = manager.bulk_check(&indicators);
    println!(
        "  Checked {} indicators, found {} threats",
        indicators.len(),
        matches.len()
    );

    // Export for firewall
    println!("\nExporting blocklists:");
    let ip_export = manager.export_ip_blocklist();
    println!("  IP blocklist: {} bytes", ip_export.len());

    let domain_export = manager.export_domain_blocklist();
    println!("  Domain blocklist: {} bytes", domain_export.len());

    // Final statistics
    let final_stats = manager.get_stats();
    println!("\nFinal Statistics:");
    println!("  Lookups performed: {}", final_stats.lookups_performed);
    println!("  Threats matched: {}", final_stats.threats_matched);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_blocklist_parsing() {
        let mut manager = ThreatIntelManager::new();

        let blocklist = "192.0.2.1\n192.0.2.2\n# comment\n198.51.100.1";
        manager.parse_ip_blocklist(blocklist, "test");

        assert_eq!(manager.stats.ip_indicators, 3);
    }

    #[test]
    fn test_ip_lookup() {
        let mut manager = ThreatIntelManager::new();
        manager.parse_ip_blocklist("192.0.2.1", "test");

        let malicious: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(manager.check_ip(&malicious).is_some());

        let clean: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(manager.check_ip(&clean).is_none());
    }

    #[test]
    fn test_domain_blocklist_parsing() {
        let mut manager = ThreatIntelManager::new();

        let blocklist = "evil.com\n0.0.0.0 bad.com\n127.0.0.1 malware.net";
        manager.parse_domain_blocklist(blocklist, "test");

        assert_eq!(manager.stats.domain_indicators, 3);
    }

    #[test]
    fn test_domain_lookup_with_subdomain() {
        let mut manager = ThreatIntelManager::new();
        manager.parse_domain_blocklist("evil.com", "test");

        // Exact match
        assert!(manager.check_domain("evil.com").is_some());

        // Subdomain match
        assert!(manager.check_domain("sub.evil.com").is_some());

        // Non-match
        assert!(manager.check_domain("good.com").is_none());
    }

    #[test]
    fn test_hash_lookup() {
        let mut manager = ThreatIntelManager::new();

        let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        manager.parse_hash_list(hash, "test");

        assert!(manager.check_hash(hash).is_some());
        assert!(manager.check_hash(&hash.to_uppercase()).is_some()); // Case insensitive
        assert!(manager
            .check_hash("0000000000000000000000000000000000000000000000000000000000000000")
            .is_none());
    }

    #[test]
    fn test_url_extraction() {
        assert_eq!(
            extract_domain_from_url("https://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_domain_from_url("http://sub.example.com:8080/path"),
            Some("sub.example.com".to_string())
        );
    }

    #[test]
    fn test_bulk_check() {
        let mut manager = ThreatIntelManager::new();
        manager.parse_ip_blocklist("192.0.2.1", "test");
        manager.parse_domain_blocklist("evil.com", "test");

        let indicators = vec![
            "192.0.2.1".to_string(),
            "8.8.8.8".to_string(),
            "evil.com".to_string(),
            "good.com".to_string(),
        ];

        let matches = manager.bulk_check(&indicators);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Unknown);
    }

    #[test]
    fn test_threat_match_confidence() {
        let high_conf = ThreatMatch {
            indicator: "test".to_string(),
            indicator_type: IoCType::Domain,
            threat_type: None,
            confidence: 85,
            severity: Severity::Medium,
            source: "test".to_string(),
            tags: Vec::new(),
        };
        assert!(high_conf.is_high_confidence());

        let low_conf = ThreatMatch {
            confidence: 50,
            ..high_conf.clone()
        };
        assert!(!low_conf.is_high_confidence());
    }

    #[test]
    fn test_export_blocklist() {
        let mut manager = ThreatIntelManager::new();
        manager.parse_ip_blocklist("192.0.2.1\n192.0.2.2", "test");

        let export = manager.export_ip_blocklist();
        assert!(export.contains("192.0.2.1"));
        assert!(export.contains("192.0.2.2"));
        assert!(export.contains("# Auto-generated"));
    }
}
