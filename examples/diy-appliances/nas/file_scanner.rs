//! NAS File Scanner - Malware Detection and File Integrity Monitoring
//!
//! This example demonstrates building a file scanning engine for NAS devices
//! with real-time malware detection, quarantine, and integrity monitoring.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// File type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    Executable,
    Script,
    Document,
    Archive,
    Image,
    Video,
    Audio,
    Unknown,
}

impl FileType {
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "exe" | "dll" | "so" | "dylib" | "bin" | "elf" => Self::Executable,
            "sh" | "bash" | "py" | "rb" | "pl" | "ps1" | "bat" | "cmd" | "js" => Self::Script,
            "doc" | "docx" | "pdf" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" => Self::Document,
            "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" | "xz" => Self::Archive,
            "jpg" | "jpeg" | "png" | "gif" | "bmp" | "svg" | "webp" => Self::Image,
            "mp4" | "avi" | "mkv" | "mov" | "wmv" | "flv" => Self::Video,
            "mp3" | "wav" | "flac" | "aac" | "ogg" => Self::Audio,
            _ => Self::Unknown,
        }
    }

    pub fn is_risky(&self) -> bool {
        matches!(self, Self::Executable | Self::Script | Self::Archive)
    }
}

/// Scan result for a file
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub path: PathBuf,
    pub file_type: FileType,
    pub size: u64,
    pub hash_sha256: String,
    pub scan_time: u64,
    pub threats: Vec<ThreatMatch>,
    pub risk_score: f32,
    pub action: ScanAction,
    pub metadata: FileMetadata,
}

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
    pub owner: Option<String>,
    pub permissions: u32,
    pub is_hidden: bool,
    pub is_symlink: bool,
}

#[derive(Debug, Clone)]
pub struct ThreatMatch {
    pub signature_id: String,
    pub name: String,
    pub category: ThreatCategory,
    pub severity: ThreatSeverity,
    pub confidence: f32,
    pub description: String,
    pub offset: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreatCategory {
    Virus,
    Trojan,
    Ransomware,
    Spyware,
    Adware,
    Rootkit,
    Worm,
    Miner,
    PotentiallyUnwanted,
    Suspicious,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum ThreatSeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanAction {
    Clean,
    Quarantine,
    Delete,
    Ignore,
    ManualReview,
}

/// Malware signature
#[derive(Debug, Clone)]
pub struct MalwareSignature {
    pub id: String,
    pub name: String,
    pub category: ThreatCategory,
    pub severity: ThreatSeverity,
    pub pattern: SignaturePattern,
    pub description: String,
    pub cve: Option<String>,
}

#[derive(Debug, Clone)]
pub enum SignaturePattern {
    /// SHA256 hash match
    Hash(String),
    /// Byte sequence match
    ByteSequence(Vec<u8>),
    /// YARA rule
    YaraRule(String),
    /// File name pattern
    FileName(String),
    /// Entropy-based detection
    HighEntropy { threshold: f32, min_size: u64 },
}

/// Quarantine entry
#[derive(Debug, Clone)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub quarantined_at: u64,
    pub threat_info: Vec<ThreatMatch>,
    pub file_hash: String,
    pub file_size: u64,
    pub can_restore: bool,
    pub expires_at: Option<u64>,
}

/// File integrity baseline
#[derive(Debug, Clone)]
pub struct IntegrityBaseline {
    pub path: PathBuf,
    pub hash: String,
    pub size: u64,
    pub permissions: u32,
    pub modified: u64,
    pub baseline_created: u64,
}

/// Integrity check result
#[derive(Debug, Clone)]
pub struct IntegrityResult {
    pub path: PathBuf,
    pub status: IntegrityStatus,
    pub changes: Vec<IntegrityChange>,
    pub checked_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityStatus {
    Unchanged,
    Modified,
    Deleted,
    New,
    PermissionsChanged,
}

#[derive(Debug, Clone)]
pub struct IntegrityChange {
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

/// Scanner configuration
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Scan archives recursively
    pub scan_archives: bool,
    /// Maximum archive depth
    pub max_archive_depth: u32,
    /// Maximum file size to scan (bytes)
    pub max_file_size: u64,
    /// Enable heuristic scanning
    pub heuristics_enabled: bool,
    /// Heuristic sensitivity (0.0 - 1.0)
    pub heuristic_sensitivity: f32,
    /// Quarantine directory
    pub quarantine_dir: PathBuf,
    /// Auto-quarantine threshold severity
    pub auto_quarantine_severity: ThreatSeverity,
    /// Days to keep quarantined files
    pub quarantine_retention_days: u32,
    /// Enable real-time scanning
    pub realtime_enabled: bool,
    /// File types to skip
    pub skip_extensions: HashSet<String>,
    /// Directories to exclude
    pub exclude_paths: Vec<PathBuf>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            scan_archives: true,
            max_archive_depth: 3,
            max_file_size: 100 * 1024 * 1024, // 100MB
            heuristics_enabled: true,
            heuristic_sensitivity: 0.7,
            quarantine_dir: PathBuf::from("/var/quarantine"),
            auto_quarantine_severity: ThreatSeverity::High,
            quarantine_retention_days: 30,
            realtime_enabled: true,
            skip_extensions: HashSet::new(),
            exclude_paths: Vec::new(),
        }
    }
}

/// Scan statistics
#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub threats_found: u64,
    pub files_quarantined: u64,
    pub files_cleaned: u64,
    pub files_skipped: u64,
    pub errors: u64,
    pub scan_duration_ms: u64,
}

/// Main file scanner
pub struct FileScanner {
    config: ScannerConfig,
    signatures: RwLock<Vec<MalwareSignature>>,
    quarantine: RwLock<HashMap<String, QuarantineEntry>>,
    baselines: RwLock<HashMap<PathBuf, IntegrityBaseline>>,
    scan_history: RwLock<VecDeque<ScanResult>>,
    stats: RwLock<ScanStats>,
}

impl FileScanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self {
            config,
            signatures: RwLock::new(Self::load_default_signatures()),
            quarantine: RwLock::new(HashMap::new()),
            baselines: RwLock::new(HashMap::new()),
            scan_history: RwLock::new(VecDeque::with_capacity(10000)),
            stats: RwLock::new(ScanStats::default()),
        }
    }

    /// Load default malware signatures
    fn load_default_signatures() -> Vec<MalwareSignature> {
        vec![
            MalwareSignature {
                id: "MAL-001".to_string(),
                name: "EICAR-Test-File".to_string(),
                category: ThreatCategory::Virus,
                severity: ThreatSeverity::Low,
                pattern: SignaturePattern::ByteSequence(
                    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR".to_vec(),
                ),
                description: "EICAR antivirus test file".to_string(),
                cve: None,
            },
            MalwareSignature {
                id: "RAN-001".to_string(),
                name: "Ransomware-Extension-Pattern".to_string(),
                category: ThreatCategory::Ransomware,
                severity: ThreatSeverity::Critical,
                pattern: SignaturePattern::FileName("*.encrypted".to_string()),
                description: "Files with ransomware encryption extension".to_string(),
                cve: None,
            },
            MalwareSignature {
                id: "MIN-001".to_string(),
                name: "Cryptominer-Pattern".to_string(),
                category: ThreatCategory::Miner,
                severity: ThreatSeverity::Medium,
                pattern: SignaturePattern::ByteSequence(b"stratum+tcp://".to_vec()),
                description: "Cryptocurrency mining pool connection".to_string(),
                cve: None,
            },
            MalwareSignature {
                id: "SUS-001".to_string(),
                name: "High-Entropy-File".to_string(),
                category: ThreatCategory::Suspicious,
                severity: ThreatSeverity::Medium,
                pattern: SignaturePattern::HighEntropy {
                    threshold: 7.9,
                    min_size: 10000,
                },
                description: "File with unusually high entropy (possible encryption/packing)"
                    .to_string(),
                cve: None,
            },
        ]
    }

    /// Scan a single file
    pub fn scan_file(&self, path: &Path) -> ScanResult {
        let start = std::time::Instant::now();

        // Get file metadata
        let metadata = self.get_file_metadata(path);
        let size = metadata.as_ref().map(|m| 1024u64).unwrap_or(0); // Simulated

        // Determine file type
        let file_type = path
            .extension()
            .and_then(|e| e.to_str())
            .map(FileType::from_extension)
            .unwrap_or(FileType::Unknown);

        // Check exclusions
        if self.should_skip(path, file_type) {
            self.update_stats(|s| s.files_skipped += 1);
            return ScanResult {
                path: path.to_path_buf(),
                file_type,
                size,
                hash_sha256: String::new(),
                scan_time: current_timestamp(),
                threats: Vec::new(),
                risk_score: 0.0,
                action: ScanAction::Ignore,
                metadata: metadata.unwrap_or_else(|| self.empty_metadata()),
            };
        }

        // Calculate file hash
        let hash = self.calculate_hash(path);

        // Scan for threats
        let threats = self.match_signatures(path, &hash, size);

        // Calculate risk score
        let risk_score = self.calculate_risk_score(&threats, file_type);

        // Determine action
        let action = self.determine_action(&threats, risk_score);

        // Execute action if needed
        if action == ScanAction::Quarantine {
            let _ = self.quarantine_file(path, &threats, &hash);
            self.update_stats(|s| s.files_quarantined += 1);
        }

        // Update statistics
        self.update_stats(|s| {
            s.files_scanned += 1;
            s.bytes_scanned += size;
            s.threats_found += threats.len() as u64;
            s.scan_duration_ms += start.elapsed().as_millis() as u64;
        });

        let result = ScanResult {
            path: path.to_path_buf(),
            file_type,
            size,
            hash_sha256: hash,
            scan_time: current_timestamp(),
            threats,
            risk_score,
            action,
            metadata: metadata.unwrap_or_else(|| self.empty_metadata()),
        };

        // Record in history
        {
            let mut history = self.scan_history.write().unwrap();
            history.push_back(result.clone());
            if history.len() > 10000 {
                history.pop_front();
            }
        }

        result
    }

    /// Scan a directory recursively
    pub fn scan_directory(&self, path: &Path) -> Vec<ScanResult> {
        let mut results = Vec::new();

        // Simulate directory scan
        let simulated_files = vec![
            path.join("document.pdf"),
            path.join("script.sh"),
            path.join("archive.zip"),
            path.join("image.jpg"),
        ];

        for file in simulated_files {
            if !self.is_excluded(&file) {
                results.push(self.scan_file(&file));
            }
        }

        results
    }

    /// Match file against signatures
    fn match_signatures(&self, path: &Path, hash: &str, size: u64) -> Vec<ThreatMatch> {
        let signatures = self.signatures.read().unwrap();
        let mut matches = Vec::new();

        for sig in signatures.iter() {
            let matched = match &sig.pattern {
                SignaturePattern::Hash(h) => h == hash,
                SignaturePattern::FileName(pattern) => {
                    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    self.matches_pattern(filename, pattern)
                }
                SignaturePattern::ByteSequence(bytes) => {
                    // Simulated byte matching
                    bytes.len() > 0 && size > bytes.len() as u64
                }
                SignaturePattern::HighEntropy {
                    threshold,
                    min_size,
                } => {
                    if size >= *min_size {
                        let entropy = self.calculate_entropy(path);
                        entropy >= *threshold
                    } else {
                        false
                    }
                }
                SignaturePattern::YaraRule(_rule) => {
                    // Would use YARA library in production
                    false
                }
            };

            if matched {
                matches.push(ThreatMatch {
                    signature_id: sig.id.clone(),
                    name: sig.name.clone(),
                    category: sig.category,
                    severity: sig.severity,
                    confidence: 0.95,
                    description: sig.description.clone(),
                    offset: None,
                });
            }
        }

        // Heuristic scanning
        if self.config.heuristics_enabled {
            if let Some(heuristic_match) = self.heuristic_scan(path, size) {
                matches.push(heuristic_match);
            }
        }

        matches
    }

    /// Heuristic-based threat detection
    fn heuristic_scan(&self, path: &Path, size: u64) -> Option<ThreatMatch> {
        let file_type = path
            .extension()
            .and_then(|e| e.to_str())
            .map(FileType::from_extension)
            .unwrap_or(FileType::Unknown);

        // Suspicious: executable in unusual location
        if file_type == FileType::Executable {
            let path_str = path.to_string_lossy();
            if path_str.contains("temp") || path_str.contains("tmp") || path_str.contains("cache") {
                return Some(ThreatMatch {
                    signature_id: "HEUR-001".to_string(),
                    name: "Heuristic.Suspicious.Location".to_string(),
                    category: ThreatCategory::Suspicious,
                    severity: ThreatSeverity::Medium,
                    confidence: 0.6,
                    description: "Executable in temporary/cache directory".to_string(),
                    offset: None,
                });
            }
        }

        // Suspicious: hidden executable
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with('.'))
            .unwrap_or(false)
            && file_type.is_risky()
        {
            return Some(ThreatMatch {
                signature_id: "HEUR-002".to_string(),
                name: "Heuristic.Hidden.Executable".to_string(),
                category: ThreatCategory::Suspicious,
                severity: ThreatSeverity::Medium,
                confidence: 0.5,
                description: "Hidden file with executable extension".to_string(),
                offset: None,
            });
        }

        None
    }

    /// Quarantine a file
    pub fn quarantine_file(
        &self,
        path: &Path,
        threats: &[ThreatMatch],
        hash: &str,
    ) -> Result<QuarantineEntry, ScanError> {
        let id = generate_quarantine_id();
        let quarantine_path = self.config.quarantine_dir.join(&id);

        // In production: move file, encrypt, set permissions
        let entry = QuarantineEntry {
            id: id.clone(),
            original_path: path.to_path_buf(),
            quarantine_path,
            quarantined_at: current_timestamp(),
            threat_info: threats.to_vec(),
            file_hash: hash.to_string(),
            file_size: 1024, // Simulated
            can_restore: true,
            expires_at: Some(
                current_timestamp() + (self.config.quarantine_retention_days as u64 * 86400),
            ),
        };

        let mut quarantine = self.quarantine.write().unwrap();
        quarantine.insert(id.clone(), entry.clone());

        Ok(entry)
    }

    /// Restore a file from quarantine
    pub fn restore_from_quarantine(&self, id: &str) -> Result<PathBuf, ScanError> {
        let mut quarantine = self.quarantine.write().unwrap();
        let entry = quarantine
            .remove(id)
            .ok_or(ScanError::QuarantineNotFound(id.to_string()))?;

        if !entry.can_restore {
            return Err(ScanError::RestoreNotAllowed(id.to_string()));
        }

        // In production: decrypt and move file back
        Ok(entry.original_path)
    }

    /// Create integrity baseline for a path
    pub fn create_baseline(&self, path: &Path) -> IntegrityBaseline {
        let hash = self.calculate_hash(path);
        let baseline = IntegrityBaseline {
            path: path.to_path_buf(),
            hash,
            size: 1024, // Simulated
            permissions: 0o644,
            modified: current_timestamp(),
            baseline_created: current_timestamp(),
        };

        let mut baselines = self.baselines.write().unwrap();
        baselines.insert(path.to_path_buf(), baseline.clone());

        baseline
    }

    /// Check file integrity against baseline
    pub fn check_integrity(&self, path: &Path) -> IntegrityResult {
        let baselines = self.baselines.read().unwrap();

        if let Some(baseline) = baselines.get(path) {
            let current_hash = self.calculate_hash(path);
            let mut changes = Vec::new();

            if current_hash != baseline.hash {
                changes.push(IntegrityChange {
                    field: "hash".to_string(),
                    old_value: baseline.hash.clone(),
                    new_value: current_hash,
                });
            }

            IntegrityResult {
                path: path.to_path_buf(),
                status: if changes.is_empty() {
                    IntegrityStatus::Unchanged
                } else {
                    IntegrityStatus::Modified
                },
                changes,
                checked_at: current_timestamp(),
            }
        } else {
            IntegrityResult {
                path: path.to_path_buf(),
                status: IntegrityStatus::New,
                changes: Vec::new(),
                checked_at: current_timestamp(),
            }
        }
    }

    /// Add custom signature
    pub fn add_signature(&self, signature: MalwareSignature) {
        self.signatures.write().unwrap().push(signature);
    }

    /// Get scan statistics
    pub fn get_stats(&self) -> ScanStats {
        self.stats.read().unwrap().clone()
    }

    /// Get quarantine entries
    pub fn get_quarantine(&self) -> Vec<QuarantineEntry> {
        self.quarantine.read().unwrap().values().cloned().collect()
    }

    /// Get recent scan history
    pub fn get_history(&self, limit: usize) -> Vec<ScanResult> {
        let history = self.scan_history.read().unwrap();
        history.iter().rev().take(limit).cloned().collect()
    }

    // Helper methods

    fn should_skip(&self, path: &Path, file_type: FileType) -> bool {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if self.config.skip_extensions.contains(ext) {
                return true;
            }
        }
        self.is_excluded(path)
    }

    fn is_excluded(&self, path: &Path) -> bool {
        self.config
            .exclude_paths
            .iter()
            .any(|excluded| path.starts_with(excluded))
    }

    fn calculate_hash(&self, path: &Path) -> String {
        // Simulated hash calculation
        format!("sha256:{:x}", path.to_string_lossy().len() * 12345)
    }

    fn calculate_entropy(&self, _path: &Path) -> f32 {
        // Simulated entropy calculation
        7.5
    }

    fn matches_pattern(&self, filename: &str, pattern: &str) -> bool {
        if pattern.starts_with('*') {
            filename.ends_with(&pattern[1..])
        } else if pattern.ends_with('*') {
            filename.starts_with(&pattern[..pattern.len() - 1])
        } else {
            filename == pattern
        }
    }

    fn calculate_risk_score(&self, threats: &[ThreatMatch], file_type: FileType) -> f32 {
        let mut score = 0.0;

        for threat in threats {
            score += match threat.severity {
                ThreatSeverity::Low => 0.2,
                ThreatSeverity::Medium => 0.4,
                ThreatSeverity::High => 0.7,
                ThreatSeverity::Critical => 1.0,
            } * threat.confidence;
        }

        // File type modifier
        if file_type.is_risky() {
            score *= 1.2;
        }

        score.min(1.0)
    }

    fn determine_action(&self, threats: &[ThreatMatch], risk_score: f32) -> ScanAction {
        if threats.is_empty() {
            return ScanAction::Clean;
        }

        let max_severity = threats
            .iter()
            .map(|t| t.severity)
            .max()
            .unwrap_or(ThreatSeverity::Low);

        if max_severity >= self.config.auto_quarantine_severity {
            ScanAction::Quarantine
        } else if risk_score > 0.5 {
            ScanAction::ManualReview
        } else {
            ScanAction::Ignore
        }
    }

    fn get_file_metadata(&self, _path: &Path) -> Option<FileMetadata> {
        Some(FileMetadata {
            created: current_timestamp() - 86400,
            modified: current_timestamp() - 3600,
            accessed: current_timestamp(),
            owner: Some("user".to_string()),
            permissions: 0o644,
            is_hidden: false,
            is_symlink: false,
        })
    }

    fn empty_metadata(&self) -> FileMetadata {
        FileMetadata {
            created: 0,
            modified: 0,
            accessed: 0,
            owner: None,
            permissions: 0,
            is_hidden: false,
            is_symlink: false,
        }
    }

    fn update_stats<F: FnOnce(&mut ScanStats)>(&self, f: F) {
        let mut stats = self.stats.write().unwrap();
        f(&mut stats);
    }
}

#[derive(Debug, Clone)]
pub enum ScanError {
    FileNotFound(PathBuf),
    PermissionDenied(PathBuf),
    QuarantineNotFound(String),
    RestoreNotAllowed(String),
    IoError(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileNotFound(p) => write!(f, "File not found: {:?}", p),
            Self::PermissionDenied(p) => write!(f, "Permission denied: {:?}", p),
            Self::QuarantineNotFound(id) => write!(f, "Quarantine entry not found: {}", id),
            Self::RestoreNotAllowed(id) => write!(f, "Restore not allowed: {}", id),
            Self::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for ScanError {}

// Helper functions

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn generate_quarantine_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "q-{}-{}",
        current_timestamp(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn main() {
    println!("=== NAS File Scanner ===\n");

    // Create scanner
    let config = ScannerConfig {
        scan_archives: true,
        heuristics_enabled: true,
        auto_quarantine_severity: ThreatSeverity::High,
        ..Default::default()
    };
    let scanner = FileScanner::new(config);

    // Add custom signature
    scanner.add_signature(MalwareSignature {
        id: "CUSTOM-001".to_string(),
        name: "Test-Malware".to_string(),
        category: ThreatCategory::Virus,
        severity: ThreatSeverity::High,
        pattern: SignaturePattern::FileName("malware.exe".to_string()),
        description: "Custom test signature".to_string(),
        cve: None,
    });

    // Scan files
    println!("--- Scanning Files ---");
    let test_files = vec![
        Path::new("/data/document.pdf"),
        Path::new("/data/script.sh"),
        Path::new("/tmp/suspicious.exe"),
        Path::new("/data/malware.exe"),
    ];

    for file in test_files {
        let result = scanner.scan_file(file);
        println!(
            "{:?}: {:?} - Risk: {:.2} - Action: {:?}",
            file.file_name().unwrap_or_default(),
            result.file_type,
            result.risk_score,
            result.action
        );
        for threat in &result.threats {
            println!(
                "  [{:?}] {}: {}",
                threat.severity, threat.name, threat.description
            );
        }
    }

    // Scan directory
    println!("\n--- Scanning Directory ---");
    let results = scanner.scan_directory(Path::new("/data"));
    println!("Scanned {} files", results.len());

    // Check quarantine
    println!("\n--- Quarantine ---");
    let quarantine = scanner.get_quarantine();
    println!("Quarantined files: {}", quarantine.len());
    for entry in &quarantine {
        println!(
            "  {} -> {:?} (threats: {})",
            entry.id,
            entry.original_path,
            entry.threat_info.len()
        );
    }

    // Create integrity baseline
    println!("\n--- Integrity Monitoring ---");
    let baseline = scanner.create_baseline(Path::new("/data/important.conf"));
    println!("Created baseline for: {:?}", baseline.path);

    // Check integrity
    let integrity = scanner.check_integrity(Path::new("/data/important.conf"));
    println!("Integrity status: {:?}", integrity.status);

    // Get statistics
    println!("\n--- Scan Statistics ---");
    let stats = scanner.get_stats();
    println!("Files scanned: {}", stats.files_scanned);
    println!("Bytes scanned: {}", stats.bytes_scanned);
    println!("Threats found: {}", stats.threats_found);
    println!("Files quarantined: {}", stats.files_quarantined);

    println!("\n=== File Scanner Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_scanner() -> FileScanner {
        FileScanner::new(ScannerConfig::default())
    }

    #[test]
    fn test_file_type_detection() {
        assert_eq!(FileType::from_extension("exe"), FileType::Executable);
        assert_eq!(FileType::from_extension("pdf"), FileType::Document);
        assert_eq!(FileType::from_extension("jpg"), FileType::Image);
        assert_eq!(FileType::from_extension("sh"), FileType::Script);
    }

    #[test]
    fn test_clean_file_scan() {
        let scanner = test_scanner();
        let result = scanner.scan_file(Path::new("/data/clean.txt"));
        assert_eq!(result.action, ScanAction::Ignore); // No threats
    }

    #[test]
    fn test_threat_detection() {
        let scanner = test_scanner();
        scanner.add_signature(MalwareSignature {
            id: "TEST-001".to_string(),
            name: "Test".to_string(),
            category: ThreatCategory::Virus,
            severity: ThreatSeverity::High,
            pattern: SignaturePattern::FileName("test.virus".to_string()),
            description: "Test".to_string(),
            cve: None,
        });

        let result = scanner.scan_file(Path::new("/data/test.virus"));
        assert!(!result.threats.is_empty());
    }

    #[test]
    fn test_quarantine() {
        let scanner = test_scanner();
        let entry = scanner
            .quarantine_file(
                Path::new("/data/malware.exe"),
                &[ThreatMatch {
                    signature_id: "TEST".to_string(),
                    name: "Test".to_string(),
                    category: ThreatCategory::Virus,
                    severity: ThreatSeverity::High,
                    confidence: 0.9,
                    description: "Test".to_string(),
                    offset: None,
                }],
                "hash123",
            )
            .unwrap();

        assert!(!entry.id.is_empty());
        assert_eq!(scanner.get_quarantine().len(), 1);
    }

    #[test]
    fn test_restore_from_quarantine() {
        let scanner = test_scanner();
        let entry = scanner
            .quarantine_file(Path::new("/data/file.exe"), &[], "hash")
            .unwrap();

        let restored = scanner.restore_from_quarantine(&entry.id).unwrap();
        assert_eq!(restored, Path::new("/data/file.exe"));
    }

    #[test]
    fn test_integrity_baseline() {
        let scanner = test_scanner();
        let baseline = scanner.create_baseline(Path::new("/data/config.txt"));

        let result = scanner.check_integrity(Path::new("/data/config.txt"));
        assert_eq!(result.status, IntegrityStatus::Unchanged);
    }

    #[test]
    fn test_new_file_integrity() {
        let scanner = test_scanner();
        let result = scanner.check_integrity(Path::new("/data/new_file.txt"));
        assert_eq!(result.status, IntegrityStatus::New);
    }

    #[test]
    fn test_stats_tracking() {
        let scanner = test_scanner();
        scanner.scan_file(Path::new("/data/file1.txt"));
        scanner.scan_file(Path::new("/data/file2.txt"));

        let stats = scanner.get_stats();
        assert!(stats.files_scanned >= 2 || stats.files_skipped >= 2);
    }

    #[test]
    fn test_risky_file_types() {
        assert!(FileType::Executable.is_risky());
        assert!(FileType::Script.is_risky());
        assert!(!FileType::Document.is_risky());
        assert!(!FileType::Image.is_risky());
    }

    #[test]
    fn test_risk_score_calculation() {
        let scanner = test_scanner();
        let threats = vec![ThreatMatch {
            signature_id: "TEST".to_string(),
            name: "Test".to_string(),
            category: ThreatCategory::Virus,
            severity: ThreatSeverity::High,
            confidence: 1.0,
            description: "Test".to_string(),
            offset: None,
        }];

        let score = scanner.calculate_risk_score(&threats, FileType::Executable);
        assert!(score > 0.5);
    }
}
