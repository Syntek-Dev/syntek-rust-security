//! File Integrity Monitor
//!
//! Real-time file integrity monitoring for NAS security.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Hash algorithm for integrity checking
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashAlgorithm {
    SHA256,
    SHA512,
    Blake3,
    XXHash,
}

impl HashAlgorithm {
    pub fn hash_size(&self) -> usize {
        match self {
            Self::SHA256 => 32,
            Self::SHA512 => 64,
            Self::Blake3 => 32,
            Self::XXHash => 8,
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SHA256 => write!(f, "SHA-256"),
            Self::SHA512 => write!(f, "SHA-512"),
            Self::Blake3 => write!(f, "BLAKE3"),
            Self::XXHash => write!(f, "XXHash"),
        }
    }
}

/// File metadata for integrity tracking
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub path: PathBuf,
    pub size: u64,
    pub hash: Vec<u8>,
    pub hash_algorithm: HashAlgorithm,
    pub permissions: u32,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub modified_time: SystemTime,
    pub created_time: Option<SystemTime>,
    pub is_executable: bool,
    pub is_symlink: bool,
    pub symlink_target: Option<PathBuf>,
    pub extended_attributes: HashMap<String, Vec<u8>>,
}

impl FileMetadata {
    pub fn new(path: PathBuf, size: u64, hash: Vec<u8>, algorithm: HashAlgorithm) -> Self {
        Self {
            path,
            size,
            hash,
            hash_algorithm: algorithm,
            permissions: 0o644,
            owner_uid: 0,
            owner_gid: 0,
            modified_time: SystemTime::now(),
            created_time: None,
            is_executable: false,
            is_symlink: false,
            symlink_target: None,
            extended_attributes: HashMap::new(),
        }
    }

    pub fn hash_hex(&self) -> String {
        self.hash.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn matches(&self, other: &FileMetadata) -> bool {
        self.hash == other.hash && self.size == other.size && self.permissions == other.permissions
    }
}

/// Type of change detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeType {
    Created,
    Modified,
    Deleted,
    Renamed,
    PermissionsChanged,
    OwnerChanged,
    AttributesChanged,
    ContentChanged,
}

impl ChangeType {
    pub fn severity(&self) -> ChangeSeverity {
        match self {
            Self::Created => ChangeSeverity::Low,
            Self::Modified | Self::ContentChanged => ChangeSeverity::Medium,
            Self::Deleted => ChangeSeverity::High,
            Self::Renamed => ChangeSeverity::Low,
            Self::PermissionsChanged => ChangeSeverity::Medium,
            Self::OwnerChanged => ChangeSeverity::High,
            Self::AttributesChanged => ChangeSeverity::Low,
        }
    }
}

impl fmt::Display for ChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created => write!(f, "CREATED"),
            Self::Modified => write!(f, "MODIFIED"),
            Self::Deleted => write!(f, "DELETED"),
            Self::Renamed => write!(f, "RENAMED"),
            Self::PermissionsChanged => write!(f, "PERMISSIONS"),
            Self::OwnerChanged => write!(f, "OWNER"),
            Self::AttributesChanged => write!(f, "ATTRIBUTES"),
            Self::ContentChanged => write!(f, "CONTENT"),
        }
    }
}

/// Change severity level
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChangeSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Detected file change
#[derive(Debug, Clone)]
pub struct FileChange {
    pub path: PathBuf,
    pub change_type: ChangeType,
    pub detected_at: SystemTime,
    pub old_metadata: Option<FileMetadata>,
    pub new_metadata: Option<FileMetadata>,
    pub description: String,
}

impl FileChange {
    pub fn new(
        path: PathBuf,
        change_type: ChangeType,
        old: Option<FileMetadata>,
        new: Option<FileMetadata>,
    ) -> Self {
        let description = match &change_type {
            ChangeType::Created => format!("New file created: {}", path.display()),
            ChangeType::Deleted => format!("File deleted: {}", path.display()),
            ChangeType::Modified => format!("File modified: {}", path.display()),
            ChangeType::ContentChanged => {
                if let (Some(o), Some(n)) = (&old, &new) {
                    format!(
                        "Content changed: {} (hash: {} -> {})",
                        path.display(),
                        &o.hash_hex()[..8],
                        &n.hash_hex()[..8]
                    )
                } else {
                    format!("Content changed: {}", path.display())
                }
            }
            ChangeType::PermissionsChanged => {
                if let (Some(o), Some(n)) = (&old, &new) {
                    format!(
                        "Permissions changed: {} ({:o} -> {:o})",
                        path.display(),
                        o.permissions,
                        n.permissions
                    )
                } else {
                    format!("Permissions changed: {}", path.display())
                }
            }
            ChangeType::OwnerChanged => {
                if let (Some(o), Some(n)) = (&old, &new) {
                    format!(
                        "Owner changed: {} ({}:{} -> {}:{})",
                        path.display(),
                        o.owner_uid,
                        o.owner_gid,
                        n.owner_uid,
                        n.owner_gid
                    )
                } else {
                    format!("Owner changed: {}", path.display())
                }
            }
            _ => format!("{}: {}", change_type, path.display()),
        };

        Self {
            path,
            change_type,
            detected_at: SystemTime::now(),
            old_metadata: old,
            new_metadata: new,
            description,
        }
    }

    pub fn severity(&self) -> ChangeSeverity {
        let base = self.change_type.severity();

        // Elevate severity for critical paths
        let path_str = self.path.to_string_lossy().to_lowercase();
        if path_str.contains("/etc/")
            || path_str.contains("/bin/")
            || path_str.contains("/sbin/")
            || path_str.contains("/.ssh/")
        {
            return ChangeSeverity::Critical;
        }

        // Elevate for executable changes
        if let Some(new) = &self.new_metadata {
            if new.is_executable {
                return std::cmp::max(base, ChangeSeverity::High);
            }
        }

        base
    }
}

/// Watch policy for directories
#[derive(Debug, Clone)]
pub struct WatchPolicy {
    pub path: PathBuf,
    pub recursive: bool,
    pub include_patterns: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub check_content: bool,
    pub check_permissions: bool,
    pub check_owner: bool,
    pub check_attributes: bool,
    pub alert_on_create: bool,
    pub alert_on_delete: bool,
    pub alert_on_modify: bool,
}

impl Default for WatchPolicy {
    fn default() -> Self {
        Self {
            path: PathBuf::new(),
            recursive: true,
            include_patterns: vec!["*".to_string()],
            exclude_patterns: Vec::new(),
            check_content: true,
            check_permissions: true,
            check_owner: true,
            check_attributes: false,
            alert_on_create: true,
            alert_on_delete: true,
            alert_on_modify: true,
        }
    }
}

impl WatchPolicy {
    pub fn for_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            ..Default::default()
        }
    }

    pub fn system_binaries() -> Self {
        Self {
            path: PathBuf::from("/usr/bin"),
            recursive: false,
            check_content: true,
            check_permissions: true,
            check_owner: true,
            exclude_patterns: vec!["*.log".to_string(), "*.tmp".to_string()],
            ..Default::default()
        }
    }

    pub fn config_files() -> Self {
        Self {
            path: PathBuf::from("/etc"),
            recursive: true,
            include_patterns: vec!["*.conf".to_string(), "*.cfg".to_string()],
            ..Default::default()
        }
    }

    pub fn matches(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        // Check excludes first
        for pattern in &self.exclude_patterns {
            if self.glob_match(pattern, &path_str) {
                return false;
            }
        }

        // Check includes
        if self.include_patterns.is_empty() {
            return true;
        }

        for pattern in &self.include_patterns {
            if self.glob_match(pattern, &path_str) {
                return true;
            }
        }

        false
    }

    fn glob_match(&self, pattern: &str, path: &str) -> bool {
        // Simple glob matching
        if pattern == "*" {
            return true;
        }

        if pattern.starts_with('*') {
            return path.ends_with(&pattern[1..]);
        }

        if pattern.ends_with('*') {
            return path.starts_with(&pattern[..pattern.len() - 1]);
        }

        path.contains(pattern)
    }
}

/// File integrity database
pub struct IntegrityDatabase {
    entries: HashMap<PathBuf, FileMetadata>,
    algorithm: HashAlgorithm,
    last_scan: Option<SystemTime>,
    scan_count: u64,
}

impl IntegrityDatabase {
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            entries: HashMap::new(),
            algorithm,
            last_scan: None,
            scan_count: 0,
        }
    }

    pub fn add_entry(&mut self, metadata: FileMetadata) {
        self.entries.insert(metadata.path.clone(), metadata);
    }

    pub fn get_entry(&self, path: &Path) -> Option<&FileMetadata> {
        self.entries.get(path)
    }

    pub fn remove_entry(&mut self, path: &Path) -> Option<FileMetadata> {
        self.entries.remove(path)
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn mark_scanned(&mut self) {
        self.last_scan = Some(SystemTime::now());
        self.scan_count += 1;
    }

    pub fn entries(&self) -> impl Iterator<Item = &FileMetadata> {
        self.entries.values()
    }

    /// Export database to JSON
    pub fn export(&self) -> String {
        let entries: Vec<String> = self
            .entries
            .values()
            .map(|e| {
                format!(
                    r#"    {{
      "path": "{}",
      "size": {},
      "hash": "{}",
      "permissions": "0{:o}",
      "uid": {},
      "gid": {},
      "executable": {}
    }}"#,
                    e.path.display(),
                    e.size,
                    e.hash_hex(),
                    e.permissions,
                    e.owner_uid,
                    e.owner_gid,
                    e.is_executable
                )
            })
            .collect();

        format!(
            r#"{{
  "algorithm": "{}",
  "entry_count": {},
  "scan_count": {},
  "entries": [
{}
  ]
}}"#,
            self.algorithm,
            self.entries.len(),
            self.scan_count,
            entries.join(",\n")
        )
    }
}

/// File integrity monitor
pub struct IntegrityMonitor {
    database: IntegrityDatabase,
    policies: Vec<WatchPolicy>,
    changes: Vec<FileChange>,
    config: MonitorConfig,
}

/// Monitor configuration
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    pub hash_algorithm: HashAlgorithm,
    pub scan_interval: Duration,
    pub batch_size: usize,
    pub alert_threshold: ChangeSeverity,
    pub quarantine_on_change: bool,
    pub backup_on_change: bool,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            hash_algorithm: HashAlgorithm::Blake3,
            scan_interval: Duration::from_secs(300),
            batch_size: 1000,
            alert_threshold: ChangeSeverity::Medium,
            quarantine_on_change: false,
            backup_on_change: true,
        }
    }
}

impl IntegrityMonitor {
    pub fn new(config: MonitorConfig) -> Self {
        Self {
            database: IntegrityDatabase::new(config.hash_algorithm.clone()),
            policies: Vec::new(),
            changes: Vec::new(),
            config,
        }
    }

    pub fn add_policy(&mut self, policy: WatchPolicy) {
        self.policies.push(policy);
    }

    /// Baseline scan - record current state
    pub fn baseline_scan(&mut self, files: &[FileMetadata]) {
        for file in files {
            self.database.add_entry(file.clone());
        }
        self.database.mark_scanned();
    }

    /// Verify files against baseline
    pub fn verify(&mut self, current_files: &[FileMetadata]) -> Vec<FileChange> {
        let mut changes = Vec::new();
        let mut seen_paths: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

        // Check current files against baseline
        for current in current_files {
            seen_paths.insert(current.path.clone());

            if let Some(baseline) = self.database.get_entry(&current.path) {
                // Check for changes
                if current.hash != baseline.hash {
                    changes.push(FileChange::new(
                        current.path.clone(),
                        ChangeType::ContentChanged,
                        Some(baseline.clone()),
                        Some(current.clone()),
                    ));
                } else if current.permissions != baseline.permissions {
                    changes.push(FileChange::new(
                        current.path.clone(),
                        ChangeType::PermissionsChanged,
                        Some(baseline.clone()),
                        Some(current.clone()),
                    ));
                } else if current.owner_uid != baseline.owner_uid
                    || current.owner_gid != baseline.owner_gid
                {
                    changes.push(FileChange::new(
                        current.path.clone(),
                        ChangeType::OwnerChanged,
                        Some(baseline.clone()),
                        Some(current.clone()),
                    ));
                }
            } else {
                // New file
                changes.push(FileChange::new(
                    current.path.clone(),
                    ChangeType::Created,
                    None,
                    Some(current.clone()),
                ));
            }
        }

        // Check for deleted files
        for (path, metadata) in &self.database.entries {
            if !seen_paths.contains(path) {
                changes.push(FileChange::new(
                    path.clone(),
                    ChangeType::Deleted,
                    Some(metadata.clone()),
                    None,
                ));
            }
        }

        // Store changes
        self.changes.extend(changes.clone());
        self.database.mark_scanned();

        changes
    }

    /// Get changes above threshold
    pub fn critical_changes(&self) -> Vec<&FileChange> {
        self.changes
            .iter()
            .filter(|c| c.severity() >= self.config.alert_threshold)
            .collect()
    }

    /// Generate verification report
    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str("=== File Integrity Report ===\n\n");

        report.push_str(&format!(
            "Database entries: {}\n",
            self.database.entry_count()
        ));
        report.push_str(&format!("Total changes detected: {}\n", self.changes.len()));
        report.push_str(&format!(
            "Critical changes: {}\n\n",
            self.critical_changes().len()
        ));

        // Group by severity
        let mut by_severity: HashMap<String, Vec<&FileChange>> = HashMap::new();
        for change in &self.changes {
            by_severity
                .entry(format!("{:?}", change.severity()))
                .or_default()
                .push(change);
        }

        for (severity, changes) in &by_severity {
            report.push_str(&format!("\n{} Severity ({}):\n", severity, changes.len()));
            for change in changes.iter().take(10) {
                report.push_str(&format!(
                    "  [{}] {}\n",
                    change.change_type, change.description
                ));
            }
            if changes.len() > 10 {
                report.push_str(&format!("  ... and {} more\n", changes.len() - 10));
            }
        }

        report
    }

    /// Clear recorded changes
    pub fn clear_changes(&mut self) {
        self.changes.clear();
    }

    /// Update baseline with current state
    pub fn update_baseline(&mut self, path: &Path, metadata: FileMetadata) {
        self.database.add_entry(metadata);
    }
}

/// Simulated hash function for demonstration
fn simulate_hash(data: &[u8], algorithm: &HashAlgorithm) -> Vec<u8> {
    let mut hash = vec![0u8; algorithm.hash_size()];

    for (i, &byte) in data.iter().enumerate() {
        hash[i % hash.len()] ^= byte.wrapping_mul((i as u8).wrapping_add(1));
    }

    hash
}

fn main() {
    println!("=== File Integrity Monitor Demo ===\n");

    // Create monitor
    let config = MonitorConfig {
        hash_algorithm: HashAlgorithm::Blake3,
        alert_threshold: ChangeSeverity::Low,
        ..Default::default()
    };
    let mut monitor = IntegrityMonitor::new(config);

    // Add watch policies
    monitor.add_policy(WatchPolicy::system_binaries());
    monitor.add_policy(WatchPolicy::config_files());

    // Create baseline files
    let baseline_files = vec![
        FileMetadata::new(
            PathBuf::from("/etc/passwd"),
            1024,
            simulate_hash(b"passwd_content", &HashAlgorithm::Blake3),
            HashAlgorithm::Blake3,
        ),
        FileMetadata::new(
            PathBuf::from("/etc/shadow"),
            512,
            simulate_hash(b"shadow_content", &HashAlgorithm::Blake3),
            HashAlgorithm::Blake3,
        ),
        FileMetadata::new(
            PathBuf::from("/usr/bin/ls"),
            50000,
            simulate_hash(b"ls_binary", &HashAlgorithm::Blake3),
            HashAlgorithm::Blake3,
        ),
        FileMetadata::new(
            PathBuf::from("/etc/ssh/sshd_config"),
            2048,
            simulate_hash(b"sshd_config", &HashAlgorithm::Blake3),
            HashAlgorithm::Blake3,
        ),
    ];

    println!("Creating baseline with {} files...\n", baseline_files.len());
    monitor.baseline_scan(&baseline_files);

    // Simulate current state with some changes
    let current_files = vec![
        // Unchanged
        FileMetadata::new(
            PathBuf::from("/etc/passwd"),
            1024,
            simulate_hash(b"passwd_content", &HashAlgorithm::Blake3),
            HashAlgorithm::Blake3,
        ),
        // Modified content
        FileMetadata::new(
            PathBuf::from("/etc/shadow"),
            520,
            simulate_hash(b"shadow_modified", &HashAlgorithm::Blake3),
            HashAlgorithm::Blake3,
        ),
        // Changed permissions
        {
            let mut meta = FileMetadata::new(
                PathBuf::from("/usr/bin/ls"),
                50000,
                simulate_hash(b"ls_binary", &HashAlgorithm::Blake3),
                HashAlgorithm::Blake3,
            );
            meta.permissions = 0o755;
            meta
        },
        // New file
        FileMetadata::new(
            PathBuf::from("/etc/malicious.conf"),
            100,
            simulate_hash(b"malicious", &HashAlgorithm::Blake3),
            HashAlgorithm::Blake3,
        ),
        // sshd_config deleted (not in current)
    ];

    println!("Verifying against baseline...\n");
    let changes = monitor.verify(&current_files);

    // Print detected changes
    println!("Detected {} changes:\n", changes.len());
    for change in &changes {
        println!(
            "[{:?}] {} - {}",
            change.severity(),
            change.change_type,
            change.description
        );
    }

    // Generate report
    println!("\n{}", monitor.generate_report());

    // Export database
    println!("\n--- Database Export (JSON) ---");
    println!("{}", monitor.database.export());

    // Demonstrate watch policy
    println!("\n--- Watch Policy Matching ---");
    let policy = WatchPolicy::config_files();
    let test_paths = [
        "/etc/nginx.conf",
        "/etc/ssh/config",
        "/var/log/syslog",
        "/tmp/test.tmp",
    ];

    for path in test_paths {
        let matches = policy.matches(Path::new(path));
        println!("  {} -> {}", path, if matches { "WATCH" } else { "IGNORE" });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithm_size() {
        assert_eq!(HashAlgorithm::SHA256.hash_size(), 32);
        assert_eq!(HashAlgorithm::SHA512.hash_size(), 64);
        assert_eq!(HashAlgorithm::Blake3.hash_size(), 32);
    }

    #[test]
    fn test_file_metadata() {
        let meta = FileMetadata::new(
            PathBuf::from("/test/file"),
            1024,
            vec![0xAB, 0xCD, 0xEF],
            HashAlgorithm::Blake3,
        );

        assert_eq!(meta.size, 1024);
        assert_eq!(meta.hash_hex(), "abcdef");
    }

    #[test]
    fn test_change_type_severity() {
        assert_eq!(ChangeType::Created.severity(), ChangeSeverity::Low);
        assert_eq!(ChangeType::Deleted.severity(), ChangeSeverity::High);
        assert_eq!(ChangeType::OwnerChanged.severity(), ChangeSeverity::High);
    }

    #[test]
    fn test_file_change_severity_elevation() {
        let change = FileChange::new(
            PathBuf::from("/etc/passwd"),
            ChangeType::Modified,
            None,
            None,
        );

        // Should be elevated due to /etc/ path
        assert_eq!(change.severity(), ChangeSeverity::Critical);
    }

    #[test]
    fn test_watch_policy_matching() {
        let policy = WatchPolicy {
            include_patterns: vec!["*.conf".to_string()],
            exclude_patterns: vec!["*.tmp".to_string()],
            ..Default::default()
        };

        assert!(policy.matches(Path::new("/etc/nginx.conf")));
        assert!(!policy.matches(Path::new("/tmp/test.tmp")));
    }

    #[test]
    fn test_integrity_database() {
        let mut db = IntegrityDatabase::new(HashAlgorithm::Blake3);

        let meta = FileMetadata::new(
            PathBuf::from("/test/file"),
            1024,
            vec![1, 2, 3],
            HashAlgorithm::Blake3,
        );

        db.add_entry(meta.clone());

        assert_eq!(db.entry_count(), 1);
        assert!(db.get_entry(Path::new("/test/file")).is_some());
    }

    #[test]
    fn test_integrity_monitor_baseline() {
        let config = MonitorConfig::default();
        let mut monitor = IntegrityMonitor::new(config);

        let files = vec![FileMetadata::new(
            PathBuf::from("/test"),
            100,
            vec![1, 2, 3],
            HashAlgorithm::Blake3,
        )];

        monitor.baseline_scan(&files);

        assert_eq!(monitor.database.entry_count(), 1);
    }

    #[test]
    fn test_detect_content_change() {
        let config = MonitorConfig::default();
        let mut monitor = IntegrityMonitor::new(config);

        // Baseline
        let baseline = vec![FileMetadata::new(
            PathBuf::from("/test"),
            100,
            vec![1, 2, 3],
            HashAlgorithm::Blake3,
        )];
        monitor.baseline_scan(&baseline);

        // Current with different hash
        let current = vec![FileMetadata::new(
            PathBuf::from("/test"),
            100,
            vec![4, 5, 6],
            HashAlgorithm::Blake3,
        )];

        let changes = monitor.verify(&current);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ChangeType::ContentChanged);
    }

    #[test]
    fn test_detect_new_file() {
        let config = MonitorConfig::default();
        let mut monitor = IntegrityMonitor::new(config);

        // Empty baseline
        monitor.baseline_scan(&[]);

        // Current with new file
        let current = vec![FileMetadata::new(
            PathBuf::from("/test"),
            100,
            vec![1, 2, 3],
            HashAlgorithm::Blake3,
        )];

        let changes = monitor.verify(&current);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ChangeType::Created);
    }

    #[test]
    fn test_detect_deleted_file() {
        let config = MonitorConfig::default();
        let mut monitor = IntegrityMonitor::new(config);

        // Baseline with file
        let baseline = vec![FileMetadata::new(
            PathBuf::from("/test"),
            100,
            vec![1, 2, 3],
            HashAlgorithm::Blake3,
        )];
        monitor.baseline_scan(&baseline);

        // Current without file
        let changes = monitor.verify(&[]);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ChangeType::Deleted);
    }

    #[test]
    fn test_detect_permission_change() {
        let config = MonitorConfig::default();
        let mut monitor = IntegrityMonitor::new(config);

        let mut baseline_file = FileMetadata::new(
            PathBuf::from("/test"),
            100,
            vec![1, 2, 3],
            HashAlgorithm::Blake3,
        );
        baseline_file.permissions = 0o644;
        monitor.baseline_scan(&[baseline_file]);

        let mut current_file = FileMetadata::new(
            PathBuf::from("/test"),
            100,
            vec![1, 2, 3],
            HashAlgorithm::Blake3,
        );
        current_file.permissions = 0o777;

        let changes = monitor.verify(&[current_file]);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ChangeType::PermissionsChanged);
    }

    #[test]
    fn test_critical_changes_filter() {
        let config = MonitorConfig {
            alert_threshold: ChangeSeverity::High,
            ..Default::default()
        };
        let mut monitor = IntegrityMonitor::new(config);

        // Add low severity change
        monitor.changes.push(FileChange::new(
            PathBuf::from("/tmp/test"),
            ChangeType::Created,
            None,
            None,
        ));

        // Add high severity change
        monitor.changes.push(FileChange::new(
            PathBuf::from("/etc/passwd"),
            ChangeType::Modified,
            None,
            None,
        ));

        let critical = monitor.critical_changes();
        assert_eq!(critical.len(), 1);
    }

    #[test]
    fn test_database_export() {
        let mut db = IntegrityDatabase::new(HashAlgorithm::Blake3);

        db.add_entry(FileMetadata::new(
            PathBuf::from("/test"),
            100,
            vec![0xAB],
            HashAlgorithm::Blake3,
        ));

        let json = db.export();

        assert!(json.contains("\"path\": \"/test\""));
        assert!(json.contains("\"size\": 100"));
    }
}
