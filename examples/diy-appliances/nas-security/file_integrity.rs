//! NAS File Integrity Monitor
//!
//! Implements AIDE-like file integrity monitoring with baseline management,
//! change detection, and audit logging for NAS security.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// File integrity monitor configuration
#[derive(Debug, Clone)]
pub struct IntegrityConfig {
    /// Directories to monitor
    pub watch_paths: Vec<PathBuf>,
    /// Excluded patterns (glob-like)
    pub exclude_patterns: Vec<String>,
    /// Check file permissions
    pub check_permissions: bool,
    /// Check file ownership
    pub check_ownership: bool,
    /// Check file size
    pub check_size: bool,
    /// Check modification time
    pub check_mtime: bool,
    /// Check content hash
    pub check_hash: bool,
    /// Database path
    pub database_path: PathBuf,
    /// Alert on new files
    pub alert_new_files: bool,
    /// Alert on deleted files
    pub alert_deleted_files: bool,
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            watch_paths: vec![],
            exclude_patterns: vec![
                "*.log".to_string(),
                "*.tmp".to_string(),
                "*.cache".to_string(),
                "*/.git/*".to_string(),
            ],
            check_permissions: true,
            check_ownership: true,
            check_size: true,
            check_mtime: true,
            check_hash: true,
            database_path: PathBuf::from("/var/lib/integrity/database.json"),
            alert_new_files: true,
            alert_deleted_files: true,
        }
    }
}

/// File metadata for integrity checking
#[derive(Debug, Clone, PartialEq)]
pub struct FileMetadata {
    /// File path
    pub path: PathBuf,
    /// File type
    pub file_type: FileType,
    /// File size in bytes
    pub size: u64,
    /// SHA-256 hash of content
    pub hash: String,
    /// Permissions (Unix mode)
    pub permissions: u32,
    /// Owner user ID
    pub uid: u32,
    /// Owner group ID
    pub gid: u32,
    /// Modification time
    pub mtime: SystemTime,
    /// Creation time (if available)
    pub ctime: Option<SystemTime>,
    /// Last scan time
    pub scan_time: SystemTime,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    Other,
}

/// Change detected during scan
#[derive(Debug, Clone)]
pub struct Change {
    /// File path
    pub path: PathBuf,
    /// Change type
    pub change_type: ChangeType,
    /// Old value (if applicable)
    pub old_value: Option<String>,
    /// New value (if applicable)
    pub new_value: Option<String>,
    /// Severity
    pub severity: ChangeSeverity,
    /// Detection time
    pub detected_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChangeType {
    NewFile,
    DeletedFile,
    ContentModified,
    PermissionsChanged,
    OwnershipChanged,
    SizeChanged,
    MtimeChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChangeSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Scan result
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Scan start time
    pub start_time: SystemTime,
    /// Scan end time
    pub end_time: SystemTime,
    /// Files scanned
    pub files_scanned: u64,
    /// Directories scanned
    pub directories_scanned: u64,
    /// Bytes processed
    pub bytes_processed: u64,
    /// Changes detected
    pub changes: Vec<Change>,
    /// Errors encountered
    pub errors: Vec<ScanError>,
}

#[derive(Debug, Clone)]
pub struct ScanError {
    pub path: PathBuf,
    pub message: String,
}

/// File integrity monitor
pub struct IntegrityMonitor {
    config: IntegrityConfig,
    /// Baseline database
    baseline: HashMap<PathBuf, FileMetadata>,
    /// Statistics
    stats: IntegrityStats,
    /// Last scan result
    last_scan: Option<ScanResult>,
}

#[derive(Debug, Default, Clone)]
pub struct IntegrityStats {
    pub total_scans: u64,
    pub total_files_checked: u64,
    pub total_changes_detected: u64,
    pub baseline_files: u64,
    pub last_scan_time: Option<SystemTime>,
}

impl IntegrityMonitor {
    /// Create new integrity monitor
    pub fn new(config: IntegrityConfig) -> Self {
        Self {
            config,
            baseline: HashMap::new(),
            stats: IntegrityStats::default(),
            last_scan: None,
        }
    }

    /// Initialize baseline from current filesystem state
    pub fn init_baseline(&mut self) -> io::Result<u64> {
        self.baseline.clear();

        let mut count = 0u64;

        for path in &self.config.watch_paths.clone() {
            count += self.scan_directory_for_baseline(path)?;
        }

        self.stats.baseline_files = count;

        Ok(count)
    }

    fn scan_directory_for_baseline(&mut self, path: &Path) -> io::Result<u64> {
        let mut count = 0u64;

        if !path.exists() {
            return Ok(0);
        }

        if path.is_file() {
            if !self.is_excluded(path) {
                if let Ok(metadata) = self.get_file_metadata(path) {
                    self.baseline.insert(path.to_path_buf(), metadata);
                    count += 1;
                }
            }
            return Ok(count);
        }

        let entries = match fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => return Ok(0),
        };

        for entry in entries.flatten() {
            let entry_path = entry.path();

            if self.is_excluded(&entry_path) {
                continue;
            }

            if entry_path.is_dir() {
                count += self.scan_directory_for_baseline(&entry_path)?;
            } else if entry_path.is_file() {
                if let Ok(metadata) = self.get_file_metadata(&entry_path) {
                    self.baseline.insert(entry_path, metadata);
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    fn is_excluded(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        for pattern in &self.config.exclude_patterns {
            if self.glob_match(pattern, &path_str) {
                return true;
            }
        }

        false
    }

    fn glob_match(&self, pattern: &str, path: &str) -> bool {
        // Simple glob matching (supports * and ?)
        let mut pattern_chars = pattern.chars().peekable();
        let mut path_chars = path.chars().peekable();

        while let Some(pc) = pattern_chars.next() {
            match pc {
                '*' => {
                    // Match any sequence
                    if pattern_chars.peek().is_none() {
                        return true;
                    }

                    // Try matching rest of pattern at each position
                    while path_chars.peek().is_some() {
                        let remaining_path: String = path_chars.clone().collect();
                        let remaining_pattern: String = pattern_chars.clone().collect();
                        if self.glob_match(&remaining_pattern, &remaining_path) {
                            return true;
                        }
                        path_chars.next();
                    }
                    return false;
                }
                '?' => {
                    // Match any single character
                    if path_chars.next().is_none() {
                        return false;
                    }
                }
                c => {
                    if path_chars.next() != Some(c) {
                        return false;
                    }
                }
            }
        }

        path_chars.peek().is_none()
    }

    fn get_file_metadata(&self, path: &Path) -> io::Result<FileMetadata> {
        let metadata = fs::metadata(path)?;

        let file_type = if metadata.is_file() {
            FileType::Regular
        } else if metadata.is_dir() {
            FileType::Directory
        } else if metadata.file_type().is_symlink() {
            FileType::Symlink
        } else {
            FileType::Other
        };

        let hash = if self.config.check_hash && metadata.is_file() {
            self.calculate_hash(path)?
        } else {
            String::new()
        };

        // Get Unix metadata (simplified for cross-platform)
        #[cfg(unix)]
        let (permissions, uid, gid) = {
            use std::os::unix::fs::MetadataExt;
            (metadata.mode(), metadata.uid(), metadata.gid())
        };

        #[cfg(not(unix))]
        let (permissions, uid, gid) = (0o644, 0, 0);

        Ok(FileMetadata {
            path: path.to_path_buf(),
            file_type,
            size: metadata.len(),
            hash,
            permissions,
            uid,
            gid,
            mtime: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            ctime: metadata.created().ok(),
            scan_time: SystemTime::now(),
        })
    }

    fn calculate_hash(&self, path: &Path) -> io::Result<String> {
        let mut file = fs::File::open(path)?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;

        // Simplified hash (in production use sha2 crate)
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        let h1 = hasher.finish();

        content.iter().rev().for_each(|b| b.hash(&mut hasher));
        let h2 = hasher.finish();

        Ok(format!(
            "{:016x}{:016x}{:016x}{:016x}",
            h1,
            h2,
            h1 ^ h2,
            h1.wrapping_add(h2)
        ))
    }

    /// Perform integrity scan
    pub fn scan(&mut self) -> ScanResult {
        let start_time = SystemTime::now();
        let mut changes = Vec::new();
        let mut errors = Vec::new();
        let mut files_scanned = 0u64;
        let mut directories_scanned = 0u64;
        let mut bytes_processed = 0u64;

        // Track which baseline files were found
        let mut found_files: HashMap<PathBuf, FileMetadata> = HashMap::new();

        // Scan all watch paths
        for path in &self.config.watch_paths.clone() {
            self.scan_directory(
                path,
                &mut found_files,
                &mut changes,
                &mut errors,
                &mut files_scanned,
                &mut directories_scanned,
                &mut bytes_processed,
            );
        }

        // Check for deleted files
        if self.config.alert_deleted_files {
            for (path, metadata) in &self.baseline {
                if !found_files.contains_key(path) {
                    changes.push(Change {
                        path: path.clone(),
                        change_type: ChangeType::DeletedFile,
                        old_value: Some(format!("hash: {}", metadata.hash)),
                        new_value: None,
                        severity: ChangeSeverity::High,
                        detected_at: SystemTime::now(),
                    });
                }
            }
        }

        let end_time = SystemTime::now();

        // Update statistics
        self.stats.total_scans += 1;
        self.stats.total_files_checked += files_scanned;
        self.stats.total_changes_detected += changes.len() as u64;
        self.stats.last_scan_time = Some(end_time);

        let result = ScanResult {
            start_time,
            end_time,
            files_scanned,
            directories_scanned,
            bytes_processed,
            changes,
            errors,
        };

        self.last_scan = Some(result.clone());

        result
    }

    fn scan_directory(
        &self,
        path: &Path,
        found_files: &mut HashMap<PathBuf, FileMetadata>,
        changes: &mut Vec<Change>,
        errors: &mut Vec<ScanError>,
        files_scanned: &mut u64,
        directories_scanned: &mut u64,
        bytes_processed: &mut u64,
    ) {
        if !path.exists() {
            return;
        }

        if self.is_excluded(path) {
            return;
        }

        if path.is_file() {
            self.check_file(
                path,
                found_files,
                changes,
                errors,
                files_scanned,
                bytes_processed,
            );
            return;
        }

        *directories_scanned += 1;

        let entries = match fs::read_dir(path) {
            Ok(e) => e,
            Err(e) => {
                errors.push(ScanError {
                    path: path.to_path_buf(),
                    message: e.to_string(),
                });
                return;
            }
        };

        for entry in entries.flatten() {
            let entry_path = entry.path();

            if self.is_excluded(&entry_path) {
                continue;
            }

            if entry_path.is_dir() {
                self.scan_directory(
                    &entry_path,
                    found_files,
                    changes,
                    errors,
                    files_scanned,
                    directories_scanned,
                    bytes_processed,
                );
            } else if entry_path.is_file() {
                self.check_file(
                    &entry_path,
                    found_files,
                    changes,
                    errors,
                    files_scanned,
                    bytes_processed,
                );
            }
        }
    }

    fn check_file(
        &self,
        path: &Path,
        found_files: &mut HashMap<PathBuf, FileMetadata>,
        changes: &mut Vec<Change>,
        errors: &mut Vec<ScanError>,
        files_scanned: &mut u64,
        bytes_processed: &mut u64,
    ) {
        *files_scanned += 1;

        let current = match self.get_file_metadata(path) {
            Ok(m) => m,
            Err(e) => {
                errors.push(ScanError {
                    path: path.to_path_buf(),
                    message: e.to_string(),
                });
                return;
            }
        };

        *bytes_processed += current.size;

        if let Some(baseline) = self.baseline.get(path) {
            // Compare with baseline
            if self.config.check_hash && current.hash != baseline.hash {
                changes.push(Change {
                    path: path.to_path_buf(),
                    change_type: ChangeType::ContentModified,
                    old_value: Some(baseline.hash.clone()),
                    new_value: Some(current.hash.clone()),
                    severity: ChangeSeverity::Critical,
                    detected_at: SystemTime::now(),
                });
            }

            if self.config.check_size && current.size != baseline.size {
                changes.push(Change {
                    path: path.to_path_buf(),
                    change_type: ChangeType::SizeChanged,
                    old_value: Some(baseline.size.to_string()),
                    new_value: Some(current.size.to_string()),
                    severity: ChangeSeverity::Medium,
                    detected_at: SystemTime::now(),
                });
            }

            if self.config.check_permissions && current.permissions != baseline.permissions {
                changes.push(Change {
                    path: path.to_path_buf(),
                    change_type: ChangeType::PermissionsChanged,
                    old_value: Some(format!("{:o}", baseline.permissions)),
                    new_value: Some(format!("{:o}", current.permissions)),
                    severity: ChangeSeverity::High,
                    detected_at: SystemTime::now(),
                });
            }

            if self.config.check_ownership
                && (current.uid != baseline.uid || current.gid != baseline.gid)
            {
                changes.push(Change {
                    path: path.to_path_buf(),
                    change_type: ChangeType::OwnershipChanged,
                    old_value: Some(format!("{}:{}", baseline.uid, baseline.gid)),
                    new_value: Some(format!("{}:{}", current.uid, current.gid)),
                    severity: ChangeSeverity::High,
                    detected_at: SystemTime::now(),
                });
            }

            if self.config.check_mtime && current.mtime != baseline.mtime {
                changes.push(Change {
                    path: path.to_path_buf(),
                    change_type: ChangeType::MtimeChanged,
                    old_value: Some(format!("{:?}", baseline.mtime)),
                    new_value: Some(format!("{:?}", current.mtime)),
                    severity: ChangeSeverity::Low,
                    detected_at: SystemTime::now(),
                });
            }
        } else if self.config.alert_new_files {
            // New file not in baseline
            changes.push(Change {
                path: path.to_path_buf(),
                change_type: ChangeType::NewFile,
                old_value: None,
                new_value: Some(format!("size: {}, hash: {}", current.size, current.hash)),
                severity: ChangeSeverity::Medium,
                detected_at: SystemTime::now(),
            });
        }

        found_files.insert(path.to_path_buf(), current);
    }

    /// Update baseline with current state
    pub fn update_baseline(&mut self) -> io::Result<u64> {
        self.init_baseline()
    }

    /// Update single file in baseline
    pub fn update_file(&mut self, path: &Path) -> io::Result<()> {
        let metadata = self.get_file_metadata(path)?;
        self.baseline.insert(path.to_path_buf(), metadata);
        Ok(())
    }

    /// Remove file from baseline
    pub fn remove_from_baseline(&mut self, path: &Path) {
        self.baseline.remove(path);
    }

    /// Get baseline entry for path
    pub fn get_baseline(&self, path: &Path) -> Option<&FileMetadata> {
        self.baseline.get(path)
    }

    /// Get all baseline entries
    pub fn get_all_baseline(&self) -> &HashMap<PathBuf, FileMetadata> {
        &self.baseline
    }

    /// Get statistics
    pub fn get_stats(&self) -> &IntegrityStats {
        &self.stats
    }

    /// Get last scan result
    pub fn get_last_scan(&self) -> Option<&ScanResult> {
        self.last_scan.as_ref()
    }

    /// Save baseline to file
    pub fn save_baseline(&self) -> io::Result<()> {
        // Create parent directory if needed
        if let Some(parent) = self.config.database_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Serialize baseline (simplified JSON)
        let mut json = String::from("{\n  \"files\": [\n");

        for (i, (path, metadata)) in self.baseline.iter().enumerate() {
            if i > 0 {
                json.push_str(",\n");
            }
            json.push_str(&format!(
                "    {{\n      \"path\": \"{}\",\n      \"size\": {},\n      \"hash\": \"{}\",\n      \"permissions\": {}\n    }}",
                path.display().to_string().replace('\\', "\\\\").replace('"', "\\\""),
                metadata.size,
                metadata.hash,
                metadata.permissions
            ));
        }

        json.push_str("\n  ]\n}");

        fs::write(&self.config.database_path, json)?;

        Ok(())
    }

    /// Generate integrity report
    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str("=== File Integrity Monitor Report ===\n\n");

        // Statistics
        report.push_str("Statistics:\n");
        report.push_str(&format!("  Total scans: {}\n", self.stats.total_scans));
        report.push_str(&format!(
            "  Files in baseline: {}\n",
            self.stats.baseline_files
        ));
        report.push_str(&format!(
            "  Total files checked: {}\n",
            self.stats.total_files_checked
        ));
        report.push_str(&format!(
            "  Total changes detected: {}\n",
            self.stats.total_changes_detected
        ));

        if let Some(last_time) = self.stats.last_scan_time {
            report.push_str(&format!("  Last scan: {:?}\n", last_time));
        }

        // Last scan results
        if let Some(ref scan) = self.last_scan {
            report.push_str(&format!("\nLast Scan Results:\n"));
            report.push_str(&format!("  Files scanned: {}\n", scan.files_scanned));
            report.push_str(&format!(
                "  Directories scanned: {}\n",
                scan.directories_scanned
            ));
            report.push_str(&format!("  Bytes processed: {}\n", scan.bytes_processed));
            report.push_str(&format!("  Changes detected: {}\n", scan.changes.len()));
            report.push_str(&format!("  Errors: {}\n", scan.errors.len()));

            if !scan.changes.is_empty() {
                report.push_str("\n  Changes:\n");
                for change in &scan.changes {
                    report.push_str(&format!(
                        "    [{:?}] {:?}: {}\n",
                        change.severity,
                        change.change_type,
                        change.path.display()
                    ));
                }
            }

            if !scan.errors.is_empty() {
                report.push_str("\n  Errors:\n");
                for error in &scan.errors {
                    report.push_str(&format!(
                        "    {}: {}\n",
                        error.path.display(),
                        error.message
                    ));
                }
            }
        }

        report
    }
}

fn main() {
    println!("=== File Integrity Monitor Demo ===\n");

    // Create configuration
    let config = IntegrityConfig {
        watch_paths: vec![PathBuf::from("/tmp/integrity_test")],
        exclude_patterns: vec!["*.tmp".to_string(), "*.log".to_string()],
        check_hash: true,
        check_permissions: true,
        check_ownership: true,
        check_size: true,
        check_mtime: true,
        alert_new_files: true,
        alert_deleted_files: true,
        database_path: PathBuf::from("/tmp/integrity_test/baseline.json"),
    };

    // Create monitor
    let mut monitor = IntegrityMonitor::new(config);

    // Create test directory and files
    fs::create_dir_all("/tmp/integrity_test").ok();
    fs::write("/tmp/integrity_test/file1.txt", "Original content").ok();
    fs::write("/tmp/integrity_test/file2.txt", "Another file").ok();
    fs::create_dir_all("/tmp/integrity_test/subdir").ok();
    fs::write("/tmp/integrity_test/subdir/nested.txt", "Nested file").ok();

    // Initialize baseline
    println!("Initializing baseline...");
    match monitor.init_baseline() {
        Ok(count) => println!("Baseline initialized with {} files\n", count),
        Err(e) => {
            println!("Failed to initialize baseline: {}", e);
            return;
        }
    }

    // First scan (should show no changes)
    println!("First scan (no changes expected):");
    let result = monitor.scan();
    println!("  Files scanned: {}", result.files_scanned);
    println!("  Changes detected: {}", result.changes.len());

    // Modify a file
    println!("\nModifying file1.txt...");
    fs::write("/tmp/integrity_test/file1.txt", "Modified content!").ok();

    // Add a new file
    println!("Adding new file...");
    fs::write("/tmp/integrity_test/new_file.txt", "This is new").ok();

    // Delete a file
    println!("Deleting file2.txt...");
    fs::remove_file("/tmp/integrity_test/file2.txt").ok();

    // Second scan (should detect changes)
    println!("\nSecond scan (changes expected):");
    let result = monitor.scan();
    println!("  Files scanned: {}", result.files_scanned);
    println!("  Changes detected: {}", result.changes.len());

    for change in &result.changes {
        println!(
            "  [{:?}] {:?}: {}",
            change.severity,
            change.change_type,
            change.path.display()
        );
        if let Some(ref old) = change.old_value {
            println!("    Old: {}", if old.len() > 50 { &old[..50] } else { old });
        }
        if let Some(ref new) = change.new_value {
            println!("    New: {}", if new.len() > 50 { &new[..50] } else { new });
        }
    }

    // Generate report
    println!("\n{}", monitor.generate_report());

    // Cleanup
    let _ = fs::remove_dir_all("/tmp/integrity_test");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_test_dir() -> PathBuf {
        let path = PathBuf::from("/tmp/integrity_test_unit");
        fs::create_dir_all(&path).ok();
        path
    }

    fn cleanup_test_dir() {
        let _ = fs::remove_dir_all("/tmp/integrity_test_unit");
    }

    #[test]
    fn test_baseline_initialization() {
        let test_dir = setup_test_dir();
        fs::write(test_dir.join("test.txt"), "test content").unwrap();

        let config = IntegrityConfig {
            watch_paths: vec![test_dir.clone()],
            ..Default::default()
        };

        let mut monitor = IntegrityMonitor::new(config);
        let count = monitor.init_baseline().unwrap();

        assert!(count >= 1);
        assert!(monitor.baseline.contains_key(&test_dir.join("test.txt")));

        cleanup_test_dir();
    }

    #[test]
    fn test_content_change_detection() {
        let test_dir = setup_test_dir();
        let test_file = test_dir.join("detect.txt");
        fs::write(&test_file, "original").unwrap();

        let config = IntegrityConfig {
            watch_paths: vec![test_dir.clone()],
            check_hash: true,
            ..Default::default()
        };

        let mut monitor = IntegrityMonitor::new(config);
        monitor.init_baseline().unwrap();

        // Modify file
        fs::write(&test_file, "modified content").unwrap();

        let result = monitor.scan();

        assert!(result
            .changes
            .iter()
            .any(|c| c.path == test_file && c.change_type == ChangeType::ContentModified));

        cleanup_test_dir();
    }

    #[test]
    fn test_new_file_detection() {
        let test_dir = setup_test_dir();

        let config = IntegrityConfig {
            watch_paths: vec![test_dir.clone()],
            alert_new_files: true,
            ..Default::default()
        };

        let mut monitor = IntegrityMonitor::new(config);
        monitor.init_baseline().unwrap();

        // Add new file
        let new_file = test_dir.join("new.txt");
        fs::write(&new_file, "new content").unwrap();

        let result = monitor.scan();

        assert!(result
            .changes
            .iter()
            .any(|c| c.path == new_file && c.change_type == ChangeType::NewFile));

        cleanup_test_dir();
    }

    #[test]
    fn test_deleted_file_detection() {
        let test_dir = setup_test_dir();
        let test_file = test_dir.join("to_delete.txt");
        fs::write(&test_file, "will be deleted").unwrap();

        let config = IntegrityConfig {
            watch_paths: vec![test_dir.clone()],
            alert_deleted_files: true,
            ..Default::default()
        };

        let mut monitor = IntegrityMonitor::new(config);
        monitor.init_baseline().unwrap();

        // Delete file
        fs::remove_file(&test_file).unwrap();

        let result = monitor.scan();

        assert!(result
            .changes
            .iter()
            .any(|c| c.path == test_file && c.change_type == ChangeType::DeletedFile));

        cleanup_test_dir();
    }

    #[test]
    fn test_glob_matching() {
        let monitor = IntegrityMonitor::new(IntegrityConfig::default());

        assert!(monitor.glob_match("*.log", "test.log"));
        assert!(monitor.glob_match("*.log", "error.log"));
        assert!(!monitor.glob_match("*.log", "test.txt"));
        assert!(monitor.glob_match("test?", "test1"));
        assert!(!monitor.glob_match("test?", "test12"));
        assert!(monitor.glob_match("*/.git/*", "/repo/.git/config"));
    }

    #[test]
    fn test_exclusion() {
        let config = IntegrityConfig {
            exclude_patterns: vec!["*.tmp".to_string(), "*.log".to_string()],
            ..Default::default()
        };

        let monitor = IntegrityMonitor::new(config);

        assert!(monitor.is_excluded(Path::new("/tmp/test.tmp")));
        assert!(monitor.is_excluded(Path::new("/var/log/app.log")));
        assert!(!monitor.is_excluded(Path::new("/data/storage/file.txt")));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(ChangeSeverity::Critical > ChangeSeverity::High);
        assert!(ChangeSeverity::High > ChangeSeverity::Medium);
        assert!(ChangeSeverity::Medium > ChangeSeverity::Low);
        assert!(ChangeSeverity::Low > ChangeSeverity::Info);
    }
}
