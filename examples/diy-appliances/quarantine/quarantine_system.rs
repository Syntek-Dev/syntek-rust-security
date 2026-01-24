//! File Quarantine System
//!
//! Implements a secure file quarantine system for isolating suspicious files,
//! with admin notification, restoration workflows, and audit logging.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Quarantine system configuration
#[derive(Debug, Clone)]
pub struct QuarantineConfig {
    /// Quarantine storage directory
    pub quarantine_dir: PathBuf,
    /// Metadata storage directory
    pub metadata_dir: PathBuf,
    /// Maximum storage size (bytes)
    pub max_storage_size: u64,
    /// Default retention period
    pub default_retention: Duration,
    /// Enable encryption for quarantined files
    pub encrypt_files: bool,
    /// Encryption key (32 bytes for AES-256)
    pub encryption_key: Option<[u8; 32]>,
    /// Enable tamper-evident logging
    pub tamper_evident_logging: bool,
    /// Notification webhook URL
    pub notification_webhook: Option<String>,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            quarantine_dir: PathBuf::from("/var/quarantine/files"),
            metadata_dir: PathBuf::from("/var/quarantine/metadata"),
            max_storage_size: 10 * 1024 * 1024 * 1024, // 10GB
            default_retention: Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            encrypt_files: true,
            encryption_key: None,
            tamper_evident_logging: true,
            notification_webhook: None,
        }
    }
}

/// Quarantine entry metadata
#[derive(Debug, Clone)]
pub struct QuarantineEntry {
    /// Unique quarantine ID
    pub id: String,
    /// Original file path
    pub original_path: PathBuf,
    /// Original filename
    pub original_name: String,
    /// File hash (SHA256)
    pub file_hash: String,
    /// File size
    pub file_size: u64,
    /// Quarantine timestamp
    pub quarantined_at: SystemTime,
    /// Expiration timestamp
    pub expires_at: SystemTime,
    /// Quarantine reason
    pub reason: QuarantineReason,
    /// Detection details
    pub detection_info: DetectionInfo,
    /// Current status
    pub status: QuarantineStatus,
    /// User who quarantined (if manual)
    pub quarantined_by: Option<String>,
    /// Admin notes
    pub notes: Vec<QuarantineNote>,
    /// Restoration attempts
    pub restoration_attempts: Vec<RestorationAttempt>,
}

#[derive(Debug, Clone)]
pub enum QuarantineReason {
    MalwareDetected,
    SuspiciousActivity,
    PolicyViolation,
    UserRequested,
    RansomwareProtection,
    IntegrityViolation,
    ManualQuarantine,
}

#[derive(Debug, Clone)]
pub struct DetectionInfo {
    /// Detection source (scanner name)
    pub source: String,
    /// Threat name
    pub threat_name: Option<String>,
    /// Threat severity
    pub severity: ThreatSeverity,
    /// Detection confidence (0-100)
    pub confidence: u8,
    /// Additional details
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq)]
pub enum QuarantineStatus {
    Active,
    PendingReview,
    Approved,
    Restored,
    Deleted,
    Expired,
}

#[derive(Debug, Clone)]
pub struct QuarantineNote {
    pub timestamp: SystemTime,
    pub author: String,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct RestorationAttempt {
    pub timestamp: SystemTime,
    pub requested_by: String,
    pub approved_by: Option<String>,
    pub status: RestorationStatus,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RestorationStatus {
    Pending,
    Approved,
    Denied,
    Completed,
    Failed,
}

/// Quarantine manager
pub struct QuarantineManager {
    config: QuarantineConfig,
    /// In-memory entry index
    entries: HashMap<String, QuarantineEntry>,
    /// Statistics
    stats: QuarantineStats,
    /// Audit log
    audit_log: Vec<AuditLogEntry>,
}

#[derive(Debug, Default, Clone)]
pub struct QuarantineStats {
    pub total_quarantined: u64,
    pub total_restored: u64,
    pub total_deleted: u64,
    pub current_file_count: u64,
    pub current_storage_used: u64,
    pub malware_detected: u64,
    pub false_positives: u64,
}

#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub timestamp: SystemTime,
    pub action: AuditAction,
    pub entry_id: Option<String>,
    pub user: Option<String>,
    pub details: String,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuditAction {
    FileQuarantined,
    FileRestored,
    FileDeleted,
    StatusChanged,
    NoteAdded,
    RestorationRequested,
    RestorationApproved,
    RestorationDenied,
    ConfigChanged,
}

impl QuarantineManager {
    /// Create new quarantine manager
    pub fn new(config: QuarantineConfig) -> io::Result<Self> {
        // Create directories if they don't exist
        fs::create_dir_all(&config.quarantine_dir)?;
        fs::create_dir_all(&config.metadata_dir)?;

        let mut manager = Self {
            config,
            entries: HashMap::new(),
            stats: QuarantineStats::default(),
            audit_log: Vec::new(),
        };

        // Load existing entries
        manager.load_entries()?;

        Ok(manager)
    }

    fn load_entries(&mut self) -> io::Result<()> {
        // Load metadata files
        if let Ok(entries) = fs::read_dir(&self.config.metadata_dir) {
            for entry in entries.flatten() {
                if entry.path().extension().map_or(false, |e| e == "json") {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        if let Ok(qe) = self.parse_entry_metadata(&content) {
                            self.entries.insert(qe.id.clone(), qe);
                            self.stats.current_file_count += 1;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn parse_entry_metadata(&self, _content: &str) -> Result<QuarantineEntry, String> {
        // Simplified - in production use serde_json
        Err("Not implemented".to_string())
    }

    /// Quarantine a file
    pub fn quarantine_file(
        &mut self,
        path: &Path,
        reason: QuarantineReason,
        detection: DetectionInfo,
        user: Option<String>,
    ) -> Result<String, QuarantineError> {
        // Check if file exists
        if !path.exists() {
            return Err(QuarantineError::FileNotFound(path.to_path_buf()));
        }

        // Read file metadata and content
        let metadata = fs::metadata(path).map_err(|e| QuarantineError::IoError(e.to_string()))?;

        let file_size = metadata.len();

        // Check storage limits
        if self.stats.current_storage_used + file_size > self.config.max_storage_size {
            return Err(QuarantineError::StorageFull);
        }

        // Read file content
        let content = fs::read(path).map_err(|e| QuarantineError::IoError(e.to_string()))?;

        // Calculate file hash
        let file_hash = self.calculate_hash(&content);

        // Generate quarantine ID
        let id = self.generate_id();

        // Encrypt content if enabled
        let stored_content = if self.config.encrypt_files {
            self.encrypt_content(&content)?
        } else {
            content
        };

        // Save quarantined file
        let quarantine_path = self.config.quarantine_dir.join(&id);
        fs::write(&quarantine_path, &stored_content)
            .map_err(|e| QuarantineError::IoError(e.to_string()))?;

        // Create entry
        let now = SystemTime::now();
        let entry = QuarantineEntry {
            id: id.clone(),
            original_path: path.to_path_buf(),
            original_name: path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string(),
            file_hash,
            file_size,
            quarantined_at: now,
            expires_at: now + self.config.default_retention,
            reason,
            detection_info: detection,
            status: QuarantineStatus::Active,
            quarantined_by: user.clone(),
            notes: Vec::new(),
            restoration_attempts: Vec::new(),
        };

        // Save metadata
        self.save_entry_metadata(&entry)?;

        // Remove original file
        fs::remove_file(path)
            .map_err(|e| QuarantineError::IoError(format!("Failed to remove original: {}", e)))?;

        // Update statistics
        self.stats.total_quarantined += 1;
        self.stats.current_file_count += 1;
        self.stats.current_storage_used += file_size;

        if matches!(entry.reason, QuarantineReason::MalwareDetected) {
            self.stats.malware_detected += 1;
        }

        // Log audit entry
        self.log_audit(
            AuditAction::FileQuarantined,
            Some(&id),
            user.as_deref(),
            &format!(
                "Quarantined: {} (reason: {:?})",
                entry.original_name, entry.reason
            ),
        );

        // Store entry
        self.entries.insert(id.clone(), entry);

        // Send notification if configured
        if self.config.notification_webhook.is_some() {
            self.send_notification(&id)?;
        }

        Ok(id)
    }

    fn generate_id(&self) -> String {
        use std::time::UNIX_EPOCH;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("Q{:016X}", timestamp)
    }

    fn calculate_hash(&self, data: &[u8]) -> String {
        // Simplified hash - in production use sha2 crate
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        let h1 = hasher.finish();

        data.iter().rev().for_each(|b| b.hash(&mut hasher));
        let h2 = hasher.finish();

        format!(
            "{:016x}{:016x}{:016x}{:016x}",
            h1,
            h2,
            h1 ^ h2,
            h1.wrapping_add(h2)
        )
    }

    fn encrypt_content(&self, content: &[u8]) -> Result<Vec<u8>, QuarantineError> {
        // Simplified encryption - in production use aes-gcm crate
        if let Some(key) = &self.config.encryption_key {
            let mut encrypted = Vec::with_capacity(content.len() + 28);

            // Add a marker
            encrypted.extend_from_slice(b"ENC1");

            // Generate nonce (12 bytes)
            let nonce: [u8; 12] = [0u8; 12]; // In production: use random nonce
            encrypted.extend_from_slice(&nonce);

            // Simple XOR encryption (NOT SECURE - demo only)
            for (i, byte) in content.iter().enumerate() {
                encrypted.push(byte ^ key[i % 32] ^ nonce[i % 12]);
            }

            // Add tag (16 bytes placeholder)
            encrypted.extend_from_slice(&[0u8; 12]);

            Ok(encrypted)
        } else {
            Ok(content.to_vec())
        }
    }

    fn decrypt_content(&self, encrypted: &[u8]) -> Result<Vec<u8>, QuarantineError> {
        if encrypted.len() < 28 || &encrypted[..4] != b"ENC1" {
            // Not encrypted or wrong format
            return Ok(encrypted.to_vec());
        }

        if let Some(key) = &self.config.encryption_key {
            let nonce = &encrypted[4..16];
            let ciphertext = &encrypted[16..encrypted.len() - 12];

            let mut decrypted = Vec::with_capacity(ciphertext.len());
            for (i, byte) in ciphertext.iter().enumerate() {
                decrypted.push(byte ^ key[i % 32] ^ nonce[i % 12]);
            }

            Ok(decrypted)
        } else {
            Err(QuarantineError::DecryptionFailed(
                "No encryption key".to_string(),
            ))
        }
    }

    fn save_entry_metadata(&self, entry: &QuarantineEntry) -> Result<(), QuarantineError> {
        // Create JSON metadata (simplified)
        let metadata = format!(
            r#"{{
    "id": "{}",
    "original_path": "{}",
    "original_name": "{}",
    "file_hash": "{}",
    "file_size": {},
    "quarantined_at": {:?},
    "status": "{:?}",
    "reason": "{:?}"
}}"#,
            entry.id,
            entry.original_path.display(),
            entry.original_name,
            entry.file_hash,
            entry.file_size,
            entry
                .quarantined_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            entry.status,
            entry.reason,
        );

        let path = self.config.metadata_dir.join(format!("{}.json", entry.id));
        fs::write(&path, metadata).map_err(|e| QuarantineError::IoError(e.to_string()))?;

        Ok(())
    }

    fn log_audit(
        &mut self,
        action: AuditAction,
        entry_id: Option<&str>,
        user: Option<&str>,
        details: &str,
    ) {
        let entry = AuditLogEntry {
            timestamp: SystemTime::now(),
            action,
            entry_id: entry_id.map(String::from),
            user: user.map(String::from),
            details: details.to_string(),
            hash: self.calculate_audit_hash(details),
        };

        self.audit_log.push(entry);

        // Optionally write to tamper-evident log file
        if self.config.tamper_evident_logging {
            let _ = self.append_to_audit_log(details);
        }
    }

    fn calculate_audit_hash(&self, data: &str) -> String {
        // Chain hash with previous entry
        let prev_hash = self
            .audit_log
            .last()
            .map(|e| e.hash.as_str())
            .unwrap_or("GENESIS");

        let combined = format!("{}{}", prev_hash, data);
        self.calculate_hash(combined.as_bytes())
    }

    fn append_to_audit_log(&self, _details: &str) -> io::Result<()> {
        // Would append to immutable log file
        Ok(())
    }

    fn send_notification(&self, _entry_id: &str) -> Result<(), QuarantineError> {
        // Would send webhook notification
        Ok(())
    }

    /// Request file restoration
    pub fn request_restoration(
        &mut self,
        entry_id: &str,
        requested_by: &str,
        reason: &str,
    ) -> Result<(), QuarantineError> {
        let entry = self
            .entries
            .get_mut(entry_id)
            .ok_or(QuarantineError::EntryNotFound(entry_id.to_string()))?;

        if entry.status != QuarantineStatus::Active {
            return Err(QuarantineError::InvalidStatus(format!(
                "Cannot request restoration for entry in {:?} status",
                entry.status
            )));
        }

        entry.restoration_attempts.push(RestorationAttempt {
            timestamp: SystemTime::now(),
            requested_by: requested_by.to_string(),
            approved_by: None,
            status: RestorationStatus::Pending,
            reason: reason.to_string(),
        });

        entry.status = QuarantineStatus::PendingReview;

        self.log_audit(
            AuditAction::RestorationRequested,
            Some(entry_id),
            Some(requested_by),
            &format!("Restoration requested: {}", reason),
        );

        self.save_entry_metadata(entry)?;

        Ok(())
    }

    /// Approve restoration request
    pub fn approve_restoration(
        &mut self,
        entry_id: &str,
        approved_by: &str,
    ) -> Result<PathBuf, QuarantineError> {
        let entry = self
            .entries
            .get_mut(entry_id)
            .ok_or(QuarantineError::EntryNotFound(entry_id.to_string()))?;

        if entry.status != QuarantineStatus::PendingReview {
            return Err(QuarantineError::InvalidStatus(
                "Entry is not pending review".to_string(),
            ));
        }

        // Update restoration attempt
        if let Some(attempt) = entry.restoration_attempts.last_mut() {
            attempt.approved_by = Some(approved_by.to_string());
            attempt.status = RestorationStatus::Approved;
        }

        entry.status = QuarantineStatus::Approved;

        self.log_audit(
            AuditAction::RestorationApproved,
            Some(entry_id),
            Some(approved_by),
            "Restoration approved",
        );

        // Perform actual restoration
        self.restore_file(entry_id, approved_by)
    }

    /// Restore a file from quarantine
    fn restore_file(&mut self, entry_id: &str, user: &str) -> Result<PathBuf, QuarantineError> {
        let entry = self
            .entries
            .get(entry_id)
            .ok_or(QuarantineError::EntryNotFound(entry_id.to_string()))?
            .clone();

        // Read quarantined file
        let quarantine_path = self.config.quarantine_dir.join(&entry.id);
        let encrypted_content =
            fs::read(&quarantine_path).map_err(|e| QuarantineError::IoError(e.to_string()))?;

        // Decrypt content
        let content = self.decrypt_content(&encrypted_content)?;

        // Verify hash
        let current_hash = self.calculate_hash(&content);
        if current_hash != entry.file_hash {
            return Err(QuarantineError::IntegrityError(
                "File hash mismatch - file may be corrupted".to_string(),
            ));
        }

        // Determine restoration path
        let restore_path = if entry.original_path.exists() {
            // Original path is taken, use alternative
            let parent = entry.original_path.parent().unwrap_or(Path::new("/tmp"));
            let new_name = format!("restored_{}", entry.original_name);
            parent.join(new_name)
        } else {
            entry.original_path.clone()
        };

        // Restore file
        fs::write(&restore_path, &content).map_err(|e| QuarantineError::IoError(e.to_string()))?;

        // Remove from quarantine
        fs::remove_file(&quarantine_path).map_err(|e| QuarantineError::IoError(e.to_string()))?;

        // Remove metadata
        let metadata_path = self.config.metadata_dir.join(format!("{}.json", entry.id));
        let _ = fs::remove_file(&metadata_path);

        // Update entry status
        if let Some(e) = self.entries.get_mut(entry_id) {
            e.status = QuarantineStatus::Restored;
            if let Some(attempt) = e.restoration_attempts.last_mut() {
                attempt.status = RestorationStatus::Completed;
            }
        }

        // Update statistics
        self.stats.total_restored += 1;
        self.stats.current_file_count = self.stats.current_file_count.saturating_sub(1);
        self.stats.current_storage_used = self
            .stats
            .current_storage_used
            .saturating_sub(entry.file_size);
        self.stats.false_positives += 1;

        self.log_audit(
            AuditAction::FileRestored,
            Some(entry_id),
            Some(user),
            &format!("File restored to: {}", restore_path.display()),
        );

        Ok(restore_path)
    }

    /// Deny restoration request
    pub fn deny_restoration(
        &mut self,
        entry_id: &str,
        denied_by: &str,
        reason: &str,
    ) -> Result<(), QuarantineError> {
        let entry = self
            .entries
            .get_mut(entry_id)
            .ok_or(QuarantineError::EntryNotFound(entry_id.to_string()))?;

        if let Some(attempt) = entry.restoration_attempts.last_mut() {
            attempt.approved_by = Some(denied_by.to_string());
            attempt.status = RestorationStatus::Denied;
        }

        entry.status = QuarantineStatus::Active;

        self.log_audit(
            AuditAction::RestorationDenied,
            Some(entry_id),
            Some(denied_by),
            &format!("Restoration denied: {}", reason),
        );

        self.save_entry_metadata(entry)?;

        Ok(())
    }

    /// Permanently delete a quarantined file
    pub fn delete_file(&mut self, entry_id: &str, user: &str) -> Result<(), QuarantineError> {
        let entry = self
            .entries
            .get(entry_id)
            .ok_or(QuarantineError::EntryNotFound(entry_id.to_string()))?
            .clone();

        // Remove quarantine file
        let quarantine_path = self.config.quarantine_dir.join(&entry.id);
        if quarantine_path.exists() {
            fs::remove_file(&quarantine_path)
                .map_err(|e| QuarantineError::IoError(e.to_string()))?;
        }

        // Remove metadata
        let metadata_path = self.config.metadata_dir.join(format!("{}.json", entry.id));
        let _ = fs::remove_file(&metadata_path);

        // Update entry
        if let Some(e) = self.entries.get_mut(entry_id) {
            e.status = QuarantineStatus::Deleted;
        }

        // Update statistics
        self.stats.total_deleted += 1;
        self.stats.current_file_count = self.stats.current_file_count.saturating_sub(1);
        self.stats.current_storage_used = self
            .stats
            .current_storage_used
            .saturating_sub(entry.file_size);

        self.log_audit(
            AuditAction::FileDeleted,
            Some(entry_id),
            Some(user),
            "File permanently deleted",
        );

        Ok(())
    }

    /// Add note to quarantine entry
    pub fn add_note(
        &mut self,
        entry_id: &str,
        author: &str,
        content: &str,
    ) -> Result<(), QuarantineError> {
        let entry = self
            .entries
            .get_mut(entry_id)
            .ok_or(QuarantineError::EntryNotFound(entry_id.to_string()))?;

        entry.notes.push(QuarantineNote {
            timestamp: SystemTime::now(),
            author: author.to_string(),
            content: content.to_string(),
        });

        self.log_audit(
            AuditAction::NoteAdded,
            Some(entry_id),
            Some(author),
            &format!("Note added: {}", content),
        );

        self.save_entry_metadata(entry)?;

        Ok(())
    }

    /// Get entry by ID
    pub fn get_entry(&self, entry_id: &str) -> Option<&QuarantineEntry> {
        self.entries.get(entry_id)
    }

    /// List all entries
    pub fn list_entries(&self) -> Vec<&QuarantineEntry> {
        self.entries.values().collect()
    }

    /// List entries by status
    pub fn list_by_status(&self, status: QuarantineStatus) -> Vec<&QuarantineEntry> {
        self.entries
            .values()
            .filter(|e| e.status == status)
            .collect()
    }

    /// Search entries by filename
    pub fn search(&self, query: &str) -> Vec<&QuarantineEntry> {
        let query_lower = query.to_lowercase();
        self.entries
            .values()
            .filter(|e| e.original_name.to_lowercase().contains(&query_lower))
            .collect()
    }

    /// Cleanup expired entries
    pub fn cleanup_expired(&mut self) -> Result<Vec<String>, QuarantineError> {
        let now = SystemTime::now();
        let mut expired = Vec::new();

        for (id, entry) in &self.entries {
            if entry.expires_at < now && entry.status == QuarantineStatus::Active {
                expired.push(id.clone());
            }
        }

        for id in &expired {
            self.delete_file(id, "SYSTEM")?;
            if let Some(entry) = self.entries.get_mut(id) {
                entry.status = QuarantineStatus::Expired;
            }
        }

        Ok(expired)
    }

    /// Get statistics
    pub fn get_stats(&self) -> &QuarantineStats {
        &self.stats
    }

    /// Get audit log
    pub fn get_audit_log(&self) -> &[AuditLogEntry] {
        &self.audit_log
    }

    /// Verify audit log integrity
    pub fn verify_audit_integrity(&self) -> bool {
        let mut prev_hash = "GENESIS".to_string();

        for entry in &self.audit_log {
            let combined = format!("{}{}", prev_hash, entry.details);
            let expected_hash = self.calculate_hash(combined.as_bytes());

            if entry.hash != expected_hash {
                return false;
            }

            prev_hash = entry.hash.clone();
        }

        true
    }

    /// Export report
    pub fn export_report(&self) -> String {
        let mut report = String::new();
        report.push_str("=== Quarantine System Report ===\n\n");

        report.push_str(&format!(
            "Total quarantined: {}\n",
            self.stats.total_quarantined
        ));
        report.push_str(&format!("Total restored: {}\n", self.stats.total_restored));
        report.push_str(&format!("Total deleted: {}\n", self.stats.total_deleted));
        report.push_str(&format!(
            "Current files: {}\n",
            self.stats.current_file_count
        ));
        report.push_str(&format!(
            "Storage used: {} bytes\n",
            self.stats.current_storage_used
        ));
        report.push_str(&format!(
            "Malware detected: {}\n",
            self.stats.malware_detected
        ));
        report.push_str(&format!(
            "False positives: {}\n\n",
            self.stats.false_positives
        ));

        report.push_str("Active entries:\n");
        for entry in self.list_by_status(QuarantineStatus::Active) {
            report.push_str(&format!(
                "  {} - {} ({} bytes) - {:?}\n",
                entry.id, entry.original_name, entry.file_size, entry.reason
            ));
        }

        report.push_str(&format!(
            "\nPending review: {}\n",
            self.list_by_status(QuarantineStatus::PendingReview).len()
        ));

        report
    }
}

/// Quarantine errors
#[derive(Debug)]
pub enum QuarantineError {
    FileNotFound(PathBuf),
    EntryNotFound(String),
    IoError(String),
    StorageFull,
    InvalidStatus(String),
    DecryptionFailed(String),
    IntegrityError(String),
}

impl std::fmt::Display for QuarantineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileNotFound(p) => write!(f, "File not found: {}", p.display()),
            Self::EntryNotFound(id) => write!(f, "Entry not found: {}", id),
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::StorageFull => write!(f, "Quarantine storage is full"),
            Self::InvalidStatus(s) => write!(f, "Invalid status: {}", s),
            Self::DecryptionFailed(e) => write!(f, "Decryption failed: {}", e),
            Self::IntegrityError(e) => write!(f, "Integrity error: {}", e),
        }
    }
}

fn main() {
    println!("=== File Quarantine System Demo ===\n");

    // Create configuration
    let config = QuarantineConfig {
        quarantine_dir: PathBuf::from("/tmp/quarantine_demo/files"),
        metadata_dir: PathBuf::from("/tmp/quarantine_demo/metadata"),
        encrypt_files: true,
        encryption_key: Some([0x42u8; 32]), // Demo key
        ..Default::default()
    };

    // Create manager
    let manager_result = QuarantineManager::new(config);

    match manager_result {
        Ok(mut manager) => {
            println!("Quarantine manager initialized\n");

            // Simulate quarantine operations
            println!("Simulating quarantine operations:\n");

            // Create a test file
            let test_file = PathBuf::from("/tmp/quarantine_demo/test_malware.exe");
            fs::create_dir_all("/tmp/quarantine_demo").ok();
            fs::write(&test_file, b"SIMULATED_MALWARE_CONTENT").ok();

            // Quarantine the file
            let detection = DetectionInfo {
                source: "MalwareScanner".to_string(),
                threat_name: Some("Trojan.Generic".to_string()),
                severity: ThreatSeverity::High,
                confidence: 95,
                details: HashMap::new(),
            };

            match manager.quarantine_file(
                &test_file,
                QuarantineReason::MalwareDetected,
                detection,
                Some("security-scanner".to_string()),
            ) {
                Ok(id) => {
                    println!("1. File quarantined successfully");
                    println!("   ID: {}", id);

                    // Add a note
                    manager
                        .add_note(&id, "analyst", "Detected by automated scan")
                        .ok();
                    println!("2. Note added to entry");

                    // Request restoration
                    manager
                        .request_restoration(&id, "user@example.com", "Need this file for testing")
                        .ok();
                    println!("3. Restoration requested");

                    // Show entry details
                    if let Some(entry) = manager.get_entry(&id) {
                        println!("\nEntry details:");
                        println!("  Original: {}", entry.original_name);
                        println!("  Hash: {}", entry.file_hash);
                        println!("  Status: {:?}", entry.status);
                        println!("  Reason: {:?}", entry.reason);
                        println!("  Notes: {}", entry.notes.len());
                    }
                }
                Err(e) => {
                    println!("Failed to quarantine: {}", e);
                }
            }

            // Show statistics
            println!("\nQuarantine Statistics:");
            let stats = manager.get_stats();
            println!("  Total quarantined: {}", stats.total_quarantined);
            println!("  Current files: {}", stats.current_file_count);
            println!("  Storage used: {} bytes", stats.current_storage_used);

            // Verify audit integrity
            println!(
                "\nAudit log integrity: {}",
                if manager.verify_audit_integrity() {
                    "VALID"
                } else {
                    "COMPROMISED"
                }
            );

            // Show audit log
            println!("\nRecent audit entries:");
            for entry in manager.get_audit_log().iter().take(5) {
                println!("  [{:?}] {}", entry.action, entry.details);
            }

            // Export report
            println!("\n{}", manager.export_report());
        }
        Err(e) => {
            println!("Failed to initialize quarantine manager: {}", e);
        }
    }

    // Cleanup demo directory
    let _ = fs::remove_dir_all("/tmp/quarantine_demo");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn create_test_manager() -> QuarantineManager {
        let config = QuarantineConfig {
            quarantine_dir: PathBuf::from("/tmp/quarantine_test/files"),
            metadata_dir: PathBuf::from("/tmp/quarantine_test/metadata"),
            encrypt_files: false,
            ..Default::default()
        };
        QuarantineManager::new(config).unwrap()
    }

    fn cleanup_test_dir() {
        let _ = fs::remove_dir_all("/tmp/quarantine_test");
    }

    #[test]
    fn test_generate_id() {
        let manager = create_test_manager();
        let id1 = manager.generate_id();
        let id2 = manager.generate_id();

        assert!(id1.starts_with("Q"));
        assert_ne!(id1, id2);

        cleanup_test_dir();
    }

    #[test]
    fn test_hash_calculation() {
        let manager = create_test_manager();

        let data1 = b"test data";
        let data2 = b"test data";
        let data3 = b"different data";

        assert_eq!(manager.calculate_hash(data1), manager.calculate_hash(data2));
        assert_ne!(manager.calculate_hash(data1), manager.calculate_hash(data3));

        cleanup_test_dir();
    }

    #[test]
    fn test_encryption_roundtrip() {
        let mut config = QuarantineConfig::default();
        config.quarantine_dir = PathBuf::from("/tmp/quarantine_test/files");
        config.metadata_dir = PathBuf::from("/tmp/quarantine_test/metadata");
        config.encrypt_files = true;
        config.encryption_key = Some([0x42u8; 32]);

        let manager = QuarantineManager::new(config).unwrap();

        let original = b"Secret test content that should be encrypted";
        let encrypted = manager.encrypt_content(original).unwrap();
        let decrypted = manager.decrypt_content(&encrypted).unwrap();

        assert_ne!(original.as_slice(), encrypted.as_slice());
        assert_eq!(original.as_slice(), decrypted.as_slice());

        cleanup_test_dir();
    }

    #[test]
    fn test_audit_integrity() {
        let mut manager = create_test_manager();

        manager.log_audit(
            AuditAction::FileQuarantined,
            Some("test1"),
            Some("user"),
            "Test entry 1",
        );
        manager.log_audit(
            AuditAction::NoteAdded,
            Some("test1"),
            Some("user"),
            "Test entry 2",
        );
        manager.log_audit(
            AuditAction::FileRestored,
            Some("test1"),
            Some("admin"),
            "Test entry 3",
        );

        assert!(manager.verify_audit_integrity());

        cleanup_test_dir();
    }

    #[test]
    fn test_status_values() {
        assert_ne!(QuarantineStatus::Active, QuarantineStatus::Deleted);
        assert_ne!(QuarantineStatus::PendingReview, QuarantineStatus::Approved);
    }

    #[test]
    fn test_severity_values() {
        assert_ne!(ThreatSeverity::Low, ThreatSeverity::Critical);
        assert_ne!(ThreatSeverity::Medium, ThreatSeverity::High);
    }
}
