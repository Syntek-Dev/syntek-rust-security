# Rust Quarantine System Template

File quarantine and remediation system for isolating malicious or suspicious
files.

## Project Structure

```
rust-quarantine-system/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── quarantine/
│   │   ├── mod.rs
│   │   ├── vault.rs
│   │   ├── metadata.rs
│   │   └── encryption.rs
│   ├── policy/
│   │   ├── mod.rs
│   │   ├── rules.rs
│   │   └── retention.rs
│   ├── restore/
│   │   ├── mod.rs
│   │   └── workflow.rs
│   ├── notification/
│   │   ├── mod.rs
│   │   └── alerts.rs
│   ├── api/
│   │   ├── mod.rs
│   │   └── server.rs
│   └── config.rs
└── quarantine/
    └── .gitkeep
```

## Cargo.toml

```toml
[package]
name = "rust-quarantine-system"
version = "0.1.0"
edition = "2021"
rust-version = "1.92"

[dependencies]
tokio = { version = "1", features = ["full"] }
aes-gcm = "0.10"
rand = "0.8"
sha2 = "0.10"
hex = "0.4"
uuid = { version = "1", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
rusqlite = { version = "0.32", features = ["bundled"] }
axum = "0.7"
tracing = "0.1"
tracing-subscriber = "0.3"
thiserror = "2"
anyhow = "1"
walkdir = "2"
notify-rust = "4"
lettre = { version = "0.11", features = ["tokio1-native-tls"] }
```

## Core Implementation

### src/lib.rs

```rust
pub mod quarantine;
pub mod policy;
pub mod restore;
pub mod notification;
pub mod api;
pub mod config;

pub use quarantine::{QuarantineVault, QuarantinedFile};
pub use policy::RetentionPolicy;
```

### src/quarantine/mod.rs

```rust
pub mod vault;
pub mod metadata;
pub mod encryption;

pub use vault::QuarantineVault;
pub use metadata::{QuarantinedFile, QuarantineReason, ThreatInfo};
```

### src/quarantine/metadata.rs

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedFile {
    pub id: Uuid,
    pub original_path: String,
    pub original_name: String,
    pub quarantine_path: String,
    pub size: u64,
    pub sha256: String,
    pub quarantined_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub reason: QuarantineReason,
    pub threat_info: Option<ThreatInfo>,
    pub status: QuarantineStatus,
    pub quarantined_by: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QuarantineReason {
    MalwareDetected,
    SuspiciousBehavior,
    PolicyViolation,
    ManualQuarantine,
    RansomwareIndicator,
    UnauthorizedExecutable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInfo {
    pub detection_name: String,
    pub severity: ThreatSeverity,
    pub category: String,
    pub scanner: String,
    pub signature_id: Option<String>,
    pub confidence: u8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum QuarantineStatus {
    Active,
    PendingReview,
    Restored,
    Deleted,
    Expired,
}

impl QuarantinedFile {
    pub fn new(
        original_path: String,
        size: u64,
        sha256: String,
        reason: QuarantineReason,
        quarantined_by: String,
    ) -> Self {
        let id = Uuid::new_v4();
        let original_name = std::path::Path::new(&original_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        Self {
            id,
            original_path,
            original_name,
            quarantine_path: String::new(), // Set by vault
            size,
            sha256,
            quarantined_at: Utc::now(),
            expires_at: None,
            reason,
            threat_info: None,
            status: QuarantineStatus::Active,
            quarantined_by,
            notes: None,
        }
    }

    pub fn with_threat_info(mut self, info: ThreatInfo) -> Self {
        self.threat_info = Some(info);
        self
    }

    pub fn with_expiry(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| Utc::now() > exp)
            .unwrap_or(false)
    }
}
```

### src/quarantine/encryption.rs

```rust
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid key")]
    InvalidKey,
}

pub struct QuarantineEncryption {
    cipher: Aes256Gcm,
}

impl QuarantineEncryption {
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key).expect("valid key size");
        Self { cipher }
    }

    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher
            .encrypt(nonce, data)
            .map_err(|_| EncryptionError::EncryptionFailed)?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if data.len() < 12 {
            return Err(EncryptionError::DecryptionFailed);
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| EncryptionError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = QuarantineEncryption::generate_key();
        let encryption = QuarantineEncryption::new(&key);

        let plaintext = b"This is a test file content";
        let ciphertext = encryption.encrypt(plaintext).unwrap();
        let decrypted = encryption.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
```

### src/quarantine/vault.rs

```rust
use std::path::{Path, PathBuf};
use tokio::fs;
use sha2::{Sha256, Digest};
use uuid::Uuid;
use tracing::{info, warn, error};

use super::encryption::QuarantineEncryption;
use super::metadata::{QuarantinedFile, QuarantineStatus};
use crate::policy::RetentionPolicy;

pub struct QuarantineVault {
    base_path: PathBuf,
    encryption: QuarantineEncryption,
    db: crate::api::QuarantineDb,
}

impl QuarantineVault {
    pub async fn new(
        base_path: PathBuf,
        encryption_key: [u8; 32],
        db_path: &Path,
    ) -> anyhow::Result<Self> {
        fs::create_dir_all(&base_path).await?;

        // Create subdirectories for organization
        fs::create_dir_all(base_path.join("files")).await?;
        fs::create_dir_all(base_path.join("metadata")).await?;

        let encryption = QuarantineEncryption::new(&encryption_key);
        let db = crate::api::QuarantineDb::open(db_path)?;

        info!("Quarantine vault initialized at {:?}", base_path);

        Ok(Self {
            base_path,
            encryption,
            db,
        })
    }

    pub async fn quarantine(&self, mut file: QuarantinedFile) -> anyhow::Result<QuarantinedFile> {
        let source_path = Path::new(&file.original_path);

        // Verify file exists
        if !source_path.exists() {
            anyhow::bail!("Source file does not exist: {}", file.original_path);
        }

        // Read and hash the file
        let content = fs::read(source_path).await?;
        let hash = Self::compute_sha256(&content);

        // Verify hash matches if provided
        if !file.sha256.is_empty() && file.sha256 != hash {
            warn!(
                "Hash mismatch for {}: expected {}, got {}",
                file.original_path, file.sha256, hash
            );
        }
        file.sha256 = hash;

        // Generate quarantine path
        let quarantine_filename = format!("{}.quarantine", file.id);
        let quarantine_path = self.base_path.join("files").join(&quarantine_filename);
        file.quarantine_path = quarantine_path.to_string_lossy().to_string();

        // Encrypt and write to quarantine
        let encrypted = self.encryption.encrypt(&content)?;
        fs::write(&quarantine_path, &encrypted).await?;

        // Remove original file
        fs::remove_file(source_path).await?;

        // Save metadata
        self.db.insert_quarantined_file(&file)?;

        info!(
            "Quarantined file {} -> {} (sha256: {})",
            file.original_path, file.quarantine_path, file.sha256
        );

        Ok(file)
    }

    pub async fn restore(&self, id: Uuid, restore_path: Option<&Path>) -> anyhow::Result<PathBuf> {
        let mut file = self.db.get_quarantined_file(id)?
            .ok_or_else(|| anyhow::anyhow!("Quarantined file not found"))?;

        if file.status != QuarantineStatus::Active
            && file.status != QuarantineStatus::PendingReview {
            anyhow::bail!("Cannot restore file with status {:?}", file.status);
        }

        // Read and decrypt
        let encrypted = fs::read(&file.quarantine_path).await?;
        let content = self.encryption.decrypt(&encrypted)?;

        // Verify hash
        let hash = Self::compute_sha256(&content);
        if hash != file.sha256 {
            anyhow::bail!("Hash mismatch during restore - file may be corrupted");
        }

        // Determine restore path
        let target_path = restore_path
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(&file.original_path));

        // Ensure parent directory exists
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Write restored file
        fs::write(&target_path, &content).await?;

        // Update status
        file.status = QuarantineStatus::Restored;
        self.db.update_status(id, QuarantineStatus::Restored)?;

        info!("Restored file {} to {:?}", id, target_path);

        Ok(target_path)
    }

    pub async fn delete_permanently(&self, id: Uuid) -> anyhow::Result<()> {
        let file = self.db.get_quarantined_file(id)?
            .ok_or_else(|| anyhow::anyhow!("Quarantined file not found"))?;

        // Securely delete the quarantined file
        let quarantine_path = Path::new(&file.quarantine_path);
        if quarantine_path.exists() {
            // Overwrite with zeros before deletion
            let size = fs::metadata(quarantine_path).await?.len();
            let zeros = vec![0u8; size as usize];
            fs::write(quarantine_path, &zeros).await?;
            fs::remove_file(quarantine_path).await?;
        }

        // Update database
        self.db.update_status(id, QuarantineStatus::Deleted)?;

        info!("Permanently deleted quarantined file {}", id);

        Ok(())
    }

    pub async fn apply_retention_policy(&self, policy: &RetentionPolicy) -> anyhow::Result<usize> {
        let expired_files = self.db.get_expired_files(policy)?;
        let mut deleted_count = 0;

        for file in expired_files {
            match self.delete_permanently(file.id).await {
                Ok(_) => deleted_count += 1,
                Err(e) => error!("Failed to delete expired file {}: {}", file.id, e),
            }
        }

        info!("Retention policy applied: {} files deleted", deleted_count);

        Ok(deleted_count)
    }

    pub fn list_quarantined(&self, status: Option<QuarantineStatus>) -> anyhow::Result<Vec<QuarantinedFile>> {
        self.db.list_files(status)
    }

    pub fn get_file(&self, id: Uuid) -> anyhow::Result<Option<QuarantinedFile>> {
        self.db.get_quarantined_file(id)
    }

    pub async fn get_file_preview(&self, id: Uuid, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
        let file = self.db.get_quarantined_file(id)?
            .ok_or_else(|| anyhow::anyhow!("File not found"))?;

        let encrypted = fs::read(&file.quarantine_path).await?;
        let content = self.encryption.decrypt(&encrypted)?;

        Ok(content.into_iter().take(max_bytes).collect())
    }

    fn compute_sha256(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    pub fn stats(&self) -> anyhow::Result<QuarantineStats> {
        self.db.get_stats()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct QuarantineStats {
    pub total_files: usize,
    pub active_files: usize,
    pub total_size_bytes: u64,
    pub by_reason: std::collections::HashMap<String, usize>,
    pub by_severity: std::collections::HashMap<String, usize>,
}
```

### src/policy/retention.rs

```rust
use chrono::Duration;
use serde::{Deserialize, Serialize};

use crate::quarantine::{ThreatSeverity, QuarantineReason};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Default retention period for quarantined files
    pub default_retention_days: i64,

    /// Retention periods by threat severity
    pub severity_retention: SeverityRetention,

    /// Maximum storage size in bytes
    pub max_storage_bytes: u64,

    /// Auto-delete after review
    pub auto_delete_after_review: bool,

    /// Keep permanently flagged files indefinitely
    pub preserve_flagged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityRetention {
    pub low_days: i64,
    pub medium_days: i64,
    pub high_days: i64,
    pub critical_days: i64,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            default_retention_days: 30,
            severity_retention: SeverityRetention {
                low_days: 7,
                medium_days: 30,
                high_days: 90,
                critical_days: 365,
            },
            max_storage_bytes: 10 * 1024 * 1024 * 1024, // 10 GB
            auto_delete_after_review: false,
            preserve_flagged: true,
        }
    }
}

impl RetentionPolicy {
    pub fn retention_for_severity(&self, severity: ThreatSeverity) -> Duration {
        let days = match severity {
            ThreatSeverity::Low => self.severity_retention.low_days,
            ThreatSeverity::Medium => self.severity_retention.medium_days,
            ThreatSeverity::High => self.severity_retention.high_days,
            ThreatSeverity::Critical => self.severity_retention.critical_days,
        };
        Duration::days(days)
    }

    pub fn retention_for_reason(&self, reason: &QuarantineReason) -> Duration {
        let days = match reason {
            QuarantineReason::MalwareDetected => self.severity_retention.critical_days,
            QuarantineReason::RansomwareIndicator => self.severity_retention.critical_days,
            QuarantineReason::SuspiciousBehavior => self.severity_retention.high_days,
            QuarantineReason::PolicyViolation => self.severity_retention.medium_days,
            QuarantineReason::UnauthorizedExecutable => self.severity_retention.medium_days,
            QuarantineReason::ManualQuarantine => self.default_retention_days,
        };
        Duration::days(days)
    }
}
```

### src/restore/workflow.rs

```rust
use uuid::Uuid;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::quarantine::{QuarantineVault, QuarantinedFile, QuarantineStatus};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreRequest {
    pub file_id: Uuid,
    pub requested_by: String,
    pub reason: String,
    pub restore_path: Option<String>,
    pub requires_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreApproval {
    pub request_id: Uuid,
    pub approved_by: String,
    pub approved: bool,
    pub comments: Option<String>,
}

pub struct RestoreWorkflow {
    vault: std::sync::Arc<QuarantineVault>,
    require_approval_for_malware: bool,
}

impl RestoreWorkflow {
    pub fn new(vault: std::sync::Arc<QuarantineVault>) -> Self {
        Self {
            vault,
            require_approval_for_malware: true,
        }
    }

    pub async fn request_restore(&self, request: RestoreRequest) -> anyhow::Result<RestoreResult> {
        let file = self.vault.get_file(request.file_id)?
            .ok_or_else(|| anyhow::anyhow!("File not found"))?;

        // Check if approval is required
        let needs_approval = request.requires_approval
            || (self.require_approval_for_malware && self.is_malware(&file));

        if needs_approval {
            // Mark as pending review
            // In a real implementation, this would create a pending request
            Ok(RestoreResult::PendingApproval {
                request_id: Uuid::new_v4(),
                message: "Restore request submitted for approval".to_string(),
            })
        } else {
            // Direct restore
            let restore_path = request.restore_path.as_deref().map(std::path::Path::new);
            let path = self.vault.restore(request.file_id, restore_path).await?;

            Ok(RestoreResult::Restored {
                path: path.to_string_lossy().to_string(),
            })
        }
    }

    pub async fn approve_restore(
        &self,
        approval: RestoreApproval,
        original_request: &RestoreRequest,
    ) -> anyhow::Result<RestoreResult> {
        if !approval.approved {
            return Ok(RestoreResult::Denied {
                reason: approval.comments.unwrap_or_else(|| "Request denied".to_string()),
            });
        }

        let restore_path = original_request.restore_path.as_deref().map(std::path::Path::new);
        let path = self.vault.restore(original_request.file_id, restore_path).await?;

        Ok(RestoreResult::Restored {
            path: path.to_string_lossy().to_string(),
        })
    }

    fn is_malware(&self, file: &QuarantinedFile) -> bool {
        matches!(
            file.reason,
            crate::quarantine::QuarantineReason::MalwareDetected
            | crate::quarantine::QuarantineReason::RansomwareIndicator
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum RestoreResult {
    Restored { path: String },
    PendingApproval { request_id: Uuid, message: String },
    Denied { reason: String },
}
```

### src/notification/alerts.rs

```rust
use serde::{Deserialize, Serialize};
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;

use crate::quarantine::{QuarantinedFile, ThreatSeverity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub from_address: String,
    pub admin_emails: Vec<String>,
    pub notify_on_quarantine: bool,
    pub notify_on_restore: bool,
    pub min_severity_for_alert: ThreatSeverity,
}

pub struct AlertService {
    config: NotificationConfig,
    mailer: Option<SmtpTransport>,
}

impl AlertService {
    pub fn new(config: NotificationConfig) -> Self {
        let mailer = if !config.smtp_host.is_empty() {
            let creds = Credentials::new(
                config.smtp_username.clone(),
                config.smtp_password.clone(),
            );

            SmtpTransport::relay(&config.smtp_host)
                .ok()
                .map(|builder| builder.credentials(creds).build())
        } else {
            None
        };

        Self { config, mailer }
    }

    pub async fn notify_quarantine(&self, file: &QuarantinedFile) -> anyhow::Result<()> {
        if !self.config.notify_on_quarantine {
            return Ok(());
        }

        // Check severity threshold
        if let Some(ref threat_info) = file.threat_info {
            if !self.meets_severity_threshold(threat_info.severity) {
                return Ok(());
            }
        }

        let subject = format!(
            "[Quarantine Alert] {} quarantined: {}",
            format!("{:?}", file.reason),
            file.original_name
        );

        let body = self.format_quarantine_alert(file);
        self.send_alert(&subject, &body).await
    }

    pub async fn notify_restore(&self, file: &QuarantinedFile, restored_path: &str) -> anyhow::Result<()> {
        if !self.config.notify_on_restore {
            return Ok(());
        }

        let subject = format!(
            "[Quarantine Notice] File restored: {}",
            file.original_name
        );

        let body = format!(
            "A quarantined file has been restored.\n\n\
            Original Path: {}\n\
            Restored To: {}\n\
            Quarantine Reason: {:?}\n\
            Quarantined At: {}\n\
            SHA256: {}",
            file.original_path,
            restored_path,
            file.reason,
            file.quarantined_at,
            file.sha256
        );

        self.send_alert(&subject, &body).await
    }

    fn meets_severity_threshold(&self, severity: ThreatSeverity) -> bool {
        let threshold_value = match self.config.min_severity_for_alert {
            ThreatSeverity::Low => 0,
            ThreatSeverity::Medium => 1,
            ThreatSeverity::High => 2,
            ThreatSeverity::Critical => 3,
        };

        let severity_value = match severity {
            ThreatSeverity::Low => 0,
            ThreatSeverity::Medium => 1,
            ThreatSeverity::High => 2,
            ThreatSeverity::Critical => 3,
        };

        severity_value >= threshold_value
    }

    fn format_quarantine_alert(&self, file: &QuarantinedFile) -> String {
        let mut body = format!(
            "A file has been quarantined.\n\n\
            File: {}\n\
            Original Path: {}\n\
            Size: {} bytes\n\
            SHA256: {}\n\
            Reason: {:?}\n\
            Quarantined At: {}\n\
            Quarantined By: {}",
            file.original_name,
            file.original_path,
            file.size,
            file.sha256,
            file.reason,
            file.quarantined_at,
            file.quarantined_by
        );

        if let Some(ref threat_info) = file.threat_info {
            body.push_str(&format!(
                "\n\nThreat Information:\n\
                Detection: {}\n\
                Severity: {:?}\n\
                Category: {}\n\
                Scanner: {}\n\
                Confidence: {}%",
                threat_info.detection_name,
                threat_info.severity,
                threat_info.category,
                threat_info.scanner,
                threat_info.confidence
            ));
        }

        body
    }

    async fn send_alert(&self, subject: &str, body: &str) -> anyhow::Result<()> {
        let Some(ref mailer) = self.mailer else {
            tracing::warn!("Email not configured, skipping alert");
            return Ok(());
        };

        for recipient in &self.config.admin_emails {
            let email = Message::builder()
                .from(self.config.from_address.parse()?)
                .to(recipient.parse()?)
                .subject(subject)
                .body(body.to_string())?;

            mailer.send(&email)?;
        }

        Ok(())
    }

    // Desktop notification (for local admin)
    pub fn desktop_notify(&self, title: &str, message: &str) {
        #[cfg(target_os = "linux")]
        {
            let _ = notify_rust::Notification::new()
                .summary(title)
                .body(message)
                .icon("dialog-warning")
                .show();
        }
    }
}
```

### src/api/server.rs

```rust
use std::sync::Arc;
use axum::{
    extract::{Path, State, Json},
    routing::{get, post, delete},
    Router,
    http::StatusCode,
};
use uuid::Uuid;

use crate::quarantine::{QuarantineVault, QuarantinedFile, QuarantineStatus, QuarantineReason};
use crate::restore::{RestoreWorkflow, RestoreRequest};

pub struct ApiState {
    pub vault: Arc<QuarantineVault>,
    pub workflow: Arc<RestoreWorkflow>,
}

pub fn create_router(state: ApiState) -> Router {
    Router::new()
        .route("/api/quarantine", get(list_quarantined).post(quarantine_file))
        .route("/api/quarantine/:id", get(get_file).delete(delete_file))
        .route("/api/quarantine/:id/restore", post(restore_file))
        .route("/api/quarantine/:id/preview", get(preview_file))
        .route("/api/quarantine/stats", get(get_stats))
        .with_state(Arc::new(state))
}

#[derive(serde::Deserialize)]
pub struct QuarantineRequest {
    pub path: String,
    pub reason: QuarantineReason,
    pub threat_info: Option<crate::quarantine::ThreatInfo>,
}

async fn quarantine_file(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<QuarantineRequest>,
) -> Result<Json<QuarantinedFile>, (StatusCode, String)> {
    let metadata = tokio::fs::metadata(&req.path).await
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    let mut file = QuarantinedFile::new(
        req.path,
        metadata.len(),
        String::new(),
        req.reason,
        "api".to_string(),
    );

    if let Some(threat_info) = req.threat_info {
        file = file.with_threat_info(threat_info);
    }

    let quarantined = state.vault.quarantine(file).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(quarantined))
}

async fn list_quarantined(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<Vec<QuarantinedFile>>, (StatusCode, String)> {
    let files = state.vault.list_quarantined(Some(QuarantineStatus::Active))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(files))
}

async fn get_file(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<QuarantinedFile>, (StatusCode, String)> {
    let file = state.vault.get_file(id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "File not found".to_string()))?;

    Ok(Json(file))
}

async fn restore_file(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<RestoreRequestApi>,
) -> Result<Json<crate::restore::RestoreResult>, (StatusCode, String)> {
    let restore_req = RestoreRequest {
        file_id: id,
        requested_by: req.requested_by,
        reason: req.reason,
        restore_path: req.restore_path,
        requires_approval: req.requires_approval.unwrap_or(false),
    };

    let result = state.workflow.request_restore(restore_req).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(result))
}

#[derive(serde::Deserialize)]
pub struct RestoreRequestApi {
    pub requested_by: String,
    pub reason: String,
    pub restore_path: Option<String>,
    pub requires_approval: Option<bool>,
}

async fn delete_file(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    state.vault.delete_permanently(id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

async fn preview_file(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let preview = state.vault.get_file_preview(id, 4096).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(preview)
}

async fn get_stats(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<crate::quarantine::vault::QuarantineStats>, (StatusCode, String)> {
    let stats = state.vault.stats()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(stats))
}
```

### src/main.rs

```rust
use std::sync::Arc;
use std::path::PathBuf;
use tracing::info;

mod config;
mod quarantine;
mod policy;
mod restore;
mod notification;
mod api;

use quarantine::QuarantineVault;
use restore::RestoreWorkflow;
use api::{ApiState, create_router};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = config::Config::load("config.toml").await?;

    // Initialize encryption key (in production, load from secure storage)
    let encryption_key = quarantine::encryption::QuarantineEncryption::generate_key();

    // Initialize vault
    let vault = Arc::new(
        QuarantineVault::new(
            PathBuf::from(&config.quarantine_path),
            encryption_key,
            std::path::Path::new(&config.database_path),
        ).await?
    );

    // Initialize workflow
    let workflow = Arc::new(RestoreWorkflow::new(Arc::clone(&vault)));

    // Start retention policy task
    let vault_clone = Arc::clone(&vault);
    let policy = config.retention_policy.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            if let Err(e) = vault_clone.apply_retention_policy(&policy).await {
                tracing::error!("Retention policy error: {}", e);
            }
        }
    });

    // Start API server
    let state = ApiState { vault, workflow };
    let app = create_router(state);

    let listener = tokio::net::TcpListener::bind(&config.api_listen).await?;
    info!("Quarantine API listening on {}", config.api_listen);

    axum::serve(listener, app).await?;

    Ok(())
}
```

## Security Checklist

- [ ] Encrypt all quarantined files at rest
- [ ] Securely wipe files on permanent deletion
- [ ] Verify file hashes before restore
- [ ] Require authentication for all API endpoints
- [ ] Implement role-based access control
- [ ] Log all quarantine/restore operations
- [ ] Validate file paths to prevent directory traversal
- [ ] Implement approval workflow for malware restores
- [ ] Set appropriate retention policies
- [ ] Protect encryption keys (HSM/Vault integration)
- [ ] Rate limit API endpoints
- [ ] Sanitize file metadata in logs
