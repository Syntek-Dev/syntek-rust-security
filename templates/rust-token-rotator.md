# Rust Token Rotator Template

## Overview

This template provides an automated token and secret rotation system in Rust. It
manages the lifecycle of API keys, database credentials, encryption keys, and
other secrets with secure rotation, notification, and audit logging
capabilities.

**Target Use Cases:**

- API key rotation (Cloudflare, AWS, etc.)
- Database credential rotation
- Encryption key rotation
- Certificate rotation
- Service account token rotation
- Vault token renewal

## Project Structure

```
my-token-rotator/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── config.rs              # Configuration
│   ├── rotator/
│   │   ├── mod.rs
│   │   ├── manager.rs         # Rotation manager
│   │   ├── scheduler.rs       # Cron scheduling
│   │   └── executor.rs        # Rotation executor
│   ├── providers/
│   │   ├── mod.rs
│   │   ├── cloudflare.rs      # Cloudflare API tokens
│   │   ├── aws.rs             # AWS access keys
│   │   ├── database.rs        # Database credentials
│   │   ├── vault.rs           # Vault tokens
│   │   └── generic.rs         # Generic secrets
│   ├── storage/
│   │   ├── mod.rs
│   │   ├── vault.rs           # Vault KV storage
│   │   └── file.rs            # Encrypted file storage
│   ├── notification/
│   │   ├── mod.rs
│   │   ├── slack.rs
│   │   └── email.rs
│   ├── audit.rs               # Audit logging
│   └── error.rs
├── config/
│   └── rotator.toml
├── tests/
│   └── rotation_tests.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-token-rotator"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"

[[bin]]
name = "token-rotator"
path = "src/main.rs"

[dependencies]
# Async runtime
tokio = { version = "1.40", features = ["full"] }

# Configuration
config = "0.14"
serde = { version = "1.0", features = ["derive"] }
toml = "0.8"

# Vault client
vaultrs = "0.7"

# HTTP client
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }

# Secure memory
zeroize = { version = "1.8", features = ["derive"] }
secrecy = { version = "0.10", features = ["serde"] }

# Cryptography
aes-gcm = "0.10"
rand = "0.8"
argon2 = "0.5"

# Scheduling
cron = "0.12"
chrono = { version = "0.4", features = ["serde"] }

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

# Error handling
thiserror = "2.0"
anyhow = "1.0"

# CLI
clap = { version = "4.5", features = ["derive"] }

# UUID
uuid = { version = "1.10", features = ["v4", "serde"] }

# Base64
base64 = "0.22"

[dev-dependencies]
tokio-test = "0.4"
wiremock = "0.6"
tempfile = "3.12"
```

## Core Implementation

### src/lib.rs

```rust
pub mod audit;
pub mod config;
pub mod error;
pub mod notification;
pub mod providers;
pub mod rotator;
pub mod storage;

pub use config::RotatorConfig;
pub use error::RotationError;
pub use rotator::RotationManager;
```

### src/error.rs

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RotationError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Provider error: {0}")]
    ProviderError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Notification error: {0}")]
    NotificationError(String),

    #[error("Rotation failed for {secret_name}: {reason}")]
    RotationFailed {
        secret_name: String,
        reason: String,
    },

    #[error("Rollback failed: {0}")]
    RollbackFailed(String),

    #[error("Secret not found: {0}")]
    SecretNotFound(String),

    #[error("Vault error: {0}")]
    VaultError(#[from] vaultrs::error::ClientError),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
}

pub type Result<T> = std::result::Result<T, RotationError>;
```

### src/config.rs

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RotatorConfig {
    pub vault: VaultConfig,
    pub storage: StorageConfig,
    pub notifications: NotificationConfig,
    pub secrets: Vec<SecretConfig>,
    pub audit: AuditConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VaultConfig {
    pub address: String,
    pub auth_method: AuthMethod,
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum AuthMethod {
    #[serde(rename = "token")]
    Token { token_path: PathBuf },
    #[serde(rename = "approle")]
    AppRole {
        role_id: String,
        secret_id_path: PathBuf,
    },
    #[serde(rename = "kubernetes")]
    Kubernetes { role: String },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    pub backend: StorageBackend,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum StorageBackend {
    #[serde(rename = "vault")]
    Vault { mount: String },
    #[serde(rename = "file")]
    File {
        path: PathBuf,
        key_file: PathBuf,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NotificationConfig {
    pub enabled: bool,
    pub slack: Option<SlackConfig>,
    pub email: Option<EmailConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SlackConfig {
    pub webhook_url: String,
    pub channel: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub from: String,
    pub to: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretConfig {
    pub name: String,
    pub provider: ProviderConfig,
    pub schedule: String,
    pub retention_count: usize,
    pub pre_rotation_hook: Option<String>,
    pub post_rotation_hook: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum ProviderConfig {
    #[serde(rename = "cloudflare")]
    Cloudflare {
        api_token_path: String,
        zone_id: Option<String>,
    },
    #[serde(rename = "aws")]
    Aws {
        access_key_id: String,
        user_name: String,
    },
    #[serde(rename = "database")]
    Database {
        vault_mount: String,
        role: String,
    },
    #[serde(rename = "vault_token")]
    VaultToken {
        policies: Vec<String>,
        ttl: String,
    },
    #[serde(rename = "generic")]
    Generic {
        generator: GeneratorConfig,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GeneratorConfig {
    pub length: usize,
    pub charset: String,
    pub prefix: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditConfig {
    pub enabled: bool,
    pub log_path: PathBuf,
    pub retention_days: u32,
}

impl RotatorConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let settings = config::Config::builder()
            .add_source(config::File::with_name(path))
            .add_source(config::Environment::with_prefix("ROTATOR"))
            .build()?;

        Ok(settings.try_deserialize()?)
    }
}
```

### src/rotator/manager.rs

```rust
use crate::audit::AuditLogger;
use crate::config::{RotatorConfig, SecretConfig};
use crate::error::{Result, RotationError};
use crate::notification::Notifier;
use crate::providers::SecretProvider;
use crate::storage::SecretStorage;
use chrono::{DateTime, Utc};
use secrecy::Secret;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Rotation event
#[derive(Debug, Clone)]
pub struct RotationEvent {
    pub id: Uuid,
    pub secret_name: String,
    pub timestamp: DateTime<Utc>,
    pub status: RotationStatus,
    pub old_version: Option<String>,
    pub new_version: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RotationStatus {
    Started,
    Completed,
    Failed,
    RolledBack,
}

/// Manages secret rotation
pub struct RotationManager {
    config: RotatorConfig,
    providers: HashMap<String, Arc<dyn SecretProvider>>,
    storage: Arc<dyn SecretStorage>,
    notifier: Arc<Notifier>,
    audit: Arc<AuditLogger>,
    state: Arc<RwLock<ManagerState>>,
}

#[derive(Debug, Default)]
struct ManagerState {
    last_rotation: HashMap<String, DateTime<Utc>>,
    rotation_history: Vec<RotationEvent>,
}

impl RotationManager {
    pub async fn new(config: RotatorConfig) -> Result<Self> {
        let storage = Self::create_storage(&config).await?;
        let notifier = Arc::new(Notifier::new(&config.notifications));
        let audit = Arc::new(AuditLogger::new(&config.audit)?);
        let providers = Self::create_providers(&config).await?;

        Ok(Self {
            config,
            providers,
            storage,
            notifier,
            audit,
            state: Arc::new(RwLock::new(ManagerState::default())),
        })
    }

    async fn create_storage(config: &RotatorConfig) -> Result<Arc<dyn SecretStorage>> {
        use crate::storage::{VaultStorage, FileStorage};

        match &config.storage.backend {
            crate::config::StorageBackend::Vault { mount } => {
                Ok(Arc::new(VaultStorage::new(&config.vault, mount).await?))
            }
            crate::config::StorageBackend::File { path, key_file } => {
                Ok(Arc::new(FileStorage::new(path, key_file)?))
            }
        }
    }

    async fn create_providers(
        config: &RotatorConfig,
    ) -> Result<HashMap<String, Arc<dyn SecretProvider>>> {
        use crate::providers::*;

        let mut providers = HashMap::new();

        for secret in &config.secrets {
            let provider: Arc<dyn SecretProvider> = match &secret.provider {
                crate::config::ProviderConfig::Cloudflare { api_token_path, zone_id } => {
                    Arc::new(CloudflareProvider::new(api_token_path, zone_id.clone()).await?)
                }
                crate::config::ProviderConfig::Aws { access_key_id, user_name } => {
                    Arc::new(AwsProvider::new(access_key_id, user_name).await?)
                }
                crate::config::ProviderConfig::Database { vault_mount, role } => {
                    Arc::new(DatabaseProvider::new(&config.vault, vault_mount, role).await?)
                }
                crate::config::ProviderConfig::VaultToken { policies, ttl } => {
                    Arc::new(VaultTokenProvider::new(&config.vault, policies.clone(), ttl).await?)
                }
                crate::config::ProviderConfig::Generic { generator } => {
                    Arc::new(GenericProvider::new(generator.clone()))
                }
            };

            providers.insert(secret.name.clone(), provider);
        }

        Ok(providers)
    }

    /// Rotate a specific secret
    pub async fn rotate(&self, secret_name: &str) -> Result<RotationEvent> {
        let secret_config = self
            .config
            .secrets
            .iter()
            .find(|s| s.name == secret_name)
            .ok_or_else(|| RotationError::SecretNotFound(secret_name.to_string()))?;

        let provider = self
            .providers
            .get(secret_name)
            .ok_or_else(|| RotationError::SecretNotFound(secret_name.to_string()))?;

        let event_id = Uuid::new_v4();
        let mut event = RotationEvent {
            id: event_id,
            secret_name: secret_name.to_string(),
            timestamp: Utc::now(),
            status: RotationStatus::Started,
            old_version: None,
            new_version: None,
            error: None,
        };

        info!(
            event_id = %event_id,
            secret = secret_name,
            "Starting secret rotation"
        );

        // Log start event
        self.audit.log_event(&event).await?;

        // Execute pre-rotation hook
        if let Some(hook) = &secret_config.pre_rotation_hook {
            self.execute_hook(hook).await?;
        }

        // Get current secret version
        let old_version = self.storage.get_current_version(secret_name).await.ok();
        event.old_version = old_version.clone();

        // Generate new secret
        let new_secret = match provider.generate().await {
            Ok(secret) => secret,
            Err(e) => {
                event.status = RotationStatus::Failed;
                event.error = Some(e.to_string());
                self.audit.log_event(&event).await?;
                self.notifier.notify_failure(&event).await;
                return Err(e);
            }
        };

        // Store new secret
        let new_version = match self
            .storage
            .store(secret_name, &new_secret, secret_config.retention_count)
            .await
        {
            Ok(version) => version,
            Err(e) => {
                event.status = RotationStatus::Failed;
                event.error = Some(e.to_string());
                self.audit.log_event(&event).await?;
                self.notifier.notify_failure(&event).await;
                return Err(e);
            }
        };

        event.new_version = Some(new_version.clone());

        // Activate new secret with provider
        if let Err(e) = provider.activate(&new_secret).await {
            // Rollback
            warn!(
                event_id = %event_id,
                secret = secret_name,
                error = %e,
                "Rotation failed, attempting rollback"
            );

            if let Err(rollback_err) = self.rollback(secret_name, &old_version).await {
                event.status = RotationStatus::Failed;
                event.error = Some(format!(
                    "Activation failed: {}. Rollback also failed: {}",
                    e, rollback_err
                ));
            } else {
                event.status = RotationStatus::RolledBack;
                event.error = Some(format!("Activation failed: {}. Rolled back.", e));
            }

            self.audit.log_event(&event).await?;
            self.notifier.notify_failure(&event).await;

            return Err(RotationError::RotationFailed {
                secret_name: secret_name.to_string(),
                reason: e.to_string(),
            });
        }

        // Revoke old secret if supported
        if let Some(old_ver) = &old_version {
            if let Err(e) = provider.revoke(old_ver).await {
                warn!(
                    event_id = %event_id,
                    secret = secret_name,
                    old_version = old_ver,
                    error = %e,
                    "Failed to revoke old secret (non-fatal)"
                );
            }
        }

        // Execute post-rotation hook
        if let Some(hook) = &secret_config.post_rotation_hook {
            if let Err(e) = self.execute_hook(hook).await {
                warn!(
                    event_id = %event_id,
                    secret = secret_name,
                    error = %e,
                    "Post-rotation hook failed (non-fatal)"
                );
            }
        }

        event.status = RotationStatus::Completed;

        info!(
            event_id = %event_id,
            secret = secret_name,
            new_version = %new_version,
            "Secret rotation completed"
        );

        // Update state
        {
            let mut state = self.state.write().await;
            state.last_rotation.insert(secret_name.to_string(), Utc::now());
            state.rotation_history.push(event.clone());
        }

        // Log and notify
        self.audit.log_event(&event).await?;
        self.notifier.notify_success(&event).await;

        Ok(event)
    }

    /// Rotate all secrets that are due
    pub async fn rotate_all(&self) -> Vec<Result<RotationEvent>> {
        let mut results = Vec::new();

        for secret in &self.config.secrets {
            if self.is_due_for_rotation(&secret.name, &secret.schedule).await {
                results.push(self.rotate(&secret.name).await);
            }
        }

        results
    }

    /// Check if a secret is due for rotation
    async fn is_due_for_rotation(&self, secret_name: &str, schedule: &str) -> bool {
        use cron::Schedule;
        use std::str::FromStr;

        let state = self.state.read().await;
        let last_rotation = state.last_rotation.get(secret_name);

        let schedule = match Schedule::from_str(schedule) {
            Ok(s) => s,
            Err(e) => {
                error!(secret = secret_name, error = %e, "Invalid cron schedule");
                return false;
            }
        };

        match last_rotation {
            Some(last) => {
                if let Some(next) = schedule.after(last).next() {
                    next <= Utc::now()
                } else {
                    false
                }
            }
            None => true, // Never rotated, rotate now
        }
    }

    /// Rollback to a previous version
    async fn rollback(&self, secret_name: &str, version: &Option<String>) -> Result<()> {
        if let Some(ver) = version {
            let secret = self.storage.get_version(secret_name, ver).await?;
            let provider = self
                .providers
                .get(secret_name)
                .ok_or_else(|| RotationError::SecretNotFound(secret_name.to_string()))?;

            provider.activate(&secret).await?;
            self.storage.set_current_version(secret_name, ver).await?;

            info!(secret = secret_name, version = ver, "Rolled back to previous version");
        }

        Ok(())
    }

    /// Execute a hook command
    async fn execute_hook(&self, hook: &str) -> Result<()> {
        use tokio::process::Command;

        let output = Command::new("sh")
            .arg("-c")
            .arg(hook)
            .output()
            .await
            .map_err(|e| RotationError::ProviderError(format!("Hook execution failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(RotationError::ProviderError(format!(
                "Hook failed with status {}: {}",
                output.status,
                stderr
            )));
        }

        Ok(())
    }

    /// Get rotation history
    pub async fn get_history(&self) -> Vec<RotationEvent> {
        let state = self.state.read().await;
        state.rotation_history.clone()
    }

    /// Force rotation of a secret
    pub async fn force_rotate(&self, secret_name: &str) -> Result<RotationEvent> {
        self.rotate(secret_name).await
    }
}
```

### src/providers/mod.rs

```rust
pub mod cloudflare;
pub mod aws;
pub mod database;
pub mod vault;
pub mod generic;

pub use cloudflare::CloudflareProvider;
pub use aws::AwsProvider;
pub use database::DatabaseProvider;
pub use vault::VaultTokenProvider;
pub use generic::GenericProvider;

use crate::error::Result;
use async_trait::async_trait;
use secrecy::Secret;

/// Trait for secret providers
#[async_trait]
pub trait SecretProvider: Send + Sync {
    /// Generate a new secret
    async fn generate(&self) -> Result<Secret<String>>;

    /// Activate a secret (make it the current one)
    async fn activate(&self, secret: &Secret<String>) -> Result<()>;

    /// Revoke an old secret
    async fn revoke(&self, version: &str) -> Result<()>;

    /// Get provider name
    fn name(&self) -> &str;
}
```

### src/providers/cloudflare.rs

```rust
use crate::error::{Result, RotationError};
use crate::providers::SecretProvider;
use async_trait::async_trait;
use reqwest::Client;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use tracing::info;

pub struct CloudflareProvider {
    client: Client,
    api_token: Secret<String>,
    zone_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreateTokenRequest {
    name: String,
    policies: Vec<TokenPolicy>,
}

#[derive(Debug, Serialize)]
struct TokenPolicy {
    effect: String,
    permission_groups: Vec<PermissionGroup>,
    resources: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct PermissionGroup {
    id: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    result: TokenResult,
    success: bool,
}

#[derive(Debug, Deserialize)]
struct TokenResult {
    id: String,
    value: Option<String>,
}

impl CloudflareProvider {
    pub async fn new(api_token_path: &str, zone_id: Option<String>) -> Result<Self> {
        let api_token = std::fs::read_to_string(api_token_path)
            .map_err(|e| RotationError::ConfigError(format!(
                "Failed to read API token: {}", e
            )))?;

        Ok(Self {
            client: Client::new(),
            api_token: Secret::new(api_token.trim().to_string()),
            zone_id,
        })
    }

    async fn create_api_token(&self, name: &str) -> Result<Secret<String>> {
        let request = CreateTokenRequest {
            name: name.to_string(),
            policies: vec![
                // Configure policies based on your needs
            ],
        };

        let response = self
            .client
            .post("https://api.cloudflare.com/client/v4/user/tokens")
            .bearer_auth(self.api_token.expose_secret())
            .json(&request)
            .send()
            .await?
            .json::<TokenResponse>()
            .await?;

        if !response.success {
            return Err(RotationError::ProviderError(
                "Failed to create Cloudflare token".to_string(),
            ));
        }

        let token_value = response
            .result
            .value
            .ok_or_else(|| RotationError::ProviderError("No token value returned".to_string()))?;

        info!("Created new Cloudflare API token");
        Ok(Secret::new(token_value))
    }

    async fn delete_api_token(&self, token_id: &str) -> Result<()> {
        let response = self
            .client
            .delete(format!(
                "https://api.cloudflare.com/client/v4/user/tokens/{}",
                token_id
            ))
            .bearer_auth(self.api_token.expose_secret())
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(RotationError::ProviderError(format!(
                "Failed to delete token: {}",
                response.status()
            )));
        }

        info!(token_id = token_id, "Deleted Cloudflare API token");
        Ok(())
    }
}

#[async_trait]
impl SecretProvider for CloudflareProvider {
    async fn generate(&self) -> Result<Secret<String>> {
        let name = format!("rotated-token-{}", chrono::Utc::now().timestamp());
        self.create_api_token(&name).await
    }

    async fn activate(&self, _secret: &Secret<String>) -> Result<()> {
        // Cloudflare tokens are active immediately upon creation
        Ok(())
    }

    async fn revoke(&self, version: &str) -> Result<()> {
        self.delete_api_token(version).await
    }

    fn name(&self) -> &str {
        "cloudflare"
    }
}
```

### src/providers/generic.rs

```rust
use crate::config::GeneratorConfig;
use crate::error::Result;
use crate::providers::SecretProvider;
use async_trait::async_trait;
use rand::Rng;
use secrecy::Secret;

pub struct GenericProvider {
    config: GeneratorConfig,
}

impl GenericProvider {
    pub fn new(config: GeneratorConfig) -> Self {
        Self { config }
    }

    fn generate_secret(&self) -> String {
        let charset: Vec<char> = self.config.charset.chars().collect();
        let mut rng = rand::thread_rng();

        let secret: String = (0..self.config.length)
            .map(|_| {
                let idx = rng.gen_range(0..charset.len());
                charset[idx]
            })
            .collect();

        match &self.config.prefix {
            Some(prefix) => format!("{}{}", prefix, secret),
            None => secret,
        }
    }
}

#[async_trait]
impl SecretProvider for GenericProvider {
    async fn generate(&self) -> Result<Secret<String>> {
        Ok(Secret::new(self.generate_secret()))
    }

    async fn activate(&self, _secret: &Secret<String>) -> Result<()> {
        // Generic secrets don't need activation
        Ok(())
    }

    async fn revoke(&self, _version: &str) -> Result<()> {
        // Generic secrets don't support revocation
        Ok(())
    }

    fn name(&self) -> &str {
        "generic"
    }
}
```

### src/storage/vault.rs

```rust
use crate::config::VaultConfig;
use crate::error::{Result, RotationError};
use async_trait::async_trait;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::kv2;

/// Secret version metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    pub version: String,
    pub created_at: String,
    pub is_current: bool,
}

/// Vault-based secret storage
pub struct VaultStorage {
    client: VaultClient,
    mount: String,
}

impl VaultStorage {
    pub async fn new(config: &VaultConfig, mount: &str) -> Result<Self> {
        let settings = VaultClientSettingsBuilder::default()
            .address(&config.address)
            .build()
            .map_err(|e| RotationError::ConfigError(e.to_string()))?;

        let client = VaultClient::new(settings)
            .map_err(|e| RotationError::StorageError(e.to_string()))?;

        Ok(Self {
            client,
            mount: mount.to_string(),
        })
    }

    fn secret_path(&self, name: &str) -> String {
        format!("rotator/{}", name)
    }

    fn metadata_path(&self, name: &str) -> String {
        format!("rotator/{}/metadata", name)
    }
}

#[async_trait]
pub trait SecretStorage: Send + Sync {
    async fn store(
        &self,
        name: &str,
        secret: &Secret<String>,
        retention_count: usize,
    ) -> Result<String>;

    async fn get_current(&self, name: &str) -> Result<Secret<String>>;

    async fn get_version(&self, name: &str, version: &str) -> Result<Secret<String>>;

    async fn get_current_version(&self, name: &str) -> Result<String>;

    async fn set_current_version(&self, name: &str, version: &str) -> Result<()>;

    async fn list_versions(&self, name: &str) -> Result<Vec<SecretVersion>>;

    async fn delete_version(&self, name: &str, version: &str) -> Result<()>;
}

#[async_trait]
impl SecretStorage for VaultStorage {
    async fn store(
        &self,
        name: &str,
        secret: &Secret<String>,
        retention_count: usize,
    ) -> Result<String> {
        let version = uuid::Uuid::new_v4().to_string();
        let path = format!("{}/{}", self.secret_path(name), version);

        let mut data = HashMap::new();
        data.insert("value".to_string(), secret.expose_secret().clone());
        data.insert("version".to_string(), version.clone());
        data.insert("created_at".to_string(), chrono::Utc::now().to_rfc3339());

        kv2::set(&self.client, &self.mount, &path, &data)
            .await
            .map_err(|e| RotationError::StorageError(e.to_string()))?;

        // Update current version
        self.set_current_version(name, &version).await?;

        // Clean up old versions
        self.cleanup_old_versions(name, retention_count).await?;

        Ok(version)
    }

    async fn get_current(&self, name: &str) -> Result<Secret<String>> {
        let version = self.get_current_version(name).await?;
        self.get_version(name, &version).await
    }

    async fn get_version(&self, name: &str, version: &str) -> Result<Secret<String>> {
        let path = format!("{}/{}", self.secret_path(name), version);

        let data: HashMap<String, String> = kv2::read(&self.client, &self.mount, &path)
            .await
            .map_err(|e| RotationError::StorageError(e.to_string()))?;

        let value = data
            .get("value")
            .ok_or_else(|| RotationError::StorageError("Secret value not found".to_string()))?;

        Ok(Secret::new(value.clone()))
    }

    async fn get_current_version(&self, name: &str) -> Result<String> {
        let path = self.metadata_path(name);

        let data: HashMap<String, String> = kv2::read(&self.client, &self.mount, &path)
            .await
            .map_err(|e| RotationError::StorageError(e.to_string()))?;

        data.get("current_version")
            .cloned()
            .ok_or_else(|| RotationError::SecretNotFound(name.to_string()))
    }

    async fn set_current_version(&self, name: &str, version: &str) -> Result<()> {
        let path = self.metadata_path(name);

        let mut data = HashMap::new();
        data.insert("current_version".to_string(), version.to_string());
        data.insert("updated_at".to_string(), chrono::Utc::now().to_rfc3339());

        kv2::set(&self.client, &self.mount, &path, &data)
            .await
            .map_err(|e| RotationError::StorageError(e.to_string()))?;

        Ok(())
    }

    async fn list_versions(&self, name: &str) -> Result<Vec<SecretVersion>> {
        let path = self.secret_path(name);

        let keys = kv2::list(&self.client, &self.mount, &path)
            .await
            .map_err(|e| RotationError::StorageError(e.to_string()))?;

        let current = self.get_current_version(name).await.ok();

        let versions: Vec<SecretVersion> = keys
            .into_iter()
            .map(|k| SecretVersion {
                is_current: current.as_ref() == Some(&k),
                version: k,
                created_at: String::new(), // Would need to fetch metadata
            })
            .collect();

        Ok(versions)
    }

    async fn delete_version(&self, name: &str, version: &str) -> Result<()> {
        let path = format!("{}/{}", self.secret_path(name), version);

        kv2::delete_latest(&self.client, &self.mount, &path)
            .await
            .map_err(|e| RotationError::StorageError(e.to_string()))?;

        Ok(())
    }
}

impl VaultStorage {
    async fn cleanup_old_versions(&self, name: &str, retention_count: usize) -> Result<()> {
        let versions = self.list_versions(name).await?;

        if versions.len() > retention_count {
            let to_delete = versions.len() - retention_count;
            for version in versions.iter().take(to_delete) {
                if !version.is_current {
                    self.delete_version(name, &version.version).await?;
                }
            }
        }

        Ok(())
    }
}
```

### src/main.rs

```rust
use clap::{Parser, Subcommand};
use my_token_rotator::{RotationManager, RotatorConfig};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "token-rotator")]
#[command(about = "Automated token and secret rotation")]
struct Cli {
    #[arg(short, long, default_value = "config/rotator.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Rotate a specific secret
    Rotate {
        /// Secret name to rotate
        name: String,
    },
    /// Rotate all secrets that are due
    RotateAll,
    /// List configured secrets
    List,
    /// Show rotation history
    History {
        /// Secret name (optional, shows all if not specified)
        name: Option<String>,
    },
    /// Run as a daemon
    Daemon,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();
    let config = RotatorConfig::load(&cli.config)?;
    let manager = RotationManager::new(config.clone()).await?;

    match cli.command {
        Commands::Rotate { name } => {
            let event = manager.rotate(&name).await?;
            println!("Rotation completed: {:?}", event.status);
        }
        Commands::RotateAll => {
            let results = manager.rotate_all().await;
            for result in results {
                match result {
                    Ok(event) => println!("{}: {:?}", event.secret_name, event.status),
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
        }
        Commands::List => {
            for secret in &config.secrets {
                println!("- {} (schedule: {})", secret.name, secret.schedule);
            }
        }
        Commands::History { name } => {
            let history = manager.get_history().await;
            for event in history {
                if name.is_none() || name.as_ref() == Some(&event.secret_name) {
                    println!(
                        "{} | {} | {:?}",
                        event.timestamp, event.secret_name, event.status
                    );
                }
            }
        }
        Commands::Daemon => {
            run_daemon(manager).await?;
        }
    }

    Ok(())
}

async fn run_daemon(manager: RotationManager) -> anyhow::Result<()> {
    use tokio::time::{interval, Duration};

    tracing::info!("Starting token rotator daemon");

    let mut check_interval = interval(Duration::from_secs(60));

    loop {
        check_interval.tick().await;

        let results = manager.rotate_all().await;
        for result in results {
            if let Err(e) = result {
                tracing::error!(error = %e, "Rotation failed");
            }
        }
    }
}
```

## Configuration Example

### config/rotator.toml

```toml
[vault]
address = "https://vault.example.com:8200"
namespace = "my-namespace"

[vault.auth_method]
type = "approle"
role_id = "my-role-id"
secret_id_path = "/etc/rotator/secret-id"

[storage.backend]
type = "vault"
mount = "secret"

[notifications]
enabled = true

[notifications.slack]
webhook_url = "https://hooks.slack.com/services/..."
channel = "#security-alerts"

[audit]
enabled = true
log_path = "/var/log/rotator/audit.log"
retention_days = 90

[[secrets]]
name = "cloudflare-api-token"
schedule = "0 0 * * 0"  # Weekly on Sunday
retention_count = 3

[secrets.provider]
type = "cloudflare"
api_token_path = "/etc/rotator/cloudflare-admin-token"

[[secrets]]
name = "database-password"
schedule = "0 0 1 * *"  # Monthly
retention_count = 2

[secrets.provider]
type = "database"
vault_mount = "database"
role = "readonly"

[[secrets]]
name = "api-key"
schedule = "0 0 * * *"  # Daily
retention_count = 7

[secrets.provider]
type = "generic"

[secrets.provider.generator]
length = 32
charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
prefix = "sk_"
```

## Security Checklist

- [ ] Rotator credentials stored securely
- [ ] Audit logging enabled and protected
- [ ] Notifications configured for failures
- [ ] Rollback tested and working
- [ ] Retention policy configured
- [ ] Pre/post rotation hooks validated
- [ ] Network access restricted to necessary services
- [ ] TLS/mTLS for all communications
- [ ] Secrets zeroized after use
- [ ] Daemon runs with minimal privileges
