# Rust Vault Client Template

## Overview

This template provides a secure HashiCorp Vault client implementation in Rust
using the vaultrs crate. It enables secure secret retrieval, dynamic credential
management, Transit engine encryption, and PKI certificate operations with
proper error handling and retry logic.

**Target Use Cases:**

- Application secret retrieval
- Dynamic database credentials
- Transit engine encryption/decryption
- PKI certificate management
- Token and lease renewal
- AppRole authentication

## Project Structure

```
my-vault-client/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── client.rs              # Vault client wrapper
│   ├── auth/
│   │   ├── mod.rs
│   │   ├── token.rs           # Token authentication
│   │   ├── approle.rs         # AppRole authentication
│   │   └── kubernetes.rs      # Kubernetes authentication
│   ├── secrets/
│   │   ├── mod.rs
│   │   ├── kv.rs              # KV secrets engine
│   │   ├── database.rs        # Database secrets engine
│   │   └── pki.rs             # PKI secrets engine
│   ├── transit/
│   │   ├── mod.rs
│   │   └── encrypt.rs         # Transit encryption
│   ├── lease.rs               # Lease management
│   └── error.rs               # Error types
├── examples/
│   ├── basic_usage.rs
│   ├── database_creds.rs
│   └── transit_encryption.rs
├── tests/
│   └── integration_tests.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-vault-client"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"

[dependencies]
# Vault client
vaultrs = "0.7"
vaultrs-login = "0.2"

# Async runtime
tokio = { version = "1.40", features = ["full"] }

# HTTP client
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Secure memory
zeroize = { version = "1.8", features = ["derive"] }
secrecy = { version = "0.10", features = ["serde"] }

# Error handling
thiserror = "2.0"
anyhow = "1.0"

# Logging
tracing = "0.1"

# Time
chrono = { version = "0.4", features = ["serde"] }

# Base64
base64 = "0.22"

# Retry logic
backoff = { version = "0.4", features = ["tokio"] }

[dev-dependencies]
tokio-test = "0.4"
wiremock = "0.6"

[features]
default = []
kubernetes = []
```

## Core Implementation

### src/lib.rs

```rust
pub mod auth;
pub mod client;
pub mod error;
pub mod lease;
pub mod secrets;
pub mod transit;

pub use client::VaultClient;
pub use error::VaultError;
```

### src/error.rs

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Secret not found: {0}")]
    SecretNotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Lease expired: {0}")]
    LeaseExpired(String),

    #[error("Transit operation failed: {0}")]
    TransitError(String),

    #[error("PKI operation failed: {0}")]
    PkiError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Invalid configuration: {0}")]
    ConfigurationError(String),

    #[error("Vault error: {0}")]
    VaultApiError(#[from] vaultrs::error::ClientError),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, VaultError>;
```

### src/client.rs

```rust
use crate::auth::{AppRoleAuth, TokenAuth};
use crate::error::{Result, VaultError};
use crate::secrets::{DatabaseSecrets, KvSecrets, PkiSecrets};
use crate::transit::TransitEngine;
use secrecy::{ExposeSecret, Secret};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use vaultrs::client::{VaultClient as VaultrsClient, VaultClientSettingsBuilder};

/// Configuration for the Vault client
#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub address: String,
    pub namespace: Option<String>,
    pub ca_cert: Option<String>,
    pub timeout_secs: u64,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            address: std::env::var("VAULT_ADDR")
                .unwrap_or_else(|_| "http://127.0.0.1:8200".to_string()),
            namespace: std::env::var("VAULT_NAMESPACE").ok(),
            ca_cert: std::env::var("VAULT_CACERT").ok(),
            timeout_secs: 30,
        }
    }
}

/// Vault client wrapper with authentication and secret management
pub struct VaultClient {
    inner: Arc<RwLock<VaultrsClient>>,
    config: VaultConfig,
    token: Arc<RwLock<Option<Secret<String>>>>,
}

impl VaultClient {
    /// Create a new Vault client
    pub async fn new(config: VaultConfig) -> Result<Self> {
        let settings = VaultClientSettingsBuilder::default()
            .address(&config.address)
            .timeout(Some(std::time::Duration::from_secs(config.timeout_secs)))
            .build()
            .map_err(|e| VaultError::ConfigurationError(e.to_string()))?;

        let client = VaultrsClient::new(settings)
            .map_err(|e| VaultError::ConnectionError(e.to_string()))?;

        Ok(Self {
            inner: Arc::new(RwLock::new(client)),
            config,
            token: Arc::new(RwLock::new(None)),
        })
    }

    /// Authenticate with a token
    pub async fn auth_with_token(&self, token: Secret<String>) -> Result<()> {
        let mut client = self.inner.write().await;
        client.set_token(token.expose_secret());

        let mut token_guard = self.token.write().await;
        *token_guard = Some(token);

        info!("Authenticated with token");
        Ok(())
    }

    /// Authenticate with AppRole
    pub async fn auth_with_approle(
        &self,
        role_id: &str,
        secret_id: &Secret<String>,
    ) -> Result<()> {
        use vaultrs::auth::approle;

        let client = self.inner.read().await;
        let auth_info = approle::login(
            &*client,
            "approle",
            role_id,
            secret_id.expose_secret(),
        )
        .await
        .map_err(|e| VaultError::AuthenticationFailed(e.to_string()))?;

        drop(client);

        let token = Secret::new(auth_info.client_token);
        self.auth_with_token(token).await?;

        info!("Authenticated with AppRole");
        Ok(())
    }

    /// Authenticate with Kubernetes service account
    #[cfg(feature = "kubernetes")]
    pub async fn auth_with_kubernetes(&self, role: &str) -> Result<()> {
        use vaultrs::auth::kubernetes;
        use std::fs;

        let jwt = fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
            .map_err(|e| VaultError::AuthenticationFailed(format!(
                "Failed to read service account token: {}", e
            )))?;

        let client = self.inner.read().await;
        let auth_info = kubernetes::login(&*client, "kubernetes", role, &jwt)
            .await
            .map_err(|e| VaultError::AuthenticationFailed(e.to_string()))?;

        drop(client);

        let token = Secret::new(auth_info.client_token);
        self.auth_with_token(token).await?;

        info!("Authenticated with Kubernetes");
        Ok(())
    }

    /// Get KV secrets engine
    pub fn kv(&self, mount: &str) -> KvSecrets {
        KvSecrets::new(self.inner.clone(), mount.to_string())
    }

    /// Get database secrets engine
    pub fn database(&self, mount: &str) -> DatabaseSecrets {
        DatabaseSecrets::new(self.inner.clone(), mount.to_string())
    }

    /// Get PKI secrets engine
    pub fn pki(&self, mount: &str) -> PkiSecrets {
        PkiSecrets::new(self.inner.clone(), mount.to_string())
    }

    /// Get transit engine
    pub fn transit(&self, mount: &str) -> TransitEngine {
        TransitEngine::new(self.inner.clone(), mount.to_string())
    }

    /// Check if client is authenticated
    pub async fn is_authenticated(&self) -> bool {
        self.token.read().await.is_some()
    }

    /// Renew the current token
    pub async fn renew_token(&self) -> Result<()> {
        use vaultrs::auth::token;

        let client = self.inner.read().await;
        token::renew_self(&*client, None)
            .await
            .map_err(|e| VaultError::AuthenticationFailed(format!(
                "Token renewal failed: {}", e
            )))?;

        info!("Token renewed successfully");
        Ok(())
    }
}
```

### src/secrets/kv.rs

```rust
use crate::error::{Result, VaultError};
use secrecy::{ExposeSecret, Secret};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;
use vaultrs::client::VaultClient;
use vaultrs::kv2;
use zeroize::Zeroize;

/// KV version 2 secrets engine client
pub struct KvSecrets {
    client: Arc<RwLock<VaultClient>>,
    mount: String,
}

impl KvSecrets {
    pub fn new(client: Arc<RwLock<VaultClient>>, mount: String) -> Self {
        Self { client, mount }
    }

    /// Read a secret from KV store
    pub async fn read<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let client = self.client.read().await;
        let secret: T = kv2::read(&*client, &self.mount, path)
            .await
            .map_err(|e| match e {
                vaultrs::error::ClientError::APIError { code: 404, .. } => {
                    VaultError::SecretNotFound(path.to_string())
                }
                vaultrs::error::ClientError::APIError { code: 403, .. } => {
                    VaultError::PermissionDenied(path.to_string())
                }
                _ => VaultError::VaultApiError(e),
            })?;

        debug!("Read secret from {}/{}", self.mount, path);
        Ok(secret)
    }

    /// Read a secret as a secure string map
    pub async fn read_map(&self, path: &str) -> Result<HashMap<String, Secret<String>>> {
        let data: HashMap<String, String> = self.read(path).await?;

        let secure_map: HashMap<String, Secret<String>> = data
            .into_iter()
            .map(|(k, v)| (k, Secret::new(v)))
            .collect();

        Ok(secure_map)
    }

    /// Write a secret to KV store
    pub async fn write<T: Serialize>(&self, path: &str, data: &T) -> Result<()> {
        let client = self.client.read().await;
        kv2::set(&*client, &self.mount, path, data)
            .await
            .map_err(|e| match e {
                vaultrs::error::ClientError::APIError { code: 403, .. } => {
                    VaultError::PermissionDenied(path.to_string())
                }
                _ => VaultError::VaultApiError(e),
            })?;

        debug!("Wrote secret to {}/{}", self.mount, path);
        Ok(())
    }

    /// Delete a secret from KV store
    pub async fn delete(&self, path: &str) -> Result<()> {
        let client = self.client.read().await;
        kv2::delete_latest(&*client, &self.mount, path)
            .await
            .map_err(|e| VaultError::VaultApiError(e))?;

        debug!("Deleted secret at {}/{}", self.mount, path);
        Ok(())
    }

    /// List secrets at a path
    pub async fn list(&self, path: &str) -> Result<Vec<String>> {
        let client = self.client.read().await;
        let keys = kv2::list(&*client, &self.mount, path)
            .await
            .map_err(|e| VaultError::VaultApiError(e))?;

        Ok(keys)
    }

    /// Read a specific version of a secret
    pub async fn read_version<T: DeserializeOwned>(
        &self,
        path: &str,
        version: u64,
    ) -> Result<T> {
        let client = self.client.read().await;
        let secret: T = kv2::read_version(&*client, &self.mount, path, version)
            .await
            .map_err(|e| VaultError::VaultApiError(e))?;

        Ok(secret)
    }
}

/// Secure secret wrapper that zeroizes on drop
#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct SecureSecret {
    data: HashMap<String, String>,
}

impl SecureSecret {
    pub fn new(data: HashMap<String, String>) -> Self {
        Self { data }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.data.get(key).map(|s| s.as_str())
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.data.keys()
    }
}
```

### src/secrets/database.rs

```rust
use crate::error::{Result, VaultError};
use secrecy::Secret;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};
use vaultrs::client::VaultClient;
use vaultrs::api::database::requests::GenerateCredentialsRequest;
use zeroize::Zeroize;

/// Database credentials with automatic cleanup
#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct DatabaseCredentials {
    pub username: String,
    pub password: String,
    #[zeroize(skip)]
    pub lease_id: String,
    #[zeroize(skip)]
    pub lease_duration: u64,
}

/// Database secrets engine client
pub struct DatabaseSecrets {
    client: Arc<RwLock<VaultClient>>,
    mount: String,
}

impl DatabaseSecrets {
    pub fn new(client: Arc<RwLock<VaultClient>>, mount: String) -> Self {
        Self { client, mount }
    }

    /// Generate dynamic database credentials
    pub async fn get_credentials(&self, role: &str) -> Result<DatabaseCredentials> {
        let client = self.client.read().await;

        let response = vaultrs::database::creds::generate(&*client, &self.mount, role)
            .await
            .map_err(|e| match e {
                vaultrs::error::ClientError::APIError { code: 403, .. } => {
                    VaultError::PermissionDenied(format!("database role: {}", role))
                }
                _ => VaultError::VaultApiError(e),
            })?;

        info!(
            role = role,
            lease_duration = response.lease_duration,
            "Generated database credentials"
        );

        Ok(DatabaseCredentials {
            username: response.username,
            password: response.password,
            lease_id: response.lease_id,
            lease_duration: response.lease_duration,
        })
    }

    /// Renew database credential lease
    pub async fn renew_lease(&self, lease_id: &str, increment: Option<u64>) -> Result<u64> {
        let client = self.client.read().await;

        let response = vaultrs::sys::lease::renew(&*client, lease_id, increment)
            .await
            .map_err(|e| VaultError::VaultApiError(e))?;

        debug!(
            lease_id = lease_id,
            new_duration = response.lease_duration,
            "Renewed database credential lease"
        );

        Ok(response.lease_duration)
    }

    /// Revoke database credential lease
    pub async fn revoke_lease(&self, lease_id: &str) -> Result<()> {
        let client = self.client.read().await;

        vaultrs::sys::lease::revoke(&*client, lease_id)
            .await
            .map_err(|e| VaultError::VaultApiError(e))?;

        info!(lease_id = lease_id, "Revoked database credential lease");
        Ok(())
    }
}

/// Connection string builder for database credentials
impl DatabaseCredentials {
    /// Build PostgreSQL connection string
    pub fn postgres_url(&self, host: &str, port: u16, database: &str) -> Secret<String> {
        Secret::new(format!(
            "postgres://{}:{}@{}:{}/{}",
            self.username, self.password, host, port, database
        ))
    }

    /// Build MySQL connection string
    pub fn mysql_url(&self, host: &str, port: u16, database: &str) -> Secret<String> {
        Secret::new(format!(
            "mysql://{}:{}@{}:{}/{}",
            self.username, self.password, host, port, database
        ))
    }

    /// Build MongoDB connection string
    pub fn mongodb_url(&self, host: &str, port: u16, database: &str) -> Secret<String> {
        Secret::new(format!(
            "mongodb://{}:{}@{}:{}/{}",
            self.username, self.password, host, port, database
        ))
    }
}
```

### src/transit/mod.rs

```rust
use crate::error::{Result, VaultError};
use base64::Engine;
use secrecy::{ExposeSecret, Secret};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;
use vaultrs::client::VaultClient;
use vaultrs::transit;
use zeroize::Zeroize;

/// Transit secrets engine for encryption operations
pub struct TransitEngine {
    client: Arc<RwLock<VaultClient>>,
    mount: String,
}

impl TransitEngine {
    pub fn new(client: Arc<RwLock<VaultClient>>, mount: String) -> Self {
        Self { client, mount }
    }

    /// Encrypt plaintext using a named key
    pub async fn encrypt(&self, key_name: &str, plaintext: &[u8]) -> Result<String> {
        let client = self.client.read().await;

        // Base64 encode the plaintext
        let b64_plaintext = base64::engine::general_purpose::STANDARD.encode(plaintext);

        let response = transit::data::encrypt(
            &*client,
            &self.mount,
            key_name,
            &b64_plaintext,
            None,
        )
        .await
        .map_err(|e| VaultError::TransitError(e.to_string()))?;

        debug!(key = key_name, "Encrypted data with Transit");
        Ok(response.ciphertext)
    }

    /// Decrypt ciphertext using a named key
    pub async fn decrypt(&self, key_name: &str, ciphertext: &str) -> Result<Vec<u8>> {
        let client = self.client.read().await;

        let response = transit::data::decrypt(
            &*client,
            &self.mount,
            key_name,
            ciphertext,
            None,
        )
        .await
        .map_err(|e| VaultError::TransitError(e.to_string()))?;

        // Base64 decode the plaintext
        let plaintext = base64::engine::general_purpose::STANDARD
            .decode(&response.plaintext)
            .map_err(|e| VaultError::TransitError(format!("Invalid base64: {}", e)))?;

        debug!(key = key_name, "Decrypted data with Transit");
        Ok(plaintext)
    }

    /// Encrypt a string
    pub async fn encrypt_string(&self, key_name: &str, plaintext: &str) -> Result<String> {
        self.encrypt(key_name, plaintext.as_bytes()).await
    }

    /// Decrypt to a string
    pub async fn decrypt_string(&self, key_name: &str, ciphertext: &str) -> Result<String> {
        let plaintext = self.decrypt(key_name, ciphertext).await?;
        String::from_utf8(plaintext)
            .map_err(|e| VaultError::TransitError(format!("Invalid UTF-8: {}", e)))
    }

    /// Rewrap ciphertext with a new key version
    pub async fn rewrap(&self, key_name: &str, ciphertext: &str) -> Result<String> {
        let client = self.client.read().await;

        let response = transit::data::rewrap(
            &*client,
            &self.mount,
            key_name,
            ciphertext,
            None,
        )
        .await
        .map_err(|e| VaultError::TransitError(e.to_string()))?;

        debug!(key = key_name, "Rewrapped ciphertext");
        Ok(response.ciphertext)
    }

    /// Generate a data key for local encryption
    pub async fn generate_data_key(
        &self,
        key_name: &str,
        bits: u32,
    ) -> Result<DataKey> {
        let client = self.client.read().await;

        let response = transit::key::generate_data_key(
            &*client,
            &self.mount,
            key_name,
            bits,
        )
        .await
        .map_err(|e| VaultError::TransitError(e.to_string()))?;

        let plaintext_key = base64::engine::general_purpose::STANDARD
            .decode(&response.plaintext)
            .map_err(|e| VaultError::TransitError(format!("Invalid base64: {}", e)))?;

        debug!(key = key_name, bits = bits, "Generated data key");

        Ok(DataKey {
            plaintext: Secret::new(plaintext_key),
            ciphertext: response.ciphertext,
        })
    }

    /// Create a new encryption key
    pub async fn create_key(&self, key_name: &str, key_type: &str) -> Result<()> {
        let client = self.client.read().await;

        transit::key::create(&*client, &self.mount, key_name, Some(key_type))
            .await
            .map_err(|e| VaultError::TransitError(e.to_string()))?;

        debug!(key = key_name, key_type = key_type, "Created Transit key");
        Ok(())
    }

    /// Rotate an encryption key
    pub async fn rotate_key(&self, key_name: &str) -> Result<()> {
        let client = self.client.read().await;

        transit::key::rotate(&*client, &self.mount, key_name)
            .await
            .map_err(|e| VaultError::TransitError(e.to_string()))?;

        debug!(key = key_name, "Rotated Transit key");
        Ok(())
    }

    /// Sign data
    pub async fn sign(
        &self,
        key_name: &str,
        data: &[u8],
        hash_algorithm: Option<&str>,
    ) -> Result<String> {
        let client = self.client.read().await;

        let b64_data = base64::engine::general_purpose::STANDARD.encode(data);

        let response = transit::data::sign(
            &*client,
            &self.mount,
            key_name,
            &b64_data,
            hash_algorithm,
            None,
        )
        .await
        .map_err(|e| VaultError::TransitError(e.to_string()))?;

        debug!(key = key_name, "Signed data");
        Ok(response.signature)
    }

    /// Verify a signature
    pub async fn verify(
        &self,
        key_name: &str,
        data: &[u8],
        signature: &str,
        hash_algorithm: Option<&str>,
    ) -> Result<bool> {
        let client = self.client.read().await;

        let b64_data = base64::engine::general_purpose::STANDARD.encode(data);

        let response = transit::data::verify(
            &*client,
            &self.mount,
            key_name,
            &b64_data,
            signature,
            hash_algorithm,
            None,
        )
        .await
        .map_err(|e| VaultError::TransitError(e.to_string()))?;

        debug!(key = key_name, valid = response.valid, "Verified signature");
        Ok(response.valid)
    }
}

/// Data key for envelope encryption
pub struct DataKey {
    /// Plaintext key (use for local encryption, then discard)
    pub plaintext: Secret<Vec<u8>>,
    /// Encrypted key (store alongside encrypted data)
    pub ciphertext: String,
}

impl DataKey {
    /// Get the plaintext key bytes
    pub fn key_bytes(&self) -> &[u8] {
        self.plaintext.expose_secret()
    }
}
```

### src/secrets/pki.rs

```rust
use crate::error::{Result, VaultError};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};
use vaultrs::client::VaultClient;
use vaultrs::pki;
use zeroize::Zeroize;

/// PKI certificate with private key
#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct Certificate {
    #[zeroize(skip)]
    pub certificate: String,
    pub private_key: String,
    #[zeroize(skip)]
    pub ca_chain: Vec<String>,
    #[zeroize(skip)]
    pub serial_number: String,
    #[zeroize(skip)]
    pub expiration: i64,
}

/// PKI secrets engine client
pub struct PkiSecrets {
    client: Arc<RwLock<VaultClient>>,
    mount: String,
}

impl PkiSecrets {
    pub fn new(client: Arc<RwLock<VaultClient>>, mount: String) -> Self {
        Self { client, mount }
    }

    /// Issue a new certificate
    pub async fn issue_certificate(
        &self,
        role: &str,
        common_name: &str,
        ttl: Option<&str>,
        alt_names: Option<Vec<String>>,
        ip_sans: Option<Vec<String>>,
    ) -> Result<Certificate> {
        let client = self.client.read().await;

        let mut request = pki::requests::GenerateCertificateRequest::builder()
            .common_name(common_name);

        if let Some(ttl_value) = ttl {
            request = request.ttl(ttl_value);
        }

        if let Some(names) = alt_names {
            request = request.alt_names(names.join(","));
        }

        if let Some(ips) = ip_sans {
            request = request.ip_sans(ips.join(","));
        }

        let response = pki::cert::generate(&*client, &self.mount, role, request.build().unwrap())
            .await
            .map_err(|e| VaultError::PkiError(e.to_string()))?;

        info!(
            role = role,
            common_name = common_name,
            serial = %response.serial_number,
            "Issued PKI certificate"
        );

        Ok(Certificate {
            certificate: response.certificate,
            private_key: response.private_key.unwrap_or_default(),
            ca_chain: response.ca_chain.unwrap_or_default(),
            serial_number: response.serial_number,
            expiration: response.expiration,
        })
    }

    /// Revoke a certificate
    pub async fn revoke_certificate(&self, serial_number: &str) -> Result<()> {
        let client = self.client.read().await;

        pki::cert::revoke(&*client, &self.mount, serial_number)
            .await
            .map_err(|e| VaultError::PkiError(e.to_string()))?;

        info!(serial = serial_number, "Revoked PKI certificate");
        Ok(())
    }

    /// Get the CA certificate
    pub async fn get_ca_certificate(&self) -> Result<String> {
        let client = self.client.read().await;

        let response = pki::cert::ca(&*client, &self.mount)
            .await
            .map_err(|e| VaultError::PkiError(e.to_string()))?;

        Ok(response)
    }

    /// Get the CA chain
    pub async fn get_ca_chain(&self) -> Result<String> {
        let client = self.client.read().await;

        let response = pki::cert::ca_chain(&*client, &self.mount)
            .await
            .map_err(|e| VaultError::PkiError(e.to_string()))?;

        Ok(response)
    }

    /// List certificates
    pub async fn list_certificates(&self) -> Result<Vec<String>> {
        let client = self.client.read().await;

        let response = pki::cert::list(&*client, &self.mount)
            .await
            .map_err(|e| VaultError::PkiError(e.to_string()))?;

        Ok(response)
    }

    /// Read a certificate by serial number
    pub async fn read_certificate(&self, serial: &str) -> Result<String> {
        let client = self.client.read().await;

        let response = pki::cert::read(&*client, &self.mount, serial)
            .await
            .map_err(|e| VaultError::PkiError(e.to_string()))?;

        Ok(response.certificate)
    }
}
```

## Usage Examples

### examples/basic_usage.rs

```rust
use my_vault_client::{VaultClient, VaultConfig};
use secrecy::Secret;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize client
    let config = VaultConfig::default();
    let client = VaultClient::new(config).await?;

    // Authenticate with token
    let token = Secret::new(std::env::var("VAULT_TOKEN")?);
    client.auth_with_token(token).await?;

    // Read a secret
    let kv = client.kv("secret");
    let secret: HashMap<String, String> = kv.read("myapp/config").await?;
    println!("Database host: {}", secret.get("db_host").unwrap_or(&"".to_string()));

    // Write a secret
    let mut new_secret = HashMap::new();
    new_secret.insert("api_key".to_string(), "new-secret-value".to_string());
    kv.write("myapp/api", &new_secret).await?;

    Ok(())
}
```

### examples/database_creds.rs

```rust
use my_vault_client::{VaultClient, VaultConfig};
use secrecy::{ExposeSecret, Secret};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = VaultClient::new(VaultConfig::default()).await?;

    // Authenticate
    let token = Secret::new(std::env::var("VAULT_TOKEN")?);
    client.auth_with_token(token).await?;

    // Get dynamic database credentials
    let db = client.database("database");
    let creds = db.get_credentials("readonly").await?;

    println!("Username: {}", creds.username);
    println!("Lease duration: {} seconds", creds.lease_duration);

    // Build connection string
    let conn_string = creds.postgres_url("localhost", 5432, "mydb");

    // Use credentials...
    // (credentials are automatically zeroized when dropped)

    // Renew lease if needed
    let new_duration = db.renew_lease(&creds.lease_id, Some(3600)).await?;
    println!("Renewed lease for {} seconds", new_duration);

    Ok(())
}
```

### examples/transit_encryption.rs

```rust
use my_vault_client::{VaultClient, VaultConfig};
use secrecy::{ExposeSecret, Secret};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = VaultClient::new(VaultConfig::default()).await?;

    let token = Secret::new(std::env::var("VAULT_TOKEN")?);
    client.auth_with_token(token).await?;

    let transit = client.transit("transit");

    // Encrypt data
    let plaintext = "sensitive data";
    let ciphertext = transit.encrypt_string("my-key", plaintext).await?;
    println!("Encrypted: {}", ciphertext);

    // Decrypt data
    let decrypted = transit.decrypt_string("my-key", &ciphertext).await?;
    println!("Decrypted: {}", decrypted);

    // Generate data key for envelope encryption
    let data_key = transit.generate_data_key("my-key", 256).await?;
    println!("Encrypted data key: {}", data_key.ciphertext);

    // Use plaintext key for local encryption, store encrypted key with data
    let local_key = data_key.key_bytes();
    // ... encrypt locally with local_key ...

    Ok(())
}
```

## Security Checklist

- [ ] Vault token stored securely (not in code)
- [ ] AppRole secret ID rotated regularly
- [ ] Lease renewal handled automatically
- [ ] Credentials zeroized after use
- [ ] TLS/mTLS enabled for Vault communication
- [ ] Audit logging enabled in Vault
- [ ] Policies follow principle of least privilege
- [ ] Token TTL kept short with renewal
- [ ] Response wrapping used for sensitive operations
- [ ] Namespace isolation configured
