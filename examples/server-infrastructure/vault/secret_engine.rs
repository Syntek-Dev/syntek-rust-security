//! HashiCorp Vault Secret Engine Integration
//!
//! This example demonstrates secure integration with HashiCorp Vault
//! including KV secrets engine, dynamic credentials, token management,
//! and secret rotation for Rust applications.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// Vault Types
// ============================================================================

/// Vault authentication method
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// Token-based authentication
    Token(String),
    /// AppRole authentication
    AppRole { role_id: String, secret_id: String },
    /// Kubernetes authentication
    Kubernetes { role: String, jwt: String },
    /// AWS IAM authentication
    AwsIam {
        role: String,
        access_key: String,
        secret_key: String,
        session_token: Option<String>,
    },
    /// TLS certificate authentication
    TlsCert { cert_path: String, key_path: String },
    /// Userpass authentication
    Userpass { username: String, password: String },
}

/// Vault token with metadata
#[derive(Debug, Clone)]
pub struct VaultToken {
    /// Token string
    pub token: String,
    /// Token accessor
    pub accessor: String,
    /// Creation time
    pub created_at: Instant,
    /// Time-to-live
    pub ttl: Duration,
    /// Is renewable
    pub renewable: bool,
    /// Policies attached
    pub policies: Vec<String>,
    /// Token type
    pub token_type: TokenType,
}

impl VaultToken {
    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.ttl
    }

    /// Check if token needs renewal
    pub fn needs_renewal(&self, threshold: f32) -> bool {
        let elapsed = self.created_at.elapsed();
        let threshold_duration = Duration::from_secs_f64(self.ttl.as_secs_f64() * threshold as f64);
        elapsed >= threshold_duration
    }

    /// Get remaining TTL
    pub fn remaining_ttl(&self) -> Option<Duration> {
        let elapsed = self.created_at.elapsed();
        if elapsed >= self.ttl {
            None
        } else {
            Some(self.ttl - elapsed)
        }
    }
}

/// Token type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Service,
    Batch,
    Recovery,
}

/// Secret data from Vault
#[derive(Debug, Clone)]
pub struct Secret {
    /// Secret path
    pub path: String,
    /// Secret data
    pub data: HashMap<String, String>,
    /// Metadata
    pub metadata: SecretMetadata,
    /// Lease information
    pub lease: Option<LeaseInfo>,
}

/// Secret metadata
#[derive(Debug, Clone)]
pub struct SecretMetadata {
    /// Creation time
    pub created_time: SystemTime,
    /// Deletion time (if scheduled)
    pub deletion_time: Option<SystemTime>,
    /// Is destroyed
    pub destroyed: bool,
    /// Version number
    pub version: u32,
}

/// Lease information for dynamic secrets
#[derive(Debug, Clone)]
pub struct LeaseInfo {
    /// Lease ID
    pub lease_id: String,
    /// Lease duration
    pub lease_duration: Duration,
    /// Is renewable
    pub renewable: bool,
    /// Creation time
    pub created_at: Instant,
}

impl LeaseInfo {
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.lease_duration
    }

    pub fn remaining_duration(&self) -> Option<Duration> {
        let elapsed = self.created_at.elapsed();
        if elapsed >= self.lease_duration {
            None
        } else {
            Some(self.lease_duration - elapsed)
        }
    }
}

// ============================================================================
// Vault Client Configuration
// ============================================================================

/// Vault client configuration
#[derive(Clone)]
pub struct VaultConfig {
    /// Vault address
    pub address: String,
    /// Namespace (enterprise feature)
    pub namespace: Option<String>,
    /// Request timeout
    pub timeout: Duration,
    /// TLS verification
    pub tls_verify: bool,
    /// CA certificate path
    pub ca_cert: Option<String>,
    /// Maximum retries
    pub max_retries: u32,
    /// Retry delay
    pub retry_delay: Duration,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            address: "http://127.0.0.1:8200".to_string(),
            namespace: None,
            timeout: Duration::from_secs(30),
            tls_verify: true,
            ca_cert: None,
            max_retries: 3,
            retry_delay: Duration::from_millis(500),
        }
    }
}

impl VaultConfig {
    pub fn new(address: &str) -> Self {
        Self {
            address: address.to_string(),
            ..Default::default()
        }
    }

    pub fn with_namespace(mut self, namespace: &str) -> Self {
        self.namespace = Some(namespace.to_string());
        self
    }

    pub fn with_tls(mut self, ca_cert: &str) -> Self {
        self.tls_verify = true;
        self.ca_cert = Some(ca_cert.to_string());
        self
    }

    pub fn skip_tls_verify(mut self) -> Self {
        self.tls_verify = false;
        self
    }
}

// ============================================================================
// Vault Client
// ============================================================================

/// Vault client
pub struct VaultClient {
    config: VaultConfig,
    token: Arc<RwLock<Option<VaultToken>>>,
    auth_method: AuthMethod,
    lease_cache: Arc<RwLock<HashMap<String, LeaseInfo>>>,
    stats: Arc<RwLock<ClientStats>>,
}

/// Client statistics
#[derive(Debug, Default)]
pub struct ClientStats {
    pub requests_total: u64,
    pub requests_success: u64,
    pub requests_failed: u64,
    pub secrets_read: u64,
    pub secrets_written: u64,
    pub token_renewals: u64,
    pub lease_renewals: u64,
}

/// Vault error
#[derive(Debug)]
pub enum VaultError {
    AuthenticationFailed(String),
    PermissionDenied(String),
    SecretNotFound(String),
    InvalidPath(String),
    NetworkError(String),
    TokenExpired,
    LeaseExpired(String),
    ConfigError(String),
    SerializationError(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::AuthenticationFailed(msg) => write!(f, "Authentication failed: {}", msg),
            VaultError::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            VaultError::SecretNotFound(msg) => write!(f, "Secret not found: {}", msg),
            VaultError::InvalidPath(msg) => write!(f, "Invalid path: {}", msg),
            VaultError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            VaultError::TokenExpired => write!(f, "Token expired"),
            VaultError::LeaseExpired(msg) => write!(f, "Lease expired: {}", msg),
            VaultError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            VaultError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for VaultError {}

impl VaultClient {
    /// Create new client with auth method
    pub fn new(config: VaultConfig, auth_method: AuthMethod) -> Self {
        Self {
            config,
            token: Arc::new(RwLock::new(None)),
            auth_method,
            lease_cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ClientStats::default())),
        }
    }

    /// Create from environment
    pub fn from_env() -> Result<Self, VaultError> {
        let address =
            std::env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_string());

        let token = std::env::var("VAULT_TOKEN")
            .map_err(|_| VaultError::ConfigError("VAULT_TOKEN not set".to_string()))?;

        let config = VaultConfig::new(&address);
        let auth = AuthMethod::Token(token);

        Ok(Self::new(config, auth))
    }

    /// Authenticate with Vault
    pub fn authenticate(&self) -> Result<VaultToken, VaultError> {
        self.increment_stat(|s| s.requests_total += 1);

        let token = match &self.auth_method {
            AuthMethod::Token(t) => self.auth_with_token(t)?,
            AuthMethod::AppRole { role_id, secret_id } => {
                self.auth_with_approle(role_id, secret_id)?
            }
            AuthMethod::Kubernetes { role, jwt } => self.auth_with_kubernetes(role, jwt)?,
            AuthMethod::Userpass { username, password } => {
                self.auth_with_userpass(username, password)?
            }
            _ => {
                return Err(VaultError::AuthenticationFailed(
                    "Unsupported auth method".to_string(),
                ))
            }
        };

        // Cache the token
        if let Ok(mut cached) = self.token.write() {
            *cached = Some(token.clone());
        }

        self.increment_stat(|s| s.requests_success += 1);
        Ok(token)
    }

    fn auth_with_token(&self, token: &str) -> Result<VaultToken, VaultError> {
        // In real implementation, would call /v1/auth/token/lookup-self
        Ok(VaultToken {
            token: token.to_string(),
            accessor: self.generate_id(),
            created_at: Instant::now(),
            ttl: Duration::from_secs(3600),
            renewable: true,
            policies: vec!["default".to_string()],
            token_type: TokenType::Service,
        })
    }

    fn auth_with_approle(&self, role_id: &str, secret_id: &str) -> Result<VaultToken, VaultError> {
        // In real implementation, would call /v1/auth/approle/login
        if role_id.is_empty() || secret_id.is_empty() {
            return Err(VaultError::AuthenticationFailed(
                "Empty role_id or secret_id".to_string(),
            ));
        }

        Ok(VaultToken {
            token: format!("s.{}", self.generate_id()),
            accessor: self.generate_id(),
            created_at: Instant::now(),
            ttl: Duration::from_secs(3600),
            renewable: true,
            policies: vec!["default".to_string(), "app-policy".to_string()],
            token_type: TokenType::Service,
        })
    }

    fn auth_with_kubernetes(&self, role: &str, _jwt: &str) -> Result<VaultToken, VaultError> {
        // In real implementation, would call /v1/auth/kubernetes/login
        Ok(VaultToken {
            token: format!("s.{}", self.generate_id()),
            accessor: self.generate_id(),
            created_at: Instant::now(),
            ttl: Duration::from_secs(3600),
            renewable: true,
            policies: vec!["default".to_string(), role.to_string()],
            token_type: TokenType::Service,
        })
    }

    fn auth_with_userpass(
        &self,
        username: &str,
        _password: &str,
    ) -> Result<VaultToken, VaultError> {
        // In real implementation, would call /v1/auth/userpass/login/:username
        Ok(VaultToken {
            token: format!("s.{}", self.generate_id()),
            accessor: self.generate_id(),
            created_at: Instant::now(),
            ttl: Duration::from_secs(3600),
            renewable: true,
            policies: vec!["default".to_string(), format!("user-{}", username)],
            token_type: TokenType::Service,
        })
    }

    /// Read a secret from KV v2
    pub fn read_secret(&self, path: &str) -> Result<Secret, VaultError> {
        self.ensure_authenticated()?;
        self.increment_stat(|s| {
            s.requests_total += 1;
            s.secrets_read += 1;
        });

        // Normalize path
        let normalized_path = self.normalize_kv_path(path);

        // In real implementation, would call /v1/{mount}/data/{path}
        let secret = self.simulate_read_secret(&normalized_path)?;

        self.increment_stat(|s| s.requests_success += 1);
        Ok(secret)
    }

    /// Write a secret to KV v2
    pub fn write_secret(
        &self,
        path: &str,
        data: HashMap<String, String>,
    ) -> Result<SecretMetadata, VaultError> {
        self.ensure_authenticated()?;
        self.increment_stat(|s| {
            s.requests_total += 1;
            s.secrets_written += 1;
        });

        let normalized_path = self.normalize_kv_path(path);

        // In real implementation, would call /v1/{mount}/data/{path}
        let metadata = SecretMetadata {
            created_time: SystemTime::now(),
            deletion_time: None,
            destroyed: false,
            version: 1,
        };

        self.increment_stat(|s| s.requests_success += 1);
        Ok(metadata)
    }

    /// Delete a secret
    pub fn delete_secret(&self, path: &str) -> Result<(), VaultError> {
        self.ensure_authenticated()?;
        self.increment_stat(|s| s.requests_total += 1);

        // In real implementation, would call DELETE /v1/{mount}/data/{path}
        self.increment_stat(|s| s.requests_success += 1);
        Ok(())
    }

    /// Get dynamic database credentials
    pub fn get_database_creds(&self, role: &str) -> Result<DatabaseCredentials, VaultError> {
        self.ensure_authenticated()?;
        self.increment_stat(|s| s.requests_total += 1);

        // In real implementation, would call /v1/database/creds/{role}
        let creds = DatabaseCredentials {
            username: format!("v-token-{}-{}", role, &self.generate_id()[..8]),
            password: self.generate_password(),
            lease: LeaseInfo {
                lease_id: format!("database/creds/{}/{}", role, self.generate_id()),
                lease_duration: Duration::from_secs(3600),
                renewable: true,
                created_at: Instant::now(),
            },
        };

        // Cache the lease
        if let Ok(mut cache) = self.lease_cache.write() {
            cache.insert(creds.lease.lease_id.clone(), creds.lease.clone());
        }

        self.increment_stat(|s| s.requests_success += 1);
        Ok(creds)
    }

    /// Renew a lease
    pub fn renew_lease(
        &self,
        lease_id: &str,
        increment: Duration,
    ) -> Result<LeaseInfo, VaultError> {
        self.ensure_authenticated()?;
        self.increment_stat(|s| {
            s.requests_total += 1;
            s.lease_renewals += 1;
        });

        // In real implementation, would call /v1/sys/leases/renew
        let renewed = LeaseInfo {
            lease_id: lease_id.to_string(),
            lease_duration: increment,
            renewable: true,
            created_at: Instant::now(),
        };

        // Update cache
        if let Ok(mut cache) = self.lease_cache.write() {
            cache.insert(lease_id.to_string(), renewed.clone());
        }

        self.increment_stat(|s| s.requests_success += 1);
        Ok(renewed)
    }

    /// Revoke a lease
    pub fn revoke_lease(&self, lease_id: &str) -> Result<(), VaultError> {
        self.ensure_authenticated()?;
        self.increment_stat(|s| s.requests_total += 1);

        // In real implementation, would call /v1/sys/leases/revoke
        if let Ok(mut cache) = self.lease_cache.write() {
            cache.remove(lease_id);
        }

        self.increment_stat(|s| s.requests_success += 1);
        Ok(())
    }

    /// Renew token
    pub fn renew_token(&self) -> Result<VaultToken, VaultError> {
        self.ensure_authenticated()?;
        self.increment_stat(|s| {
            s.requests_total += 1;
            s.token_renewals += 1;
        });

        // In real implementation, would call /v1/auth/token/renew-self
        let current = self
            .token
            .read()
            .map_err(|_| VaultError::TokenExpired)?
            .clone()
            .ok_or(VaultError::TokenExpired)?;

        let renewed = VaultToken {
            token: current.token.clone(),
            accessor: current.accessor.clone(),
            created_at: Instant::now(),
            ttl: current.ttl,
            renewable: current.renewable,
            policies: current.policies.clone(),
            token_type: current.token_type,
        };

        if let Ok(mut cached) = self.token.write() {
            *cached = Some(renewed.clone());
        }

        self.increment_stat(|s| s.requests_success += 1);
        Ok(renewed)
    }

    /// Get transit encryption
    pub fn encrypt(&self, key_name: &str, plaintext: &[u8]) -> Result<String, VaultError> {
        self.ensure_authenticated()?;
        self.increment_stat(|s| s.requests_total += 1);

        // Base64 encode plaintext
        let b64 = base64_encode(plaintext);

        // In real implementation, would call /v1/transit/encrypt/{key_name}
        let ciphertext = format!(
            "vault:v1:{}",
            base64_encode(format!("encrypted:{}", b64).as_bytes())
        );

        self.increment_stat(|s| s.requests_success += 1);
        Ok(ciphertext)
    }

    /// Get transit decryption
    pub fn decrypt(&self, key_name: &str, ciphertext: &str) -> Result<Vec<u8>, VaultError> {
        self.ensure_authenticated()?;
        self.increment_stat(|s| s.requests_total += 1);

        // In real implementation, would call /v1/transit/decrypt/{key_name}
        // For demo, just return placeholder
        let plaintext = b"decrypted_data".to_vec();

        self.increment_stat(|s| s.requests_success += 1);
        Ok(plaintext)
    }

    /// Get PKI certificate
    pub fn issue_certificate(
        &self,
        role: &str,
        common_name: &str,
    ) -> Result<Certificate, VaultError> {
        self.ensure_authenticated()?;
        self.increment_stat(|s| s.requests_total += 1);

        // In real implementation, would call /v1/pki/issue/{role}
        let cert = Certificate {
            certificate: format!("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"),
            private_key: format!(
                "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
            ),
            ca_chain: vec![format!(
                "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
            )],
            serial_number: self.generate_id(),
            expiration: SystemTime::now() + Duration::from_secs(86400 * 365),
            lease: LeaseInfo {
                lease_id: format!("pki/issue/{}/{}", role, self.generate_id()),
                lease_duration: Duration::from_secs(86400 * 365),
                renewable: false,
                created_at: Instant::now(),
            },
        };

        self.increment_stat(|s| s.requests_success += 1);
        Ok(cert)
    }

    /// Get client statistics
    pub fn stats(&self) -> ClientStats {
        self.stats
            .read()
            .map(|s| ClientStats {
                requests_total: s.requests_total,
                requests_success: s.requests_success,
                requests_failed: s.requests_failed,
                secrets_read: s.secrets_read,
                secrets_written: s.secrets_written,
                token_renewals: s.token_renewals,
                lease_renewals: s.lease_renewals,
            })
            .unwrap_or_default()
    }

    // Helper methods

    fn ensure_authenticated(&self) -> Result<(), VaultError> {
        let needs_auth = match self.token.read() {
            Ok(guard) => guard.as_ref().map(|t| t.is_expired()).unwrap_or(true),
            Err(_) => true,
        };

        if needs_auth {
            self.authenticate()?;
        }

        Ok(())
    }

    fn normalize_kv_path(&self, path: &str) -> String {
        // Remove leading slashes and normalize
        path.trim_start_matches('/').to_string()
    }

    fn simulate_read_secret(&self, path: &str) -> Result<Secret, VaultError> {
        // Simulate secret data
        let mut data = HashMap::new();
        data.insert("username".to_string(), "admin".to_string());
        data.insert("password".to_string(), "secret123".to_string());

        Ok(Secret {
            path: path.to_string(),
            data,
            metadata: SecretMetadata {
                created_time: SystemTime::now() - Duration::from_secs(3600),
                deletion_time: None,
                destroyed: false,
                version: 3,
            },
            lease: None,
        })
    }

    fn increment_stat<F>(&self, f: F)
    where
        F: FnOnce(&mut ClientStats),
    {
        if let Ok(mut stats) = self.stats.write() {
            f(&mut stats);
        }
    }

    fn generate_id(&self) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{:x}", timestamp)
    }

    fn generate_password(&self) -> String {
        format!("A1b2C3d4-{}", &self.generate_id()[..8])
    }
}

// ============================================================================
// Dynamic Credential Types
// ============================================================================

/// Database credentials
#[derive(Debug, Clone)]
pub struct DatabaseCredentials {
    pub username: String,
    pub password: String,
    pub lease: LeaseInfo,
}

/// PKI Certificate
#[derive(Debug, Clone)]
pub struct Certificate {
    pub certificate: String,
    pub private_key: String,
    pub ca_chain: Vec<String>,
    pub serial_number: String,
    pub expiration: SystemTime,
    pub lease: LeaseInfo,
}

// ============================================================================
// Secret Manager
// ============================================================================

/// High-level secret manager with caching and auto-renewal
pub struct SecretManager {
    client: VaultClient,
    cache: Arc<RwLock<HashMap<String, CachedSecret>>>,
    cache_ttl: Duration,
    renewal_threshold: f32,
}

struct CachedSecret {
    secret: Secret,
    cached_at: Instant,
}

impl SecretManager {
    pub fn new(client: VaultClient) -> Self {
        Self {
            client,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(300),
            renewal_threshold: 0.75,
        }
    }

    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Get secret with caching
    pub fn get(&self, path: &str) -> Result<Secret, VaultError> {
        // Check cache
        if let Some(secret) = self.get_cached(path) {
            return Ok(secret);
        }

        // Fetch from Vault
        let secret = self.client.read_secret(path)?;

        // Cache it
        self.cache_secret(path, &secret);

        Ok(secret)
    }

    /// Get specific field from secret
    pub fn get_field(&self, path: &str, field: &str) -> Result<String, VaultError> {
        let secret = self.get(path)?;
        secret
            .data
            .get(field)
            .cloned()
            .ok_or_else(|| VaultError::SecretNotFound(format!("Field '{}' not found", field)))
    }

    /// Invalidate cache entry
    pub fn invalidate(&self, path: &str) {
        if let Ok(mut cache) = self.cache.write() {
            cache.remove(path);
        }
    }

    /// Clear entire cache
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }

    fn get_cached(&self, path: &str) -> Option<Secret> {
        let cache = self.cache.read().ok()?;
        let cached = cache.get(path)?;

        if cached.cached_at.elapsed() < self.cache_ttl {
            Some(cached.secret.clone())
        } else {
            None
        }
    }

    fn cache_secret(&self, path: &str, secret: &Secret) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(
                path.to_string(),
                CachedSecret {
                    secret: secret.clone(),
                    cached_at: Instant::now(),
                },
            );
        }
    }
}

// ============================================================================
// Lease Manager
// ============================================================================

/// Manages automatic lease renewal
pub struct LeaseManager {
    client: Arc<VaultClient>,
    leases: Arc<RwLock<HashMap<String, ManagedLease>>>,
}

struct ManagedLease {
    lease: LeaseInfo,
    on_renewal: Option<Box<dyn Fn(&LeaseInfo) + Send + Sync>>,
    on_expiry: Option<Box<dyn Fn(&str) + Send + Sync>>,
}

impl LeaseManager {
    pub fn new(client: Arc<VaultClient>) -> Self {
        Self {
            client,
            leases: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a lease for auto-renewal
    pub fn register(&self, lease: LeaseInfo) {
        if let Ok(mut leases) = self.leases.write() {
            leases.insert(
                lease.lease_id.clone(),
                ManagedLease {
                    lease,
                    on_renewal: None,
                    on_expiry: None,
                },
            );
        }
    }

    /// Unregister a lease
    pub fn unregister(&self, lease_id: &str) {
        if let Ok(mut leases) = self.leases.write() {
            leases.remove(lease_id);
        }
    }

    /// Check and renew expiring leases
    pub fn check_renewals(&self, threshold: f32) -> Vec<Result<LeaseInfo, VaultError>> {
        let leases_to_renew: Vec<String> = {
            let leases = match self.leases.read() {
                Ok(l) => l,
                Err(_) => return vec![],
            };

            leases
                .iter()
                .filter(|(_, managed)| {
                    let elapsed = managed.lease.created_at.elapsed();
                    let threshold_duration = Duration::from_secs_f64(
                        managed.lease.lease_duration.as_secs_f64() * threshold as f64,
                    );
                    elapsed >= threshold_duration && managed.lease.renewable
                })
                .map(|(id, _)| id.clone())
                .collect()
        };

        leases_to_renew
            .iter()
            .map(|lease_id| {
                let result = self.client.renew_lease(lease_id, Duration::from_secs(3600));

                if let Ok(ref renewed) = result {
                    if let Ok(mut leases) = self.leases.write() {
                        if let Some(managed) = leases.get_mut(lease_id) {
                            managed.lease = renewed.clone();
                        }
                    }
                }

                result
            })
            .collect()
    }

    /// Get all managed leases
    pub fn list_leases(&self) -> Vec<LeaseInfo> {
        self.leases
            .read()
            .map(|leases| leases.values().map(|m| m.lease.clone()).collect())
            .unwrap_or_default()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    for chunk in data.chunks(3) {
        let mut n = (chunk[0] as u32) << 16;
        if chunk.len() > 1 {
            n |= (chunk[1] as u32) << 8;
        }
        if chunk.len() > 2 {
            n |= chunk[2] as u32;
        }

        result.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
        result.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[(n >> 6 & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[(n & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== HashiCorp Vault Secret Engine Integration ===\n");

    // Example 1: Client configuration
    println!("1. Client Configuration:");
    let config = VaultConfig::new("https://vault.example.com:8200")
        .with_namespace("my-namespace")
        .with_tls("/path/to/ca.crt");

    println!("   Address: {}", config.address);
    println!("   Namespace: {:?}", config.namespace);
    println!("   TLS Verify: {}", config.tls_verify);

    // Example 2: Authentication methods
    println!("\n2. Authentication Methods:");

    // Token auth
    let token_auth = AuthMethod::Token("s.xyz123".to_string());
    println!("   Token auth configured");

    // AppRole auth
    let approle_auth = AuthMethod::AppRole {
        role_id: "my-role-id".to_string(),
        secret_id: "my-secret-id".to_string(),
    };
    println!("   AppRole auth configured");

    // Kubernetes auth
    let k8s_auth = AuthMethod::Kubernetes {
        role: "my-k8s-role".to_string(),
        jwt: "eyJ...".to_string(),
    };
    println!("   Kubernetes auth configured");

    // Example 3: Create client and authenticate
    println!("\n3. Client Authentication:");
    let config = VaultConfig::default();
    let client = VaultClient::new(config, approle_auth);

    match client.authenticate() {
        Ok(token) => {
            println!("   Authenticated successfully");
            println!("   Token type: {:?}", token.token_type);
            println!("   TTL: {:?}", token.ttl);
            println!("   Policies: {:?}", token.policies);
            println!("   Renewable: {}", token.renewable);
        }
        Err(e) => println!("   Auth failed: {}", e),
    }

    // Example 4: Read/write secrets
    println!("\n4. KV Secret Operations:");

    // Read
    match client.read_secret("secret/data/my-app/config") {
        Ok(secret) => {
            println!("   Read secret from: {}", secret.path);
            println!("   Version: {}", secret.metadata.version);
            for (key, _) in &secret.data {
                println!("   Key: {} = ***", key);
            }
        }
        Err(e) => println!("   Read failed: {}", e),
    }

    // Write
    let mut data = HashMap::new();
    data.insert("api_key".to_string(), "sk-xxx".to_string());
    data.insert("api_secret".to_string(), "secret123".to_string());

    match client.write_secret("secret/data/my-app/credentials", data) {
        Ok(metadata) => {
            println!("   Written secret version: {}", metadata.version);
        }
        Err(e) => println!("   Write failed: {}", e),
    }

    // Example 5: Dynamic database credentials
    println!("\n5. Dynamic Database Credentials:");
    match client.get_database_creds("my-postgres-role") {
        Ok(creds) => {
            println!("   Username: {}", creds.username);
            println!("   Password: {}...", &creds.password[..8]);
            println!("   Lease ID: {}", creds.lease.lease_id);
            println!("   Lease duration: {:?}", creds.lease.lease_duration);
        }
        Err(e) => println!("   Failed: {}", e),
    }

    // Example 6: Transit encryption
    println!("\n6. Transit Encryption:");
    let plaintext = b"sensitive data";

    match client.encrypt("my-key", plaintext) {
        Ok(ciphertext) => {
            println!("   Plaintext: {:?}", String::from_utf8_lossy(plaintext));
            println!("   Ciphertext: {}...", &ciphertext[..30]);

            // Decrypt
            match client.decrypt("my-key", &ciphertext) {
                Ok(decrypted) => {
                    println!("   Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
                }
                Err(e) => println!("   Decrypt failed: {}", e),
            }
        }
        Err(e) => println!("   Encrypt failed: {}", e),
    }

    // Example 7: PKI certificates
    println!("\n7. PKI Certificate Issuance:");
    match client.issue_certificate("web-server", "app.example.com") {
        Ok(cert) => {
            println!("   Serial: {}", cert.serial_number);
            println!("   Certificate: {}...", &cert.certificate[..40]);
            println!("   CA chain length: {}", cert.ca_chain.len());
        }
        Err(e) => println!("   Failed: {}", e),
    }

    // Example 8: Secret Manager with caching
    println!("\n8. Secret Manager (with caching):");
    let manager = SecretManager::new(VaultClient::new(
        VaultConfig::default(),
        AuthMethod::Token("test".to_string()),
    ))
    .with_cache_ttl(Duration::from_secs(300));

    // First call - fetches from Vault
    let _ = manager.get("secret/app/config");
    println!("   First get: fetched from Vault");

    // Second call - served from cache
    let _ = manager.get("secret/app/config");
    println!("   Second get: served from cache");

    // Get specific field
    match manager.get_field("secret/app/config", "username") {
        Ok(value) => println!("   Username field: {}", value),
        Err(e) => println!("   Field not found: {}", e),
    }

    // Example 9: Lease management
    println!("\n9. Lease Management:");
    let client = Arc::new(VaultClient::new(
        VaultConfig::default(),
        AuthMethod::Token("test".to_string()),
    ));
    let lease_manager = LeaseManager::new(client);

    // Register a lease
    let lease = LeaseInfo {
        lease_id: "database/creds/role/xxx".to_string(),
        lease_duration: Duration::from_secs(3600),
        renewable: true,
        created_at: Instant::now(),
    };
    lease_manager.register(lease);
    println!("   Registered 1 lease");

    // List leases
    let leases = lease_manager.list_leases();
    println!("   Active leases: {}", leases.len());

    // Check for renewals
    let renewals = lease_manager.check_renewals(0.75);
    println!("   Renewal checks: {}", renewals.len());

    // Example 10: Client statistics
    println!("\n10. Client Statistics:");
    let stats = client.stats();
    println!("   Total requests: {}", stats.requests_total);
    println!("   Successful: {}", stats.requests_success);
    println!("   Failed: {}", stats.requests_failed);
    println!("   Secrets read: {}", stats.secrets_read);
    println!("   Secrets written: {}", stats.secrets_written);
    println!("   Token renewals: {}", stats.token_renewals);
    println!("   Lease renewals: {}", stats.lease_renewals);

    println!("\n=== Vault Integration Complete ===");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_config_default() {
        let config = VaultConfig::default();
        assert!(config.address.contains("127.0.0.1"));
        assert!(config.tls_verify);
    }

    #[test]
    fn test_vault_config_builder() {
        let config = VaultConfig::new("https://vault.example.com")
            .with_namespace("test")
            .skip_tls_verify();

        assert_eq!(config.address, "https://vault.example.com");
        assert_eq!(config.namespace, Some("test".to_string()));
        assert!(!config.tls_verify);
    }

    #[test]
    fn test_vault_token_expiry() {
        let token = VaultToken {
            token: "test".to_string(),
            accessor: "accessor".to_string(),
            created_at: Instant::now() - Duration::from_secs(7200),
            ttl: Duration::from_secs(3600),
            renewable: true,
            policies: vec![],
            token_type: TokenType::Service,
        };

        assert!(token.is_expired());
    }

    #[test]
    fn test_vault_token_not_expired() {
        let token = VaultToken {
            token: "test".to_string(),
            accessor: "accessor".to_string(),
            created_at: Instant::now(),
            ttl: Duration::from_secs(3600),
            renewable: true,
            policies: vec![],
            token_type: TokenType::Service,
        };

        assert!(!token.is_expired());
    }

    #[test]
    fn test_token_needs_renewal() {
        let token = VaultToken {
            token: "test".to_string(),
            accessor: "accessor".to_string(),
            created_at: Instant::now() - Duration::from_secs(2800),
            ttl: Duration::from_secs(3600),
            renewable: true,
            policies: vec![],
            token_type: TokenType::Service,
        };

        assert!(token.needs_renewal(0.75));
    }

    #[test]
    fn test_lease_info_expiry() {
        let lease = LeaseInfo {
            lease_id: "test".to_string(),
            lease_duration: Duration::from_secs(3600),
            renewable: true,
            created_at: Instant::now(),
        };

        assert!(!lease.is_expired());
        assert!(lease.remaining_duration().is_some());
    }

    #[test]
    fn test_client_creation() {
        let config = VaultConfig::default();
        let auth = AuthMethod::Token("test".to_string());
        let client = VaultClient::new(config, auth);

        let stats = client.stats();
        assert_eq!(stats.requests_total, 0);
    }

    #[test]
    fn test_client_authentication() {
        let config = VaultConfig::default();
        let auth = AuthMethod::Token("test-token".to_string());
        let client = VaultClient::new(config, auth);

        let result = client.authenticate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_approle_authentication() {
        let config = VaultConfig::default();
        let auth = AuthMethod::AppRole {
            role_id: "role".to_string(),
            secret_id: "secret".to_string(),
        };
        let client = VaultClient::new(config, auth);

        let result = client.authenticate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_read_secret() {
        let config = VaultConfig::default();
        let auth = AuthMethod::Token("test".to_string());
        let client = VaultClient::new(config, auth);

        let result = client.read_secret("secret/test");
        assert!(result.is_ok());

        let secret = result.unwrap();
        assert!(!secret.data.is_empty());
    }

    #[test]
    fn test_write_secret() {
        let config = VaultConfig::default();
        let auth = AuthMethod::Token("test".to_string());
        let client = VaultClient::new(config, auth);

        let mut data = HashMap::new();
        data.insert("key".to_string(), "value".to_string());

        let result = client.write_secret("secret/test", data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_database_credentials() {
        let config = VaultConfig::default();
        let auth = AuthMethod::Token("test".to_string());
        let client = VaultClient::new(config, auth);

        let result = client.get_database_creds("role");
        assert!(result.is_ok());

        let creds = result.unwrap();
        assert!(!creds.username.is_empty());
        assert!(!creds.password.is_empty());
    }

    #[test]
    fn test_transit_encryption() {
        let config = VaultConfig::default();
        let auth = AuthMethod::Token("test".to_string());
        let client = VaultClient::new(config, auth);

        let result = client.encrypt("key", b"plaintext");
        assert!(result.is_ok());

        let ciphertext = result.unwrap();
        assert!(ciphertext.starts_with("vault:"));
    }

    #[test]
    fn test_pki_certificate() {
        let config = VaultConfig::default();
        let auth = AuthMethod::Token("test".to_string());
        let client = VaultClient::new(config, auth);

        let result = client.issue_certificate("role", "example.com");
        assert!(result.is_ok());

        let cert = result.unwrap();
        assert!(cert.certificate.contains("CERTIFICATE"));
    }

    #[test]
    fn test_secret_manager_caching() {
        let client = VaultClient::new(
            VaultConfig::default(),
            AuthMethod::Token("test".to_string()),
        );
        let manager = SecretManager::new(client);

        // First call
        let _ = manager.get("secret/test");

        // Should be cached now
        let _ = manager.get("secret/test");

        // Invalidate
        manager.invalidate("secret/test");
    }

    #[test]
    fn test_lease_manager() {
        let client = Arc::new(VaultClient::new(
            VaultConfig::default(),
            AuthMethod::Token("test".to_string()),
        ));
        let manager = LeaseManager::new(client);

        let lease = LeaseInfo {
            lease_id: "test-lease".to_string(),
            lease_duration: Duration::from_secs(3600),
            renewable: true,
            created_at: Instant::now(),
        };

        manager.register(lease);
        assert_eq!(manager.list_leases().len(), 1);

        manager.unregister("test-lease");
        assert_eq!(manager.list_leases().len(), 0);
    }

    #[test]
    fn test_vault_error_display() {
        let err = VaultError::SecretNotFound("test".to_string());
        assert!(format!("{}", err).contains("not found"));

        let err = VaultError::TokenExpired;
        assert!(format!("{}", err).contains("expired"));
    }

    #[test]
    fn test_base64_encode() {
        let encoded = base64_encode(b"hello");
        assert!(!encoded.is_empty());
    }
}
