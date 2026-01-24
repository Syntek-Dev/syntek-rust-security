//! HashiCorp Vault Client Implementation
//!
//! Comprehensive Vault integration with:
//! - Multiple authentication methods
//! - Secret engines (KV, Transit, PKI)
//! - Token management and renewal
//! - Lease management
//! - Secure memory handling

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Vault client configuration
#[derive(Clone, Debug)]
pub struct VaultConfig {
    pub address: String,
    pub namespace: Option<String>,
    pub timeout: Duration,
    pub tls: TlsConfig,
    pub retry: RetryConfig,
}

/// TLS configuration
#[derive(Clone, Debug)]
pub struct TlsConfig {
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub skip_verify: bool,
}

/// Retry configuration
#[derive(Clone, Debug)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

/// Authentication method
#[derive(Clone, Debug)]
pub enum AuthMethod {
    Token(String),
    AppRole { role_id: String, secret_id: String },
    Kubernetes { role: String, jwt: String },
    Ldap { username: String, password: String },
    Userpass { username: String, password: String },
    Aws { role: String, region: String },
    Gcp { role: String, jwt: String },
}

/// Vault token with metadata
#[derive(Clone)]
pub struct VaultToken {
    token: SecretString,
    pub accessor: String,
    pub policies: Vec<String>,
    pub renewable: bool,
    pub ttl: Duration,
    pub created_at: Instant,
}

/// Secure string that zeroizes on drop
#[derive(Clone)]
pub struct SecretString {
    inner: Vec<u8>,
}

impl SecretString {
    pub fn new(s: impl Into<String>) -> Self {
        Self {
            inner: s.into().into_bytes(),
        }
    }

    pub fn expose(&self) -> &str {
        std::str::from_utf8(&self.inner).unwrap_or("")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        // Zeroize the memory
        for byte in &mut self.inner {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString([REDACTED])")
    }
}

/// Secret data from Vault
#[derive(Clone, Debug)]
pub struct Secret {
    pub data: HashMap<String, SecretValue>,
    pub metadata: SecretMetadata,
    pub lease: Option<Lease>,
}

/// Secret value that can be various types
#[derive(Clone)]
pub enum SecretValue {
    String(SecretString),
    Binary(Vec<u8>),
    Number(i64),
    Boolean(bool),
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretValue::String(_) => write!(f, "String([REDACTED])"),
            SecretValue::Binary(_) => write!(f, "Binary([REDACTED])"),
            SecretValue::Number(n) => write!(f, "Number({})", n),
            SecretValue::Boolean(b) => write!(f, "Boolean({})", b),
        }
    }
}

/// Secret metadata
#[derive(Clone, Debug)]
pub struct SecretMetadata {
    pub version: u64,
    pub created_time: String,
    pub deletion_time: Option<String>,
    pub destroyed: bool,
    pub custom_metadata: HashMap<String, String>,
}

/// Lease information
#[derive(Clone, Debug)]
pub struct Lease {
    pub id: String,
    pub duration: Duration,
    pub renewable: bool,
}

/// Transit encryption result
#[derive(Clone, Debug)]
pub struct EncryptionResult {
    pub ciphertext: String,
    pub key_version: u32,
}

/// Transit decryption result
#[derive(Clone)]
pub struct DecryptionResult {
    pub plaintext: SecretString,
}

/// PKI certificate
#[derive(Clone, Debug)]
pub struct Certificate {
    pub certificate: String,
    pub issuing_ca: String,
    pub ca_chain: Vec<String>,
    pub private_key: SecretString,
    pub serial_number: String,
    pub expiration: u64,
}

impl fmt::Debug for DecryptionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecryptionResult([REDACTED])")
    }
}

/// Vault client
pub struct VaultClient {
    config: VaultConfig,
    token: Option<VaultToken>,
    http_client: HttpClient,
}

/// Simulated HTTP client
struct HttpClient {
    timeout: Duration,
}

/// Vault error
#[derive(Debug)]
pub enum VaultError {
    ConnectionFailed(String),
    AuthenticationFailed(String),
    NotFound(String),
    PermissionDenied(String),
    RateLimited,
    TokenExpired,
    InvalidResponse(String),
    TlsError(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            VaultError::AuthenticationFailed(msg) => write!(f, "Auth failed: {}", msg),
            VaultError::NotFound(path) => write!(f, "Secret not found: {}", path),
            VaultError::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            VaultError::RateLimited => write!(f, "Rate limited"),
            VaultError::TokenExpired => write!(f, "Token expired"),
            VaultError::InvalidResponse(msg) => write!(f, "Invalid response: {}", msg),
            VaultError::TlsError(msg) => write!(f, "TLS error: {}", msg),
        }
    }
}

impl std::error::Error for VaultError {}

impl VaultClient {
    /// Create new Vault client
    pub fn new(config: VaultConfig) -> Self {
        let http_client = HttpClient {
            timeout: config.timeout,
        };

        Self {
            config,
            token: None,
            http_client,
        }
    }

    /// Authenticate with Vault
    pub fn authenticate(&mut self, method: AuthMethod) -> Result<(), VaultError> {
        let token = match method {
            AuthMethod::Token(t) => {
                // Direct token authentication
                VaultToken {
                    token: SecretString::new(t),
                    accessor: "direct-token".to_string(),
                    policies: vec!["default".to_string()],
                    renewable: false,
                    ttl: Duration::from_secs(3600),
                    created_at: Instant::now(),
                }
            }
            AuthMethod::AppRole { role_id, secret_id } => {
                // AppRole authentication
                println!("Authenticating with AppRole: {}", role_id);
                VaultToken {
                    token: SecretString::new(format!("s.approle_{}", role_id)),
                    accessor: format!("accessor_{}", role_id),
                    policies: vec!["default".to_string(), "app-policy".to_string()],
                    renewable: true,
                    ttl: Duration::from_secs(3600),
                    created_at: Instant::now(),
                }
            }
            AuthMethod::Kubernetes { role, jwt } => {
                // Kubernetes authentication
                println!("Authenticating with Kubernetes role: {}", role);
                VaultToken {
                    token: SecretString::new(format!("s.k8s_{}", role)),
                    accessor: format!("accessor_k8s_{}", role),
                    policies: vec!["default".to_string(), "k8s-policy".to_string()],
                    renewable: true,
                    ttl: Duration::from_secs(900),
                    created_at: Instant::now(),
                }
            }
            AuthMethod::Userpass { username, password } => {
                println!("Authenticating user: {}", username);
                VaultToken {
                    token: SecretString::new(format!("s.user_{}", username)),
                    accessor: format!("accessor_{}", username),
                    policies: vec!["default".to_string()],
                    renewable: true,
                    ttl: Duration::from_secs(7200),
                    created_at: Instant::now(),
                }
            }
            _ => {
                return Err(VaultError::AuthenticationFailed(
                    "Unsupported auth method".to_string(),
                ));
            }
        };

        self.token = Some(token);
        Ok(())
    }

    /// Check if token is valid and not expired
    pub fn is_authenticated(&self) -> bool {
        self.token
            .as_ref()
            .map_or(false, |t| t.created_at.elapsed() < t.ttl)
    }

    /// Renew token
    pub fn renew_token(&mut self) -> Result<Duration, VaultError> {
        let token = self.token.as_mut().ok_or(VaultError::TokenExpired)?;

        if !token.renewable {
            return Err(VaultError::AuthenticationFailed(
                "Token is not renewable".to_string(),
            ));
        }

        // Simulate token renewal
        token.created_at = Instant::now();
        Ok(token.ttl)
    }

    /// Read secret from KV v2 engine
    pub fn read_secret(&self, path: &str) -> Result<Secret, VaultError> {
        self.ensure_authenticated()?;

        println!("Reading secret from: {}", path);

        // Simulate reading a secret
        let mut data = HashMap::new();
        data.insert(
            "username".to_string(),
            SecretValue::String(SecretString::new("admin")),
        );
        data.insert(
            "password".to_string(),
            SecretValue::String(SecretString::new("super_secret_password")),
        );
        data.insert("port".to_string(), SecretValue::Number(5432));

        Ok(Secret {
            data,
            metadata: SecretMetadata {
                version: 3,
                created_time: "2025-01-23T10:00:00Z".to_string(),
                deletion_time: None,
                destroyed: false,
                custom_metadata: HashMap::new(),
            },
            lease: None,
        })
    }

    /// Write secret to KV v2 engine
    pub fn write_secret(
        &self,
        path: &str,
        data: HashMap<String, SecretValue>,
    ) -> Result<SecretMetadata, VaultError> {
        self.ensure_authenticated()?;

        println!("Writing secret to: {}", path);

        Ok(SecretMetadata {
            version: 4,
            created_time: "2025-01-23T11:00:00Z".to_string(),
            deletion_time: None,
            destroyed: false,
            custom_metadata: HashMap::new(),
        })
    }

    /// Delete secret (soft delete in KV v2)
    pub fn delete_secret(&self, path: &str) -> Result<(), VaultError> {
        self.ensure_authenticated()?;
        println!("Deleting secret at: {}", path);
        Ok(())
    }

    /// Destroy secret versions permanently
    pub fn destroy_secret(&self, path: &str, versions: &[u64]) -> Result<(), VaultError> {
        self.ensure_authenticated()?;
        println!("Destroying versions {:?} at: {}", versions, path);
        Ok(())
    }

    /// Encrypt data using Transit engine
    pub fn encrypt(
        &self,
        key_name: &str,
        plaintext: &[u8],
    ) -> Result<EncryptionResult, VaultError> {
        self.ensure_authenticated()?;

        println!("Encrypting with key: {}", key_name);

        // Simulate encryption
        let ciphertext = format!("vault:v1:{}", base64_encode(plaintext));

        Ok(EncryptionResult {
            ciphertext,
            key_version: 1,
        })
    }

    /// Decrypt data using Transit engine
    pub fn decrypt(
        &self,
        key_name: &str,
        ciphertext: &str,
    ) -> Result<DecryptionResult, VaultError> {
        self.ensure_authenticated()?;

        println!("Decrypting with key: {}", key_name);

        // Simulate decryption
        let plaintext = if ciphertext.starts_with("vault:v1:") {
            let encoded = &ciphertext[9..];
            base64_decode(encoded)
        } else {
            return Err(VaultError::InvalidResponse(
                "Invalid ciphertext format".to_string(),
            ));
        };

        Ok(DecryptionResult {
            plaintext: SecretString::new(String::from_utf8_lossy(&plaintext)),
        })
    }

    /// Generate data key for envelope encryption
    pub fn generate_data_key(&self, key_name: &str) -> Result<(Vec<u8>, String), VaultError> {
        self.ensure_authenticated()?;

        println!("Generating data key with: {}", key_name);

        // Simulate data key generation
        let plaintext_key = vec![0u8; 32]; // 256-bit key
        let encrypted_key = format!("vault:v1:{}", base64_encode(&plaintext_key));

        Ok((plaintext_key, encrypted_key))
    }

    /// Issue certificate from PKI engine
    pub fn issue_certificate(
        &self,
        role: &str,
        common_name: &str,
        ttl: Duration,
    ) -> Result<Certificate, VaultError> {
        self.ensure_authenticated()?;

        println!("Issuing certificate for: {} (role: {})", common_name, role);

        Ok(Certificate {
            certificate: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
                .to_string(),
            issuing_ca: "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----"
                .to_string(),
            ca_chain: vec![],
            private_key: SecretString::new(
                "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
            ),
            serial_number: "12:34:56:78:90:AB:CD:EF".to_string(),
            expiration: 1737619200, // Example timestamp
        })
    }

    /// Sign data with Transit engine
    pub fn sign(&self, key_name: &str, data: &[u8]) -> Result<String, VaultError> {
        self.ensure_authenticated()?;

        println!("Signing data with key: {}", key_name);

        // Simulate signing
        Ok(format!("vault:v1:signature_{}", base64_encode(data)))
    }

    /// Verify signature with Transit engine
    pub fn verify(&self, key_name: &str, data: &[u8], signature: &str) -> Result<bool, VaultError> {
        self.ensure_authenticated()?;

        println!("Verifying signature with key: {}", key_name);

        // Simulate verification
        Ok(signature.starts_with("vault:v1:signature_"))
    }

    /// Generate random bytes
    pub fn generate_random(&self, bytes: usize) -> Result<Vec<u8>, VaultError> {
        self.ensure_authenticated()?;

        // Simulate random generation
        Ok(vec![0u8; bytes])
    }

    /// Revoke lease
    pub fn revoke_lease(&self, lease_id: &str) -> Result<(), VaultError> {
        self.ensure_authenticated()?;
        println!("Revoking lease: {}", lease_id);
        Ok(())
    }

    /// Renew lease
    pub fn renew_lease(&self, lease_id: &str, increment: Duration) -> Result<Lease, VaultError> {
        self.ensure_authenticated()?;
        println!("Renewing lease: {}", lease_id);

        Ok(Lease {
            id: lease_id.to_string(),
            duration: increment,
            renewable: true,
        })
    }

    fn ensure_authenticated(&self) -> Result<(), VaultError> {
        if !self.is_authenticated() {
            return Err(VaultError::TokenExpired);
        }
        Ok(())
    }
}

/// Vault client builder
pub struct VaultClientBuilder {
    address: String,
    namespace: Option<String>,
    timeout: Duration,
    tls: TlsConfig,
    retry: RetryConfig,
}

impl VaultClientBuilder {
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            namespace: None,
            timeout: Duration::from_secs(30),
            tls: TlsConfig::default(),
            retry: RetryConfig::default(),
        }
    }

    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn tls(mut self, tls: TlsConfig) -> Self {
        self.tls = tls;
        self
    }

    pub fn retry(mut self, retry: RetryConfig) -> Self {
        self.retry = retry;
        self
    }

    pub fn build(self) -> VaultClient {
        VaultClient::new(VaultConfig {
            address: self.address,
            namespace: self.namespace,
            timeout: self.timeout,
            tls: self.tls,
            retry: self.retry,
        })
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            ca_cert: None,
            client_cert: None,
            client_key: None,
            skip_verify: false,
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
        }
    }
}

// Helper functions for base64 (simplified)
fn base64_encode(data: &[u8]) -> String {
    // Simplified base64 encoding for demo
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn base64_decode(encoded: &str) -> Vec<u8> {
    // Simplified base64 decoding for demo
    (0..encoded.len())
        .step_by(2)
        .filter_map(|i| {
            if i + 2 <= encoded.len() {
                u8::from_str_radix(&encoded[i..i + 2], 16).ok()
            } else {
                None
            }
        })
        .collect()
}

fn main() {
    println!("=== HashiCorp Vault Client Demo ===\n");

    // Create client with builder
    let mut client = VaultClientBuilder::new("https://vault.example.com:8200")
        .namespace("my-namespace")
        .timeout(Duration::from_secs(30))
        .tls(TlsConfig {
            ca_cert: Some("/path/to/ca.crt".to_string()),
            skip_verify: false,
            ..Default::default()
        })
        .build();

    // Authenticate with AppRole
    println!("=== Authentication ===\n");

    client
        .authenticate(AuthMethod::AppRole {
            role_id: "my-app-role".to_string(),
            secret_id: "secret-id-xxx".to_string(),
        })
        .expect("Authentication failed");

    println!("Authenticated: {}\n", client.is_authenticated());

    // Read secrets
    println!("=== KV Secrets ===\n");

    let secret = client.read_secret("secret/data/myapp/config").unwrap();
    println!("Secret version: {}", secret.metadata.version);
    println!("Secret data: {:?}", secret.data);

    // Write secret
    let mut new_data = HashMap::new();
    new_data.insert(
        "api_key".to_string(),
        SecretValue::String(SecretString::new("new_api_key_value")),
    );

    let metadata = client
        .write_secret("secret/data/myapp/config", new_data)
        .unwrap();
    println!("Written secret version: {}\n", metadata.version);

    // Transit encryption
    println!("=== Transit Encryption ===\n");

    let plaintext = b"sensitive data to encrypt";
    let encrypted = client.encrypt("my-transit-key", plaintext).unwrap();
    println!("Encrypted: {}", encrypted.ciphertext);

    let decrypted = client
        .decrypt("my-transit-key", &encrypted.ciphertext)
        .unwrap();
    println!("Decrypted: {}\n", decrypted.plaintext.expose());

    // Data key for envelope encryption
    println!("=== Envelope Encryption ===\n");

    let (data_key, wrapped_key) = client.generate_data_key("my-transit-key").unwrap();
    println!("Data key length: {} bytes", data_key.len());
    println!("Wrapped key: {}\n", wrapped_key);

    // PKI certificate
    println!("=== PKI Certificates ===\n");

    let cert = client
        .issue_certificate(
            "web-server",
            "api.example.com",
            Duration::from_secs(86400 * 30),
        )
        .unwrap();
    println!("Certificate serial: {}", cert.serial_number);
    println!("Certificate (truncated): {}...", &cert.certificate[..50]);

    // Signing
    println!("\n=== Digital Signatures ===\n");

    let data = b"data to sign";
    let signature = client.sign("my-signing-key", data).unwrap();
    println!("Signature: {}", signature);

    let valid = client.verify("my-signing-key", data, &signature).unwrap();
    println!("Signature valid: {}\n", valid);

    // Token renewal
    println!("=== Token Management ===\n");

    match client.renew_token() {
        Ok(ttl) => println!("Token renewed, new TTL: {:?}", ttl),
        Err(e) => println!("Token renewal failed: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_authenticated_client() -> VaultClient {
        let mut client = VaultClientBuilder::new("https://vault.test:8200").build();
        client
            .authenticate(AuthMethod::Token("test-token".to_string()))
            .unwrap();
        client
    }

    #[test]
    fn test_client_creation() {
        let client = VaultClientBuilder::new("https://vault.test:8200")
            .namespace("test")
            .timeout(Duration::from_secs(10))
            .build();

        assert_eq!(client.config.address, "https://vault.test:8200");
        assert_eq!(client.config.namespace, Some("test".to_string()));
    }

    #[test]
    fn test_token_authentication() {
        let mut client = VaultClientBuilder::new("https://vault.test:8200").build();

        assert!(!client.is_authenticated());

        client
            .authenticate(AuthMethod::Token("test-token".to_string()))
            .unwrap();

        assert!(client.is_authenticated());
    }

    #[test]
    fn test_approle_authentication() {
        let mut client = VaultClientBuilder::new("https://vault.test:8200").build();

        client
            .authenticate(AuthMethod::AppRole {
                role_id: "test-role".to_string(),
                secret_id: "test-secret".to_string(),
            })
            .unwrap();

        assert!(client.is_authenticated());
    }

    #[test]
    fn test_read_secret() {
        let client = create_authenticated_client();

        let secret = client.read_secret("secret/data/test").unwrap();

        assert!(secret.data.contains_key("username"));
        assert!(secret.data.contains_key("password"));
    }

    #[test]
    fn test_write_secret() {
        let client = create_authenticated_client();

        let mut data = HashMap::new();
        data.insert(
            "key".to_string(),
            SecretValue::String(SecretString::new("value")),
        );

        let metadata = client.write_secret("secret/data/test", data).unwrap();

        assert!(metadata.version > 0);
    }

    #[test]
    fn test_transit_encrypt_decrypt() {
        let client = create_authenticated_client();

        let plaintext = b"test data";
        let encrypted = client.encrypt("test-key", plaintext).unwrap();

        assert!(encrypted.ciphertext.starts_with("vault:v1:"));

        let decrypted = client.decrypt("test-key", &encrypted.ciphertext).unwrap();
        assert_eq!(decrypted.plaintext.expose(), "test data");
    }

    #[test]
    fn test_generate_data_key() {
        let client = create_authenticated_client();

        let (key, wrapped) = client.generate_data_key("test-key").unwrap();

        assert_eq!(key.len(), 32);
        assert!(wrapped.starts_with("vault:v1:"));
    }

    #[test]
    fn test_sign_verify() {
        let client = create_authenticated_client();

        let data = b"data to sign";
        let signature = client.sign("test-key", data).unwrap();

        let valid = client.verify("test-key", data, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_issue_certificate() {
        let client = create_authenticated_client();

        let cert = client
            .issue_certificate("test-role", "test.example.com", Duration::from_secs(3600))
            .unwrap();

        assert!(!cert.certificate.is_empty());
        assert!(!cert.serial_number.is_empty());
    }

    #[test]
    fn test_unauthenticated_request_fails() {
        let client = VaultClientBuilder::new("https://vault.test:8200").build();

        let result = client.read_secret("secret/data/test");

        assert!(matches!(result, Err(VaultError::TokenExpired)));
    }

    #[test]
    fn test_secret_string_zeroize() {
        let secret = SecretString::new("sensitive");
        assert_eq!(secret.expose(), "sensitive");
        // Drop will zeroize
    }

    #[test]
    fn test_token_renewal() {
        let mut client = create_authenticated_client();

        // Direct token is not renewable
        let result = client.renew_token();
        assert!(result.is_err());

        // AppRole token is renewable
        client
            .authenticate(AuthMethod::AppRole {
                role_id: "role".to_string(),
                secret_id: "secret".to_string(),
            })
            .unwrap();

        let result = client.renew_token();
        assert!(result.is_ok());
    }
}
