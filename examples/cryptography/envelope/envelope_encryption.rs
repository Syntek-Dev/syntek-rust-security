//! Envelope Encryption Implementation
//!
//! This example demonstrates envelope encryption patterns where
//! data is encrypted with a Data Encryption Key (DEK) which is
//! then encrypted with a Key Encryption Key (KEK), commonly used
//! with cloud KMS services.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// Key Types
// ============================================================================

/// Key Encryption Key (KEK) - master key
#[derive(Clone)]
pub struct KeyEncryptionKey {
    /// Key identifier
    pub key_id: String,
    /// Key material (in production, this would be in HSM/KMS)
    key_material: [u8; 32],
    /// Creation time
    pub created_at: SystemTime,
    /// Expiration time
    pub expires_at: Option<SystemTime>,
    /// Key version
    pub version: u32,
    /// Algorithm
    pub algorithm: KeyAlgorithm,
}

impl KeyEncryptionKey {
    pub fn generate(key_id: &str, algorithm: KeyAlgorithm) -> Self {
        Self {
            key_id: key_id.to_string(),
            key_material: Self::generate_key_material(),
            created_at: SystemTime::now(),
            expires_at: Some(SystemTime::now() + Duration::from_secs(365 * 24 * 3600)),
            version: 1,
            algorithm,
        }
    }

    fn generate_key_material() -> [u8; 32] {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};

        let state = RandomState::new();
        let mut hasher = state.build_hasher();

        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            hasher.write_usize(i);
            hasher.write_u128(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(),
            );
            *byte = (hasher.finish() & 0xFF) as u8;
        }
        key
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            SystemTime::now() > expires
        } else {
            false
        }
    }

    /// Encrypt a Data Encryption Key
    pub fn wrap_key(&self, dek: &DataEncryptionKey) -> Result<WrappedKey, CryptoError> {
        if self.is_expired() {
            return Err(CryptoError::KeyExpired);
        }

        // Simple XOR-based wrapping for demonstration
        // In production, use AES-KWP or similar
        let mut wrapped = Vec::with_capacity(dek.key_material.len());
        for (i, &byte) in dek.key_material.iter().enumerate() {
            wrapped.push(byte ^ self.key_material[i % self.key_material.len()]);
        }

        Ok(WrappedKey {
            kek_id: self.key_id.clone(),
            kek_version: self.version,
            wrapped_key: wrapped,
            algorithm: self.algorithm,
        })
    }

    /// Decrypt a wrapped Data Encryption Key
    pub fn unwrap_key(&self, wrapped: &WrappedKey) -> Result<DataEncryptionKey, CryptoError> {
        if self.is_expired() {
            return Err(CryptoError::KeyExpired);
        }

        if wrapped.kek_id != self.key_id {
            return Err(CryptoError::KeyMismatch);
        }

        // Unwrap (reverse the XOR)
        let mut key_material = [0u8; 32];
        for (i, &byte) in wrapped.wrapped_key.iter().enumerate() {
            if i < 32 {
                key_material[i] = byte ^ self.key_material[i % self.key_material.len()];
            }
        }

        Ok(DataEncryptionKey {
            key_id: format!("dek-unwrapped-{}", generate_id()),
            key_material,
            algorithm: wrapped.algorithm,
            created_at: SystemTime::now(),
        })
    }
}

/// Data Encryption Key (DEK) - used to encrypt data
#[derive(Clone)]
pub struct DataEncryptionKey {
    /// Key identifier
    pub key_id: String,
    /// Key material
    key_material: [u8; 32],
    /// Algorithm
    pub algorithm: KeyAlgorithm,
    /// Creation time
    pub created_at: SystemTime,
}

impl DataEncryptionKey {
    pub fn generate(algorithm: KeyAlgorithm) -> Self {
        Self {
            key_id: format!("dek-{}", generate_id()),
            key_material: KeyEncryptionKey::generate_key_material(),
            algorithm,
            created_at: SystemTime::now(),
        }
    }

    /// Encrypt data with this DEK
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData, CryptoError> {
        // Generate nonce/IV
        let nonce = generate_nonce();

        // Simple XOR encryption for demonstration
        // In production, use AES-GCM or ChaCha20-Poly1305
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for (i, &byte) in plaintext.iter().enumerate() {
            let key_byte = self.key_material[i % self.key_material.len()];
            let nonce_byte = nonce[i % nonce.len()];
            ciphertext.push(byte ^ key_byte ^ nonce_byte);
        }

        // Generate authentication tag (simplified)
        let tag = self.compute_tag(&ciphertext, &nonce);

        Ok(EncryptedData {
            ciphertext,
            nonce: nonce.to_vec(),
            tag,
            algorithm: self.algorithm,
        })
    }

    /// Decrypt data with this DEK
    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>, CryptoError> {
        // Verify tag
        let expected_tag = self.compute_tag(&encrypted.ciphertext, &encrypted.nonce);
        if expected_tag != encrypted.tag {
            return Err(CryptoError::AuthenticationFailed);
        }

        // Decrypt
        let mut plaintext = Vec::with_capacity(encrypted.ciphertext.len());
        for (i, &byte) in encrypted.ciphertext.iter().enumerate() {
            let key_byte = self.key_material[i % self.key_material.len()];
            let nonce_byte = encrypted.nonce[i % encrypted.nonce.len()];
            plaintext.push(byte ^ key_byte ^ nonce_byte);
        }

        Ok(plaintext)
    }

    fn compute_tag(&self, data: &[u8], nonce: &[u8]) -> Vec<u8> {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};

        let state = RandomState::new();
        let mut hasher = state.build_hasher();

        for &b in &self.key_material {
            hasher.write_u8(b);
        }
        for &b in data {
            hasher.write_u8(b);
        }
        for &b in nonce {
            hasher.write_u8(b);
        }

        hasher.finish().to_le_bytes().to_vec()
    }
}

/// Wrapped (encrypted) key
#[derive(Debug, Clone)]
pub struct WrappedKey {
    /// KEK identifier used for wrapping
    pub kek_id: String,
    /// KEK version
    pub kek_version: u32,
    /// Encrypted key material
    pub wrapped_key: Vec<u8>,
    /// Algorithm
    pub algorithm: KeyAlgorithm,
}

impl WrappedKey {
    /// Serialize for storage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // KEK ID length and data
        bytes.extend_from_slice(&(self.kek_id.len() as u32).to_le_bytes());
        bytes.extend_from_slice(self.kek_id.as_bytes());

        // KEK version
        bytes.extend_from_slice(&self.kek_version.to_le_bytes());

        // Algorithm
        bytes.push(self.algorithm as u8);

        // Wrapped key
        bytes.extend_from_slice(&(self.wrapped_key.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.wrapped_key);

        bytes
    }

    /// Deserialize from storage
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 9 {
            return Err(CryptoError::InvalidFormat);
        }

        let mut offset = 0;

        // KEK ID
        let id_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        if bytes.len() < offset + id_len {
            return Err(CryptoError::InvalidFormat);
        }

        let kek_id = String::from_utf8(bytes[offset..offset + id_len].to_vec())
            .map_err(|_| CryptoError::InvalidFormat)?;
        offset += id_len;

        // KEK version
        let kek_version = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        // Algorithm
        let algorithm = KeyAlgorithm::from_u8(bytes[offset])?;
        offset += 1;

        // Wrapped key
        let key_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        let wrapped_key = bytes[offset..offset + key_len].to_vec();

        Ok(Self {
            kek_id,
            kek_version,
            wrapped_key,
            algorithm,
        })
    }
}

/// Encrypted data with metadata
#[derive(Debug, Clone)]
pub struct EncryptedData {
    /// Ciphertext
    pub ciphertext: Vec<u8>,
    /// Nonce/IV
    pub nonce: Vec<u8>,
    /// Authentication tag
    pub tag: Vec<u8>,
    /// Algorithm used
    pub algorithm: KeyAlgorithm,
}

impl EncryptedData {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.push(self.algorithm as u8);

        bytes.extend_from_slice(&(self.nonce.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.nonce);

        bytes.extend_from_slice(&(self.tag.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.tag);

        bytes.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.ciphertext);

        bytes
    }
}

/// Key algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2,
    Aes256Cbc = 3,
}

impl KeyAlgorithm {
    pub fn from_u8(value: u8) -> Result<Self, CryptoError> {
        match value {
            1 => Ok(KeyAlgorithm::Aes256Gcm),
            2 => Ok(KeyAlgorithm::ChaCha20Poly1305),
            3 => Ok(KeyAlgorithm::Aes256Cbc),
            _ => Err(CryptoError::UnsupportedAlgorithm),
        }
    }
}

// ============================================================================
// Envelope
// ============================================================================

/// Complete envelope containing encrypted data and wrapped key
#[derive(Debug, Clone)]
pub struct Envelope {
    /// Wrapped DEK
    pub wrapped_key: WrappedKey,
    /// Encrypted data
    pub encrypted_data: EncryptedData,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Creation timestamp
    pub created_at: SystemTime,
}

impl Envelope {
    /// Serialize envelope for storage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Magic number
        bytes.extend_from_slice(b"ENV1");

        // Timestamp
        let timestamp = self
            .created_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        bytes.extend_from_slice(&timestamp.to_le_bytes());

        // Wrapped key
        let wrapped_bytes = self.wrapped_key.to_bytes();
        bytes.extend_from_slice(&(wrapped_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&wrapped_bytes);

        // Encrypted data
        let encrypted_bytes = self.encrypted_data.to_bytes();
        bytes.extend_from_slice(&(encrypted_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&encrypted_bytes);

        // Metadata count
        bytes.extend_from_slice(&(self.metadata.len() as u32).to_le_bytes());
        for (key, value) in &self.metadata {
            bytes.extend_from_slice(&(key.len() as u32).to_le_bytes());
            bytes.extend_from_slice(key.as_bytes());
            bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }

        bytes
    }
}

/// Envelope encryption service
pub struct EnvelopeService {
    /// Key registry
    keys: HashMap<String, KeyEncryptionKey>,
    /// Default KEK ID
    default_kek: Option<String>,
    /// Statistics
    stats: ServiceStats,
}

/// Service statistics
#[derive(Debug, Default)]
pub struct ServiceStats {
    pub encryptions: u64,
    pub decryptions: u64,
    pub key_wraps: u64,
    pub key_unwraps: u64,
    pub failures: u64,
}

impl EnvelopeService {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            default_kek: None,
            stats: ServiceStats::default(),
        }
    }

    /// Register a KEK
    pub fn register_key(&mut self, kek: KeyEncryptionKey) {
        let key_id = kek.key_id.clone();
        if self.default_kek.is_none() {
            self.default_kek = Some(key_id.clone());
        }
        self.keys.insert(key_id, kek);
    }

    /// Set default KEK
    pub fn set_default_key(&mut self, key_id: &str) -> Result<(), CryptoError> {
        if self.keys.contains_key(key_id) {
            self.default_kek = Some(key_id.to_string());
            Ok(())
        } else {
            Err(CryptoError::KeyNotFound)
        }
    }

    /// Encrypt data with envelope encryption
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Envelope, CryptoError> {
        self.encrypt_with_key(plaintext, self.default_kek.as_deref())
    }

    /// Encrypt with specific KEK
    pub fn encrypt_with_key(
        &mut self,
        plaintext: &[u8],
        kek_id: Option<&str>,
    ) -> Result<Envelope, CryptoError> {
        let kek_id = kek_id
            .or(self.default_kek.as_deref())
            .ok_or(CryptoError::NoDefaultKey)?;

        let kek = self.keys.get(kek_id).ok_or(CryptoError::KeyNotFound)?;

        // Generate a new DEK for this encryption
        let dek = DataEncryptionKey::generate(kek.algorithm);

        // Encrypt data with DEK
        let encrypted_data = dek.encrypt(plaintext)?;
        self.stats.encryptions += 1;

        // Wrap DEK with KEK
        let wrapped_key = kek.wrap_key(&dek)?;
        self.stats.key_wraps += 1;

        Ok(Envelope {
            wrapped_key,
            encrypted_data,
            metadata: HashMap::new(),
            created_at: SystemTime::now(),
        })
    }

    /// Encrypt with metadata
    pub fn encrypt_with_metadata(
        &mut self,
        plaintext: &[u8],
        metadata: HashMap<String, String>,
    ) -> Result<Envelope, CryptoError> {
        let mut envelope = self.encrypt(plaintext)?;
        envelope.metadata = metadata;
        Ok(envelope)
    }

    /// Decrypt an envelope
    pub fn decrypt(&mut self, envelope: &Envelope) -> Result<Vec<u8>, CryptoError> {
        let kek = self
            .keys
            .get(&envelope.wrapped_key.kek_id)
            .ok_or(CryptoError::KeyNotFound)?;

        // Unwrap DEK
        let dek = kek.unwrap_key(&envelope.wrapped_key)?;
        self.stats.key_unwraps += 1;

        // Decrypt data
        let plaintext = dek.decrypt(&envelope.encrypted_data)?;
        self.stats.decryptions += 1;

        Ok(plaintext)
    }

    /// Re-encrypt with new KEK
    pub fn reencrypt(
        &mut self,
        envelope: &Envelope,
        new_kek_id: &str,
    ) -> Result<Envelope, CryptoError> {
        // Decrypt with old key
        let plaintext = self.decrypt(envelope)?;

        // Encrypt with new key
        self.encrypt_with_key(&plaintext, Some(new_kek_id))
    }

    /// Get statistics
    pub fn stats(&self) -> &ServiceStats {
        &self.stats
    }

    /// Get registered key IDs
    pub fn key_ids(&self) -> Vec<&str> {
        self.keys.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for EnvelopeService {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Cloud KMS Integration
// ============================================================================

/// Cloud KMS provider interface
pub trait KmsProvider {
    /// Encrypt data with KMS
    fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Decrypt data with KMS
    fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Generate data key
    fn generate_data_key(&self, key_id: &str) -> Result<GeneratedDataKey, CryptoError>;
}

/// Generated data key from KMS
#[derive(Debug, Clone)]
pub struct GeneratedDataKey {
    /// Plaintext key (use and zeroize immediately)
    pub plaintext: Vec<u8>,
    /// Encrypted key (store this)
    pub ciphertext: Vec<u8>,
    /// Key ID used
    pub key_id: String,
}

/// AWS KMS provider (simulated)
pub struct AwsKmsProvider {
    region: String,
    keys: HashMap<String, [u8; 32]>,
}

impl AwsKmsProvider {
    pub fn new(region: &str) -> Self {
        Self {
            region: region.to_string(),
            keys: HashMap::new(),
        }
    }

    pub fn register_key(&mut self, key_id: &str) {
        let key = KeyEncryptionKey::generate_key_material();
        self.keys.insert(key_id.to_string(), key);
    }
}

impl KmsProvider for AwsKmsProvider {
    fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = self.keys.get(key_id).ok_or(CryptoError::KeyNotFound)?;

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for (i, &byte) in plaintext.iter().enumerate() {
            ciphertext.push(byte ^ key[i % key.len()]);
        }

        Ok(ciphertext)
    }

    fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // XOR is symmetric
        self.encrypt(key_id, ciphertext)
    }

    fn generate_data_key(&self, key_id: &str) -> Result<GeneratedDataKey, CryptoError> {
        let plaintext = KeyEncryptionKey::generate_key_material().to_vec();
        let ciphertext = self.encrypt(key_id, &plaintext)?;

        Ok(GeneratedDataKey {
            plaintext,
            ciphertext,
            key_id: key_id.to_string(),
        })
    }
}

/// GCP Cloud KMS provider (simulated)
pub struct GcpKmsProvider {
    project: String,
    location: String,
    keys: HashMap<String, [u8; 32]>,
}

impl GcpKmsProvider {
    pub fn new(project: &str, location: &str) -> Self {
        Self {
            project: project.to_string(),
            location: location.to_string(),
            keys: HashMap::new(),
        }
    }

    pub fn register_key(&mut self, key_ring: &str, key_name: &str) {
        let full_name = format!(
            "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}",
            self.project, self.location, key_ring, key_name
        );
        let key = KeyEncryptionKey::generate_key_material();
        self.keys.insert(full_name, key);
    }

    pub fn key_name(&self, key_ring: &str, key_name: &str) -> String {
        format!(
            "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}",
            self.project, self.location, key_ring, key_name
        )
    }
}

impl KmsProvider for GcpKmsProvider {
    fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = self.keys.get(key_id).ok_or(CryptoError::KeyNotFound)?;

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for (i, &byte) in plaintext.iter().enumerate() {
            ciphertext.push(byte ^ key[i % key.len()]);
        }

        Ok(ciphertext)
    }

    fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.encrypt(key_id, ciphertext)
    }

    fn generate_data_key(&self, key_id: &str) -> Result<GeneratedDataKey, CryptoError> {
        let plaintext = KeyEncryptionKey::generate_key_material().to_vec();
        let ciphertext = self.encrypt(key_id, &plaintext)?;

        Ok(GeneratedDataKey {
            plaintext,
            ciphertext,
            key_id: key_id.to_string(),
        })
    }
}

/// Azure Key Vault provider (simulated)
pub struct AzureKeyVaultProvider {
    vault_name: String,
    keys: HashMap<String, [u8; 32]>,
}

impl AzureKeyVaultProvider {
    pub fn new(vault_name: &str) -> Self {
        Self {
            vault_name: vault_name.to_string(),
            keys: HashMap::new(),
        }
    }

    pub fn register_key(&mut self, key_name: &str) {
        let full_name = format!(
            "https://{}.vault.azure.net/keys/{}",
            self.vault_name, key_name
        );
        let key = KeyEncryptionKey::generate_key_material();
        self.keys.insert(full_name, key);
    }

    pub fn key_url(&self, key_name: &str) -> String {
        format!(
            "https://{}.vault.azure.net/keys/{}",
            self.vault_name, key_name
        )
    }
}

impl KmsProvider for AzureKeyVaultProvider {
    fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = self.keys.get(key_id).ok_or(CryptoError::KeyNotFound)?;

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for (i, &byte) in plaintext.iter().enumerate() {
            ciphertext.push(byte ^ key[i % key.len()]);
        }

        Ok(ciphertext)
    }

    fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.encrypt(key_id, ciphertext)
    }

    fn generate_data_key(&self, key_id: &str) -> Result<GeneratedDataKey, CryptoError> {
        let plaintext = KeyEncryptionKey::generate_key_material().to_vec();
        let ciphertext = self.encrypt(key_id, &plaintext)?;

        Ok(GeneratedDataKey {
            plaintext,
            ciphertext,
            key_id: key_id.to_string(),
        })
    }
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug)]
pub enum CryptoError {
    KeyNotFound,
    KeyExpired,
    KeyMismatch,
    AuthenticationFailed,
    InvalidFormat,
    UnsupportedAlgorithm,
    NoDefaultKey,
    EncryptionFailed(String),
    DecryptionFailed(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::KeyNotFound => write!(f, "Key not found"),
            CryptoError::KeyExpired => write!(f, "Key has expired"),
            CryptoError::KeyMismatch => write!(f, "Key ID mismatch"),
            CryptoError::AuthenticationFailed => write!(f, "Authentication failed"),
            CryptoError::InvalidFormat => write!(f, "Invalid format"),
            CryptoError::UnsupportedAlgorithm => write!(f, "Unsupported algorithm"),
            CryptoError::NoDefaultKey => write!(f, "No default key configured"),
            CryptoError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            CryptoError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {}

// ============================================================================
// Helper Functions
// ============================================================================

fn generate_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}", timestamp)
}

fn generate_nonce() -> [u8; 12] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let state = RandomState::new();
    let mut hasher = state.build_hasher();

    hasher.write_u128(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    );

    let hash = hasher.finish();
    let mut nonce = [0u8; 12];

    for (i, byte) in nonce.iter_mut().enumerate() {
        *byte = ((hash >> (i * 5)) & 0xFF) as u8;
    }

    nonce
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== Envelope Encryption Implementation ===\n");

    // Example 1: Basic envelope encryption
    println!("1. Basic Envelope Encryption:");

    let mut service = EnvelopeService::new();

    // Generate and register a KEK
    let kek = KeyEncryptionKey::generate("master-key-1", KeyAlgorithm::Aes256Gcm);
    println!("   Created KEK: {}", kek.key_id);
    service.register_key(kek);

    // Encrypt some data
    let plaintext = b"This is sensitive data that needs encryption";
    let envelope = service.encrypt(plaintext).unwrap();

    println!("   Original: {:?}", String::from_utf8_lossy(plaintext));
    println!(
        "   Ciphertext length: {} bytes",
        envelope.encrypted_data.ciphertext.len()
    );
    println!(
        "   Wrapped key length: {} bytes",
        envelope.wrapped_key.wrapped_key.len()
    );

    // Decrypt
    let decrypted = service.decrypt(&envelope).unwrap();
    println!("   Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
    println!("   Match: {}", plaintext == decrypted.as_slice());

    // Example 2: Multiple KEKs
    println!("\n2. Multiple KEKs:");
    let kek2 = KeyEncryptionKey::generate("master-key-2", KeyAlgorithm::ChaCha20Poly1305);
    service.register_key(kek2);

    println!("   Registered keys: {:?}", service.key_ids());

    // Encrypt with specific key
    let envelope2 = service
        .encrypt_with_key(b"Different data", Some("master-key-2"))
        .unwrap();
    println!("   Encrypted with: {}", envelope2.wrapped_key.kek_id);

    // Example 3: Key rotation
    println!("\n3. Key Rotation:");
    let kek3 = KeyEncryptionKey::generate("master-key-3", KeyAlgorithm::Aes256Gcm);
    service.register_key(kek3);

    // Re-encrypt with new key
    let old_kek_id = envelope.wrapped_key.kek_id.clone();
    let rotated = service.reencrypt(&envelope, "master-key-3").unwrap();

    println!("   Old KEK: {}", old_kek_id);
    println!("   New KEK: {}", rotated.wrapped_key.kek_id);

    // Verify data is still accessible
    let decrypted_rotated = service.decrypt(&rotated).unwrap();
    println!(
        "   Data preserved: {}",
        plaintext == decrypted_rotated.as_slice()
    );

    // Example 4: Envelope with metadata
    println!("\n4. Envelope with Metadata:");
    let mut metadata = HashMap::new();
    metadata.insert("content-type".to_string(), "application/json".to_string());
    metadata.insert("version".to_string(), "1.0".to_string());

    let envelope_meta = service
        .encrypt_with_metadata(b"{\"user\": \"test\"}", metadata)
        .unwrap();
    println!("   Metadata:");
    for (key, value) in &envelope_meta.metadata {
        println!("     {}: {}", key, value);
    }

    // Example 5: AWS KMS simulation
    println!("\n5. AWS KMS Integration:");
    let mut aws_kms = AwsKmsProvider::new("us-east-1");
    aws_kms.register_key("alias/my-key");

    let data_key = aws_kms.generate_data_key("alias/my-key").unwrap();
    println!("   Generated data key for: {}", data_key.key_id);
    println!(
        "   Plaintext key length: {} bytes",
        data_key.plaintext.len()
    );
    println!(
        "   Encrypted key length: {} bytes",
        data_key.ciphertext.len()
    );

    // Example 6: GCP Cloud KMS simulation
    println!("\n6. GCP Cloud KMS Integration:");
    let mut gcp_kms = GcpKmsProvider::new("my-project", "global");
    gcp_kms.register_key("my-keyring", "my-key");

    let key_name = gcp_kms.key_name("my-keyring", "my-key");
    println!("   Key name: {}", key_name);

    let gcp_data_key = gcp_kms.generate_data_key(&key_name).unwrap();
    println!("   Generated data key");

    // Example 7: Azure Key Vault simulation
    println!("\n7. Azure Key Vault Integration:");
    let mut azure_kv = AzureKeyVaultProvider::new("my-vault");
    azure_kv.register_key("my-key");

    let key_url = azure_kv.key_url("my-key");
    println!("   Key URL: {}", key_url);

    // Example 8: Envelope serialization
    println!("\n8. Envelope Serialization:");
    let envelope_bytes = envelope.to_bytes();
    println!("   Serialized envelope: {} bytes", envelope_bytes.len());
    println!(
        "   Header: {:?}",
        String::from_utf8_lossy(&envelope_bytes[0..4])
    );

    // Example 9: Service statistics
    println!("\n9. Service Statistics:");
    let stats = service.stats();
    println!("   Encryptions: {}", stats.encryptions);
    println!("   Decryptions: {}", stats.decryptions);
    println!("   Key wraps: {}", stats.key_wraps);
    println!("   Key unwraps: {}", stats.key_unwraps);

    // Example 10: Key expiration
    println!("\n10. Key Expiration:");
    let kek = KeyEncryptionKey::generate("temp-key", KeyAlgorithm::Aes256Gcm);
    println!("   Key expired: {}", kek.is_expired());
    println!("   Expires at: {:?}", kek.expires_at);

    println!("\n=== Envelope Encryption Complete ===");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kek_generation() {
        let kek = KeyEncryptionKey::generate("test-key", KeyAlgorithm::Aes256Gcm);
        assert_eq!(kek.key_id, "test-key");
        assert!(!kek.is_expired());
    }

    #[test]
    fn test_dek_generation() {
        let dek = DataEncryptionKey::generate(KeyAlgorithm::Aes256Gcm);
        assert!(!dek.key_id.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let dek = DataEncryptionKey::generate(KeyAlgorithm::Aes256Gcm);
        let plaintext = b"test data";

        let encrypted = dek.encrypt(plaintext).unwrap();
        let decrypted = dek.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_key_wrap_unwrap() {
        let kek = KeyEncryptionKey::generate("kek", KeyAlgorithm::Aes256Gcm);
        let dek = DataEncryptionKey::generate(KeyAlgorithm::Aes256Gcm);

        let wrapped = kek.wrap_key(&dek).unwrap();
        let unwrapped = kek.unwrap_key(&wrapped).unwrap();

        // Keys should be functionally equivalent
        let plaintext = b"test";
        let encrypted = dek.encrypt(plaintext).unwrap();
        let decrypted = unwrapped.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_envelope_service() {
        let mut service = EnvelopeService::new();
        let kek = KeyEncryptionKey::generate("master", KeyAlgorithm::Aes256Gcm);
        service.register_key(kek);

        let plaintext = b"sensitive data";
        let envelope = service.encrypt(plaintext).unwrap();
        let decrypted = service.decrypt(&envelope).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_key_rotation() {
        let mut service = EnvelopeService::new();
        service.register_key(KeyEncryptionKey::generate("key-1", KeyAlgorithm::Aes256Gcm));
        service.register_key(KeyEncryptionKey::generate("key-2", KeyAlgorithm::Aes256Gcm));

        let plaintext = b"data";
        let envelope = service.encrypt_with_key(plaintext, Some("key-1")).unwrap();
        let rotated = service.reencrypt(&envelope, "key-2").unwrap();

        assert_eq!(rotated.wrapped_key.kek_id, "key-2");

        let decrypted = service.decrypt(&rotated).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_wrapped_key_serialization() {
        let kek = KeyEncryptionKey::generate("kek", KeyAlgorithm::Aes256Gcm);
        let dek = DataEncryptionKey::generate(KeyAlgorithm::Aes256Gcm);

        let wrapped = kek.wrap_key(&dek).unwrap();
        let bytes = wrapped.to_bytes();
        let restored = WrappedKey::from_bytes(&bytes).unwrap();

        assert_eq!(wrapped.kek_id, restored.kek_id);
        assert_eq!(wrapped.kek_version, restored.kek_version);
    }

    #[test]
    fn test_algorithm_from_u8() {
        assert!(matches!(
            KeyAlgorithm::from_u8(1),
            Ok(KeyAlgorithm::Aes256Gcm)
        ));
        assert!(matches!(
            KeyAlgorithm::from_u8(2),
            Ok(KeyAlgorithm::ChaCha20Poly1305)
        ));
        assert!(matches!(
            KeyAlgorithm::from_u8(99),
            Err(CryptoError::UnsupportedAlgorithm)
        ));
    }

    #[test]
    fn test_aws_kms_provider() {
        let mut kms = AwsKmsProvider::new("us-east-1");
        kms.register_key("test-key");

        let data_key = kms.generate_data_key("test-key").unwrap();
        assert_eq!(data_key.key_id, "test-key");
        assert_eq!(data_key.plaintext.len(), 32);
    }

    #[test]
    fn test_gcp_kms_provider() {
        let mut kms = GcpKmsProvider::new("project", "location");
        kms.register_key("ring", "key");

        let key_name = kms.key_name("ring", "key");
        let data_key = kms.generate_data_key(&key_name).unwrap();

        assert!(!data_key.plaintext.is_empty());
    }

    #[test]
    fn test_azure_kv_provider() {
        let mut kv = AzureKeyVaultProvider::new("vault");
        kv.register_key("key");

        let key_url = kv.key_url("key");
        let data_key = kv.generate_data_key(&key_url).unwrap();

        assert!(!data_key.plaintext.is_empty());
    }

    #[test]
    fn test_envelope_serialization() {
        let mut service = EnvelopeService::new();
        service.register_key(KeyEncryptionKey::generate("key", KeyAlgorithm::Aes256Gcm));

        let envelope = service.encrypt(b"test").unwrap();
        let bytes = envelope.to_bytes();

        // Check magic number
        assert_eq!(&bytes[0..4], b"ENV1");
    }

    #[test]
    fn test_service_stats() {
        let mut service = EnvelopeService::new();
        service.register_key(KeyEncryptionKey::generate("key", KeyAlgorithm::Aes256Gcm));

        let _ = service.encrypt(b"test");

        let stats = service.stats();
        assert_eq!(stats.encryptions, 1);
        assert_eq!(stats.key_wraps, 1);
    }

    #[test]
    fn test_metadata() {
        let mut service = EnvelopeService::new();
        service.register_key(KeyEncryptionKey::generate("key", KeyAlgorithm::Aes256Gcm));

        let mut metadata = HashMap::new();
        metadata.insert("key".to_string(), "value".to_string());

        let envelope = service.encrypt_with_metadata(b"test", metadata).unwrap();
        assert_eq!(envelope.metadata.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_key_mismatch() {
        let kek1 = KeyEncryptionKey::generate("kek1", KeyAlgorithm::Aes256Gcm);
        let kek2 = KeyEncryptionKey::generate("kek2", KeyAlgorithm::Aes256Gcm);
        let dek = DataEncryptionKey::generate(KeyAlgorithm::Aes256Gcm);

        let wrapped = kek1.wrap_key(&dek).unwrap();
        let result = kek2.unwrap_key(&wrapped);

        assert!(matches!(result, Err(CryptoError::KeyMismatch)));
    }

    #[test]
    fn test_no_default_key() {
        let mut service = EnvelopeService::new();
        let result = service.encrypt(b"test");

        assert!(matches!(result, Err(CryptoError::NoDefaultKey)));
    }
}
