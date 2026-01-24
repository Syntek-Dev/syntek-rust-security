//! UniFFI React Native Integration - Cross-Platform Mobile Encryption
//!
//! This example demonstrates building a cross-platform encryption library
//! using UniFFI for React Native (iOS and Android) applications.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Error types exposed to React Native
#[derive(Debug, Clone)]
pub enum MobileCryptoError {
    KeyNotFound { key_id: String },
    InvalidKeyMaterial { reason: String },
    EncryptionFailed { reason: String },
    DecryptionFailed { reason: String },
    AuthenticationFailed,
    BiometricRequired,
    KeychainAccessDenied,
    InvalidInput { field: String, reason: String },
    StorageError { reason: String },
}

impl std::fmt::Display for MobileCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyNotFound { key_id } => write!(f, "Key not found: {}", key_id),
            Self::InvalidKeyMaterial { reason } => write!(f, "Invalid key material: {}", reason),
            Self::EncryptionFailed { reason } => write!(f, "Encryption failed: {}", reason),
            Self::DecryptionFailed { reason } => write!(f, "Decryption failed: {}", reason),
            Self::AuthenticationFailed => write!(f, "Authentication tag verification failed"),
            Self::BiometricRequired => write!(f, "Biometric authentication required"),
            Self::KeychainAccessDenied => write!(f, "Keychain access denied"),
            Self::InvalidInput { field, reason } => {
                write!(f, "Invalid input for {}: {}", field, reason)
            }
            Self::StorageError { reason } => write!(f, "Storage error: {}", reason),
        }
    }
}

impl std::error::Error for MobileCryptoError {}

/// Key protection level for mobile platforms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProtection {
    /// Key stored in app sandbox (least secure)
    Software,
    /// Key stored in OS keychain/keystore
    Keychain,
    /// Key protected by Secure Enclave (iOS) or StrongBox (Android)
    SecureHardware,
    /// Key requires biometric authentication to use
    BiometricProtected,
}

/// Algorithm selection for mobile
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MobileAlgorithm {
    /// AES-256-GCM - widely supported, hardware acceleration
    Aes256Gcm,
    /// ChaCha20-Poly1305 - good on older devices without AES-NI
    ChaCha20Poly1305,
}

impl MobileAlgorithm {
    pub fn key_size(&self) -> usize {
        32
    }

    pub fn nonce_size(&self) -> usize {
        12
    }
}

/// Key metadata for React Native
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub id: String,
    pub algorithm: MobileAlgorithm,
    pub protection: KeyProtection,
    pub created_at_millis: u64,
    pub last_used_millis: Option<u64>,
    pub use_count: u64,
}

/// Internal key storage
struct MobileKey {
    info: KeyInfo,
    key_bytes: Vec<u8>,
}

impl Drop for MobileKey {
    fn drop(&mut self) {
        // Secure zeroization
        for byte in &mut self.key_bytes {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Encrypted data container for React Native
#[derive(Debug, Clone)]
pub struct EncryptedPayload {
    pub ciphertext_hex: String,
    pub nonce_hex: String,
    pub tag_hex: String,
    pub key_id: String,
    pub algorithm: String,
}

/// Configuration for the crypto manager
#[derive(Debug, Clone)]
pub struct CryptoConfig {
    pub default_algorithm: MobileAlgorithm,
    pub default_protection: KeyProtection,
    pub require_biometric_for_sensitive: bool,
    pub key_rotation_days: u32,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            default_algorithm: MobileAlgorithm::Aes256Gcm,
            default_protection: KeyProtection::Keychain,
            require_biometric_for_sensitive: true,
            key_rotation_days: 90,
        }
    }
}

/// Main crypto manager exposed to React Native via UniFFI
pub struct MobileCryptoManager {
    config: CryptoConfig,
    keys: RwLock<HashMap<String, MobileKey>>,
    biometric_authenticated: RwLock<bool>,
}

impl MobileCryptoManager {
    /// Create a new crypto manager with default config
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            config: CryptoConfig::default(),
            keys: RwLock::new(HashMap::new()),
            biometric_authenticated: RwLock::new(false),
        })
    }

    /// Create with custom configuration
    pub fn with_config(config: CryptoConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            keys: RwLock::new(HashMap::new()),
            biometric_authenticated: RwLock::new(false),
        })
    }

    /// Generate a new encryption key
    pub fn generate_key(
        &self,
        key_id: String,
        protection: Option<KeyProtection>,
    ) -> Result<KeyInfo, MobileCryptoError> {
        let protection = protection.unwrap_or(self.config.default_protection);
        let algorithm = self.config.default_algorithm;

        let key_bytes = generate_secure_random(algorithm.key_size());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let info = KeyInfo {
            id: key_id.clone(),
            algorithm,
            protection,
            created_at_millis: now,
            last_used_millis: None,
            use_count: 0,
        };

        let key = MobileKey {
            info: info.clone(),
            key_bytes,
        };

        let mut keys = self.keys.write().unwrap();
        keys.insert(key_id, key);

        Ok(info)
    }

    /// Import a key from bytes (hex-encoded for React Native)
    pub fn import_key(
        &self,
        key_id: String,
        key_hex: String,
        protection: Option<KeyProtection>,
    ) -> Result<KeyInfo, MobileCryptoError> {
        let key_bytes =
            hex_decode(&key_hex).map_err(|e| MobileCryptoError::InvalidKeyMaterial {
                reason: e.to_string(),
            })?;

        let algorithm = self.config.default_algorithm;
        if key_bytes.len() != algorithm.key_size() {
            return Err(MobileCryptoError::InvalidKeyMaterial {
                reason: format!(
                    "Expected {} bytes, got {}",
                    algorithm.key_size(),
                    key_bytes.len()
                ),
            });
        }

        let protection = protection.unwrap_or(self.config.default_protection);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let info = KeyInfo {
            id: key_id.clone(),
            algorithm,
            protection,
            created_at_millis: now,
            last_used_millis: None,
            use_count: 0,
        };

        let key = MobileKey {
            info: info.clone(),
            key_bytes,
        };

        let mut keys = self.keys.write().unwrap();
        keys.insert(key_id, key);

        Ok(info)
    }

    /// Get information about a key
    pub fn get_key_info(&self, key_id: String) -> Result<KeyInfo, MobileCryptoError> {
        let keys = self.keys.read().unwrap();
        keys.get(&key_id)
            .map(|k| k.info.clone())
            .ok_or(MobileCryptoError::KeyNotFound { key_id })
    }

    /// List all key IDs
    pub fn list_keys(&self) -> Vec<String> {
        self.keys.read().unwrap().keys().cloned().collect()
    }

    /// Delete a key
    pub fn delete_key(&self, key_id: String) -> Result<(), MobileCryptoError> {
        let mut keys = self.keys.write().unwrap();
        keys.remove(&key_id)
            .map(|_| ())
            .ok_or(MobileCryptoError::KeyNotFound { key_id })
    }

    /// Set biometric authentication status (called from React Native after Face ID/Touch ID)
    pub fn set_biometric_authenticated(&self, authenticated: bool) {
        *self.biometric_authenticated.write().unwrap() = authenticated;
    }

    /// Encrypt a string (most common use case in React Native)
    pub fn encrypt_string(
        &self,
        key_id: String,
        plaintext: String,
    ) -> Result<EncryptedPayload, MobileCryptoError> {
        self.encrypt_bytes(key_id, plaintext.into_bytes())
    }

    /// Encrypt raw bytes
    pub fn encrypt_bytes(
        &self,
        key_id: String,
        plaintext: Vec<u8>,
    ) -> Result<EncryptedPayload, MobileCryptoError> {
        // Check biometric requirement
        {
            let keys = self.keys.read().unwrap();
            if let Some(key) = keys.get(&key_id) {
                if key.info.protection == KeyProtection::BiometricProtected {
                    if !*self.biometric_authenticated.read().unwrap() {
                        return Err(MobileCryptoError::BiometricRequired);
                    }
                }
            } else {
                return Err(MobileCryptoError::KeyNotFound {
                    key_id: key_id.clone(),
                });
            }
        }

        // Perform encryption
        let (ciphertext, nonce, tag, algorithm) = {
            let mut keys = self.keys.write().unwrap();
            let key = keys.get_mut(&key_id).unwrap();

            let nonce = generate_secure_random(key.info.algorithm.nonce_size());
            let (ciphertext, tag) = encrypt_aead(&key.key_bytes, &nonce, &plaintext)?;

            // Update usage stats
            key.info.use_count += 1;
            key.info.last_used_millis = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            );

            let algorithm = format!("{:?}", key.info.algorithm);
            (ciphertext, nonce, tag, algorithm)
        };

        Ok(EncryptedPayload {
            ciphertext_hex: hex_encode(&ciphertext),
            nonce_hex: hex_encode(&nonce),
            tag_hex: hex_encode(&tag),
            key_id,
            algorithm,
        })
    }

    /// Decrypt to string
    pub fn decrypt_string(&self, payload: EncryptedPayload) -> Result<String, MobileCryptoError> {
        let bytes = self.decrypt_bytes(payload)?;
        String::from_utf8(bytes).map_err(|e| MobileCryptoError::DecryptionFailed {
            reason: format!("Invalid UTF-8: {}", e),
        })
    }

    /// Decrypt to raw bytes
    pub fn decrypt_bytes(&self, payload: EncryptedPayload) -> Result<Vec<u8>, MobileCryptoError> {
        // Check biometric requirement
        {
            let keys = self.keys.read().unwrap();
            if let Some(key) = keys.get(&payload.key_id) {
                if key.info.protection == KeyProtection::BiometricProtected {
                    if !*self.biometric_authenticated.read().unwrap() {
                        return Err(MobileCryptoError::BiometricRequired);
                    }
                }
            } else {
                return Err(MobileCryptoError::KeyNotFound {
                    key_id: payload.key_id.clone(),
                });
            }
        }

        // Decode hex values
        let ciphertext =
            hex_decode(&payload.ciphertext_hex).map_err(|e| MobileCryptoError::InvalidInput {
                field: "ciphertext".to_string(),
                reason: e.to_string(),
            })?;
        let nonce =
            hex_decode(&payload.nonce_hex).map_err(|e| MobileCryptoError::InvalidInput {
                field: "nonce".to_string(),
                reason: e.to_string(),
            })?;
        let tag = hex_decode(&payload.tag_hex).map_err(|e| MobileCryptoError::InvalidInput {
            field: "tag".to_string(),
            reason: e.to_string(),
        })?;

        // Perform decryption
        let plaintext = {
            let mut keys = self.keys.write().unwrap();
            let key = keys.get_mut(&payload.key_id).unwrap();

            let plaintext = decrypt_aead(&key.key_bytes, &nonce, &ciphertext, &tag)?;

            // Update usage stats
            key.info.use_count += 1;
            key.info.last_used_millis = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            );

            plaintext
        };

        Ok(plaintext)
    }

    /// Check if a key needs rotation
    pub fn key_needs_rotation(&self, key_id: String) -> Result<bool, MobileCryptoError> {
        let keys = self.keys.read().unwrap();
        let key = keys
            .get(&key_id)
            .ok_or(MobileCryptoError::KeyNotFound { key_id })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let age_millis = now - key.info.created_at_millis;
        let rotation_millis = self.config.key_rotation_days as u64 * 24 * 60 * 60 * 1000;

        Ok(age_millis >= rotation_millis)
    }
}

impl Default for MobileCryptoManager {
    fn default() -> Self {
        Self {
            config: CryptoConfig::default(),
            keys: RwLock::new(HashMap::new()),
            biometric_authenticated: RwLock::new(false),
        }
    }
}

/// Secure storage abstraction for React Native
pub struct SecureStorage {
    manager: Arc<MobileCryptoManager>,
    storage_key_id: String,
}

impl SecureStorage {
    /// Create a new secure storage instance
    pub fn new(manager: Arc<MobileCryptoManager>) -> Result<Self, MobileCryptoError> {
        // Generate or retrieve storage key
        let storage_key_id = "secure_storage_master_key".to_string();

        if manager.get_key_info(storage_key_id.clone()).is_err() {
            manager.generate_key(storage_key_id.clone(), Some(KeyProtection::SecureHardware))?;
        }

        Ok(Self {
            manager,
            storage_key_id,
        })
    }

    /// Store a value securely
    pub fn set(&self, key: String, value: String) -> Result<EncryptedPayload, MobileCryptoError> {
        // Prefix key to avoid collisions
        let storage_value = format!("{}:{}", key, value);
        self.manager
            .encrypt_string(self.storage_key_id.clone(), storage_value)
    }

    /// Retrieve a value
    pub fn get(&self, payload: EncryptedPayload) -> Result<(String, String), MobileCryptoError> {
        let decrypted = self.manager.decrypt_string(payload)?;

        let parts: Vec<&str> = decrypted.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(MobileCryptoError::StorageError {
                reason: "Invalid storage format".to_string(),
            });
        }

        Ok((parts[0].to_string(), parts[1].to_string()))
    }
}

/// Biometric-protected credential storage
pub struct CredentialVault {
    manager: Arc<MobileCryptoManager>,
    vault_key_id: String,
}

impl CredentialVault {
    /// Create a new credential vault (requires biometric setup)
    pub fn new(manager: Arc<MobileCryptoManager>) -> Result<Self, MobileCryptoError> {
        let vault_key_id = "credential_vault_key".to_string();

        if manager.get_key_info(vault_key_id.clone()).is_err() {
            manager.generate_key(
                vault_key_id.clone(),
                Some(KeyProtection::BiometricProtected),
            )?;
        }

        Ok(Self {
            manager,
            vault_key_id,
        })
    }

    /// Store a credential (requires biometric auth first)
    pub fn store_credential(
        &self,
        service: String,
        username: String,
        password: String,
    ) -> Result<EncryptedPayload, MobileCryptoError> {
        let credential = format!("{}:{}:{}", service, username, password);
        self.manager
            .encrypt_string(self.vault_key_id.clone(), credential)
    }

    /// Retrieve a credential (requires biometric auth first)
    pub fn retrieve_credential(
        &self,
        payload: EncryptedPayload,
    ) -> Result<(String, String, String), MobileCryptoError> {
        let decrypted = self.manager.decrypt_string(payload)?;

        let parts: Vec<&str> = decrypted.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(MobileCryptoError::StorageError {
                reason: "Invalid credential format".to_string(),
            });
        }

        Ok((
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].to_string(),
        ))
    }
}

// Helper functions

fn generate_secure_random(size: usize) -> Vec<u8> {
    // In production, use platform-specific CSPRNG
    // iOS: SecRandomCopyBytes
    // Android: SecureRandom
    (0..size)
        .map(|i| {
            ((i * 31 + 17) ^ (SystemTime::now().elapsed().unwrap_or_default().as_nanos() as usize))
                as u8
        })
        .collect()
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("Invalid hex string length".to_string());
    }

    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("Invalid hex: {}", e)))
        .collect()
}

fn encrypt_aead(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), MobileCryptoError> {
    // Simplified AEAD - in production use RustCrypto aead crate
    let mut ciphertext = plaintext.to_vec();
    for (i, byte) in ciphertext.iter_mut().enumerate() {
        *byte ^= key[i % key.len()] ^ nonce[i % nonce.len()];
    }

    // Generate tag
    let mut tag = vec![0u8; 16];
    for (i, t) in tag.iter_mut().enumerate() {
        *t = key[i % key.len()] ^ ciphertext.get(i).copied().unwrap_or(0);
    }

    Ok((ciphertext, tag))
}

fn decrypt_aead(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, MobileCryptoError> {
    // Verify tag first
    let mut expected_tag = vec![0u8; 16];
    for (i, t) in expected_tag.iter_mut().enumerate() {
        *t = key[i % key.len()] ^ ciphertext.get(i).copied().unwrap_or(0);
    }

    // Constant-time comparison
    let mut diff = 0u8;
    for (a, b) in tag.iter().zip(expected_tag.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(MobileCryptoError::AuthenticationFailed);
    }

    // Decrypt
    let mut plaintext = ciphertext.to_vec();
    for (i, byte) in plaintext.iter_mut().enumerate() {
        *byte ^= key[i % key.len()] ^ nonce[i % nonce.len()];
    }

    Ok(plaintext)
}

fn main() {
    println!("=== UniFFI React Native Crypto Module ===\n");

    // Create manager with custom config
    let config = CryptoConfig {
        default_algorithm: MobileAlgorithm::Aes256Gcm,
        default_protection: KeyProtection::Keychain,
        require_biometric_for_sensitive: true,
        key_rotation_days: 90,
    };
    let manager = MobileCryptoManager::with_config(config);

    // Generate encryption key
    let key_info = manager
        .generate_key("user-data-key".to_string(), None)
        .unwrap();
    println!("Generated key: {}", key_info.id);
    println!("  Algorithm: {:?}", key_info.algorithm);
    println!("  Protection: {:?}", key_info.protection);

    // Encrypt user data
    let user_json = r#"{"email": "user@example.com", "token": "secret123"}"#;
    let encrypted = manager
        .encrypt_string("user-data-key".to_string(), user_json.to_string())
        .unwrap();
    println!("\nEncrypted user data:");
    println!("  Ciphertext: {}...", &encrypted.ciphertext_hex[..20]);
    println!("  Key ID: {}", encrypted.key_id);

    // Decrypt
    let decrypted = manager.decrypt_string(encrypted).unwrap();
    println!("Decrypted: {}", decrypted);

    // Biometric-protected key example
    println!("\n--- Biometric Protection ---");
    let bio_key = manager
        .generate_key(
            "bio-protected-key".to_string(),
            Some(KeyProtection::BiometricProtected),
        )
        .unwrap();
    println!("Created biometric-protected key: {}", bio_key.id);

    // Try to use without authentication
    let result = manager.encrypt_string("bio-protected-key".to_string(), "secret".to_string());
    match result {
        Err(MobileCryptoError::BiometricRequired) => {
            println!("Biometric authentication required (expected)");
        }
        _ => println!("Unexpected result"),
    }

    // Simulate biometric authentication
    manager.set_biometric_authenticated(true);
    let encrypted = manager
        .encrypt_string("bio-protected-key".to_string(), "secret data".to_string())
        .unwrap();
    println!("Encrypted after biometric auth: success");

    // Secure storage example
    println!("\n--- Secure Storage ---");
    let storage = SecureStorage::new(Arc::clone(&manager)).unwrap();
    let stored = storage
        .set("api_key".to_string(), "sk-abc123xyz".to_string())
        .unwrap();
    println!("Stored value encrypted with key: {}", stored.key_id);

    let (key, value) = storage.get(stored).unwrap();
    println!("Retrieved: {} = {}", key, value);

    // Credential vault example
    println!("\n--- Credential Vault ---");
    let vault = CredentialVault::new(Arc::clone(&manager)).unwrap();
    let cred = vault
        .store_credential(
            "github.com".to_string(),
            "user@example.com".to_string(),
            "ghp_secrettoken".to_string(),
        )
        .unwrap();
    println!("Credential stored");

    let (service, username, password) = vault.retrieve_credential(cred).unwrap();
    println!("Retrieved: {} - {} / ***", service, username);

    // Key rotation check
    println!("\n--- Key Management ---");
    let needs_rotation = manager
        .key_needs_rotation("user-data-key".to_string())
        .unwrap();
    println!("Key needs rotation: {}", needs_rotation);

    let keys = manager.list_keys();
    println!("Total keys: {}", keys.len());

    println!("\n=== UniFFI Module Ready for React Native ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let manager = MobileCryptoManager::new();
        let info = manager.generate_key("test-key".to_string(), None).unwrap();

        assert_eq!(info.id, "test-key");
        assert_eq!(info.use_count, 0);
    }

    #[test]
    fn test_encrypt_decrypt_string() {
        let manager = MobileCryptoManager::new();
        manager
            .generate_key("test".to_string(), Some(KeyProtection::Software))
            .unwrap();

        let original = "Hello, React Native!";
        let encrypted = manager
            .encrypt_string("test".to_string(), original.to_string())
            .unwrap();
        let decrypted = manager.decrypt_string(encrypted).unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_bytes() {
        let manager = MobileCryptoManager::new();
        manager.generate_key("bytes-key".to_string(), None).unwrap();

        let original = vec![0x01, 0x02, 0x03, 0x04];
        let encrypted = manager
            .encrypt_bytes("bytes-key".to_string(), original.clone())
            .unwrap();
        let decrypted = manager.decrypt_bytes(encrypted).unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_biometric_requirement() {
        let manager = MobileCryptoManager::new();
        manager
            .generate_key(
                "bio-key".to_string(),
                Some(KeyProtection::BiometricProtected),
            )
            .unwrap();

        // Should fail without biometric auth
        let result = manager.encrypt_string("bio-key".to_string(), "test".to_string());
        assert!(matches!(result, Err(MobileCryptoError::BiometricRequired)));

        // Should succeed after auth
        manager.set_biometric_authenticated(true);
        let result = manager.encrypt_string("bio-key".to_string(), "test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_key_not_found() {
        let manager = MobileCryptoManager::new();
        let result = manager.encrypt_string("nonexistent".to_string(), "test".to_string());
        assert!(matches!(result, Err(MobileCryptoError::KeyNotFound { .. })));
    }

    #[test]
    fn test_import_key() {
        let manager = MobileCryptoManager::new();
        let key_hex = "0102030405060708091011121314151617181920212223242526272829303132";
        let info = manager
            .import_key("imported".to_string(), key_hex.to_string(), None)
            .unwrap();

        assert_eq!(info.id, "imported");
    }

    #[test]
    fn test_invalid_key_size() {
        let manager = MobileCryptoManager::new();
        let result = manager.import_key("bad".to_string(), "0102".to_string(), None);
        assert!(matches!(
            result,
            Err(MobileCryptoError::InvalidKeyMaterial { .. })
        ));
    }

    #[test]
    fn test_usage_tracking() {
        let manager = MobileCryptoManager::new();
        manager
            .generate_key("tracked".to_string(), Some(KeyProtection::Software))
            .unwrap();

        manager
            .encrypt_string("tracked".to_string(), "data1".to_string())
            .unwrap();
        manager
            .encrypt_string("tracked".to_string(), "data2".to_string())
            .unwrap();

        let info = manager.get_key_info("tracked".to_string()).unwrap();
        assert_eq!(info.use_count, 2);
        assert!(info.last_used_millis.is_some());
    }

    #[test]
    fn test_delete_key() {
        let manager = MobileCryptoManager::new();
        manager.generate_key("to-delete".to_string(), None).unwrap();

        assert!(manager.list_keys().contains(&"to-delete".to_string()));
        manager.delete_key("to-delete".to_string()).unwrap();
        assert!(!manager.list_keys().contains(&"to-delete".to_string()));
    }

    #[test]
    fn test_secure_storage() {
        let manager = MobileCryptoManager::new();
        manager.set_biometric_authenticated(true);
        let storage = SecureStorage::new(manager).unwrap();

        let payload = storage
            .set("my_key".to_string(), "my_value".to_string())
            .unwrap();
        let (key, value) = storage.get(payload).unwrap();

        assert_eq!(key, "my_key");
        assert_eq!(value, "my_value");
    }

    #[test]
    fn test_hex_encode_decode() {
        let original = vec![0x00, 0x0F, 0x10, 0xFF];
        let encoded = hex_encode(&original);
        let decoded = hex_decode(&encoded).unwrap();

        assert_eq!(original, decoded);
        assert_eq!(encoded, "000f10ff");
    }

    #[test]
    fn test_authentication_failure() {
        let manager = MobileCryptoManager::new();
        manager
            .generate_key("auth-test".to_string(), Some(KeyProtection::Software))
            .unwrap();

        let mut encrypted = manager
            .encrypt_string("auth-test".to_string(), "secret".to_string())
            .unwrap();

        // Tamper with tag
        let mut tag_bytes = hex_decode(&encrypted.tag_hex).unwrap();
        tag_bytes[0] ^= 0xFF;
        encrypted.tag_hex = hex_encode(&tag_bytes);

        let result = manager.decrypt_string(encrypted);
        assert!(matches!(
            result,
            Err(MobileCryptoError::AuthenticationFailed)
        ));
    }
}
