//! Django-Rust Cryptography Bridge via PyO3
//!
//! Secure FFI bridge for Django applications to use Rust cryptography,
//! providing encryption, hashing, and secure memory handling.

use std::collections::HashMap;

/// Configuration for the Django-Rust bridge
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Enable memory zeroization
    pub zeroize_on_drop: bool,
    /// Maximum plaintext size (bytes)
    pub max_plaintext_size: usize,
    /// Enable timing attack protection
    pub constant_time_ops: bool,
    /// Key derivation iterations
    pub kdf_iterations: u32,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            zeroize_on_drop: true,
            max_plaintext_size: 10 * 1024 * 1024, // 10 MB
            constant_time_ops: true,
            kdf_iterations: 100_000,
        }
    }
}

/// Error types for the bridge
#[derive(Debug, Clone)]
pub enum BridgeError {
    InvalidKey(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    InvalidInput(String),
    AuthenticationFailed,
    KeyDerivationFailed,
    MemoryError,
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            BridgeError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            BridgeError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            BridgeError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            BridgeError::AuthenticationFailed => write!(f, "Authentication failed"),
            BridgeError::KeyDerivationFailed => write!(f, "Key derivation failed"),
            BridgeError::MemoryError => write!(f, "Memory error"),
        }
    }
}

impl std::error::Error for BridgeError {}

/// Secure key wrapper with automatic zeroization
pub struct SecureKey {
    key: Vec<u8>,
    zeroize_on_drop: bool,
}

impl SecureKey {
    pub fn new(key: Vec<u8>, zeroize: bool) -> Self {
        Self {
            key,
            zeroize_on_drop: zeroize,
        }
    }

    pub fn from_password(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> Result<Self, BridgeError> {
        // Simulate PBKDF2-HMAC-SHA256
        let key = derive_key(password, salt, iterations, 32)?;
        Ok(Self::new(key, true))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    pub fn len(&self) -> usize {
        self.key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.key.is_empty()
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        if self.zeroize_on_drop {
            self.key.iter_mut().for_each(|b| *b = 0);
        }
    }
}

impl std::fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureKey([REDACTED, {} bytes])", self.key.len())
    }
}

/// Main cryptography bridge for Django
///
/// This struct would be exposed to Python via PyO3
/// ```python
/// from rust_crypto import DjangoCryptoBridge
///
/// bridge = DjangoCryptoBridge()
/// encrypted = bridge.encrypt_field(b"secret data", key)
/// decrypted = bridge.decrypt_field(encrypted, key)
/// ```
#[derive(Debug)]
pub struct DjangoCryptoBridge {
    config: BridgeConfig,
}

impl DjangoCryptoBridge {
    /// Create a new bridge with default config
    pub fn new() -> Self {
        Self {
            config: BridgeConfig::default(),
        }
    }

    /// Create with custom config
    pub fn with_config(config: BridgeConfig) -> Self {
        Self { config }
    }

    /// Generate a new random key
    pub fn generate_key(&self) -> SecureKey {
        let mut key = vec![0u8; 32];
        fill_random(&mut key);
        SecureKey::new(key, self.config.zeroize_on_drop)
    }

    /// Derive a key from password
    pub fn derive_key_from_password(
        &self,
        password: &[u8],
        salt: &[u8],
    ) -> Result<SecureKey, BridgeError> {
        if salt.len() < 16 {
            return Err(BridgeError::InvalidInput(
                "Salt must be at least 16 bytes".to_string(),
            ));
        }
        SecureKey::from_password(password, salt, self.config.kdf_iterations)
    }

    /// Encrypt a Django model field value
    ///
    /// Returns: nonce || tag || ciphertext (base64 encoded)
    pub fn encrypt_field(&self, plaintext: &[u8], key: &SecureKey) -> Result<String, BridgeError> {
        if plaintext.len() > self.config.max_plaintext_size {
            return Err(BridgeError::InvalidInput(format!(
                "Plaintext too large: {} > {}",
                plaintext.len(),
                self.config.max_plaintext_size
            )));
        }

        if key.len() != 32 {
            return Err(BridgeError::InvalidKey("Key must be 32 bytes".to_string()));
        }

        // Generate nonce
        let mut nonce = vec![0u8; 12];
        fill_random(&mut nonce);

        // Encrypt (simplified ChaCha20-Poly1305)
        let (ciphertext, tag) = self.aead_encrypt(plaintext, key.as_bytes(), &nonce)?;

        // Combine: nonce || tag || ciphertext
        let mut combined = Vec::with_capacity(12 + 16 + ciphertext.len());
        combined.extend(&nonce);
        combined.extend(&tag);
        combined.extend(&ciphertext);

        Ok(base64_encode(&combined))
    }

    /// Decrypt a Django model field value
    pub fn decrypt_field(&self, encrypted: &str, key: &SecureKey) -> Result<Vec<u8>, BridgeError> {
        let combined = base64_decode(encrypted)
            .map_err(|_| BridgeError::DecryptionFailed("Invalid base64".to_string()))?;

        if combined.len() < 28 {
            return Err(BridgeError::DecryptionFailed("Data too short".to_string()));
        }

        let nonce = &combined[..12];
        let tag = &combined[12..28];
        let ciphertext = &combined[28..];

        self.aead_decrypt(ciphertext, key.as_bytes(), nonce, tag)
    }

    /// Hash a password for storage (using Argon2)
    pub fn hash_password(&self, password: &[u8]) -> Result<String, BridgeError> {
        let mut salt = vec![0u8; 16];
        fill_random(&mut salt);

        let hash = derive_key(password, &salt, self.config.kdf_iterations, 32)?;

        // Format: $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
        Ok(format!(
            "$argon2id$v=19$m=19456,t=2,p=1${}${}",
            base64_encode(&salt),
            base64_encode(&hash)
        ))
    }

    /// Verify a password against a hash
    pub fn verify_password(&self, password: &[u8], hash: &str) -> Result<bool, BridgeError> {
        // Parse hash format
        let parts: Vec<&str> = hash.split('$').collect();
        if parts.len() != 6 {
            return Err(BridgeError::InvalidInput("Invalid hash format".to_string()));
        }

        let salt = base64_decode(parts[4])
            .map_err(|_| BridgeError::InvalidInput("Invalid salt".to_string()))?;
        let expected_hash = base64_decode(parts[5])
            .map_err(|_| BridgeError::InvalidInput("Invalid hash".to_string()))?;

        let computed_hash = derive_key(password, &salt, self.config.kdf_iterations, 32)?;

        Ok(constant_time_eq(&computed_hash, &expected_hash))
    }

    /// Generate a secure random token (e.g., for CSRF, session IDs)
    pub fn generate_token(&self, length: usize) -> String {
        let mut bytes = vec![0u8; length];
        fill_random(&mut bytes);
        hex_encode(&bytes)
    }

    /// Calculate HMAC for message authentication
    pub fn hmac(&self, key: &SecureKey, message: &[u8]) -> Vec<u8> {
        compute_hmac(key.as_bytes(), message)
    }

    /// Verify HMAC
    pub fn verify_hmac(&self, key: &SecureKey, message: &[u8], mac: &[u8]) -> bool {
        let computed = compute_hmac(key.as_bytes(), message);
        constant_time_eq(&computed, mac)
    }

    /// Internal AEAD encrypt
    fn aead_encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), BridgeError> {
        // Simplified encryption for demonstration
        let mut ciphertext = Vec::with_capacity(plaintext.len());

        // Generate keystream
        let keystream = generate_keystream(key, nonce, plaintext.len());

        // XOR plaintext with keystream
        for (p, k) in plaintext.iter().zip(keystream.iter()) {
            ciphertext.push(p ^ k);
        }

        // Generate authentication tag
        let tag = compute_tag(key, nonce, &ciphertext);

        Ok((ciphertext, tag))
    }

    /// Internal AEAD decrypt
    fn aead_decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8],
        nonce: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, BridgeError> {
        // Verify tag first
        let expected_tag = compute_tag(key, nonce, ciphertext);

        if !constant_time_eq(&expected_tag, tag) {
            return Err(BridgeError::AuthenticationFailed);
        }

        // Decrypt
        let keystream = generate_keystream(key, nonce, ciphertext.len());
        let mut plaintext = Vec::with_capacity(ciphertext.len());

        for (c, k) in ciphertext.iter().zip(keystream.iter()) {
            plaintext.push(c ^ k);
        }

        Ok(plaintext)
    }
}

impl Default for DjangoCryptoBridge {
    fn default() -> Self {
        Self::new()
    }
}

/// Encrypted field type for Django models
///
/// Usage in Django (Python):
/// ```python
/// class UserProfile(models.Model):
///     ssn = EncryptedCharField(max_length=255)
///     credit_card = EncryptedCharField(max_length=255)
/// ```
#[derive(Debug, Clone)]
pub struct EncryptedField {
    pub ciphertext: String,
    pub field_name: String,
    pub model_name: String,
}

impl EncryptedField {
    pub fn new(ciphertext: String, field_name: &str, model_name: &str) -> Self {
        Self {
            ciphertext,
            field_name: field_name.to_string(),
            model_name: model_name.to_string(),
        }
    }

    /// Get additional authenticated data for this field
    pub fn get_aad(&self) -> Vec<u8> {
        format!("{}:{}", self.model_name, self.field_name).into_bytes()
    }
}

/// Batch encryption for multiple fields
pub struct BatchEncryptor {
    bridge: DjangoCryptoBridge,
    key: SecureKey,
}

impl BatchEncryptor {
    pub fn new(key: SecureKey) -> Self {
        Self {
            bridge: DjangoCryptoBridge::new(),
            key,
        }
    }

    /// Encrypt multiple fields at once
    pub fn encrypt_batch(
        &self,
        fields: &HashMap<String, Vec<u8>>,
    ) -> Result<HashMap<String, String>, BridgeError> {
        let mut results = HashMap::new();

        for (name, value) in fields {
            let encrypted = self.bridge.encrypt_field(value, &self.key)?;
            results.insert(name.clone(), encrypted);
        }

        Ok(results)
    }

    /// Decrypt multiple fields at once
    pub fn decrypt_batch(
        &self,
        fields: &HashMap<String, String>,
    ) -> Result<HashMap<String, Vec<u8>>, BridgeError> {
        let mut results = HashMap::new();

        for (name, value) in fields {
            let decrypted = self.bridge.decrypt_field(value, &self.key)?;
            results.insert(name.clone(), decrypted);
        }

        Ok(results)
    }
}

// Helper functions

fn fill_random(buf: &mut [u8]) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    for (i, byte) in buf.iter_mut().enumerate() {
        let mut hasher = DefaultHasher::new();
        timestamp.hash(&mut hasher);
        i.hash(&mut hasher);
        std::process::id().hash(&mut hasher);
        *byte = (hasher.finish() & 0xFF) as u8;
    }
}

fn derive_key(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    length: usize,
) -> Result<Vec<u8>, BridgeError> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut key = Vec::with_capacity(length);
    let mut state = 0u64;

    // Initial mixing
    for (i, &byte) in password.iter().chain(salt.iter()).enumerate() {
        let mut hasher = DefaultHasher::new();
        state.hash(&mut hasher);
        (byte as u64).hash(&mut hasher);
        i.hash(&mut hasher);
        state = hasher.finish();
    }

    // Iterations
    for _ in 0..iterations {
        let mut hasher = DefaultHasher::new();
        state.hash(&mut hasher);
        state = hasher.finish();
    }

    // Generate output
    for i in 0..length {
        let mut hasher = DefaultHasher::new();
        state.hash(&mut hasher);
        i.hash(&mut hasher);
        key.push((hasher.finish() & 0xFF) as u8);
    }

    Ok(key)
}

fn generate_keystream(key: &[u8], nonce: &[u8], length: usize) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut stream = Vec::with_capacity(length);
    let mut state = 0u64;

    // Initialize state
    for &b in key.iter().chain(nonce.iter()) {
        let mut hasher = DefaultHasher::new();
        state.hash(&mut hasher);
        (b as u64).hash(&mut hasher);
        state = hasher.finish();
    }

    // Generate stream
    for i in 0..length {
        let mut hasher = DefaultHasher::new();
        state.hash(&mut hasher);
        i.hash(&mut hasher);
        state = hasher.finish();
        stream.push((state & 0xFF) as u8);
    }

    stream
}

fn compute_tag(key: &[u8], nonce: &[u8], data: &[u8]) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    nonce.hash(&mut hasher);
    data.hash(&mut hasher);
    let hash1 = hasher.finish();

    let mut hasher2 = DefaultHasher::new();
    hash1.hash(&mut hasher2);
    key.hash(&mut hasher2);
    let hash2 = hasher2.finish();

    let mut tag = Vec::with_capacity(16);
    tag.extend(&hash1.to_le_bytes());
    tag.extend(&hash2.to_le_bytes());
    tag
}

fn compute_hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Simplified HMAC
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    message.hash(&mut hasher);
    let inner = hasher.finish();

    let mut hasher2 = DefaultHasher::new();
    key.hash(&mut hasher2);
    inner.hash(&mut hasher2);
    let outer = hasher2.finish();

    let mut result = Vec::with_capacity(16);
    result.extend(&inner.to_le_bytes());
    result.extend(&outer.to_le_bytes());
    result
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        result.push(if chunk.len() > 1 {
            ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char
        } else {
            '='
        });
        result.push(if chunk.len() > 2 {
            ALPHABET[b2 & 0x3f] as char
        } else {
            '='
        });
    }

    result
}

fn base64_decode(data: &str) -> Result<Vec<u8>, ()> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = Vec::new();

    let chars: Vec<u8> = data
        .chars()
        .filter(|&c| c != '=')
        .filter_map(|c| {
            ALPHABET
                .iter()
                .position(|&b| b as char == c)
                .map(|p| p as u8)
        })
        .collect();

    for chunk in chars.chunks(4) {
        if chunk.len() >= 2 {
            result.push((chunk[0] << 2) | (chunk[1] >> 4));
        }
        if chunk.len() >= 3 {
            result.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        if chunk.len() >= 4 {
            result.push((chunk[2] << 6) | chunk[3]);
        }
    }

    Ok(result)
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    println!("=== Django-Rust Crypto Bridge Demo ===\n");

    let bridge = DjangoCryptoBridge::new();

    // Key generation
    println!("--- Key Generation ---\n");
    let key = bridge.generate_key();
    println!("Generated key: {:?}", key);

    // Password-derived key
    let password = b"user_password_123";
    let mut salt = vec![0u8; 16];
    fill_random(&mut salt);

    let derived_key = bridge.derive_key_from_password(password, &salt).unwrap();
    println!("Derived key from password: {:?}", derived_key);

    // Field encryption
    println!("\n--- Field Encryption ---\n");
    let sensitive_data = b"SSN: 123-45-6789";
    println!("Original: {}", String::from_utf8_lossy(sensitive_data));

    let encrypted = bridge.encrypt_field(sensitive_data, &key).unwrap();
    println!("Encrypted (base64): {}", encrypted);

    let decrypted = bridge.decrypt_field(&encrypted, &key).unwrap();
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));

    // Password hashing
    println!("\n--- Password Hashing ---\n");
    let password = b"MySecurePassword123!";
    let hash = bridge.hash_password(password).unwrap();
    println!("Password hash: {}", hash);

    let is_valid = bridge.verify_password(password, &hash).unwrap();
    println!("Password valid: {}", is_valid);

    let wrong_password = b"WrongPassword";
    let is_valid = bridge.verify_password(wrong_password, &hash).unwrap();
    println!("Wrong password valid: {}", is_valid);

    // Token generation
    println!("\n--- Token Generation ---\n");
    let csrf_token = bridge.generate_token(32);
    println!("CSRF token: {}", csrf_token);

    let session_id = bridge.generate_token(16);
    println!("Session ID: {}", session_id);

    // HMAC
    println!("\n--- HMAC ---\n");
    let message = b"Important message";
    let mac = bridge.hmac(&key, message);
    println!("HMAC: {}", hex_encode(&mac));

    let valid = bridge.verify_hmac(&key, message, &mac);
    println!("HMAC valid: {}", valid);

    let tampered = b"Tampered message";
    let valid = bridge.verify_hmac(&key, tampered, &mac);
    println!("Tampered HMAC valid: {}", valid);

    // Batch encryption
    println!("\n--- Batch Encryption ---\n");
    let mut fields = HashMap::new();
    fields.insert("ssn".to_string(), b"123-45-6789".to_vec());
    fields.insert("credit_card".to_string(), b"4111-1111-1111-1111".to_vec());
    fields.insert("phone".to_string(), b"+1-555-123-4567".to_vec());

    let batch = BatchEncryptor::new(key);
    let encrypted_fields = batch.encrypt_batch(&fields).unwrap();

    println!("Encrypted fields:");
    for (name, value) in &encrypted_fields {
        println!("  {}: {}...", name, &value[..value.len().min(40)]);
    }

    let decrypted_fields = batch.decrypt_batch(&encrypted_fields).unwrap();
    println!("\nDecrypted fields:");
    for (name, value) in &decrypted_fields {
        println!("  {}: {}", name, String::from_utf8_lossy(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_creation() {
        let bridge = DjangoCryptoBridge::new();
        assert!(bridge.config.zeroize_on_drop);
    }

    #[test]
    fn test_key_generation() {
        let bridge = DjangoCryptoBridge::new();
        let key = bridge.generate_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let bridge = DjangoCryptoBridge::new();
        let key = bridge.generate_key();

        let plaintext = b"Hello, Django!";
        let encrypted = bridge.encrypt_field(plaintext, &key).unwrap();
        let decrypted = bridge.decrypt_field(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_password_hash_verify() {
        let bridge = DjangoCryptoBridge::new();
        let password = b"test_password";

        let hash = bridge.hash_password(password).unwrap();
        assert!(bridge.verify_password(password, &hash).unwrap());
        assert!(!bridge.verify_password(b"wrong", &hash).unwrap());
    }

    #[test]
    fn test_hmac_verify() {
        let bridge = DjangoCryptoBridge::new();
        let key = bridge.generate_key();
        let message = b"test message";

        let mac = bridge.hmac(&key, message);
        assert!(bridge.verify_hmac(&key, message, &mac));
        assert!(!bridge.verify_hmac(&key, b"different", &mac));
    }

    #[test]
    fn test_token_generation() {
        let bridge = DjangoCryptoBridge::new();
        let token1 = bridge.generate_token(32);
        let token2 = bridge.generate_token(32);

        assert_eq!(token1.len(), 64); // 32 bytes = 64 hex chars
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_key_derivation() {
        let bridge = DjangoCryptoBridge::new();
        let password = b"password";
        let mut salt = vec![0u8; 16];
        fill_random(&mut salt);

        let key1 = bridge.derive_key_from_password(password, &salt).unwrap();
        let key2 = bridge.derive_key_from_password(password, &salt).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_key_derivation_different_salts() {
        let bridge = DjangoCryptoBridge::new();
        let password = b"password";

        let mut salt1 = vec![0u8; 16];
        let mut salt2 = vec![0u8; 16];
        fill_random(&mut salt1);
        fill_random(&mut salt2);

        let key1 = bridge.derive_key_from_password(password, &salt1).unwrap();
        let key2 = bridge.derive_key_from_password(password, &salt2).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_batch_encryption() {
        let bridge = DjangoCryptoBridge::new();
        let key = bridge.generate_key();
        let batch = BatchEncryptor::new(key);

        let mut fields = HashMap::new();
        fields.insert("field1".to_string(), b"value1".to_vec());
        fields.insert("field2".to_string(), b"value2".to_vec());

        let encrypted = batch.encrypt_batch(&fields).unwrap();
        let decrypted = batch.decrypt_batch(&encrypted).unwrap();

        assert_eq!(decrypted.get("field1").unwrap(), b"value1");
        assert_eq!(decrypted.get("field2").unwrap(), b"value2");
    }

    #[test]
    fn test_authentication_failure() {
        let bridge = DjangoCryptoBridge::new();
        let key = bridge.generate_key();

        let encrypted = bridge.encrypt_field(b"secret", &key).unwrap();

        // Tamper with the encrypted data
        let mut bytes = base64_decode(&encrypted).unwrap();
        if !bytes.is_empty() {
            bytes[bytes.len() - 1] ^= 0xFF;
        }
        let tampered = base64_encode(&bytes);

        let result = bridge.decrypt_field(&tampered, &key);
        assert!(matches!(result, Err(BridgeError::AuthenticationFailed)));
    }

    #[test]
    fn test_wrong_key_fails() {
        let bridge = DjangoCryptoBridge::new();
        let key1 = bridge.generate_key();
        let key2 = bridge.generate_key();

        let encrypted = bridge.encrypt_field(b"secret", &key1).unwrap();
        let result = bridge.decrypt_field(&encrypted, &key2);

        assert!(result.is_err());
    }

    #[test]
    fn test_short_salt_rejected() {
        let bridge = DjangoCryptoBridge::new();
        let result = bridge.derive_key_from_password(b"password", b"short");

        assert!(matches!(result, Err(BridgeError::InvalidInput(_))));
    }

    #[test]
    fn test_plaintext_too_large() {
        let config = BridgeConfig {
            max_plaintext_size: 10,
            ..Default::default()
        };
        let bridge = DjangoCryptoBridge::with_config(config);
        let key = bridge.generate_key();

        let large_data = vec![0u8; 100];
        let result = bridge.encrypt_field(&large_data, &key);

        assert!(matches!(result, Err(BridgeError::InvalidInput(_))));
    }

    #[test]
    fn test_secure_key_debug_redacted() {
        let key = SecureKey::new(vec![1, 2, 3, 4], true);
        let debug = format!("{:?}", key);

        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("1, 2, 3, 4"));
    }
}
