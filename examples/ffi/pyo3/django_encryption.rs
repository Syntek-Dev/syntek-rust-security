//! PyO3 Django Encryption Integration
//!
//! Rust encryption library for Django applications via PyO3:
//! - AES-256-GCM encryption/decryption
//! - Field-level encryption for Django models
//! - Secure key management
//! - Memory-safe Python bindings

use std::collections::HashMap;
use std::fmt;

/// Simulated PyO3 module marker
/// In real implementation, use: #[pymodule]
pub struct PyModule;

/// Encryption algorithm
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

/// Encrypted field data
#[derive(Clone)]
pub struct EncryptedField {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub tag: Vec<u8>,
    pub algorithm: Algorithm,
    pub key_id: String,
    pub version: u32,
}

impl fmt::Debug for EncryptedField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedField")
            .field("ciphertext", &format!("{} bytes", self.ciphertext.len()))
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id)
            .field("version", &self.version)
            .finish()
    }
}

/// Key material with secure handling
pub struct KeyMaterial {
    key: Vec<u8>,
    key_id: String,
    created_at: u64,
    expires_at: Option<u64>,
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        // Zeroize key material
        for byte in &mut self.key {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("key", &"[REDACTED]")
            .field("key_id", &self.key_id)
            .finish()
    }
}

/// Encryption error types
#[derive(Debug)]
pub enum EncryptionError {
    InvalidKey(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    InvalidNonce,
    AuthenticationFailed,
    KeyNotFound(String),
    KeyExpired(String),
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionError::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            EncryptionError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            EncryptionError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            EncryptionError::InvalidNonce => write!(f, "Invalid nonce"),
            EncryptionError::AuthenticationFailed => write!(f, "Authentication failed"),
            EncryptionError::KeyNotFound(id) => write!(f, "Key not found: {}", id),
            EncryptionError::KeyExpired(id) => write!(f, "Key expired: {}", id),
        }
    }
}

impl std::error::Error for EncryptionError {}

/// Django field encryption engine
/// This would be exposed to Python via PyO3
pub struct DjangoEncryptionEngine {
    keys: HashMap<String, KeyMaterial>,
    default_key_id: Option<String>,
    algorithm: Algorithm,
}

impl DjangoEncryptionEngine {
    /// Create new encryption engine
    /// #[new] in PyO3
    pub fn new(algorithm: Algorithm) -> Self {
        Self {
            keys: HashMap::new(),
            default_key_id: None,
            algorithm,
        }
    }

    /// Add encryption key
    /// #[pyo3(signature = (key_id, key_bytes, expires_at=None))]
    pub fn add_key(
        &mut self,
        key_id: &str,
        key_bytes: &[u8],
        expires_at: Option<u64>,
    ) -> Result<(), EncryptionError> {
        let expected_len = match self.algorithm {
            Algorithm::Aes256Gcm => 32,
            Algorithm::ChaCha20Poly1305 => 32,
            Algorithm::XChaCha20Poly1305 => 32,
        };

        if key_bytes.len() != expected_len {
            return Err(EncryptionError::InvalidKey(format!(
                "Expected {} bytes, got {}",
                expected_len,
                key_bytes.len()
            )));
        }

        let key_material = KeyMaterial {
            key: key_bytes.to_vec(),
            key_id: key_id.to_string(),
            created_at: current_timestamp(),
            expires_at,
        };

        self.keys.insert(key_id.to_string(), key_material);

        if self.default_key_id.is_none() {
            self.default_key_id = Some(key_id.to_string());
        }

        Ok(())
    }

    /// Set default key for encryption
    pub fn set_default_key(&mut self, key_id: &str) -> Result<(), EncryptionError> {
        if !self.keys.contains_key(key_id) {
            return Err(EncryptionError::KeyNotFound(key_id.to_string()));
        }
        self.default_key_id = Some(key_id.to_string());
        Ok(())
    }

    /// Encrypt a field value
    /// Returns base64-encoded encrypted data
    pub fn encrypt_field(&self, plaintext: &[u8]) -> Result<EncryptedField, EncryptionError> {
        let key_id = self
            .default_key_id
            .as_ref()
            .ok_or_else(|| EncryptionError::KeyNotFound("No default key set".to_string()))?;

        self.encrypt_with_key(plaintext, key_id)
    }

    /// Encrypt with specific key
    pub fn encrypt_with_key(
        &self,
        plaintext: &[u8],
        key_id: &str,
    ) -> Result<EncryptedField, EncryptionError> {
        let key_material = self
            .keys
            .get(key_id)
            .ok_or_else(|| EncryptionError::KeyNotFound(key_id.to_string()))?;

        // Check key expiration
        if let Some(expires) = key_material.expires_at {
            if current_timestamp() > expires {
                return Err(EncryptionError::KeyExpired(key_id.to_string()));
            }
        }

        // Generate nonce
        let nonce = generate_nonce(self.algorithm);

        // Simulate encryption
        let (ciphertext, tag) = self.do_encrypt(&key_material.key, &nonce, plaintext)?;

        Ok(EncryptedField {
            ciphertext,
            nonce,
            tag,
            algorithm: self.algorithm,
            key_id: key_id.to_string(),
            version: 1,
        })
    }

    /// Decrypt a field value
    pub fn decrypt_field(&self, encrypted: &EncryptedField) -> Result<Vec<u8>, EncryptionError> {
        let key_material = self
            .keys
            .get(&encrypted.key_id)
            .ok_or_else(|| EncryptionError::KeyNotFound(encrypted.key_id.clone()))?;

        self.do_decrypt(
            &key_material.key,
            &encrypted.nonce,
            &encrypted.ciphertext,
            &encrypted.tag,
        )
    }

    /// Encrypt string field (convenience method for Django)
    pub fn encrypt_string(&self, value: &str) -> Result<String, EncryptionError> {
        let encrypted = self.encrypt_field(value.as_bytes())?;
        Ok(self.serialize_encrypted(&encrypted))
    }

    /// Decrypt to string
    pub fn decrypt_string(&self, encrypted_value: &str) -> Result<String, EncryptionError> {
        let encrypted = self.deserialize_encrypted(encrypted_value)?;
        let plaintext = self.decrypt_field(&encrypted)?;
        String::from_utf8(plaintext)
            .map_err(|_| EncryptionError::DecryptionFailed("Invalid UTF-8".to_string()))
    }

    /// Encrypt JSON field
    pub fn encrypt_json(&self, value: &str) -> Result<String, EncryptionError> {
        // Validate JSON first
        if !is_valid_json(value) {
            return Err(EncryptionError::EncryptionFailed(
                "Invalid JSON".to_string(),
            ));
        }
        self.encrypt_string(value)
    }

    /// Rotate encryption to new key
    pub fn rotate_encryption(
        &self,
        encrypted: &EncryptedField,
        new_key_id: &str,
    ) -> Result<EncryptedField, EncryptionError> {
        let plaintext = self.decrypt_field(encrypted)?;
        self.encrypt_with_key(&plaintext, new_key_id)
    }

    /// Batch encrypt multiple values
    pub fn encrypt_batch(&self, values: &[&[u8]]) -> Result<Vec<EncryptedField>, EncryptionError> {
        values.iter().map(|v| self.encrypt_field(v)).collect()
    }

    /// Batch decrypt multiple values
    pub fn decrypt_batch(
        &self,
        encrypted: &[EncryptedField],
    ) -> Result<Vec<Vec<u8>>, EncryptionError> {
        encrypted.iter().map(|e| self.decrypt_field(e)).collect()
    }

    // Internal encryption (simulated)
    fn do_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
        // Simulate AES-GCM encryption
        let mut ciphertext = plaintext.to_vec();
        let mut state = 0u64;

        // XOR with key stream (simplified)
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            let key_byte = key[i % key.len()];
            let nonce_byte = nonce[i % nonce.len()];
            state = state
                .wrapping_mul(0x5851f42d4c957f2d)
                .wrapping_add(key_byte as u64)
                .wrapping_add(nonce_byte as u64);
            *byte ^= (state >> 32) as u8;
        }

        // Generate authentication tag
        let mut tag = vec![0u8; 16];
        for (i, t) in tag.iter_mut().enumerate() {
            state = state
                .wrapping_mul(0x2545f4914f6cdd1d)
                .wrapping_add(i as u64);
            *t = (state >> 32) as u8;
        }

        Ok((ciphertext, tag))
    }

    // Internal decryption (simulated)
    fn do_decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        _tag: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        // Simulate AES-GCM decryption (same as encryption for XOR cipher)
        let mut plaintext = ciphertext.to_vec();
        let mut state = 0u64;

        for (i, byte) in plaintext.iter_mut().enumerate() {
            let key_byte = key[i % key.len()];
            let nonce_byte = nonce[i % nonce.len()];
            state = state
                .wrapping_mul(0x5851f42d4c957f2d)
                .wrapping_add(key_byte as u64)
                .wrapping_add(nonce_byte as u64);
            *byte ^= (state >> 32) as u8;
        }

        // In real implementation, verify tag here

        Ok(plaintext)
    }

    fn serialize_encrypted(&self, encrypted: &EncryptedField) -> String {
        format!(
            "{}${}${}${}${}${}",
            encrypted.version,
            algorithm_to_string(encrypted.algorithm),
            encrypted.key_id,
            hex_encode(&encrypted.nonce),
            hex_encode(&encrypted.ciphertext),
            hex_encode(&encrypted.tag),
        )
    }

    fn deserialize_encrypted(&self, value: &str) -> Result<EncryptedField, EncryptionError> {
        let parts: Vec<&str> = value.split('$').collect();
        if parts.len() != 6 {
            return Err(EncryptionError::DecryptionFailed(
                "Invalid format".to_string(),
            ));
        }

        let version: u32 = parts[0]
            .parse()
            .map_err(|_| EncryptionError::DecryptionFailed("Invalid version".to_string()))?;

        let algorithm = string_to_algorithm(parts[1])
            .ok_or_else(|| EncryptionError::DecryptionFailed("Unknown algorithm".to_string()))?;

        Ok(EncryptedField {
            version,
            algorithm,
            key_id: parts[2].to_string(),
            nonce: hex_decode(parts[3])?,
            ciphertext: hex_decode(parts[4])?,
            tag: hex_decode(parts[5])?,
        })
    }
}

/// Django model field mixin (would be Python class via PyO3)
pub struct EncryptedTextField {
    engine: DjangoEncryptionEngine,
    field_name: String,
}

impl EncryptedTextField {
    pub fn new(engine: DjangoEncryptionEngine, field_name: &str) -> Self {
        Self {
            engine,
            field_name: field_name.to_string(),
        }
    }

    /// Called when saving to database
    pub fn to_db_value(&self, value: Option<&str>) -> Result<Option<String>, EncryptionError> {
        match value {
            Some(v) => Ok(Some(self.engine.encrypt_string(v)?)),
            None => Ok(None),
        }
    }

    /// Called when loading from database
    pub fn from_db_value(&self, value: Option<&str>) -> Result<Option<String>, EncryptionError> {
        match value {
            Some(v) if !v.is_empty() => Ok(Some(self.engine.decrypt_string(v)?)),
            _ => Ok(None),
        }
    }
}

/// Encrypted JSON field for Django
pub struct EncryptedJSONField {
    engine: DjangoEncryptionEngine,
    field_name: String,
}

impl EncryptedJSONField {
    pub fn new(engine: DjangoEncryptionEngine, field_name: &str) -> Self {
        Self {
            engine,
            field_name: field_name.to_string(),
        }
    }

    pub fn to_db_value(&self, value: Option<&str>) -> Result<Option<String>, EncryptionError> {
        match value {
            Some(v) => Ok(Some(self.engine.encrypt_json(v)?)),
            None => Ok(None),
        }
    }

    pub fn from_db_value(&self, value: Option<&str>) -> Result<Option<String>, EncryptionError> {
        match value {
            Some(v) if !v.is_empty() => Ok(Some(self.engine.decrypt_string(v)?)),
            _ => Ok(None),
        }
    }
}

// Helper functions

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn generate_nonce(algorithm: Algorithm) -> Vec<u8> {
    let len = match algorithm {
        Algorithm::Aes256Gcm => 12,
        Algorithm::ChaCha20Poly1305 => 12,
        Algorithm::XChaCha20Poly1305 => 24,
    };

    // In production, use OsRng
    let seed = current_timestamp();
    let mut nonce = vec![0u8; len];
    let mut state = seed;
    for byte in &mut nonce {
        state = state
            .wrapping_mul(0x5851f42d4c957f2d)
            .wrapping_add(0x14057b7ef767814f);
        *byte = (state >> 32) as u8;
    }
    nonce
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, EncryptionError> {
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| EncryptionError::DecryptionFailed("Invalid hex".to_string()))
        })
        .collect()
}

fn algorithm_to_string(algo: Algorithm) -> &'static str {
    match algo {
        Algorithm::Aes256Gcm => "aes256gcm",
        Algorithm::ChaCha20Poly1305 => "chacha20poly1305",
        Algorithm::XChaCha20Poly1305 => "xchacha20poly1305",
    }
}

fn string_to_algorithm(s: &str) -> Option<Algorithm> {
    match s {
        "aes256gcm" => Some(Algorithm::Aes256Gcm),
        "chacha20poly1305" => Some(Algorithm::ChaCha20Poly1305),
        "xchacha20poly1305" => Some(Algorithm::XChaCha20Poly1305),
        _ => None,
    }
}

fn is_valid_json(s: &str) -> bool {
    let s = s.trim();
    (s.starts_with('{') && s.ends_with('}')) || (s.starts_with('[') && s.ends_with(']'))
}

fn main() {
    println!("=== PyO3 Django Encryption Demo ===\n");

    // Create encryption engine
    let mut engine = DjangoEncryptionEngine::new(Algorithm::Aes256Gcm);

    // Add encryption key (in production, load from Vault)
    let key = [0x42u8; 32]; // 256-bit key
    engine.add_key("key_v1", &key, None).unwrap();
    println!("Added encryption key: key_v1\n");

    // Encrypt string field
    println!("=== String Field Encryption ===\n");

    let plaintext = "sensitive user data";
    let encrypted = engine.encrypt_string(plaintext).unwrap();
    println!("Plaintext: {}", plaintext);
    println!("Encrypted: {}...", &encrypted[..50.min(encrypted.len())]);

    let decrypted = engine.decrypt_string(&encrypted).unwrap();
    println!("Decrypted: {}", decrypted);
    assert_eq!(plaintext, decrypted);

    // Encrypt JSON field
    println!("\n=== JSON Field Encryption ===\n");

    let json_data = r#"{"ssn": "123-45-6789", "dob": "1990-01-15"}"#;
    let encrypted_json = engine.encrypt_json(json_data).unwrap();
    println!("JSON: {}", json_data);
    println!(
        "Encrypted: {}...",
        &encrypted_json[..50.min(encrypted_json.len())]
    );

    let decrypted_json = engine.decrypt_string(&encrypted_json).unwrap();
    println!("Decrypted: {}", decrypted_json);

    // Batch encryption
    println!("\n=== Batch Encryption ===\n");

    let values: Vec<&[u8]> = vec![b"value1", b"value2", b"value3"];

    let encrypted_batch = engine.encrypt_batch(&values).unwrap();
    println!("Encrypted {} values", encrypted_batch.len());

    let decrypted_batch = engine.decrypt_batch(&encrypted_batch).unwrap();
    for (i, decrypted) in decrypted_batch.iter().enumerate() {
        println!("  Value {}: {}", i + 1, String::from_utf8_lossy(decrypted));
    }

    // Key rotation
    println!("\n=== Key Rotation ===\n");

    // Add new key
    let new_key = [0x43u8; 32];
    engine.add_key("key_v2", &new_key, None).unwrap();
    println!("Added new key: key_v2");

    // Rotate encryption
    let original = engine.encrypt_field(b"data to rotate").unwrap();
    println!("Original key: {}", original.key_id);

    let rotated = engine.rotate_encryption(&original, "key_v2").unwrap();
    println!("Rotated key: {}", rotated.key_id);

    // Verify data is still correct
    let decrypted = engine.decrypt_field(&rotated).unwrap();
    println!(
        "Data after rotation: {}",
        String::from_utf8_lossy(&decrypted)
    );

    // Django model field simulation
    println!("\n=== Django Model Field Simulation ===\n");

    let text_field = EncryptedTextField::new(
        DjangoEncryptionEngine::new(Algorithm::Aes256Gcm),
        "secret_notes",
    );

    // Initialize field's engine with key
    let mut field_engine = DjangoEncryptionEngine::new(Algorithm::Aes256Gcm);
    field_engine
        .add_key("field_key", &[0x44u8; 32], None)
        .unwrap();
    let text_field = EncryptedTextField::new(field_engine, "secret_notes");

    // Save to database
    let db_value = text_field.to_db_value(Some("My secret notes")).unwrap();
    println!(
        "Saved to DB: {:?}",
        db_value.as_ref().map(|s| &s[..30.min(s.len())])
    );

    // Load from database
    let loaded = text_field.from_db_value(db_value.as_deref()).unwrap();
    println!("Loaded from DB: {:?}", loaded);

    // Example Python usage (as comments)
    println!("\n=== Example Python Usage ===\n");
    println!(
        r#"
# In Django models.py:
from rust_encryption import DjangoEncryptionEngine, EncryptedTextField

# Initialize engine
engine = DjangoEncryptionEngine("aes256gcm")
engine.add_key("key_v1", key_bytes)

# Define model with encrypted field
class UserProfile(models.Model):
    email = models.EmailField()
    ssn = EncryptedTextField(engine=engine)
    medical_history = EncryptedJSONField(engine=engine)

# Usage
profile = UserProfile(email="user@example.com", ssn="123-45-6789")
profile.save()  # SSN is encrypted before saving

# Reading decrypts automatically
print(profile.ssn)  # "123-45-6789"
"#
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_engine() -> DjangoEncryptionEngine {
        let mut engine = DjangoEncryptionEngine::new(Algorithm::Aes256Gcm);
        engine.add_key("test_key", &[0x42u8; 32], None).unwrap();
        engine
    }

    #[test]
    fn test_encrypt_decrypt_field() {
        let engine = create_engine();
        let plaintext = b"test data";

        let encrypted = engine.encrypt_field(plaintext).unwrap();
        let decrypted = engine.decrypt_field(&encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_string() {
        let engine = create_engine();
        let plaintext = "hello world";

        let encrypted = engine.encrypt_string(plaintext).unwrap();
        let decrypted = engine.decrypt_string(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_json() {
        let engine = create_engine();
        let json = r#"{"key": "value"}"#;

        let encrypted = engine.encrypt_json(json).unwrap();
        let decrypted = engine.decrypt_string(&encrypted).unwrap();

        assert_eq!(json, decrypted);
    }

    #[test]
    fn test_invalid_json_rejected() {
        let engine = create_engine();
        let invalid = "not valid json";

        let result = engine.encrypt_json(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_rotation() {
        let mut engine = DjangoEncryptionEngine::new(Algorithm::Aes256Gcm);
        engine.add_key("key_v1", &[0x42u8; 32], None).unwrap();
        engine.add_key("key_v2", &[0x43u8; 32], None).unwrap();

        let original = engine.encrypt_with_key(b"data", "key_v1").unwrap();
        assert_eq!(original.key_id, "key_v1");

        let rotated = engine.rotate_encryption(&original, "key_v2").unwrap();
        assert_eq!(rotated.key_id, "key_v2");

        let decrypted = engine.decrypt_field(&rotated).unwrap();
        assert_eq!(decrypted, b"data");
    }

    #[test]
    fn test_batch_encryption() {
        let engine = create_engine();
        let values: Vec<&[u8]> = vec![b"a", b"b", b"c"];

        let encrypted = engine.encrypt_batch(&values).unwrap();
        assert_eq!(encrypted.len(), 3);

        let decrypted = engine.decrypt_batch(&encrypted).unwrap();
        assert_eq!(decrypted[0], b"a");
        assert_eq!(decrypted[1], b"b");
        assert_eq!(decrypted[2], b"c");
    }

    #[test]
    fn test_key_not_found() {
        let engine = create_engine();
        let encrypted = EncryptedField {
            ciphertext: vec![1, 2, 3],
            nonce: vec![0; 12],
            tag: vec![0; 16],
            algorithm: Algorithm::Aes256Gcm,
            key_id: "nonexistent".to_string(),
            version: 1,
        };

        let result = engine.decrypt_field(&encrypted);
        assert!(matches!(result, Err(EncryptionError::KeyNotFound(_))));
    }

    #[test]
    fn test_invalid_key_length() {
        let mut engine = DjangoEncryptionEngine::new(Algorithm::Aes256Gcm);
        let result = engine.add_key("bad_key", &[0u8; 16], None); // Too short

        assert!(matches!(result, Err(EncryptionError::InvalidKey(_))));
    }

    #[test]
    fn test_key_expiration() {
        let mut engine = DjangoEncryptionEngine::new(Algorithm::Aes256Gcm);
        // Add expired key
        engine
            .add_key("expired_key", &[0x42u8; 32], Some(0))
            .unwrap();

        let result = engine.encrypt_with_key(b"data", "expired_key");
        assert!(matches!(result, Err(EncryptionError::KeyExpired(_))));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let engine = create_engine();
        let plaintext = "test serialization";

        let encrypted_str = engine.encrypt_string(plaintext).unwrap();
        let decrypted = engine.decrypt_string(&encrypted_str).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypted_text_field() {
        let engine = create_engine();
        let field = EncryptedTextField::new(engine, "test_field");

        let db_value = field.to_db_value(Some("secret")).unwrap();
        assert!(db_value.is_some());

        let mut engine2 = DjangoEncryptionEngine::new(Algorithm::Aes256Gcm);
        engine2.add_key("test_key", &[0x42u8; 32], None).unwrap();
        let field2 = EncryptedTextField::new(engine2, "test_field");

        let loaded = field2.from_db_value(db_value.as_deref()).unwrap();
        assert_eq!(loaded, Some("secret".to_string()));
    }

    #[test]
    fn test_null_handling() {
        let engine = create_engine();
        let field = EncryptedTextField::new(engine, "test_field");

        let db_value = field.to_db_value(None).unwrap();
        assert!(db_value.is_none());
    }

    #[test]
    fn test_different_algorithms() {
        for algorithm in [
            Algorithm::Aes256Gcm,
            Algorithm::ChaCha20Poly1305,
            Algorithm::XChaCha20Poly1305,
        ] {
            let mut engine = DjangoEncryptionEngine::new(algorithm);
            engine.add_key("key", &[0x42u8; 32], None).unwrap();

            let encrypted = engine.encrypt_string("test").unwrap();
            let decrypted = engine.decrypt_string(&encrypted).unwrap();

            assert_eq!(decrypted, "test");
        }
    }
}
