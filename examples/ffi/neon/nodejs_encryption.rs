//! Neon Node.js Integration - Encryption Module for Next.js/React
//!
//! This example demonstrates building a native Node.js addon using Neon
//! for high-performance encryption in Next.js and React applications.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Encryption algorithm supported by the Neon module
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl EncryptionAlgorithm {
    pub fn key_size(&self) -> usize {
        match self {
            Self::Aes256Gcm => 32,
            Self::ChaCha20Poly1305 => 32,
            Self::XChaCha20Poly1305 => 32,
        }
    }

    pub fn nonce_size(&self) -> usize {
        match self {
            Self::Aes256Gcm => 12,
            Self::ChaCha20Poly1305 => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }

    pub fn tag_size(&self) -> usize {
        16 // All AEAD algorithms use 16-byte tags
    }
}

/// Key wrapper with metadata for Neon export
#[derive(Debug, Clone)]
pub struct NeonKey {
    id: String,
    algorithm: EncryptionAlgorithm,
    key_bytes: Vec<u8>,
    created_at: Instant,
    rotation_due: Option<Instant>,
}

impl NeonKey {
    pub fn generate(id: impl Into<String>, algorithm: EncryptionAlgorithm) -> Self {
        let key_bytes = generate_random_bytes(algorithm.key_size());
        Self {
            id: id.into(),
            algorithm,
            key_bytes,
            created_at: Instant::now(),
            rotation_due: Some(Instant::now() + Duration::from_secs(86400 * 30)), // 30 days
        }
    }

    pub fn from_bytes(
        id: impl Into<String>,
        algorithm: EncryptionAlgorithm,
        bytes: Vec<u8>,
    ) -> Result<Self, NeonCryptoError> {
        if bytes.len() != algorithm.key_size() {
            return Err(NeonCryptoError::InvalidKeySize {
                expected: algorithm.key_size(),
                got: bytes.len(),
            });
        }
        Ok(Self {
            id: id.into(),
            algorithm,
            key_bytes: bytes,
            created_at: Instant::now(),
            rotation_due: None,
        })
    }

    pub fn needs_rotation(&self) -> bool {
        self.rotation_due
            .map(|due| Instant::now() >= due)
            .unwrap_or(false)
    }
}

impl Drop for NeonKey {
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

/// Encrypted data with all components for JavaScript interop
#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub tag: Vec<u8>,
    pub algorithm: EncryptionAlgorithm,
    pub key_id: String,
    pub associated_data: Option<Vec<u8>>,
}

impl EncryptedData {
    /// Serialize to JSON-compatible format for JavaScript
    pub fn to_js_object(&self) -> JsCompatibleObject {
        JsCompatibleObject {
            ciphertext_base64: base64_encode(&self.ciphertext),
            nonce_base64: base64_encode(&self.nonce),
            tag_base64: base64_encode(&self.tag),
            algorithm: format!("{:?}", self.algorithm),
            key_id: self.key_id.clone(),
            aad_base64: self.associated_data.as_ref().map(|d| base64_encode(d)),
        }
    }

    /// Deserialize from JavaScript object
    pub fn from_js_object(obj: &JsCompatibleObject) -> Result<Self, NeonCryptoError> {
        let algorithm = match obj.algorithm.as_str() {
            "Aes256Gcm" => EncryptionAlgorithm::Aes256Gcm,
            "ChaCha20Poly1305" => EncryptionAlgorithm::ChaCha20Poly1305,
            "XChaCha20Poly1305" => EncryptionAlgorithm::XChaCha20Poly1305,
            other => return Err(NeonCryptoError::UnknownAlgorithm(other.to_string())),
        };

        Ok(Self {
            ciphertext: base64_decode(&obj.ciphertext_base64)?,
            nonce: base64_decode(&obj.nonce_base64)?,
            tag: base64_decode(&obj.tag_base64)?,
            algorithm,
            key_id: obj.key_id.clone(),
            associated_data: obj
                .aad_base64
                .as_ref()
                .map(|s| base64_decode(s))
                .transpose()?,
        })
    }
}

/// JavaScript-compatible serialized format
#[derive(Debug, Clone)]
pub struct JsCompatibleObject {
    pub ciphertext_base64: String,
    pub nonce_base64: String,
    pub tag_base64: String,
    pub algorithm: String,
    pub key_id: String,
    pub aad_base64: Option<String>,
}

/// Error types for Neon crypto operations
#[derive(Debug, Clone)]
pub enum NeonCryptoError {
    InvalidKeySize { expected: usize, got: usize },
    InvalidNonceSize { expected: usize, got: usize },
    EncryptionFailed(String),
    DecryptionFailed(String),
    AuthenticationFailed,
    KeyNotFound(String),
    KeyRotationRequired(String),
    Base64DecodeError(String),
    UnknownAlgorithm(String),
    BufferTooSmall { required: usize, got: usize },
}

impl std::fmt::Display for NeonCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeySize { expected, got } => {
                write!(f, "Invalid key size: expected {}, got {}", expected, got)
            }
            Self::InvalidNonceSize { expected, got } => {
                write!(f, "Invalid nonce size: expected {}, got {}", expected, got)
            }
            Self::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            Self::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            Self::AuthenticationFailed => write!(f, "Authentication tag verification failed"),
            Self::KeyNotFound(id) => write!(f, "Key not found: {}", id),
            Self::KeyRotationRequired(id) => write!(f, "Key rotation required for: {}", id),
            Self::Base64DecodeError(msg) => write!(f, "Base64 decode error: {}", msg),
            Self::UnknownAlgorithm(alg) => write!(f, "Unknown algorithm: {}", alg),
            Self::BufferTooSmall { required, got } => {
                write!(f, "Buffer too small: required {}, got {}", required, got)
            }
        }
    }
}

impl std::error::Error for NeonCryptoError {}

/// Main Neon encryption context - thread-safe for Node.js worker threads
pub struct NeonCryptoContext {
    keys: Arc<Mutex<HashMap<String, NeonKey>>>,
    default_algorithm: EncryptionAlgorithm,
    enforce_rotation: bool,
    metrics: Arc<Mutex<CryptoMetrics>>,
}

/// Metrics for monitoring from JavaScript
#[derive(Debug, Default, Clone)]
pub struct CryptoMetrics {
    pub encryptions: u64,
    pub decryptions: u64,
    pub encryption_failures: u64,
    pub decryption_failures: u64,
    pub auth_failures: u64,
    pub total_bytes_encrypted: u64,
    pub total_bytes_decrypted: u64,
}

impl NeonCryptoContext {
    pub fn new(default_algorithm: EncryptionAlgorithm) -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
            default_algorithm,
            enforce_rotation: true,
            metrics: Arc::new(Mutex::new(CryptoMetrics::default())),
        }
    }

    pub fn with_rotation_enforcement(mut self, enforce: bool) -> Self {
        self.enforce_rotation = enforce;
        self
    }

    /// Add a key to the context
    pub fn add_key(&self, key: NeonKey) -> Result<(), NeonCryptoError> {
        let mut keys = self.keys.lock().unwrap();
        keys.insert(key.id.clone(), key);
        Ok(())
    }

    /// Generate and add a new key
    pub fn generate_key(&self, id: impl Into<String>) -> Result<String, NeonCryptoError> {
        let id = id.into();
        let key = NeonKey::generate(&id, self.default_algorithm);
        self.add_key(key)?;
        Ok(id)
    }

    /// Encrypt data - main API for Neon export
    pub fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<EncryptedData, NeonCryptoError> {
        let keys = self.keys.lock().unwrap();
        let key = keys
            .get(key_id)
            .ok_or_else(|| NeonCryptoError::KeyNotFound(key_id.to_string()))?;

        if self.enforce_rotation && key.needs_rotation() {
            return Err(NeonCryptoError::KeyRotationRequired(key_id.to_string()));
        }

        let nonce = generate_random_bytes(key.algorithm.nonce_size());
        let (ciphertext, tag) = self.encrypt_internal(
            key.algorithm,
            &key.key_bytes,
            &nonce,
            plaintext,
            associated_data,
        )?;

        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.encryptions += 1;
            metrics.total_bytes_encrypted += plaintext.len() as u64;
        }

        Ok(EncryptedData {
            ciphertext,
            nonce,
            tag,
            algorithm: key.algorithm,
            key_id: key_id.to_string(),
            associated_data: associated_data.map(|d| d.to_vec()),
        })
    }

    /// Decrypt data - main API for Neon export
    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>, NeonCryptoError> {
        let keys = self.keys.lock().unwrap();
        let key = keys
            .get(&encrypted.key_id)
            .ok_or_else(|| NeonCryptoError::KeyNotFound(encrypted.key_id.clone()))?;

        let plaintext = self.decrypt_internal(
            key.algorithm,
            &key.key_bytes,
            &encrypted.nonce,
            &encrypted.ciphertext,
            &encrypted.tag,
            encrypted.associated_data.as_deref(),
        )?;

        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.decryptions += 1;
            metrics.total_bytes_decrypted += plaintext.len() as u64;
        }

        Ok(plaintext)
    }

    /// Encrypt string - convenience API for JavaScript
    pub fn encrypt_string(
        &self,
        key_id: &str,
        plaintext: &str,
        associated_data: Option<&str>,
    ) -> Result<JsCompatibleObject, NeonCryptoError> {
        let encrypted = self.encrypt(
            key_id,
            plaintext.as_bytes(),
            associated_data.map(|s| s.as_bytes()),
        )?;
        Ok(encrypted.to_js_object())
    }

    /// Decrypt to string - convenience API for JavaScript
    pub fn decrypt_string(
        &self,
        encrypted: &JsCompatibleObject,
    ) -> Result<String, NeonCryptoError> {
        let encrypted_data = EncryptedData::from_js_object(encrypted)?;
        let plaintext = self.decrypt(&encrypted_data)?;
        String::from_utf8(plaintext).map_err(|e| NeonCryptoError::DecryptionFailed(e.to_string()))
    }

    /// Get current metrics
    pub fn get_metrics(&self) -> CryptoMetrics {
        self.metrics.lock().unwrap().clone()
    }

    /// List all key IDs
    pub fn list_keys(&self) -> Vec<String> {
        self.keys.lock().unwrap().keys().cloned().collect()
    }

    /// Check if a key needs rotation
    pub fn key_needs_rotation(&self, key_id: &str) -> Result<bool, NeonCryptoError> {
        let keys = self.keys.lock().unwrap();
        let key = keys
            .get(key_id)
            .ok_or_else(|| NeonCryptoError::KeyNotFound(key_id.to_string()))?;
        Ok(key.needs_rotation())
    }

    /// Rotate a key - generates new key with same ID
    pub fn rotate_key(&self, key_id: &str) -> Result<(), NeonCryptoError> {
        let mut keys = self.keys.lock().unwrap();
        let old_key = keys
            .get(key_id)
            .ok_or_else(|| NeonCryptoError::KeyNotFound(key_id.to_string()))?;
        let algorithm = old_key.algorithm;
        let new_key = NeonKey::generate(key_id, algorithm);
        keys.insert(key_id.to_string(), new_key);
        Ok(())
    }

    // Internal encryption implementation
    fn encrypt_internal(
        &self,
        algorithm: EncryptionAlgorithm,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>), NeonCryptoError> {
        // Simulated encryption - in real implementation would use RustCrypto
        let _ = (algorithm, aad);

        // XOR with key-derived stream (simplified for example)
        let mut ciphertext = plaintext.to_vec();
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= key[i % key.len()] ^ nonce[i % nonce.len()];
        }

        // Generate authentication tag (simplified)
        let tag = generate_hmac_tag(key, &ciphertext, aad.unwrap_or(&[]));

        Ok((ciphertext, tag))
    }

    // Internal decryption implementation
    fn decrypt_internal(
        &self,
        algorithm: EncryptionAlgorithm,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, NeonCryptoError> {
        let _ = algorithm;

        // Verify authentication tag first
        let expected_tag = generate_hmac_tag(key, ciphertext, aad.unwrap_or(&[]));
        if !constant_time_compare(tag, &expected_tag) {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.auth_failures += 1;
            return Err(NeonCryptoError::AuthenticationFailed);
        }

        // Decrypt (reverse XOR)
        let mut plaintext = ciphertext.to_vec();
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte ^= key[i % key.len()] ^ nonce[i % nonce.len()];
        }

        Ok(plaintext)
    }
}

/// Streaming encryption for large files from JavaScript
pub struct NeonStreamCipher {
    context: Arc<NeonCryptoContext>,
    key_id: String,
    buffer: Vec<u8>,
    chunk_size: usize,
}

impl NeonStreamCipher {
    pub fn new(context: Arc<NeonCryptoContext>, key_id: String, chunk_size: usize) -> Self {
        Self {
            context,
            key_id,
            buffer: Vec::new(),
            chunk_size,
        }
    }

    /// Push data for encryption, returns encrypted chunks when buffer is full
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<EncryptedData>, NeonCryptoError> {
        self.buffer.extend_from_slice(data);
        let mut results = Vec::new();

        while self.buffer.len() >= self.chunk_size {
            let chunk: Vec<u8> = self.buffer.drain(..self.chunk_size).collect();
            let encrypted = self.context.encrypt(&self.key_id, &chunk, None)?;
            results.push(encrypted);
        }

        Ok(results)
    }

    /// Finalize encryption, encrypting any remaining data
    pub fn finalize(&mut self) -> Result<Option<EncryptedData>, NeonCryptoError> {
        if self.buffer.is_empty() {
            return Ok(None);
        }

        let remaining = std::mem::take(&mut self.buffer);
        let encrypted = self.context.encrypt(&self.key_id, &remaining, None)?;
        Ok(Some(encrypted))
    }
}

/// Batch encryption for multiple items
pub struct BatchEncryptor {
    context: Arc<NeonCryptoContext>,
}

impl BatchEncryptor {
    pub fn new(context: Arc<NeonCryptoContext>) -> Self {
        Self { context }
    }

    /// Encrypt multiple items in batch
    pub fn encrypt_batch(
        &self,
        key_id: &str,
        items: &[&[u8]],
    ) -> Result<Vec<EncryptedData>, NeonCryptoError> {
        items
            .iter()
            .map(|item| self.context.encrypt(key_id, item, None))
            .collect()
    }

    /// Decrypt multiple items in batch
    pub fn decrypt_batch(&self, items: &[EncryptedData]) -> Result<Vec<Vec<u8>>, NeonCryptoError> {
        items
            .iter()
            .map(|item| self.context.decrypt(item))
            .collect()
    }

    /// Encrypt JSON-serializable objects (for React state encryption)
    pub fn encrypt_json_batch(
        &self,
        key_id: &str,
        json_strings: &[&str],
    ) -> Result<Vec<JsCompatibleObject>, NeonCryptoError> {
        json_strings
            .iter()
            .map(|s| self.context.encrypt_string(key_id, s, None))
            .collect()
    }
}

// Helper functions

fn generate_random_bytes(size: usize) -> Vec<u8> {
    // In production, use a CSPRNG
    (0..size).map(|i| (i * 17 + 23) as u8).collect()
}

fn base64_encode(data: &[u8]) -> String {
    // Simplified base64 encoding
    use std::fmt::Write;
    let mut result = String::new();
    for byte in data {
        write!(result, "{:02x}", byte).unwrap();
    }
    result
}

fn base64_decode(s: &str) -> Result<Vec<u8>, NeonCryptoError> {
    let mut result = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    for chunk in chars.chunks(2) {
        if chunk.len() == 2 {
            let byte = u8::from_str_radix(&format!("{}{}", chunk[0], chunk[1]), 16)
                .map_err(|e| NeonCryptoError::Base64DecodeError(e.to_string()))?;
            result.push(byte);
        }
    }
    Ok(result)
}

fn generate_hmac_tag(key: &[u8], data: &[u8], aad: &[u8]) -> Vec<u8> {
    // Simplified HMAC - in production use proper HMAC-SHA256
    let mut tag = vec![0u8; 16];
    for (i, t) in tag.iter_mut().enumerate() {
        *t = key.get(i).copied().unwrap_or(0)
            ^ data.get(i).copied().unwrap_or(0)
            ^ aad.get(i).copied().unwrap_or(0);
    }
    tag
}

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

fn main() {
    println!("=== Neon Node.js Encryption Module ===\n");

    // Create crypto context
    let ctx = Arc::new(NeonCryptoContext::new(EncryptionAlgorithm::Aes256Gcm));

    // Generate keys
    let key_id = ctx.generate_key("nextjs-session-key").unwrap();
    println!("Generated key: {}", key_id);

    // Encrypt string data (common in React/Next.js)
    let user_data = r#"{"userId": "123", "email": "user@example.com", "role": "admin"}"#;
    let encrypted = ctx
        .encrypt_string(&key_id, user_data, Some("session"))
        .unwrap();
    println!("\nEncrypted user data:");
    println!("  Ciphertext: {}...", &encrypted.ciphertext_base64[..20]);
    println!("  Algorithm: {}", encrypted.algorithm);
    println!("  Key ID: {}", encrypted.key_id);

    // Decrypt
    let decrypted = ctx.decrypt_string(&encrypted).unwrap();
    println!("\nDecrypted: {}", decrypted);

    // Batch encryption for multiple React state objects
    let batch = BatchEncryptor::new(Arc::clone(&ctx));
    let states = vec![
        r#"{"cart": []}"#,
        r#"{"preferences": {"theme": "dark"}}"#,
        r#"{"notifications": ["msg1", "msg2"]}"#,
    ];
    let encrypted_states = batch.encrypt_json_batch(&key_id, &states).unwrap();
    println!(
        "\nBatch encrypted {} React state objects",
        encrypted_states.len()
    );

    // Streaming encryption for file uploads
    let mut stream = NeonStreamCipher::new(Arc::clone(&ctx), key_id.clone(), 1024);
    let file_data = b"Large file content that would be streamed from JavaScript...";
    let _chunks = stream.push(file_data).unwrap();
    let _final_chunk = stream.finalize().unwrap();
    println!("Stream encryption completed");

    // Check metrics
    let metrics = ctx.get_metrics();
    println!("\nCrypto metrics:");
    println!("  Encryptions: {}", metrics.encryptions);
    println!("  Decryptions: {}", metrics.decryptions);
    println!("  Bytes encrypted: {}", metrics.total_bytes_encrypted);

    // Key rotation check
    if ctx.key_needs_rotation(&key_id).unwrap() {
        println!("\nKey {} needs rotation", key_id);
        ctx.rotate_key(&key_id).unwrap();
        println!("Key rotated successfully");
    }

    println!("\n=== Neon Module Ready for Node.js Export ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = NeonKey::generate("test-key", EncryptionAlgorithm::Aes256Gcm);
        assert_eq!(key.id, "test-key");
        assert_eq!(key.key_bytes.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let ctx =
            NeonCryptoContext::new(EncryptionAlgorithm::Aes256Gcm).with_rotation_enforcement(false);
        ctx.generate_key("test").unwrap();

        let plaintext = b"Hello from Next.js!";
        let encrypted = ctx.encrypt("test", plaintext, None).unwrap();
        let decrypted = ctx.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_string_encryption() {
        let ctx = NeonCryptoContext::new(EncryptionAlgorithm::ChaCha20Poly1305)
            .with_rotation_enforcement(false);
        ctx.generate_key("string-key").unwrap();

        let original = "React component state data";
        let encrypted = ctx.encrypt_string("string-key", original, None).unwrap();
        let decrypted = ctx.decrypt_string(&encrypted).unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_js_object_serialization() {
        let ctx =
            NeonCryptoContext::new(EncryptionAlgorithm::Aes256Gcm).with_rotation_enforcement(false);
        ctx.generate_key("js-key").unwrap();

        let encrypted = ctx.encrypt("js-key", b"test data", Some(b"aad")).unwrap();
        let js_obj = encrypted.to_js_object();

        // Verify roundtrip through JS format
        let restored = EncryptedData::from_js_object(&js_obj).unwrap();
        assert_eq!(encrypted.ciphertext, restored.ciphertext);
        assert_eq!(encrypted.nonce, restored.nonce);
    }

    #[test]
    fn test_batch_encryption() {
        let ctx = Arc::new(
            NeonCryptoContext::new(EncryptionAlgorithm::Aes256Gcm).with_rotation_enforcement(false),
        );
        ctx.generate_key("batch-key").unwrap();

        let batch = BatchEncryptor::new(ctx);
        let items: Vec<&[u8]> = vec![b"item1", b"item2", b"item3"];
        let encrypted = batch.encrypt_batch("batch-key", &items).unwrap();

        assert_eq!(encrypted.len(), 3);
    }

    #[test]
    fn test_stream_cipher() {
        let ctx = Arc::new(
            NeonCryptoContext::new(EncryptionAlgorithm::ChaCha20Poly1305)
                .with_rotation_enforcement(false),
        );
        ctx.generate_key("stream-key").unwrap();

        let mut stream = NeonStreamCipher::new(ctx, "stream-key".to_string(), 10);

        let chunks = stream.push(b"0123456789ABCDEF").unwrap();
        assert_eq!(chunks.len(), 1); // One full chunk

        let final_chunk = stream.finalize().unwrap();
        assert!(final_chunk.is_some()); // Remaining 6 bytes
    }

    #[test]
    fn test_authentication_failure() {
        let ctx =
            NeonCryptoContext::new(EncryptionAlgorithm::Aes256Gcm).with_rotation_enforcement(false);
        ctx.generate_key("auth-key").unwrap();

        let mut encrypted = ctx.encrypt("auth-key", b"secret", None).unwrap();
        // Tamper with tag
        encrypted.tag[0] ^= 0xFF;

        let result = ctx.decrypt(&encrypted);
        assert!(matches!(result, Err(NeonCryptoError::AuthenticationFailed)));
    }

    #[test]
    fn test_key_not_found() {
        let ctx = NeonCryptoContext::new(EncryptionAlgorithm::Aes256Gcm);
        let result = ctx.encrypt("nonexistent", b"data", None);
        assert!(matches!(result, Err(NeonCryptoError::KeyNotFound(_))));
    }

    #[test]
    fn test_metrics_tracking() {
        let ctx =
            NeonCryptoContext::new(EncryptionAlgorithm::Aes256Gcm).with_rotation_enforcement(false);
        ctx.generate_key("metrics-key").unwrap();

        ctx.encrypt("metrics-key", b"test1", None).unwrap();
        ctx.encrypt("metrics-key", b"test2", None).unwrap();

        let metrics = ctx.get_metrics();
        assert_eq!(metrics.encryptions, 2);
        assert_eq!(metrics.total_bytes_encrypted, 10);
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare(b"hello", b"hello"));
        assert!(!constant_time_compare(b"hello", b"world"));
        assert!(!constant_time_compare(b"hello", b"hell"));
    }
}
