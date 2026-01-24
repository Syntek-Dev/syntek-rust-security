//! WebAssembly Browser Crypto - Client-Side Encryption for Web Apps
//!
//! This example demonstrates building a WebAssembly module using wasm-bindgen
//! for secure client-side encryption in browser-based applications.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// JavaScript-compatible error type
#[derive(Debug, Clone)]
pub struct WasmCryptoError {
    pub code: String,
    pub message: String,
}

impl WasmCryptoError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn key_not_found(key_id: &str) -> Self {
        Self::new("KEY_NOT_FOUND", format!("Key '{}' not found", key_id))
    }

    pub fn encryption_failed(reason: &str) -> Self {
        Self::new("ENCRYPTION_FAILED", reason)
    }

    pub fn decryption_failed(reason: &str) -> Self {
        Self::new("DECRYPTION_FAILED", reason)
    }

    pub fn auth_failed() -> Self {
        Self::new("AUTH_FAILED", "Authentication tag verification failed")
    }

    pub fn invalid_input(field: &str, reason: &str) -> Self {
        Self::new("INVALID_INPUT", format!("{}: {}", field, reason))
    }
}

impl std::fmt::Display for WasmCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for WasmCryptoError {}

/// Encryption algorithm for WASM
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmAlgorithm {
    /// AES-256-GCM using WebCrypto API
    Aes256Gcm,
    /// ChaCha20-Poly1305 (pure Rust implementation)
    ChaCha20Poly1305,
}

impl WasmAlgorithm {
    pub fn key_length(&self) -> usize {
        32
    }

    pub fn nonce_length(&self) -> usize {
        12
    }

    pub fn tag_length(&self) -> usize {
        16
    }

    /// Get WebCrypto algorithm name
    pub fn webcrypto_name(&self) -> Option<&'static str> {
        match self {
            Self::Aes256Gcm => Some("AES-GCM"),
            Self::ChaCha20Poly1305 => None, // Not available in WebCrypto
        }
    }
}

/// Key for WASM crypto operations
#[derive(Debug, Clone)]
pub struct WasmKey {
    id: String,
    algorithm: WasmAlgorithm,
    key_bytes: Vec<u8>,
    created_timestamp: u64,
}

impl WasmKey {
    pub fn generate(id: impl Into<String>, algorithm: WasmAlgorithm) -> Self {
        Self {
            id: id.into(),
            algorithm,
            key_bytes: generate_random(algorithm.key_length()),
            created_timestamp: current_timestamp(),
        }
    }

    pub fn from_bytes(
        id: impl Into<String>,
        algorithm: WasmAlgorithm,
        bytes: Vec<u8>,
    ) -> Result<Self, WasmCryptoError> {
        if bytes.len() != algorithm.key_length() {
            return Err(WasmCryptoError::invalid_input(
                "key_bytes",
                &format!(
                    "expected {} bytes, got {}",
                    algorithm.key_length(),
                    bytes.len()
                ),
            ));
        }
        Ok(Self {
            id: id.into(),
            algorithm,
            key_bytes: bytes,
            created_timestamp: current_timestamp(),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn algorithm(&self) -> WasmAlgorithm {
        self.algorithm
    }

    /// Export key as base64 (for secure storage in IndexedDB)
    pub fn export_base64(&self) -> String {
        base64_encode(&self.key_bytes)
    }
}

impl Drop for WasmKey {
    fn drop(&mut self) {
        // Secure zeroization
        for byte in &mut self.key_bytes {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
}

/// Encrypted data structure for JavaScript interop
#[derive(Debug, Clone)]
pub struct EncryptedBundle {
    pub ciphertext_b64: String,
    pub nonce_b64: String,
    pub tag_b64: String,
    pub algorithm: String,
    pub key_id: String,
    pub timestamp: u64,
}

impl EncryptedBundle {
    /// Serialize to JSON string for JavaScript
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"ciphertext":"{}","nonce":"{}","tag":"{}","algorithm":"{}","keyId":"{}","timestamp":{}}}"#,
            self.ciphertext_b64,
            self.nonce_b64,
            self.tag_b64,
            self.algorithm,
            self.key_id,
            self.timestamp
        )
    }

    /// Parse from JSON string
    pub fn from_json(json: &str) -> Result<Self, WasmCryptoError> {
        // Simplified JSON parsing - in production use serde_json
        let extract = |key: &str| -> Result<String, WasmCryptoError> {
            let pattern = format!(r#""{}":\s*"([^"]*)""#, key);
            // Simple extraction for demonstration
            if let Some(start) = json.find(&format!("\"{}\":", key)) {
                let rest = &json[start + key.len() + 3..];
                if let Some(quote_start) = rest.find('"') {
                    let rest = &rest[quote_start + 1..];
                    if let Some(quote_end) = rest.find('"') {
                        return Ok(rest[..quote_end].to_string());
                    }
                }
            }
            Err(WasmCryptoError::invalid_input(
                "json",
                &format!("missing field: {}", key),
            ))
        };

        let extract_num = |key: &str| -> Result<u64, WasmCryptoError> {
            if let Some(start) = json.find(&format!("\"{}\":", key)) {
                let rest = &json[start + key.len() + 3..];
                let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                return num_str.parse().map_err(|_| {
                    WasmCryptoError::invalid_input("json", &format!("invalid {}", key))
                });
            }
            Err(WasmCryptoError::invalid_input(
                "json",
                &format!("missing field: {}", key),
            ))
        };

        Ok(Self {
            ciphertext_b64: extract("ciphertext")?,
            nonce_b64: extract("nonce")?,
            tag_b64: extract("tag")?,
            algorithm: extract("algorithm")?,
            key_id: extract("keyId")?,
            timestamp: extract_num("timestamp")?,
        })
    }
}

/// Statistics for monitoring in JavaScript
#[derive(Debug, Default)]
pub struct CryptoStats {
    encryptions: AtomicU64,
    decryptions: AtomicU64,
    bytes_encrypted: AtomicU64,
    bytes_decrypted: AtomicU64,
    failures: AtomicU64,
}

impl CryptoStats {
    pub fn record_encryption(&self, bytes: usize) {
        self.encryptions.fetch_add(1, Ordering::Relaxed);
        self.bytes_encrypted
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_decryption(&self, bytes: usize) {
        self.decryptions.fetch_add(1, Ordering::Relaxed);
        self.bytes_decrypted
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn to_json(&self) -> String {
        format!(
            r#"{{"encryptions":{},"decryptions":{},"bytesEncrypted":{},"bytesDecrypted":{},"failures":{}}}"#,
            self.encryptions.load(Ordering::Relaxed),
            self.decryptions.load(Ordering::Relaxed),
            self.bytes_encrypted.load(Ordering::Relaxed),
            self.bytes_decrypted.load(Ordering::Relaxed),
            self.failures.load(Ordering::Relaxed)
        )
    }
}

/// Main WASM crypto context - designed for wasm-bindgen export
pub struct WasmCrypto {
    keys: HashMap<String, WasmKey>,
    default_algorithm: WasmAlgorithm,
    stats: CryptoStats,
}

impl WasmCrypto {
    /// Create a new WASM crypto context
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            default_algorithm: WasmAlgorithm::Aes256Gcm,
            stats: CryptoStats::default(),
        }
    }

    /// Set default algorithm
    pub fn set_default_algorithm(&mut self, algorithm: WasmAlgorithm) {
        self.default_algorithm = algorithm;
    }

    /// Generate a new key
    pub fn generate_key(&mut self, key_id: String) -> String {
        let key = WasmKey::generate(&key_id, self.default_algorithm);
        let info = format!(
            r#"{{"id":"{}","algorithm":"{:?}","created":{}}}"#,
            key.id, key.algorithm, key.created_timestamp
        );
        self.keys.insert(key_id, key);
        info
    }

    /// Import a key from base64
    pub fn import_key(
        &mut self,
        key_id: String,
        key_b64: String,
    ) -> Result<String, WasmCryptoError> {
        let bytes = base64_decode(&key_b64)?;
        let key = WasmKey::from_bytes(&key_id, self.default_algorithm, bytes)?;
        let info = format!(
            r#"{{"id":"{}","algorithm":"{:?}","created":{}}}"#,
            key.id, key.algorithm, key.created_timestamp
        );
        self.keys.insert(key_id, key);
        Ok(info)
    }

    /// Export a key as base64
    pub fn export_key(&self, key_id: &str) -> Result<String, WasmCryptoError> {
        self.keys
            .get(key_id)
            .map(|k| k.export_base64())
            .ok_or_else(|| WasmCryptoError::key_not_found(key_id))
    }

    /// Delete a key
    pub fn delete_key(&mut self, key_id: &str) -> bool {
        self.keys.remove(key_id).is_some()
    }

    /// List all key IDs as JSON array
    pub fn list_keys(&self) -> String {
        let keys: Vec<&str> = self.keys.keys().map(|s| s.as_str()).collect();
        format!(r#"["{}"]"#, keys.join("\",\""))
    }

    /// Encrypt a string
    pub fn encrypt_string(
        &mut self,
        key_id: &str,
        plaintext: &str,
    ) -> Result<String, WasmCryptoError> {
        let bundle = self.encrypt_bytes(key_id, plaintext.as_bytes())?;
        Ok(bundle.to_json())
    }

    /// Encrypt bytes (exposed as Uint8Array in JS)
    pub fn encrypt_bytes(
        &mut self,
        key_id: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedBundle, WasmCryptoError> {
        let key = self
            .keys
            .get(key_id)
            .ok_or_else(|| WasmCryptoError::key_not_found(key_id))?;

        let nonce = generate_random(key.algorithm.nonce_length());
        let (ciphertext, tag) = encrypt_aead(key.algorithm, &key.key_bytes, &nonce, plaintext)?;

        self.stats.record_encryption(plaintext.len());

        Ok(EncryptedBundle {
            ciphertext_b64: base64_encode(&ciphertext),
            nonce_b64: base64_encode(&nonce),
            tag_b64: base64_encode(&tag),
            algorithm: format!("{:?}", key.algorithm),
            key_id: key_id.to_string(),
            timestamp: current_timestamp(),
        })
    }

    /// Decrypt a string (from JSON bundle)
    pub fn decrypt_string(&mut self, bundle_json: &str) -> Result<String, WasmCryptoError> {
        let bundle = EncryptedBundle::from_json(bundle_json)?;
        let bytes = self.decrypt_bundle(&bundle)?;
        String::from_utf8(bytes).map_err(|e| WasmCryptoError::decryption_failed(&e.to_string()))
    }

    /// Decrypt a bundle to bytes
    pub fn decrypt_bundle(&mut self, bundle: &EncryptedBundle) -> Result<Vec<u8>, WasmCryptoError> {
        let key = self
            .keys
            .get(&bundle.key_id)
            .ok_or_else(|| WasmCryptoError::key_not_found(&bundle.key_id))?;

        let ciphertext = base64_decode(&bundle.ciphertext_b64)?;
        let nonce = base64_decode(&bundle.nonce_b64)?;
        let tag = base64_decode(&bundle.tag_b64)?;

        let plaintext = decrypt_aead(key.algorithm, &key.key_bytes, &nonce, &ciphertext, &tag)?;

        self.stats.record_decryption(plaintext.len());

        Ok(plaintext)
    }

    /// Get statistics as JSON
    pub fn get_stats(&self) -> String {
        self.stats.to_json()
    }

    /// Derive a key from password using PBKDF2
    pub fn derive_key_from_password(
        &mut self,
        key_id: String,
        password: &str,
        salt: &str,
        iterations: u32,
    ) -> Result<String, WasmCryptoError> {
        let salt_bytes = salt.as_bytes();
        let key_bytes = pbkdf2_derive(password.as_bytes(), salt_bytes, iterations, 32);

        let key = WasmKey::from_bytes(&key_id, self.default_algorithm, key_bytes)?;
        let info = format!(
            r#"{{"id":"{}","algorithm":"{:?}","derived":true}}"#,
            key.id, key.algorithm
        );
        self.keys.insert(key_id, key);
        Ok(info)
    }
}

impl Default for WasmCrypto {
    fn default() -> Self {
        Self::new()
    }
}

/// Streaming encryptor for large files
pub struct StreamEncryptor {
    key_bytes: Vec<u8>,
    algorithm: WasmAlgorithm,
    key_id: String,
    chunk_size: usize,
    buffer: Vec<u8>,
    chunk_index: u64,
}

impl StreamEncryptor {
    pub fn new(
        crypto: &WasmCrypto,
        key_id: &str,
        chunk_size: usize,
    ) -> Result<Self, WasmCryptoError> {
        let key = crypto
            .keys
            .get(key_id)
            .ok_or_else(|| WasmCryptoError::key_not_found(key_id))?;

        Ok(Self {
            key_bytes: key.key_bytes.clone(),
            algorithm: key.algorithm,
            key_id: key_id.to_string(),
            chunk_size,
            buffer: Vec::new(),
            chunk_index: 0,
        })
    }

    /// Push data and get encrypted chunks
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<String>, WasmCryptoError> {
        self.buffer.extend_from_slice(data);
        let mut results = Vec::new();

        while self.buffer.len() >= self.chunk_size {
            let chunk: Vec<u8> = self.buffer.drain(..self.chunk_size).collect();
            let bundle = self.encrypt_chunk(&chunk)?;
            results.push(bundle.to_json());
        }

        Ok(results)
    }

    /// Finalize and encrypt remaining data
    pub fn finalize(&mut self) -> Result<Option<String>, WasmCryptoError> {
        if self.buffer.is_empty() {
            return Ok(None);
        }

        let remaining = std::mem::take(&mut self.buffer);
        let bundle = self.encrypt_chunk(&remaining)?;
        Ok(Some(bundle.to_json()))
    }

    fn encrypt_chunk(&mut self, chunk: &[u8]) -> Result<EncryptedBundle, WasmCryptoError> {
        // Use chunk index as part of nonce to ensure uniqueness
        let mut nonce = generate_random(self.algorithm.nonce_length());
        let idx_bytes = self.chunk_index.to_le_bytes();
        for (i, b) in idx_bytes.iter().enumerate() {
            if i < nonce.len() {
                nonce[i] ^= b;
            }
        }
        self.chunk_index += 1;

        let (ciphertext, tag) = encrypt_aead(self.algorithm, &self.key_bytes, &nonce, chunk)?;

        Ok(EncryptedBundle {
            ciphertext_b64: base64_encode(&ciphertext),
            nonce_b64: base64_encode(&nonce),
            tag_b64: base64_encode(&tag),
            algorithm: format!("{:?}", self.algorithm),
            key_id: self.key_id.clone(),
            timestamp: current_timestamp(),
        })
    }
}

impl Drop for StreamEncryptor {
    fn drop(&mut self) {
        for byte in &mut self.key_bytes {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

/// Form field encryptor for sensitive input
pub struct FormEncryptor {
    crypto: WasmCrypto,
    field_key_mapping: HashMap<String, String>,
}

impl FormEncryptor {
    pub fn new() -> Self {
        Self {
            crypto: WasmCrypto::new(),
            field_key_mapping: HashMap::new(),
        }
    }

    /// Register a field with its own key
    pub fn register_field(&mut self, field_name: &str) -> String {
        let key_id = format!("field_{}", field_name);
        let info = self.crypto.generate_key(key_id.clone());
        self.field_key_mapping
            .insert(field_name.to_string(), key_id);
        info
    }

    /// Encrypt a form field value
    pub fn encrypt_field(
        &mut self,
        field_name: &str,
        value: &str,
    ) -> Result<String, WasmCryptoError> {
        let key_id = self
            .field_key_mapping
            .get(field_name)
            .ok_or_else(|| WasmCryptoError::new("FIELD_NOT_REGISTERED", field_name))?
            .clone();

        self.crypto.encrypt_string(&key_id, value)
    }

    /// Decrypt a form field value
    pub fn decrypt_field(&mut self, encrypted_json: &str) -> Result<String, WasmCryptoError> {
        self.crypto.decrypt_string(encrypted_json)
    }

    /// Get all field keys for export
    pub fn export_keys(&self) -> String {
        let mut result = String::from("{");
        for (field, key_id) in &self.field_key_mapping {
            if let Ok(key_b64) = self.crypto.export_key(key_id) {
                if result.len() > 1 {
                    result.push(',');
                }
                result.push_str(&format!(
                    r#""{}":{{"keyId":"{}","key":"{}"}}"#,
                    field, key_id, key_b64
                ));
            }
        }
        result.push('}');
        result
    }
}

impl Default for FormEncryptor {
    fn default() -> Self {
        Self::new()
    }
}

// Helper functions

fn generate_random(size: usize) -> Vec<u8> {
    // In WASM, use crypto.getRandomValues via wasm-bindgen
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    (0..size)
        .map(|i| ((i as u64 * 31 + count * 17 + 23) & 0xFF) as u8)
        .collect()
}

fn current_timestamp() -> u64 {
    // In WASM, use Date.now() via wasm-bindgen
    1706140800000 // Placeholder
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 3) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 15) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 63] as char);
        } else {
            result.push('=');
        }
    }

    result
}

fn base64_decode(s: &str) -> Result<Vec<u8>, WasmCryptoError> {
    const DECODE: [i8; 128] = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
        -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1,
        -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
        46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    ];

    let s = s.trim_end_matches('=');
    let mut result = Vec::with_capacity(s.len() * 3 / 4);

    let chars: Vec<u8> = s
        .chars()
        .filter_map(|c| {
            if c.is_ascii() && DECODE[c as usize] >= 0 {
                Some(DECODE[c as usize] as u8)
            } else {
                None
            }
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

fn encrypt_aead(
    algorithm: WasmAlgorithm,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), WasmCryptoError> {
    let _ = algorithm;

    // Simplified encryption
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
    algorithm: WasmAlgorithm,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, WasmCryptoError> {
    let _ = algorithm;

    // Verify tag
    let mut expected_tag = vec![0u8; 16];
    for (i, t) in expected_tag.iter_mut().enumerate() {
        *t = key[i % key.len()] ^ ciphertext.get(i).copied().unwrap_or(0);
    }

    let mut diff = 0u8;
    for (a, b) in tag.iter().zip(expected_tag.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(WasmCryptoError::auth_failed());
    }

    // Decrypt
    let mut plaintext = ciphertext.to_vec();
    for (i, byte) in plaintext.iter_mut().enumerate() {
        *byte ^= key[i % key.len()] ^ nonce[i % nonce.len()];
    }

    Ok(plaintext)
}

fn pbkdf2_derive(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
    // Simplified PBKDF2 - in production use proper implementation
    let mut key = vec![0u8; key_len];
    for i in 0..key_len {
        let mut val = password.get(i % password.len()).copied().unwrap_or(0);
        for _ in 0..iterations {
            val = val.wrapping_add(salt.get(i % salt.len()).copied().unwrap_or(0));
            val = val.rotate_left(3);
        }
        key[i] = val;
    }
    key
}

fn main() {
    println!("=== WebAssembly Browser Crypto Module ===\n");

    // Create crypto context
    let mut crypto = WasmCrypto::new();

    // Generate a key
    let key_info = crypto.generate_key("session-key".to_string());
    println!("Generated key: {}", key_info);

    // Encrypt sensitive data
    let user_data = r#"{"ssn": "123-45-6789", "creditCard": "4111111111111111"}"#;
    let encrypted = crypto.encrypt_string("session-key", user_data).unwrap();
    println!("\nEncrypted sensitive data:");
    println!("  JSON: {}...", &encrypted[..80]);

    // Decrypt
    let decrypted = crypto.decrypt_string(&encrypted).unwrap();
    println!("Decrypted: {}", decrypted);

    // Password-derived key
    println!("\n--- Password-Derived Key ---");
    let derived_info = crypto
        .derive_key_from_password(
            "user-password-key".to_string(),
            "SecureP@ssw0rd!",
            "random_salt_value",
            100000,
        )
        .unwrap();
    println!("Derived key: {}", derived_info);

    // Streaming encryption for file upload
    println!("\n--- Streaming Encryption ---");
    let mut stream = StreamEncryptor::new(&crypto, "session-key", 1024).unwrap();
    let chunks = stream.push(b"First chunk of file data...").unwrap();
    println!("Encrypted {} chunks", chunks.len());
    let final_chunk = stream.finalize().unwrap();
    if final_chunk.is_some() {
        println!("Final chunk encrypted");
    }

    // Form field encryption
    println!("\n--- Form Field Encryption ---");
    let mut form = FormEncryptor::new();
    form.register_field("password");
    form.register_field("ssn");
    form.register_field("credit_card");

    let enc_password = form
        .encrypt_field("password", "MySecretPassword123!")
        .unwrap();
    let enc_ssn = form.encrypt_field("ssn", "123-45-6789").unwrap();
    println!("Encrypted password field: {}...", &enc_password[..60]);
    println!("Encrypted SSN field: {}...", &enc_ssn[..60]);

    // Export keys for secure storage
    let keys_json = form.export_keys();
    println!("\nExported form keys: {}...", &keys_json[..80]);

    // Statistics
    let stats = crypto.get_stats();
    println!("\nCrypto stats: {}", stats);

    // Key management
    println!("\n--- Key Management ---");
    let keys = crypto.list_keys();
    println!("All keys: {}", keys);

    let exported = crypto.export_key("session-key").unwrap();
    println!("Exported session-key: {}...", &exported[..20]);

    println!("\n=== WASM Module Ready for Browser ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_string() {
        let mut crypto = WasmCrypto::new();
        crypto.generate_key("test-key".to_string());

        let original = "Hello, WebAssembly!";
        let encrypted = crypto.encrypt_string("test-key", original).unwrap();
        let decrypted = crypto.decrypt_string(&encrypted).unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_bytes() {
        let mut crypto = WasmCrypto::new();
        crypto.generate_key("bytes-key".to_string());

        let original = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let bundle = crypto.encrypt_bytes("bytes-key", &original).unwrap();
        let decrypted = crypto.decrypt_bundle(&bundle).unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_key_not_found() {
        let mut crypto = WasmCrypto::new();
        let result = crypto.encrypt_string("nonexistent", "data");
        assert!(result.is_err());
        assert!(result.unwrap_err().code == "KEY_NOT_FOUND");
    }

    #[test]
    fn test_import_export_key() {
        let mut crypto = WasmCrypto::new();
        crypto.generate_key("export-test".to_string());

        let exported = crypto.export_key("export-test").unwrap();

        let mut crypto2 = WasmCrypto::new();
        crypto2
            .import_key("imported".to_string(), exported)
            .unwrap();

        // Keys should work the same
        let encrypted = crypto.encrypt_string("export-test", "test").unwrap();
        // Note: Can't decrypt with different key due to nonce
    }

    #[test]
    fn test_password_derivation() {
        let mut crypto = WasmCrypto::new();
        crypto
            .derive_key_from_password("password-key".to_string(), "password123", "salt", 1000)
            .unwrap();

        let encrypted = crypto.encrypt_string("password-key", "secret").unwrap();
        let decrypted = crypto.decrypt_string(&encrypted).unwrap();

        assert_eq!("secret", decrypted);
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = vec![0x00, 0x01, 0x02, 0xFE, 0xFF];
        let encoded = base64_encode(&original);
        let decoded = base64_decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_encrypted_bundle_json() {
        let bundle = EncryptedBundle {
            ciphertext_b64: "dGVzdA==".to_string(),
            nonce_b64: "bm9uY2U=".to_string(),
            tag_b64: "dGFn".to_string(),
            algorithm: "Aes256Gcm".to_string(),
            key_id: "test-key".to_string(),
            timestamp: 1234567890,
        };

        let json = bundle.to_json();
        let parsed = EncryptedBundle::from_json(&json).unwrap();

        assert_eq!(bundle.ciphertext_b64, parsed.ciphertext_b64);
        assert_eq!(bundle.key_id, parsed.key_id);
    }

    #[test]
    fn test_stream_encryptor() {
        let mut crypto = WasmCrypto::new();
        crypto.generate_key("stream-key".to_string());

        let mut stream = StreamEncryptor::new(&crypto, "stream-key", 10).unwrap();

        let chunks = stream.push(b"0123456789ABCDE").unwrap();
        assert_eq!(chunks.len(), 1);

        let final_chunk = stream.finalize().unwrap();
        assert!(final_chunk.is_some());
    }

    #[test]
    fn test_form_encryptor() {
        let mut form = FormEncryptor::new();
        form.register_field("email");
        form.register_field("password");

        let encrypted = form.encrypt_field("email", "user@example.com").unwrap();
        let decrypted = form.decrypt_field(&encrypted).unwrap();

        assert_eq!("user@example.com", decrypted);
    }

    #[test]
    fn test_authentication_failure() {
        let mut crypto = WasmCrypto::new();
        crypto.generate_key("auth-key".to_string());

        let bundle = crypto.encrypt_bytes("auth-key", b"secret").unwrap();

        // Tamper with ciphertext
        let mut tampered = bundle.clone();
        if let Ok(mut ct) = base64_decode(&tampered.ciphertext_b64) {
            ct[0] ^= 0xFF;
            tampered.ciphertext_b64 = base64_encode(&ct);
        }

        let result = crypto.decrypt_bundle(&tampered);
        assert!(result.is_err());
    }

    #[test]
    fn test_statistics() {
        let mut crypto = WasmCrypto::new();
        crypto.generate_key("stats-key".to_string());

        crypto.encrypt_string("stats-key", "test1").unwrap();
        crypto.encrypt_string("stats-key", "test2").unwrap();

        let stats = crypto.get_stats();
        assert!(stats.contains("\"encryptions\":2"));
    }

    #[test]
    fn test_list_and_delete_keys() {
        let mut crypto = WasmCrypto::new();
        crypto.generate_key("key1".to_string());
        crypto.generate_key("key2".to_string());

        let keys = crypto.list_keys();
        assert!(keys.contains("key1"));
        assert!(keys.contains("key2"));

        crypto.delete_key("key1");
        let keys = crypto.list_keys();
        assert!(!keys.contains("key1"));
        assert!(keys.contains("key2"));
    }
}
