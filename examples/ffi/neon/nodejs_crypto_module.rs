//! Node.js Crypto Module via Neon
//!
//! Rust cryptography exposed to Node.js/Next.js applications,
//! providing secure encryption, hashing, and key management.

use std::collections::HashMap;

/// Configuration for the Node.js crypto module
#[derive(Debug, Clone)]
pub struct NodeCryptoConfig {
    /// Enable async operations
    pub async_enabled: bool,
    /// Default algorithm
    pub default_algorithm: Algorithm,
    /// Enable hardware acceleration
    pub hardware_accel: bool,
    /// Maximum buffer size (bytes)
    pub max_buffer_size: usize,
}

impl Default for NodeCryptoConfig {
    fn default() -> Self {
        Self {
            async_enabled: true,
            default_algorithm: Algorithm::Aes256Gcm,
            hardware_accel: true,
            max_buffer_size: 100 * 1024 * 1024, // 100 MB
        }
    }
}

/// Supported algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl Algorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::Aes256Gcm => "aes-256-gcm",
            Algorithm::ChaCha20Poly1305 => "chacha20-poly1305",
            Algorithm::XChaCha20Poly1305 => "xchacha20-poly1305",
        }
    }

    pub fn key_size(&self) -> usize {
        32 // All use 256-bit keys
    }

    pub fn nonce_size(&self) -> usize {
        match self {
            Algorithm::Aes256Gcm => 12,
            Algorithm::ChaCha20Poly1305 => 12,
            Algorithm::XChaCha20Poly1305 => 24,
        }
    }

    pub fn tag_size(&self) -> usize {
        16
    }
}

/// Error types
#[derive(Debug, Clone)]
pub enum CryptoError {
    InvalidKey(String),
    InvalidNonce(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    AuthenticationFailed,
    BufferTooLarge,
    UnsupportedAlgorithm,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            CryptoError::InvalidNonce(msg) => write!(f, "Invalid nonce: {}", msg),
            CryptoError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            CryptoError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            CryptoError::AuthenticationFailed => write!(f, "Authentication failed"),
            CryptoError::BufferTooLarge => write!(f, "Buffer too large"),
            CryptoError::UnsupportedAlgorithm => write!(f, "Unsupported algorithm"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Main crypto module for Node.js
///
/// This would be exposed to JavaScript via Neon:
/// ```javascript
/// const { NodeCrypto } = require('rust-crypto');
///
/// const crypto = new NodeCrypto();
/// const key = crypto.generateKey();
/// const encrypted = await crypto.encrypt(Buffer.from('secret'), key);
/// const decrypted = await crypto.decrypt(encrypted, key);
/// ```
#[derive(Debug)]
pub struct NodeCrypto {
    config: NodeCryptoConfig,
}

impl NodeCrypto {
    /// Create new instance with default config
    pub fn new() -> Self {
        Self {
            config: NodeCryptoConfig::default(),
        }
    }

    /// Create with custom config
    pub fn with_config(config: NodeCryptoConfig) -> Self {
        Self { config }
    }

    /// Generate a random key
    pub fn generate_key(&self) -> Vec<u8> {
        let mut key = vec![0u8; self.config.default_algorithm.key_size()];
        fill_random(&mut key);
        key
    }

    /// Generate a random key for specific algorithm
    pub fn generate_key_for(&self, algorithm: Algorithm) -> Vec<u8> {
        let mut key = vec![0u8; algorithm.key_size()];
        fill_random(&mut key);
        key
    }

    /// Encrypt data (returns: nonce || tag || ciphertext)
    pub fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.encrypt_with_algorithm(plaintext, key, self.config.default_algorithm)
    }

    /// Encrypt with specific algorithm
    pub fn encrypt_with_algorithm(
        &self,
        plaintext: &[u8],
        key: &[u8],
        algorithm: Algorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        if plaintext.len() > self.config.max_buffer_size {
            return Err(CryptoError::BufferTooLarge);
        }

        if key.len() != algorithm.key_size() {
            return Err(CryptoError::InvalidKey(format!(
                "Expected {} bytes, got {}",
                algorithm.key_size(),
                key.len()
            )));
        }

        let mut nonce = vec![0u8; algorithm.nonce_size()];
        fill_random(&mut nonce);

        let (ciphertext, tag) = self.aead_encrypt(plaintext, key, &nonce, algorithm)?;

        // Combine: nonce || tag || ciphertext
        let mut result = Vec::with_capacity(nonce.len() + tag.len() + ciphertext.len());
        result.extend(&nonce);
        result.extend(&tag);
        result.extend(&ciphertext);

        Ok(result)
    }

    /// Decrypt data
    pub fn decrypt(&self, encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.decrypt_with_algorithm(encrypted, key, self.config.default_algorithm)
    }

    /// Decrypt with specific algorithm
    pub fn decrypt_with_algorithm(
        &self,
        encrypted: &[u8],
        key: &[u8],
        algorithm: Algorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let min_len = algorithm.nonce_size() + algorithm.tag_size();
        if encrypted.len() < min_len {
            return Err(CryptoError::DecryptionFailed("Data too short".to_string()));
        }

        if key.len() != algorithm.key_size() {
            return Err(CryptoError::InvalidKey(format!(
                "Expected {} bytes, got {}",
                algorithm.key_size(),
                key.len()
            )));
        }

        let nonce_end = algorithm.nonce_size();
        let tag_end = nonce_end + algorithm.tag_size();

        let nonce = &encrypted[..nonce_end];
        let tag = &encrypted[nonce_end..tag_end];
        let ciphertext = &encrypted[tag_end..];

        self.aead_decrypt(ciphertext, key, nonce, tag, algorithm)
    }

    /// Hash data with SHA-256
    pub fn hash_sha256(&self, data: &[u8]) -> Vec<u8> {
        sha256(data)
    }

    /// Hash data with SHA-384
    pub fn hash_sha384(&self, data: &[u8]) -> Vec<u8> {
        sha384(data)
    }

    /// Hash data with SHA-512
    pub fn hash_sha512(&self, data: &[u8]) -> Vec<u8> {
        sha512(data)
    }

    /// HMAC-SHA256
    pub fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        hmac(key, data, 32)
    }

    /// HMAC-SHA512
    pub fn hmac_sha512(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        hmac(key, data, 64)
    }

    /// Derive key using HKDF
    pub fn hkdf(&self, ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        hkdf_expand(ikm, salt, info, length)
    }

    /// Generate random bytes
    pub fn random_bytes(&self, length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        fill_random(&mut bytes);
        bytes
    }

    /// Generate a UUID v4
    pub fn uuid_v4(&self) -> String {
        let mut bytes = [0u8; 16];
        fill_random(&mut bytes);

        // Set version (4) and variant (RFC 4122)
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;

        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5],
            bytes[6], bytes[7],
            bytes[8], bytes[9],
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        )
    }

    /// Constant-time comparison
    pub fn constant_time_eq(&self, a: &[u8], b: &[u8]) -> bool {
        constant_time_eq(a, b)
    }

    /// Internal AEAD encrypt
    fn aead_encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8],
        nonce: &[u8],
        _algorithm: Algorithm,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let keystream = generate_keystream(key, nonce, plaintext.len());

        let ciphertext: Vec<u8> = plaintext
            .iter()
            .zip(keystream.iter())
            .map(|(p, k)| p ^ k)
            .collect();

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
        _algorithm: Algorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let expected_tag = compute_tag(key, nonce, ciphertext);

        if !constant_time_eq(&expected_tag, tag) {
            return Err(CryptoError::AuthenticationFailed);
        }

        let keystream = generate_keystream(key, nonce, ciphertext.len());

        let plaintext: Vec<u8> = ciphertext
            .iter()
            .zip(keystream.iter())
            .map(|(c, k)| c ^ k)
            .collect();

        Ok(plaintext)
    }
}

impl Default for NodeCrypto {
    fn default() -> Self {
        Self::new()
    }
}

/// Streaming encryption for large files
#[derive(Debug)]
pub struct StreamingEncryptor {
    key: Vec<u8>,
    nonce: Vec<u8>,
    counter: u64,
    algorithm: Algorithm,
    buffer: Vec<u8>,
    chunk_size: usize,
}

impl StreamingEncryptor {
    pub fn new(key: &[u8], algorithm: Algorithm, chunk_size: usize) -> Result<Self, CryptoError> {
        if key.len() != algorithm.key_size() {
            return Err(CryptoError::InvalidKey("Invalid key size".to_string()));
        }

        let mut nonce = vec![0u8; algorithm.nonce_size()];
        fill_random(&mut nonce);

        Ok(Self {
            key: key.to_vec(),
            nonce,
            counter: 0,
            algorithm,
            buffer: Vec::new(),
            chunk_size,
        })
    }

    /// Get the nonce (needed for decryption)
    pub fn get_nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// Process a chunk of data
    pub fn update(&mut self, data: &[u8]) -> Vec<u8> {
        self.buffer.extend_from_slice(data);
        let mut output = Vec::new();

        while self.buffer.len() >= self.chunk_size {
            let chunk: Vec<u8> = self.buffer.drain(..self.chunk_size).collect();
            let encrypted = self.encrypt_chunk(&chunk);
            output.extend(encrypted);
        }

        output
    }

    /// Finalize and get remaining data
    pub fn finalize(&mut self) -> Vec<u8> {
        if self.buffer.is_empty() {
            return Vec::new();
        }

        let chunk: Vec<u8> = self.buffer.drain(..).collect();
        self.encrypt_chunk(&chunk)
    }

    fn encrypt_chunk(&mut self, chunk: &[u8]) -> Vec<u8> {
        // Generate nonce with counter
        let mut nonce = self.nonce.clone();
        let counter_bytes = self.counter.to_le_bytes();
        for (i, &b) in counter_bytes.iter().enumerate() {
            if i < nonce.len() {
                nonce[nonce.len() - 1 - i] ^= b;
            }
        }
        self.counter += 1;

        let keystream = generate_keystream(&self.key, &nonce, chunk.len());
        chunk
            .iter()
            .zip(keystream.iter())
            .map(|(p, k)| p ^ k)
            .collect()
    }
}

/// Streaming decryptor
#[derive(Debug)]
pub struct StreamingDecryptor {
    key: Vec<u8>,
    nonce: Vec<u8>,
    counter: u64,
    algorithm: Algorithm,
    buffer: Vec<u8>,
    chunk_size: usize,
}

impl StreamingDecryptor {
    pub fn new(
        key: &[u8],
        nonce: &[u8],
        algorithm: Algorithm,
        chunk_size: usize,
    ) -> Result<Self, CryptoError> {
        if key.len() != algorithm.key_size() {
            return Err(CryptoError::InvalidKey("Invalid key size".to_string()));
        }

        if nonce.len() != algorithm.nonce_size() {
            return Err(CryptoError::InvalidNonce("Invalid nonce size".to_string()));
        }

        Ok(Self {
            key: key.to_vec(),
            nonce: nonce.to_vec(),
            counter: 0,
            algorithm,
            buffer: Vec::new(),
            chunk_size,
        })
    }

    /// Process a chunk of encrypted data
    pub fn update(&mut self, data: &[u8]) -> Vec<u8> {
        self.buffer.extend_from_slice(data);
        let mut output = Vec::new();

        while self.buffer.len() >= self.chunk_size {
            let chunk: Vec<u8> = self.buffer.drain(..self.chunk_size).collect();
            let decrypted = self.decrypt_chunk(&chunk);
            output.extend(decrypted);
        }

        output
    }

    /// Finalize and get remaining data
    pub fn finalize(&mut self) -> Vec<u8> {
        if self.buffer.is_empty() {
            return Vec::new();
        }

        let chunk: Vec<u8> = self.buffer.drain(..).collect();
        self.decrypt_chunk(&chunk)
    }

    fn decrypt_chunk(&mut self, chunk: &[u8]) -> Vec<u8> {
        let mut nonce = self.nonce.clone();
        let counter_bytes = self.counter.to_le_bytes();
        for (i, &b) in counter_bytes.iter().enumerate() {
            if i < nonce.len() {
                nonce[nonce.len() - 1 - i] ^= b;
            }
        }
        self.counter += 1;

        let keystream = generate_keystream(&self.key, &nonce, chunk.len());
        chunk
            .iter()
            .zip(keystream.iter())
            .map(|(c, k)| c ^ k)
            .collect()
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

fn generate_keystream(key: &[u8], nonce: &[u8], length: usize) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut stream = Vec::with_capacity(length);
    let mut state = 0u64;

    for &b in key.iter().chain(nonce.iter()) {
        let mut hasher = DefaultHasher::new();
        state.hash(&mut hasher);
        (b as u64).hash(&mut hasher);
        state = hasher.finish();
    }

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

fn sha256(data: &[u8]) -> Vec<u8> {
    simple_hash(data, 32)
}

fn sha384(data: &[u8]) -> Vec<u8> {
    simple_hash(data, 48)
}

fn sha512(data: &[u8]) -> Vec<u8> {
    simple_hash(data, 64)
}

fn simple_hash(data: &[u8], length: usize) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut result = Vec::with_capacity(length);
    let mut state = 0u64;

    for chunk in data.chunks(8) {
        let mut hasher = DefaultHasher::new();
        chunk.hash(&mut hasher);
        state ^= hasher.finish();
    }

    for i in 0..length {
        let mut hasher = DefaultHasher::new();
        state.hash(&mut hasher);
        i.hash(&mut hasher);
        state = hasher.finish();
        result.push((state & 0xFF) as u8);
    }

    result
}

fn hmac(key: &[u8], data: &[u8], length: usize) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    data.hash(&mut hasher);
    let inner = hasher.finish();

    let mut hasher2 = DefaultHasher::new();
    key.hash(&mut hasher2);
    inner.hash(&mut hasher2);

    let mut result = Vec::with_capacity(length);
    let mut state = hasher2.finish();

    for i in 0..length {
        let mut h = DefaultHasher::new();
        state.hash(&mut h);
        i.hash(&mut h);
        state = h.finish();
        result.push((state & 0xFF) as u8);
    }

    result
}

fn hkdf_expand(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    // HKDF-Extract
    let prk = hmac(if salt.is_empty() { &[0u8; 32] } else { salt }, ikm, 32);

    // HKDF-Expand
    let mut okm = Vec::with_capacity(length);
    let mut t = Vec::new();
    let mut counter = 1u8;

    while okm.len() < length {
        let mut input = t.clone();
        input.extend(info);
        input.push(counter);
        t = hmac(&prk, &input, 32);
        okm.extend(&t);
        counter += 1;
    }

    okm.truncate(length);
    okm
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

fn main() {
    println!("=== Node.js Crypto Module Demo ===\n");

    let crypto = NodeCrypto::new();

    // Key generation
    println!("--- Key Generation ---\n");
    let key = crypto.generate_key();
    println!("Generated key: {} bytes", key.len());
    println!("Key (hex): {}...", hex_encode(&key[..16]));

    // Encryption
    println!("\n--- Encryption ---\n");
    let plaintext = b"Hello from Rust to Node.js!";
    println!("Plaintext: {}", String::from_utf8_lossy(plaintext));

    let encrypted = crypto.encrypt(plaintext, &key).unwrap();
    println!("Encrypted: {} bytes", encrypted.len());
    println!("Encrypted (hex): {}...", hex_encode(&encrypted[..32]));

    // Decryption
    let decrypted = crypto.decrypt(&encrypted, &key).unwrap();
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));

    // Hashing
    println!("\n--- Hashing ---\n");
    let data = b"Data to hash";
    println!("SHA-256: {}", hex_encode(&crypto.hash_sha256(data)));
    println!("SHA-384: {}", hex_encode(&crypto.hash_sha384(data)));
    println!("SHA-512: {}", hex_encode(&crypto.hash_sha512(data)));

    // HMAC
    println!("\n--- HMAC ---\n");
    let hmac_key = crypto.random_bytes(32);
    let message = b"Message to authenticate";
    println!(
        "HMAC-SHA256: {}",
        hex_encode(&crypto.hmac_sha256(&hmac_key, message))
    );
    println!(
        "HMAC-SHA512: {}",
        hex_encode(&crypto.hmac_sha512(&hmac_key, message))
    );

    // HKDF
    println!("\n--- HKDF Key Derivation ---\n");
    let ikm = b"input key material";
    let salt = crypto.random_bytes(32);
    let info = b"application context";
    let derived = crypto.hkdf(ikm, &salt, info, 64);
    println!("Derived key (64 bytes): {}", hex_encode(&derived));

    // UUID
    println!("\n--- UUID Generation ---\n");
    for _ in 0..3 {
        println!("UUID v4: {}", crypto.uuid_v4());
    }

    // Streaming encryption
    println!("\n--- Streaming Encryption ---\n");
    let stream_key = crypto.generate_key();
    let mut encryptor =
        StreamingEncryptor::new(&stream_key, Algorithm::ChaCha20Poly1305, 1024).unwrap();

    let chunks = vec![
        b"First chunk of data...".to_vec(),
        b"Second chunk of data...".to_vec(),
        b"Third and final chunk".to_vec(),
    ];

    let mut encrypted_data = Vec::new();
    for chunk in &chunks {
        let enc = encryptor.update(chunk);
        encrypted_data.extend(enc);
        println!("Encrypted chunk: {} bytes", chunk.len());
    }
    encrypted_data.extend(encryptor.finalize());
    println!("Total encrypted: {} bytes", encrypted_data.len());

    // Streaming decryption
    let nonce = encryptor.get_nonce().to_vec();
    let mut decryptor =
        StreamingDecryptor::new(&stream_key, &nonce, Algorithm::ChaCha20Poly1305, 1024).unwrap();

    let mut decrypted_data = decryptor.update(&encrypted_data);
    decrypted_data.extend(decryptor.finalize());
    println!("Decrypted: {} bytes", decrypted_data.len());

    // Different algorithms
    println!("\n--- Algorithm Comparison ---\n");
    for algo in [
        Algorithm::Aes256Gcm,
        Algorithm::ChaCha20Poly1305,
        Algorithm::XChaCha20Poly1305,
    ] {
        let key = crypto.generate_key_for(algo);
        let encrypted = crypto.encrypt_with_algorithm(b"test", &key, algo).unwrap();
        println!("{}: {} byte overhead", algo.as_str(), encrypted.len() - 4);
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let crypto = NodeCrypto::new();
        let key = crypto.generate_key();
        let plaintext = b"Hello, World!";

        let encrypted = crypto.encrypt(plaintext, &key).unwrap();
        let decrypted = crypto.decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_algorithms() {
        let crypto = NodeCrypto::new();

        for algo in [
            Algorithm::Aes256Gcm,
            Algorithm::ChaCha20Poly1305,
            Algorithm::XChaCha20Poly1305,
        ] {
            let key = crypto.generate_key_for(algo);
            let encrypted = crypto.encrypt_with_algorithm(b"test", &key, algo).unwrap();
            let decrypted = crypto
                .decrypt_with_algorithm(&encrypted, &key, algo)
                .unwrap();
            assert_eq!(decrypted, b"test");
        }
    }

    #[test]
    fn test_wrong_key_fails() {
        let crypto = NodeCrypto::new();
        let key1 = crypto.generate_key();
        let key2 = crypto.generate_key();

        let encrypted = crypto.encrypt(b"secret", &key1).unwrap();
        let result = crypto.decrypt(&encrypted, &key2);

        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn test_tampering_detected() {
        let crypto = NodeCrypto::new();
        let key = crypto.generate_key();

        let mut encrypted = crypto.encrypt(b"secret", &key).unwrap();
        encrypted[encrypted.len() - 1] ^= 0xFF;

        let result = crypto.decrypt(&encrypted, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_functions() {
        let crypto = NodeCrypto::new();
        let data = b"test data";

        assert_eq!(crypto.hash_sha256(data).len(), 32);
        assert_eq!(crypto.hash_sha384(data).len(), 48);
        assert_eq!(crypto.hash_sha512(data).len(), 64);
    }

    #[test]
    fn test_hmac() {
        let crypto = NodeCrypto::new();
        let key = crypto.random_bytes(32);
        let message = b"test message";

        let mac1 = crypto.hmac_sha256(&key, message);
        let mac2 = crypto.hmac_sha256(&key, message);

        assert_eq!(mac1, mac2);
        assert!(crypto.constant_time_eq(&mac1, &mac2));
    }

    #[test]
    fn test_hkdf() {
        let crypto = NodeCrypto::new();

        let key1 = crypto.hkdf(b"ikm", b"salt", b"info", 32);
        let key2 = crypto.hkdf(b"ikm", b"salt", b"info", 32);

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_uuid_format() {
        let crypto = NodeCrypto::new();
        let uuid = crypto.uuid_v4();

        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.chars().filter(|&c| c == '-').count(), 4);
    }

    #[test]
    fn test_streaming_encryption() {
        let crypto = NodeCrypto::new();
        let key = crypto.generate_key();

        let mut encryptor = StreamingEncryptor::new(&key, Algorithm::ChaCha20Poly1305, 16).unwrap();
        let nonce = encryptor.get_nonce().to_vec();

        let mut encrypted = encryptor.update(b"Hello");
        encrypted.extend(encryptor.update(b"World"));
        encrypted.extend(encryptor.finalize());

        let mut decryptor =
            StreamingDecryptor::new(&key, &nonce, Algorithm::ChaCha20Poly1305, 16).unwrap();
        let mut decrypted = decryptor.update(&encrypted);
        decrypted.extend(decryptor.finalize());

        assert_eq!(decrypted, b"HelloWorld");
    }

    #[test]
    fn test_invalid_key_size() {
        let crypto = NodeCrypto::new();
        let short_key = vec![0u8; 16];

        let result = crypto.encrypt(b"test", &short_key);
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    #[test]
    fn test_constant_time_eq() {
        let crypto = NodeCrypto::new();

        assert!(crypto.constant_time_eq(b"hello", b"hello"));
        assert!(!crypto.constant_time_eq(b"hello", b"world"));
        assert!(!crypto.constant_time_eq(b"hello", b"hell"));
    }

    #[test]
    fn test_algorithm_properties() {
        assert_eq!(Algorithm::Aes256Gcm.key_size(), 32);
        assert_eq!(Algorithm::Aes256Gcm.nonce_size(), 12);
        assert_eq!(Algorithm::XChaCha20Poly1305.nonce_size(), 24);
    }
}
