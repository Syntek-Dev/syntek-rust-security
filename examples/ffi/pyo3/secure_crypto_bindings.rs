//! Secure Crypto Bindings for Python
//!
//! PyO3 bindings providing secure cryptographic operations for Python applications.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

/// Error types for crypto operations
#[derive(Debug, Clone)]
pub enum CryptoError {
    InvalidKey,
    InvalidNonce,
    InvalidCiphertext,
    EncryptionFailed,
    DecryptionFailed,
    AuthenticationFailed,
    KeyDerivationFailed,
    RandomGenerationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "Invalid key"),
            Self::InvalidNonce => write!(f, "Invalid nonce"),
            Self::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            Self::EncryptionFailed => write!(f, "Encryption failed"),
            Self::DecryptionFailed => write!(f, "Decryption failed"),
            Self::AuthenticationFailed => write!(f, "Authentication failed"),
            Self::KeyDerivationFailed => write!(f, "Key derivation failed"),
            Self::RandomGenerationFailed => write!(f, "Random generation failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Encryption algorithm
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Algorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl Algorithm {
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
        16 // All supported algorithms use 16-byte tags
    }
}

/// Secure key that zeroizes on drop
#[derive(Clone)]
pub struct SecureKey {
    key: Vec<u8>,
    algorithm: Algorithm,
}

impl SecureKey {
    pub fn new(key: Vec<u8>, algorithm: Algorithm) -> Result<Self, CryptoError> {
        if key.len() != algorithm.key_size() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self { key, algorithm })
    }

    pub fn generate(algorithm: Algorithm) -> Result<Self, CryptoError> {
        let key = generate_random_bytes(algorithm.key_size())?;
        Ok(Self { key, algorithm })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    pub fn algorithm(&self) -> &Algorithm {
        &self.algorithm
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        // Secure zeroization
        for byte in &mut self.key {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

impl fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureKey")
            .field("algorithm", &self.algorithm)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Encryption result
#[derive(Debug, Clone)]
pub struct EncryptionResult {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub tag: Vec<u8>,
}

impl EncryptionResult {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result =
            Vec::with_capacity(self.nonce.len() + self.tag.len() + self.ciphertext.len());
        result.extend_from_slice(&self.nonce);
        result.extend_from_slice(&self.tag);
        result.extend_from_slice(&self.ciphertext);
        result
    }

    pub fn from_bytes(
        data: &[u8],
        nonce_size: usize,
        tag_size: usize,
    ) -> Result<Self, CryptoError> {
        if data.len() < nonce_size + tag_size {
            return Err(CryptoError::InvalidCiphertext);
        }

        let nonce = data[..nonce_size].to_vec();
        let tag = data[nonce_size..nonce_size + tag_size].to_vec();
        let ciphertext = data[nonce_size + tag_size..].to_vec();

        Ok(Self {
            ciphertext,
            nonce,
            tag,
        })
    }
}

/// Encryption context for AEAD operations
pub struct EncryptionContext {
    key: SecureKey,
    aad: Vec<u8>,
}

impl EncryptionContext {
    pub fn new(key: SecureKey) -> Self {
        Self {
            key,
            aad: Vec::new(),
        }
    }

    pub fn with_aad(mut self, aad: Vec<u8>) -> Self {
        self.aad = aad;
        self
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptionResult, CryptoError> {
        let nonce = generate_random_bytes(self.key.algorithm().nonce_size())?;
        self.encrypt_with_nonce(plaintext, &nonce)
    }

    pub fn encrypt_with_nonce(
        &self,
        plaintext: &[u8],
        nonce: &[u8],
    ) -> Result<EncryptionResult, CryptoError> {
        if nonce.len() != self.key.algorithm().nonce_size() {
            return Err(CryptoError::InvalidNonce);
        }

        // Simulated encryption (in real implementation, use actual crypto)
        let ciphertext = simulate_encrypt(plaintext, self.key.as_bytes(), nonce, &self.aad);
        let tag = generate_tag(plaintext, self.key.as_bytes(), nonce, &self.aad);

        Ok(EncryptionResult {
            ciphertext,
            nonce: nonce.to_vec(),
            tag,
        })
    }

    pub fn decrypt(&self, encrypted: &EncryptionResult) -> Result<Vec<u8>, CryptoError> {
        // Verify tag
        let expected_tag = generate_tag(
            &encrypted.ciphertext,
            self.key.as_bytes(),
            &encrypted.nonce,
            &self.aad,
        );

        if !constant_time_compare(&encrypted.tag, &expected_tag) {
            return Err(CryptoError::AuthenticationFailed);
        }

        // Decrypt
        let plaintext =
            simulate_decrypt(&encrypted.ciphertext, self.key.as_bytes(), &encrypted.nonce);

        Ok(plaintext)
    }
}

/// Key derivation context
pub struct KeyDerivation {
    salt: Vec<u8>,
    iterations: u32,
    memory_cost: u32,
}

impl KeyDerivation {
    pub fn new() -> Self {
        Self {
            salt: Vec::new(),
            iterations: 100000,
            memory_cost: 65536,
        }
    }

    pub fn with_salt(mut self, salt: Vec<u8>) -> Self {
        self.salt = salt;
        self
    }

    pub fn with_iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }

    pub fn derive_key(
        &self,
        password: &[u8],
        algorithm: Algorithm,
    ) -> Result<SecureKey, CryptoError> {
        let salt = if self.salt.is_empty() {
            generate_random_bytes(16)?
        } else {
            self.salt.clone()
        };

        // Simulated key derivation
        let key = simulate_pbkdf2(password, &salt, self.iterations, algorithm.key_size());

        SecureKey::new(key, algorithm)
    }

    pub fn derive_key_argon2(
        &self,
        password: &[u8],
        algorithm: Algorithm,
    ) -> Result<(SecureKey, Vec<u8>), CryptoError> {
        let salt = if self.salt.is_empty() {
            generate_random_bytes(16)?
        } else {
            self.salt.clone()
        };

        // Simulated Argon2 key derivation
        let key = simulate_argon2(
            password,
            &salt,
            self.iterations,
            self.memory_cost,
            algorithm.key_size(),
        );

        let secure_key = SecureKey::new(key, algorithm)?;
        Ok((secure_key, salt))
    }
}

impl Default for KeyDerivation {
    fn default() -> Self {
        Self::new()
    }
}

/// Hashing utilities
pub struct Hasher;

impl Hasher {
    pub fn sha256(data: &[u8]) -> Vec<u8> {
        simulate_hash(data, 32)
    }

    pub fn sha512(data: &[u8]) -> Vec<u8> {
        simulate_hash(data, 64)
    }

    pub fn blake3(data: &[u8]) -> Vec<u8> {
        simulate_hash(data, 32)
    }

    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
        simulate_hmac(key, data, 32)
    }

    pub fn hmac_sha512(key: &[u8], data: &[u8]) -> Vec<u8> {
        simulate_hmac(key, data, 64)
    }
}

/// Secure random number generation
pub struct SecureRandom;

impl SecureRandom {
    pub fn bytes(length: usize) -> Result<Vec<u8>, CryptoError> {
        generate_random_bytes(length)
    }

    pub fn u64() -> Result<u64, CryptoError> {
        let bytes = generate_random_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub fn token(length: usize) -> Result<String, CryptoError> {
        let bytes = generate_random_bytes(length)?;
        Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
    }

    pub fn uuid() -> Result<String, CryptoError> {
        let bytes = generate_random_bytes(16)?;
        Ok(format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5],
            bytes[6], bytes[7],
            bytes[8], bytes[9],
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }
}

/// Password hashing for storage
pub struct PasswordHasher {
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
}

impl PasswordHasher {
    pub fn new() -> Self {
        Self {
            memory_cost: 65536,
            time_cost: 3,
            parallelism: 4,
        }
    }

    pub fn with_params(memory_cost: u32, time_cost: u32, parallelism: u32) -> Self {
        Self {
            memory_cost,
            time_cost,
            parallelism,
        }
    }

    pub fn hash(&self, password: &[u8]) -> Result<String, CryptoError> {
        let salt = generate_random_bytes(16)?;
        let hash = simulate_argon2(password, &salt, self.time_cost, self.memory_cost, 32);

        // Format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
        let salt_b64 = base64_encode(&salt);
        let hash_b64 = base64_encode(&hash);

        Ok(format!(
            "$argon2id$v=19$m={},t={},p={}${}${}",
            self.memory_cost, self.time_cost, self.parallelism, salt_b64, hash_b64
        ))
    }

    pub fn verify(&self, password: &[u8], hash_string: &str) -> Result<bool, CryptoError> {
        // Parse hash string
        let parts: Vec<&str> = hash_string.split('$').collect();
        if parts.len() != 6 {
            return Err(CryptoError::InvalidCiphertext);
        }

        let salt = base64_decode(parts[4])?;
        let stored_hash = base64_decode(parts[5])?;

        let computed_hash = simulate_argon2(password, &salt, self.time_cost, self.memory_cost, 32);

        Ok(constant_time_compare(&computed_hash, &stored_hash))
    }
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Key store for managing multiple keys
pub struct KeyStore {
    keys: Mutex<HashMap<String, SecureKey>>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }

    pub fn generate_key(&self, name: &str, algorithm: Algorithm) -> Result<(), CryptoError> {
        let key = SecureKey::generate(algorithm)?;
        let mut keys = self.keys.lock().unwrap();
        keys.insert(name.to_string(), key);
        Ok(())
    }

    pub fn import_key(
        &self,
        name: &str,
        key_bytes: Vec<u8>,
        algorithm: Algorithm,
    ) -> Result<(), CryptoError> {
        let key = SecureKey::new(key_bytes, algorithm)?;
        let mut keys = self.keys.lock().unwrap();
        keys.insert(name.to_string(), key);
        Ok(())
    }

    pub fn encrypt_with_key(
        &self,
        key_name: &str,
        plaintext: &[u8],
    ) -> Result<EncryptionResult, CryptoError> {
        let keys = self.keys.lock().unwrap();
        let key = keys.get(key_name).ok_or(CryptoError::InvalidKey)?;
        let ctx = EncryptionContext::new(key.clone());
        ctx.encrypt(plaintext)
    }

    pub fn decrypt_with_key(
        &self,
        key_name: &str,
        encrypted: &EncryptionResult,
    ) -> Result<Vec<u8>, CryptoError> {
        let keys = self.keys.lock().unwrap();
        let key = keys.get(key_name).ok_or(CryptoError::InvalidKey)?;
        let ctx = EncryptionContext::new(key.clone());
        ctx.decrypt(encrypted)
    }

    pub fn remove_key(&self, name: &str) -> bool {
        let mut keys = self.keys.lock().unwrap();
        keys.remove(name).is_some()
    }

    pub fn list_keys(&self) -> Vec<String> {
        let keys = self.keys.lock().unwrap();
        keys.keys().cloned().collect()
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

// Helper functions

fn generate_random_bytes(length: usize) -> Result<Vec<u8>, CryptoError> {
    // Simulated random generation
    // In real implementation, use a CSPRNG
    Ok((0..length)
        .map(|i| ((i as u64 * 17 + 42) % 256) as u8)
        .collect())
}

fn simulate_encrypt(plaintext: &[u8], key: &[u8], nonce: &[u8], _aad: &[u8]) -> Vec<u8> {
    plaintext
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()] ^ nonce[i % nonce.len()])
        .collect()
}

fn simulate_decrypt(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    // XOR is symmetric
    simulate_encrypt(ciphertext, key, nonce, &[])
}

fn generate_tag(data: &[u8], key: &[u8], nonce: &[u8], _aad: &[u8]) -> Vec<u8> {
    let mut tag = vec![0u8; 16];
    for (i, &b) in data.iter().enumerate() {
        tag[i % 16] ^= b ^ key[i % key.len()] ^ nonce[i % nonce.len()];
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

fn simulate_pbkdf2(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
    let mut key = vec![0u8; key_len];
    for i in 0..key_len {
        let p = password
            .get(i % password.len().max(1))
            .copied()
            .unwrap_or(0);
        let s = salt.get(i % salt.len().max(1)).copied().unwrap_or(0);
        key[i] = p.wrapping_add(s).wrapping_mul((iterations % 256) as u8);
    }
    key
}

fn simulate_argon2(
    password: &[u8],
    salt: &[u8],
    time_cost: u32,
    _memory_cost: u32,
    key_len: usize,
) -> Vec<u8> {
    simulate_pbkdf2(password, salt, time_cost * 1000, key_len)
}

fn simulate_hash(data: &[u8], output_len: usize) -> Vec<u8> {
    let mut hash = vec![0u8; output_len];
    for (i, &b) in data.iter().enumerate() {
        hash[i % output_len] ^= b.wrapping_mul((i as u8).wrapping_add(1));
    }
    hash
}

fn simulate_hmac(key: &[u8], data: &[u8], output_len: usize) -> Vec<u8> {
    let mut combined = key.to_vec();
    combined.extend_from_slice(data);
    simulate_hash(&combined, output_len)
}

fn base64_encode(data: &[u8]) -> String {
    // Simple base64-like encoding for demo
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn base64_decode(data: &str) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = Vec::new();
    let chars: Vec<char> = data.chars().collect();

    for chunk in chars.chunks(2) {
        if chunk.len() == 2 {
            let hex: String = chunk.iter().collect();
            let byte = u8::from_str_radix(&hex, 16).map_err(|_| CryptoError::InvalidCiphertext)?;
            bytes.push(byte);
        }
    }

    Ok(bytes)
}

fn main() {
    println!("=== Secure Crypto Bindings Demo ===\n");

    // Generate a key
    println!("--- Key Generation ---");
    let key = SecureKey::generate(Algorithm::Aes256Gcm).unwrap();
    println!("Generated {:?} key", key.algorithm());

    // Encrypt data
    println!("\n--- Encryption ---");
    let ctx = EncryptionContext::new(key.clone());
    let plaintext = b"Hello, secure world!";
    let encrypted = ctx.encrypt(plaintext).unwrap();

    println!("Plaintext: {:?}", String::from_utf8_lossy(plaintext));
    println!("Ciphertext length: {} bytes", encrypted.ciphertext.len());
    println!("Nonce: {:02x?}", &encrypted.nonce[..4]);
    println!("Tag: {:02x?}", &encrypted.tag[..4]);

    // Decrypt data
    println!("\n--- Decryption ---");
    let decrypted = ctx.decrypt(&encrypted).unwrap();
    println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted));

    // Encrypt with AAD
    println!("\n--- AEAD with AAD ---");
    let aad = b"additional authenticated data";
    let ctx_with_aad = EncryptionContext::new(key.clone()).with_aad(aad.to_vec());
    let encrypted_aad = ctx_with_aad.encrypt(plaintext).unwrap();
    let decrypted_aad = ctx_with_aad.decrypt(&encrypted_aad).unwrap();
    println!("AAD: {:?}", String::from_utf8_lossy(aad));
    println!(
        "Decrypted with AAD: {:?}",
        String::from_utf8_lossy(&decrypted_aad)
    );

    // Key derivation
    println!("\n--- Key Derivation ---");
    let password = b"my_secure_password";
    let kd = KeyDerivation::new().with_iterations(100000);
    let (derived_key, salt) = kd
        .derive_key_argon2(password, Algorithm::ChaCha20Poly1305)
        .unwrap();
    println!("Derived key from password");
    println!("Salt: {:02x?}", &salt[..8]);

    // Password hashing
    println!("\n--- Password Hashing ---");
    let hasher = PasswordHasher::new();
    let password_hash = hasher.hash(b"user_password").unwrap();
    println!("Password hash: {}", &password_hash[..50]);

    let is_valid = hasher.verify(b"user_password", &password_hash).unwrap();
    println!("Password verification: {}", is_valid);

    // Hashing
    println!("\n--- Hashing ---");
    let data = b"data to hash";
    let sha256 = Hasher::sha256(data);
    let blake3 = Hasher::blake3(data);
    println!("SHA-256: {:02x?}...", &sha256[..8]);
    println!("BLAKE3:  {:02x?}...", &blake3[..8]);

    // HMAC
    println!("\n--- HMAC ---");
    let hmac_key = b"hmac_secret_key";
    let hmac = Hasher::hmac_sha256(hmac_key, data);
    println!("HMAC-SHA256: {:02x?}...", &hmac[..8]);

    // Random generation
    println!("\n--- Secure Random ---");
    let random_bytes = SecureRandom::bytes(16).unwrap();
    println!("Random bytes: {:02x?}", &random_bytes[..8]);

    let token = SecureRandom::token(32).unwrap();
    println!("Random token: {}...", &token[..16]);

    let uuid = SecureRandom::uuid().unwrap();
    println!("Random UUID: {}", uuid);

    // Key store
    println!("\n--- Key Store ---");
    let store = KeyStore::new();
    store
        .generate_key("encryption_key", Algorithm::Aes256Gcm)
        .unwrap();
    store
        .generate_key("signing_key", Algorithm::ChaCha20Poly1305)
        .unwrap();

    println!("Keys in store: {:?}", store.list_keys());

    let encrypted_from_store = store
        .encrypt_with_key("encryption_key", b"secret data")
        .unwrap();
    let decrypted_from_store = store
        .decrypt_with_key("encryption_key", &encrypted_from_store)
        .unwrap();
    println!(
        "Encrypted and decrypted from store: {:?}",
        String::from_utf8_lossy(&decrypted_from_store)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_properties() {
        assert_eq!(Algorithm::Aes256Gcm.key_size(), 32);
        assert_eq!(Algorithm::Aes256Gcm.nonce_size(), 12);
        assert_eq!(Algorithm::XChaCha20Poly1305.nonce_size(), 24);
    }

    #[test]
    fn test_secure_key_generation() {
        let key = SecureKey::generate(Algorithm::Aes256Gcm).unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn test_secure_key_validation() {
        let short_key = vec![0u8; 16];
        assert!(SecureKey::new(short_key, Algorithm::Aes256Gcm).is_err());

        let valid_key = vec![0u8; 32];
        assert!(SecureKey::new(valid_key, Algorithm::Aes256Gcm).is_ok());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = SecureKey::generate(Algorithm::Aes256Gcm).unwrap();
        let ctx = EncryptionContext::new(key);

        let plaintext = b"test message";
        let encrypted = ctx.encrypt(plaintext).unwrap();
        let decrypted = ctx.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let key = SecureKey::generate(Algorithm::Aes256Gcm).unwrap();
        let ctx = EncryptionContext::new(key).with_aad(b"aad".to_vec());

        let plaintext = b"test message";
        let encrypted = ctx.encrypt(plaintext).unwrap();
        let decrypted = ctx.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_encryption_result_serialization() {
        let result = EncryptionResult {
            ciphertext: vec![1, 2, 3],
            nonce: vec![4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            tag: vec![
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ],
        };

        let bytes = result.to_bytes();
        let parsed = EncryptionResult::from_bytes(&bytes, 12, 16).unwrap();

        assert_eq!(result.nonce, parsed.nonce);
        assert_eq!(result.tag, parsed.tag);
        assert_eq!(result.ciphertext, parsed.ciphertext);
    }

    #[test]
    fn test_key_derivation() {
        let kd = KeyDerivation::new().with_iterations(1000);
        let key = kd.derive_key(b"password", Algorithm::Aes256Gcm).unwrap();

        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn test_password_hash_verify() {
        let hasher = PasswordHasher::new();
        let hash = hasher.hash(b"password").unwrap();

        assert!(hasher.verify(b"password", &hash).unwrap());
        assert!(!hasher.verify(b"wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_hasher() {
        let data = b"test data";

        let sha256 = Hasher::sha256(data);
        assert_eq!(sha256.len(), 32);

        let sha512 = Hasher::sha512(data);
        assert_eq!(sha512.len(), 64);

        let blake3 = Hasher::blake3(data);
        assert_eq!(blake3.len(), 32);
    }

    #[test]
    fn test_hmac() {
        let key = b"secret_key";
        let data = b"message";

        let hmac = Hasher::hmac_sha256(key, data);
        assert_eq!(hmac.len(), 32);
    }

    #[test]
    fn test_secure_random() {
        let bytes = SecureRandom::bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);

        let token = SecureRandom::token(16).unwrap();
        assert_eq!(token.len(), 32); // hex encoding doubles length

        let uuid = SecureRandom::uuid().unwrap();
        assert_eq!(uuid.len(), 36); // UUID format with dashes
    }

    #[test]
    fn test_key_store() {
        let store = KeyStore::new();

        store.generate_key("test", Algorithm::Aes256Gcm).unwrap();
        assert!(store.list_keys().contains(&"test".to_string()));

        let encrypted = store.encrypt_with_key("test", b"data").unwrap();
        let decrypted = store.decrypt_with_key("test", &encrypted).unwrap();
        assert_eq!(decrypted, b"data");

        assert!(store.remove_key("test"));
        assert!(store.encrypt_with_key("test", b"data").is_err());
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_compare(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_compare(&[1, 2], &[1, 2, 3]));
    }
}
