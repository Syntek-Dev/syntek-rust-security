//! Neon Node.js Crypto Bindings
//!
//! This example demonstrates creating secure Node.js native modules
//! using Neon for cryptographic operations, with proper error handling,
//! async support, and memory safety.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// Neon Context Simulation
// ============================================================================

// Note: In a real implementation, you would use the actual neon crate.
// This is a simulation for demonstration purposes.

/// Simulated Neon context
pub struct Context {
    _marker: std::marker::PhantomData<()>,
}

/// Simulated JavaScript value
#[derive(Debug, Clone)]
pub enum JsValue {
    Undefined,
    Null,
    Boolean(bool),
    Number(f64),
    String(String),
    Array(Vec<JsValue>),
    Object(HashMap<String, JsValue>),
    Buffer(Vec<u8>),
    Error(String),
}

impl JsValue {
    pub fn as_string(&self) -> Option<&str> {
        match self {
            JsValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_number(&self) -> Option<f64> {
        match self {
            JsValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_buffer(&self) -> Option<&[u8]> {
        match self {
            JsValue::Buffer(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&HashMap<String, JsValue>> {
        match self {
            JsValue::Object(o) => Some(o),
            _ => None,
        }
    }
}

/// Function result type
pub type JsResult<T> = Result<T, JsError>;

/// JavaScript error
#[derive(Debug)]
pub struct JsError {
    pub message: String,
    pub kind: ErrorKind,
}

#[derive(Debug)]
pub enum ErrorKind {
    TypeError,
    RangeError,
    Error,
}

impl JsError {
    pub fn type_error(msg: &str) -> Self {
        Self {
            message: msg.to_string(),
            kind: ErrorKind::TypeError,
        }
    }

    pub fn range_error(msg: &str) -> Self {
        Self {
            message: msg.to_string(),
            kind: ErrorKind::RangeError,
        }
    }

    pub fn error(msg: &str) -> Self {
        Self {
            message: msg.to_string(),
            kind: ErrorKind::Error,
        }
    }
}

// ============================================================================
// Crypto Module
// ============================================================================

/// Main crypto module that would be exported to Node.js
pub struct CryptoModule {
    /// Encryption key store
    key_store: Arc<RwLock<HashMap<String, EncryptionKey>>>,
    /// Statistics
    stats: Arc<RwLock<ModuleStats>>,
}

/// Encryption key
#[derive(Clone)]
pub struct EncryptionKey {
    pub id: String,
    pub algorithm: Algorithm,
    key_material: Vec<u8>,
    pub created_at: SystemTime,
}

impl EncryptionKey {
    pub fn generate(algorithm: Algorithm) -> Self {
        Self {
            id: generate_key_id(),
            algorithm,
            key_material: generate_random_bytes(algorithm.key_size()),
            created_at: SystemTime::now(),
        }
    }

    pub fn from_bytes(algorithm: Algorithm, bytes: &[u8]) -> JsResult<Self> {
        if bytes.len() != algorithm.key_size() {
            return Err(JsError::range_error(&format!(
                "Key must be {} bytes for {:?}",
                algorithm.key_size(),
                algorithm
            )));
        }

        Ok(Self {
            id: generate_key_id(),
            algorithm,
            key_material: bytes.to_vec(),
            created_at: SystemTime::now(),
        })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> JsResult<EncryptedData> {
        let nonce = generate_random_bytes(self.algorithm.nonce_size());

        // Simplified encryption (use ring/sodiumoxide in production)
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for (i, &byte) in plaintext.iter().enumerate() {
            let key_byte = self.key_material[i % self.key_material.len()];
            let nonce_byte = nonce[i % nonce.len()];
            ciphertext.push(byte ^ key_byte ^ nonce_byte);
        }

        // Generate tag
        let tag = self.compute_tag(&ciphertext, &nonce);

        Ok(EncryptedData {
            ciphertext,
            nonce,
            tag,
            algorithm: self.algorithm,
        })
    }

    pub fn decrypt(&self, encrypted: &EncryptedData) -> JsResult<Vec<u8>> {
        // Verify tag
        let expected_tag = self.compute_tag(&encrypted.ciphertext, &encrypted.nonce);
        if !constant_time_compare(&expected_tag, &encrypted.tag) {
            return Err(JsError::error("Authentication failed"));
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

/// Encryption algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl Algorithm {
    pub fn key_size(&self) -> usize {
        match self {
            Algorithm::Aes256Gcm => 32,
            Algorithm::ChaCha20Poly1305 => 32,
            Algorithm::XChaCha20Poly1305 => 32,
        }
    }

    pub fn nonce_size(&self) -> usize {
        match self {
            Algorithm::Aes256Gcm => 12,
            Algorithm::ChaCha20Poly1305 => 12,
            Algorithm::XChaCha20Poly1305 => 24,
        }
    }

    pub fn from_str(s: &str) -> JsResult<Self> {
        match s.to_lowercase().as_str() {
            "aes-256-gcm" | "aes256gcm" => Ok(Algorithm::Aes256Gcm),
            "chacha20-poly1305" | "chacha20poly1305" => Ok(Algorithm::ChaCha20Poly1305),
            "xchacha20-poly1305" | "xchacha20poly1305" => Ok(Algorithm::XChaCha20Poly1305),
            _ => Err(JsError::type_error(&format!("Unknown algorithm: {}", s))),
        }
    }
}

/// Encrypted data
#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub tag: Vec<u8>,
    pub algorithm: Algorithm,
}

impl EncryptedData {
    /// Serialize to buffer for Node.js
    pub fn to_buffer(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        // Algorithm byte
        buffer.push(match self.algorithm {
            Algorithm::Aes256Gcm => 1,
            Algorithm::ChaCha20Poly1305 => 2,
            Algorithm::XChaCha20Poly1305 => 3,
        });

        // Nonce
        buffer.push(self.nonce.len() as u8);
        buffer.extend_from_slice(&self.nonce);

        // Tag
        buffer.push(self.tag.len() as u8);
        buffer.extend_from_slice(&self.tag);

        // Ciphertext
        buffer.extend_from_slice(&self.ciphertext);

        buffer
    }

    /// Deserialize from buffer
    pub fn from_buffer(buffer: &[u8]) -> JsResult<Self> {
        if buffer.len() < 3 {
            return Err(JsError::range_error("Buffer too short"));
        }

        let mut offset = 0;

        // Algorithm
        let algorithm = match buffer[offset] {
            1 => Algorithm::Aes256Gcm,
            2 => Algorithm::ChaCha20Poly1305,
            3 => Algorithm::XChaCha20Poly1305,
            _ => return Err(JsError::type_error("Unknown algorithm")),
        };
        offset += 1;

        // Nonce
        let nonce_len = buffer[offset] as usize;
        offset += 1;
        if buffer.len() < offset + nonce_len {
            return Err(JsError::range_error("Buffer too short for nonce"));
        }
        let nonce = buffer[offset..offset + nonce_len].to_vec();
        offset += nonce_len;

        // Tag
        let tag_len = buffer[offset] as usize;
        offset += 1;
        if buffer.len() < offset + tag_len {
            return Err(JsError::range_error("Buffer too short for tag"));
        }
        let tag = buffer[offset..offset + tag_len].to_vec();
        offset += tag_len;

        // Ciphertext
        let ciphertext = buffer[offset..].to_vec();

        Ok(Self {
            ciphertext,
            nonce,
            tag,
            algorithm,
        })
    }
}

/// Module statistics
#[derive(Debug, Default)]
pub struct ModuleStats {
    pub keys_generated: u64,
    pub encryptions: u64,
    pub decryptions: u64,
    pub hashes: u64,
    pub signatures: u64,
    pub verifications: u64,
}

impl CryptoModule {
    pub fn new() -> Self {
        Self {
            key_store: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ModuleStats::default())),
        }
    }

    /// Generate a new encryption key
    /// JS: generateKey(algorithm: string): KeyHandle
    pub fn generate_key(&self, algorithm: &str) -> JsResult<JsValue> {
        let algo = Algorithm::from_str(algorithm)?;
        let key = EncryptionKey::generate(algo);
        let key_id = key.id.clone();

        if let Ok(mut store) = self.key_store.write() {
            store.insert(key_id.clone(), key);
        }

        if let Ok(mut stats) = self.stats.write() {
            stats.keys_generated += 1;
        }

        let mut result = HashMap::new();
        result.insert("keyId".to_string(), JsValue::String(key_id));
        result.insert(
            "algorithm".to_string(),
            JsValue::String(algorithm.to_string()),
        );

        Ok(JsValue::Object(result))
    }

    /// Import a key from bytes
    /// JS: importKey(algorithm: string, keyData: Buffer): KeyHandle
    pub fn import_key(&self, algorithm: &str, key_data: &[u8]) -> JsResult<JsValue> {
        let algo = Algorithm::from_str(algorithm)?;
        let key = EncryptionKey::from_bytes(algo, key_data)?;
        let key_id = key.id.clone();

        if let Ok(mut store) = self.key_store.write() {
            store.insert(key_id.clone(), key);
        }

        let mut result = HashMap::new();
        result.insert("keyId".to_string(), JsValue::String(key_id));
        result.insert(
            "algorithm".to_string(),
            JsValue::String(algorithm.to_string()),
        );

        Ok(JsValue::Object(result))
    }

    /// Encrypt data
    /// JS: encrypt(keyId: string, plaintext: Buffer): Buffer
    pub fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> JsResult<JsValue> {
        let key = self.get_key(key_id)?;
        let encrypted = key.encrypt(plaintext)?;

        if let Ok(mut stats) = self.stats.write() {
            stats.encryptions += 1;
        }

        Ok(JsValue::Buffer(encrypted.to_buffer()))
    }

    /// Decrypt data
    /// JS: decrypt(keyId: string, ciphertext: Buffer): Buffer
    pub fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> JsResult<JsValue> {
        let key = self.get_key(key_id)?;
        let encrypted = EncryptedData::from_buffer(ciphertext)?;
        let plaintext = key.decrypt(&encrypted)?;

        if let Ok(mut stats) = self.stats.write() {
            stats.decryptions += 1;
        }

        Ok(JsValue::Buffer(plaintext))
    }

    /// Encrypt with additional authenticated data
    /// JS: encryptAead(keyId: string, plaintext: Buffer, aad: Buffer): Buffer
    pub fn encrypt_aead(&self, key_id: &str, plaintext: &[u8], _aad: &[u8]) -> JsResult<JsValue> {
        // In a real implementation, AAD would be included in the tag computation
        self.encrypt(key_id, plaintext)
    }

    /// Compute hash
    /// JS: hash(algorithm: string, data: Buffer): Buffer
    pub fn hash(&self, algorithm: &str, data: &[u8]) -> JsResult<JsValue> {
        let hash = match algorithm.to_lowercase().as_str() {
            "sha256" => compute_sha256(data),
            "sha384" => compute_sha384(data),
            "sha512" => compute_sha512(data),
            "blake2b" => compute_blake2b(data),
            _ => {
                return Err(JsError::type_error(&format!(
                    "Unknown hash algorithm: {}",
                    algorithm
                )))
            }
        };

        if let Ok(mut stats) = self.stats.write() {
            stats.hashes += 1;
        }

        Ok(JsValue::Buffer(hash))
    }

    /// Compute HMAC
    /// JS: hmac(algorithm: string, key: Buffer, data: Buffer): Buffer
    pub fn hmac(&self, algorithm: &str, key: &[u8], data: &[u8]) -> JsResult<JsValue> {
        let hmac = compute_hmac(algorithm, key, data)?;
        Ok(JsValue::Buffer(hmac))
    }

    /// Derive key using PBKDF2
    /// JS: pbkdf2(password: Buffer, salt: Buffer, iterations: number, keyLength: number): Buffer
    pub fn pbkdf2(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        key_length: usize,
    ) -> JsResult<JsValue> {
        if iterations < 10000 {
            return Err(JsError::range_error("Iterations must be at least 10000"));
        }

        let derived = derive_pbkdf2(password, salt, iterations, key_length);
        Ok(JsValue::Buffer(derived))
    }

    /// Derive key using Argon2
    /// JS: argon2(password: Buffer, salt: Buffer, options?: Argon2Options): Buffer
    pub fn argon2(
        &self,
        password: &[u8],
        salt: &[u8],
        memory_cost: u32,
        time_cost: u32,
        parallelism: u32,
    ) -> JsResult<JsValue> {
        if salt.len() < 16 {
            return Err(JsError::range_error("Salt must be at least 16 bytes"));
        }

        let derived = derive_argon2(password, salt, memory_cost, time_cost, parallelism);
        Ok(JsValue::Buffer(derived))
    }

    /// Generate random bytes
    /// JS: randomBytes(length: number): Buffer
    pub fn random_bytes(&self, length: usize) -> JsResult<JsValue> {
        if length > 1024 * 1024 {
            return Err(JsError::range_error("Maximum length is 1MB"));
        }

        let bytes = generate_random_bytes(length);
        Ok(JsValue::Buffer(bytes))
    }

    /// Get module statistics
    /// JS: getStats(): Stats
    pub fn get_stats(&self) -> JsValue {
        let stats = self.stats.read().map(|s| s.clone()).unwrap_or_default();

        let mut result = HashMap::new();
        result.insert(
            "keysGenerated".to_string(),
            JsValue::Number(stats.keys_generated as f64),
        );
        result.insert(
            "encryptions".to_string(),
            JsValue::Number(stats.encryptions as f64),
        );
        result.insert(
            "decryptions".to_string(),
            JsValue::Number(stats.decryptions as f64),
        );
        result.insert("hashes".to_string(), JsValue::Number(stats.hashes as f64));

        JsValue::Object(result)
    }

    fn get_key(&self, key_id: &str) -> JsResult<EncryptionKey> {
        self.key_store
            .read()
            .map_err(|_| JsError::error("Failed to access key store"))?
            .get(key_id)
            .cloned()
            .ok_or_else(|| JsError::error(&format!("Key not found: {}", key_id)))
    }
}

impl Default for CryptoModule {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Password Hashing
// ============================================================================

/// Password hasher for secure password storage
pub struct PasswordHasher {
    algorithm: PasswordAlgorithm,
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
}

/// Password hashing algorithm
#[derive(Debug, Clone, Copy)]
pub enum PasswordAlgorithm {
    Argon2id,
    Argon2i,
    Argon2d,
    Bcrypt,
    Scrypt,
}

impl PasswordHasher {
    pub fn new(algorithm: PasswordAlgorithm) -> Self {
        let (memory, time, parallel) = match algorithm {
            PasswordAlgorithm::Argon2id
            | PasswordAlgorithm::Argon2i
            | PasswordAlgorithm::Argon2d => {
                (65536, 3, 4) // 64MB, 3 iterations, 4 lanes
            }
            PasswordAlgorithm::Bcrypt => (0, 12, 0), // cost factor 12
            PasswordAlgorithm::Scrypt => (32768, 8, 1), // N=32768, r=8, p=1
        };

        Self {
            algorithm,
            memory_cost: memory,
            time_cost: time,
            parallelism: parallel,
        }
    }

    /// Hash a password
    pub fn hash(&self, password: &[u8]) -> JsResult<JsValue> {
        let salt = generate_random_bytes(16);
        let hash = derive_argon2(
            password,
            &salt,
            self.memory_cost,
            self.time_cost,
            self.parallelism,
        );

        // Encode as PHC string format
        let encoded = format!(
            "$argon2id$v=19$m={},t={},p={}${}${}",
            self.memory_cost,
            self.time_cost,
            self.parallelism,
            base64_encode(&salt),
            base64_encode(&hash),
        );

        Ok(JsValue::String(encoded))
    }

    /// Verify a password against a hash
    pub fn verify(&self, password: &[u8], hash_string: &str) -> JsResult<JsValue> {
        // Parse PHC string (simplified)
        let parts: Vec<&str> = hash_string.split('$').collect();
        if parts.len() < 6 {
            return Err(JsError::error("Invalid hash format"));
        }

        let salt = base64_decode(parts[4]).map_err(|_| JsError::error("Invalid salt"))?;
        let stored_hash = base64_decode(parts[5]).map_err(|_| JsError::error("Invalid hash"))?;

        let computed = derive_argon2(
            password,
            &salt,
            self.memory_cost,
            self.time_cost,
            self.parallelism,
        );

        let matches = constant_time_compare(&computed, &stored_hash);
        Ok(JsValue::Boolean(matches))
    }
}

// ============================================================================
// Digital Signatures
// ============================================================================

/// Signing key pair
pub struct SigningKeyPair {
    pub public_key: Vec<u8>,
    private_key: Vec<u8>,
    pub algorithm: SigningAlgorithm,
}

/// Signing algorithm
#[derive(Debug, Clone, Copy)]
pub enum SigningAlgorithm {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    Rsa2048,
}

impl SigningKeyPair {
    pub fn generate(algorithm: SigningAlgorithm) -> Self {
        let (public_len, private_len) = match algorithm {
            SigningAlgorithm::Ed25519 => (32, 64),
            SigningAlgorithm::EcdsaP256 => (65, 32),
            SigningAlgorithm::EcdsaP384 => (97, 48),
            SigningAlgorithm::Rsa2048 => (294, 1190),
        };

        Self {
            public_key: generate_random_bytes(public_len),
            private_key: generate_random_bytes(private_len),
            algorithm,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        // Simplified signature (use actual crypto in production)
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};

        let state = RandomState::new();
        let mut hasher = state.build_hasher();

        for &b in &self.private_key {
            hasher.write_u8(b);
        }
        for &b in message {
            hasher.write_u8(b);
        }

        let mut sig = hasher.finish().to_le_bytes().to_vec();
        sig.extend_from_slice(&hasher.finish().to_be_bytes());
        sig
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let expected = self.sign(message);
        constant_time_compare(&expected, signature)
    }

    pub fn to_js_value(&self) -> JsValue {
        let mut result = HashMap::new();
        result.insert(
            "publicKey".to_string(),
            JsValue::Buffer(self.public_key.clone()),
        );
        result.insert(
            "algorithm".to_string(),
            JsValue::String(format!("{:?}", self.algorithm)),
        );
        JsValue::Object(result)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn generate_key_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("key-{:x}", timestamp)
}

fn generate_random_bytes(length: usize) -> Vec<u8> {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let state = RandomState::new();
    let mut hasher = state.build_hasher();

    let mut bytes = Vec::with_capacity(length);
    for i in 0..length {
        hasher.write_usize(i);
        hasher.write_u128(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        );
        bytes.push((hasher.finish() & 0xFF) as u8);
    }

    bytes
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

fn compute_sha256(data: &[u8]) -> Vec<u8> {
    // Simplified hash (use ring/sha2 in production)
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let state = RandomState::new();
    let mut hasher = state.build_hasher();

    for &b in data {
        hasher.write_u8(b);
    }

    let mut hash = Vec::with_capacity(32);
    for i in 0..4 {
        hash.extend_from_slice(&(hasher.finish().wrapping_add(i)).to_le_bytes());
    }
    hash
}

fn compute_sha384(data: &[u8]) -> Vec<u8> {
    let mut hash = compute_sha256(data);
    hash.extend_from_slice(&compute_sha256(&hash)[..16]);
    hash
}

fn compute_sha512(data: &[u8]) -> Vec<u8> {
    let mut hash = compute_sha256(data);
    hash.extend_from_slice(&compute_sha256(&hash));
    hash
}

fn compute_blake2b(data: &[u8]) -> Vec<u8> {
    compute_sha512(data) // Placeholder
}

fn compute_hmac(algorithm: &str, key: &[u8], data: &[u8]) -> JsResult<Vec<u8>> {
    // Simplified HMAC
    let block_size = 64;
    let mut padded_key = vec![0u8; block_size];

    if key.len() > block_size {
        let hashed = compute_sha256(key);
        padded_key[..hashed.len()].copy_from_slice(&hashed);
    } else {
        padded_key[..key.len()].copy_from_slice(key);
    }

    let mut inner = Vec::with_capacity(block_size + data.len());
    for &b in &padded_key {
        inner.push(b ^ 0x36);
    }
    inner.extend_from_slice(data);

    let inner_hash = compute_sha256(&inner);

    let mut outer = Vec::with_capacity(block_size + 32);
    for &b in &padded_key {
        outer.push(b ^ 0x5c);
    }
    outer.extend_from_slice(&inner_hash);

    Ok(compute_sha256(&outer))
}

fn derive_pbkdf2(password: &[u8], salt: &[u8], iterations: u32, key_length: usize) -> Vec<u8> {
    // Simplified PBKDF2
    let mut derived = Vec::with_capacity(key_length);
    let mut block_num = 1u32;

    while derived.len() < key_length {
        let mut block_salt = salt.to_vec();
        block_salt.extend_from_slice(&block_num.to_be_bytes());

        let mut u = compute_hmac("sha256", password, &block_salt).unwrap();
        let mut result = u.clone();

        for _ in 1..iterations {
            u = compute_hmac("sha256", password, &u).unwrap();
            for (r, u_byte) in result.iter_mut().zip(u.iter()) {
                *r ^= u_byte;
            }
        }

        derived.extend_from_slice(&result);
        block_num += 1;
    }

    derived.truncate(key_length);
    derived
}

fn derive_argon2(
    password: &[u8],
    salt: &[u8],
    _memory_cost: u32,
    _time_cost: u32,
    _parallelism: u32,
) -> Vec<u8> {
    // Simplified Argon2 (use argon2 crate in production)
    let mut input = password.to_vec();
    input.extend_from_slice(salt);
    compute_sha512(&input)
}

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
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[(n & 0x3F) as usize] as char);
        }
    }
    result
}

fn base64_decode(data: &str) -> Result<Vec<u8>, ()> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = Vec::new();
    let chars: Vec<u8> = data.bytes().collect();

    for chunk in chars.chunks(4) {
        let mut indices = [0u8; 4];
        for (i, &c) in chunk.iter().enumerate() {
            indices[i] = ALPHABET.iter().position(|&x| x == c).ok_or(())? as u8;
        }

        let n = ((indices[0] as u32) << 18)
            | ((indices[1] as u32) << 12)
            | ((indices.get(2).copied().unwrap_or(0) as u32) << 6)
            | (indices.get(3).copied().unwrap_or(0) as u32);

        result.push((n >> 16 & 0xFF) as u8);
        if chunk.len() > 2 {
            result.push((n >> 8 & 0xFF) as u8);
        }
        if chunk.len() > 3 {
            result.push((n & 0xFF) as u8);
        }
    }

    Ok(result)
}

// ============================================================================
// Module Registration (Neon Pattern)
// ============================================================================

/// Register all exports for the Node.js module
pub fn register_module() -> HashMap<String, String> {
    let mut exports = HashMap::new();

    exports.insert(
        "generateKey".to_string(),
        "Generate encryption key".to_string(),
    );
    exports.insert(
        "importKey".to_string(),
        "Import key from buffer".to_string(),
    );
    exports.insert("encrypt".to_string(), "Encrypt data".to_string());
    exports.insert("decrypt".to_string(), "Decrypt data".to_string());
    exports.insert("hash".to_string(), "Compute hash".to_string());
    exports.insert("hmac".to_string(), "Compute HMAC".to_string());
    exports.insert("pbkdf2".to_string(), "PBKDF2 key derivation".to_string());
    exports.insert("argon2".to_string(), "Argon2 key derivation".to_string());
    exports.insert(
        "randomBytes".to_string(),
        "Generate random bytes".to_string(),
    );
    exports.insert("hashPassword".to_string(), "Hash password".to_string());
    exports.insert("verifyPassword".to_string(), "Verify password".to_string());
    exports.insert(
        "generateKeyPair".to_string(),
        "Generate signing key pair".to_string(),
    );
    exports.insert("sign".to_string(), "Sign message".to_string());
    exports.insert("verify".to_string(), "Verify signature".to_string());

    exports
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== Neon Node.js Crypto Bindings ===\n");

    // Example 1: Initialize module
    println!("1. Module Initialization:");
    let crypto = CryptoModule::new();
    println!("   CryptoModule initialized");

    // Example 2: Generate key
    println!("\n2. Key Generation:");
    let key_handle = crypto.generate_key("aes-256-gcm").unwrap();
    if let JsValue::Object(obj) = &key_handle {
        println!("   Key ID: {:?}", obj.get("keyId"));
        println!("   Algorithm: {:?}", obj.get("algorithm"));
    }

    // Example 3: Encrypt/Decrypt
    println!("\n3. Encryption/Decryption:");
    let plaintext = b"Hello from Rust to Node.js!";
    println!("   Plaintext: {:?}", String::from_utf8_lossy(plaintext));

    if let JsValue::Object(obj) = &key_handle {
        if let Some(JsValue::String(key_id)) = obj.get("keyId") {
            let encrypted = crypto.encrypt(key_id, plaintext).unwrap();
            if let JsValue::Buffer(buf) = &encrypted {
                println!("   Encrypted length: {} bytes", buf.len());

                let decrypted = crypto.decrypt(key_id, buf).unwrap();
                if let JsValue::Buffer(dec) = &decrypted {
                    println!("   Decrypted: {:?}", String::from_utf8_lossy(dec));
                }
            }
        }
    }

    // Example 4: Hashing
    println!("\n4. Hashing:");
    let data = b"data to hash";

    for algo in &["sha256", "sha384", "sha512"] {
        let hash = crypto.hash(algo, data).unwrap();
        if let JsValue::Buffer(h) = hash {
            println!("   {}: {} bytes", algo, h.len());
        }
    }

    // Example 5: HMAC
    println!("\n5. HMAC:");
    let key = b"secret key";
    let hmac = crypto.hmac("sha256", key, b"message").unwrap();
    if let JsValue::Buffer(h) = hmac {
        println!("   HMAC-SHA256: {} bytes", h.len());
    }

    // Example 6: Key derivation
    println!("\n6. Key Derivation:");
    let password = b"password123";
    let salt = b"random_salt_value";

    let derived = crypto.pbkdf2(password, salt, 100000, 32).unwrap();
    if let JsValue::Buffer(d) = derived {
        println!("   PBKDF2 derived key: {} bytes", d.len());
    }

    let argon = crypto.argon2(password, salt, 65536, 3, 4).unwrap();
    if let JsValue::Buffer(a) = argon {
        println!("   Argon2 derived key: {} bytes", a.len());
    }

    // Example 7: Random bytes
    println!("\n7. Random Bytes:");
    let random = crypto.random_bytes(32).unwrap();
    if let JsValue::Buffer(r) = random {
        println!("   Generated {} random bytes", r.len());
    }

    // Example 8: Password hashing
    println!("\n8. Password Hashing:");
    let hasher = PasswordHasher::new(PasswordAlgorithm::Argon2id);
    let hash_result = hasher.hash(b"my_password").unwrap();
    if let JsValue::String(h) = &hash_result {
        println!("   Password hash: {}...", &h[..50]);

        let verify_result = hasher.verify(b"my_password", h).unwrap();
        if let JsValue::Boolean(v) = verify_result {
            println!("   Verification: {}", v);
        }
    }

    // Example 9: Digital signatures
    println!("\n9. Digital Signatures:");
    let keypair = SigningKeyPair::generate(SigningAlgorithm::Ed25519);
    println!("   Generated Ed25519 key pair");
    println!("   Public key: {} bytes", keypair.public_key.len());

    let message = b"message to sign";
    let signature = keypair.sign(message);
    println!("   Signature: {} bytes", signature.len());

    let valid = keypair.verify(message, &signature);
    println!("   Verification: {}", valid);

    // Example 10: Statistics
    println!("\n10. Module Statistics:");
    let stats = crypto.get_stats();
    if let JsValue::Object(s) = stats {
        for (key, value) in s {
            println!("   {}: {:?}", key, value);
        }
    }

    // Example 11: Module exports
    println!("\n11. Module Exports:");
    let exports = register_module();
    for (name, desc) in exports.iter().take(5) {
        println!("   {} - {}", name, desc);
    }
    println!("   ... and {} more", exports.len() - 5);

    println!("\n=== Neon Bindings Complete ===");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_from_str() {
        assert!(matches!(
            Algorithm::from_str("aes-256-gcm"),
            Ok(Algorithm::Aes256Gcm)
        ));
        assert!(matches!(
            Algorithm::from_str("chacha20-poly1305"),
            Ok(Algorithm::ChaCha20Poly1305)
        ));
        assert!(Algorithm::from_str("unknown").is_err());
    }

    #[test]
    fn test_key_generation() {
        let key = EncryptionKey::generate(Algorithm::Aes256Gcm);
        assert!(!key.id.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = EncryptionKey::generate(Algorithm::Aes256Gcm);
        let plaintext = b"test data";

        let encrypted = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let key = EncryptionKey::generate(Algorithm::Aes256Gcm);
        let encrypted = key.encrypt(b"test").unwrap();

        let buffer = encrypted.to_buffer();
        let restored = EncryptedData::from_buffer(&buffer).unwrap();

        assert_eq!(encrypted.ciphertext, restored.ciphertext);
        assert_eq!(encrypted.nonce, restored.nonce);
    }

    #[test]
    fn test_crypto_module() {
        let crypto = CryptoModule::new();
        let key = crypto.generate_key("aes-256-gcm").unwrap();

        matches!(key, JsValue::Object(_));
    }

    #[test]
    fn test_hash() {
        let crypto = CryptoModule::new();
        let hash = crypto.hash("sha256", b"test").unwrap();

        if let JsValue::Buffer(h) = hash {
            assert_eq!(h.len(), 32);
        } else {
            panic!("Expected buffer");
        }
    }

    #[test]
    fn test_hmac() {
        let crypto = CryptoModule::new();
        let hmac = crypto.hmac("sha256", b"key", b"data").unwrap();

        matches!(hmac, JsValue::Buffer(_));
    }

    #[test]
    fn test_pbkdf2() {
        let crypto = CryptoModule::new();
        let result = crypto.pbkdf2(b"password", b"salt", 10000, 32).unwrap();

        if let JsValue::Buffer(d) = result {
            assert_eq!(d.len(), 32);
        }
    }

    #[test]
    fn test_pbkdf2_low_iterations() {
        let crypto = CryptoModule::new();
        let result = crypto.pbkdf2(b"password", b"salt", 100, 32);

        assert!(result.is_err());
    }

    #[test]
    fn test_random_bytes() {
        let crypto = CryptoModule::new();
        let result = crypto.random_bytes(64).unwrap();

        if let JsValue::Buffer(r) = result {
            assert_eq!(r.len(), 64);
        }
    }

    #[test]
    fn test_password_hasher() {
        let hasher = PasswordHasher::new(PasswordAlgorithm::Argon2id);
        let hash = hasher.hash(b"password").unwrap();

        if let JsValue::String(h) = &hash {
            assert!(h.starts_with("$argon2id$"));

            let verify = hasher.verify(b"password", h).unwrap();
            matches!(verify, JsValue::Boolean(true));
        }
    }

    #[test]
    fn test_signing_keypair() {
        let kp = SigningKeyPair::generate(SigningAlgorithm::Ed25519);
        let message = b"test message";

        let sig = kp.sign(message);
        assert!(kp.verify(message, &sig));
        assert!(!kp.verify(b"other", &sig));
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare(b"abc", b"abc"));
        assert!(!constant_time_compare(b"abc", b"abd"));
        assert!(!constant_time_compare(b"abc", b"ab"));
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"hello world";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_js_value_accessors() {
        let string = JsValue::String("test".to_string());
        assert_eq!(string.as_string(), Some("test"));

        let number = JsValue::Number(42.0);
        assert_eq!(number.as_number(), Some(42.0));

        let buffer = JsValue::Buffer(vec![1, 2, 3]);
        assert_eq!(buffer.as_buffer(), Some([1u8, 2, 3].as_slice()));
    }

    #[test]
    fn test_module_exports() {
        let exports = register_module();
        assert!(exports.contains_key("encrypt"));
        assert!(exports.contains_key("decrypt"));
        assert!(exports.contains_key("hash"));
    }
}
