//! WebAssembly Cryptography Module
//!
//! Secure cryptographic operations for web applications via WASM.

use std::collections::HashMap;

/// Error type for WASM crypto operations
#[derive(Debug, Clone)]
pub enum WasmCryptoError {
    InvalidKey(String),
    InvalidInput(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    HashingFailed(String),
    SignatureFailed(String),
    VerificationFailed(String),
    KeyGenerationFailed(String),
}

impl std::fmt::Display for WasmCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            Self::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            Self::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            Self::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            Self::HashingFailed(msg) => write!(f, "Hashing failed: {}", msg),
            Self::SignatureFailed(msg) => write!(f, "Signature failed: {}", msg),
            Self::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            Self::KeyGenerationFailed(msg) => write!(f, "Key generation failed: {}", msg),
        }
    }
}

impl std::error::Error for WasmCryptoError {}

/// Symmetric encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymmetricAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl SymmetricAlgorithm {
    pub fn key_length(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    pub fn nonce_length(&self) -> usize {
        12 // All supported algorithms use 12-byte nonces
    }

    pub fn tag_length(&self) -> usize {
        16 // All supported algorithms use 16-byte tags
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Aes128Gcm => "AES-128-GCM",
            Self::Aes256Gcm => "AES-256-GCM",
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        }
    }
}

/// Hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Blake2b256,
    Blake2b512,
    Blake3,
}

impl HashAlgorithm {
    pub fn output_length(&self) -> usize {
        match self {
            Self::Sha256 | Self::Blake2b256 | Self::Blake3 => 32,
            Self::Sha384 => 48,
            Self::Sha512 | Self::Blake2b512 => 64,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Blake2b256 => "BLAKE2b-256",
            Self::Blake2b512 => "BLAKE2b-512",
            Self::Blake3 => "BLAKE3",
        }
    }
}

/// Signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
}

impl SignatureAlgorithm {
    pub fn public_key_length(&self) -> usize {
        match self {
            Self::Ed25519 => 32,
            Self::EcdsaP256 => 64,
            Self::EcdsaP384 => 96,
        }
    }

    pub fn private_key_length(&self) -> usize {
        match self {
            Self::Ed25519 => 64, // includes public key
            Self::EcdsaP256 => 32,
            Self::EcdsaP384 => 48,
        }
    }

    pub fn signature_length(&self) -> usize {
        match self {
            Self::Ed25519 => 64,
            Self::EcdsaP256 => 64,
            Self::EcdsaP384 => 96,
        }
    }
}

/// Encrypted data container
#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub algorithm: SymmetricAlgorithm,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

impl EncryptedData {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Algorithm identifier (1 byte)
        result.push(match self.algorithm {
            SymmetricAlgorithm::Aes128Gcm => 1,
            SymmetricAlgorithm::Aes256Gcm => 2,
            SymmetricAlgorithm::ChaCha20Poly1305 => 3,
        });

        // Nonce
        result.extend_from_slice(&self.nonce);

        // Tag
        result.extend_from_slice(&self.tag);

        // Ciphertext
        result.extend_from_slice(&self.ciphertext);

        result
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, WasmCryptoError> {
        if data.is_empty() {
            return Err(WasmCryptoError::InvalidInput("Empty data".to_string()));
        }

        let algorithm = match data[0] {
            1 => SymmetricAlgorithm::Aes128Gcm,
            2 => SymmetricAlgorithm::Aes256Gcm,
            3 => SymmetricAlgorithm::ChaCha20Poly1305,
            _ => {
                return Err(WasmCryptoError::InvalidInput(
                    "Unknown algorithm".to_string(),
                ))
            }
        };

        let nonce_len = algorithm.nonce_length();
        let tag_len = algorithm.tag_length();
        let min_len = 1 + nonce_len + tag_len;

        if data.len() < min_len {
            return Err(WasmCryptoError::InvalidInput("Data too short".to_string()));
        }

        let nonce = data[1..1 + nonce_len].to_vec();
        let tag = data[1 + nonce_len..1 + nonce_len + tag_len].to_vec();
        let ciphertext = data[1 + nonce_len + tag_len..].to_vec();

        Ok(Self {
            algorithm,
            nonce,
            ciphertext,
            tag,
        })
    }

    /// Encode as base64
    pub fn to_base64(&self) -> String {
        base64_encode(&self.to_bytes())
    }

    /// Decode from base64
    pub fn from_base64(s: &str) -> Result<Self, WasmCryptoError> {
        let data = base64_decode(s).map_err(|e| WasmCryptoError::InvalidInput(e.to_string()))?;
        Self::from_bytes(&data)
    }
}

/// Key pair for asymmetric operations
#[derive(Clone)]
pub struct KeyPair {
    pub algorithm: SignatureAlgorithm,
    pub public_key: Vec<u8>,
    private_key: Vec<u8>,
}

impl KeyPair {
    pub fn generate(algorithm: SignatureAlgorithm) -> Result<Self, WasmCryptoError> {
        // Simulated key generation
        let private_key = generate_random_bytes(algorithm.private_key_length());
        let public_key = derive_public_key(&private_key, algorithm);

        Ok(Self {
            algorithm,
            public_key,
            private_key,
        })
    }

    pub fn from_private_key(
        private_key: Vec<u8>,
        algorithm: SignatureAlgorithm,
    ) -> Result<Self, WasmCryptoError> {
        if private_key.len() != algorithm.private_key_length() {
            return Err(WasmCryptoError::InvalidKey(format!(
                "Expected {} bytes, got {}",
                algorithm.private_key_length(),
                private_key.len()
            )));
        }

        let public_key = derive_public_key(&private_key, algorithm);

        Ok(Self {
            algorithm,
            public_key,
            private_key,
        })
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, WasmCryptoError> {
        // Simulated signing
        let mut signature = vec![0u8; self.algorithm.signature_length()];
        for (i, byte) in message.iter().enumerate() {
            let pk_byte = self.private_key[i % self.private_key.len()];
            signature[i % signature.len()] ^= byte ^ pk_byte;
        }
        Ok(signature)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, WasmCryptoError> {
        if signature.len() != self.algorithm.signature_length() {
            return Err(WasmCryptoError::VerificationFailed(
                "Invalid signature length".to_string(),
            ));
        }

        // Simulated verification
        let expected = self.sign(message)?;
        Ok(constant_time_eq(&expected, signature))
    }

    pub fn export_public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    pub fn export_private_key(&self) -> Vec<u8> {
        self.private_key.clone()
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("algorithm", &self.algorithm)
            .field("public_key", &hex_encode(&self.public_key))
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// WASM-compatible crypto context
pub struct WasmCrypto {
    symmetric_keys: HashMap<String, Vec<u8>>,
    key_pairs: HashMap<String, KeyPair>,
}

impl WasmCrypto {
    pub fn new() -> Self {
        Self {
            symmetric_keys: HashMap::new(),
            key_pairs: HashMap::new(),
        }
    }

    // Key management

    pub fn generate_symmetric_key(
        &mut self,
        name: &str,
        algorithm: SymmetricAlgorithm,
    ) -> Result<(), WasmCryptoError> {
        let key = generate_random_bytes(algorithm.key_length());
        self.symmetric_keys.insert(name.to_string(), key);
        Ok(())
    }

    pub fn import_symmetric_key(
        &mut self,
        name: &str,
        key: Vec<u8>,
        algorithm: SymmetricAlgorithm,
    ) -> Result<(), WasmCryptoError> {
        if key.len() != algorithm.key_length() {
            return Err(WasmCryptoError::InvalidKey(format!(
                "Expected {} bytes, got {}",
                algorithm.key_length(),
                key.len()
            )));
        }
        self.symmetric_keys.insert(name.to_string(), key);
        Ok(())
    }

    pub fn generate_key_pair(
        &mut self,
        name: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<(), WasmCryptoError> {
        let key_pair = KeyPair::generate(algorithm)?;
        self.key_pairs.insert(name.to_string(), key_pair);
        Ok(())
    }

    pub fn import_key_pair(
        &mut self,
        name: &str,
        private_key: Vec<u8>,
        algorithm: SignatureAlgorithm,
    ) -> Result<(), WasmCryptoError> {
        let key_pair = KeyPair::from_private_key(private_key, algorithm)?;
        self.key_pairs.insert(name.to_string(), key_pair);
        Ok(())
    }

    // Symmetric encryption

    pub fn encrypt(
        &self,
        key_name: &str,
        plaintext: &[u8],
        algorithm: SymmetricAlgorithm,
        aad: Option<&[u8]>,
    ) -> Result<EncryptedData, WasmCryptoError> {
        let key = self
            .symmetric_keys
            .get(key_name)
            .ok_or_else(|| WasmCryptoError::InvalidKey(format!("Key '{}' not found", key_name)))?;

        let nonce = generate_random_bytes(algorithm.nonce_length());
        let (ciphertext, tag) = encrypt_aead(key, &nonce, plaintext, aad.unwrap_or(&[]))?;

        Ok(EncryptedData {
            algorithm,
            nonce,
            ciphertext,
            tag,
        })
    }

    pub fn decrypt(
        &self,
        key_name: &str,
        encrypted: &EncryptedData,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, WasmCryptoError> {
        let key = self
            .symmetric_keys
            .get(key_name)
            .ok_or_else(|| WasmCryptoError::InvalidKey(format!("Key '{}' not found", key_name)))?;

        decrypt_aead(
            key,
            &encrypted.nonce,
            &encrypted.ciphertext,
            &encrypted.tag,
            aad.unwrap_or(&[]),
        )
    }

    // Signatures

    pub fn sign(&self, key_name: &str, message: &[u8]) -> Result<Vec<u8>, WasmCryptoError> {
        let key_pair = self.key_pairs.get(key_name).ok_or_else(|| {
            WasmCryptoError::InvalidKey(format!("Key pair '{}' not found", key_name))
        })?;

        key_pair.sign(message)
    }

    pub fn verify(
        &self,
        key_name: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, WasmCryptoError> {
        let key_pair = self.key_pairs.get(key_name).ok_or_else(|| {
            WasmCryptoError::InvalidKey(format!("Key pair '{}' not found", key_name))
        })?;

        key_pair.verify(message, signature)
    }

    // Hashing

    pub fn hash(data: &[u8], algorithm: HashAlgorithm) -> Vec<u8> {
        compute_hash(data, algorithm)
    }

    pub fn hmac(key: &[u8], data: &[u8], algorithm: HashAlgorithm) -> Vec<u8> {
        compute_hmac(key, data, algorithm)
    }

    // Utilities

    pub fn random_bytes(length: usize) -> Vec<u8> {
        generate_random_bytes(length)
    }

    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        constant_time_eq(a, b)
    }
}

impl Default for WasmCrypto {
    fn default() -> Self {
        Self::new()
    }
}

// Helper functions

fn generate_random_bytes(length: usize) -> Vec<u8> {
    // Simulated CSPRNG - in real WASM, use getrandom or Web Crypto API
    (0..length)
        .map(|i| ((i as u64).wrapping_mul(6364136223846793005).wrapping_add(1) % 256) as u8)
        .collect()
}

fn derive_public_key(private_key: &[u8], algorithm: SignatureAlgorithm) -> Vec<u8> {
    let mut public_key = vec![0u8; algorithm.public_key_length()];
    for (i, &byte) in private_key.iter().enumerate() {
        public_key[i % public_key.len()] ^= byte.wrapping_mul(17);
    }
    public_key
}

fn encrypt_aead(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), WasmCryptoError> {
    // Simulated AEAD encryption
    let ciphertext: Vec<u8> = plaintext
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()] ^ nonce[i % nonce.len()])
        .collect();

    let mut tag = vec![0u8; 16];
    for (i, &b) in plaintext.iter().chain(aad.iter()).enumerate() {
        tag[i % 16] ^= b ^ key[i % key.len()];
    }

    Ok((ciphertext, tag))
}

fn decrypt_aead(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, WasmCryptoError> {
    // Simulated AEAD decryption
    let plaintext: Vec<u8> = ciphertext
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()] ^ nonce[i % nonce.len()])
        .collect();

    // Verify tag
    let mut expected_tag = vec![0u8; 16];
    for (i, &b) in plaintext.iter().chain(aad.iter()).enumerate() {
        expected_tag[i % 16] ^= b ^ key[i % key.len()];
    }

    if !constant_time_eq(tag, &expected_tag) {
        return Err(WasmCryptoError::DecryptionFailed(
            "Authentication failed".to_string(),
        ));
    }

    Ok(plaintext)
}

fn compute_hash(data: &[u8], algorithm: HashAlgorithm) -> Vec<u8> {
    let output_len = algorithm.output_length();
    let mut hash = vec![0u8; output_len];

    for (i, &byte) in data.iter().enumerate() {
        hash[i % output_len] ^= byte.wrapping_mul((i as u8).wrapping_add(1));
    }

    hash
}

fn compute_hmac(key: &[u8], data: &[u8], algorithm: HashAlgorithm) -> Vec<u8> {
    // Simulated HMAC
    let mut combined = key.to_vec();
    combined.extend_from_slice(data);
    compute_hash(&combined, algorithm)
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

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn base64_encode(data: &[u8]) -> String {
    // Simplified base64 encoding for demo
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(CHARS[(b0 >> 2) & 0x3F] as char);
        result.push(CHARS[((b0 << 4) | (b1 >> 4)) & 0x3F] as char);

        if chunk.len() > 1 {
            result.push(CHARS[((b1 << 2) | (b2 >> 6)) & 0x3F] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(CHARS[b2 & 0x3F] as char);
        } else {
            result.push('=');
        }
    }

    result
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = Vec::new();
    let chars: Vec<char> = s.chars().filter(|c| *c != '=').collect();

    for chunk in chars.chunks(4) {
        if chunk.len() < 2 {
            break;
        }

        let b0 = CHARS.iter().position(|&c| c == chunk[0] as u8).unwrap_or(0);
        let b1 = CHARS.iter().position(|&c| c == chunk[1] as u8).unwrap_or(0);

        result.push(((b0 << 2) | (b1 >> 4)) as u8);

        if chunk.len() > 2 {
            let b2 = CHARS.iter().position(|&c| c == chunk[2] as u8).unwrap_or(0);
            result.push(((b1 << 4) | (b2 >> 2)) as u8);

            if chunk.len() > 3 {
                let b3 = CHARS.iter().position(|&c| c == chunk[3] as u8).unwrap_or(0);
                result.push(((b2 << 6) | b3) as u8);
            }
        }
    }

    Ok(result)
}

fn main() {
    println!("=== WebAssembly Crypto Module Demo ===\n");

    let mut crypto = WasmCrypto::new();

    // Generate symmetric key
    println!("--- Symmetric Encryption ---");
    crypto
        .generate_symmetric_key("aes_key", SymmetricAlgorithm::Aes256Gcm)
        .unwrap();

    let plaintext = b"Hello, WebAssembly!";
    let aad = b"additional data";

    let encrypted = crypto
        .encrypt(
            "aes_key",
            plaintext,
            SymmetricAlgorithm::Aes256Gcm,
            Some(aad),
        )
        .unwrap();

    println!("Plaintext: {:?}", String::from_utf8_lossy(plaintext));
    println!("Encrypted (base64): {}", encrypted.to_base64());

    let decrypted = crypto.decrypt("aes_key", &encrypted, Some(aad)).unwrap();
    println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted));

    // Digital signatures
    println!("\n--- Digital Signatures ---");
    crypto
        .generate_key_pair("signing_key", SignatureAlgorithm::Ed25519)
        .unwrap();

    let message = b"Message to sign";
    let signature = crypto.sign("signing_key", message).unwrap();
    println!("Signature: {}", hex_encode(&signature));

    let is_valid = crypto.verify("signing_key", message, &signature).unwrap();
    println!("Signature valid: {}", is_valid);

    let is_invalid = crypto
        .verify("signing_key", b"Different message", &signature)
        .unwrap();
    println!("Wrong message valid: {}", is_invalid);

    // Hashing
    println!("\n--- Hashing ---");
    let data = b"data to hash";
    let sha256 = WasmCrypto::hash(data, HashAlgorithm::Sha256);
    let blake3 = WasmCrypto::hash(data, HashAlgorithm::Blake3);

    println!("SHA-256: {}", hex_encode(&sha256));
    println!("BLAKE3:  {}", hex_encode(&blake3));

    // HMAC
    println!("\n--- HMAC ---");
    let hmac_key = b"secret_key";
    let hmac = WasmCrypto::hmac(hmac_key, data, HashAlgorithm::Sha256);
    println!("HMAC-SHA256: {}", hex_encode(&hmac));

    // Random bytes
    println!("\n--- Random Generation ---");
    let random = WasmCrypto::random_bytes(16);
    println!("Random bytes: {}", hex_encode(&random));

    // Serialization
    println!("\n--- Serialization ---");
    let serialized = encrypted.to_bytes();
    println!("Serialized length: {} bytes", serialized.len());

    let deserialized = EncryptedData::from_bytes(&serialized).unwrap();
    println!("Deserialized algorithm: {:?}", deserialized.algorithm);

    // Algorithm info
    println!("\n--- Algorithm Information ---");
    println!(
        "AES-256-GCM: key={} nonce={} tag={}",
        SymmetricAlgorithm::Aes256Gcm.key_length(),
        SymmetricAlgorithm::Aes256Gcm.nonce_length(),
        SymmetricAlgorithm::Aes256Gcm.tag_length()
    );
    println!(
        "Ed25519: public={} private={} sig={}",
        SignatureAlgorithm::Ed25519.public_key_length(),
        SignatureAlgorithm::Ed25519.private_key_length(),
        SignatureAlgorithm::Ed25519.signature_length()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_algorithm_properties() {
        let algo = SymmetricAlgorithm::Aes256Gcm;
        assert_eq!(algo.key_length(), 32);
        assert_eq!(algo.nonce_length(), 12);
        assert_eq!(algo.tag_length(), 16);
    }

    #[test]
    fn test_hash_algorithm_properties() {
        assert_eq!(HashAlgorithm::Sha256.output_length(), 32);
        assert_eq!(HashAlgorithm::Sha512.output_length(), 64);
    }

    #[test]
    fn test_signature_algorithm_properties() {
        let algo = SignatureAlgorithm::Ed25519;
        assert_eq!(algo.public_key_length(), 32);
        assert_eq!(algo.signature_length(), 64);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut crypto = WasmCrypto::new();
        crypto
            .generate_symmetric_key("test", SymmetricAlgorithm::Aes256Gcm)
            .unwrap();

        let plaintext = b"test message";
        let encrypted = crypto
            .encrypt("test", plaintext, SymmetricAlgorithm::Aes256Gcm, None)
            .unwrap();
        let decrypted = crypto.decrypt("test", &encrypted, None).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let mut crypto = WasmCrypto::new();
        crypto
            .generate_symmetric_key("test", SymmetricAlgorithm::ChaCha20Poly1305)
            .unwrap();

        let plaintext = b"test message";
        let aad = b"additional data";

        let encrypted = crypto
            .encrypt(
                "test",
                plaintext,
                SymmetricAlgorithm::ChaCha20Poly1305,
                Some(aad),
            )
            .unwrap();
        let decrypted = crypto.decrypt("test", &encrypted, Some(aad)).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_sign_verify() {
        let mut crypto = WasmCrypto::new();
        crypto
            .generate_key_pair("test", SignatureAlgorithm::Ed25519)
            .unwrap();

        let message = b"test message";
        let signature = crypto.sign("test", message).unwrap();
        let valid = crypto.verify("test", message, &signature).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_sign_verify_invalid() {
        let mut crypto = WasmCrypto::new();
        crypto
            .generate_key_pair("test", SignatureAlgorithm::Ed25519)
            .unwrap();

        let message = b"test message";
        let signature = crypto.sign("test", message).unwrap();
        let valid = crypto.verify("test", b"different", &signature).unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_hashing() {
        let data = b"test data";

        let sha256 = WasmCrypto::hash(data, HashAlgorithm::Sha256);
        assert_eq!(sha256.len(), 32);

        let sha512 = WasmCrypto::hash(data, HashAlgorithm::Sha512);
        assert_eq!(sha512.len(), 64);
    }

    #[test]
    fn test_hmac() {
        let key = b"secret";
        let data = b"message";

        let hmac = WasmCrypto::hmac(key, data, HashAlgorithm::Sha256);
        assert_eq!(hmac.len(), 32);
    }

    #[test]
    fn test_random_bytes() {
        let bytes = WasmCrypto::random_bytes(32);
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(WasmCrypto::constant_time_compare(&[1, 2, 3], &[1, 2, 3]));
        assert!(!WasmCrypto::constant_time_compare(&[1, 2, 3], &[1, 2, 4]));
        assert!(!WasmCrypto::constant_time_compare(&[1, 2], &[1, 2, 3]));
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let encrypted = EncryptedData {
            algorithm: SymmetricAlgorithm::Aes256Gcm,
            nonce: vec![1; 12],
            ciphertext: vec![2; 32],
            tag: vec![3; 16],
        };

        let bytes = encrypted.to_bytes();
        let parsed = EncryptedData::from_bytes(&bytes).unwrap();

        assert_eq!(encrypted.algorithm, parsed.algorithm);
        assert_eq!(encrypted.nonce, parsed.nonce);
        assert_eq!(encrypted.ciphertext, parsed.ciphertext);
        assert_eq!(encrypted.tag, parsed.tag);
    }

    #[test]
    fn test_encrypted_data_base64() {
        let encrypted = EncryptedData {
            algorithm: SymmetricAlgorithm::Aes256Gcm,
            nonce: vec![1; 12],
            ciphertext: vec![2; 8],
            tag: vec![3; 16],
        };

        let base64 = encrypted.to_base64();
        let parsed = EncryptedData::from_base64(&base64).unwrap();

        assert_eq!(encrypted.algorithm, parsed.algorithm);
    }

    #[test]
    fn test_key_pair() {
        let key_pair = KeyPair::generate(SignatureAlgorithm::Ed25519).unwrap();

        assert_eq!(key_pair.public_key.len(), 32);
        assert_eq!(key_pair.algorithm, SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn test_import_key() {
        let mut crypto = WasmCrypto::new();

        let key = vec![0u8; 32];
        crypto
            .import_symmetric_key("imported", key, SymmetricAlgorithm::Aes256Gcm)
            .unwrap();

        let encrypted = crypto
            .encrypt("imported", b"test", SymmetricAlgorithm::Aes256Gcm, None)
            .unwrap();

        assert!(!encrypted.ciphertext.is_empty());
    }

    #[test]
    fn test_invalid_key_length() {
        let mut crypto = WasmCrypto::new();

        let short_key = vec![0u8; 16];
        let result = crypto.import_symmetric_key("test", short_key, SymmetricAlgorithm::Aes256Gcm);

        assert!(result.is_err());
    }
}
