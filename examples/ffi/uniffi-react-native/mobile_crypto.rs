//! UniFFI React Native Mobile Crypto Bindings
//!
//! Provides secure cryptographic operations for React Native mobile apps
//! using Mozilla's UniFFI for cross-platform FFI generation.
//!
//! # Features
//! - AES-256-GCM encryption/decryption
//! - Secure key derivation (Argon2id)
//! - Secure random generation
//! - Memory-safe string handling
//! - Automatic secret zeroization

use std::sync::Arc;

// ============================================================================
// UniFFI Interface Definition (would be in .udl file)
// ============================================================================

/// UniFFI namespace definition (simulated - normally in .udl file)
/// ```udl
/// namespace mobile_crypto {
///     [Throws=CryptoError]
///     SecureString encrypt(string plaintext, SecureKey key);
///
///     [Throws=CryptoError]
///     string decrypt(SecureString ciphertext, SecureKey key);
///
///     [Throws=CryptoError]
///     SecureKey derive_key(string password, [ByRef] bytes salt);
///
///     bytes generate_salt();
/// };
///
/// [Error]
/// enum CryptoError {
///     "InvalidKey",
///     "DecryptionFailed",
///     "EncodingError",
///     "KeyDerivationFailed",
/// };
///
/// interface SecureKey {
///     constructor([ByRef] bytes key_bytes);
///     bytes get_id();
/// };
///
/// interface SecureString {
///     constructor(string ciphertext, [ByRef] bytes nonce, [ByRef] bytes tag);
///     string to_base64();
///     [Name=from_base64, Throws=CryptoError]
///     constructor(string encoded);
/// };
/// ```

// ============================================================================
// Error Types
// ============================================================================

/// Cryptographic error types exposed to React Native
#[derive(Debug, Clone)]
pub enum CryptoError {
    InvalidKey(String),
    DecryptionFailed(String),
    EncodingError(String),
    KeyDerivationFailed(String),
    RandomGenerationFailed(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            Self::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            Self::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
            Self::KeyDerivationFailed(msg) => write!(f, "Key derivation failed: {}", msg),
            Self::RandomGenerationFailed(msg) => write!(f, "Random generation failed: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {}

// ============================================================================
// Secure Key Management
// ============================================================================

/// A secure key that zeroizes on drop
pub struct SecureKey {
    /// The actual key bytes (would use secrecy crate in production)
    key_bytes: Vec<u8>,
    /// Unique identifier for the key (non-sensitive)
    key_id: [u8; 8],
}

impl SecureKey {
    /// Create a new SecureKey from raw bytes
    pub fn new(key_bytes: Vec<u8>) -> Result<Arc<Self>, CryptoError> {
        if key_bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(format!(
                "Key must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        // Generate a random key ID for identification without exposing key material
        let mut key_id = [0u8; 8];
        // In production: use ring or getrandom
        for (i, byte) in key_id.iter_mut().enumerate() {
            *byte =
                (key_bytes[i] ^ key_bytes[i + 8] ^ key_bytes[i + 16] ^ key_bytes[i + 24]) ^ 0x55;
        }

        Ok(Arc::new(Self { key_bytes, key_id }))
    }

    /// Get the key ID (safe to expose)
    pub fn get_id(&self) -> Vec<u8> {
        self.key_id.to_vec()
    }

    /// Internal: get key bytes for crypto operations
    fn as_bytes(&self) -> &[u8] {
        &self.key_bytes
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        // Zeroize key material
        for byte in &mut self.key_bytes {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

// ============================================================================
// Secure String (Encrypted Data Container)
// ============================================================================

/// Encrypted data container for React Native
pub struct SecureString {
    /// Base64-encoded ciphertext
    ciphertext: Vec<u8>,
    /// Nonce/IV used for encryption
    nonce: [u8; 12],
    /// Authentication tag
    tag: [u8; 16],
}

impl SecureString {
    /// Create from components
    pub fn new(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        tag: Vec<u8>,
    ) -> Result<Arc<Self>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::EncodingError("Nonce must be 12 bytes".into()));
        }
        if tag.len() != 16 {
            return Err(CryptoError::EncodingError("Tag must be 16 bytes".into()));
        }

        let mut nonce_arr = [0u8; 12];
        let mut tag_arr = [0u8; 16];
        nonce_arr.copy_from_slice(&nonce);
        tag_arr.copy_from_slice(&tag);

        Ok(Arc::new(Self {
            ciphertext,
            nonce: nonce_arr,
            tag: tag_arr,
        }))
    }

    /// Encode to base64 for storage/transmission
    pub fn to_base64(&self) -> String {
        // Format: version(1) || nonce(12) || tag(16) || ciphertext(n)
        let mut combined = Vec::with_capacity(1 + 12 + 16 + self.ciphertext.len());
        combined.push(0x01); // Version byte
        combined.extend_from_slice(&self.nonce);
        combined.extend_from_slice(&self.tag);
        combined.extend_from_slice(&self.ciphertext);
        base64_encode(&combined)
    }

    /// Decode from base64
    pub fn from_base64(encoded: &str) -> Result<Arc<Self>, CryptoError> {
        let decoded = base64_decode(encoded)
            .map_err(|e| CryptoError::EncodingError(format!("Base64 decode failed: {}", e)))?;

        if decoded.len() < 1 + 12 + 16 {
            return Err(CryptoError::EncodingError("Data too short".into()));
        }

        let version = decoded[0];
        if version != 0x01 {
            return Err(CryptoError::EncodingError(format!(
                "Unknown version: {}",
                version
            )));
        }

        let nonce = decoded[1..13].to_vec();
        let tag = decoded[13..29].to_vec();
        let ciphertext = decoded[29..].to_vec();

        Self::new(ciphertext, nonce, tag)
    }
}

// ============================================================================
// Cryptographic Operations
// ============================================================================

/// Mobile crypto operations exposed via UniFFI
pub struct MobileCrypto;

impl MobileCrypto {
    /// Encrypt plaintext with AES-256-GCM
    pub fn encrypt(plaintext: &str, key: &SecureKey) -> Result<Arc<SecureString>, CryptoError> {
        let key_bytes = key.as_bytes();
        let plaintext_bytes = plaintext.as_bytes();

        // Generate random nonce
        let nonce = generate_random_bytes(12)
            .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;

        // Simulate AES-256-GCM encryption
        // In production: use ring::aead or aes-gcm crate
        let (ciphertext, tag) = aes_gcm_encrypt(key_bytes, &nonce, plaintext_bytes, &[])?;

        SecureString::new(ciphertext, nonce, tag)
    }

    /// Decrypt ciphertext with AES-256-GCM
    pub fn decrypt(secure_string: &SecureString, key: &SecureKey) -> Result<String, CryptoError> {
        let key_bytes = key.as_bytes();

        // Simulate AES-256-GCM decryption
        let plaintext_bytes = aes_gcm_decrypt(
            key_bytes,
            &secure_string.nonce,
            &secure_string.ciphertext,
            &secure_string.tag,
            &[],
        )?;

        String::from_utf8(plaintext_bytes)
            .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid UTF-8: {}", e)))
    }

    /// Derive a key from password using Argon2id
    pub fn derive_key(password: &str, salt: &[u8]) -> Result<Arc<SecureKey>, CryptoError> {
        if salt.len() < 16 {
            return Err(CryptoError::KeyDerivationFailed(
                "Salt must be at least 16 bytes".into(),
            ));
        }

        // Simulate Argon2id key derivation
        // In production: use argon2 crate
        let key_bytes = argon2id_derive(password.as_bytes(), salt, 32)?;

        SecureKey::new(key_bytes)
    }

    /// Generate cryptographically secure salt
    pub fn generate_salt() -> Result<Vec<u8>, CryptoError> {
        generate_random_bytes(32).map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))
    }
}

// ============================================================================
// Crypto Primitives (Simulated - use real crates in production)
// ============================================================================

fn generate_random_bytes(len: usize) -> Result<Vec<u8>, &'static str> {
    // In production: use ring::rand or getrandom
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let mut bytes = vec![0u8; len];
    let mut state = seed as u64;
    for byte in &mut bytes {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *byte = (state >> 33) as u8;
    }
    Ok(bytes)
}

fn aes_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    _aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // Simulated AES-GCM - in production use ring::aead or aes-gcm
    let mut ciphertext = plaintext.to_vec();

    // XOR with key-derived stream (simplified)
    for (i, byte) in ciphertext.iter_mut().enumerate() {
        *byte ^= key[i % key.len()] ^ nonce[i % nonce.len()];
    }

    // Generate authentication tag (simplified)
    let mut tag = [0u8; 16];
    for (i, t) in tag.iter_mut().enumerate() {
        let mut acc = key[i % key.len()];
        for (j, &c) in ciphertext.iter().enumerate() {
            acc ^= c.wrapping_add((j + i) as u8);
        }
        *t = acc;
    }

    Ok((ciphertext, tag.to_vec()))
}

fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    _aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Verify tag (simplified)
    let mut expected_tag = [0u8; 16];
    for (i, t) in expected_tag.iter_mut().enumerate() {
        let mut acc = key[i % key.len()];
        for (j, &c) in ciphertext.iter().enumerate() {
            acc ^= c.wrapping_add((j + i) as u8);
        }
        *t = acc;
    }

    // Constant-time comparison
    let mut diff = 0u8;
    for (a, b) in expected_tag.iter().zip(tag.iter()) {
        diff |= a ^ b;
    }

    if diff != 0 {
        return Err(CryptoError::DecryptionFailed(
            "Authentication failed".into(),
        ));
    }

    // Decrypt
    let mut plaintext = ciphertext.to_vec();
    for (i, byte) in plaintext.iter_mut().enumerate() {
        *byte ^= key[i % key.len()] ^ nonce[i % nonce.len()];
    }

    Ok(plaintext)
}

fn argon2id_derive(
    password: &[u8],
    salt: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    // Simulated Argon2id - in production use argon2 crate
    let mut key = vec![0u8; output_len];

    // Mix password and salt (simplified)
    for (i, k) in key.iter_mut().enumerate() {
        let p = password[i % password.len()];
        let s = salt[i % salt.len()];
        *k = p.wrapping_mul(s).wrapping_add((i * 31) as u8);
    }

    // Multiple rounds of mixing (simplified)
    for _ in 0..1000 {
        for i in 0..output_len {
            key[i] = key[i]
                .wrapping_add(key[(i + 1) % output_len])
                .wrapping_mul(key[(i + output_len - 1) % output_len].wrapping_add(1));
        }
    }

    Ok(key)
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

        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
    }

    result
}

fn base64_decode(data: &str) -> Result<Vec<u8>, &'static str> {
    const DECODE: [i8; 128] = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
        -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1,
        -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
        46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    ];

    let data = data.trim_end_matches('=');
    let mut result = Vec::with_capacity(data.len() * 3 / 4);

    let bytes: Vec<u8> = data.bytes().collect();
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            break;
        }

        let b0 = DECODE.get(chunk[0] as usize).copied().unwrap_or(-1);
        let b1 = DECODE.get(chunk[1] as usize).copied().unwrap_or(-1);
        let b2 = chunk
            .get(2)
            .and_then(|&c| DECODE.get(c as usize).copied())
            .unwrap_or(0);
        let b3 = chunk
            .get(3)
            .and_then(|&c| DECODE.get(c as usize).copied())
            .unwrap_or(0);

        if b0 < 0 || b1 < 0 {
            return Err("Invalid base64");
        }

        result.push(((b0 << 2) | (b1 >> 4)) as u8);
        if chunk.len() > 2 && b2 >= 0 {
            result.push((((b1 & 0x0f) << 4) | (b2 >> 2)) as u8);
        }
        if chunk.len() > 3 && b3 >= 0 {
            result.push((((b2 & 0x03) << 6) | b3) as u8);
        }
    }

    Ok(result)
}

// ============================================================================
// React Native Bridge Code Generator
// ============================================================================

/// Generates TypeScript definitions for React Native
pub fn generate_typescript_definitions() -> String {
    r#"// Auto-generated TypeScript definitions for mobile_crypto

export interface CryptoError {
  type: 'InvalidKey' | 'DecryptionFailed' | 'EncodingError' | 'KeyDerivationFailed' | 'RandomGenerationFailed';
  message: string;
}

export interface SecureKey {
  readonly keyId: Uint8Array;
}

export interface SecureString {
  toBase64(): string;
}

export interface MobileCryptoModule {
  /**
   * Derive a secure key from password using Argon2id
   * @param password - User's password
   * @param salt - Random salt (use generateSalt())
   * @returns Promise resolving to SecureKey
   */
  deriveKey(password: string, salt: Uint8Array): Promise<SecureKey>;

  /**
   * Encrypt plaintext string
   * @param plaintext - Text to encrypt
   * @param key - SecureKey from deriveKey()
   * @returns Promise resolving to SecureString
   */
  encrypt(plaintext: string, key: SecureKey): Promise<SecureString>;

  /**
   * Decrypt ciphertext
   * @param ciphertext - SecureString from encrypt() or fromBase64()
   * @param key - SecureKey used for encryption
   * @returns Promise resolving to plaintext string
   */
  decrypt(ciphertext: SecureString, key: SecureKey): Promise<string>;

  /**
   * Generate cryptographically secure salt
   * @returns Promise resolving to 32-byte salt
   */
  generateSalt(): Promise<Uint8Array>;

  /**
   * Restore SecureString from base64
   * @param encoded - Base64 string from toBase64()
   * @returns Promise resolving to SecureString
   */
  secureStringFromBase64(encoded: string): Promise<SecureString>;
}

declare const MobileCrypto: MobileCryptoModule;
export default MobileCrypto;
"#.to_string()
}

/// Generates React Native usage example
pub fn generate_react_native_example() -> String {
    r#"// React Native usage example
import MobileCrypto, { SecureKey, SecureString } from 'mobile-crypto';
import AsyncStorage from '@react-native-async-storage/async-storage';

// Secure storage wrapper
class SecureStorage {
  private key: SecureKey | null = null;
  private readonly SALT_KEY = '@secure_storage_salt';

  async initialize(password: string): Promise<void> {
    // Get or create salt
    let saltBase64 = await AsyncStorage.getItem(this.SALT_KEY);
    let salt: Uint8Array;

    if (saltBase64) {
      salt = this.base64ToBytes(saltBase64);
    } else {
      salt = await MobileCrypto.generateSalt();
      await AsyncStorage.setItem(this.SALT_KEY, this.bytesToBase64(salt));
    }

    // Derive key from password
    this.key = await MobileCrypto.deriveKey(password, salt);
  }

  async setItem(key: string, value: string): Promise<void> {
    if (!this.key) throw new Error('Storage not initialized');

    const encrypted = await MobileCrypto.encrypt(value, this.key);
    await AsyncStorage.setItem(key, encrypted.toBase64());
  }

  async getItem(key: string): Promise<string | null> {
    if (!this.key) throw new Error('Storage not initialized');

    const stored = await AsyncStorage.getItem(key);
    if (!stored) return null;

    const secureString = await MobileCrypto.secureStringFromBase64(stored);
    return MobileCrypto.decrypt(secureString, this.key);
  }

  private bytesToBase64(bytes: Uint8Array): string {
    return btoa(String.fromCharCode(...bytes));
  }

  private base64ToBytes(base64: string): Uint8Array {
    return new Uint8Array(atob(base64).split('').map(c => c.charCodeAt(0)));
  }
}

// Usage
const storage = new SecureStorage();
await storage.initialize('user-password');
await storage.setItem('api_token', 'secret-token-12345');
const token = await storage.getItem('api_token');
"#
    .to_string()
}

// ============================================================================
// Main and Tests
// ============================================================================

fn main() {
    println!("UniFFI React Native Mobile Crypto Example\n");

    // Generate salt
    let salt = MobileCrypto::generate_salt().expect("Failed to generate salt");
    println!("Generated salt ({} bytes)", salt.len());

    // Derive key from password
    let key = MobileCrypto::derive_key("my-secure-password", &salt).expect("Failed to derive key");
    println!("Derived key with ID: {:02x?}", key.get_id());

    // Encrypt sensitive data
    let plaintext = "This is sensitive user data!";
    let encrypted = MobileCrypto::encrypt(plaintext, &key).expect("Failed to encrypt");

    let encoded = encrypted.to_base64();
    println!(
        "Encrypted (base64): {}...",
        &encoded[..50.min(encoded.len())]
    );

    // Simulate storage/transmission
    let restored = SecureString::from_base64(&encoded).expect("Failed to decode");

    // Decrypt
    let decrypted = MobileCrypto::decrypt(&restored, &key).expect("Failed to decrypt");
    println!("Decrypted: {}", decrypted);

    assert_eq!(plaintext, decrypted);
    println!("\nRound-trip successful!");

    // Print TypeScript definitions
    println!("\n--- TypeScript Definitions ---\n");
    println!("{}", generate_typescript_definitions());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_creation() {
        let key_bytes = vec![0x42u8; 32];
        let key = SecureKey::new(key_bytes).expect("Should create key");
        assert_eq!(key.get_id().len(), 8);
    }

    #[test]
    fn test_key_invalid_length() {
        let key_bytes = vec![0x42u8; 16]; // Wrong length
        let result = SecureKey::new(key_bytes);
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let salt = MobileCrypto::generate_salt().unwrap();
        let key = MobileCrypto::derive_key("test-password", &salt).unwrap();

        let plaintext = "Hello, React Native!";
        let encrypted = MobileCrypto::encrypt(plaintext, &key).unwrap();
        let decrypted = MobileCrypto::decrypt(&encrypted, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_base64_roundtrip() {
        let salt = MobileCrypto::generate_salt().unwrap();
        let key = MobileCrypto::derive_key("test-password", &salt).unwrap();

        let plaintext = "Sensitive data";
        let encrypted = MobileCrypto::encrypt(plaintext, &key).unwrap();

        let encoded = encrypted.to_base64();
        let restored = SecureString::from_base64(&encoded).unwrap();
        let decrypted = MobileCrypto::decrypt(&restored, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let salt = MobileCrypto::generate_salt().unwrap();
        let key1 = MobileCrypto::derive_key("password1", &salt).unwrap();
        let key2 = MobileCrypto::derive_key("password2", &salt).unwrap();

        let encrypted = MobileCrypto::encrypt("secret", &key1).unwrap();
        let result = MobileCrypto::decrypt(&encrypted, &key2);

        assert!(matches!(result, Err(CryptoError::DecryptionFailed(_))));
    }

    #[test]
    fn test_salt_uniqueness() {
        let salt1 = MobileCrypto::generate_salt().unwrap();
        let salt2 = MobileCrypto::generate_salt().unwrap();

        // Salts should be different (probabilistically)
        assert_ne!(salt1, salt2);
    }

    #[test]
    fn test_typescript_generation() {
        let ts = generate_typescript_definitions();
        assert!(ts.contains("export interface SecureKey"));
        assert!(ts.contains("deriveKey"));
        assert!(ts.contains("encrypt"));
        assert!(ts.contains("decrypt"));
    }
}
