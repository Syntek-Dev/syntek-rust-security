//! Neon Node.js FFI Binding Example
//!
//! Demonstrates creating secure Rust cryptographic functions
//! that can be called from Node.js/JavaScript applications.

use std::collections::HashMap;

/// Simulated Neon context for demonstration
/// In real code, this would be neon::prelude::*
pub mod neon_mock {
    use std::any::Any;

    pub trait Context<'a> {
        fn string(&mut self, s: &str) -> JsString;
        fn number(&mut self, n: f64) -> JsNumber;
        fn boolean(&mut self, b: bool) -> JsBoolean;
        fn array_buffer(&mut self, data: Vec<u8>) -> JsArrayBuffer;
        fn throw_error(&mut self, msg: &str) -> NeonResult<()>;
    }

    pub struct FunctionContext {
        args: Vec<Box<dyn Any>>,
    }

    impl FunctionContext {
        pub fn new() -> Self {
            Self { args: Vec::new() }
        }

        pub fn argument<T: 'static + Clone>(&self, index: usize) -> Option<T> {
            self.args.get(index)?.downcast_ref::<T>().cloned()
        }

        pub fn add_arg<T: 'static>(&mut self, arg: T) {
            self.args.push(Box::new(arg));
        }
    }

    impl<'a> Context<'a> for FunctionContext {
        fn string(&mut self, s: &str) -> JsString {
            JsString(s.to_string())
        }

        fn number(&mut self, n: f64) -> JsNumber {
            JsNumber(n)
        }

        fn boolean(&mut self, b: bool) -> JsBoolean {
            JsBoolean(b)
        }

        fn array_buffer(&mut self, data: Vec<u8>) -> JsArrayBuffer {
            JsArrayBuffer(data)
        }

        fn throw_error(&mut self, msg: &str) -> NeonResult<()> {
            Err(NeonError(msg.to_string()))
        }
    }

    #[derive(Debug, Clone)]
    pub struct JsString(pub String);

    #[derive(Debug, Clone)]
    pub struct JsNumber(pub f64);

    #[derive(Debug, Clone)]
    pub struct JsBoolean(pub bool);

    #[derive(Debug, Clone)]
    pub struct JsArrayBuffer(pub Vec<u8>);

    #[derive(Debug)]
    pub struct NeonError(pub String);

    pub type NeonResult<T> = Result<T, NeonError>;
}

use neon_mock::*;

/// Encryption result for JS interop
#[derive(Debug, Clone)]
pub struct EncryptionResult {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub tag: Vec<u8>,
}

/// Cryptographic operations exposed to Node.js
pub struct CryptoModule {
    // Would hold key material in real implementation
}

impl CryptoModule {
    /// Generate a random key of specified length
    pub fn generate_key(cx: &mut FunctionContext, key_length: usize) -> NeonResult<JsArrayBuffer> {
        if key_length != 16 && key_length != 24 && key_length != 32 {
            return Err(NeonError(
                "Key length must be 16, 24, or 32 bytes".to_string(),
            ));
        }

        // Generate random key (simplified - use proper CSPRNG)
        let key: Vec<u8> = (0..key_length)
            .map(|i| ((i * 17 + 42) % 256) as u8)
            .collect();

        Ok(cx.array_buffer(key))
    }

    /// Encrypt data with AES-GCM
    pub fn encrypt_aes_gcm(
        cx: &mut FunctionContext,
        plaintext: &[u8],
        key: &[u8],
        aad: Option<&[u8]>,
    ) -> NeonResult<EncryptionResult> {
        // Validate key length
        if key.len() != 16 && key.len() != 24 && key.len() != 32 {
            return Err(NeonError("Invalid key length".to_string()));
        }

        // Generate nonce (12 bytes for AES-GCM)
        let nonce: Vec<u8> = (0..12).map(|i| ((i * 23 + 11) % 256) as u8).collect();

        // Simplified encryption simulation
        // Real implementation would use ring or aes-gcm crate
        let ciphertext: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()] ^ nonce[i % nonce.len()])
            .collect();

        // Generate tag (16 bytes)
        let tag: Vec<u8> = (0..16)
            .map(|i| {
                let mut t = ciphertext.get(i).copied().unwrap_or(0);
                t ^= key[i % key.len()];
                if let Some(aad_bytes) = aad {
                    t ^= aad_bytes.get(i).copied().unwrap_or(0);
                }
                t
            })
            .collect();

        Ok(EncryptionResult {
            ciphertext,
            nonce,
            tag,
        })
    }

    /// Decrypt data with AES-GCM
    pub fn decrypt_aes_gcm(
        cx: &mut FunctionContext,
        ciphertext: &[u8],
        key: &[u8],
        nonce: &[u8],
        tag: &[u8],
        aad: Option<&[u8]>,
    ) -> NeonResult<Vec<u8>> {
        // Validate inputs
        if key.len() != 16 && key.len() != 24 && key.len() != 32 {
            return Err(NeonError("Invalid key length".to_string()));
        }

        if nonce.len() != 12 {
            return Err(NeonError("Nonce must be 12 bytes".to_string()));
        }

        if tag.len() != 16 {
            return Err(NeonError("Tag must be 16 bytes".to_string()));
        }

        // Verify tag (simplified)
        let expected_tag: Vec<u8> = (0..16)
            .map(|i| {
                let mut t = ciphertext.get(i).copied().unwrap_or(0);
                t ^= key[i % key.len()];
                if let Some(aad_bytes) = aad {
                    t ^= aad_bytes.get(i).copied().unwrap_or(0);
                }
                t
            })
            .collect();

        if tag != expected_tag.as_slice() {
            return Err(NeonError("Authentication failed".to_string()));
        }

        // Decrypt
        let plaintext: Vec<u8> = ciphertext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()] ^ nonce[i % nonce.len()])
            .collect();

        Ok(plaintext)
    }

    /// Hash data with SHA-256
    pub fn hash_sha256(cx: &mut FunctionContext, data: &[u8]) -> JsArrayBuffer {
        // Simplified hash simulation
        // Real implementation would use sha2 crate
        let mut hash = [0u8; 32];
        for (i, &byte) in data.iter().enumerate() {
            hash[i % 32] ^= byte;
            hash[(i + 1) % 32] = hash[(i + 1) % 32].wrapping_add(byte);
        }
        cx.array_buffer(hash.to_vec())
    }

    /// Derive key using PBKDF2
    pub fn derive_key_pbkdf2(
        cx: &mut FunctionContext,
        password: &str,
        salt: &[u8],
        iterations: u32,
        key_length: usize,
    ) -> NeonResult<JsArrayBuffer> {
        if iterations < 100_000 {
            return Err(NeonError("Iterations must be at least 100,000".to_string()));
        }

        if salt.len() < 16 {
            return Err(NeonError("Salt must be at least 16 bytes".to_string()));
        }

        if key_length > 64 {
            return Err(NeonError("Key length too large".to_string()));
        }

        // Simplified derivation simulation
        let password_bytes = password.as_bytes();
        let mut derived = vec![0u8; key_length];

        for round in 0..iterations {
            for (i, d) in derived.iter_mut().enumerate() {
                *d ^= password_bytes
                    .get(i % password_bytes.len())
                    .copied()
                    .unwrap_or(0);
                *d ^= salt.get(i % salt.len()).copied().unwrap_or(0);
                *d = d.wrapping_add((round % 256) as u8);
            }
        }

        Ok(cx.array_buffer(derived))
    }

    /// Constant-time comparison for security
    pub fn constant_time_compare(cx: &mut FunctionContext, a: &[u8], b: &[u8]) -> JsBoolean {
        if a.len() != b.len() {
            return cx.boolean(false);
        }

        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }

        cx.boolean(result == 0)
    }

    /// Generate secure random bytes
    pub fn random_bytes(cx: &mut FunctionContext, length: usize) -> NeonResult<JsArrayBuffer> {
        if length > 65536 {
            return Err(NeonError("Requested too many bytes".to_string()));
        }

        // Simplified random generation
        // Real implementation would use getrandom crate
        let bytes: Vec<u8> = (0..length)
            .map(|i| ((i as u64 * 1103515245 + 12345) % 256) as u8)
            .collect();

        Ok(cx.array_buffer(bytes))
    }
}

/// TypeScript type definitions generator
pub fn generate_type_definitions() -> String {
    r#"// Auto-generated TypeScript definitions for Rust crypto module

export interface EncryptionResult {
  ciphertext: ArrayBuffer;
  nonce: ArrayBuffer;
  tag: ArrayBuffer;
}

export interface CryptoModule {
  /**
   * Generate a cryptographically secure random key
   * @param keyLength - Key length in bytes (16, 24, or 32)
   */
  generateKey(keyLength: number): ArrayBuffer;

  /**
   * Encrypt data using AES-GCM
   * @param plaintext - Data to encrypt
   * @param key - Encryption key
   * @param aad - Optional additional authenticated data
   */
  encryptAesGcm(
    plaintext: ArrayBuffer,
    key: ArrayBuffer,
    aad?: ArrayBuffer
  ): EncryptionResult;

  /**
   * Decrypt data using AES-GCM
   * @param ciphertext - Encrypted data
   * @param key - Decryption key
   * @param nonce - Nonce used during encryption
   * @param tag - Authentication tag
   * @param aad - Optional additional authenticated data
   */
  decryptAesGcm(
    ciphertext: ArrayBuffer,
    key: ArrayBuffer,
    nonce: ArrayBuffer,
    tag: ArrayBuffer,
    aad?: ArrayBuffer
  ): ArrayBuffer;

  /**
   * Hash data using SHA-256
   * @param data - Data to hash
   */
  hashSha256(data: ArrayBuffer): ArrayBuffer;

  /**
   * Derive a key from a password using PBKDF2
   * @param password - Password to derive from
   * @param salt - Random salt (at least 16 bytes)
   * @param iterations - Number of iterations (at least 100,000)
   * @param keyLength - Desired key length in bytes
   */
  deriveKeyPbkdf2(
    password: string,
    salt: ArrayBuffer,
    iterations: number,
    keyLength: number
  ): ArrayBuffer;

  /**
   * Constant-time comparison of two buffers
   * @param a - First buffer
   * @param b - Second buffer
   */
  constantTimeCompare(a: ArrayBuffer, b: ArrayBuffer): boolean;

  /**
   * Generate cryptographically secure random bytes
   * @param length - Number of bytes to generate
   */
  randomBytes(length: number): ArrayBuffer;
}

declare const crypto: CryptoModule;
export default crypto;
"#
    .to_string()
}

/// Generate JavaScript usage example
pub fn generate_usage_example() -> String {
    r#"// Example usage of Rust crypto module in Node.js

const crypto = require('./rust-crypto');

async function example() {
  // Generate a 256-bit key
  const key = crypto.generateKey(32);
  console.log('Generated key:', Buffer.from(key).toString('hex'));

  // Encrypt some data
  const plaintext = Buffer.from('Hello, secure world!');
  const result = crypto.encryptAesGcm(plaintext, key);
  console.log('Ciphertext:', Buffer.from(result.ciphertext).toString('hex'));
  console.log('Nonce:', Buffer.from(result.nonce).toString('hex'));
  console.log('Tag:', Buffer.from(result.tag).toString('hex'));

  // Decrypt the data
  const decrypted = crypto.decryptAesGcm(
    result.ciphertext,
    key,
    result.nonce,
    result.tag
  );
  console.log('Decrypted:', Buffer.from(decrypted).toString());

  // Hash some data
  const hash = crypto.hashSha256(plaintext);
  console.log('SHA-256:', Buffer.from(hash).toString('hex'));

  // Derive a key from password
  const salt = crypto.randomBytes(16);
  const derivedKey = crypto.deriveKeyPbkdf2(
    'my-secure-password',
    salt,
    100000,
    32
  );
  console.log('Derived key:', Buffer.from(derivedKey).toString('hex'));

  // Constant-time comparison
  const key1 = crypto.randomBytes(32);
  const key2 = crypto.randomBytes(32);
  console.log('Keys equal:', crypto.constantTimeCompare(key1, key1)); // true
  console.log('Keys equal:', crypto.constantTimeCompare(key1, key2)); // false
}

example().catch(console.error);
"#
    .to_string()
}

fn main() {
    println!("Neon Node.js FFI Binding Example");
    println!("=================================\n");

    let mut cx = FunctionContext::new();

    // Generate key
    println!("Generating 256-bit key...");
    let key_result = CryptoModule::generate_key(&mut cx, 32).unwrap();
    println!("  Key: {:02x?}\n", &key_result.0[..8]);

    // Encrypt data
    let plaintext = b"Hello, Node.js from Rust!";
    let key = vec![0x42u8; 32];
    println!("Encrypting: {:?}", String::from_utf8_lossy(plaintext));

    let enc_result = CryptoModule::encrypt_aes_gcm(&mut cx, plaintext, &key, None).unwrap();
    println!("  Ciphertext length: {} bytes", enc_result.ciphertext.len());
    println!("  Nonce: {:02x?}", &enc_result.nonce);
    println!("  Tag: {:02x?}\n", &enc_result.tag[..8]);

    // Decrypt data
    let decrypted = CryptoModule::decrypt_aes_gcm(
        &mut cx,
        &enc_result.ciphertext,
        &key,
        &enc_result.nonce,
        &enc_result.tag,
        None,
    )
    .unwrap();
    println!("Decrypted: {:?}\n", String::from_utf8_lossy(&decrypted));

    // Hash data
    let hash = CryptoModule::hash_sha256(&mut cx, plaintext);
    println!("SHA-256 hash: {:02x?}...\n", &hash.0[..8]);

    // Derive key
    let salt = vec![0x01u8; 16];
    let derived =
        CryptoModule::derive_key_pbkdf2(&mut cx, "password123", &salt, 100_000, 32).unwrap();
    println!("Derived key: {:02x?}...\n", &derived.0[..8]);

    // Constant-time compare
    let a = vec![1, 2, 3, 4];
    let b = vec![1, 2, 3, 4];
    let c = vec![1, 2, 3, 5];
    println!("Constant-time compare:");
    println!(
        "  a == b: {}",
        CryptoModule::constant_time_compare(&mut cx, &a, &b).0
    );
    println!(
        "  a == c: {}",
        CryptoModule::constant_time_compare(&mut cx, &a, &c).0
    );

    // Generate TypeScript definitions
    println!("\n\nTypeScript Definitions:");
    println!("========================");
    for line in generate_type_definitions().lines().take(20) {
        println!("{}", line);
    }
    println!("...\n");

    // Generate usage example
    println!("JavaScript Usage Example:");
    println!("=========================");
    for line in generate_usage_example().lines().take(15) {
        println!("{}", line);
    }
    println!("...");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_valid_lengths() {
        let mut cx = FunctionContext::new();

        assert!(CryptoModule::generate_key(&mut cx, 16).is_ok());
        assert!(CryptoModule::generate_key(&mut cx, 24).is_ok());
        assert!(CryptoModule::generate_key(&mut cx, 32).is_ok());
    }

    #[test]
    fn test_generate_key_invalid_length() {
        let mut cx = FunctionContext::new();

        assert!(CryptoModule::generate_key(&mut cx, 15).is_err());
        assert!(CryptoModule::generate_key(&mut cx, 64).is_err());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut cx = FunctionContext::new();

        let plaintext = b"Test message for encryption";
        let key = vec![0x42u8; 32];

        let enc = CryptoModule::encrypt_aes_gcm(&mut cx, plaintext, &key, None).unwrap();
        let dec = CryptoModule::decrypt_aes_gcm(
            &mut cx,
            &enc.ciphertext,
            &key,
            &enc.nonce,
            &enc.tag,
            None,
        )
        .unwrap();

        assert_eq!(plaintext.to_vec(), dec);
    }

    #[test]
    fn test_encrypt_invalid_key() {
        let mut cx = FunctionContext::new();
        let plaintext = b"test";
        let bad_key = vec![0u8; 15]; // Invalid length

        assert!(CryptoModule::encrypt_aes_gcm(&mut cx, plaintext, &bad_key, None).is_err());
    }

    #[test]
    fn test_decrypt_wrong_tag() {
        let mut cx = FunctionContext::new();

        let plaintext = b"Test";
        let key = vec![0x42u8; 32];

        let enc = CryptoModule::encrypt_aes_gcm(&mut cx, plaintext, &key, None).unwrap();
        let wrong_tag = vec![0xFFu8; 16];

        let result = CryptoModule::decrypt_aes_gcm(
            &mut cx,
            &enc.ciphertext,
            &key,
            &enc.nonce,
            &wrong_tag,
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_hash_sha256() {
        let mut cx = FunctionContext::new();

        let data = b"hello";
        let hash = CryptoModule::hash_sha256(&mut cx, data);

        assert_eq!(hash.0.len(), 32);
    }

    #[test]
    fn test_derive_key_min_iterations() {
        let mut cx = FunctionContext::new();
        let salt = vec![0u8; 16];

        assert!(CryptoModule::derive_key_pbkdf2(&mut cx, "password", &salt, 50_000, 32).is_err());
        assert!(CryptoModule::derive_key_pbkdf2(&mut cx, "password", &salt, 100_000, 32).is_ok());
    }

    #[test]
    fn test_derive_key_min_salt() {
        let mut cx = FunctionContext::new();
        let short_salt = vec![0u8; 8];

        assert!(
            CryptoModule::derive_key_pbkdf2(&mut cx, "password", &short_salt, 100_000, 32).is_err()
        );
    }

    #[test]
    fn test_constant_time_compare_equal() {
        let mut cx = FunctionContext::new();

        let a = vec![1, 2, 3, 4, 5];
        let b = vec![1, 2, 3, 4, 5];

        assert!(CryptoModule::constant_time_compare(&mut cx, &a, &b).0);
    }

    #[test]
    fn test_constant_time_compare_different() {
        let mut cx = FunctionContext::new();

        let a = vec![1, 2, 3, 4, 5];
        let b = vec![1, 2, 3, 4, 6];

        assert!(!CryptoModule::constant_time_compare(&mut cx, &a, &b).0);
    }

    #[test]
    fn test_constant_time_compare_different_length() {
        let mut cx = FunctionContext::new();

        let a = vec![1, 2, 3];
        let b = vec![1, 2, 3, 4];

        assert!(!CryptoModule::constant_time_compare(&mut cx, &a, &b).0);
    }

    #[test]
    fn test_random_bytes() {
        let mut cx = FunctionContext::new();

        let bytes = CryptoModule::random_bytes(&mut cx, 32).unwrap();
        assert_eq!(bytes.0.len(), 32);
    }

    #[test]
    fn test_random_bytes_too_large() {
        let mut cx = FunctionContext::new();

        assert!(CryptoModule::random_bytes(&mut cx, 100_000).is_err());
    }
}
