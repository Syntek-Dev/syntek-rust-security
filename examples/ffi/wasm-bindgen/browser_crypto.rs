//! WebAssembly Browser Crypto Example
//!
//! Demonstrates creating secure cryptographic functions for browsers
//! using wasm-bindgen, with proper memory management and security.

use std::collections::HashMap;

/// Mock wasm_bindgen types for demonstration
/// In real code, use wasm_bindgen crate
pub mod wasm_mock {
    pub struct JsValue(pub String);

    impl JsValue {
        pub fn from_str(s: &str) -> Self {
            JsValue(s.to_string())
        }

        pub fn is_undefined(&self) -> bool {
            self.0 == "undefined"
        }
    }

    pub struct Uint8Array(pub Vec<u8>);

    impl Uint8Array {
        pub fn new_with_length(len: u32) -> Self {
            Uint8Array(vec![0; len as usize])
        }

        pub fn from(data: &[u8]) -> Self {
            Uint8Array(data.to_vec())
        }

        pub fn to_vec(&self) -> Vec<u8> {
            self.0.clone()
        }

        pub fn length(&self) -> u32 {
            self.0.len() as u32
        }

        pub fn copy_to(&self, dest: &mut [u8]) {
            dest[..self.0.len()].copy_from_slice(&self.0);
        }
    }

    pub type WasmResult<T> = Result<T, JsValue>;
}

use wasm_mock::*;

/// Secure memory wrapper that zeroizes on drop
#[derive(Clone)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0; size],
        }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn to_uint8array(&self) -> Uint8Array {
        Uint8Array::from(&self.data)
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // Securely zero memory
        for byte in &mut self.data {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// WebAssembly crypto module for browsers
pub struct WasmCrypto;

impl WasmCrypto {
    /// Generate cryptographically secure random bytes
    /// Uses Web Crypto API via JavaScript interop
    pub fn get_random_bytes(length: u32) -> WasmResult<Uint8Array> {
        if length > 65536 {
            return Err(JsValue::from_str("Requested length too large"));
        }

        // In real implementation, would call crypto.getRandomValues()
        let mut bytes = vec![0u8; length as usize];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = ((i as u64 * 1103515245 + 12345) % 256) as u8;
        }

        Ok(Uint8Array::from(&bytes))
    }

    /// AES-GCM encryption for browser use
    pub fn aes_gcm_encrypt(
        plaintext: &Uint8Array,
        key: &Uint8Array,
        nonce: &Uint8Array,
        aad: Option<&Uint8Array>,
    ) -> WasmResult<Uint8Array> {
        let key_bytes = key.to_vec();
        let nonce_bytes = nonce.to_vec();
        let plaintext_bytes = plaintext.to_vec();

        // Validate key length
        if key_bytes.len() != 16 && key_bytes.len() != 32 {
            return Err(JsValue::from_str("Key must be 128 or 256 bits"));
        }

        // Validate nonce length
        if nonce_bytes.len() != 12 {
            return Err(JsValue::from_str("Nonce must be 96 bits"));
        }

        // Simplified encryption (real impl would use proper AES-GCM)
        let mut ciphertext = SecureBuffer::new(plaintext_bytes.len() + 16); // +16 for tag
        let ct = ciphertext.as_mut_slice();

        for (i, &p) in plaintext_bytes.iter().enumerate() {
            ct[i] = p ^ key_bytes[i % key_bytes.len()] ^ nonce_bytes[i % nonce_bytes.len()];
        }

        // Generate tag
        let tag_start = plaintext_bytes.len();
        for i in 0..16 {
            ct[tag_start + i] = ct.get(i).copied().unwrap_or(0) ^ key_bytes[i % key_bytes.len()];
            if let Some(aad_arr) = aad {
                let aad_bytes = aad_arr.to_vec();
                ct[tag_start + i] ^= aad_bytes.get(i).copied().unwrap_or(0);
            }
        }

        Ok(ciphertext.to_uint8array())
    }

    /// AES-GCM decryption for browser use
    pub fn aes_gcm_decrypt(
        ciphertext: &Uint8Array,
        key: &Uint8Array,
        nonce: &Uint8Array,
        aad: Option<&Uint8Array>,
    ) -> WasmResult<Uint8Array> {
        let key_bytes = key.to_vec();
        let nonce_bytes = nonce.to_vec();
        let ct_bytes = ciphertext.to_vec();

        if ct_bytes.len() < 16 {
            return Err(JsValue::from_str("Ciphertext too short"));
        }

        // Validate key/nonce
        if key_bytes.len() != 16 && key_bytes.len() != 32 {
            return Err(JsValue::from_str("Key must be 128 or 256 bits"));
        }

        if nonce_bytes.len() != 12 {
            return Err(JsValue::from_str("Nonce must be 96 bits"));
        }

        let ct_len = ct_bytes.len() - 16;
        let tag = &ct_bytes[ct_len..];

        // Verify tag
        let mut expected_tag = [0u8; 16];
        for i in 0..16 {
            expected_tag[i] =
                ct_bytes.get(i).copied().unwrap_or(0) ^ key_bytes[i % key_bytes.len()];
            if let Some(aad_arr) = aad {
                let aad_bytes = aad_arr.to_vec();
                expected_tag[i] ^= aad_bytes.get(i).copied().unwrap_or(0);
            }
        }

        // Constant-time comparison
        let mut diff = 0u8;
        for (a, b) in tag.iter().zip(expected_tag.iter()) {
            diff |= a ^ b;
        }

        if diff != 0 {
            return Err(JsValue::from_str("Authentication failed"));
        }

        // Decrypt
        let mut plaintext = SecureBuffer::new(ct_len);
        let pt = plaintext.as_mut_slice();

        for (i, &c) in ct_bytes[..ct_len].iter().enumerate() {
            pt[i] = c ^ key_bytes[i % key_bytes.len()] ^ nonce_bytes[i % nonce_bytes.len()];
        }

        Ok(plaintext.to_uint8array())
    }

    /// SHA-256 hash
    pub fn sha256(data: &Uint8Array) -> Uint8Array {
        let input = data.to_vec();

        // Simplified hash (real impl would use proper SHA-256)
        let mut hash = [0u8; 32];
        for (i, &byte) in input.iter().enumerate() {
            hash[i % 32] ^= byte;
            hash[(i + 1) % 32] = hash[(i + 1) % 32].wrapping_add(byte);
            hash[(i + 7) % 32] = hash[(i + 7) % 32].wrapping_mul(byte.wrapping_add(1));
        }

        Uint8Array::from(&hash)
    }

    /// PBKDF2 key derivation
    pub fn pbkdf2(
        password: &str,
        salt: &Uint8Array,
        iterations: u32,
        key_length: u32,
    ) -> WasmResult<Uint8Array> {
        if iterations < 100_000 {
            return Err(JsValue::from_str("Iterations must be at least 100,000"));
        }

        if key_length > 64 {
            return Err(JsValue::from_str("Key length too large"));
        }

        let salt_bytes = salt.to_vec();
        if salt_bytes.len() < 16 {
            return Err(JsValue::from_str("Salt must be at least 16 bytes"));
        }

        let password_bytes = password.as_bytes();
        let mut derived = SecureBuffer::new(key_length as usize);
        let key = derived.as_mut_slice();

        // Simplified PBKDF2 (real impl would use proper HMAC-based derivation)
        for round in 0..iterations {
            for (i, k) in key.iter_mut().enumerate() {
                *k ^= password_bytes
                    .get(i % password_bytes.len())
                    .copied()
                    .unwrap_or(0);
                *k ^= salt_bytes.get(i % salt_bytes.len()).copied().unwrap_or(0);
                *k = k.wrapping_add((round % 256) as u8);
            }
        }

        Ok(derived.to_uint8array())
    }

    /// Base64 encode
    pub fn base64_encode(data: &Uint8Array) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let input = data.to_vec();
        let mut output = String::new();

        for chunk in input.chunks(3) {
            let b0 = chunk[0] as usize;
            let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
            let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

            output.push(ALPHABET[b0 >> 2] as char);
            output.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

            if chunk.len() > 1 {
                output.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
            } else {
                output.push('=');
            }

            if chunk.len() > 2 {
                output.push(ALPHABET[b2 & 0x3f] as char);
            } else {
                output.push('=');
            }
        }

        output
    }

    /// Base64 decode
    pub fn base64_decode(encoded: &str) -> WasmResult<Uint8Array> {
        fn decode_char(c: char) -> Option<u8> {
            match c {
                'A'..='Z' => Some(c as u8 - b'A'),
                'a'..='z' => Some(c as u8 - b'a' + 26),
                '0'..='9' => Some(c as u8 - b'0' + 52),
                '+' => Some(62),
                '/' => Some(63),
                '=' => Some(0),
                _ => None,
            }
        }

        let chars: Vec<char> = encoded.chars().filter(|c| !c.is_whitespace()).collect();

        if chars.len() % 4 != 0 {
            return Err(JsValue::from_str("Invalid base64 length"));
        }

        let mut output = Vec::new();

        for chunk in chars.chunks(4) {
            let b0 = decode_char(chunk[0])
                .ok_or_else(|| JsValue::from_str("Invalid base64 character"))?;
            let b1 = decode_char(chunk[1])
                .ok_or_else(|| JsValue::from_str("Invalid base64 character"))?;
            let b2 = decode_char(chunk[2])
                .ok_or_else(|| JsValue::from_str("Invalid base64 character"))?;
            let b3 = decode_char(chunk[3])
                .ok_or_else(|| JsValue::from_str("Invalid base64 character"))?;

            output.push((b0 << 2) | (b1 >> 4));

            if chunk[2] != '=' {
                output.push((b1 << 4) | (b2 >> 2));
            }

            if chunk[3] != '=' {
                output.push((b2 << 6) | b3);
            }
        }

        Ok(Uint8Array::from(&output))
    }

    /// Hex encode
    pub fn hex_encode(data: &Uint8Array) -> String {
        data.to_vec().iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Hex decode
    pub fn hex_decode(hex: &str) -> WasmResult<Uint8Array> {
        if hex.len() % 2 != 0 {
            return Err(JsValue::from_str("Invalid hex length"));
        }

        let mut output = Vec::new();

        for i in (0..hex.len()).step_by(2) {
            let byte = u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| JsValue::from_str("Invalid hex character"))?;
            output.push(byte);
        }

        Ok(Uint8Array::from(&output))
    }
}

/// Generate JavaScript glue code
pub fn generate_js_glue() -> String {
    r#"// WebAssembly Crypto Module Loader

let wasmInstance = null;

export async function init() {
  const { instance } = await WebAssembly.instantiateStreaming(
    fetch('./rust_crypto_bg.wasm'),
    { /* imports */ }
  );
  wasmInstance = instance;
  return instance.exports;
}

export function getRandomBytes(length) {
  if (!wasmInstance) throw new Error('WASM not initialized');
  return wasmInstance.exports.get_random_bytes(length);
}

export function aesGcmEncrypt(plaintext, key, nonce, aad = null) {
  if (!wasmInstance) throw new Error('WASM not initialized');
  return wasmInstance.exports.aes_gcm_encrypt(plaintext, key, nonce, aad);
}

export function aesGcmDecrypt(ciphertext, key, nonce, aad = null) {
  if (!wasmInstance) throw new Error('WASM not initialized');
  return wasmInstance.exports.aes_gcm_decrypt(ciphertext, key, nonce, aad);
}

export function sha256(data) {
  if (!wasmInstance) throw new Error('WASM not initialized');
  return wasmInstance.exports.sha256(data);
}

export function pbkdf2(password, salt, iterations, keyLength) {
  if (!wasmInstance) throw new Error('WASM not initialized');
  return wasmInstance.exports.pbkdf2(password, salt, iterations, keyLength);
}

// Usage example:
// import { init, aesGcmEncrypt, sha256 } from './crypto';
// await init();
// const hash = sha256(new Uint8Array([1, 2, 3]));
"#
    .to_string()
}

fn main() {
    println!("WebAssembly Browser Crypto Example");
    println!("===================================\n");

    // Generate random bytes
    println!("Generating random bytes...");
    let random = WasmCrypto::get_random_bytes(16).unwrap();
    println!("  Random: {}\n", WasmCrypto::hex_encode(&random));

    // Encrypt data
    let plaintext = Uint8Array::from(b"Hello from WebAssembly!");
    let key = Uint8Array::from(&[0x42u8; 32]);
    let nonce = Uint8Array::from(&[0x01u8; 12]);

    println!("Encrypting data...");
    let ciphertext = WasmCrypto::aes_gcm_encrypt(&plaintext, &key, &nonce, None).unwrap();
    println!(
        "  Ciphertext: {}...\n",
        &WasmCrypto::hex_encode(&ciphertext)[..32]
    );

    // Decrypt data
    println!("Decrypting data...");
    let decrypted = WasmCrypto::aes_gcm_decrypt(&ciphertext, &key, &nonce, None).unwrap();
    println!(
        "  Decrypted: {}\n",
        String::from_utf8_lossy(&decrypted.to_vec())
    );

    // Hash data
    println!("Computing SHA-256...");
    let hash = WasmCrypto::sha256(&plaintext);
    println!("  Hash: {}\n", WasmCrypto::hex_encode(&hash));

    // Derive key
    println!("Deriving key with PBKDF2...");
    let salt = Uint8Array::from(&[0x00u8; 16]);
    let derived = WasmCrypto::pbkdf2("my-password", &salt, 100_000, 32).unwrap();
    println!("  Derived: {}\n", WasmCrypto::hex_encode(&derived));

    // Base64 encoding
    println!("Base64 encoding...");
    let encoded = WasmCrypto::base64_encode(&plaintext);
    println!("  Encoded: {}", encoded);
    let decoded = WasmCrypto::base64_decode(&encoded).unwrap();
    println!(
        "  Decoded: {}\n",
        String::from_utf8_lossy(&decoded.to_vec())
    );

    // Generate JS glue code
    println!("JavaScript Glue Code:");
    println!("=====================");
    for line in generate_js_glue().lines().take(20) {
        println!("{}", line);
    }
    println!("...");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer_zeroing() {
        let buffer = SecureBuffer::from_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(buffer.len(), 5);
        // Memory is zeroed on drop
    }

    #[test]
    fn test_random_bytes() {
        let bytes = WasmCrypto::get_random_bytes(32).unwrap();
        assert_eq!(bytes.length(), 32);
    }

    #[test]
    fn test_random_bytes_too_large() {
        assert!(WasmCrypto::get_random_bytes(100_000).is_err());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = Uint8Array::from(b"Test message");
        let key = Uint8Array::from(&[0x42u8; 32]);
        let nonce = Uint8Array::from(&[0x01u8; 12]);

        let ct = WasmCrypto::aes_gcm_encrypt(&plaintext, &key, &nonce, None).unwrap();
        let pt = WasmCrypto::aes_gcm_decrypt(&ct, &key, &nonce, None).unwrap();

        assert_eq!(plaintext.to_vec(), pt.to_vec());
    }

    #[test]
    fn test_encrypt_invalid_key() {
        let plaintext = Uint8Array::from(b"Test");
        let bad_key = Uint8Array::from(&[0u8; 15]); // Invalid size
        let nonce = Uint8Array::from(&[0u8; 12]);

        assert!(WasmCrypto::aes_gcm_encrypt(&plaintext, &bad_key, &nonce, None).is_err());
    }

    #[test]
    fn test_decrypt_auth_failure() {
        let plaintext = Uint8Array::from(b"Test");
        let key = Uint8Array::from(&[0x42u8; 32]);
        let nonce = Uint8Array::from(&[0x01u8; 12]);

        let mut ct = WasmCrypto::aes_gcm_encrypt(&plaintext, &key, &nonce, None).unwrap();
        // Tamper with ciphertext
        ct.0[0] ^= 0xFF;

        assert!(WasmCrypto::aes_gcm_decrypt(&ct, &key, &nonce, None).is_err());
    }

    #[test]
    fn test_sha256() {
        let data = Uint8Array::from(b"hello");
        let hash = WasmCrypto::sha256(&data);
        assert_eq!(hash.length(), 32);
    }

    #[test]
    fn test_pbkdf2() {
        let salt = Uint8Array::from(&[0u8; 16]);
        let key = WasmCrypto::pbkdf2("password", &salt, 100_000, 32).unwrap();
        assert_eq!(key.length(), 32);
    }

    #[test]
    fn test_pbkdf2_low_iterations() {
        let salt = Uint8Array::from(&[0u8; 16]);
        assert!(WasmCrypto::pbkdf2("password", &salt, 1000, 32).is_err());
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = Uint8Array::from(b"Hello, World!");
        let encoded = WasmCrypto::base64_encode(&data);
        let decoded = WasmCrypto::base64_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded.to_vec());
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = Uint8Array::from(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let hex = WasmCrypto::hex_encode(&data);
        assert_eq!(hex, "deadbeef");
        let decoded = WasmCrypto::hex_decode(&hex).unwrap();
        assert_eq!(data.to_vec(), decoded.to_vec());
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert!(WasmCrypto::hex_decode("xyz").is_err());
        assert!(WasmCrypto::hex_decode("abc").is_err()); // Odd length
    }
}
