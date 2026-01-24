//! AES-GCM Authenticated Encryption Example
//!
//! Demonstrates secure AES-256-GCM encryption with proper nonce handling.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed - data may be tampered")]
    DecryptionFailed,
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Invalid ciphertext format")]
    InvalidFormat,
}

/// AES-256-GCM cipher wrapper with secure defaults
pub struct AesGcmCipher {
    cipher: Aes256Gcm,
}

impl AesGcmCipher {
    /// Create a new cipher with the provided 256-bit key
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key);
        Self {
            cipher: Aes256Gcm::new(key),
        }
    }

    /// Generate a new random 256-bit key
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        use rand::RngCore;
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Encrypt data with a random nonce
    /// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Generate random 96-bit nonce (NIST recommended)
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend(ciphertext);

        Ok(result)
    }

    /// Encrypt data with Additional Authenticated Data (AAD)
    /// AAD is authenticated but not encrypted
    pub fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use aes_gcm::aead::Payload;

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let payload = Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = self
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend(ciphertext);

        Ok(result)
    }

    /// Decrypt data encrypted with encrypt()
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < 12 + 16 {
            return Err(CryptoError::InvalidFormat);
        }

        let (nonce_bytes, ct) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ct)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    /// Decrypt data with AAD verification
    pub fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use aes_gcm::aead::Payload;

        if ciphertext.len() < 12 + 16 {
            return Err(CryptoError::InvalidFormat);
        }

        let (nonce_bytes, ct) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let payload = Payload { msg: ct, aad };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

/// Streaming encryption for large files
pub struct StreamingEncryptor {
    cipher: Aes256Gcm,
    nonce_counter: u64,
    base_nonce: [u8; 4],
}

impl StreamingEncryptor {
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let mut base_nonce = [0u8; 4];
        use rand::RngCore;
        OsRng.fill_bytes(&mut base_nonce);

        Self {
            cipher: Aes256Gcm::new(key),
            nonce_counter: 0,
            base_nonce,
        }
    }

    /// Get the base nonce (must be stored with ciphertext for decryption)
    pub fn base_nonce(&self) -> &[u8; 4] {
        &self.base_nonce
    }

    /// Encrypt a chunk of data
    pub fn encrypt_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.next_nonce();

        self.cipher
            .encrypt(&nonce, chunk)
            .map_err(|_| CryptoError::EncryptionFailed)
    }

    fn next_nonce(&mut self) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&self.base_nonce);
        nonce_bytes[4..].copy_from_slice(&self.nonce_counter.to_be_bytes());
        self.nonce_counter += 1;
        *Nonce::from_slice(&nonce_bytes)
    }
}

/// Streaming decryptor for large files
pub struct StreamingDecryptor {
    cipher: Aes256Gcm,
    nonce_counter: u64,
    base_nonce: [u8; 4],
}

impl StreamingDecryptor {
    pub fn new(key: &[u8; 32], base_nonce: [u8; 4]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key);

        Self {
            cipher: Aes256Gcm::new(key),
            nonce_counter: 0,
            base_nonce,
        }
    }

    /// Decrypt a chunk of data
    pub fn decrypt_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.next_nonce();

        self.cipher
            .decrypt(&nonce, chunk)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    fn next_nonce(&mut self) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&self.base_nonce);
        nonce_bytes[4..].copy_from_slice(&self.nonce_counter.to_be_bytes());
        self.nonce_counter += 1;
        *Nonce::from_slice(&nonce_bytes)
    }
}

fn main() {
    // Generate a random key
    let key = AesGcmCipher::generate_key();
    println!("Generated key: {} bytes", key.len());

    // Create cipher
    let cipher = AesGcmCipher::new(&key);

    // Basic encryption/decryption
    let plaintext = b"Hello, secure world!";
    println!("\nOriginal: {:?}", String::from_utf8_lossy(plaintext));

    let ciphertext = cipher.encrypt(plaintext).expect("Encryption failed");
    println!("Ciphertext length: {} bytes", ciphertext.len());
    println!(
        "Overhead: {} bytes (nonce + tag)",
        ciphertext.len() - plaintext.len()
    );

    let decrypted = cipher.decrypt(&ciphertext).expect("Decryption failed");
    println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted));

    // Encryption with AAD
    println!("\n--- With Additional Authenticated Data ---");
    let aad = b"message-id:12345";
    let ciphertext_aad = cipher
        .encrypt_with_aad(plaintext, aad)
        .expect("Encryption failed");

    // Correct AAD - decryption succeeds
    let decrypted_aad = cipher
        .decrypt_with_aad(&ciphertext_aad, aad)
        .expect("Decryption failed");
    println!(
        "Decrypted with correct AAD: {:?}",
        String::from_utf8_lossy(&decrypted_aad)
    );

    // Wrong AAD - decryption fails
    let wrong_aad = b"message-id:99999";
    let result = cipher.decrypt_with_aad(&ciphertext_aad, wrong_aad);
    println!("Decryption with wrong AAD: {:?}", result.is_err());

    // Demonstrate tamper detection
    println!("\n--- Tamper Detection ---");
    let mut tampered = ciphertext.clone();
    tampered[20] ^= 0xFF; // Flip some bits
    let result = cipher.decrypt(&tampered);
    println!("Tampered ciphertext detected: {:?}", result.is_err());

    // Streaming encryption for large data
    println!("\n--- Streaming Encryption ---");
    let large_data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
    let chunk_size = 256;

    let mut encryptor = StreamingEncryptor::new(&key);
    let base_nonce = *encryptor.base_nonce();

    let mut encrypted_chunks = Vec::new();
    for chunk in large_data.chunks(chunk_size) {
        let encrypted = encryptor
            .encrypt_chunk(chunk)
            .expect("Chunk encryption failed");
        encrypted_chunks.push(encrypted);
    }
    println!("Encrypted {} chunks", encrypted_chunks.len());

    // Decrypt chunks
    let mut decryptor = StreamingDecryptor::new(&key, base_nonce);
    let mut decrypted_data = Vec::new();
    for chunk in &encrypted_chunks {
        let decrypted = decryptor
            .decrypt_chunk(chunk)
            .expect("Chunk decryption failed");
        decrypted_data.extend(decrypted);
    }

    assert_eq!(large_data, decrypted_data);
    println!("Streaming decryption verified!");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = AesGcmCipher::generate_key();
        let cipher = AesGcmCipher::new(&key);

        let plaintext = b"Test message";
        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aad_verification() {
        let key = AesGcmCipher::generate_key();
        let cipher = AesGcmCipher::new(&key);

        let plaintext = b"Test message";
        let aad = b"context";

        let ciphertext = cipher.encrypt_with_aad(plaintext, aad).unwrap();

        // Correct AAD
        let decrypted = cipher.decrypt_with_aad(&ciphertext, aad).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());

        // Wrong AAD should fail
        let result = cipher.decrypt_with_aad(&ciphertext, b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_tamper_detection() {
        let key = AesGcmCipher::generate_key();
        let cipher = AesGcmCipher::new(&key);

        let plaintext = b"Test message";
        let mut ciphertext = cipher.encrypt(plaintext).unwrap();

        // Tamper with ciphertext
        ciphertext[15] ^= 0xFF;

        let result = cipher.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_streaming() {
        let key = AesGcmCipher::generate_key();
        let data: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();

        let mut encryptor = StreamingEncryptor::new(&key);
        let base_nonce = *encryptor.base_nonce();

        let mut encrypted = Vec::new();
        for chunk in data.chunks(100) {
            encrypted.push(encryptor.encrypt_chunk(chunk).unwrap());
        }

        let mut decryptor = StreamingDecryptor::new(&key, base_nonce);
        let mut decrypted = Vec::new();
        for chunk in &encrypted {
            decrypted.extend(decryptor.decrypt_chunk(chunk).unwrap());
        }

        assert_eq!(data, decrypted);
    }
}
