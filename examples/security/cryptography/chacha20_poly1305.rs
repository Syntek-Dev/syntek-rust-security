//! ChaCha20-Poly1305 Authenticated Encryption Example
//!
//! Demonstrates ChaCha20-Poly1305 AEAD cipher - an alternative to AES-GCM
//! that doesn't require hardware acceleration for good performance.

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid format")]
    InvalidFormat,
}

/// ChaCha20-Poly1305 cipher (96-bit nonce)
pub struct ChaCha20Cipher {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Cipher {
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::from_slice(key);
        Self {
            cipher: ChaCha20Poly1305::new(key),
        }
    }

    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        use rand::RngCore;
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Encrypt with random nonce
    /// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend(ciphertext);

        Ok(result)
    }

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
}

/// XChaCha20-Poly1305 cipher (192-bit nonce)
/// Extended nonce version - safer for random nonce generation
pub struct XChaCha20Cipher {
    cipher: XChaCha20Poly1305,
}

impl XChaCha20Cipher {
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::from_slice(key);
        Self {
            cipher: XChaCha20Poly1305::new(key),
        }
    }

    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        use rand::RngCore;
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Encrypt with random 192-bit nonce
    /// The larger nonce makes random generation much safer
    /// Returns: nonce (24 bytes) || ciphertext || tag (16 bytes)
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let mut result = Vec::with_capacity(24 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend(ciphertext);

        Ok(result)
    }

    /// Encrypt with AAD
    pub fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use chacha20poly1305::aead::Payload;

        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        let payload = Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = self
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let mut result = Vec::with_capacity(24 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend(ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < 24 + 16 {
            return Err(CryptoError::InvalidFormat);
        }

        let (nonce_bytes, ct) = ciphertext.split_at(24);
        let nonce = XNonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ct)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    pub fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use chacha20poly1305::aead::Payload;

        if ciphertext.len() < 24 + 16 {
            return Err(CryptoError::InvalidFormat);
        }

        let (nonce_bytes, ct) = ciphertext.split_at(24);
        let nonce = XNonce::from_slice(nonce_bytes);

        let payload = Payload { msg: ct, aad };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

/// Comparison of ChaCha20 vs AES-GCM characteristics
pub fn cipher_comparison() {
    println!("=== Cipher Comparison ===\n");

    println!("ChaCha20-Poly1305:");
    println!("  - Nonce size: 96 bits (12 bytes)");
    println!("  - Key size: 256 bits");
    println!("  - Tag size: 128 bits (16 bytes)");
    println!("  - Software performance: Excellent");
    println!("  - Hardware acceleration: Limited");
    println!("  - Side-channel resistance: Good (constant-time)");
    println!();

    println!("XChaCha20-Poly1305:");
    println!("  - Nonce size: 192 bits (24 bytes)");
    println!("  - Key size: 256 bits");
    println!("  - Tag size: 128 bits (16 bytes)");
    println!("  - Random nonce safety: Excellent");
    println!("  - Recommended for: Random nonce generation at scale");
    println!();

    println!("AES-256-GCM:");
    println!("  - Nonce size: 96 bits (12 bytes)");
    println!("  - Key size: 256 bits");
    println!("  - Tag size: 128 bits (16 bytes)");
    println!("  - Hardware acceleration: Excellent (AES-NI)");
    println!("  - Software performance: Moderate without AES-NI");
    println!();

    println!("Recommendations:");
    println!("  - Use XChaCha20-Poly1305 for random nonces");
    println!("  - Use ChaCha20-Poly1305 for counter-based nonces");
    println!("  - Use AES-GCM when hardware acceleration available");
}

/// Nonce management strategies
pub mod nonce_strategies {
    use super::*;

    /// Counter-based nonce (deterministic, requires state)
    pub struct CounterNonce {
        prefix: [u8; 4],
        counter: u64,
    }

    impl CounterNonce {
        pub fn new() -> Self {
            let mut prefix = [0u8; 4];
            use rand::RngCore;
            OsRng.fill_bytes(&mut prefix);
            Self { prefix, counter: 0 }
        }

        pub fn next(&mut self) -> [u8; 12] {
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&self.prefix);
            nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
            self.counter += 1;
            nonce
        }

        /// Check if nonce space is near exhaustion
        pub fn is_near_limit(&self) -> bool {
            // Warn when 75% of nonce space used
            self.counter > (u64::MAX / 4) * 3
        }
    }

    impl Default for CounterNonce {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Random nonce (stateless, small collision risk with 96-bit)
    pub fn random_nonce_96() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        use rand::RngCore;
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// Random nonce for XChaCha20 (stateless, negligible collision risk)
    pub fn random_nonce_192() -> [u8; 24] {
        let mut nonce = [0u8; 24];
        use rand::RngCore;
        OsRng.fill_bytes(&mut nonce);
        nonce
    }
}

fn main() {
    cipher_comparison();

    // ChaCha20-Poly1305 example
    println!("\n=== ChaCha20-Poly1305 ===\n");

    let key = ChaCha20Cipher::generate_key();
    let cipher = ChaCha20Cipher::new(&key);

    let plaintext = b"ChaCha20 is fast in software!";
    let ciphertext = cipher.encrypt(plaintext).unwrap();

    println!("Plaintext: {:?}", String::from_utf8_lossy(plaintext));
    println!("Ciphertext length: {} bytes", ciphertext.len());
    println!("Overhead: {} bytes", ciphertext.len() - plaintext.len());

    let decrypted = cipher.decrypt(&ciphertext).unwrap();
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    println!("Decryption successful!");

    // XChaCha20-Poly1305 example
    println!("\n=== XChaCha20-Poly1305 ===\n");

    let key = XChaCha20Cipher::generate_key();
    let cipher = XChaCha20Cipher::new(&key);

    let plaintext = b"Extended nonce for safer random generation!";
    let ciphertext = cipher.encrypt(plaintext).unwrap();

    println!("Plaintext: {:?}", String::from_utf8_lossy(plaintext));
    println!("Ciphertext length: {} bytes", ciphertext.len());
    println!(
        "Overhead: {} bytes (larger nonce)",
        ciphertext.len() - plaintext.len()
    );

    let decrypted = cipher.decrypt(&ciphertext).unwrap();
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    println!("Decryption successful!");

    // With AAD
    println!("\n=== With Associated Data ===\n");

    let aad = b"user-id:12345";
    let ciphertext = cipher.encrypt_with_aad(plaintext, aad).unwrap();
    let decrypted = cipher.decrypt_with_aad(&ciphertext, aad).unwrap();
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    println!("AAD verification successful!");

    // Wrong AAD fails
    let result = cipher.decrypt_with_aad(&ciphertext, b"user-id:99999");
    println!("Wrong AAD detected: {}", result.is_err());

    // Counter-based nonce example
    println!("\n=== Counter-Based Nonce Strategy ===\n");

    use nonce_strategies::CounterNonce;
    let mut nonce_gen = CounterNonce::new();

    for i in 0..5 {
        let nonce = nonce_gen.next();
        println!("Nonce {}: {:02x?}", i, &nonce[..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_encrypt_decrypt() {
        let key = ChaCha20Cipher::generate_key();
        let cipher = ChaCha20Cipher::new(&key);

        let plaintext = b"Test message";
        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_xchacha20_encrypt_decrypt() {
        let key = XChaCha20Cipher::generate_key();
        let cipher = XChaCha20Cipher::new(&key);

        let plaintext = b"Test message";
        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_xchacha20_aad() {
        let key = XChaCha20Cipher::generate_key();
        let cipher = XChaCha20Cipher::new(&key);

        let plaintext = b"Test message";
        let aad = b"context";

        let ciphertext = cipher.encrypt_with_aad(plaintext, aad).unwrap();
        let decrypted = cipher.decrypt_with_aad(&ciphertext, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());

        // Wrong AAD fails
        assert!(cipher.decrypt_with_aad(&ciphertext, b"wrong").is_err());
    }

    #[test]
    fn test_tamper_detection() {
        let key = XChaCha20Cipher::generate_key();
        let cipher = XChaCha20Cipher::new(&key);

        let plaintext = b"Test message";
        let mut ciphertext = cipher.encrypt(plaintext).unwrap();

        // Tamper
        ciphertext[30] ^= 0xFF;

        assert!(cipher.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_counter_nonce() {
        use nonce_strategies::CounterNonce;

        let mut gen = CounterNonce::new();
        let n1 = gen.next();
        let n2 = gen.next();

        // Nonces should be different
        assert_ne!(n1, n2);

        // Counter portion should increment
        assert_eq!(n1[..4], n2[..4]); // Same prefix
        assert_ne!(n1[4..], n2[4..]); // Different counter
    }
}
