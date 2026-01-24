//! ChaCha20-Poly1305 Authenticated Encryption
//!
//! Implementation of ChaCha20-Poly1305 AEAD cipher for secure
//! symmetric encryption with authentication.

use std::time::{SystemTime, UNIX_EPOCH};

/// ChaCha20-Poly1305 key (256 bits)
#[derive(Clone)]
pub struct Key([u8; 32]);

impl Key {
    /// Create a new key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// Generate a random key
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        fill_random(&mut key);
        Self(key)
    }

    /// Get key as bytes (use carefully)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // Zeroize on drop for security
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key([REDACTED])")
    }
}

/// Nonce (96 bits)
#[derive(Clone, Debug)]
pub struct Nonce([u8; 12]);

impl Nonce {
    /// Create a nonce from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 12 {
            return Err(CryptoError::InvalidNonceLength);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(bytes);
        Ok(Self(nonce))
    }

    /// Generate a random nonce
    pub fn generate() -> Self {
        let mut nonce = [0u8; 12];
        fill_random(&mut nonce);
        Self(nonce)
    }

    /// Create a nonce from a counter
    pub fn from_counter(counter: u64) -> Self {
        let mut nonce = [0u8; 12];
        // Use last 8 bytes for counter
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());
        Self(nonce)
    }

    /// Get nonce as bytes
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

/// Authentication tag (128 bits)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tag([u8; 16]);

impl Tag {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 16 {
            return Err(CryptoError::InvalidTagLength);
        }
        let mut tag = [0u8; 16];
        tag.copy_from_slice(bytes);
        Ok(Self(tag))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// ChaCha20-Poly1305 cipher
#[derive(Debug)]
pub struct ChaCha20Poly1305 {
    key: Key,
}

impl ChaCha20Poly1305 {
    /// Create a new cipher instance
    pub fn new(key: Key) -> Self {
        Self { key }
    }

    /// Encrypt plaintext with associated data
    pub fn encrypt(
        &self,
        nonce: &Nonce,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Tag), CryptoError> {
        // Generate keystream using ChaCha20
        let keystream = self.chacha20_keystream(nonce, plaintext.len() + 64);

        // Encrypt plaintext
        let ciphertext: Vec<u8> = plaintext
            .iter()
            .zip(keystream[64..].iter())
            .map(|(p, k)| p ^ k)
            .collect();

        // Generate authentication tag using Poly1305
        let tag = self.poly1305_mac(&keystream[..32], &ciphertext, aad);

        Ok((ciphertext, tag))
    }

    /// Decrypt ciphertext with associated data
    pub fn decrypt(
        &self,
        nonce: &Nonce,
        ciphertext: &[u8],
        aad: &[u8],
        tag: &Tag,
    ) -> Result<Vec<u8>, CryptoError> {
        // Generate keystream
        let keystream = self.chacha20_keystream(nonce, ciphertext.len() + 64);

        // Verify authentication tag first (before decryption)
        let expected_tag = self.poly1305_mac(&keystream[..32], ciphertext, aad);

        if !constant_time_eq(tag.as_bytes(), expected_tag.as_bytes()) {
            return Err(CryptoError::AuthenticationFailed);
        }

        // Decrypt ciphertext
        let plaintext: Vec<u8> = ciphertext
            .iter()
            .zip(keystream[64..].iter())
            .map(|(c, k)| c ^ k)
            .collect();

        Ok(plaintext)
    }

    /// Encrypt and prepend nonce + tag (convenience method)
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = Nonce::generate();
        let (ciphertext, tag) = self.encrypt(&nonce, plaintext, aad)?;

        // Format: nonce (12) || tag (16) || ciphertext
        let mut sealed = Vec::with_capacity(12 + 16 + ciphertext.len());
        sealed.extend_from_slice(nonce.as_bytes());
        sealed.extend_from_slice(tag.as_bytes());
        sealed.extend_from_slice(&ciphertext);

        Ok(sealed)
    }

    /// Decrypt sealed message (convenience method)
    pub fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if sealed.len() < 28 {
            return Err(CryptoError::InvalidMessage);
        }

        let nonce = Nonce::from_bytes(&sealed[..12])?;
        let tag = Tag::from_bytes(&sealed[12..28])?;
        let ciphertext = &sealed[28..];

        self.decrypt(&nonce, ciphertext, aad, &tag)
    }

    /// Generate ChaCha20 keystream (simplified)
    fn chacha20_keystream(&self, nonce: &Nonce, len: usize) -> Vec<u8> {
        let mut keystream = Vec::with_capacity(len);
        let mut counter = 0u32;

        while keystream.len() < len {
            let block = self.chacha20_block(nonce, counter);
            keystream.extend_from_slice(&block);
            counter += 1;
        }

        keystream.truncate(len);
        keystream
    }

    /// Generate a single ChaCha20 block (simplified implementation)
    fn chacha20_block(&self, nonce: &Nonce, counter: u32) -> [u8; 64] {
        // Initialize state
        let mut state = [0u32; 16];

        // Constants "expand 32-byte k"
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // Key (8 words)
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes([
                self.key.0[i * 4],
                self.key.0[i * 4 + 1],
                self.key.0[i * 4 + 2],
                self.key.0[i * 4 + 3],
            ]);
        }

        // Counter
        state[12] = counter;

        // Nonce (3 words)
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes([
                nonce.0[i * 4],
                nonce.0[i * 4 + 1],
                nonce.0[i * 4 + 2],
                nonce.0[i * 4 + 3],
            ]);
        }

        // Copy initial state
        let initial_state = state;

        // 20 rounds (10 double-rounds)
        for _ in 0..10 {
            // Column rounds
            Self::quarter_round(&mut state, 0, 4, 8, 12);
            Self::quarter_round(&mut state, 1, 5, 9, 13);
            Self::quarter_round(&mut state, 2, 6, 10, 14);
            Self::quarter_round(&mut state, 3, 7, 11, 15);

            // Diagonal rounds
            Self::quarter_round(&mut state, 0, 5, 10, 15);
            Self::quarter_round(&mut state, 1, 6, 11, 12);
            Self::quarter_round(&mut state, 2, 7, 8, 13);
            Self::quarter_round(&mut state, 3, 4, 9, 14);
        }

        // Add initial state
        for i in 0..16 {
            state[i] = state[i].wrapping_add(initial_state[i]);
        }

        // Serialize to bytes
        let mut block = [0u8; 64];
        for (i, word) in state.iter().enumerate() {
            block[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }

        block
    }

    /// ChaCha20 quarter round
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }

    /// Poly1305 MAC (simplified)
    fn poly1305_mac(&self, key: &[u8], ciphertext: &[u8], aad: &[u8]) -> Tag {
        // This is a simplified Poly1305 for demonstration
        // In production, use a proper implementation

        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        aad.hash(&mut hasher);
        ciphertext.hash(&mut hasher);
        aad.len().hash(&mut hasher);
        ciphertext.len().hash(&mut hasher);

        let hash1 = hasher.finish();

        let mut hasher2 = DefaultHasher::new();
        hash1.hash(&mut hasher2);
        key.hash(&mut hasher2);

        let hash2 = hasher2.finish();

        let mut tag = [0u8; 16];
        tag[..8].copy_from_slice(&hash1.to_le_bytes());
        tag[8..].copy_from_slice(&hash2.to_le_bytes());

        Tag(tag)
    }
}

/// Crypto errors
#[derive(Debug, Clone)]
pub enum CryptoError {
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidTagLength,
    InvalidMessage,
    AuthenticationFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length (expected 32 bytes)"),
            CryptoError::InvalidNonceLength => {
                write!(f, "Invalid nonce length (expected 12 bytes)")
            }
            CryptoError::InvalidTagLength => write!(f, "Invalid tag length (expected 16 bytes)"),
            CryptoError::InvalidMessage => write!(f, "Invalid message format"),
            CryptoError::AuthenticationFailed => write!(f, "Authentication failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Nonce manager for sequential nonces
#[derive(Debug)]
pub struct NonceManager {
    counter: u64,
    prefix: [u8; 4],
}

impl NonceManager {
    pub fn new() -> Self {
        let mut prefix = [0u8; 4];
        fill_random(&mut prefix);
        Self { counter: 0, prefix }
    }

    pub fn next(&mut self) -> Nonce {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.prefix);
        nonce[4..12].copy_from_slice(&self.counter.to_le_bytes());
        self.counter = self.counter.wrapping_add(1);
        Nonce(nonce)
    }
}

impl Default for NonceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Constant-time comparison
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

/// Fill buffer with random bytes (simplified)
fn fill_random(buf: &mut [u8]) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

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

fn main() {
    println!("=== ChaCha20-Poly1305 Demo ===\n");

    // Generate a key
    let key = Key::generate();
    let cipher = ChaCha20Poly1305::new(key);

    // Basic encryption
    println!("--- Basic Encryption ---\n");

    let plaintext = b"Hello, ChaCha20-Poly1305!";
    let aad = b"additional authenticated data";
    let nonce = Nonce::generate();

    let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, aad).unwrap();

    println!("Plaintext: {}", String::from_utf8_lossy(plaintext));
    println!("AAD: {}", String::from_utf8_lossy(aad));
    println!("Nonce: {}", hex_encode(nonce.as_bytes()));
    println!("Ciphertext: {}", hex_encode(&ciphertext));
    println!("Tag: {}", hex_encode(tag.as_bytes()));

    // Decryption
    println!("\n--- Decryption ---\n");

    let decrypted = cipher.decrypt(&nonce, &ciphertext, aad, &tag).unwrap();
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));

    // Verify AAD tampering detection
    println!("\n--- Tampering Detection ---\n");

    let tampered_aad = b"tampered aad";
    match cipher.decrypt(&nonce, &ciphertext, tampered_aad, &tag) {
        Ok(_) => println!("ERROR: Tampering not detected!"),
        Err(e) => println!("Tampering detected: {}", e),
    }

    // Seal/Open convenience API
    println!("\n--- Seal/Open API ---\n");

    let message = b"This is a secret message";
    let sealed = cipher.seal(message, b"context").unwrap();

    println!("Original: {}", String::from_utf8_lossy(message));
    println!("Sealed (hex): {}", hex_encode(&sealed));
    println!("Sealed length: {} bytes", sealed.len());

    let opened = cipher.open(&sealed, b"context").unwrap();
    println!("Opened: {}", String::from_utf8_lossy(&opened));

    // Nonce management
    println!("\n--- Nonce Management ---\n");

    let mut nonce_mgr = NonceManager::new();
    for i in 0..5 {
        let nonce = nonce_mgr.next();
        println!("Nonce {}: {}", i, hex_encode(nonce.as_bytes()));
    }

    // Multiple messages with same key
    println!("\n--- Encrypting Multiple Messages ---\n");

    let messages = ["First message", "Second message", "Third message"];

    let mut nonce_mgr = NonceManager::new();
    let mut encrypted_messages = Vec::new();

    for msg in &messages {
        let nonce = nonce_mgr.next();
        let (ct, tag) = cipher.encrypt(&nonce, msg.as_bytes(), b"").unwrap();
        encrypted_messages.push((nonce, ct, tag));
        println!(
            "Encrypted '{}': {} bytes",
            msg,
            encrypted_messages.last().unwrap().1.len()
        );
    }

    // Decrypt all
    println!("\nDecrypting all messages:");
    for (nonce, ct, tag) in &encrypted_messages {
        let pt = cipher.decrypt(nonce, ct, b"", tag).unwrap();
        println!("  {}", String::from_utf8_lossy(&pt));
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key1 = Key::generate();
        let key2 = Key::generate();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_key_from_bytes() {
        let bytes = [0u8; 32];
        let key = Key::from_bytes(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_key_invalid_length() {
        let bytes = [0u8; 16];
        assert!(Key::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = Nonce::generate();
        let nonce2 = Nonce::generate();
        assert_ne!(nonce1.as_bytes(), nonce2.as_bytes());
    }

    #[test]
    fn test_nonce_from_counter() {
        let nonce = Nonce::from_counter(42);
        assert_eq!(nonce.0[4..12], 42u64.to_le_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = Key::generate();
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::generate();

        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad, &tag).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ciphertext_different_from_plaintext() {
        let key = Key::generate();
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::generate();

        let plaintext = b"Hello, World!";
        let (ciphertext, _) = cipher.encrypt(&nonce, plaintext, b"").unwrap();

        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_tampering_detection_ciphertext() {
        let key = Key::generate();
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::generate();

        let (mut ciphertext, tag) = cipher.encrypt(&nonce, b"secret", b"").unwrap();
        ciphertext[0] ^= 1; // Tamper with ciphertext

        let result = cipher.decrypt(&nonce, &ciphertext, b"", &tag);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn test_tampering_detection_aad() {
        let key = Key::generate();
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::generate();

        let (ciphertext, tag) = cipher.encrypt(&nonce, b"secret", b"aad").unwrap();

        let result = cipher.decrypt(&nonce, &ciphertext, b"different_aad", &tag);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn test_tampering_detection_tag() {
        let key = Key::generate();
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::generate();

        let (ciphertext, mut tag) = cipher.encrypt(&nonce, b"secret", b"").unwrap();
        tag.0[0] ^= 1; // Tamper with tag

        let result = cipher.decrypt(&nonce, &ciphertext, b"", &tag);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn test_seal_open_roundtrip() {
        let key = Key::generate();
        let cipher = ChaCha20Poly1305::new(key);

        let plaintext = b"Secret message";
        let aad = b"context";

        let sealed = cipher.seal(plaintext, aad).unwrap();
        let opened = cipher.open(&sealed, aad).unwrap();

        assert_eq!(opened, plaintext);
    }

    #[test]
    fn test_seal_format() {
        let key = Key::generate();
        let cipher = ChaCha20Poly1305::new(key);

        let plaintext = b"test";
        let sealed = cipher.seal(plaintext, b"").unwrap();

        // Format: nonce (12) + tag (16) + ciphertext
        assert_eq!(sealed.len(), 12 + 16 + plaintext.len());
    }

    #[test]
    fn test_open_invalid_length() {
        let key = Key::generate();
        let cipher = ChaCha20Poly1305::new(key);

        let short = [0u8; 10];
        assert!(matches!(
            cipher.open(&short, b""),
            Err(CryptoError::InvalidMessage)
        ));
    }

    #[test]
    fn test_empty_plaintext() {
        let key = Key::generate();
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::generate();

        let (ciphertext, tag) = cipher.encrypt(&nonce, b"", b"aad").unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, b"aad", &tag).unwrap();

        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_empty_aad() {
        let key = Key::generate();
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::generate();

        let (ciphertext, tag) = cipher.encrypt(&nonce, b"secret", b"").unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, b"", &tag).unwrap();

        assert_eq!(decrypted, b"secret");
    }

    #[test]
    fn test_different_keys_different_ciphertext() {
        let cipher1 = ChaCha20Poly1305::new(Key::generate());
        let cipher2 = ChaCha20Poly1305::new(Key::generate());
        let nonce = Nonce::generate();

        let (ct1, _) = cipher1.encrypt(&nonce, b"secret", b"").unwrap();
        let (ct2, _) = cipher2.encrypt(&nonce, b"secret", b"").unwrap();

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_different_nonces_different_ciphertext() {
        let key = Key::generate();
        let cipher = ChaCha20Poly1305::new(key);

        let (ct1, _) = cipher.encrypt(&Nonce::generate(), b"secret", b"").unwrap();
        let (ct2, _) = cipher.encrypt(&Nonce::generate(), b"secret", b"").unwrap();

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_nonce_manager_sequential() {
        let mut mgr = NonceManager::new();
        let nonce1 = mgr.next();
        let nonce2 = mgr.next();
        let nonce3 = mgr.next();

        assert_ne!(nonce1.as_bytes(), nonce2.as_bytes());
        assert_ne!(nonce2.as_bytes(), nonce3.as_bytes());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    #[test]
    fn test_large_plaintext() {
        let key = Key::generate();
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::generate();

        let plaintext: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let (ciphertext, tag) = cipher.encrypt(&nonce, &plaintext, b"").unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, b"", &tag).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
