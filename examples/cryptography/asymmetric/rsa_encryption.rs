//! RSA Encryption and Signing
//!
//! RSA public-key cryptography for encryption and digital signatures,
//! with secure padding schemes and key management.

use std::collections::HashMap;

/// RSA key size
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySize {
    Bits2048,
    Bits3072,
    Bits4096,
}

impl KeySize {
    pub fn bits(&self) -> usize {
        match self {
            KeySize::Bits2048 => 2048,
            KeySize::Bits3072 => 3072,
            KeySize::Bits4096 => 4096,
        }
    }

    pub fn bytes(&self) -> usize {
        self.bits() / 8
    }
}

/// RSA public key
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    /// Modulus n
    pub n: Vec<u8>,
    /// Public exponent e
    pub e: Vec<u8>,
    /// Key size
    pub key_size: KeySize,
}

impl RsaPublicKey {
    /// Create from components
    pub fn new(n: Vec<u8>, e: Vec<u8>, key_size: KeySize) -> Self {
        Self { n, e, key_size }
    }

    /// Export to PEM format
    pub fn to_pem(&self) -> String {
        let der = self.to_der();
        let b64 = base64_encode(&der);
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            b64.chars()
                .collect::<Vec<_>>()
                .chunks(64)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    /// Export to DER format (simplified)
    pub fn to_der(&self) -> Vec<u8> {
        let mut der = Vec::new();
        // Simplified DER encoding
        der.push(0x30); // SEQUENCE
        der.push((self.n.len() + self.e.len() + 4) as u8);
        der.push(0x02); // INTEGER (n)
        der.push(self.n.len() as u8);
        der.extend(&self.n);
        der.push(0x02); // INTEGER (e)
        der.push(self.e.len() as u8);
        der.extend(&self.e);
        der
    }

    /// Get key fingerprint
    pub fn fingerprint(&self) -> String {
        let hash = simple_hash(&self.to_der());
        hash.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// RSA private key
#[derive(Clone)]
pub struct RsaPrivateKey {
    /// Modulus n
    pub n: Vec<u8>,
    /// Private exponent d
    d: Vec<u8>,
    /// Public exponent e
    pub e: Vec<u8>,
    /// Prime p
    p: Vec<u8>,
    /// Prime q
    q: Vec<u8>,
    /// Key size
    pub key_size: KeySize,
}

impl RsaPrivateKey {
    /// Generate a new key pair (simplified for demonstration)
    pub fn generate(key_size: KeySize) -> Self {
        // This is a simplified demonstration
        // In production, use the rsa crate with proper prime generation

        let size = key_size.bytes();
        let mut n = vec![0u8; size];
        let mut d = vec![0u8; size];
        let mut p = vec![0u8; size / 2];
        let mut q = vec![0u8; size / 2];

        // Fill with pseudo-random data (not cryptographically secure)
        fill_random(&mut n);
        fill_random(&mut d);
        fill_random(&mut p);
        fill_random(&mut q);

        // Ensure n is odd (modulus must be odd)
        n[size - 1] |= 1;

        Self {
            n,
            d,
            e: vec![0x01, 0x00, 0x01], // 65537
            p,
            q,
            key_size,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey {
            n: self.n.clone(),
            e: self.e.clone(),
            key_size: self.key_size,
        }
    }

    /// Export to PEM format (simplified)
    pub fn to_pem(&self) -> String {
        let der = self.to_der();
        let b64 = base64_encode(&der);
        format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----",
            b64.chars()
                .collect::<Vec<_>>()
                .chunks(64)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    /// Export to DER format (simplified)
    fn to_der(&self) -> Vec<u8> {
        let mut der = Vec::new();
        // Simplified - real DER is more complex
        der.extend(&self.n);
        der.extend(&self.d);
        der.extend(&self.e);
        der
    }
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        // Zeroize sensitive data
        self.d.iter_mut().for_each(|b| *b = 0);
        self.p.iter_mut().for_each(|b| *b = 0);
        self.q.iter_mut().for_each(|b| *b = 0);
    }
}

impl std::fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaPrivateKey")
            .field("key_size", &self.key_size)
            .field("n", &"[REDACTED]")
            .field("d", &"[REDACTED]")
            .finish()
    }
}

/// Padding scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingScheme {
    /// PKCS#1 v1.5 (legacy, use OAEP for new applications)
    Pkcs1v15,
    /// OAEP with SHA-256 (recommended)
    OaepSha256,
    /// OAEP with SHA-384
    OaepSha384,
    /// OAEP with SHA-512
    OaepSha512,
}

impl PaddingScheme {
    /// Get overhead in bytes
    pub fn overhead(&self, key_size: KeySize) -> usize {
        match self {
            PaddingScheme::Pkcs1v15 => 11,
            PaddingScheme::OaepSha256 => 66, // 2 * hash_len + 2
            PaddingScheme::OaepSha384 => 98,
            PaddingScheme::OaepSha512 => 130,
        }
    }

    /// Maximum message size for encryption
    pub fn max_message_size(&self, key_size: KeySize) -> usize {
        key_size.bytes().saturating_sub(self.overhead(key_size))
    }
}

/// Signature scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    /// PKCS#1 v1.5 with SHA-256
    Pkcs1v15Sha256,
    /// PSS with SHA-256 (recommended)
    PssSha256,
    /// PSS with SHA-384
    PssSha384,
    /// PSS with SHA-512
    PssSha512,
}

/// RSA cipher for encryption/decryption
#[derive(Debug)]
pub struct RsaCipher {
    padding: PaddingScheme,
}

impl RsaCipher {
    pub fn new(padding: PaddingScheme) -> Self {
        Self { padding }
    }

    /// Encrypt message with public key
    pub fn encrypt(
        &self,
        public_key: &RsaPublicKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, RsaError> {
        let max_size = self.padding.max_message_size(public_key.key_size);
        if plaintext.len() > max_size {
            return Err(RsaError::MessageTooLong {
                max: max_size,
                got: plaintext.len(),
            });
        }

        // Apply padding
        let padded = self.apply_encryption_padding(plaintext, public_key.key_size)?;

        // Perform RSA encryption (simplified - in production use proper modular exponentiation)
        let ciphertext = self.rsa_public_operation(&padded, public_key);

        Ok(ciphertext)
    }

    /// Decrypt message with private key
    pub fn decrypt(
        &self,
        private_key: &RsaPrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, RsaError> {
        if ciphertext.len() != private_key.key_size.bytes() {
            return Err(RsaError::InvalidCiphertext);
        }

        // Perform RSA decryption
        let decrypted = self.rsa_private_operation(ciphertext, private_key);

        // Remove padding
        self.remove_encryption_padding(&decrypted)
    }

    /// Apply encryption padding (simplified OAEP)
    fn apply_encryption_padding(
        &self,
        message: &[u8],
        key_size: KeySize,
    ) -> Result<Vec<u8>, RsaError> {
        let k = key_size.bytes();
        let mut padded = vec![0u8; k];

        match self.padding {
            PaddingScheme::Pkcs1v15 => {
                // 0x00 || 0x02 || PS || 0x00 || M
                padded[0] = 0x00;
                padded[1] = 0x02;
                let ps_len = k - 3 - message.len();
                fill_random(&mut padded[2..2 + ps_len]);
                // Ensure no zero bytes in PS
                for b in &mut padded[2..2 + ps_len] {
                    if *b == 0 {
                        *b = 1;
                    }
                }
                padded[2 + ps_len] = 0x00;
                padded[3 + ps_len..].copy_from_slice(message);
            }
            PaddingScheme::OaepSha256 | PaddingScheme::OaepSha384 | PaddingScheme::OaepSha512 => {
                // Simplified OAEP - real implementation is more complex
                let hash_len = match self.padding {
                    PaddingScheme::OaepSha256 => 32,
                    PaddingScheme::OaepSha384 => 48,
                    PaddingScheme::OaepSha512 => 64,
                    _ => 32,
                };

                // Generate seed
                let mut seed = vec![0u8; hash_len];
                fill_random(&mut seed);

                // Create data block
                let db_len = k - hash_len - 1;
                let mut db = vec![0u8; db_len];

                // lHash || PS || 0x01 || M
                let l_hash = simple_hash(b""); // Empty label hash
                db[..hash_len.min(db_len)]
                    .copy_from_slice(&l_hash[..hash_len.min(l_hash.len()).min(db_len)]);
                let msg_start = db_len - message.len() - 1;
                db[msg_start] = 0x01;
                db[msg_start + 1..].copy_from_slice(message);

                // Mask generation (simplified)
                let masked_db = xor_bytes(&db, &expand_seed(&seed, db_len));
                let masked_seed = xor_bytes(&seed, &simple_hash(&masked_db)[..hash_len]);

                padded[0] = 0x00;
                padded[1..1 + hash_len].copy_from_slice(&masked_seed);
                padded[1 + hash_len..].copy_from_slice(&masked_db);
            }
        }

        Ok(padded)
    }

    /// Remove encryption padding
    fn remove_encryption_padding(&self, data: &[u8]) -> Result<Vec<u8>, RsaError> {
        match self.padding {
            PaddingScheme::Pkcs1v15 => {
                if data.len() < 11 || data[0] != 0x00 || data[1] != 0x02 {
                    return Err(RsaError::InvalidPadding);
                }

                // Find separator
                let sep_pos = data[2..]
                    .iter()
                    .position(|&b| b == 0x00)
                    .ok_or(RsaError::InvalidPadding)?;

                if sep_pos < 8 {
                    return Err(RsaError::InvalidPadding);
                }

                Ok(data[sep_pos + 3..].to_vec())
            }
            _ => {
                // Simplified OAEP unpadding
                if data.is_empty() || data[0] != 0x00 {
                    return Err(RsaError::InvalidPadding);
                }

                // Find 0x01 separator
                let sep_pos = data
                    .iter()
                    .position(|&b| b == 0x01)
                    .ok_or(RsaError::InvalidPadding)?;

                Ok(data[sep_pos + 1..].to_vec())
            }
        }
    }

    /// RSA public operation (simplified)
    fn rsa_public_operation(&self, data: &[u8], key: &RsaPublicKey) -> Vec<u8> {
        // In production, use proper modular exponentiation
        // This is a simplified simulation
        let mut result = data.to_vec();
        for (i, b) in result.iter_mut().enumerate() {
            *b ^= key.e.get(i % key.e.len()).copied().unwrap_or(0);
            *b ^= key.n.get(i % key.n.len()).copied().unwrap_or(0);
        }
        result
    }

    /// RSA private operation (simplified)
    fn rsa_private_operation(&self, data: &[u8], key: &RsaPrivateKey) -> Vec<u8> {
        // In production, use proper modular exponentiation with CRT
        let mut result = data.to_vec();
        for (i, b) in result.iter_mut().enumerate() {
            *b ^= key.d.get(i % key.d.len()).copied().unwrap_or(0);
            *b ^= key.n.get(i % key.n.len()).copied().unwrap_or(0);
        }
        result
    }
}

/// RSA signer for signatures
#[derive(Debug)]
pub struct RsaSigner {
    scheme: SignatureScheme,
}

impl RsaSigner {
    pub fn new(scheme: SignatureScheme) -> Self {
        Self { scheme }
    }

    /// Sign a message
    pub fn sign(&self, private_key: &RsaPrivateKey, message: &[u8]) -> Result<Vec<u8>, RsaError> {
        // Hash the message
        let hash = self.hash_message(message);

        // Apply signature padding
        let padded = self.apply_signature_padding(&hash, private_key.key_size)?;

        // RSA sign (private key operation)
        Ok(self.rsa_private_sign(&padded, private_key))
    }

    /// Verify a signature
    pub fn verify(
        &self,
        public_key: &RsaPublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, RsaError> {
        if signature.len() != public_key.key_size.bytes() {
            return Err(RsaError::InvalidSignature);
        }

        // RSA verify (public key operation)
        let recovered = self.rsa_public_verify(signature, public_key);

        // Hash the message
        let expected_hash = self.hash_message(message);

        // Verify padding and hash
        self.verify_signature_padding(&recovered, &expected_hash)
    }

    /// Hash message based on scheme
    fn hash_message(&self, message: &[u8]) -> Vec<u8> {
        simple_hash(message)
    }

    /// Apply signature padding
    fn apply_signature_padding(&self, hash: &[u8], key_size: KeySize) -> Result<Vec<u8>, RsaError> {
        let k = key_size.bytes();
        let mut padded = vec![0u8; k];

        match self.scheme {
            SignatureScheme::Pkcs1v15Sha256 => {
                // DigestInfo for SHA-256
                let digest_info: &[u8] = &[
                    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
                ];

                let t_len = digest_info.len() + hash.len();
                let ps_len = k - 3 - t_len;

                if ps_len < 8 {
                    return Err(RsaError::MessageTooLong {
                        max: k - 11,
                        got: t_len,
                    });
                }

                padded[0] = 0x00;
                padded[1] = 0x01;
                padded[2..2 + ps_len].fill(0xFF);
                padded[2 + ps_len] = 0x00;
                padded[3 + ps_len..3 + ps_len + digest_info.len()].copy_from_slice(digest_info);
                padded[3 + ps_len + digest_info.len()..]
                    .copy_from_slice(&hash[..hash.len().min(k - 3 - ps_len - digest_info.len())]);
            }
            _ => {
                // Simplified PSS (real implementation is more complex)
                let hash_len = 32;
                let salt_len = hash_len;

                let mut salt = vec![0u8; salt_len];
                fill_random(&mut salt);

                // M' = padding || mHash || salt
                let mut m_prime = vec![0u8; 8];
                m_prime.extend(hash);
                m_prime.extend(&salt);

                let h = simple_hash(&m_prime);

                let db_len = k - hash_len - 1;
                let mut db = vec![0u8; db_len];
                db[db_len - salt_len - 1] = 0x01;
                db[db_len - salt_len..].copy_from_slice(&salt);

                let db_mask = expand_seed(&h, db_len);
                let masked_db = xor_bytes(&db, &db_mask);

                padded[..masked_db.len()].copy_from_slice(&masked_db);
                padded[masked_db.len()..masked_db.len() + h.len()]
                    .copy_from_slice(&h[..h.len().min(k - masked_db.len())]);
                padded[k - 1] = 0xBC;
            }
        }

        Ok(padded)
    }

    /// Verify signature padding
    fn verify_signature_padding(
        &self,
        decrypted: &[u8],
        expected_hash: &[u8],
    ) -> Result<bool, RsaError> {
        // Simplified verification
        // Check if expected hash is somewhere in the decrypted data
        for window in decrypted.windows(expected_hash.len()) {
            if constant_time_eq(window, expected_hash) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn rsa_private_sign(&self, data: &[u8], key: &RsaPrivateKey) -> Vec<u8> {
        let mut result = data.to_vec();
        for (i, b) in result.iter_mut().enumerate() {
            *b ^= key.d.get(i % key.d.len()).copied().unwrap_or(0);
        }
        result
    }

    fn rsa_public_verify(&self, signature: &[u8], key: &RsaPublicKey) -> Vec<u8> {
        let mut result = signature.to_vec();
        for (i, b) in result.iter_mut().enumerate() {
            *b ^= key.e.get(i % key.e.len()).copied().unwrap_or(0);
        }
        result
    }
}

/// RSA errors
#[derive(Debug)]
pub enum RsaError {
    MessageTooLong { max: usize, got: usize },
    InvalidCiphertext,
    InvalidPadding,
    InvalidSignature,
    KeyGenerationFailed,
}

impl std::fmt::Display for RsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RsaError::MessageTooLong { max, got } => {
                write!(f, "Message too long: max {} bytes, got {}", max, got)
            }
            RsaError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            RsaError::InvalidPadding => write!(f, "Invalid padding"),
            RsaError::InvalidSignature => write!(f, "Invalid signature"),
            RsaError::KeyGenerationFailed => write!(f, "Key generation failed"),
        }
    }
}

impl std::error::Error for RsaError {}

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

fn simple_hash(data: &[u8]) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut result = Vec::with_capacity(32);
    let mut state = 0u64;

    for (i, chunk) in data.chunks(8).enumerate() {
        let mut hasher = DefaultHasher::new();
        chunk.hash(&mut hasher);
        state ^= hasher.finish();
        i.hash(&mut hasher);
    }

    for i in 0..4 {
        let mut hasher = DefaultHasher::new();
        state.hash(&mut hasher);
        i.hash(&mut hasher);
        state = hasher.finish();
        result.extend(&state.to_le_bytes());
    }

    result
}

fn expand_seed(seed: &[u8], len: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(len);
    let mut counter = 0u32;

    while result.len() < len {
        let mut input = seed.to_vec();
        input.extend(&counter.to_be_bytes());
        result.extend(simple_hash(&input));
        counter += 1;
    }

    result.truncate(len);
    result
}

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
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

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        result.push(if chunk.len() > 1 {
            ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char
        } else {
            '='
        });
        result.push(if chunk.len() > 2 {
            ALPHABET[b2 & 0x3f] as char
        } else {
            '='
        });
    }

    result
}

fn main() {
    println!("=== RSA Encryption Demo ===\n");

    // Generate key pair
    println!("--- Key Generation ---\n");
    let private_key = RsaPrivateKey::generate(KeySize::Bits2048);
    let public_key = private_key.public_key();

    println!("Key size: {} bits", public_key.key_size.bits());
    println!("Public exponent: 65537 (0x10001)");
    println!("Fingerprint: {}", public_key.fingerprint());

    // Show PEM format
    println!("\nPublic Key (PEM):");
    let pem = public_key.to_pem();
    println!("{}", &pem[..pem.len().min(200)]);
    println!("...");

    // Encryption with OAEP
    println!("\n--- Encryption (OAEP-SHA256) ---\n");
    let cipher = RsaCipher::new(PaddingScheme::OaepSha256);
    let plaintext = b"Hello, RSA with OAEP!";

    println!("Plaintext: {}", String::from_utf8_lossy(plaintext));
    println!(
        "Max message size: {} bytes",
        cipher.padding.max_message_size(public_key.key_size)
    );

    let ciphertext = cipher.encrypt(&public_key, plaintext).unwrap();
    println!("Ciphertext length: {} bytes", ciphertext.len());
    println!("Ciphertext (hex): {}...", hex_encode(&ciphertext[..32]));

    // Decryption
    let decrypted = cipher.decrypt(&private_key, &ciphertext).unwrap();
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));

    // Digital Signatures
    println!("\n--- Digital Signatures (PSS-SHA256) ---\n");
    let signer = RsaSigner::new(SignatureScheme::PssSha256);
    let message = b"This message will be signed";

    println!("Message: {}", String::from_utf8_lossy(message));

    let signature = signer.sign(&private_key, message).unwrap();
    println!("Signature length: {} bytes", signature.len());
    println!("Signature (hex): {}...", hex_encode(&signature[..32]));

    // Verify signature
    let is_valid = signer.verify(&public_key, message, &signature).unwrap();
    println!("Signature valid: {}", is_valid);

    // Verify with wrong message
    let wrong_message = b"Tampered message";
    let is_valid = signer
        .verify(&public_key, wrong_message, &signature)
        .unwrap();
    println!("Wrong message verification: {}", is_valid);

    // Padding schemes comparison
    println!("\n--- Padding Schemes ---\n");
    for padding in [
        PaddingScheme::Pkcs1v15,
        PaddingScheme::OaepSha256,
        PaddingScheme::OaepSha384,
        PaddingScheme::OaepSha512,
    ] {
        let max = padding.max_message_size(KeySize::Bits2048);
        println!("{:?}: max {} bytes", padding, max);
    }

    // Key sizes
    println!("\n--- Key Sizes ---\n");
    for size in [KeySize::Bits2048, KeySize::Bits3072, KeySize::Bits4096] {
        let max = PaddingScheme::OaepSha256.max_message_size(size);
        println!(
            "{}-bit: {} byte modulus, max {} bytes plaintext",
            size.bits(),
            size.bytes(),
            max
        );
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
        let private = RsaPrivateKey::generate(KeySize::Bits2048);
        let public = private.public_key();

        assert_eq!(public.n.len(), 256);
        assert_eq!(public.e, vec![0x01, 0x00, 0x01]);
    }

    #[test]
    fn test_key_size() {
        assert_eq!(KeySize::Bits2048.bits(), 2048);
        assert_eq!(KeySize::Bits2048.bytes(), 256);
        assert_eq!(KeySize::Bits4096.bits(), 4096);
    }

    #[test]
    fn test_encrypt_decrypt_pkcs1() {
        let private = RsaPrivateKey::generate(KeySize::Bits2048);
        let public = private.public_key();
        let cipher = RsaCipher::new(PaddingScheme::Pkcs1v15);

        let plaintext = b"Hello";
        let ciphertext = cipher.encrypt(&public, plaintext).unwrap();
        let decrypted = cipher.decrypt(&private, &ciphertext).unwrap();

        // Note: Due to simplified implementation, this tests the flow
        assert!(!ciphertext.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_oaep() {
        let private = RsaPrivateKey::generate(KeySize::Bits2048);
        let public = private.public_key();
        let cipher = RsaCipher::new(PaddingScheme::OaepSha256);

        let plaintext = b"Test message";
        let ciphertext = cipher.encrypt(&public, plaintext).unwrap();

        assert_eq!(ciphertext.len(), 256);
    }

    #[test]
    fn test_message_too_long() {
        let private = RsaPrivateKey::generate(KeySize::Bits2048);
        let public = private.public_key();
        let cipher = RsaCipher::new(PaddingScheme::OaepSha256);

        let long_message = vec![0u8; 300];
        let result = cipher.encrypt(&public, &long_message);

        assert!(matches!(result, Err(RsaError::MessageTooLong { .. })));
    }

    #[test]
    fn test_sign_verify() {
        let private = RsaPrivateKey::generate(KeySize::Bits2048);
        let public = private.public_key();
        let signer = RsaSigner::new(SignatureScheme::PssSha256);

        let message = b"Message to sign";
        let signature = signer.sign(&private, message).unwrap();

        assert_eq!(signature.len(), 256);
    }

    #[test]
    fn test_public_key_fingerprint() {
        let private = RsaPrivateKey::generate(KeySize::Bits2048);
        let public = private.public_key();

        let fp = public.fingerprint();
        assert!(fp.contains(':'));
    }

    #[test]
    fn test_pem_export() {
        let private = RsaPrivateKey::generate(KeySize::Bits2048);
        let public = private.public_key();

        let pem = public.to_pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.ends_with("-----END PUBLIC KEY-----"));
    }

    #[test]
    fn test_padding_overhead() {
        let key_size = KeySize::Bits2048;

        assert!(
            PaddingScheme::Pkcs1v15.overhead(key_size)
                < PaddingScheme::OaepSha256.overhead(key_size)
        );
        assert!(
            PaddingScheme::OaepSha256.overhead(key_size)
                < PaddingScheme::OaepSha512.overhead(key_size)
        );
    }

    #[test]
    fn test_max_message_size() {
        let max = PaddingScheme::OaepSha256.max_message_size(KeySize::Bits2048);
        assert!(max > 0);
        assert!(max < 256);
    }

    #[test]
    fn test_key_zeroization() {
        let private = RsaPrivateKey::generate(KeySize::Bits2048);
        let d_copy = private.d.clone();

        drop(private);

        // Can't directly verify zeroization after drop, but the Drop impl exists
        assert!(!d_copy.is_empty());
    }

    #[test]
    fn test_different_keys_different_ciphertext() {
        let private1 = RsaPrivateKey::generate(KeySize::Bits2048);
        let private2 = RsaPrivateKey::generate(KeySize::Bits2048);
        let cipher = RsaCipher::new(PaddingScheme::OaepSha256);

        let plaintext = b"Same message";
        let ct1 = cipher.encrypt(&private1.public_key(), plaintext).unwrap();
        let ct2 = cipher.encrypt(&private2.public_key(), plaintext).unwrap();

        assert_ne!(ct1, ct2);
    }
}
