# Rust Cryptographic Library Template

## Overview

This template provides a security-hardened foundation for developing cryptographic libraries in Rust. It emphasizes constant-time operations, side-channel attack resistance, formal verification patterns, comprehensive testing, and adherence to cryptographic best practices.

**Target Use Cases:**
- Cryptographic algorithm implementations
- Security protocol libraries
- Key management systems
- Hardware security module (HSM) interfaces
- Cryptographic service providers
- Zero-knowledge proof systems

## Project Structure

```
my-crypto-lib/
├── Cargo.toml
├── Cargo.lock
├── src/
│   ├── lib.rs                # Public API
│   ├── primitives/           # Cryptographic primitives
│   │   ├── mod.rs
│   │   ├── aes.rs
│   │   ├── chacha20.rs
│   │   ├── sha.rs
│   │   └── ed25519.rs
│   ├── protocols/            # Protocol implementations
│   │   ├── mod.rs
│   │   ├── tls.rs
│   │   └── noise.rs
│   ├── key_management/       # Key generation and management
│   │   ├── mod.rs
│   │   ├── derivation.rs
│   │   └── storage.rs
│   ├── rng/                  # Random number generation
│   │   ├── mod.rs
│   │   └── secure_rng.rs
│   ├── utils/                # Utilities
│   │   ├── mod.rs
│   │   ├── constant_time.rs
│   │   └── zeroize.rs
│   └── error.rs              # Error types
├── benches/                  # Benchmarks
│   ├── crypto_bench.rs
│   └── side_channel.rs
├── tests/
│   ├── test_vectors.rs       # Known-answer tests
│   ├── property_tests.rs     # Property-based tests
│   └── security_tests.rs     # Security regression tests
├── fuzz/                     # Fuzzing targets
│   └── fuzz_targets/
│       └── decrypt.rs
├── .github/
│   └── workflows/
│       └── crypto-security.yml
├── deny.toml
└── README.md
```

## Cargo.toml Template

```toml
[package]
name = "my-crypto-lib"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"
authors = ["Your Name <you@example.com>"]
license = "MIT OR Apache-2.0"
description = "Cryptographic library with constant-time guarantees"
repository = "https://github.com/username/my-crypto-lib"
keywords = ["cryptography", "security", "constant-time", "crypto"]
categories = ["cryptography", "no-std"]

[dependencies]
# Constant-time operations
subtle = "2.6"
zeroize = { version = "1.8", features = ["derive"] }

# Random number generation
rand_core = { version = "0.6", default-features = false }
getrandom = { version = "0.2", default-features = false }

# Cryptographic primitives
aes = { version = "0.8", default-features = false }
chacha20 = { version = "0.9", default-features = false }
sha2 = { version = "0.10", default-features = false }
sha3 = { version = "0.10", default-features = false }
blake3 = { version = "1.5", default-features = false }

# AEAD ciphers
aes-gcm = { version = "0.10", default-features = false }
chacha20poly1305 = { version = "0.10", default-features = false }

# Key derivation
hkdf = { version = "0.12", default-features = false }
pbkdf2 = { version = "0.12", default-features = false }
argon2 = { version = "0.5", default-features = false }

# Elliptic curves
curve25519-dalek = { version = "4.1", default-features = false }
ed25519-dalek = { version = "2.1", default-features = false }
x25519-dalek = { version = "2.0", default-features = false }

# Error handling
thiserror = { version = "2.0", optional = true }

# Serialization
serde = { version = "1.0", default-features = false, features = ["derive"], optional = true }

[dev-dependencies]
# Testing
hex = "0.4"
hex-literal = "0.4"
criterion = { version = "0.5", features = ["html_reports"] }
proptest = "1.5"

# Fuzzing
cargo-fuzz = "0.12"

# Test vectors
serde_json = "1.0"

[features]
default = ["std"]
std = ["thiserror", "getrandom/std"]
alloc = []
# no_std support (requires alloc)
# Enable hardware acceleration
hw-accel = []
# Enable side-channel mitigations
hardened = []

[profile.release]
# Maximum optimization for crypto
opt-level = 3
lto = "fat"
codegen-units = 1
overflow-checks = true
debug-assertions = false

[profile.bench]
inherits = "release"
debug = true

# Security-hardened profile
[profile.secure]
inherits = "release"
opt-level = 3
lto = "fat"
codegen-units = 1
overflow-checks = true
debug-assertions = true

[lib]
crate-type = ["lib", "staticlib", "cdylib"]

[[bench]]
name = "crypto_bench"
harness = false
```

## Security Considerations

### 1. Constant-Time Operations
- All cryptographic operations must be constant-time
- Use `subtle` crate for constant-time comparisons
- Avoid branching on secret data
- Prevent timing side-channels

### 2. Memory Safety
- Zeroize sensitive data immediately after use
- Use `zeroize` crate with `Drop` implementations
- Avoid heap allocations where possible
- Use secure memory allocators for sensitive data

### 3. Side-Channel Resistance
- Constant-time implementations
- Avoid cache-timing attacks
- Power analysis resistance (where applicable)
- Fault injection protection

### 4. API Design
- Hard to misuse (misuse-resistant)
- Type-safe cryptographic operations
- Clear documentation of security assumptions
- No default keys or IVs

### 5. Random Number Generation
- Use cryptographically secure RNG
- No predictable patterns
- Proper entropy gathering
- Fail securely on entropy exhaustion

### 6. Testing and Validation
- Known-answer tests (test vectors)
- Property-based testing
- Fuzzing
- Side-channel testing
- Formal verification (where possible)

## Required Dependencies

### Core Cryptography

| Crate | Version | Purpose |
|-------|---------|---------|
| `subtle` | 2.6+ | Constant-time operations |
| `zeroize` | 1.8+ | Memory zeroing |
| `rand_core` | 0.6+ | RNG traits |

### Primitives

| Crate | Version | Purpose |
|-------|---------|---------|
| `aes` | 0.8+ | AES block cipher |
| `chacha20` | 0.9+ | ChaCha20 stream cipher |
| `sha2` | 0.10+ | SHA-2 family |
| `blake3` | 1.5+ | BLAKE3 hash |

### AEAD Ciphers

| Crate | Version | Purpose |
|-------|---------|---------|
| `aes-gcm` | 0.10+ | AES-GCM |
| `chacha20poly1305` | 0.10+ | ChaCha20-Poly1305 |

### Key Derivation

| Crate | Version | Purpose |
|-------|---------|---------|
| `hkdf` | 0.12+ | HKDF |
| `pbkdf2` | 0.12+ | PBKDF2 |
| `argon2` | 0.5+ | Argon2 |

## Code Examples

### Example 1: Constant-Time Comparison

```rust
// src/utils/constant_time.rs
use subtle::{Choice, ConstantTimeEq, ConditionallySelectable};

/// Constant-time comparison of byte slices
///
/// This function runs in constant time regardless of the input values,
/// preventing timing side-channel attacks.
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.ct_eq(b).into()
}

/// Constant-time conditional selection
///
/// Selects `a` if `choice` is true, `b` otherwise, in constant time.
pub fn constant_time_select(choice: Choice, a: u32, b: u32) -> u32 {
    u32::conditional_select(&b, &a, choice)
}

/// Constant-time array lookup
///
/// Returns array[index] in constant time by accessing all elements.
pub fn constant_time_lookup<const N: usize>(array: &[u32; N], index: usize) -> u32 {
    let mut result = 0u32;

    for i in 0..N {
        let choice = Choice::from(((i == index) as u8));
        result = u32::conditional_select(&result, &array[i], choice);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_compare() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
    }

    #[test]
    fn test_constant_time_lookup() {
        let array = [10, 20, 30, 40, 50];
        assert_eq!(constant_time_lookup(&array, 2), 30);
        assert_eq!(constant_time_lookup(&array, 4), 50);
    }
}
```

### Example 2: Secure Key Management

```rust
// src/key_management/storage.rs
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::fmt;

/// Secure key wrapper that zeroizes on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    #[zeroize(skip)]  // Don't zeroize the length
    len: usize,
    bytes: [u8; 32],
}

impl SecretKey {
    /// Create a new secret key
    pub fn new(bytes: [u8; 32]) -> Self {
        Self {
            len: 32,
            bytes,
        }
    }

    /// Generate a random key
    pub fn generate<R: rand_core::CryptoRng + rand_core::RngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self::new(bytes)
    }

    /// Get key bytes (use carefully!)
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Derive a child key using HKDF
    pub fn derive_key(&self, info: &[u8]) -> SecretKey {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(None, self.as_bytes());
        let mut okm = [0u8; 32];
        hkdf.expand(info, &mut okm).expect("Invalid HKDF length");

        SecretKey::new(okm)
    }
}

// Prevent accidental leaking in debug output
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("len", &self.len)
            .field("bytes", &"***REDACTED***")
            .finish()
    }
}

// Prevent accidental display
impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey(***REDACTED***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_key_generation() {
        let key1 = SecretKey::generate(&mut OsRng);
        let key2 = SecretKey::generate(&mut OsRng);

        // Keys should be different
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_key_derivation() {
        let master_key = SecretKey::generate(&mut OsRng);
        let child_key1 = master_key.derive_key(b"context1");
        let child_key2 = master_key.derive_key(b"context2");

        // Derived keys should be different
        assert_ne!(child_key1.as_bytes(), child_key2.as_bytes());

        // Same context should produce same key
        let child_key1_again = master_key.derive_key(b"context1");
        assert_eq!(child_key1.as_bytes(), child_key1_again.as_bytes());
    }
}
```

### Example 3: AEAD Encryption (AES-GCM)

```rust
// src/primitives/aes.rs
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use zeroize::Zeroize;

pub struct AesGcmCipher {
    cipher: Aes256Gcm,
}

impl AesGcmCipher {
    /// Create a new AES-GCM cipher with the given key
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
        }
    }

    /// Encrypt data with authenticated encryption
    ///
    /// # Arguments
    /// * `nonce` - 96-bit nonce (must be unique per encryption)
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Additional authenticated data (not encrypted, but authenticated)
    ///
    /// # Returns
    /// Ciphertext with authentication tag appended
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: plaintext,
            aad,
        };

        self.cipher
            .encrypt(nonce, payload)
            .map_err(|_| EncryptionError::EncryptionFailed)
    }

    /// Decrypt and verify authenticated encryption
    ///
    /// # Arguments
    /// * `nonce` - 96-bit nonce used for encryption
    /// * `ciphertext` - Encrypted data with authentication tag
    /// * `aad` - Additional authenticated data (must match encryption)
    ///
    /// # Returns
    /// Decrypted plaintext if authentication succeeds
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|_| DecryptionError::AuthenticationFailed)
    }
}

impl Drop for AesGcmCipher {
    fn drop(&mut self) {
        // Zeroize internal state
        // Note: aes_gcm crate already handles this
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("Encryption failed")]
    EncryptionFailed,
}

#[derive(Debug, thiserror::Error)]
pub enum DecryptionError {
    #[error("Authentication failed - ciphertext or AAD was modified")]
    AuthenticationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_encrypt_decrypt() {
        let key = [0x42; 32];
        let cipher = AesGcmCipher::new(&key);

        let nonce = [0x12; 12];
        let plaintext = b"Secret message";
        let aad = b"Additional data";

        // Encrypt
        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();

        // Decrypt
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_aes_gcm_authentication_failure() {
        let key = [0x42; 32];
        let cipher = AesGcmCipher::new(&key);

        let nonce = [0x12; 12];
        let plaintext = b"Secret message";
        let aad = b"Additional data";

        let mut ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 0x01;

        // Decryption should fail
        let result = cipher.decrypt(&nonce, &ciphertext, aad);
        assert!(matches!(result, Err(DecryptionError::AuthenticationFailed)));
    }
}
```

### Example 4: Ed25519 Digital Signatures

```rust
// src/primitives/ed25519.rs
use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use rand_core::OsRng;
use zeroize::Zeroize;

pub struct Ed25519KeyPair {
    signing_key: SigningKey,
}

impl Ed25519KeyPair {
    /// Generate a new Ed25519 key pair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create from seed (32 bytes)
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self { signing_key }
    }

    /// Get the verifying (public) key
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Sign a message and return both signature and message
    pub fn sign_message(&self, message: &[u8]) -> SignedMessage {
        let signature = self.sign(message);
        SignedMessage {
            message: message.to_vec(),
            signature: signature.to_bytes(),
        }
    }
}

impl Drop for Ed25519KeyPair {
    fn drop(&mut self) {
        // Zeroize private key
        // ed25519_dalek already handles this
    }
}

/// Verify an Ed25519 signature
pub fn verify(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), SignatureError> {
    verifying_key
        .verify(message, signature)
        .map_err(|_| SignatureError::InvalidSignature)
}

#[derive(Debug)]
pub struct SignedMessage {
    pub message: Vec<u8>,
    pub signature: [u8; 64],
}

impl SignedMessage {
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), SignatureError> {
        let signature = Signature::from_bytes(&self.signature);
        verify(verifying_key, &self.message, &signature)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("Invalid signature")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let keypair = Ed25519KeyPair::generate();
        let message = b"Test message";

        let signature = keypair.sign(message);
        let verifying_key = keypair.verifying_key();

        // Verification should succeed
        assert!(verify(&verifying_key, message, &signature).is_ok());
    }

    #[test]
    fn test_verify_fails_on_wrong_message() {
        let keypair = Ed25519KeyPair::generate();
        let message = b"Test message";
        let wrong_message = b"Wrong message";

        let signature = keypair.sign(message);
        let verifying_key = keypair.verifying_key();

        // Verification should fail
        assert!(verify(&verifying_key, wrong_message, &signature).is_err());
    }
}
```

### Example 5: Password Hashing with Argon2

```rust
// src/key_management/derivation.rs
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use zeroize::Zeroizing;

/// Hash a password using Argon2id
///
/// Argon2id is the recommended variant, resistant to both
/// side-channel and GPU attacks.
pub fn hash_password(password: &[u8]) -> Result<String, PasswordHashError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password, &salt)
        .map_err(|e| PasswordHashError::HashingFailed(e.to_string()))?
        .to_string();

    Ok(password_hash)
}

/// Verify a password against a hash
///
/// This function runs in constant time to prevent timing attacks.
pub fn verify_password(password: &[u8], password_hash: &str) -> Result<(), PasswordHashError> {
    let parsed_hash = PasswordHash::new(password_hash)
        .map_err(|e| PasswordHashError::InvalidHash(e.to_string()))?;

    let argon2 = Argon2::default();

    argon2
        .verify_password(password, &parsed_hash)
        .map_err(|_| PasswordHashError::VerificationFailed)
}

/// Derive a key from a password using Argon2
pub fn derive_key_from_password(
    password: &[u8],
    salt: &[u8],
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>, PasswordHashError> {
    use argon2::Algorithm;

    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default(),
    );

    let mut output = Zeroizing::new(vec![0u8; output_len]);

    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| PasswordHashError::HashingFailed(e.to_string()))?;

    Ok(output)
}

#[derive(Debug, thiserror::Error)]
pub enum PasswordHashError {
    #[error("Hashing failed: {0}")]
    HashingFailed(String),
    #[error("Invalid hash: {0}")]
    InvalidHash(String),
    #[error("Verification failed")]
    VerificationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let password = b"MySecurePassword123!";
        let hash = hash_password(password).unwrap();

        // Verification should succeed
        assert!(verify_password(password, &hash).is_ok());

        // Wrong password should fail
        assert!(verify_password(b"WrongPassword", &hash).is_err());
    }

    #[test]
    fn test_key_derivation() {
        let password = b"password";
        let salt = b"unique_salt_1234";

        let key1 = derive_key_from_password(password, salt, 32).unwrap();
        let key2 = derive_key_from_password(password, salt, 32).unwrap();

        // Same inputs should produce same output
        assert_eq!(key1.as_slice(), key2.as_slice());

        // Different salt should produce different output
        let key3 = derive_key_from_password(password, b"different_salt", 32).unwrap();
        assert_ne!(key1.as_slice(), key3.as_slice());
    }
}
```

### Example 6: Secure Random Number Generation

```rust
// src/rng/secure_rng.rs
use rand_core::{CryptoRng, RngCore, OsRng};
use sha2::{Sha256, Digest};

/// Cryptographically secure random number generator
///
/// This wraps the OS RNG and provides additional entropy mixing.
pub struct SecureRng {
    entropy_pool: [u8; 32],
    counter: u64,
}

impl SecureRng {
    /// Create a new secure RNG
    pub fn new() -> Self {
        let mut entropy_pool = [0u8; 32];
        OsRng.fill_bytes(&mut entropy_pool);

        Self {
            entropy_pool,
            counter: 0,
        }
    }

    /// Add additional entropy to the pool
    pub fn add_entropy(&mut self, entropy: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.entropy_pool);
        hasher.update(entropy);
        hasher.update(self.counter.to_le_bytes());

        self.entropy_pool.copy_from_slice(&hasher.finalize());
        self.counter = self.counter.wrapping_add(1);
    }

    /// Generate random bytes
    pub fn random_bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut output = [0u8; N];
        self.fill_bytes(&mut output);
        output
    }
}

impl RngCore for SecureRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Mix entropy pool with counter
        self.add_entropy(&self.counter.to_le_bytes());

        // Use OS RNG as primary source
        OsRng.fill_bytes(dest);

        // XOR with entropy pool (for additional mixing)
        for (i, byte) in dest.iter_mut().enumerate() {
            *byte ^= self.entropy_pool[i % 32];
        }

        self.counter = self.counter.wrapping_add(1);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SecureRng {}

impl Default for SecureRng {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rng_uniqueness() {
        let mut rng = SecureRng::new();
        let val1 = rng.next_u64();
        let val2 = rng.next_u64();

        // Values should be different (with very high probability)
        assert_ne!(val1, val2);
    }

    #[test]
    fn test_entropy_mixing() {
        let mut rng = SecureRng::new();
        rng.add_entropy(b"additional entropy");

        let bytes: [u8; 32] = rng.random_bytes();
        // Should produce output (no panic)
        assert_eq!(bytes.len(), 32);
    }
}
```

## Common Vulnerabilities

### 1. Timing Attacks
**Vulnerable:**
```rust
fn verify_mac(computed: &[u8], expected: &[u8]) -> bool {
    computed == expected  // Early exit on mismatch!
}
```
**Secure:**
```rust
use subtle::ConstantTimeEq;
fn verify_mac(computed: &[u8], expected: &[u8]) -> bool {
    computed.ct_eq(expected).into()
}
```

### 2. Nonce Reuse
**Vulnerable:**
```rust
let nonce = [0u8; 12];  // Fixed nonce - DANGEROUS!
cipher.encrypt(&nonce, plaintext, aad)?;
```
**Secure:**
```rust
let mut nonce = [0u8; 12];
rng.fill_bytes(&mut nonce);  // Random nonce
cipher.encrypt(&nonce, plaintext, aad)?;
```

### 3. Weak RNG
**Vulnerable:**
```rust
use rand::thread_rng;  // Not cryptographically secure!
let key = thread_rng().gen::<[u8; 32]>();
```
**Secure:**
```rust
use rand_core::OsRng;
let mut key = [0u8; 32];
OsRng.fill_bytes(&mut key);
```

### 4. Memory Leaks
**Vulnerable:**
```rust
let key = vec![0x42; 32];
// Key remains in memory after drop!
```
**Secure:**
```rust
use zeroize::Zeroizing;
let key = Zeroizing::new(vec![0x42; 32]);
// Key is zeroized on drop
```

### 5. Side-Channel Leaks
**Vulnerable:**
```rust
if secret_bit == 1 {
    expensive_operation();  // Timing leak!
}
```
**Secure:**
```rust
let result = expensive_operation();
let mask = if secret_bit == 1 { 0xFF } else { 0x00 };
constant_time_select(mask, result, default_value);
```

## Testing Strategy

### Known-Answer Tests

```rust
// tests/test_vectors.rs
use hex_literal::hex;

#[test]
fn test_aes_gcm_nist_vector() {
    // NIST test vector
    let key = hex!("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    let nonce = hex!("cafebabefacedbaddecaf888");
    let plaintext = hex!("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
    let aad = hex!("");
    let expected_ciphertext = hex!("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad");

    let cipher = AesGcmCipher::new(&key);
    let ciphertext = cipher.encrypt(&nonce, &plaintext, &aad).unwrap();

    assert_eq!(&ciphertext[..plaintext.len()], &expected_ciphertext[..]);
}
```

### Property-Based Tests

```rust
// tests/property_tests.rs
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_encrypt_decrypt_roundtrip(
        plaintext in prop::collection::vec(any::<u8>(), 0..1024)
    ) {
        let key = [0x42; 32];
        let nonce = [0x12; 12];
        let cipher = AesGcmCipher::new(&key);

        let ciphertext = cipher.encrypt(&nonce, &plaintext, &[]).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &[]).unwrap();

        prop_assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_signature_verification(
        message in prop::collection::vec(any::<u8>(), 0..1024)
    ) {
        let keypair = Ed25519KeyPair::generate();
        let signature = keypair.sign(&message);
        let verifying_key = keypair.verifying_key();

        // Valid signature should verify
        prop_assert!(verify(&verifying_key, &message, &signature).is_ok());
    }
}
```

### Fuzzing

```rust
// fuzz/fuzz_targets/decrypt.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 44 {
        return;
    }

    let key: [u8; 32] = data[..32].try_into().unwrap();
    let nonce: [u8; 12] = data[32..44].try_into().unwrap();
    let ciphertext = &data[44..];

    let cipher = AesGcmCipher::new(&key);
    let _ = cipher.decrypt(&nonce, ciphertext, &[]);
    // Should not panic or crash
});
```

## CI/CD Integration

```yaml
# .github/workflows/crypto-security.yml
name: Cryptography Security

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Run tests
        run: cargo test --all-features

      - name: Run known-answer tests
        run: cargo test --test test_vectors

      - name: Run property tests
        run: cargo test --test property_tests -- --test-threads=1

  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly

      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz

      - name: Run fuzzer (limited time)
        run: cargo fuzz run decrypt -- -max_total_time=300

  bench:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Run benchmarks
        run: cargo bench

  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Security audit
        run: |
          cargo install cargo-audit
          cargo audit
```

## Best Practices

1. **Always use constant-time operations for secret data**
2. **Zeroize sensitive data immediately after use**
3. **Use cryptographically secure RNG (OsRng)**
4. **Never reuse nonces/IVs**
5. **Implement comprehensive test vectors**
6. **Fuzz all parsing and decryption code**
7. **Document all security assumptions**
8. **Follow established cryptographic standards**
9. **Avoid implementing custom crypto primitives**
10. **Regular security audits by cryptography experts**

## Example Projects

- **RustCrypto**: https://github.com/RustCrypto
- **ring**: https://github.com/briansmith/ring
- **sodiumoxide**: https://github.com/sodiumoxide/sodiumoxide
- **orion**: https://github.com/orion-rs/orion
