//! Key Derivation Functions Example
//!
//! Demonstrates secure key derivation using Argon2, scrypt, and PBKDF2.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use pbkdf2::pbkdf2_hmac;
use scrypt::{
    password_hash::{PasswordHasher as ScryptHasher, PasswordVerifier as ScryptVerifier},
    Scrypt,
};
use sha2::Sha256;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KdfError {
    #[error("Hashing failed: {0}")]
    HashingFailed(String),
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Invalid parameters")]
    InvalidParams,
}

/// Argon2 key derivation (recommended for password hashing)
pub mod argon2_kdf {
    use super::*;

    /// Argon2id configuration (recommended variant)
    pub struct Argon2Config {
        /// Memory cost in KiB
        pub memory_cost: u32,
        /// Time cost (iterations)
        pub time_cost: u32,
        /// Parallelism factor
        pub parallelism: u32,
        /// Output length
        pub output_len: usize,
    }

    impl Default for Argon2Config {
        fn default() -> Self {
            // OWASP recommended minimum for 2024
            Self {
                memory_cost: 65536, // 64 MiB
                time_cost: 3,
                parallelism: 4,
                output_len: 32,
            }
        }
    }

    impl Argon2Config {
        /// High-security configuration
        pub fn high_security() -> Self {
            Self {
                memory_cost: 262144, // 256 MiB
                time_cost: 4,
                parallelism: 4,
                output_len: 32,
            }
        }

        /// Interactive login configuration (faster)
        pub fn interactive() -> Self {
            Self {
                memory_cost: 19456, // 19 MiB
                time_cost: 2,
                parallelism: 1,
                output_len: 32,
            }
        }
    }

    /// Hash a password using Argon2id
    pub fn hash_password(password: &[u8], config: &Argon2Config) -> Result<String, KdfError> {
        let salt = SaltString::generate(&mut OsRng);

        let params = Params::new(
            config.memory_cost,
            config.time_cost,
            config.parallelism,
            Some(config.output_len),
        )
        .map_err(|e| KdfError::HashingFailed(e.to_string()))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let hash = argon2
            .hash_password(password, &salt)
            .map_err(|e| KdfError::HashingFailed(e.to_string()))?;

        Ok(hash.to_string())
    }

    /// Verify a password against a hash
    pub fn verify_password(password: &[u8], hash: &str) -> Result<bool, KdfError> {
        let parsed_hash =
            PasswordHash::new(hash).map_err(|e| KdfError::HashingFailed(e.to_string()))?;

        let argon2 = Argon2::default();

        Ok(argon2.verify_password(password, &parsed_hash).is_ok())
    }

    /// Derive a key from a password (for encryption keys)
    pub fn derive_key(
        password: &[u8],
        salt: &[u8],
        config: &Argon2Config,
    ) -> Result<Vec<u8>, KdfError> {
        let params = Params::new(
            config.memory_cost,
            config.time_cost,
            config.parallelism,
            Some(config.output_len),
        )
        .map_err(|e| KdfError::HashingFailed(e.to_string()))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut output = vec![0u8; config.output_len];
        argon2
            .hash_password_into(password, salt, &mut output)
            .map_err(|e| KdfError::HashingFailed(e.to_string()))?;

        Ok(output)
    }
}

/// scrypt key derivation (memory-hard, good for password hashing)
pub mod scrypt_kdf {
    use super::*;

    /// Hash a password using scrypt
    pub fn hash_password(password: &[u8]) -> Result<String, KdfError> {
        let salt = SaltString::generate(&mut OsRng);

        let hash = Scrypt
            .hash_password(password, &salt)
            .map_err(|e| KdfError::HashingFailed(e.to_string()))?;

        Ok(hash.to_string())
    }

    /// Verify a password against a scrypt hash
    pub fn verify_password(password: &[u8], hash: &str) -> Result<bool, KdfError> {
        let parsed_hash =
            PasswordHash::new(hash).map_err(|e| KdfError::HashingFailed(e.to_string()))?;

        Ok(Scrypt.verify_password(password, &parsed_hash).is_ok())
    }

    /// Derive a key using scrypt
    pub fn derive_key(
        password: &[u8],
        salt: &[u8],
        n: u32, // CPU/memory cost (power of 2)
        r: u32, // Block size
        p: u32, // Parallelism
        dk_len: usize,
    ) -> Result<Vec<u8>, KdfError> {
        let params = scrypt::Params::new(n.trailing_zeros() as u8, r, p, dk_len)
            .map_err(|_| KdfError::InvalidParams)?;

        let mut output = vec![0u8; dk_len];
        scrypt::scrypt(password, salt, &params, &mut output)
            .map_err(|e| KdfError::HashingFailed(e.to_string()))?;

        Ok(output)
    }
}

/// PBKDF2 key derivation (widely compatible, less memory-hard)
pub mod pbkdf2_kdf {
    use super::*;

    /// Derive a key using PBKDF2-HMAC-SHA256
    pub fn derive_key(password: &[u8], salt: &[u8], iterations: u32, output_len: usize) -> Vec<u8> {
        let mut output = vec![0u8; output_len];
        pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output);
        output
    }

    /// OWASP recommended iterations for 2024
    pub const RECOMMENDED_ITERATIONS: u32 = 600_000;
}

/// HKDF for key expansion (derive multiple keys from one)
pub mod hkdf_expand {
    use hkdf::Hkdf;
    use sha2::Sha256;

    /// Derive multiple keys from input keying material
    pub fn expand(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], output_len: usize) -> Vec<u8> {
        let hkdf = Hkdf::<Sha256>::new(salt, ikm);
        let mut output = vec![0u8; output_len];
        hkdf.expand(info, &mut output).expect("HKDF expand failed");
        output
    }

    /// Derive encryption and MAC keys from a master key
    pub fn derive_encryption_keys(master_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let encryption_key = expand(master_key, None, b"encryption", 32);
        let mac_key = expand(master_key, None, b"mac", 32);
        (encryption_key, mac_key)
    }
}

/// Generate cryptographically secure random salt
pub fn generate_salt(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut salt = vec![0u8; len];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn main() {
    println!("=== Key Derivation Functions ===\n");

    // Argon2id example
    println!("--- Argon2id ---");
    let password = b"secure_password_123!";

    let config = argon2_kdf::Argon2Config::default();
    let start = std::time::Instant::now();
    let hash = argon2_kdf::hash_password(password, &config).unwrap();
    println!("Argon2id hash time: {:?}", start.elapsed());
    println!("Hash: {}", &hash[..50]);

    let start = std::time::Instant::now();
    let valid = argon2_kdf::verify_password(password, &hash).unwrap();
    println!("Verification time: {:?}", start.elapsed());
    println!("Password valid: {}", valid);

    let invalid = argon2_kdf::verify_password(b"wrong_password", &hash).unwrap();
    println!("Wrong password rejected: {}", !invalid);

    // Key derivation for encryption
    println!("\n--- Key Derivation for Encryption ---");
    let salt = generate_salt(16);
    let key = argon2_kdf::derive_key(password, &salt, &config).unwrap();
    println!("Derived key: {} bytes", key.len());
    println!("Key (hex): {}...", hex::encode(&key[..8]));

    // scrypt example
    println!("\n--- scrypt ---");
    let start = std::time::Instant::now();
    let hash = scrypt_kdf::hash_password(password).unwrap();
    println!("scrypt hash time: {:?}", start.elapsed());
    println!("Hash: {}", &hash[..50]);

    let valid = scrypt_kdf::verify_password(password, &hash).unwrap();
    println!("Password valid: {}", valid);

    // PBKDF2 example
    println!("\n--- PBKDF2 ---");
    let salt = generate_salt(16);
    let start = std::time::Instant::now();
    let key = pbkdf2_kdf::derive_key(password, &salt, pbkdf2_kdf::RECOMMENDED_ITERATIONS, 32);
    println!("PBKDF2 time: {:?}", start.elapsed());
    println!("Derived key: {} bytes", key.len());

    // HKDF key expansion
    println!("\n--- HKDF Key Expansion ---");
    let master_key = generate_salt(32);
    let (enc_key, mac_key) = hkdf_expand::derive_encryption_keys(&master_key);
    println!("Encryption key: {} bytes", enc_key.len());
    println!("MAC key: {} bytes", mac_key.len());
    println!("Keys are different: {}", enc_key != mac_key);

    // Configuration comparison
    println!("\n=== Configuration Comparison ===");
    println!("\nArgon2id configurations:");

    let configs = [
        ("Interactive", argon2_kdf::Argon2Config::interactive()),
        ("Default", argon2_kdf::Argon2Config::default()),
        ("High Security", argon2_kdf::Argon2Config::high_security()),
    ];

    for (name, config) in &configs {
        println!(
            "  {}: mem={}KiB, time={}, parallel={}",
            name, config.memory_cost, config.time_cost, config.parallelism
        );
    }

    println!("\nRecommendations:");
    println!("  - Password storage: Argon2id (default config)");
    println!("  - Key derivation: Argon2id or scrypt");
    println!("  - Legacy systems: PBKDF2 with 600,000+ iterations");
    println!("  - Key expansion: HKDF");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_hash_verify() {
        let password = b"test_password";
        let config = argon2_kdf::Argon2Config::interactive();

        let hash = argon2_kdf::hash_password(password, &config).unwrap();

        assert!(argon2_kdf::verify_password(password, &hash).unwrap());
        assert!(!argon2_kdf::verify_password(b"wrong", &hash).unwrap());
    }

    #[test]
    fn test_argon2_key_derivation() {
        let password = b"test_password";
        let salt = generate_salt(16);
        let config = argon2_kdf::Argon2Config::interactive();

        let key1 = argon2_kdf::derive_key(password, &salt, &config).unwrap();
        let key2 = argon2_kdf::derive_key(password, &salt, &config).unwrap();

        // Same input produces same key
        assert_eq!(key1, key2);

        // Different salt produces different key
        let salt2 = generate_salt(16);
        let key3 = argon2_kdf::derive_key(password, &salt2, &config).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_scrypt_hash_verify() {
        let password = b"test_password";

        let hash = scrypt_kdf::hash_password(password).unwrap();

        assert!(scrypt_kdf::verify_password(password, &hash).unwrap());
        assert!(!scrypt_kdf::verify_password(b"wrong", &hash).unwrap());
    }

    #[test]
    fn test_pbkdf2_deterministic() {
        let password = b"test_password";
        let salt = b"fixed_salt_for_test";

        let key1 = pbkdf2_kdf::derive_key(password, salt, 10000, 32);
        let key2 = pbkdf2_kdf::derive_key(password, salt, 10000, 32);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_hkdf_expansion() {
        let ikm = generate_salt(32);

        let (enc_key, mac_key) = hkdf_expand::derive_encryption_keys(&ikm);

        assert_eq!(enc_key.len(), 32);
        assert_eq!(mac_key.len(), 32);
        assert_ne!(enc_key, mac_key);
    }
}
