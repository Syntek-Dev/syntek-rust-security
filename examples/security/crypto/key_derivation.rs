//! Key Derivation Functions Implementation
//!
//! Secure key derivation with:
//! - Argon2 (Argon2id, Argon2i, Argon2d)
//! - scrypt
//! - PBKDF2
//! - HKDF for key expansion
//! - Secure parameter selection

use std::fmt;
use std::time::{Duration, Instant};

/// Key derivation algorithm
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfAlgorithm {
    Argon2id,
    Argon2i,
    Argon2d,
    Scrypt,
    Pbkdf2Sha256,
    Pbkdf2Sha512,
    Hkdf,
}

/// Argon2 parameters
#[derive(Clone, Copy, Debug)]
pub struct Argon2Params {
    /// Memory cost in KiB
    pub memory_cost: u32,
    /// Time cost (iterations)
    pub time_cost: u32,
    /// Parallelism factor
    pub parallelism: u32,
    /// Output length in bytes
    pub output_length: usize,
}

/// scrypt parameters
#[derive(Clone, Copy, Debug)]
pub struct ScryptParams {
    /// CPU/memory cost parameter (log2)
    pub log_n: u8,
    /// Block size
    pub r: u32,
    /// Parallelization parameter
    pub p: u32,
    /// Output length in bytes
    pub output_length: usize,
}

/// PBKDF2 parameters
#[derive(Clone, Copy, Debug)]
pub struct Pbkdf2Params {
    /// Number of iterations
    pub iterations: u32,
    /// Output length in bytes
    pub output_length: usize,
}

/// HKDF parameters
#[derive(Clone, Debug)]
pub struct HkdfParams {
    /// Optional info string
    pub info: Vec<u8>,
    /// Output length in bytes
    pub output_length: usize,
}

/// Derived key with metadata
#[derive(Clone)]
pub struct DerivedKey {
    pub key: Vec<u8>,
    pub salt: Vec<u8>,
    pub algorithm: KdfAlgorithm,
    pub params_hash: String,
}

impl fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedKey")
            .field("key", &"[REDACTED]")
            .field("salt", &format!("{} bytes", self.salt.len()))
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

/// Key derivation error
#[derive(Debug)]
pub enum KdfError {
    InvalidParams(String),
    DerivationFailed(String),
    OutputTooLong,
    InvalidSalt,
}

impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KdfError::InvalidParams(msg) => write!(f, "Invalid parameters: {}", msg),
            KdfError::DerivationFailed(msg) => write!(f, "Derivation failed: {}", msg),
            KdfError::OutputTooLong => write!(f, "Output length too long"),
            KdfError::InvalidSalt => write!(f, "Invalid salt"),
        }
    }
}

impl std::error::Error for KdfError {}

/// Key derivation function interface
pub struct Kdf {
    algorithm: KdfAlgorithm,
}

impl Kdf {
    /// Create Argon2id KDF (recommended)
    pub fn argon2id() -> Self {
        Self {
            algorithm: KdfAlgorithm::Argon2id,
        }
    }

    /// Create Argon2i KDF (side-channel resistant)
    pub fn argon2i() -> Self {
        Self {
            algorithm: KdfAlgorithm::Argon2i,
        }
    }

    /// Create scrypt KDF
    pub fn scrypt() -> Self {
        Self {
            algorithm: KdfAlgorithm::Scrypt,
        }
    }

    /// Create PBKDF2-SHA256 KDF
    pub fn pbkdf2_sha256() -> Self {
        Self {
            algorithm: KdfAlgorithm::Pbkdf2Sha256,
        }
    }

    /// Create PBKDF2-SHA512 KDF
    pub fn pbkdf2_sha512() -> Self {
        Self {
            algorithm: KdfAlgorithm::Pbkdf2Sha512,
        }
    }

    /// Create HKDF (for key expansion, not password hashing)
    pub fn hkdf() -> Self {
        Self {
            algorithm: KdfAlgorithm::Hkdf,
        }
    }

    /// Derive key with Argon2
    pub fn derive_argon2(
        &self,
        password: &[u8],
        salt: &[u8],
        params: Argon2Params,
    ) -> Result<DerivedKey, KdfError> {
        params.validate()?;

        if salt.len() < 16 {
            return Err(KdfError::InvalidSalt);
        }

        // Simplified Argon2 simulation
        let mut output = vec![0u8; params.output_length];
        self.simulate_argon2(password, salt, &params, &mut output);

        Ok(DerivedKey {
            key: output,
            salt: salt.to_vec(),
            algorithm: self.algorithm,
            params_hash: params.to_string(),
        })
    }

    /// Derive key with scrypt
    pub fn derive_scrypt(
        &self,
        password: &[u8],
        salt: &[u8],
        params: ScryptParams,
    ) -> Result<DerivedKey, KdfError> {
        params.validate()?;

        if salt.len() < 16 {
            return Err(KdfError::InvalidSalt);
        }

        let mut output = vec![0u8; params.output_length];
        self.simulate_scrypt(password, salt, &params, &mut output);

        Ok(DerivedKey {
            key: output,
            salt: salt.to_vec(),
            algorithm: KdfAlgorithm::Scrypt,
            params_hash: params.to_string(),
        })
    }

    /// Derive key with PBKDF2
    pub fn derive_pbkdf2(
        &self,
        password: &[u8],
        salt: &[u8],
        params: Pbkdf2Params,
    ) -> Result<DerivedKey, KdfError> {
        params.validate()?;

        if salt.len() < 16 {
            return Err(KdfError::InvalidSalt);
        }

        let mut output = vec![0u8; params.output_length];
        self.simulate_pbkdf2(password, salt, &params, &mut output);

        Ok(DerivedKey {
            key: output,
            salt: salt.to_vec(),
            algorithm: self.algorithm,
            params_hash: params.to_string(),
        })
    }

    /// Expand key with HKDF
    pub fn expand_hkdf(
        &self,
        input_key: &[u8],
        salt: Option<&[u8]>,
        params: HkdfParams,
    ) -> Result<Vec<u8>, KdfError> {
        if params.output_length > 255 * 32 {
            return Err(KdfError::OutputTooLong);
        }

        let salt = salt.unwrap_or(&[0u8; 32]);
        let mut output = vec![0u8; params.output_length];
        self.simulate_hkdf(input_key, salt, &params.info, &mut output);

        Ok(output)
    }

    /// Verify password against derived key
    pub fn verify(&self, password: &[u8], derived: &DerivedKey) -> bool {
        let result = match derived.algorithm {
            KdfAlgorithm::Argon2id | KdfAlgorithm::Argon2i | KdfAlgorithm::Argon2d => {
                let params = Argon2Params::from_string(&derived.params_hash)
                    .unwrap_or(Argon2Params::default());
                self.derive_argon2(password, &derived.salt, params)
            }
            KdfAlgorithm::Scrypt => {
                let params = ScryptParams::from_string(&derived.params_hash)
                    .unwrap_or(ScryptParams::default());
                self.derive_scrypt(password, &derived.salt, params)
            }
            KdfAlgorithm::Pbkdf2Sha256 | KdfAlgorithm::Pbkdf2Sha512 => {
                let params = Pbkdf2Params::from_string(&derived.params_hash)
                    .unwrap_or(Pbkdf2Params::default());
                self.derive_pbkdf2(password, &derived.salt, params)
            }
            KdfAlgorithm::Hkdf => return false, // HKDF not for password verification
        };

        match result {
            Ok(new_derived) => constant_time_eq(&new_derived.key, &derived.key),
            Err(_) => false,
        }
    }

    // Simulation functions (in real implementation, use actual crypto)

    fn simulate_argon2(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &Argon2Params,
        output: &mut [u8],
    ) {
        let mut state = 0u64;

        // Mix password
        for &byte in password {
            state = state.wrapping_mul(31).wrapping_add(byte as u64);
        }

        // Mix salt
        for &byte in salt {
            state = state.wrapping_mul(37).wrapping_add(byte as u64);
        }

        // Simulate memory-hard computation
        for t in 0..params.time_cost {
            for m in 0..params.memory_cost {
                state = state
                    .wrapping_mul(0x5851f42d4c957f2d)
                    .wrapping_add(m as u64 + t as u64);
                state = state.rotate_left(17);
            }
        }

        // Generate output
        for (i, byte) in output.iter_mut().enumerate() {
            state = state
                .wrapping_mul(0x2545f4914f6cdd1d)
                .wrapping_add(i as u64);
            *byte = (state >> 32) as u8;
        }
    }

    fn simulate_scrypt(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ScryptParams,
        output: &mut [u8],
    ) {
        let mut state = 0u64;
        let n = 1u64 << params.log_n;

        for &byte in password {
            state = state.wrapping_mul(31).wrapping_add(byte as u64);
        }

        for &byte in salt {
            state = state.wrapping_mul(37).wrapping_add(byte as u64);
        }

        // Simulate memory-hard computation
        for _ in 0..n {
            for _ in 0..params.r {
                state = state.wrapping_mul(0x5851f42d4c957f2d);
                state = state.rotate_left(13);
            }
        }

        for (i, byte) in output.iter_mut().enumerate() {
            state = state
                .wrapping_mul(0x2545f4914f6cdd1d)
                .wrapping_add(i as u64);
            *byte = (state >> 32) as u8;
        }
    }

    fn simulate_pbkdf2(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &Pbkdf2Params,
        output: &mut [u8],
    ) {
        let mut state = 0u64;

        for &byte in password {
            state = state.wrapping_mul(31).wrapping_add(byte as u64);
        }

        for &byte in salt {
            state = state.wrapping_mul(37).wrapping_add(byte as u64);
        }

        for _ in 0..params.iterations {
            state = state.wrapping_mul(0x5851f42d4c957f2d);
            state = state.rotate_left(17);
        }

        for (i, byte) in output.iter_mut().enumerate() {
            state = state
                .wrapping_mul(0x2545f4914f6cdd1d)
                .wrapping_add(i as u64);
            *byte = (state >> 32) as u8;
        }
    }

    fn simulate_hkdf(&self, ikm: &[u8], salt: &[u8], info: &[u8], output: &mut [u8]) {
        let mut state = 0u64;

        // Extract
        for &byte in salt {
            state = state.wrapping_mul(31).wrapping_add(byte as u64);
        }
        for &byte in ikm {
            state = state.wrapping_mul(37).wrapping_add(byte as u64);
        }

        // Expand
        for &byte in info {
            state = state.wrapping_mul(41).wrapping_add(byte as u64);
        }

        for (i, byte) in output.iter_mut().enumerate() {
            state = state
                .wrapping_mul(0x2545f4914f6cdd1d)
                .wrapping_add(i as u64);
            *byte = (state >> 32) as u8;
        }
    }
}

impl Argon2Params {
    /// Default parameters (OWASP recommendations)
    pub fn default() -> Self {
        Self {
            memory_cost: 65536, // 64 MiB
            time_cost: 3,
            parallelism: 4,
            output_length: 32,
        }
    }

    /// Low memory parameters (for constrained environments)
    pub fn low_memory() -> Self {
        Self {
            memory_cost: 16384, // 16 MiB
            time_cost: 4,
            parallelism: 2,
            output_length: 32,
        }
    }

    /// High security parameters
    pub fn high_security() -> Self {
        Self {
            memory_cost: 262144, // 256 MiB
            time_cost: 4,
            parallelism: 8,
            output_length: 32,
        }
    }

    /// Calibrate parameters for target duration
    pub fn calibrate(target_duration: Duration) -> Self {
        let mut params = Self::default();
        let start = Instant::now();

        // Start with baseline
        let kdf = Kdf::argon2id();
        let salt = [0u8; 32];
        let _ = kdf.derive_argon2(b"test", &salt, params);

        let elapsed = start.elapsed();

        // Adjust time_cost to get closer to target
        if elapsed < target_duration {
            let ratio = target_duration.as_millis() as f64 / elapsed.as_millis().max(1) as f64;
            params.time_cost = ((params.time_cost as f64 * ratio) as u32).max(1);
        }

        params
    }

    fn validate(&self) -> Result<(), KdfError> {
        if self.memory_cost < 8 {
            return Err(KdfError::InvalidParams("memory_cost too low".to_string()));
        }
        if self.time_cost < 1 {
            return Err(KdfError::InvalidParams(
                "time_cost must be >= 1".to_string(),
            ));
        }
        if self.parallelism < 1 {
            return Err(KdfError::InvalidParams(
                "parallelism must be >= 1".to_string(),
            ));
        }
        if self.output_length < 4 || self.output_length > 1024 {
            return Err(KdfError::InvalidParams(
                "output_length out of range".to_string(),
            ));
        }
        Ok(())
    }

    fn from_string(s: &str) -> Option<Self> {
        // Parse "m=65536,t=3,p=4,l=32"
        let mut params = Self::default();
        for part in s.split(',') {
            let kv: Vec<&str> = part.split('=').collect();
            if kv.len() == 2 {
                match kv[0] {
                    "m" => params.memory_cost = kv[1].parse().ok()?,
                    "t" => params.time_cost = kv[1].parse().ok()?,
                    "p" => params.parallelism = kv[1].parse().ok()?,
                    "l" => params.output_length = kv[1].parse().ok()?,
                    _ => {}
                }
            }
        }
        Some(params)
    }
}

impl fmt::Display for Argon2Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "m={},t={},p={},l={}",
            self.memory_cost, self.time_cost, self.parallelism, self.output_length
        )
    }
}

impl ScryptParams {
    pub fn default() -> Self {
        Self {
            log_n: 15, // N = 32768
            r: 8,
            p: 1,
            output_length: 32,
        }
    }

    pub fn interactive() -> Self {
        Self {
            log_n: 14,
            r: 8,
            p: 1,
            output_length: 32,
        }
    }

    pub fn sensitive() -> Self {
        Self {
            log_n: 20,
            r: 8,
            p: 1,
            output_length: 32,
        }
    }

    fn validate(&self) -> Result<(), KdfError> {
        if self.log_n < 1 || self.log_n > 30 {
            return Err(KdfError::InvalidParams("log_n out of range".to_string()));
        }
        if self.r < 1 {
            return Err(KdfError::InvalidParams("r must be >= 1".to_string()));
        }
        if self.p < 1 {
            return Err(KdfError::InvalidParams("p must be >= 1".to_string()));
        }
        Ok(())
    }

    fn from_string(s: &str) -> Option<Self> {
        let mut params = Self::default();
        for part in s.split(',') {
            let kv: Vec<&str> = part.split('=').collect();
            if kv.len() == 2 {
                match kv[0] {
                    "n" => params.log_n = kv[1].parse().ok()?,
                    "r" => params.r = kv[1].parse().ok()?,
                    "p" => params.p = kv[1].parse().ok()?,
                    "l" => params.output_length = kv[1].parse().ok()?,
                    _ => {}
                }
            }
        }
        Some(params)
    }
}

impl fmt::Display for ScryptParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "n={},r={},p={},l={}",
            self.log_n, self.r, self.p, self.output_length
        )
    }
}

impl Pbkdf2Params {
    pub fn default() -> Self {
        Self {
            iterations: 600000, // OWASP 2023 recommendation for SHA-256
            output_length: 32,
        }
    }

    pub fn sha512_default() -> Self {
        Self {
            iterations: 210000, // OWASP 2023 recommendation for SHA-512
            output_length: 64,
        }
    }

    fn validate(&self) -> Result<(), KdfError> {
        if self.iterations < 10000 {
            return Err(KdfError::InvalidParams("iterations too low".to_string()));
        }
        Ok(())
    }

    fn from_string(s: &str) -> Option<Self> {
        let mut params = Self::default();
        for part in s.split(',') {
            let kv: Vec<&str> = part.split('=').collect();
            if kv.len() == 2 {
                match kv[0] {
                    "i" => params.iterations = kv[1].parse().ok()?,
                    "l" => params.output_length = kv[1].parse().ok()?,
                    _ => {}
                }
            }
        }
        Some(params)
    }
}

impl fmt::Display for Pbkdf2Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "i={},l={}", self.iterations, self.output_length)
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

/// Generate cryptographic salt
pub fn generate_salt(length: usize) -> Vec<u8> {
    // In production, use OsRng
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let mut salt = vec![0u8; length];
    let mut state = seed;
    for byte in &mut salt {
        state = state
            .wrapping_mul(0x5851f42d4c957f2d)
            .wrapping_add(0x14057b7ef767814f);
        *byte = (state >> 32) as u8;
    }
    salt
}

fn main() {
    println!("=== Key Derivation Functions Demo ===\n");

    // Argon2id (recommended)
    println!("=== Argon2id ===\n");

    let kdf = Kdf::argon2id();
    let password = b"my_secure_password";
    let salt = generate_salt(32);

    let params = Argon2Params::default();
    println!("Parameters: {}", params);

    let derived = kdf.derive_argon2(password, &salt, params).unwrap();
    println!("Derived key: {} bytes", derived.key.len());
    println!("Key (hex): {}", hex_encode(&derived.key));

    // Verify password
    let valid = kdf.verify(password, &derived);
    println!("Password verification: {}", valid);

    let wrong = kdf.verify(b"wrong_password", &derived);
    println!("Wrong password verification: {}\n", wrong);

    // scrypt
    println!("=== scrypt ===\n");

    let scrypt_kdf = Kdf::scrypt();
    let scrypt_params = ScryptParams::default();
    println!("Parameters: {}", scrypt_params);

    let scrypt_derived = scrypt_kdf
        .derive_scrypt(password, &salt, scrypt_params)
        .unwrap();
    println!("Derived key (hex): {}\n", hex_encode(&scrypt_derived.key));

    // PBKDF2
    println!("=== PBKDF2-SHA256 ===\n");

    let pbkdf2_kdf = Kdf::pbkdf2_sha256();
    let pbkdf2_params = Pbkdf2Params::default();
    println!("Parameters: {}", pbkdf2_params);

    let pbkdf2_derived = pbkdf2_kdf
        .derive_pbkdf2(password, &salt, pbkdf2_params)
        .unwrap();
    println!("Derived key (hex): {}\n", hex_encode(&pbkdf2_derived.key));

    // HKDF for key expansion
    println!("=== HKDF (Key Expansion) ===\n");

    let hkdf = Kdf::hkdf();
    let input_key = &derived.key;

    // Derive multiple keys from one master key
    let enc_key = hkdf
        .expand_hkdf(
            input_key,
            Some(&salt),
            HkdfParams {
                info: b"encryption".to_vec(),
                output_length: 32,
            },
        )
        .unwrap();

    let mac_key = hkdf
        .expand_hkdf(
            input_key,
            Some(&salt),
            HkdfParams {
                info: b"authentication".to_vec(),
                output_length: 32,
            },
        )
        .unwrap();

    println!("Encryption key: {}", hex_encode(&enc_key));
    println!("MAC key: {}", hex_encode(&mac_key));

    // Calibration
    println!("\n=== Parameter Calibration ===\n");

    let calibrated = Argon2Params::calibrate(Duration::from_millis(500));
    println!("Calibrated for ~500ms: {}", calibrated);

    // Different security levels
    println!("\n=== Security Levels ===\n");

    println!("Argon2 Low Memory: {}", Argon2Params::low_memory());
    println!("Argon2 Default: {}", Argon2Params::default());
    println!("Argon2 High Security: {}", Argon2Params::high_security());
    println!();
    println!("scrypt Interactive: {}", ScryptParams::interactive());
    println!("scrypt Default: {}", ScryptParams::default());
    println!("scrypt Sensitive: {}", ScryptParams::sensitive());
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_derivation() {
        let kdf = Kdf::argon2id();
        let password = b"test_password";
        let salt = generate_salt(32);
        let params = Argon2Params::default();

        let result = kdf.derive_argon2(password, &salt, params);
        assert!(result.is_ok());

        let derived = result.unwrap();
        assert_eq!(derived.key.len(), 32);
    }

    #[test]
    fn test_argon2_verification() {
        let kdf = Kdf::argon2id();
        let password = b"correct_password";
        let salt = generate_salt(32);

        let derived = kdf
            .derive_argon2(password, &salt, Argon2Params::default())
            .unwrap();

        assert!(kdf.verify(password, &derived));
        assert!(!kdf.verify(b"wrong_password", &derived));
    }

    #[test]
    fn test_scrypt_derivation() {
        let kdf = Kdf::scrypt();
        let password = b"test_password";
        let salt = generate_salt(32);

        let result = kdf.derive_scrypt(password, &salt, ScryptParams::default());
        assert!(result.is_ok());
    }

    #[test]
    fn test_pbkdf2_derivation() {
        let kdf = Kdf::pbkdf2_sha256();
        let password = b"test_password";
        let salt = generate_salt(32);

        let result = kdf.derive_pbkdf2(password, &salt, Pbkdf2Params::default());
        assert!(result.is_ok());
    }

    #[test]
    fn test_hkdf_expansion() {
        let kdf = Kdf::hkdf();
        let ikm = b"input_key_material";

        let result = kdf.expand_hkdf(
            ikm,
            None,
            HkdfParams {
                info: b"test".to_vec(),
                output_length: 64,
            },
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 64);
    }

    #[test]
    fn test_hkdf_different_info_different_keys() {
        let kdf = Kdf::hkdf();
        let ikm = b"master_key";
        let salt = generate_salt(32);

        let key1 = kdf
            .expand_hkdf(
                ikm,
                Some(&salt),
                HkdfParams {
                    info: b"encryption".to_vec(),
                    output_length: 32,
                },
            )
            .unwrap();

        let key2 = kdf
            .expand_hkdf(
                ikm,
                Some(&salt),
                HkdfParams {
                    info: b"authentication".to_vec(),
                    output_length: 32,
                },
            )
            .unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_salt_too_short() {
        let kdf = Kdf::argon2id();
        let password = b"test";
        let short_salt = [0u8; 8]; // Too short

        let result = kdf.derive_argon2(password, &short_salt, Argon2Params::default());
        assert!(matches!(result, Err(KdfError::InvalidSalt)));
    }

    #[test]
    fn test_invalid_argon2_params() {
        let params = Argon2Params {
            memory_cost: 4, // Too low
            ..Argon2Params::default()
        };

        assert!(params.validate().is_err());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    #[test]
    fn test_deterministic_derivation() {
        let kdf = Kdf::argon2id();
        let password = b"test";
        let salt = [1u8; 32];
        let params = Argon2Params::default();

        let derived1 = kdf.derive_argon2(password, &salt, params).unwrap();
        let derived2 = kdf.derive_argon2(password, &salt, params).unwrap();

        assert_eq!(derived1.key, derived2.key);
    }

    #[test]
    fn test_different_salts_different_keys() {
        let kdf = Kdf::argon2id();
        let password = b"test";
        let salt1 = generate_salt(32);
        let salt2 = generate_salt(32);
        let params = Argon2Params::default();

        let derived1 = kdf.derive_argon2(password, &salt1, params).unwrap();
        let derived2 = kdf.derive_argon2(password, &salt2, params).unwrap();

        assert_ne!(derived1.key, derived2.key);
    }

    #[test]
    fn test_params_to_string() {
        let argon2 = Argon2Params::default();
        let s = argon2.to_string();
        assert!(s.contains("m="));
        assert!(s.contains("t="));
        assert!(s.contains("p="));

        let parsed = Argon2Params::from_string(&s).unwrap();
        assert_eq!(parsed.memory_cost, argon2.memory_cost);
    }
}
