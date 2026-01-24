//! Argon2 Key Derivation Function
//!
//! Secure password hashing and key derivation using Argon2,
//! the winner of the Password Hashing Competition.

use std::time::{Duration, Instant};

/// Argon2 variant
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Variant {
    /// Argon2d - Data-dependent, maximum GPU resistance
    Argon2d,
    /// Argon2i - Data-independent, side-channel resistant
    Argon2i,
    /// Argon2id - Hybrid, recommended for most uses
    Argon2id,
}

impl Argon2Variant {
    pub fn as_str(&self) -> &'static str {
        match self {
            Argon2Variant::Argon2d => "argon2d",
            Argon2Variant::Argon2i => "argon2i",
            Argon2Variant::Argon2id => "argon2id",
        }
    }
}

/// Argon2 parameters
#[derive(Debug, Clone)]
pub struct Argon2Params {
    /// Memory cost in KiB
    pub memory_cost: u32,
    /// Time cost (iterations)
    pub time_cost: u32,
    /// Degree of parallelism
    pub parallelism: u32,
    /// Output length in bytes
    pub output_length: usize,
    /// Salt length in bytes
    pub salt_length: usize,
    /// Argon2 variant
    pub variant: Argon2Variant,
}

impl Default for Argon2Params {
    fn default() -> Self {
        // OWASP recommended parameters for password hashing (2024)
        Self {
            memory_cost: 19456, // 19 MiB
            time_cost: 2,       // 2 iterations
            parallelism: 1,     // 1 thread
            output_length: 32,  // 256-bit output
            salt_length: 16,    // 128-bit salt
            variant: Argon2Variant::Argon2id,
        }
    }
}

impl Argon2Params {
    /// Create new parameters with custom values
    pub fn new(memory_kib: u32, time_cost: u32, parallelism: u32) -> Self {
        Self {
            memory_cost: memory_kib,
            time_cost,
            parallelism,
            ..Default::default()
        }
    }

    /// High security profile (slower, more resistant)
    pub fn high_security() -> Self {
        Self {
            memory_cost: 65536, // 64 MiB
            time_cost: 4,
            parallelism: 4,
            ..Default::default()
        }
    }

    /// Interactive profile (faster, for real-time auth)
    pub fn interactive() -> Self {
        Self {
            memory_cost: 4096, // 4 MiB
            time_cost: 3,
            parallelism: 1,
            ..Default::default()
        }
    }

    /// Validate parameters
    pub fn validate(&self) -> Result<(), Argon2Error> {
        if self.memory_cost < 8 {
            return Err(Argon2Error::InvalidParameter(
                "memory_cost must be at least 8 KiB".to_string(),
            ));
        }
        if self.time_cost < 1 {
            return Err(Argon2Error::InvalidParameter(
                "time_cost must be at least 1".to_string(),
            ));
        }
        if self.parallelism < 1 || self.parallelism > 255 {
            return Err(Argon2Error::InvalidParameter(
                "parallelism must be between 1 and 255".to_string(),
            ));
        }
        if self.output_length < 4 || self.output_length > 1024 {
            return Err(Argon2Error::InvalidParameter(
                "output_length must be between 4 and 1024".to_string(),
            ));
        }
        if self.salt_length < 8 {
            return Err(Argon2Error::InvalidParameter(
                "salt_length must be at least 8".to_string(),
            ));
        }
        Ok(())
    }

    /// Estimate memory usage
    pub fn memory_usage(&self) -> usize {
        self.memory_cost as usize * 1024
    }

    /// Encode parameters to string
    pub fn encode(&self) -> String {
        format!(
            "${}$v=19$m={},t={},p={}",
            self.variant.as_str(),
            self.memory_cost,
            self.time_cost,
            self.parallelism
        )
    }
}

/// Argon2 hasher
#[derive(Debug)]
pub struct Argon2Hasher {
    params: Argon2Params,
}

impl Argon2Hasher {
    pub fn new(params: Argon2Params) -> Result<Self, Argon2Error> {
        params.validate()?;
        Ok(Self { params })
    }

    /// Hash a password with a random salt
    pub fn hash_password(&self, password: &[u8]) -> Result<PasswordHash, Argon2Error> {
        let salt = self.generate_salt();
        self.hash_password_with_salt(password, &salt)
    }

    /// Hash a password with a provided salt
    pub fn hash_password_with_salt(
        &self,
        password: &[u8],
        salt: &[u8],
    ) -> Result<PasswordHash, Argon2Error> {
        if salt.len() < 8 {
            return Err(Argon2Error::InvalidSalt);
        }

        // Simulate Argon2 hashing (in production, use the argon2 crate)
        let hash = self.compute_hash(password, salt)?;

        Ok(PasswordHash {
            variant: self.params.variant,
            version: 19,
            memory_cost: self.params.memory_cost,
            time_cost: self.params.time_cost,
            parallelism: self.params.parallelism,
            salt: salt.to_vec(),
            hash,
        })
    }

    /// Verify a password against a hash
    pub fn verify_password(
        &self,
        password: &[u8],
        hash: &PasswordHash,
    ) -> Result<bool, Argon2Error> {
        let computed = self.compute_hash(password, &hash.salt)?;

        // Constant-time comparison
        Ok(constant_time_eq(&computed, &hash.hash))
    }

    /// Derive a key from a password
    pub fn derive_key(
        &self,
        password: &[u8],
        salt: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, Argon2Error> {
        if salt.len() < 8 {
            return Err(Argon2Error::InvalidSalt);
        }

        let mut params = self.params.clone();
        params.output_length = key_length;

        // Simulate key derivation
        self.compute_hash_with_length(password, salt, key_length)
    }

    /// Generate a random salt
    fn generate_salt(&self) -> Vec<u8> {
        // In production, use a CSPRNG like rand::rngs::OsRng
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut salt = Vec::with_capacity(self.params.salt_length);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        for i in 0..self.params.salt_length {
            let mut hasher = DefaultHasher::new();
            timestamp.hash(&mut hasher);
            i.hash(&mut hasher);
            std::process::id().hash(&mut hasher);
            salt.push((hasher.finish() & 0xFF) as u8);
        }

        salt
    }

    /// Compute hash (simplified simulation)
    fn compute_hash(&self, password: &[u8], salt: &[u8]) -> Result<Vec<u8>, Argon2Error> {
        self.compute_hash_with_length(password, salt, self.params.output_length)
    }

    /// Compute hash with specified length
    fn compute_hash_with_length(
        &self,
        password: &[u8],
        salt: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, Argon2Error> {
        // This is a simplified simulation for demonstration
        // In production, use the argon2 crate

        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut result = Vec::with_capacity(length);
        let mut state = 0u64;

        // Mix password and salt
        for (i, &byte) in password.iter().chain(salt.iter()).enumerate() {
            let mut hasher = DefaultHasher::new();
            state.hash(&mut hasher);
            (byte as u64).hash(&mut hasher);
            (i as u64).hash(&mut hasher);
            state = hasher.finish();
        }

        // Apply time cost (iterations)
        for _ in 0..self.params.time_cost {
            let mut hasher = DefaultHasher::new();
            state.hash(&mut hasher);
            self.params.memory_cost.hash(&mut hasher);
            state = hasher.finish();
        }

        // Generate output
        for i in 0..length {
            let mut hasher = DefaultHasher::new();
            state.hash(&mut hasher);
            i.hash(&mut hasher);
            let value = hasher.finish();
            result.push((value & 0xFF) as u8);
            state = value;
        }

        Ok(result)
    }

    /// Benchmark parameters to find suitable values
    pub fn benchmark(&self, target_duration: Duration) -> BenchmarkResult {
        let password = b"benchmark_password";
        let salt = self.generate_salt();

        let start = Instant::now();
        let _ = self.hash_password_with_salt(password, &salt);
        let duration = start.elapsed();

        BenchmarkResult {
            params: self.params.clone(),
            duration,
            meets_target: duration >= target_duration,
            memory_used: self.params.memory_usage(),
        }
    }
}

/// Password hash result
#[derive(Debug, Clone)]
pub struct PasswordHash {
    pub variant: Argon2Variant,
    pub version: u8,
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub salt: Vec<u8>,
    pub hash: Vec<u8>,
}

impl PasswordHash {
    /// Encode to PHC string format
    pub fn encode(&self) -> String {
        let salt_b64 = base64_encode(&self.salt);
        let hash_b64 = base64_encode(&self.hash);

        format!(
            "${}$v={}$m={},t={},p={}${}${}",
            self.variant.as_str(),
            self.version,
            self.memory_cost,
            self.time_cost,
            self.parallelism,
            salt_b64,
            hash_b64
        )
    }

    /// Decode from PHC string format
    pub fn decode(encoded: &str) -> Result<Self, Argon2Error> {
        let parts: Vec<&str> = encoded.split('$').collect();
        if parts.len() != 6 {
            return Err(Argon2Error::InvalidHash);
        }

        let variant = match parts[1] {
            "argon2d" => Argon2Variant::Argon2d,
            "argon2i" => Argon2Variant::Argon2i,
            "argon2id" => Argon2Variant::Argon2id,
            _ => return Err(Argon2Error::InvalidHash),
        };

        // Parse version
        let version = parts[2]
            .strip_prefix("v=")
            .and_then(|v| v.parse().ok())
            .ok_or(Argon2Error::InvalidHash)?;

        // Parse parameters
        let params: Vec<&str> = parts[3].split(',').collect();
        if params.len() != 3 {
            return Err(Argon2Error::InvalidHash);
        }

        let memory_cost = params[0]
            .strip_prefix("m=")
            .and_then(|m| m.parse().ok())
            .ok_or(Argon2Error::InvalidHash)?;

        let time_cost = params[1]
            .strip_prefix("t=")
            .and_then(|t| t.parse().ok())
            .ok_or(Argon2Error::InvalidHash)?;

        let parallelism = params[2]
            .strip_prefix("p=")
            .and_then(|p| p.parse().ok())
            .ok_or(Argon2Error::InvalidHash)?;

        let salt = base64_decode(parts[4]).map_err(|_| Argon2Error::InvalidHash)?;
        let hash = base64_decode(parts[5]).map_err(|_| Argon2Error::InvalidHash)?;

        Ok(Self {
            variant,
            version,
            memory_cost,
            time_cost,
            parallelism,
            salt,
            hash,
        })
    }

    /// Check if parameters need upgrade
    pub fn needs_upgrade(&self, recommended: &Argon2Params) -> bool {
        self.memory_cost < recommended.memory_cost
            || self.time_cost < recommended.time_cost
            || self.parallelism < recommended.parallelism
    }
}

/// Benchmark result
#[derive(Debug)]
pub struct BenchmarkResult {
    pub params: Argon2Params,
    pub duration: Duration,
    pub meets_target: bool,
    pub memory_used: usize,
}

/// Argon2 errors
#[derive(Debug)]
pub enum Argon2Error {
    InvalidParameter(String),
    InvalidSalt,
    InvalidHash,
    VerificationFailed,
}

impl std::fmt::Display for Argon2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Argon2Error::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            Argon2Error::InvalidSalt => write!(f, "Invalid salt"),
            Argon2Error::InvalidHash => write!(f, "Invalid hash format"),
            Argon2Error::VerificationFailed => write!(f, "Password verification failed"),
        }
    }
}

impl std::error::Error for Argon2Error {}

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

/// Simple base64 encoding
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

/// Simple base64 decoding
fn base64_decode(data: &str) -> Result<Vec<u8>, ()> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = Vec::new();

    let chars: Vec<u8> = data
        .chars()
        .filter(|&c| c != '=')
        .filter_map(|c| {
            ALPHABET
                .iter()
                .position(|&b| b as char == c)
                .map(|p| p as u8)
        })
        .collect();

    for chunk in chars.chunks(4) {
        if chunk.len() >= 2 {
            result.push((chunk[0] << 2) | (chunk[1] >> 4));
        }
        if chunk.len() >= 3 {
            result.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        if chunk.len() >= 4 {
            result.push((chunk[2] << 6) | chunk[3]);
        }
    }

    Ok(result)
}

/// Parameter tuner for finding optimal parameters
pub struct ParameterTuner {
    target_duration: Duration,
    max_memory: usize,
}

impl ParameterTuner {
    pub fn new(target_duration: Duration, max_memory_mib: usize) -> Self {
        Self {
            target_duration,
            max_memory: max_memory_mib * 1024 * 1024,
        }
    }

    /// Find optimal parameters for target duration
    pub fn tune(&self) -> Result<Argon2Params, Argon2Error> {
        let mut best_params = Argon2Params::default();
        let mut best_diff = Duration::MAX;

        // Try different memory costs
        for memory_kib in [4096, 8192, 16384, 32768, 65536] {
            if memory_kib as usize * 1024 > self.max_memory {
                continue;
            }

            // Try different time costs
            for time_cost in [1, 2, 3, 4, 5] {
                let params = Argon2Params::new(memory_kib, time_cost, 1);
                let hasher = Argon2Hasher::new(params.clone())?;
                let result = hasher.benchmark(self.target_duration);

                let diff = if result.duration > self.target_duration {
                    result.duration - self.target_duration
                } else {
                    self.target_duration - result.duration
                };

                if diff < best_diff {
                    best_diff = diff;
                    best_params = params;
                }
            }
        }

        Ok(best_params)
    }
}

fn main() {
    println!("=== Argon2 Key Derivation Demo ===\n");

    // Create hasher with default OWASP-recommended parameters
    let params = Argon2Params::default();
    println!("Parameters:");
    println!("  Variant: {}", params.variant.as_str());
    println!("  Memory: {} KiB", params.memory_cost);
    println!("  Time cost: {}", params.time_cost);
    println!("  Parallelism: {}", params.parallelism);
    println!("  Output length: {} bytes", params.output_length);
    println!();

    let hasher = Argon2Hasher::new(params.clone()).unwrap();

    // Hash a password
    println!("--- Password Hashing ---\n");
    let password = b"my_secure_password_123!";
    let hash = hasher.hash_password(password).unwrap();

    println!("Password: {}", String::from_utf8_lossy(password));
    println!("Salt (hex): {}", hex_encode(&hash.salt));
    println!("Hash (hex): {}", hex_encode(&hash.hash));
    println!();

    // Encode to PHC format
    let encoded = hash.encode();
    println!("Encoded (PHC format):");
    println!("  {}", encoded);
    println!();

    // Verify password
    println!("--- Password Verification ---\n");
    let is_valid = hasher.verify_password(password, &hash).unwrap();
    println!("Correct password: {}", is_valid);

    let wrong_password = b"wrong_password";
    let is_valid = hasher.verify_password(wrong_password, &hash).unwrap();
    println!("Wrong password: {}", is_valid);
    println!();

    // Decode from PHC format
    println!("--- Decode PHC String ---\n");
    let decoded = PasswordHash::decode(&encoded).unwrap();
    println!("Decoded successfully:");
    println!("  Variant: {}", decoded.variant.as_str());
    println!("  Memory: {} KiB", decoded.memory_cost);
    println!("  Time cost: {}", decoded.time_cost);
    println!();

    // Key derivation
    println!("--- Key Derivation ---\n");
    let salt = b"unique_salt_for_key";
    let derived_key = hasher.derive_key(password, salt, 32).unwrap();
    println!("Derived 256-bit key: {}", hex_encode(&derived_key));
    println!();

    // Different profiles
    println!("--- Security Profiles ---\n");

    let profiles = [
        ("Default (OWASP)", Argon2Params::default()),
        ("High Security", Argon2Params::high_security()),
        ("Interactive", Argon2Params::interactive()),
    ];

    for (name, params) in profiles {
        let hasher = Argon2Hasher::new(params.clone()).unwrap();
        let result = hasher.benchmark(Duration::from_millis(100));
        println!("{}:", name);
        println!("  Memory: {} KiB", result.params.memory_cost);
        println!("  Time cost: {}", result.params.time_cost);
        println!("  Duration: {:?}", result.duration);
        println!();
    }

    // Check upgrade needed
    println!("--- Parameter Upgrade Check ---\n");
    let old_hash = PasswordHash {
        variant: Argon2Variant::Argon2id,
        version: 19,
        memory_cost: 4096,
        time_cost: 1,
        parallelism: 1,
        salt: vec![0; 16],
        hash: vec![0; 32],
    };

    let recommended = Argon2Params::default();
    if old_hash.needs_upgrade(&recommended) {
        println!("Hash needs upgrade to current recommended parameters");
        println!(
            "  Current: m={}, t={}, p={}",
            old_hash.memory_cost, old_hash.time_cost, old_hash.parallelism
        );
        println!(
            "  Recommended: m={}, t={}, p={}",
            recommended.memory_cost, recommended.time_cost, recommended.parallelism
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
    fn test_params_default() {
        let params = Argon2Params::default();
        assert!(params.validate().is_ok());
        assert_eq!(params.variant, Argon2Variant::Argon2id);
    }

    #[test]
    fn test_params_validation() {
        let invalid_params = Argon2Params {
            memory_cost: 0,
            ..Default::default()
        };
        assert!(invalid_params.validate().is_err());
    }

    #[test]
    fn test_hash_password() {
        let hasher = Argon2Hasher::new(Argon2Params::default()).unwrap();
        let hash = hasher.hash_password(b"password").unwrap();

        assert!(!hash.salt.is_empty());
        assert!(!hash.hash.is_empty());
        assert_eq!(hash.hash.len(), 32);
    }

    #[test]
    fn test_verify_correct_password() {
        let hasher = Argon2Hasher::new(Argon2Params::default()).unwrap();
        let hash = hasher.hash_password(b"password").unwrap();

        assert!(hasher.verify_password(b"password", &hash).unwrap());
    }

    #[test]
    fn test_verify_wrong_password() {
        let hasher = Argon2Hasher::new(Argon2Params::default()).unwrap();
        let hash = hasher.hash_password(b"password").unwrap();

        assert!(!hasher.verify_password(b"wrong", &hash).unwrap());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let hasher = Argon2Hasher::new(Argon2Params::default()).unwrap();
        let original = hasher.hash_password(b"password").unwrap();

        let encoded = original.encode();
        let decoded = PasswordHash::decode(&encoded).unwrap();

        assert_eq!(original.variant, decoded.variant);
        assert_eq!(original.version, decoded.version);
        assert_eq!(original.memory_cost, decoded.memory_cost);
        assert_eq!(original.time_cost, decoded.time_cost);
        assert_eq!(original.parallelism, decoded.parallelism);
    }

    #[test]
    fn test_key_derivation() {
        let hasher = Argon2Hasher::new(Argon2Params::default()).unwrap();
        let key = hasher.derive_key(b"password", b"salt12345678", 64).unwrap();

        assert_eq!(key.len(), 64);
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let hasher = Argon2Hasher::new(Argon2Params::default()).unwrap();
        let key1 = hasher.derive_key(b"password", b"salt12345678", 32).unwrap();
        let key2 = hasher.derive_key(b"password", b"salt12345678", 32).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_different_passwords_different_hashes() {
        let hasher = Argon2Hasher::new(Argon2Params::default()).unwrap();
        let salt = b"common_salt_1234";

        let hash1 = hasher.hash_password_with_salt(b"password1", salt).unwrap();
        let hash2 = hasher.hash_password_with_salt(b"password2", salt).unwrap();

        assert_ne!(hash1.hash, hash2.hash);
    }

    #[test]
    fn test_different_salts_different_hashes() {
        let hasher = Argon2Hasher::new(Argon2Params::default()).unwrap();

        let hash1 = hasher
            .hash_password_with_salt(b"password", b"salt1_12345678")
            .unwrap();
        let hash2 = hasher
            .hash_password_with_salt(b"password", b"salt2_12345678")
            .unwrap();

        assert_ne!(hash1.hash, hash2.hash);
    }

    #[test]
    fn test_invalid_salt() {
        let hasher = Argon2Hasher::new(Argon2Params::default()).unwrap();
        let result = hasher.hash_password_with_salt(b"password", b"short");

        assert!(result.is_err());
    }

    #[test]
    fn test_needs_upgrade() {
        let old_hash = PasswordHash {
            variant: Argon2Variant::Argon2id,
            version: 19,
            memory_cost: 1024,
            time_cost: 1,
            parallelism: 1,
            salt: vec![0; 16],
            hash: vec![0; 32],
        };

        let recommended = Argon2Params::default();
        assert!(old_hash.needs_upgrade(&recommended));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();

        assert_eq!(&decoded[..data.len()], data);
    }

    #[test]
    fn test_memory_usage_calculation() {
        let params = Argon2Params::new(65536, 3, 4);
        assert_eq!(params.memory_usage(), 65536 * 1024);
    }

    #[test]
    fn test_security_profiles() {
        let high = Argon2Params::high_security();
        let interactive = Argon2Params::interactive();

        assert!(high.memory_cost > interactive.memory_cost);
        assert!(high.time_cost >= interactive.time_cost);
    }
}
