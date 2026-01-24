//! Key Derivation Functions
//!
//! Secure key derivation using Argon2, scrypt, and PBKDF2.

use std::fmt;
use std::time::{Duration, Instant};

/// Key derivation algorithm
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyDerivationAlgorithm {
    Argon2id,
    Argon2i,
    Argon2d,
    Scrypt,
    PBKDF2Sha256,
    PBKDF2Sha512,
    HKDF,
    Blake3,
}

impl KeyDerivationAlgorithm {
    pub fn name(&self) -> &str {
        match self {
            Self::Argon2id => "Argon2id",
            Self::Argon2i => "Argon2i",
            Self::Argon2d => "Argon2d",
            Self::Scrypt => "scrypt",
            Self::PBKDF2Sha256 => "PBKDF2-SHA256",
            Self::PBKDF2Sha512 => "PBKDF2-SHA512",
            Self::HKDF => "HKDF-SHA256",
            Self::Blake3 => "BLAKE3-KDF",
        }
    }

    pub fn is_memory_hard(&self) -> bool {
        matches!(
            self,
            Self::Argon2id | Self::Argon2i | Self::Argon2d | Self::Scrypt
        )
    }

    pub fn recommended_for_passwords(&self) -> bool {
        matches!(self, Self::Argon2id | Self::Scrypt)
    }
}

impl fmt::Display for KeyDerivationAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Argon2 parameters
#[derive(Debug, Clone)]
pub struct Argon2Params {
    pub memory_cost: u32,     // Memory in KiB
    pub time_cost: u32,       // Number of iterations
    pub parallelism: u32,     // Degree of parallelism
    pub output_length: usize, // Output key length in bytes
    pub salt_length: usize,   // Salt length in bytes
    pub variant: Argon2Variant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Argon2Variant {
    Argon2d,  // Data-dependent
    Argon2i,  // Data-independent
    Argon2id, // Hybrid (recommended)
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_cost: 65536, // 64 MiB
            time_cost: 3,       // 3 iterations
            parallelism: 4,     // 4 parallel lanes
            output_length: 32,  // 256-bit key
            salt_length: 16,    // 128-bit salt
            variant: Argon2Variant::Argon2id,
        }
    }
}

impl Argon2Params {
    pub fn interactive() -> Self {
        Self {
            memory_cost: 65536, // 64 MiB
            time_cost: 2,
            parallelism: 4,
            ..Default::default()
        }
    }

    pub fn moderate() -> Self {
        Self {
            memory_cost: 262144, // 256 MiB
            time_cost: 3,
            parallelism: 4,
            ..Default::default()
        }
    }

    pub fn sensitive() -> Self {
        Self {
            memory_cost: 1048576, // 1 GiB
            time_cost: 4,
            parallelism: 8,
            ..Default::default()
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.memory_cost < 8 {
            return Err("Memory cost must be at least 8 KiB".to_string());
        }
        if self.time_cost < 1 {
            return Err("Time cost must be at least 1".to_string());
        }
        if self.parallelism < 1 || self.parallelism > 255 {
            return Err("Parallelism must be between 1 and 255".to_string());
        }
        if self.output_length < 4 {
            return Err("Output length must be at least 4 bytes".to_string());
        }
        Ok(())
    }
}

/// Scrypt parameters
#[derive(Debug, Clone)]
pub struct ScryptParams {
    pub n: u32,               // CPU/memory cost (power of 2)
    pub r: u32,               // Block size
    pub p: u32,               // Parallelization
    pub output_length: usize, // Output key length
    pub salt_length: usize,   // Salt length
}

impl Default for ScryptParams {
    fn default() -> Self {
        Self {
            n: 1 << 15, // 2^15 = 32768
            r: 8,
            p: 1,
            output_length: 32,
            salt_length: 16,
        }
    }
}

impl ScryptParams {
    pub fn interactive() -> Self {
        Self {
            n: 1 << 14, // 2^14
            r: 8,
            p: 1,
            ..Default::default()
        }
    }

    pub fn sensitive() -> Self {
        Self {
            n: 1 << 20, // 2^20 (1 GiB memory)
            r: 8,
            p: 1,
            ..Default::default()
        }
    }

    pub fn memory_bytes(&self) -> usize {
        128 * self.n as usize * self.r as usize
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.n.is_power_of_two() {
            return Err("N must be a power of 2".to_string());
        }
        if self.r < 1 {
            return Err("r must be at least 1".to_string());
        }
        if self.p < 1 {
            return Err("p must be at least 1".to_string());
        }
        Ok(())
    }
}

/// PBKDF2 parameters
#[derive(Debug, Clone)]
pub struct PBKDF2Params {
    pub iterations: u32,
    pub output_length: usize,
    pub salt_length: usize,
    pub hash_algorithm: PBKDF2Hash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PBKDF2Hash {
    SHA256,
    SHA512,
}

impl Default for PBKDF2Params {
    fn default() -> Self {
        Self {
            iterations: 600000, // OWASP recommendation for SHA256
            output_length: 32,
            salt_length: 16,
            hash_algorithm: PBKDF2Hash::SHA256,
        }
    }
}

impl PBKDF2Params {
    pub fn for_sha512() -> Self {
        Self {
            iterations: 210000, // OWASP recommendation for SHA512
            hash_algorithm: PBKDF2Hash::SHA512,
            ..Default::default()
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.iterations < 10000 {
            return Err("Iterations should be at least 10000".to_string());
        }
        if self.salt_length < 16 {
            return Err("Salt should be at least 16 bytes".to_string());
        }
        Ok(())
    }
}

/// HKDF parameters
#[derive(Debug, Clone)]
pub struct HKDFParams {
    pub output_length: usize,
    pub info: Vec<u8>,
}

impl Default for HKDFParams {
    fn default() -> Self {
        Self {
            output_length: 32,
            info: Vec::new(),
        }
    }
}

/// Derived key result
#[derive(Clone)]
pub struct DerivedKey {
    key: Vec<u8>,
    salt: Vec<u8>,
    algorithm: KeyDerivationAlgorithm,
    derivation_time: Duration,
}

impl DerivedKey {
    pub fn new(
        key: Vec<u8>,
        salt: Vec<u8>,
        algorithm: KeyDerivationAlgorithm,
        derivation_time: Duration,
    ) -> Self {
        Self {
            key,
            salt,
            algorithm,
            derivation_time,
        }
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    pub fn algorithm(&self) -> &KeyDerivationAlgorithm {
        &self.algorithm
    }

    pub fn derivation_time(&self) -> Duration {
        self.derivation_time
    }

    pub fn to_hex(&self) -> String {
        self.key.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn constant_time_compare(&self, other: &[u8]) -> bool {
        if self.key.len() != other.len() {
            return false;
        }

        let mut result = 0u8;
        for (a, b) in self.key.iter().zip(other.iter()) {
            result |= a ^ b;
        }
        result == 0
    }
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        // Zeroize the key
        for byte in &mut self.key {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

impl fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedKey")
            .field("algorithm", &self.algorithm)
            .field("key_length", &self.key.len())
            .field("salt_length", &self.salt.len())
            .field("derivation_time", &self.derivation_time)
            .finish()
    }
}

/// Key derivation function
pub struct KeyDerivationFunction {
    algorithm: KeyDerivationAlgorithm,
}

impl KeyDerivationFunction {
    pub fn new(algorithm: KeyDerivationAlgorithm) -> Self {
        Self { algorithm }
    }

    pub fn argon2id() -> Self {
        Self::new(KeyDerivationAlgorithm::Argon2id)
    }

    pub fn scrypt() -> Self {
        Self::new(KeyDerivationAlgorithm::Scrypt)
    }

    pub fn pbkdf2_sha256() -> Self {
        Self::new(KeyDerivationAlgorithm::PBKDF2Sha256)
    }

    /// Derive key using Argon2
    pub fn derive_argon2(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &Argon2Params,
    ) -> Result<DerivedKey, String> {
        params.validate()?;

        let start = Instant::now();

        // Simulated Argon2 derivation
        // In real implementation, use the argon2 crate
        let key = self.simulate_kdf(password, salt, params.output_length);

        let duration = start.elapsed();

        Ok(DerivedKey::new(
            key,
            salt.to_vec(),
            match params.variant {
                Argon2Variant::Argon2d => KeyDerivationAlgorithm::Argon2d,
                Argon2Variant::Argon2i => KeyDerivationAlgorithm::Argon2i,
                Argon2Variant::Argon2id => KeyDerivationAlgorithm::Argon2id,
            },
            duration,
        ))
    }

    /// Derive key using scrypt
    pub fn derive_scrypt(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ScryptParams,
    ) -> Result<DerivedKey, String> {
        params.validate()?;

        let start = Instant::now();

        // Simulated scrypt derivation
        // In real implementation, use the scrypt crate
        let key = self.simulate_kdf(password, salt, params.output_length);

        let duration = start.elapsed();

        Ok(DerivedKey::new(
            key,
            salt.to_vec(),
            KeyDerivationAlgorithm::Scrypt,
            duration,
        ))
    }

    /// Derive key using PBKDF2
    pub fn derive_pbkdf2(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &PBKDF2Params,
    ) -> Result<DerivedKey, String> {
        params.validate()?;

        let start = Instant::now();

        // Simulated PBKDF2 derivation
        // In real implementation, use the pbkdf2 crate
        let key = self.simulate_kdf(password, salt, params.output_length);

        let duration = start.elapsed();

        let algorithm = match params.hash_algorithm {
            PBKDF2Hash::SHA256 => KeyDerivationAlgorithm::PBKDF2Sha256,
            PBKDF2Hash::SHA512 => KeyDerivationAlgorithm::PBKDF2Sha512,
        };

        Ok(DerivedKey::new(key, salt.to_vec(), algorithm, duration))
    }

    /// Derive key using HKDF (for already high-entropy input)
    pub fn derive_hkdf(
        &self,
        input_key: &[u8],
        salt: &[u8],
        params: &HKDFParams,
    ) -> Result<DerivedKey, String> {
        let start = Instant::now();

        // Simulated HKDF derivation
        // In real implementation, use the hkdf crate
        let mut key = self.simulate_kdf(input_key, salt, params.output_length);

        // Mix in info
        for (i, byte) in params.info.iter().enumerate() {
            if i < key.len() {
                key[i] ^= byte;
            }
        }

        let duration = start.elapsed();

        Ok(DerivedKey::new(
            key,
            salt.to_vec(),
            KeyDerivationAlgorithm::HKDF,
            duration,
        ))
    }

    /// Generate a random salt
    pub fn generate_salt(length: usize) -> Vec<u8> {
        // In real implementation, use a CSPRNG
        (0..length)
            .map(|i| (i as u8).wrapping_mul(17).wrapping_add(42))
            .collect()
    }

    /// Simulate KDF for demonstration
    fn simulate_kdf(&self, password: &[u8], salt: &[u8], length: usize) -> Vec<u8> {
        // Simple simulation - NOT cryptographically secure
        let mut output = vec![0u8; length];

        for i in 0..length {
            let p = password
                .get(i % password.len().max(1))
                .copied()
                .unwrap_or(0);
            let s = salt.get(i % salt.len().max(1)).copied().unwrap_or(0);
            output[i] = p.wrapping_add(s).wrapping_mul(17).wrapping_add(i as u8);
        }

        output
    }
}

/// Password strength estimator
pub struct PasswordStrength;

impl PasswordStrength {
    pub fn estimate_entropy(password: &str) -> f64 {
        let len = password.len() as f64;
        let mut char_space = 0.0;

        if password.chars().any(|c| c.is_ascii_lowercase()) {
            char_space += 26.0;
        }
        if password.chars().any(|c| c.is_ascii_uppercase()) {
            char_space += 26.0;
        }
        if password.chars().any(|c| c.is_ascii_digit()) {
            char_space += 10.0;
        }
        if password.chars().any(|c| c.is_ascii_punctuation()) {
            char_space += 32.0;
        }

        if char_space == 0.0 {
            return 0.0;
        }

        len * char_space.log2()
    }

    pub fn strength_level(password: &str) -> PasswordStrengthLevel {
        let entropy = Self::estimate_entropy(password);

        if entropy < 28.0 {
            PasswordStrengthLevel::VeryWeak
        } else if entropy < 36.0 {
            PasswordStrengthLevel::Weak
        } else if entropy < 60.0 {
            PasswordStrengthLevel::Moderate
        } else if entropy < 128.0 {
            PasswordStrengthLevel::Strong
        } else {
            PasswordStrengthLevel::VeryStrong
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordStrengthLevel {
    VeryWeak,
    Weak,
    Moderate,
    Strong,
    VeryStrong,
}

impl fmt::Display for PasswordStrengthLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VeryWeak => write!(f, "Very Weak"),
            Self::Weak => write!(f, "Weak"),
            Self::Moderate => write!(f, "Moderate"),
            Self::Strong => write!(f, "Strong"),
            Self::VeryStrong => write!(f, "Very Strong"),
        }
    }
}

/// Benchmark different KDF configurations
pub struct KDFBenchmark;

impl KDFBenchmark {
    pub fn benchmark_argon2(params: &Argon2Params) -> Duration {
        let kdf = KeyDerivationFunction::argon2id();
        let password = b"benchmark_password_123";
        let salt = KeyDerivationFunction::generate_salt(params.salt_length);

        let start = Instant::now();
        let _ = kdf.derive_argon2(password, &salt, params);
        start.elapsed()
    }

    pub fn benchmark_scrypt(params: &ScryptParams) -> Duration {
        let kdf = KeyDerivationFunction::scrypt();
        let password = b"benchmark_password_123";
        let salt = KeyDerivationFunction::generate_salt(params.salt_length);

        let start = Instant::now();
        let _ = kdf.derive_scrypt(password, &salt, params);
        start.elapsed()
    }

    pub fn benchmark_pbkdf2(params: &PBKDF2Params) -> Duration {
        let kdf = KeyDerivationFunction::pbkdf2_sha256();
        let password = b"benchmark_password_123";
        let salt = KeyDerivationFunction::generate_salt(params.salt_length);

        let start = Instant::now();
        let _ = kdf.derive_pbkdf2(password, &salt, params);
        start.elapsed()
    }

    pub fn recommend_params(target_time: Duration) -> Argon2Params {
        // Start with minimal params and increase
        let mut params = Argon2Params {
            memory_cost: 16384,
            time_cost: 1,
            parallelism: 4,
            ..Default::default()
        };

        // Increase time cost until we reach target
        while Self::benchmark_argon2(&params) < target_time && params.time_cost < 10 {
            params.time_cost += 1;
        }

        // Increase memory cost
        while Self::benchmark_argon2(&params) < target_time && params.memory_cost < 1048576 {
            params.memory_cost *= 2;
        }

        params
    }
}

fn main() {
    println!("=== Key Derivation Functions Demo ===\n");

    // Password to derive key from
    let password = b"my_secure_password_123!";

    // Generate salt
    let salt = KeyDerivationFunction::generate_salt(16);
    println!("Generated salt: {:02x?}\n", &salt[..8]);

    // Argon2id derivation
    println!("--- Argon2id Key Derivation ---");
    let kdf = KeyDerivationFunction::argon2id();
    let params = Argon2Params::interactive();

    match kdf.derive_argon2(password, &salt, &params) {
        Ok(key) => {
            println!("Derived key: {}", key.to_hex());
            println!("Key length: {} bytes", key.key().len());
            println!("Derivation time: {:?}", key.derivation_time());
        }
        Err(e) => println!("Error: {}", e),
    }

    // Scrypt derivation
    println!("\n--- Scrypt Key Derivation ---");
    let kdf = KeyDerivationFunction::scrypt();
    let params = ScryptParams::default();
    println!("Memory usage: {} bytes", params.memory_bytes());

    match kdf.derive_scrypt(password, &salt, &params) {
        Ok(key) => {
            println!("Derived key: {}", key.to_hex());
            println!("Derivation time: {:?}", key.derivation_time());
        }
        Err(e) => println!("Error: {}", e),
    }

    // PBKDF2 derivation
    println!("\n--- PBKDF2-SHA256 Key Derivation ---");
    let kdf = KeyDerivationFunction::pbkdf2_sha256();
    let params = PBKDF2Params::default();
    println!("Iterations: {}", params.iterations);

    match kdf.derive_pbkdf2(password, &salt, &params) {
        Ok(key) => {
            println!("Derived key: {}", key.to_hex());
            println!("Derivation time: {:?}", key.derivation_time());
        }
        Err(e) => println!("Error: {}", e),
    }

    // HKDF for key expansion
    println!("\n--- HKDF Key Derivation ---");
    let kdf = KeyDerivationFunction::new(KeyDerivationAlgorithm::HKDF);
    let master_key = b"high_entropy_master_key_12345678";
    let info = b"application_specific_context";
    let params = HKDFParams {
        output_length: 64,
        info: info.to_vec(),
    };

    match kdf.derive_hkdf(master_key, &salt, &params) {
        Ok(key) => {
            println!("Derived key (64 bytes): {}...", &key.to_hex()[..32]);
            println!("Derivation time: {:?}", key.derivation_time());
        }
        Err(e) => println!("Error: {}", e),
    }

    // Password strength estimation
    println!("\n--- Password Strength Estimation ---");
    let passwords = [
        "password",
        "Password1",
        "P@ssw0rd!",
        "correct horse battery staple",
        "Tr0ub4dor&3",
    ];

    for pwd in passwords {
        let entropy = PasswordStrength::estimate_entropy(pwd);
        let level = PasswordStrength::strength_level(pwd);
        println!(
            "'{}': {:.1} bits entropy - {}",
            if pwd.len() > 20 {
                format!("{}...", &pwd[..20])
            } else {
                pwd.to_string()
            },
            entropy,
            level
        );
    }

    // Benchmark
    println!("\n--- KDF Benchmark ---");
    let argon2_time = KDFBenchmark::benchmark_argon2(&Argon2Params::interactive());
    let scrypt_time = KDFBenchmark::benchmark_scrypt(&ScryptParams::default());
    let pbkdf2_time = KDFBenchmark::benchmark_pbkdf2(&PBKDF2Params::default());

    println!("Argon2id (interactive): {:?}", argon2_time);
    println!("Scrypt (default): {:?}", scrypt_time);
    println!("PBKDF2-SHA256 (600k iter): {:?}", pbkdf2_time);

    // Recommend params for target time
    println!("\n--- Recommended Params for 250ms target ---");
    let recommended = KDFBenchmark::recommend_params(Duration::from_millis(250));
    println!("Memory: {} KiB", recommended.memory_cost);
    println!("Time: {} iterations", recommended.time_cost);
    println!("Parallelism: {}", recommended.parallelism);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_params_validation() {
        let valid = Argon2Params::default();
        assert!(valid.validate().is_ok());

        let invalid = Argon2Params {
            memory_cost: 4,
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_scrypt_params_validation() {
        let valid = ScryptParams::default();
        assert!(valid.validate().is_ok());

        let invalid = ScryptParams {
            n: 100, // Not power of 2
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_pbkdf2_params_validation() {
        let valid = PBKDF2Params::default();
        assert!(valid.validate().is_ok());

        let invalid = PBKDF2Params {
            iterations: 100,
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_key_derivation_argon2() {
        let kdf = KeyDerivationFunction::argon2id();
        let password = b"test_password";
        let salt = KeyDerivationFunction::generate_salt(16);

        let result = kdf.derive_argon2(password, &salt, &Argon2Params::default());
        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.key().len(), 32);
        assert_eq!(key.salt().len(), 16);
    }

    #[test]
    fn test_key_derivation_scrypt() {
        let kdf = KeyDerivationFunction::scrypt();
        let password = b"test_password";
        let salt = KeyDerivationFunction::generate_salt(16);

        let result = kdf.derive_scrypt(password, &salt, &ScryptParams::default());
        assert!(result.is_ok());
    }

    #[test]
    fn test_key_derivation_pbkdf2() {
        let kdf = KeyDerivationFunction::pbkdf2_sha256();
        let password = b"test_password";
        let salt = KeyDerivationFunction::generate_salt(16);

        let result = kdf.derive_pbkdf2(password, &salt, &PBKDF2Params::default());
        assert!(result.is_ok());
    }

    #[test]
    fn test_hkdf_derivation() {
        let kdf = KeyDerivationFunction::new(KeyDerivationAlgorithm::HKDF);
        let input_key = b"master_key_with_high_entropy";
        let salt = KeyDerivationFunction::generate_salt(16);
        let params = HKDFParams {
            output_length: 64,
            info: b"context".to_vec(),
        };

        let result = kdf.derive_hkdf(input_key, &salt, &params);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().key().len(), 64);
    }

    #[test]
    fn test_derived_key_to_hex() {
        let key = DerivedKey::new(
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            vec![0x00],
            KeyDerivationAlgorithm::Argon2id,
            Duration::from_millis(100),
        );

        assert_eq!(key.to_hex(), "deadbeef");
    }

    #[test]
    fn test_constant_time_compare() {
        let key = DerivedKey::new(
            vec![1, 2, 3, 4],
            vec![],
            KeyDerivationAlgorithm::Argon2id,
            Duration::ZERO,
        );

        assert!(key.constant_time_compare(&[1, 2, 3, 4]));
        assert!(!key.constant_time_compare(&[1, 2, 3, 5]));
        assert!(!key.constant_time_compare(&[1, 2, 3]));
    }

    #[test]
    fn test_password_strength_estimation() {
        assert!(PasswordStrength::estimate_entropy("a") < 10.0);
        assert!(PasswordStrength::estimate_entropy("password") < 40.0);
        assert!(PasswordStrength::estimate_entropy("P@ssw0rd!") > 40.0);
    }

    #[test]
    fn test_password_strength_levels() {
        assert_eq!(
            PasswordStrength::strength_level("abc"),
            PasswordStrengthLevel::VeryWeak
        );
        assert_eq!(
            PasswordStrength::strength_level("P@ssw0rd!123"),
            PasswordStrengthLevel::Moderate
        );
    }

    #[test]
    fn test_algorithm_properties() {
        assert!(KeyDerivationAlgorithm::Argon2id.is_memory_hard());
        assert!(KeyDerivationAlgorithm::Scrypt.is_memory_hard());
        assert!(!KeyDerivationAlgorithm::PBKDF2Sha256.is_memory_hard());

        assert!(KeyDerivationAlgorithm::Argon2id.recommended_for_passwords());
        assert!(!KeyDerivationAlgorithm::HKDF.recommended_for_passwords());
    }

    #[test]
    fn test_scrypt_memory_calculation() {
        let params = ScryptParams {
            n: 1 << 14,
            r: 8,
            p: 1,
            ..Default::default()
        };

        assert_eq!(params.memory_bytes(), 128 * 16384 * 8);
    }

    #[test]
    fn test_salt_generation() {
        let salt1 = KeyDerivationFunction::generate_salt(16);
        let salt2 = KeyDerivationFunction::generate_salt(16);

        assert_eq!(salt1.len(), 16);
        assert_eq!(salt2.len(), 16);
    }

    #[test]
    fn test_argon2_presets() {
        let interactive = Argon2Params::interactive();
        let moderate = Argon2Params::moderate();
        let sensitive = Argon2Params::sensitive();

        assert!(interactive.memory_cost < moderate.memory_cost);
        assert!(moderate.memory_cost < sensitive.memory_cost);
    }
}
