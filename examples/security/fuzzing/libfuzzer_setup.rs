//! LibFuzzer Integration Example
//!
//! Demonstrates setting up libfuzzer for Rust security testing.
//! This example shows how to create fuzz targets for security-critical code.

use std::collections::HashMap;

/// Represents a fuzz target configuration
#[derive(Debug, Clone)]
pub struct FuzzTarget {
    pub name: String,
    pub corpus_dir: String,
    pub max_len: usize,
    pub timeout_secs: u64,
    pub runs: Option<u64>,
}

impl FuzzTarget {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            corpus_dir: format!("fuzz/corpus/{}", name),
            max_len: 4096,
            timeout_secs: 30,
            runs: None,
        }
    }

    pub fn with_max_len(mut self, len: usize) -> Self {
        self.max_len = len;
        self
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    pub fn with_runs(mut self, runs: u64) -> Self {
        self.runs = Some(runs);
        self
    }
}

/// Fuzzing harness for parser security testing
pub mod parser_fuzz {
    use super::*;

    /// Simple JSON-like parser for fuzzing demonstration
    #[derive(Debug, PartialEq)]
    pub enum Value {
        Null,
        Bool(bool),
        Number(i64),
        String(String),
        Array(Vec<Value>),
        Object(HashMap<String, Value>),
    }

    /// Parse input with bounds checking - fuzz target
    pub fn parse_input(data: &[u8]) -> Result<Value, ParseError> {
        if data.is_empty() {
            return Ok(Value::Null);
        }

        // Limit input size to prevent DoS
        if data.len() > 1024 * 1024 {
            return Err(ParseError::InputTooLarge);
        }

        let input = std::str::from_utf8(data).map_err(|_| ParseError::InvalidUtf8)?;
        let trimmed = input.trim();

        if trimmed.is_empty() {
            return Ok(Value::Null);
        }

        match trimmed.chars().next() {
            Some('"') => parse_string(trimmed),
            Some('[') => parse_array(trimmed),
            Some('{') => parse_object(trimmed),
            Some('t') | Some('f') => parse_bool(trimmed),
            Some('n') => parse_null(trimmed),
            Some(c) if c.is_ascii_digit() || c == '-' => parse_number(trimmed),
            _ => Err(ParseError::UnexpectedCharacter),
        }
    }

    fn parse_string(input: &str) -> Result<Value, ParseError> {
        if !input.starts_with('"') || !input.ends_with('"') {
            return Err(ParseError::InvalidString);
        }
        if input.len() < 2 {
            return Err(ParseError::InvalidString);
        }
        Ok(Value::String(input[1..input.len() - 1].to_string()))
    }

    fn parse_array(input: &str) -> Result<Value, ParseError> {
        if !input.starts_with('[') || !input.ends_with(']') {
            return Err(ParseError::InvalidArray);
        }
        // Simplified: just return empty array for demo
        Ok(Value::Array(Vec::new()))
    }

    fn parse_object(input: &str) -> Result<Value, ParseError> {
        if !input.starts_with('{') || !input.ends_with('}') {
            return Err(ParseError::InvalidObject);
        }
        Ok(Value::Object(HashMap::new()))
    }

    fn parse_bool(input: &str) -> Result<Value, ParseError> {
        match input {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ => Err(ParseError::InvalidBool),
        }
    }

    fn parse_null(input: &str) -> Result<Value, ParseError> {
        if input == "null" {
            Ok(Value::Null)
        } else {
            Err(ParseError::InvalidNull)
        }
    }

    fn parse_number(input: &str) -> Result<Value, ParseError> {
        input
            .parse::<i64>()
            .map(Value::Number)
            .map_err(|_| ParseError::InvalidNumber)
    }

    #[derive(Debug, PartialEq)]
    pub enum ParseError {
        InvalidUtf8,
        InputTooLarge,
        UnexpectedCharacter,
        InvalidString,
        InvalidArray,
        InvalidObject,
        InvalidBool,
        InvalidNull,
        InvalidNumber,
    }
}

/// Fuzzing harness for cryptographic operations
pub mod crypto_fuzz {
    /// Constant-time comparison - critical for timing attack prevention
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
    }

    /// Validate key material - fuzz target
    pub fn validate_key(key: &[u8]) -> Result<(), KeyError> {
        // Check key length
        match key.len() {
            16 | 24 | 32 => {}
            _ => return Err(KeyError::InvalidLength(key.len())),
        }

        // Check for weak keys (all zeros, all ones)
        if key.iter().all(|&b| b == 0) {
            return Err(KeyError::WeakKey);
        }
        if key.iter().all(|&b| b == 0xff) {
            return Err(KeyError::WeakKey);
        }

        // Check entropy (simplified)
        let unique_bytes: std::collections::HashSet<_> = key.iter().collect();
        if unique_bytes.len() < key.len() / 4 {
            return Err(KeyError::LowEntropy);
        }

        Ok(())
    }

    #[derive(Debug, PartialEq)]
    pub enum KeyError {
        InvalidLength(usize),
        WeakKey,
        LowEntropy,
    }
}

/// Fuzzing configuration generator
pub struct FuzzConfig {
    targets: Vec<FuzzTarget>,
    sanitizers: Vec<String>,
    corpus_merge: bool,
}

impl FuzzConfig {
    pub fn new() -> Self {
        Self {
            targets: Vec::new(),
            sanitizers: vec!["address".to_string(), "memory".to_string()],
            corpus_merge: true,
        }
    }

    pub fn add_target(&mut self, target: FuzzTarget) -> &mut Self {
        self.targets.push(target);
        self
    }

    pub fn with_sanitizer(&mut self, sanitizer: &str) -> &mut Self {
        self.sanitizers.push(sanitizer.to_string());
        self
    }

    pub fn generate_cargo_fuzz_toml(&self) -> String {
        let mut output = String::from("[workspace]\nmembers = [\"fuzz\"]\n\n");

        for target in &self.targets {
            output.push_str(&format!(
                "[[bin]]\nname = \"{}\"\npath = \"fuzz/fuzz_targets/{}.rs\"\n\n",
                target.name, target.name
            ));
        }

        output
    }

    pub fn generate_fuzz_target_template(&self, target: &FuzzTarget) -> String {
        format!(
            r#"#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {{
    // Call the function under test
    let _ = my_crate::{}(data);
}});
"#,
            target.name
        )
    }
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self::new()
    }
}

fn main() {
    println!("LibFuzzer Setup Example");
    println!("========================\n");

    // Create fuzz configuration
    let mut config = FuzzConfig::new();

    // Add fuzz targets
    config.add_target(
        FuzzTarget::new("parse_input")
            .with_max_len(4096)
            .with_timeout(30),
    );

    config.add_target(
        FuzzTarget::new("validate_key")
            .with_max_len(64)
            .with_timeout(10),
    );

    config.add_target(
        FuzzTarget::new("constant_time_compare")
            .with_max_len(1024)
            .with_timeout(5)
            .with_runs(100_000),
    );

    println!("Generated Cargo.toml for fuzzing:\n");
    println!("{}", config.generate_cargo_fuzz_toml());

    // Test parser fuzzing
    println!("\nParser Fuzz Tests:");
    let test_inputs: Vec<&[u8]> = vec![
        b"",
        b"null",
        b"true",
        b"false",
        b"123",
        b"-456",
        b"\"hello\"",
        b"[]",
        b"{}",
        b"\xff\xfe", // Invalid UTF-8
    ];

    for input in test_inputs {
        match parser_fuzz::parse_input(input) {
            Ok(value) => println!("  {:?} -> {:?}", input, value),
            Err(e) => println!("  {:?} -> Error: {:?}", input, e),
        }
    }

    // Test crypto fuzzing
    println!("\nCrypto Fuzz Tests:");
    let test_keys: Vec<&[u8]> = vec![
        &[0u8; 16],                          // Weak key (all zeros)
        &[0xffu8; 32],                       // Weak key (all ones)
        &[1, 2, 3, 4, 5, 6, 7, 8],           // Invalid length
        b"0123456789abcdef",                 // Valid 16-byte key
        b"0123456789abcdef0123456789abcdef", // Valid 32-byte key
    ];

    for key in test_keys {
        match crypto_fuzz::validate_key(key) {
            Ok(()) => println!("  {} bytes: Valid", key.len()),
            Err(e) => println!("  {} bytes: {:?}", key.len(), e),
        }
    }

    // Test constant-time comparison
    println!("\nConstant-Time Comparison Tests:");
    let a = b"secret_key_12345";
    let b = b"secret_key_12345";
    let c = b"different_key___";

    println!("  a == b: {}", crypto_fuzz::constant_time_compare(a, b));
    println!("  a == c: {}", crypto_fuzz::constant_time_compare(a, c));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzz_target_builder() {
        let target = FuzzTarget::new("test_target")
            .with_max_len(8192)
            .with_timeout(60)
            .with_runs(50000);

        assert_eq!(target.name, "test_target");
        assert_eq!(target.max_len, 8192);
        assert_eq!(target.timeout_secs, 60);
        assert_eq!(target.runs, Some(50000));
    }

    #[test]
    fn test_parser_null() {
        assert_eq!(
            parser_fuzz::parse_input(b"null").unwrap(),
            parser_fuzz::Value::Null
        );
        assert_eq!(
            parser_fuzz::parse_input(b"").unwrap(),
            parser_fuzz::Value::Null
        );
    }

    #[test]
    fn test_parser_bool() {
        assert_eq!(
            parser_fuzz::parse_input(b"true").unwrap(),
            parser_fuzz::Value::Bool(true)
        );
        assert_eq!(
            parser_fuzz::parse_input(b"false").unwrap(),
            parser_fuzz::Value::Bool(false)
        );
    }

    #[test]
    fn test_parser_number() {
        assert_eq!(
            parser_fuzz::parse_input(b"123").unwrap(),
            parser_fuzz::Value::Number(123)
        );
        assert_eq!(
            parser_fuzz::parse_input(b"-456").unwrap(),
            parser_fuzz::Value::Number(-456)
        );
    }

    #[test]
    fn test_parser_string() {
        assert_eq!(
            parser_fuzz::parse_input(b"\"hello\"").unwrap(),
            parser_fuzz::Value::String("hello".to_string())
        );
    }

    #[test]
    fn test_parser_invalid_utf8() {
        assert_eq!(
            parser_fuzz::parse_input(&[0xff, 0xfe]),
            Err(parser_fuzz::ParseError::InvalidUtf8)
        );
    }

    #[test]
    fn test_key_validation() {
        // Valid keys
        assert!(crypto_fuzz::validate_key(b"0123456789abcdef").is_ok());
        assert!(crypto_fuzz::validate_key(b"0123456789abcdef01234567").is_ok());

        // Invalid length
        assert_eq!(
            crypto_fuzz::validate_key(b"short"),
            Err(crypto_fuzz::KeyError::InvalidLength(5))
        );

        // Weak keys
        assert_eq!(
            crypto_fuzz::validate_key(&[0u8; 16]),
            Err(crypto_fuzz::KeyError::WeakKey)
        );
    }

    #[test]
    fn test_constant_time_compare() {
        let a = b"test_secret";
        let b = b"test_secret";
        let c = b"other_value";
        let d = b"short";

        assert!(crypto_fuzz::constant_time_compare(a, b));
        assert!(!crypto_fuzz::constant_time_compare(a, c));
        assert!(!crypto_fuzz::constant_time_compare(a, d));
    }

    #[test]
    fn test_fuzz_config_generation() {
        let mut config = FuzzConfig::new();
        config.add_target(FuzzTarget::new("test_target"));

        let toml = config.generate_cargo_fuzz_toml();
        assert!(toml.contains("[workspace]"));
        assert!(toml.contains("test_target"));
    }
}
