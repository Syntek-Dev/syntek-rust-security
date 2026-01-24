//! Honggfuzz Integration Example
//!
//! Demonstrates setting up honggfuzz for Rust security testing.
//! Honggfuzz provides hardware-based feedback fuzzing with coverage guidance.

use std::collections::BTreeMap;

/// Honggfuzz configuration
#[derive(Debug, Clone)]
pub struct HonggfuzzConfig {
    pub workspace: String,
    pub timeout_secs: u64,
    pub iterations: Option<u64>,
    pub threads: usize,
    pub mutations_per_run: usize,
    pub dict_path: Option<String>,
    pub sanitizers: HonggfuzzSanitizers,
}

#[derive(Debug, Clone, Default)]
pub struct HonggfuzzSanitizers {
    pub address: bool,
    pub thread: bool,
    pub memory: bool,
    pub undefined: bool,
}

impl Default for HonggfuzzConfig {
    fn default() -> Self {
        Self {
            workspace: "hfuzz_workspace".to_string(),
            timeout_secs: 10,
            iterations: None,
            threads: num_cpus(),
            mutations_per_run: 6,
            dict_path: None,
            sanitizers: HonggfuzzSanitizers {
                address: true,
                ..Default::default()
            },
        }
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
}

impl HonggfuzzConfig {
    pub fn new(workspace: &str) -> Self {
        Self {
            workspace: workspace.to_string(),
            ..Default::default()
        }
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = threads;
        self
    }

    pub fn with_dictionary(mut self, path: &str) -> Self {
        self.dict_path = Some(path.to_string());
        self
    }

    pub fn enable_all_sanitizers(mut self) -> Self {
        self.sanitizers = HonggfuzzSanitizers {
            address: true,
            thread: true,
            memory: true,
            undefined: true,
        };
        self
    }

    pub fn generate_env_vars(&self) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();

        env.insert("HFUZZ_WORKSPACE".to_string(), self.workspace.clone());
        env.insert("HFUZZ_RUN_ARGS".to_string(), self.generate_run_args());

        if self.sanitizers.address {
            env.insert("RUSTFLAGS".to_string(), "-Z sanitizer=address".to_string());
        }

        env
    }

    fn generate_run_args(&self) -> String {
        let mut args = Vec::new();

        args.push(format!("--timeout {}", self.timeout_secs));
        args.push(format!("--threads {}", self.threads));
        args.push(format!("--mutations_per_run {}", self.mutations_per_run));

        if let Some(ref dict) = self.dict_path {
            args.push(format!("--dict {}", dict));
        }

        if let Some(iterations) = self.iterations {
            args.push(format!("--iterations {}", iterations));
        }

        args.join(" ")
    }
}

/// Certificate parser for honggfuzz testing
pub mod cert_parser {
    use std::convert::TryInto;

    /// Simplified X.509 certificate structure
    #[derive(Debug, Clone)]
    pub struct Certificate {
        pub version: u8,
        pub serial: Vec<u8>,
        pub issuer: String,
        pub subject: String,
        pub not_before: u64,
        pub not_after: u64,
        pub public_key: Vec<u8>,
    }

    /// Parse DER-encoded certificate (simplified)
    pub fn parse_der(data: &[u8]) -> Result<Certificate, CertError> {
        if data.len() < 10 {
            return Err(CertError::TooShort);
        }

        // Check for SEQUENCE tag (0x30)
        if data[0] != 0x30 {
            return Err(CertError::InvalidTag);
        }

        // Parse length
        let (len, offset) = parse_length(&data[1..])?;

        if data.len() < offset + 1 + len {
            return Err(CertError::IncompleteData);
        }

        // Simplified parsing - in reality this would be much more complex
        let content = &data[offset + 1..];

        // Extract version (usually at the start)
        let version = if content.len() > 4 && content[0] == 0xA0 {
            content[4]
        } else {
            1 // Default to v1
        };

        if version > 3 {
            return Err(CertError::UnsupportedVersion(version));
        }

        Ok(Certificate {
            version,
            serial: extract_serial(content),
            issuer: "CN=Example Issuer".to_string(),
            subject: "CN=Example Subject".to_string(),
            not_before: 0,
            not_after: u64::MAX,
            public_key: Vec::new(),
        })
    }

    fn parse_length(data: &[u8]) -> Result<(usize, usize), CertError> {
        if data.is_empty() {
            return Err(CertError::TooShort);
        }

        let first = data[0];

        if first < 0x80 {
            // Short form
            Ok((first as usize, 1))
        } else if first == 0x80 {
            // Indefinite length - not allowed in DER
            Err(CertError::IndefiniteLength)
        } else {
            // Long form
            let num_bytes = (first & 0x7F) as usize;

            if num_bytes > 4 {
                return Err(CertError::LengthTooLarge);
            }

            if data.len() < 1 + num_bytes {
                return Err(CertError::TooShort);
            }

            let mut len = 0usize;
            for i in 0..num_bytes {
                len = (len << 8) | (data[1 + i] as usize);
            }

            // Security: prevent excessive allocation
            if len > 10 * 1024 * 1024 {
                return Err(CertError::LengthTooLarge);
            }

            Ok((len, 1 + num_bytes))
        }
    }

    fn extract_serial(data: &[u8]) -> Vec<u8> {
        // Look for INTEGER tag (0x02)
        for (i, &byte) in data.iter().enumerate() {
            if byte == 0x02 && i + 2 < data.len() {
                let len = data[i + 1] as usize;
                if i + 2 + len <= data.len() {
                    return data[i + 2..i + 2 + len].to_vec();
                }
            }
        }
        Vec::new()
    }

    #[derive(Debug, PartialEq)]
    pub enum CertError {
        TooShort,
        InvalidTag,
        IncompleteData,
        IndefiniteLength,
        LengthTooLarge,
        UnsupportedVersion(u8),
    }
}

/// JWT parser for honggfuzz testing
pub mod jwt_parser {
    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    pub struct Jwt {
        pub header: JwtHeader,
        pub claims: HashMap<String, String>,
        pub signature: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    pub struct JwtHeader {
        pub alg: String,
        pub typ: String,
    }

    /// Parse JWT token (simplified)
    pub fn parse_jwt(token: &str) -> Result<Jwt, JwtError> {
        let parts: Vec<&str> = token.split('.').collect();

        if parts.len() != 3 {
            return Err(JwtError::InvalidFormat);
        }

        // Validate base64 characters
        for part in &parts {
            if !is_valid_base64url(part) {
                return Err(JwtError::InvalidBase64);
            }
        }

        let header = parse_header(parts[0])?;
        let claims = parse_claims(parts[1])?;
        let signature = decode_base64url(parts[2])?;

        // Security: reject "none" algorithm
        if header.alg.eq_ignore_ascii_case("none") {
            return Err(JwtError::InsecureAlgorithm);
        }

        Ok(Jwt {
            header,
            claims,
            signature,
        })
    }

    fn is_valid_base64url(s: &str) -> bool {
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
    }

    fn decode_base64url(input: &str) -> Result<Vec<u8>, JwtError> {
        // Simplified base64url decode
        let mut result = Vec::new();
        let chars: Vec<char> = input.chars().filter(|&c| c != '=').collect();

        for chunk in chars.chunks(4) {
            let mut value = 0u32;
            for (i, &c) in chunk.iter().enumerate() {
                let v = match c {
                    'A'..='Z' => c as u32 - 'A' as u32,
                    'a'..='z' => c as u32 - 'a' as u32 + 26,
                    '0'..='9' => c as u32 - '0' as u32 + 52,
                    '-' => 62,
                    '_' => 63,
                    _ => return Err(JwtError::InvalidBase64),
                };
                value |= v << (18 - 6 * i);
            }

            if chunk.len() >= 2 {
                result.push((value >> 16) as u8);
            }
            if chunk.len() >= 3 {
                result.push((value >> 8) as u8);
            }
            if chunk.len() >= 4 {
                result.push(value as u8);
            }
        }

        Ok(result)
    }

    fn parse_header(_base64: &str) -> Result<JwtHeader, JwtError> {
        // Simplified - would decode and parse JSON
        Ok(JwtHeader {
            alg: "HS256".to_string(),
            typ: "JWT".to_string(),
        })
    }

    fn parse_claims(_base64: &str) -> Result<HashMap<String, String>, JwtError> {
        // Simplified - would decode and parse JSON
        Ok(HashMap::new())
    }

    #[derive(Debug, PartialEq)]
    pub enum JwtError {
        InvalidFormat,
        InvalidBase64,
        InsecureAlgorithm,
        ExpiredToken,
        InvalidSignature,
    }
}

/// Generate honggfuzz fuzz target code
pub fn generate_fuzz_target(target_name: &str, function: &str) -> String {
    format!(
        r#"#[macro_use] extern crate honggfuzz;

fn main() {{
    loop {{
        fuzz!(|data: &[u8]| {{
            let _ = {}::{}(data);
        }});
    }}
}}
"#,
        target_name, function
    )
}

fn main() {
    println!("Honggfuzz Integration Example");
    println!("===============================\n");

    // Configure honggfuzz
    let config = HonggfuzzConfig::new("hfuzz_workspace")
        .with_timeout(5)
        .with_threads(4)
        .with_dictionary("dict/certs.dict")
        .enable_all_sanitizers();

    println!("Honggfuzz Configuration:");
    println!("  Workspace: {}", config.workspace);
    println!("  Timeout: {}s", config.timeout_secs);
    println!("  Threads: {}", config.threads);

    println!("\nEnvironment Variables:");
    for (key, value) in config.generate_env_vars() {
        println!("  {}={}", key, value);
    }

    // Test certificate parser
    println!("\nCertificate Parser Tests:");

    // Minimal valid DER structure
    let valid_der = [
        0x30, 0x06, // SEQUENCE, length 6
        0xA0, 0x03, 0x02, 0x01, 0x02, // Version context tag with INTEGER 2 (v3)
        0x02, // More content would follow
    ];

    match cert_parser::parse_der(&valid_der) {
        Ok(cert) => println!("  Valid DER: version={}", cert.version),
        Err(e) => println!("  Parse error: {:?}", e),
    }

    // Invalid tag
    let invalid_tag = [0x31, 0x00]; // SET instead of SEQUENCE
    match cert_parser::parse_der(&invalid_tag) {
        Ok(_) => println!("  Unexpected success"),
        Err(e) => println!("  Invalid tag: {:?}", e),
    }

    // Test JWT parser
    println!("\nJWT Parser Tests:");

    let valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
    match jwt_parser::parse_jwt(valid_jwt) {
        Ok(jwt) => println!("  Valid JWT: alg={}", jwt.header.alg),
        Err(e) => println!("  Parse error: {:?}", e),
    }

    let invalid_jwt = "not.a.valid.jwt.token";
    match jwt_parser::parse_jwt(invalid_jwt) {
        Ok(_) => println!("  Unexpected success"),
        Err(e) => println!("  Invalid JWT: {:?}", e),
    }

    // Generate fuzz target
    println!("\nGenerated Fuzz Target:");
    println!("{}", generate_fuzz_target("cert_parser", "parse_der"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_honggfuzz_config() {
        let config = HonggfuzzConfig::new("test_workspace")
            .with_timeout(30)
            .with_threads(8);

        assert_eq!(config.workspace, "test_workspace");
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.threads, 8);
    }

    #[test]
    fn test_config_env_vars() {
        let config = HonggfuzzConfig::default();
        let env = config.generate_env_vars();

        assert!(env.contains_key("HFUZZ_WORKSPACE"));
        assert!(env.contains_key("HFUZZ_RUN_ARGS"));
    }

    #[test]
    fn test_cert_parser_valid() {
        let valid_der = [0x30, 0x06, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02];
        let result = cert_parser::parse_der(&valid_der);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cert_parser_invalid_tag() {
        let invalid = [0x31, 0x00];
        let result = cert_parser::parse_der(&invalid);
        assert_eq!(result, Err(cert_parser::CertError::InvalidTag));
    }

    #[test]
    fn test_cert_parser_too_short() {
        let short = [0x30];
        let result = cert_parser::parse_der(&short);
        assert_eq!(result, Err(cert_parser::CertError::TooShort));
    }

    #[test]
    fn test_jwt_parser_valid_format() {
        let jwt = "header.payload.signature";
        // This will fail on base64 decode but format is valid
        let result = jwt_parser::parse_jwt(jwt);
        // The simplified parser accepts this format
        assert!(result.is_ok() || matches!(result, Err(jwt_parser::JwtError::InvalidBase64)));
    }

    #[test]
    fn test_jwt_parser_invalid_format() {
        let jwt = "only.two.parts.here.extra";
        let result = jwt_parser::parse_jwt(jwt);
        assert_eq!(result, Err(jwt_parser::JwtError::InvalidFormat));
    }

    #[test]
    fn test_fuzz_target_generation() {
        let target = generate_fuzz_target("my_module", "my_function");
        assert!(target.contains("honggfuzz"));
        assert!(target.contains("my_module::my_function"));
    }
}
