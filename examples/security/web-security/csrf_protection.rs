//! CSRF Protection Example
//!
//! Demonstrates Cross-Site Request Forgery protection patterns.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// CSRF token generator and validator
pub struct CsrfProtection {
    secret_key: Vec<u8>,
    token_lifetime_secs: u64,
}

impl CsrfProtection {
    /// Create with a secret key
    pub fn new(secret_key: &[u8]) -> Self {
        Self {
            secret_key: secret_key.to_vec(),
            token_lifetime_secs: 3600, // 1 hour default
        }
    }

    /// Set token lifetime
    pub fn with_lifetime(mut self, seconds: u64) -> Self {
        self.token_lifetime_secs = seconds;
        self
    }

    /// Generate a CSRF token for a session
    pub fn generate_token(&self, session_id: &str) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let message = format!("{}:{}", session_id, timestamp);
        let signature = self.sign(&message);

        // Token format: base64(timestamp:signature)
        let token_data = format!("{}:{}", timestamp, signature);
        URL_SAFE_NO_PAD.encode(token_data.as_bytes())
    }

    /// Validate a CSRF token
    pub fn validate_token(&self, token: &str, session_id: &str) -> Result<(), CsrfError> {
        // Decode token
        let token_bytes = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| CsrfError::InvalidToken)?;

        let token_str = String::from_utf8(token_bytes).map_err(|_| CsrfError::InvalidToken)?;

        // Parse timestamp and signature
        let parts: Vec<&str> = token_str.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(CsrfError::InvalidToken);
        }

        let timestamp: u64 = parts[0].parse().map_err(|_| CsrfError::InvalidToken)?;
        let provided_signature = parts[1];

        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now > timestamp + self.token_lifetime_secs {
            return Err(CsrfError::TokenExpired);
        }

        // Verify signature
        let message = format!("{}:{}", session_id, timestamp);
        let expected_signature = self.sign(&message);

        // Constant-time comparison
        if !constant_time_compare(provided_signature.as_bytes(), expected_signature.as_bytes()) {
            return Err(CsrfError::InvalidSignature);
        }

        Ok(())
    }

    fn sign(&self, message: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret_key).expect("HMAC can accept any key size");
        mac.update(message.as_bytes());
        let result = mac.finalize();
        URL_SAFE_NO_PAD.encode(result.into_bytes())
    }
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[derive(Debug, Clone, PartialEq)]
pub enum CsrfError {
    InvalidToken,
    TokenExpired,
    InvalidSignature,
    MissingToken,
}

impl std::fmt::Display for CsrfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidToken => write!(f, "Invalid CSRF token format"),
            Self::TokenExpired => write!(f, "CSRF token has expired"),
            Self::InvalidSignature => write!(f, "CSRF token signature invalid"),
            Self::MissingToken => write!(f, "CSRF token missing"),
        }
    }
}

impl std::error::Error for CsrfError {}

/// Double-submit cookie pattern
pub struct DoubleSubmitCsrf {
    cookie_name: String,
    header_name: String,
}

impl DoubleSubmitCsrf {
    pub fn new() -> Self {
        Self {
            cookie_name: "csrf_token".to_string(),
            header_name: "X-CSRF-Token".to_string(),
        }
    }

    /// Generate a random token
    pub fn generate_token() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(&bytes)
    }

    /// Validate that cookie and header match
    pub fn validate(&self, cookie_value: &str, header_value: &str) -> Result<(), CsrfError> {
        if cookie_value.is_empty() || header_value.is_empty() {
            return Err(CsrfError::MissingToken);
        }

        if !constant_time_compare(cookie_value.as_bytes(), header_value.as_bytes()) {
            return Err(CsrfError::InvalidToken);
        }

        Ok(())
    }

    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    pub fn header_name(&self) -> &str {
        &self.header_name
    }
}

impl Default for DoubleSubmitCsrf {
    fn default() -> Self {
        Self::new()
    }
}

/// SameSite cookie configuration
#[derive(Debug, Clone, Copy)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl SameSite {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }
}

/// Generate a secure cookie header
pub fn secure_cookie(name: &str, value: &str, same_site: SameSite) -> String {
    format!(
        "{}={}; HttpOnly; Secure; SameSite={}; Path=/",
        name,
        value,
        same_site.as_str()
    )
}

fn main() {
    println!("=== CSRF Protection Demo ===\n");

    // Signed token pattern
    println!("--- Signed Token Pattern ---");
    let secret = b"super_secret_key_for_csrf_protection";
    let csrf = CsrfProtection::new(secret);

    let session_id = "user_session_12345";
    let token = csrf.generate_token(session_id);
    println!("Generated token: {}...", &token[..20]);

    // Validate valid token
    match csrf.validate_token(&token, session_id) {
        Ok(()) => println!("Token is valid!"),
        Err(e) => println!("Validation failed: {}", e),
    }

    // Validate with wrong session
    match csrf.validate_token(&token, "different_session") {
        Ok(()) => println!("ERROR: Should have failed!"),
        Err(e) => println!("Wrong session rejected: {}", e),
    }

    // Double-submit cookie pattern
    println!("\n--- Double-Submit Cookie Pattern ---");
    let ds_csrf = DoubleSubmitCsrf::new();
    let token = DoubleSubmitCsrf::generate_token();
    println!("Token for cookie and header: {}...", &token[..20]);
    println!("Cookie name: {}", ds_csrf.cookie_name());
    println!("Header name: {}", ds_csrf.header_name());

    // Validate matching values
    match ds_csrf.validate(&token, &token) {
        Ok(()) => println!("Matching tokens validated!"),
        Err(e) => println!("Validation failed: {}", e),
    }

    // Validate mismatched values
    let fake_token = DoubleSubmitCsrf::generate_token();
    match ds_csrf.validate(&token, &fake_token) {
        Ok(()) => println!("ERROR: Should have failed!"),
        Err(e) => println!("Mismatched tokens rejected: {}", e),
    }

    // Secure cookie generation
    println!("\n--- Secure Cookie Headers ---");
    println!("{}", secure_cookie("csrf_token", &token, SameSite::Strict));

    println!("\n=== Best Practices ===");
    println!("1. Use SameSite=Strict or Lax cookies");
    println!("2. Always use HttpOnly and Secure flags");
    println!("3. Validate Origin/Referer headers");
    println!("4. Use custom headers for API requests");
    println!("5. Implement token rotation on sensitive actions");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csrf_token_generation_validation() {
        let csrf = CsrfProtection::new(b"test_secret");
        let session = "session123";

        let token = csrf.generate_token(session);
        assert!(csrf.validate_token(&token, session).is_ok());
    }

    #[test]
    fn test_csrf_wrong_session() {
        let csrf = CsrfProtection::new(b"test_secret");

        let token = csrf.generate_token("session1");
        assert!(csrf.validate_token(&token, "session2").is_err());
    }

    #[test]
    fn test_csrf_tampered_token() {
        let csrf = CsrfProtection::new(b"test_secret");
        let session = "session123";

        let mut token = csrf.generate_token(session);
        // Tamper with token
        token.push('X');

        assert!(csrf.validate_token(&token, session).is_err());
    }

    #[test]
    fn test_double_submit() {
        let ds = DoubleSubmitCsrf::new();
        let token = DoubleSubmitCsrf::generate_token();

        assert!(ds.validate(&token, &token).is_ok());
        assert!(ds.validate(&token, "different").is_err());
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare(b"hello", b"hello"));
        assert!(!constant_time_compare(b"hello", b"world"));
        assert!(!constant_time_compare(b"hello", b"hell"));
    }
}
