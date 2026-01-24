//! JWT Security Implementation
//!
//! Secure JWT handling with proper validation, signing, verification,
//! and security best practices for token-based authentication.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// JWT configuration
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// Signing algorithm
    pub algorithm: Algorithm,
    /// Token issuer
    pub issuer: String,
    /// Token audience
    pub audience: Vec<String>,
    /// Token expiration time (seconds)
    pub expiration: u64,
    /// Allow clock skew (seconds)
    pub clock_skew: u64,
    /// Require expiration claim
    pub require_exp: bool,
    /// Require issued-at claim
    pub require_iat: bool,
    /// Require not-before claim
    pub require_nbf: bool,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::HS256,
            issuer: "secure-app".to_string(),
            audience: vec!["secure-app-users".to_string()],
            expiration: 3600, // 1 hour
            clock_skew: 60,   // 1 minute
            require_exp: true,
            require_iat: true,
            require_nbf: false,
        }
    }
}

/// Supported algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
}

impl Algorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::HS256 => "HS256",
            Algorithm::HS384 => "HS384",
            Algorithm::HS512 => "HS512",
            Algorithm::RS256 => "RS256",
            Algorithm::RS384 => "RS384",
            Algorithm::RS512 => "RS512",
            Algorithm::ES256 => "ES256",
            Algorithm::ES384 => "ES384",
            Algorithm::ES512 => "ES512",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "HS256" => Some(Algorithm::HS256),
            "HS384" => Some(Algorithm::HS384),
            "HS512" => Some(Algorithm::HS512),
            "RS256" => Some(Algorithm::RS256),
            "RS384" => Some(Algorithm::RS384),
            "RS512" => Some(Algorithm::RS512),
            "ES256" => Some(Algorithm::ES256),
            "ES384" => Some(Algorithm::ES384),
            "ES512" => Some(Algorithm::ES512),
            _ => None,
        }
    }

    pub fn is_symmetric(&self) -> bool {
        matches!(self, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512)
    }
}

/// JWT header
#[derive(Debug, Clone)]
pub struct JwtHeader {
    pub alg: Algorithm,
    pub typ: String,
    pub kid: Option<String>,
}

impl Default for JwtHeader {
    fn default() -> Self {
        Self {
            alg: Algorithm::HS256,
            typ: "JWT".to_string(),
            kid: None,
        }
    }
}

impl JwtHeader {
    pub fn new(algorithm: Algorithm) -> Self {
        Self {
            alg: algorithm,
            typ: "JWT".to_string(),
            kid: None,
        }
    }

    pub fn with_kid(mut self, kid: &str) -> Self {
        self.kid = Some(kid.to_string());
        self
    }

    pub fn to_json(&self) -> String {
        let mut json = format!(r#"{{"alg":"{}","typ":"{}""#, self.alg.as_str(), self.typ);
        if let Some(ref kid) = self.kid {
            json.push_str(&format!(r#","kid":"{}""#, kid));
        }
        json.push('}');
        json
    }

    pub fn from_json(json: &str) -> Result<Self, JwtError> {
        // Simplified JSON parsing (in production, use serde_json)
        let alg_start = json
            .find(r#""alg":""#)
            .ok_or(JwtError::InvalidHeader("missing alg".to_string()))?;
        let alg_value_start = alg_start + 7;
        let alg_end = json[alg_value_start..]
            .find('"')
            .ok_or(JwtError::InvalidHeader("invalid alg".to_string()))?;
        let alg_str = &json[alg_value_start..alg_value_start + alg_end];

        let alg = Algorithm::from_str(alg_str)
            .ok_or(JwtError::UnsupportedAlgorithm(alg_str.to_string()))?;

        Ok(Self {
            alg,
            typ: "JWT".to_string(),
            kid: None,
        })
    }
}

/// JWT claims
#[derive(Debug, Clone)]
pub struct JwtClaims {
    /// Subject (user ID)
    pub sub: Option<String>,
    /// Issuer
    pub iss: Option<String>,
    /// Audience
    pub aud: Option<Vec<String>>,
    /// Expiration time
    pub exp: Option<u64>,
    /// Not before time
    pub nbf: Option<u64>,
    /// Issued at time
    pub iat: Option<u64>,
    /// JWT ID
    pub jti: Option<String>,
    /// Custom claims
    pub custom: HashMap<String, ClaimValue>,
}

/// Claim value types
#[derive(Debug, Clone)]
pub enum ClaimValue {
    String(String),
    Number(i64),
    Boolean(bool),
    Array(Vec<String>),
}

impl Default for JwtClaims {
    fn default() -> Self {
        Self {
            sub: None,
            iss: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            custom: HashMap::new(),
        }
    }
}

impl JwtClaims {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn subject(mut self, sub: &str) -> Self {
        self.sub = Some(sub.to_string());
        self
    }

    pub fn issuer(mut self, iss: &str) -> Self {
        self.iss = Some(iss.to_string());
        self
    }

    pub fn audience(mut self, aud: &[&str]) -> Self {
        self.aud = Some(aud.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn expires_in(mut self, seconds: u64) -> Self {
        self.exp = Some(current_timestamp() + seconds);
        self
    }

    pub fn expires_at(mut self, timestamp: u64) -> Self {
        self.exp = Some(timestamp);
        self
    }

    pub fn not_before(mut self, timestamp: u64) -> Self {
        self.nbf = Some(timestamp);
        self
    }

    pub fn issued_at(mut self, timestamp: u64) -> Self {
        self.iat = Some(timestamp);
        self
    }

    pub fn jti(mut self, jti: &str) -> Self {
        self.jti = Some(jti.to_string());
        self
    }

    pub fn claim(mut self, key: &str, value: ClaimValue) -> Self {
        self.custom.insert(key.to_string(), value);
        self
    }

    pub fn to_json(&self) -> String {
        let mut parts = Vec::new();

        if let Some(ref sub) = self.sub {
            parts.push(format!(r#""sub":"{}""#, escape_json(sub)));
        }
        if let Some(ref iss) = self.iss {
            parts.push(format!(r#""iss":"{}""#, escape_json(iss)));
        }
        if let Some(ref aud) = self.aud {
            let aud_json: Vec<String> = aud
                .iter()
                .map(|a| format!(r#""{}""#, escape_json(a)))
                .collect();
            parts.push(format!(r#""aud":[{}]"#, aud_json.join(",")));
        }
        if let Some(exp) = self.exp {
            parts.push(format!(r#""exp":{}"#, exp));
        }
        if let Some(nbf) = self.nbf {
            parts.push(format!(r#""nbf":{}"#, nbf));
        }
        if let Some(iat) = self.iat {
            parts.push(format!(r#""iat":{}"#, iat));
        }
        if let Some(ref jti) = self.jti {
            parts.push(format!(r#""jti":"{}""#, escape_json(jti)));
        }

        for (key, value) in &self.custom {
            let value_json = match value {
                ClaimValue::String(s) => format!(r#""{}""#, escape_json(s)),
                ClaimValue::Number(n) => n.to_string(),
                ClaimValue::Boolean(b) => b.to_string(),
                ClaimValue::Array(arr) => {
                    let items: Vec<String> = arr
                        .iter()
                        .map(|s| format!(r#""{}""#, escape_json(s)))
                        .collect();
                    format!("[{}]", items.join(","))
                }
            };
            parts.push(format!(r#""{}":"{}""#, key, value_json));
        }

        format!("{{{}}}", parts.join(","))
    }
}

/// JWT token
#[derive(Debug, Clone)]
pub struct Jwt {
    pub header: JwtHeader,
    pub claims: JwtClaims,
}

impl Jwt {
    pub fn new(header: JwtHeader, claims: JwtClaims) -> Self {
        Self { header, claims }
    }
}

/// JWT encoder/decoder
#[derive(Debug)]
pub struct JwtCodec {
    config: JwtConfig,
    secret: Vec<u8>,
}

impl JwtCodec {
    pub fn new(config: JwtConfig, secret: &[u8]) -> Self {
        Self {
            config,
            secret: secret.to_vec(),
        }
    }

    /// Encode and sign a JWT
    pub fn encode(&self, claims: JwtClaims) -> Result<String, JwtError> {
        let header = JwtHeader::new(self.config.algorithm);

        // Add standard claims if not present
        let mut claims = claims;
        if claims.iss.is_none() {
            claims.iss = Some(self.config.issuer.clone());
        }
        if claims.aud.is_none() {
            claims.aud = Some(self.config.audience.clone());
        }
        if claims.iat.is_none() {
            claims.iat = Some(current_timestamp());
        }
        if claims.exp.is_none() {
            claims.exp = Some(current_timestamp() + self.config.expiration);
        }

        // Encode header and payload
        let header_json = header.to_json();
        let claims_json = claims.to_json();

        let header_b64 = base64_url_encode(header_json.as_bytes());
        let claims_b64 = base64_url_encode(claims_json.as_bytes());

        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let signature = self.sign(&signing_input)?;
        let signature_b64 = base64_url_encode(&signature);

        Ok(format!("{}.{}", signing_input, signature_b64))
    }

    /// Decode and verify a JWT
    pub fn decode(&self, token: &str) -> Result<Jwt, JwtError> {
        // Split token
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtError::MalformedToken);
        }

        let header_b64 = parts[0];
        let claims_b64 = parts[1];
        let signature_b64 = parts[2];

        // Decode header
        let header_bytes = base64_url_decode(header_b64)
            .map_err(|_| JwtError::InvalidHeader("base64 decode failed".to_string()))?;
        let header_json = String::from_utf8(header_bytes)
            .map_err(|_| JwtError::InvalidHeader("utf8 decode failed".to_string()))?;
        let header = JwtHeader::from_json(&header_json)?;

        // Verify algorithm matches
        if header.alg != self.config.algorithm {
            return Err(JwtError::AlgorithmMismatch {
                expected: self.config.algorithm.as_str().to_string(),
                got: header.alg.as_str().to_string(),
            });
        }

        // Verify signature
        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let signature = base64_url_decode(signature_b64).map_err(|_| JwtError::InvalidSignature)?;

        self.verify(&signing_input, &signature)?;

        // Decode claims
        let claims_bytes = base64_url_decode(claims_b64)
            .map_err(|_| JwtError::InvalidClaims("base64 decode failed".to_string()))?;
        let claims_json = String::from_utf8(claims_bytes)
            .map_err(|_| JwtError::InvalidClaims("utf8 decode failed".to_string()))?;

        let claims = self.parse_claims(&claims_json)?;

        // Validate claims
        self.validate_claims(&claims)?;

        Ok(Jwt { header, claims })
    }

    /// Sign the message
    fn sign(&self, message: &str) -> Result<Vec<u8>, JwtError> {
        // Simplified HMAC-SHA256 (in production, use ring or hmac crate)
        Ok(simple_hmac_sha256(&self.secret, message.as_bytes()))
    }

    /// Verify the signature
    fn verify(&self, message: &str, signature: &[u8]) -> Result<(), JwtError> {
        let expected = self.sign(message)?;

        // Constant-time comparison
        if !constant_time_eq(&expected, signature) {
            return Err(JwtError::InvalidSignature);
        }

        Ok(())
    }

    /// Parse claims from JSON
    fn parse_claims(&self, json: &str) -> Result<JwtClaims, JwtError> {
        let mut claims = JwtClaims::default();

        // Parse subject
        if let Some(sub) = extract_string_claim(json, "sub") {
            claims.sub = Some(sub);
        }

        // Parse issuer
        if let Some(iss) = extract_string_claim(json, "iss") {
            claims.iss = Some(iss);
        }

        // Parse expiration
        if let Some(exp) = extract_number_claim(json, "exp") {
            claims.exp = Some(exp as u64);
        }

        // Parse issued at
        if let Some(iat) = extract_number_claim(json, "iat") {
            claims.iat = Some(iat as u64);
        }

        // Parse not before
        if let Some(nbf) = extract_number_claim(json, "nbf") {
            claims.nbf = Some(nbf as u64);
        }

        Ok(claims)
    }

    /// Validate claims
    fn validate_claims(&self, claims: &JwtClaims) -> Result<(), JwtError> {
        let now = current_timestamp();

        // Validate expiration
        if self.config.require_exp {
            let exp = claims
                .exp
                .ok_or(JwtError::MissingClaim("exp".to_string()))?;
            if now > exp + self.config.clock_skew {
                return Err(JwtError::Expired);
            }
        }

        // Validate not before
        if self.config.require_nbf {
            let nbf = claims
                .nbf
                .ok_or(JwtError::MissingClaim("nbf".to_string()))?;
            if now + self.config.clock_skew < nbf {
                return Err(JwtError::NotYetValid);
            }
        }

        // Validate issued at
        if self.config.require_iat {
            let iat = claims
                .iat
                .ok_or(JwtError::MissingClaim("iat".to_string()))?;
            // Token shouldn't be issued in the future
            if iat > now + self.config.clock_skew {
                return Err(JwtError::InvalidClaims("iat in future".to_string()));
            }
        }

        // Validate issuer
        if let Some(ref iss) = claims.iss {
            if iss != &self.config.issuer {
                return Err(JwtError::InvalidIssuer {
                    expected: self.config.issuer.clone(),
                    got: iss.clone(),
                });
            }
        }

        // Validate audience
        if let Some(ref aud) = claims.aud {
            let has_valid_aud = aud.iter().any(|a| self.config.audience.contains(a));
            if !has_valid_aud {
                return Err(JwtError::InvalidAudience);
            }
        }

        Ok(())
    }
}

/// JWT errors
#[derive(Debug)]
pub enum JwtError {
    MalformedToken,
    InvalidHeader(String),
    InvalidClaims(String),
    InvalidSignature,
    Expired,
    NotYetValid,
    MissingClaim(String),
    UnsupportedAlgorithm(String),
    AlgorithmMismatch { expected: String, got: String },
    InvalidIssuer { expected: String, got: String },
    InvalidAudience,
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::MalformedToken => write!(f, "Malformed JWT token"),
            JwtError::InvalidHeader(msg) => write!(f, "Invalid header: {}", msg),
            JwtError::InvalidClaims(msg) => write!(f, "Invalid claims: {}", msg),
            JwtError::InvalidSignature => write!(f, "Invalid signature"),
            JwtError::Expired => write!(f, "Token expired"),
            JwtError::NotYetValid => write!(f, "Token not yet valid"),
            JwtError::MissingClaim(claim) => write!(f, "Missing required claim: {}", claim),
            JwtError::UnsupportedAlgorithm(alg) => write!(f, "Unsupported algorithm: {}", alg),
            JwtError::AlgorithmMismatch { expected, got } => {
                write!(f, "Algorithm mismatch: expected {}, got {}", expected, got)
            }
            JwtError::InvalidIssuer { expected, got } => {
                write!(f, "Invalid issuer: expected {}, got {}", expected, got)
            }
            JwtError::InvalidAudience => write!(f, "Invalid audience"),
        }
    }
}

impl std::error::Error for JwtError {}

/// JWT blacklist for token revocation
#[derive(Debug)]
pub struct JwtBlacklist {
    revoked: HashMap<String, u64>,
}

impl JwtBlacklist {
    pub fn new() -> Self {
        Self {
            revoked: HashMap::new(),
        }
    }

    /// Revoke a token by JTI
    pub fn revoke(&mut self, jti: &str, exp: u64) {
        self.revoked.insert(jti.to_string(), exp);
    }

    /// Check if a token is revoked
    pub fn is_revoked(&self, jti: &str) -> bool {
        self.revoked.contains_key(jti)
    }

    /// Clean up expired revocations
    pub fn cleanup(&mut self) {
        let now = current_timestamp();
        self.revoked.retain(|_, exp| *exp > now);
    }
}

impl Default for JwtBlacklist {
    fn default() -> Self {
        Self::new()
    }
}

/// Refresh token manager
#[derive(Debug)]
pub struct RefreshTokenManager {
    tokens: HashMap<String, RefreshToken>,
    max_per_user: usize,
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub token: String,
    pub user_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub used: bool,
}

impl RefreshTokenManager {
    pub fn new(max_per_user: usize) -> Self {
        Self {
            tokens: HashMap::new(),
            max_per_user,
        }
    }

    /// Generate a new refresh token
    pub fn generate(&mut self, user_id: &str, lifetime: u64) -> RefreshToken {
        let now = current_timestamp();
        let token = generate_random_token();

        let refresh_token = RefreshToken {
            token: token.clone(),
            user_id: user_id.to_string(),
            created_at: now,
            expires_at: now + lifetime,
            used: false,
        };

        self.tokens.insert(token, refresh_token.clone());
        refresh_token
    }

    /// Validate and consume a refresh token
    pub fn consume(&mut self, token: &str) -> Result<RefreshToken, JwtError> {
        let refresh_token = self
            .tokens
            .get_mut(token)
            .ok_or(JwtError::InvalidSignature)?;

        // Check if expired
        if refresh_token.expires_at < current_timestamp() {
            self.tokens.remove(token);
            return Err(JwtError::Expired);
        }

        // Check if already used (one-time use)
        if refresh_token.used {
            // Token reuse detected - revoke all tokens for this user
            let user_id = refresh_token.user_id.clone();
            self.revoke_user_tokens(&user_id);
            return Err(JwtError::InvalidSignature);
        }

        // Mark as used
        refresh_token.used = true;

        Ok(refresh_token.clone())
    }

    /// Revoke all tokens for a user
    pub fn revoke_user_tokens(&mut self, user_id: &str) {
        self.tokens.retain(|_, t| t.user_id != user_id);
    }

    /// Cleanup expired tokens
    pub fn cleanup(&mut self) {
        let now = current_timestamp();
        self.tokens.retain(|_, t| t.expires_at > now);
    }
}

// Helper functions

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn base64_url_encode(data: &[u8]) -> String {
    // Simplified base64url encoding
    let b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let chars: Vec<char> = b64_chars.chars().collect();
    let mut result = String::new();

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(chars[b0 >> 2]);
        result.push(chars[((b0 & 0x03) << 4) | (b1 >> 4)]);

        if chunk.len() > 1 {
            result.push(chars[((b1 & 0x0f) << 2) | (b2 >> 6)]);
        }
        if chunk.len() > 2 {
            result.push(chars[b2 & 0x3f]);
        }
    }

    result
}

fn base64_url_decode(data: &str) -> Result<Vec<u8>, ()> {
    let b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = Vec::new();

    let chars: Vec<u8> = data
        .chars()
        .filter_map(|c| b64_chars.find(c).map(|i| i as u8))
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

fn simple_hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    // Simplified HMAC (in production, use proper crypto library)
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    message.hash(&mut hasher);

    let hash = hasher.finish();
    hash.to_le_bytes().to_vec()
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

fn generate_random_token() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    current_timestamp().hash(&mut hasher);
    std::process::id().hash(&mut hasher);

    format!(
        "{:016x}{:016x}",
        hasher.finish(),
        hasher.finish() ^ 0xDEADBEEF
    )
}

fn extract_string_claim(json: &str, key: &str) -> Option<String> {
    let pattern = format!(r#""{}":" "#, key);
    let start = json.find(&format!(r#""{}":""#, key))?;
    let value_start = start + key.len() + 4;
    let rest = &json[value_start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_number_claim(json: &str, key: &str) -> Option<i64> {
    let pattern = format!(r#""{}":"#, key);
    let start = json.find(&pattern)?;
    let value_start = start + pattern.len();
    let rest = &json[value_start..];

    let end = rest.find(|c: char| !c.is_ascii_digit())?;
    rest[..end].parse().ok()
}

fn main() {
    println!("=== JWT Security Demo ===\n");

    let config = JwtConfig {
        algorithm: Algorithm::HS256,
        issuer: "demo-app".to_string(),
        audience: vec!["demo-users".to_string()],
        expiration: 3600,
        clock_skew: 60,
        require_exp: true,
        require_iat: true,
        require_nbf: false,
    };

    let secret = b"super-secret-key-minimum-256-bits!";
    let codec = JwtCodec::new(config.clone(), secret);

    // Create and encode a token
    println!("--- Creating JWT ---");
    let claims = JwtClaims::new()
        .subject("user_123")
        .claim("role", ClaimValue::String("admin".to_string()))
        .claim(
            "permissions",
            ClaimValue::Array(vec![
                "read".to_string(),
                "write".to_string(),
                "delete".to_string(),
            ]),
        );

    let token = codec.encode(claims).unwrap();
    println!("Token: {}...{}", &token[..50], &token[token.len() - 20..]);

    // Decode and verify the token
    println!("\n--- Decoding JWT ---");
    match codec.decode(&token) {
        Ok(jwt) => {
            println!("Algorithm: {}", jwt.header.alg.as_str());
            println!("Subject: {:?}", jwt.claims.sub);
            println!("Issuer: {:?}", jwt.claims.iss);
            println!("Expires: {:?}", jwt.claims.exp);
            println!("Issued At: {:?}", jwt.claims.iat);
        }
        Err(e) => println!("Error: {}", e),
    }

    // Test invalid signature
    println!("\n--- Testing Invalid Signature ---");
    let tampered_token = format!("{}x", token);
    match codec.decode(&tampered_token) {
        Ok(_) => println!("Unexpected success!"),
        Err(e) => println!("Expected error: {}", e),
    }

    // Test algorithm confusion attack prevention
    println!("\n--- Algorithm Confusion Prevention ---");
    let none_header = r#"{"alg":"none","typ":"JWT"}"#;
    let fake_token = format!(
        "{}.{}.{}",
        base64_url_encode(none_header.as_bytes()),
        base64_url_encode(b"{}"),
        ""
    );
    match codec.decode(&fake_token) {
        Ok(_) => println!("VULNERABLE: Accepted 'none' algorithm!"),
        Err(e) => println!("Protected: {}", e),
    }

    // Token blacklist
    println!("\n--- Token Blacklist ---");
    let mut blacklist = JwtBlacklist::new();
    blacklist.revoke("jti_12345", current_timestamp() + 3600);
    println!(
        "Is 'jti_12345' revoked: {}",
        blacklist.is_revoked("jti_12345")
    );
    println!(
        "Is 'jti_other' revoked: {}",
        blacklist.is_revoked("jti_other")
    );

    // Refresh tokens
    println!("\n--- Refresh Tokens ---");
    let mut refresh_manager = RefreshTokenManager::new(5);

    let refresh_token = refresh_manager.generate("user_123", 7 * 24 * 3600);
    println!("Generated refresh token: {}...", &refresh_token.token[..20]);

    match refresh_manager.consume(&refresh_token.token) {
        Ok(t) => println!("Consumed token for user: {}", t.user_id),
        Err(e) => println!("Error: {}", e),
    }

    // Try to reuse the token
    println!("\n--- Detecting Token Reuse ---");
    match refresh_manager.consume(&refresh_token.token) {
        Ok(_) => println!("Unexpected: Token reuse allowed!"),
        Err(e) => println!("Protected against reuse: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_codec() -> JwtCodec {
        let config = JwtConfig::default();
        JwtCodec::new(config, b"test-secret-key-for-hmac-256-bits")
    }

    #[test]
    fn test_encode_decode() {
        let codec = create_codec();
        let claims = JwtClaims::new().subject("user_1");

        let token = codec.encode(claims).unwrap();
        let jwt = codec.decode(&token).unwrap();

        assert_eq!(jwt.claims.sub, Some("user_1".to_string()));
    }

    #[test]
    fn test_invalid_signature() {
        let codec = create_codec();
        let claims = JwtClaims::new().subject("user_1");

        let token = codec.encode(claims).unwrap();
        let tampered = format!("{}x", token);

        assert!(matches!(
            codec.decode(&tampered),
            Err(JwtError::InvalidSignature)
        ));
    }

    #[test]
    fn test_expired_token() {
        let config = JwtConfig {
            expiration: 0,
            clock_skew: 0,
            ..JwtConfig::default()
        };
        let codec = JwtCodec::new(config, b"test-secret-key-for-hmac-256-bits");

        let claims = JwtClaims::new()
            .subject("user_1")
            .expires_at(current_timestamp() - 100); // Expired

        let token = codec.encode(claims).unwrap();

        assert!(matches!(codec.decode(&token), Err(JwtError::Expired)));
    }

    #[test]
    fn test_algorithm_mismatch() {
        let config = JwtConfig {
            algorithm: Algorithm::HS256,
            ..JwtConfig::default()
        };
        let codec = JwtCodec::new(config, b"test-secret-key-for-hmac-256-bits");

        // Create a token with different algorithm in header
        let header = r#"{"alg":"HS512","typ":"JWT"}"#;
        let claims = r#"{"sub":"user"}"#;
        let fake_token = format!(
            "{}.{}.fake",
            base64_url_encode(header.as_bytes()),
            base64_url_encode(claims.as_bytes())
        );

        assert!(matches!(
            codec.decode(&fake_token),
            Err(JwtError::AlgorithmMismatch { .. })
        ));
    }

    #[test]
    fn test_malformed_token() {
        let codec = create_codec();

        assert!(matches!(
            codec.decode("not.a.valid.token.with.dots"),
            Err(JwtError::MalformedToken)
        ));
        assert!(matches!(
            codec.decode("nodots"),
            Err(JwtError::MalformedToken)
        ));
    }

    #[test]
    fn test_blacklist() {
        let mut blacklist = JwtBlacklist::new();

        assert!(!blacklist.is_revoked("token_1"));

        blacklist.revoke("token_1", current_timestamp() + 3600);
        assert!(blacklist.is_revoked("token_1"));
        assert!(!blacklist.is_revoked("token_2"));
    }

    #[test]
    fn test_refresh_token_generation() {
        let mut manager = RefreshTokenManager::new(5);
        let token = manager.generate("user_1", 3600);

        assert!(!token.token.is_empty());
        assert_eq!(token.user_id, "user_1");
        assert!(!token.used);
    }

    #[test]
    fn test_refresh_token_consume() {
        let mut manager = RefreshTokenManager::new(5);
        let token = manager.generate("user_1", 3600);

        let consumed = manager.consume(&token.token).unwrap();
        assert_eq!(consumed.user_id, "user_1");
    }

    #[test]
    fn test_refresh_token_reuse_detection() {
        let mut manager = RefreshTokenManager::new(5);
        let token = manager.generate("user_1", 3600);

        // First use
        manager.consume(&token.token).unwrap();

        // Second use should fail
        assert!(manager.consume(&token.token).is_err());
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
        let encoded = base64_url_encode(data);
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(&decoded[..data.len()], data);
    }

    #[test]
    fn test_jwt_header_json() {
        let header = JwtHeader::new(Algorithm::HS256).with_kid("key-1");
        let json = header.to_json();

        assert!(json.contains(r#""alg":"HS256""#));
        assert!(json.contains(r#""typ":"JWT""#));
        assert!(json.contains(r#""kid":"key-1""#));
    }

    #[test]
    fn test_jwt_claims_json() {
        let claims = JwtClaims::new()
            .subject("user_1")
            .issuer("test-issuer")
            .expires_at(1234567890);

        let json = claims.to_json();

        assert!(json.contains(r#""sub":"user_1""#));
        assert!(json.contains(r#""iss":"test-issuer""#));
        assert!(json.contains(r#""exp":1234567890"#));
    }
}
