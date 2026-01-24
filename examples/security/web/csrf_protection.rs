//! CSRF Protection Implementation
//!
//! This example demonstrates Cross-Site Request Forgery protection
//! with double-submit cookies, synchronizer tokens, and SameSite
//! cookie attributes for Rust web applications.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// CSRF Token Types
// ============================================================================

/// CSRF protection strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsrfStrategy {
    /// Synchronizer token pattern (stateful)
    SynchronizerToken,
    /// Double-submit cookie pattern (stateless)
    DoubleSubmitCookie,
    /// Encrypted token pattern
    EncryptedToken,
    /// HMAC-based token pattern
    HmacToken,
}

/// CSRF token with metadata
#[derive(Debug, Clone)]
pub struct CsrfToken {
    /// The token value
    pub value: String,
    /// Creation timestamp
    pub created_at: Instant,
    /// Expiration duration
    pub expires_in: Duration,
    /// Associated session ID (for synchronizer pattern)
    pub session_id: Option<String>,
    /// Token strategy used
    pub strategy: CsrfStrategy,
}

impl CsrfToken {
    /// Check if token has expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.expires_in
    }

    /// Get remaining validity duration
    pub fn remaining_validity(&self) -> Option<Duration> {
        let elapsed = self.created_at.elapsed();
        if elapsed > self.expires_in {
            None
        } else {
            Some(self.expires_in - elapsed)
        }
    }
}

/// Cookie configuration for CSRF
#[derive(Debug, Clone)]
pub struct CookieConfig {
    /// Cookie name
    pub name: String,
    /// SameSite attribute
    pub same_site: SameSite,
    /// Secure flag (HTTPS only)
    pub secure: bool,
    /// HttpOnly flag
    pub http_only: bool,
    /// Cookie path
    pub path: String,
    /// Cookie domain
    pub domain: Option<String>,
    /// Max age in seconds
    pub max_age: Option<u64>,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: "__csrf_token".to_string(),
            same_site: SameSite::Strict,
            secure: true,
            http_only: false, // Must be readable by JS for double-submit
            path: "/".to_string(),
            domain: None,
            max_age: Some(3600),
        }
    }
}

/// SameSite cookie attribute
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl SameSite {
    pub fn as_str(&self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }
}

// ============================================================================
// Token Storage
// ============================================================================

/// Token store for synchronizer pattern
pub struct TokenStore {
    tokens: RwLock<HashMap<String, CsrfToken>>,
    max_tokens_per_session: usize,
    cleanup_interval: Duration,
    last_cleanup: RwLock<Instant>,
}

impl TokenStore {
    pub fn new(max_tokens_per_session: usize) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            max_tokens_per_session,
            cleanup_interval: Duration::from_secs(300),
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Store a token
    pub fn store(&self, token: CsrfToken) -> Result<(), CsrfError> {
        self.maybe_cleanup();

        let mut tokens = self.tokens.write().map_err(|_| CsrfError::StorageError)?;

        // Check per-session limit
        if let Some(session_id) = &token.session_id {
            let session_token_count = tokens
                .values()
                .filter(|t| t.session_id.as_ref() == Some(session_id))
                .count();

            if session_token_count >= self.max_tokens_per_session {
                // Remove oldest token for this session
                let oldest_key = tokens
                    .iter()
                    .filter(|(_, t)| t.session_id.as_ref() == Some(session_id))
                    .min_by_key(|(_, t)| t.created_at)
                    .map(|(k, _)| k.clone());

                if let Some(key) = oldest_key {
                    tokens.remove(&key);
                }
            }
        }

        tokens.insert(token.value.clone(), token);
        Ok(())
    }

    /// Validate and consume a token
    pub fn validate_and_consume(&self, token_value: &str) -> Result<bool, CsrfError> {
        let mut tokens = self.tokens.write().map_err(|_| CsrfError::StorageError)?;

        if let Some(token) = tokens.remove(token_value) {
            if token.is_expired() {
                return Ok(false);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Validate without consuming (for multiple submissions)
    pub fn validate(&self, token_value: &str) -> Result<bool, CsrfError> {
        let tokens = self.tokens.read().map_err(|_| CsrfError::StorageError)?;

        if let Some(token) = tokens.get(token_value) {
            Ok(!token.is_expired())
        } else {
            Ok(false)
        }
    }

    fn maybe_cleanup(&self) {
        let should_cleanup = {
            let last = self.last_cleanup.read().ok();
            last.map(|l| l.elapsed() > self.cleanup_interval)
                .unwrap_or(true)
        };

        if should_cleanup {
            if let Ok(mut last) = self.last_cleanup.write() {
                *last = Instant::now();
            }

            if let Ok(mut tokens) = self.tokens.write() {
                tokens.retain(|_, t| !t.is_expired());
            }
        }
    }
}

// ============================================================================
// CSRF Protection Manager
// ============================================================================

/// CSRF protection configuration
#[derive(Debug, Clone)]
pub struct CsrfConfig {
    /// Protection strategy
    pub strategy: CsrfStrategy,
    /// Token expiration
    pub token_expiry: Duration,
    /// Cookie configuration
    pub cookie: CookieConfig,
    /// Header name for token submission
    pub header_name: String,
    /// Form field name for token submission
    pub form_field_name: String,
    /// Secret key for HMAC/encryption
    pub secret_key: Vec<u8>,
    /// Exempt paths (regex patterns)
    pub exempt_paths: Vec<String>,
    /// Exempt methods
    pub exempt_methods: Vec<HttpMethod>,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            strategy: CsrfStrategy::DoubleSubmitCookie,
            token_expiry: Duration::from_secs(3600),
            cookie: CookieConfig::default(),
            header_name: "X-CSRF-Token".to_string(),
            form_field_name: "csrf_token".to_string(),
            secret_key: vec![0u8; 32], // Should be properly initialized
            exempt_paths: vec![],
            exempt_methods: vec![HttpMethod::Get, HttpMethod::Head, HttpMethod::Options],
        }
    }
}

/// HTTP methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

/// CSRF protection manager
pub struct CsrfProtection {
    config: CsrfConfig,
    token_store: Option<Arc<TokenStore>>,
}

impl CsrfProtection {
    pub fn new(config: CsrfConfig) -> Self {
        let token_store = match config.strategy {
            CsrfStrategy::SynchronizerToken => Some(Arc::new(TokenStore::new(10))),
            _ => None,
        };

        Self {
            config,
            token_store,
        }
    }

    /// Generate a new CSRF token
    pub fn generate_token(&self, session_id: Option<String>) -> Result<CsrfToken, CsrfError> {
        let token_value = match self.config.strategy {
            CsrfStrategy::SynchronizerToken => self.generate_random_token(),
            CsrfStrategy::DoubleSubmitCookie => self.generate_random_token(),
            CsrfStrategy::EncryptedToken => self.generate_encrypted_token(&session_id)?,
            CsrfStrategy::HmacToken => self.generate_hmac_token(&session_id)?,
        };

        let token = CsrfToken {
            value: token_value,
            created_at: Instant::now(),
            expires_in: self.config.token_expiry,
            session_id: session_id.clone(),
            strategy: self.config.strategy,
        };

        // Store for synchronizer pattern
        if let Some(store) = &self.token_store {
            store.store(token.clone())?;
        }

        Ok(token)
    }

    /// Validate a submitted token
    pub fn validate_token(
        &self,
        submitted_token: &str,
        cookie_token: Option<&str>,
        session_id: Option<&str>,
    ) -> Result<ValidationResult, CsrfError> {
        match self.config.strategy {
            CsrfStrategy::SynchronizerToken => self.validate_synchronizer_token(submitted_token),
            CsrfStrategy::DoubleSubmitCookie => {
                self.validate_double_submit(submitted_token, cookie_token)
            }
            CsrfStrategy::EncryptedToken => {
                self.validate_encrypted_token(submitted_token, session_id)
            }
            CsrfStrategy::HmacToken => self.validate_hmac_token(submitted_token, session_id),
        }
    }

    /// Check if request should be exempt from CSRF protection
    pub fn is_exempt(&self, method: HttpMethod, path: &str) -> bool {
        // Check method exemption
        if self.config.exempt_methods.contains(&method) {
            return true;
        }

        // Check path exemption
        for pattern in &self.config.exempt_paths {
            if path.starts_with(pattern) || path == pattern {
                return true;
            }
        }

        false
    }

    /// Generate cookie header value
    pub fn cookie_header(&self, token: &CsrfToken) -> String {
        let mut parts = vec![
            format!("{}={}", self.config.cookie.name, token.value),
            format!("Path={}", self.config.cookie.path),
            format!("SameSite={}", self.config.cookie.same_site.as_str()),
        ];

        if self.config.cookie.secure {
            parts.push("Secure".to_string());
        }

        if self.config.cookie.http_only {
            parts.push("HttpOnly".to_string());
        }

        if let Some(domain) = &self.config.cookie.domain {
            parts.push(format!("Domain={}", domain));
        }

        if let Some(max_age) = self.config.cookie.max_age {
            parts.push(format!("Max-Age={}", max_age));
        }

        parts.join("; ")
    }

    /// Generate HTML hidden input for forms
    pub fn hidden_input(&self, token: &CsrfToken) -> String {
        format!(
            r#"<input type="hidden" name="{}" value="{}" />"#,
            self.config.form_field_name,
            html_escape(&token.value)
        )
    }

    /// Generate meta tag for JavaScript access
    pub fn meta_tag(&self, token: &CsrfToken) -> String {
        format!(
            r#"<meta name="csrf-token" content="{}" />"#,
            html_escape(&token.value)
        )
    }

    // Private helper methods

    fn generate_random_token(&self) -> String {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};

        let state = RandomState::new();
        let mut hasher = state.build_hasher();
        hasher.write_u128(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        );

        let random_bytes: [u8; 32] = {
            let mut bytes = [0u8; 32];
            for (i, byte) in bytes.iter_mut().enumerate() {
                hasher.write_usize(i);
                *byte = (hasher.finish() & 0xFF) as u8;
            }
            bytes
        };

        base64_encode(&random_bytes)
    }

    fn generate_encrypted_token(&self, session_id: &Option<String>) -> Result<String, CsrfError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CsrfError::TokenGenerationError)?
            .as_secs();

        let session = session_id.as_deref().unwrap_or("");
        let payload = format!("{}:{}", timestamp, session);

        // Simple XOR encryption (use proper encryption in production)
        let encrypted: Vec<u8> = payload
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ self.config.secret_key[i % self.config.secret_key.len()])
            .collect();

        Ok(base64_encode(&encrypted))
    }

    fn generate_hmac_token(&self, session_id: &Option<String>) -> Result<String, CsrfError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CsrfError::TokenGenerationError)?
            .as_secs();

        let session = session_id.as_deref().unwrap_or("");
        let message = format!("{}:{}", timestamp, session);

        let hmac = compute_hmac(&self.config.secret_key, message.as_bytes());

        Ok(format!("{}:{}", base64_encode(&hmac), timestamp))
    }

    fn validate_synchronizer_token(&self, token: &str) -> Result<ValidationResult, CsrfError> {
        if let Some(store) = &self.token_store {
            if store.validate_and_consume(token)? {
                Ok(ValidationResult::Valid)
            } else {
                Ok(ValidationResult::Invalid(InvalidReason::TokenNotFound))
            }
        } else {
            Err(CsrfError::ConfigurationError)
        }
    }

    fn validate_double_submit(
        &self,
        submitted_token: &str,
        cookie_token: Option<&str>,
    ) -> Result<ValidationResult, CsrfError> {
        match cookie_token {
            Some(cookie) if constant_time_compare(submitted_token, cookie) => {
                Ok(ValidationResult::Valid)
            }
            Some(_) => Ok(ValidationResult::Invalid(InvalidReason::TokenMismatch)),
            None => Ok(ValidationResult::Invalid(InvalidReason::MissingCookie)),
        }
    }

    fn validate_encrypted_token(
        &self,
        token: &str,
        session_id: Option<&str>,
    ) -> Result<ValidationResult, CsrfError> {
        let encrypted = base64_decode(token).map_err(|_| CsrfError::InvalidToken)?;

        // Decrypt
        let decrypted: Vec<u8> = encrypted
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ self.config.secret_key[i % self.config.secret_key.len()])
            .collect();

        let payload = String::from_utf8(decrypted).map_err(|_| CsrfError::InvalidToken)?;

        let parts: Vec<&str> = payload.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Ok(ValidationResult::Invalid(InvalidReason::MalformedToken));
        }

        let timestamp: u64 = parts[0].parse().map_err(|_| CsrfError::InvalidToken)?;
        let token_session = parts[1];

        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CsrfError::ValidationError)?
            .as_secs();

        if now - timestamp > self.config.token_expiry.as_secs() {
            return Ok(ValidationResult::Invalid(InvalidReason::TokenExpired));
        }

        // Check session
        let expected_session = session_id.unwrap_or("");
        if !constant_time_compare(token_session, expected_session) {
            return Ok(ValidationResult::Invalid(InvalidReason::SessionMismatch));
        }

        Ok(ValidationResult::Valid)
    }

    fn validate_hmac_token(
        &self,
        token: &str,
        session_id: Option<&str>,
    ) -> Result<ValidationResult, CsrfError> {
        let parts: Vec<&str> = token.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Ok(ValidationResult::Invalid(InvalidReason::MalformedToken));
        }

        let submitted_hmac = base64_decode(parts[0]).map_err(|_| CsrfError::InvalidToken)?;
        let timestamp: u64 = parts[1].parse().map_err(|_| CsrfError::InvalidToken)?;

        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CsrfError::ValidationError)?
            .as_secs();

        if now - timestamp > self.config.token_expiry.as_secs() {
            return Ok(ValidationResult::Invalid(InvalidReason::TokenExpired));
        }

        // Recompute HMAC
        let session = session_id.unwrap_or("");
        let message = format!("{}:{}", timestamp, session);
        let expected_hmac = compute_hmac(&self.config.secret_key, message.as_bytes());

        if constant_time_compare_bytes(&submitted_hmac, &expected_hmac) {
            Ok(ValidationResult::Valid)
        } else {
            Ok(ValidationResult::Invalid(InvalidReason::InvalidSignature))
        }
    }
}

// ============================================================================
// Validation Result
// ============================================================================

/// Result of CSRF validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    Valid,
    Invalid(InvalidReason),
}

/// Reason for invalid token
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidReason {
    TokenNotFound,
    TokenMismatch,
    TokenExpired,
    MissingCookie,
    MissingHeader,
    MalformedToken,
    SessionMismatch,
    InvalidSignature,
}

/// CSRF errors
#[derive(Debug)]
pub enum CsrfError {
    TokenGenerationError,
    ValidationError,
    InvalidToken,
    StorageError,
    ConfigurationError,
}

impl std::fmt::Display for CsrfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CsrfError::TokenGenerationError => write!(f, "Failed to generate token"),
            CsrfError::ValidationError => write!(f, "Token validation failed"),
            CsrfError::InvalidToken => write!(f, "Invalid token format"),
            CsrfError::StorageError => write!(f, "Token storage error"),
            CsrfError::ConfigurationError => write!(f, "Configuration error"),
        }
    }
}

impl std::error::Error for CsrfError {}

// ============================================================================
// Middleware Integration
// ============================================================================

/// CSRF middleware for web frameworks
pub struct CsrfMiddleware {
    protection: Arc<CsrfProtection>,
}

impl CsrfMiddleware {
    pub fn new(protection: CsrfProtection) -> Self {
        Self {
            protection: Arc::new(protection),
        }
    }

    /// Process incoming request
    pub fn process_request(
        &self,
        method: HttpMethod,
        path: &str,
        headers: &HashMap<String, String>,
        cookies: &HashMap<String, String>,
        form_data: &HashMap<String, String>,
    ) -> Result<MiddlewareResult, CsrfError> {
        // Check exemptions
        if self.protection.is_exempt(method, path) {
            return Ok(MiddlewareResult::Continue);
        }

        // Extract token from header or form
        let submitted_token = headers
            .get(&self.protection.config.header_name)
            .or_else(|| form_data.get(&self.protection.config.form_field_name));

        let submitted_token = match submitted_token {
            Some(t) => t,
            None => {
                return Ok(MiddlewareResult::Reject(InvalidReason::MissingHeader));
            }
        };

        // Get cookie token for double-submit
        let cookie_token = cookies.get(&self.protection.config.cookie.name);

        // Validate
        let session_id = cookies.get("session_id").map(|s| s.as_str());
        let result = self.protection.validate_token(
            submitted_token,
            cookie_token.map(|s| s.as_str()),
            session_id,
        )?;

        match result {
            ValidationResult::Valid => Ok(MiddlewareResult::Continue),
            ValidationResult::Invalid(reason) => Ok(MiddlewareResult::Reject(reason)),
        }
    }

    /// Add CSRF token to response
    pub fn process_response(
        &self,
        session_id: Option<String>,
    ) -> Result<ResponseAdditions, CsrfError> {
        let token = self.protection.generate_token(session_id)?;

        Ok(ResponseAdditions {
            cookie_header: self.protection.cookie_header(&token),
            hidden_input: self.protection.hidden_input(&token),
            meta_tag: self.protection.meta_tag(&token),
            token_value: token.value,
        })
    }
}

/// Middleware processing result
#[derive(Debug)]
pub enum MiddlewareResult {
    Continue,
    Reject(InvalidReason),
}

/// Additions to add to response
#[derive(Debug)]
pub struct ResponseAdditions {
    pub cookie_header: String,
    pub hidden_input: String,
    pub meta_tag: String,
    pub token_value: String,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// HTML escape for XSS prevention
fn html_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#x27;".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

/// Constant-time string comparison
fn constant_time_compare(a: &str, b: &str) -> bool {
    constant_time_compare_bytes(a.as_bytes(), b.as_bytes())
}

/// Constant-time byte comparison
fn constant_time_compare_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Simple HMAC computation (use ring or similar in production)
fn compute_hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let state = RandomState::new();
    let mut hasher = state.build_hasher();

    // HMAC-like construction
    let block_size = 64;
    let mut padded_key = vec![0u8; block_size];

    if key.len() > block_size {
        for (i, &b) in key.iter().enumerate() {
            hasher.write_u8(b);
            padded_key[i % block_size] ^= (hasher.finish() & 0xFF) as u8;
        }
    } else {
        padded_key[..key.len()].copy_from_slice(key);
    }

    // Inner hash
    let i_key_pad: Vec<u8> = padded_key.iter().map(|b| b ^ 0x36).collect();
    hasher = state.build_hasher();
    for b in i_key_pad.iter().chain(message.iter()) {
        hasher.write_u8(*b);
    }
    let inner_hash = hasher.finish().to_le_bytes();

    // Outer hash
    let o_key_pad: Vec<u8> = padded_key.iter().map(|b| b ^ 0x5c).collect();
    hasher = state.build_hasher();
    for b in o_key_pad.iter().chain(inner_hash.iter()) {
        hasher.write_u8(*b);
    }

    hasher.finish().to_le_bytes().to_vec()
}

/// Base64 encode
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = String::new();
    for chunk in data.chunks(3) {
        let mut n = (chunk[0] as u32) << 16;
        if chunk.len() > 1 {
            n |= (chunk[1] as u32) << 8;
        }
        if chunk.len() > 2 {
            n |= chunk[2] as u32;
        }

        result.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
        result.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[(n >> 6 & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[(n & 0x3F) as usize] as char);
        }
    }
    result
}

/// Base64 decode
fn base64_decode(data: &str) -> Result<Vec<u8>, ()> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = Vec::new();
    let chars: Vec<u8> = data.bytes().collect();

    for chunk in chars.chunks(4) {
        let mut indices = [0u8; 4];
        for (i, &c) in chunk.iter().enumerate() {
            indices[i] = ALPHABET.iter().position(|&x| x == c).ok_or(())? as u8;
        }

        let n = ((indices[0] as u32) << 18)
            | ((indices[1] as u32) << 12)
            | ((indices.get(2).copied().unwrap_or(0) as u32) << 6)
            | (indices.get(3).copied().unwrap_or(0) as u32);

        result.push((n >> 16 & 0xFF) as u8);
        if chunk.len() > 2 {
            result.push((n >> 8 & 0xFF) as u8);
        }
        if chunk.len() > 3 {
            result.push((n & 0xFF) as u8);
        }
    }

    Ok(result)
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== CSRF Protection Implementation ===\n");

    // Example 1: Double-Submit Cookie Pattern
    println!("1. Double-Submit Cookie Pattern:");
    let config = CsrfConfig {
        strategy: CsrfStrategy::DoubleSubmitCookie,
        ..Default::default()
    };
    let protection = CsrfProtection::new(config);

    let token = protection
        .generate_token(Some("user-session-123".to_string()))
        .unwrap();
    println!("   Generated token: {}...", &token.value[..20]);
    println!("   Cookie header: {}", protection.cookie_header(&token));

    // Validate matching tokens
    let result = protection
        .validate_token(&token.value, Some(&token.value), None)
        .unwrap();
    println!("   Validation (matching): {:?}", result);

    // Validate mismatched tokens
    let result = protection
        .validate_token("wrong-token", Some(&token.value), None)
        .unwrap();
    println!("   Validation (mismatched): {:?}", result);

    // Example 2: Synchronizer Token Pattern
    println!("\n2. Synchronizer Token Pattern:");
    let config = CsrfConfig {
        strategy: CsrfStrategy::SynchronizerToken,
        ..Default::default()
    };
    let protection = CsrfProtection::new(config);

    let token = protection
        .generate_token(Some("user-session-456".to_string()))
        .unwrap();
    println!("   Stored token: {}...", &token.value[..20]);

    // First validation consumes the token
    let result = protection.validate_token(&token.value, None, None).unwrap();
    println!("   First validation: {:?}", result);

    // Second validation fails (token consumed)
    let result = protection.validate_token(&token.value, None, None).unwrap();
    println!("   Second validation: {:?}", result);

    // Example 3: HMAC Token Pattern
    println!("\n3. HMAC Token Pattern:");
    let config = CsrfConfig {
        strategy: CsrfStrategy::HmacToken,
        secret_key: b"super-secret-key-for-hmac-signing".to_vec(),
        ..Default::default()
    };
    let protection = CsrfProtection::new(config);

    let session_id = "user-session-789";
    let token = protection
        .generate_token(Some(session_id.to_string()))
        .unwrap();
    println!("   HMAC token: {}...", &token.value[..30]);

    let result = protection
        .validate_token(&token.value, None, Some(session_id))
        .unwrap();
    println!("   Validation (correct session): {:?}", result);

    let result = protection
        .validate_token(&token.value, None, Some("wrong-session"))
        .unwrap();
    println!("   Validation (wrong session): {:?}", result);

    // Example 4: Middleware Integration
    println!("\n4. Middleware Integration:");
    let config = CsrfConfig {
        strategy: CsrfStrategy::DoubleSubmitCookie,
        exempt_paths: vec!["/api/public".to_string()],
        ..Default::default()
    };
    let middleware = CsrfMiddleware::new(CsrfProtection::new(config));

    // GET request (exempt)
    let result = middleware
        .process_request(
            HttpMethod::Get,
            "/dashboard",
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
    println!("   GET request: {:?}", result);

    // POST to exempt path
    let result = middleware
        .process_request(
            HttpMethod::Post,
            "/api/public/webhook",
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
    println!("   POST to exempt path: {:?}", result);

    // POST without token
    let result = middleware
        .process_request(
            HttpMethod::Post,
            "/api/users",
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
    println!("   POST without token: {:?}", result);

    // Generate response additions
    let additions = middleware
        .process_response(Some("session-123".to_string()))
        .unwrap();
    println!("\n5. Response Additions:");
    println!("   Cookie: {}", additions.cookie_header);
    println!("   Hidden input: {}", additions.hidden_input);
    println!("   Meta tag: {}", additions.meta_tag);

    // POST with valid token
    let mut headers = HashMap::new();
    headers.insert("X-CSRF-Token".to_string(), additions.token_value.clone());

    let mut cookies = HashMap::new();
    cookies.insert("__csrf_token".to_string(), additions.token_value.clone());

    let result = middleware
        .process_request(
            HttpMethod::Post,
            "/api/users",
            &headers,
            &cookies,
            &HashMap::new(),
        )
        .unwrap();
    println!("\n   POST with valid token: {:?}", result);

    println!("\n=== CSRF Protection Complete ===");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_submit_valid() {
        let config = CsrfConfig {
            strategy: CsrfStrategy::DoubleSubmitCookie,
            ..Default::default()
        };
        let protection = CsrfProtection::new(config);
        let token = protection.generate_token(None).unwrap();

        let result = protection
            .validate_token(&token.value, Some(&token.value), None)
            .unwrap();
        assert_eq!(result, ValidationResult::Valid);
    }

    #[test]
    fn test_double_submit_mismatch() {
        let config = CsrfConfig {
            strategy: CsrfStrategy::DoubleSubmitCookie,
            ..Default::default()
        };
        let protection = CsrfProtection::new(config);
        let token = protection.generate_token(None).unwrap();

        let result = protection
            .validate_token("wrong-token", Some(&token.value), None)
            .unwrap();
        assert_eq!(
            result,
            ValidationResult::Invalid(InvalidReason::TokenMismatch)
        );
    }

    #[test]
    fn test_synchronizer_token_consumed() {
        let config = CsrfConfig {
            strategy: CsrfStrategy::SynchronizerToken,
            ..Default::default()
        };
        let protection = CsrfProtection::new(config);
        let token = protection.generate_token(None).unwrap();

        // First validation succeeds
        let result = protection.validate_token(&token.value, None, None).unwrap();
        assert_eq!(result, ValidationResult::Valid);

        // Second validation fails (consumed)
        let result = protection.validate_token(&token.value, None, None).unwrap();
        assert_eq!(
            result,
            ValidationResult::Invalid(InvalidReason::TokenNotFound)
        );
    }

    #[test]
    fn test_hmac_token_session_binding() {
        let config = CsrfConfig {
            strategy: CsrfStrategy::HmacToken,
            secret_key: b"test-secret-key".to_vec(),
            ..Default::default()
        };
        let protection = CsrfProtection::new(config);

        let session_id = "user-123";
        let token = protection
            .generate_token(Some(session_id.to_string()))
            .unwrap();

        // Correct session
        let result = protection
            .validate_token(&token.value, None, Some(session_id))
            .unwrap();
        assert_eq!(result, ValidationResult::Valid);

        // Wrong session
        let result = protection
            .validate_token(&token.value, None, Some("user-456"))
            .unwrap();
        assert_eq!(
            result,
            ValidationResult::Invalid(InvalidReason::InvalidSignature)
        );
    }

    #[test]
    fn test_method_exemption() {
        let config = CsrfConfig {
            exempt_methods: vec![HttpMethod::Get, HttpMethod::Head],
            ..Default::default()
        };
        let protection = CsrfProtection::new(config);

        assert!(protection.is_exempt(HttpMethod::Get, "/any/path"));
        assert!(protection.is_exempt(HttpMethod::Head, "/any/path"));
        assert!(!protection.is_exempt(HttpMethod::Post, "/any/path"));
    }

    #[test]
    fn test_path_exemption() {
        let config = CsrfConfig {
            exempt_paths: vec!["/api/public".to_string(), "/webhooks".to_string()],
            exempt_methods: vec![],
            ..Default::default()
        };
        let protection = CsrfProtection::new(config);

        assert!(protection.is_exempt(HttpMethod::Post, "/api/public"));
        assert!(protection.is_exempt(HttpMethod::Post, "/api/public/webhook"));
        assert!(protection.is_exempt(HttpMethod::Post, "/webhooks"));
        assert!(!protection.is_exempt(HttpMethod::Post, "/api/private"));
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("hello", "hello"));
        assert!(!constant_time_compare("hello", "world"));
        assert!(!constant_time_compare("hello", "hell"));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_token_expiration() {
        let token = CsrfToken {
            value: "test".to_string(),
            created_at: Instant::now() - Duration::from_secs(3700),
            expires_in: Duration::from_secs(3600),
            session_id: None,
            strategy: CsrfStrategy::DoubleSubmitCookie,
        };
        assert!(token.is_expired());
        assert!(token.remaining_validity().is_none());
    }

    #[test]
    fn test_cookie_header_generation() {
        let config = CsrfConfig::default();
        let protection = CsrfProtection::new(config);
        let token = protection.generate_token(None).unwrap();

        let header = protection.cookie_header(&token);
        assert!(header.contains("__csrf_token="));
        assert!(header.contains("SameSite=Strict"));
        assert!(header.contains("Secure"));
        assert!(header.contains("Path=/"));
    }

    #[test]
    fn test_hidden_input_generation() {
        let config = CsrfConfig::default();
        let protection = CsrfProtection::new(config);
        let token = protection.generate_token(None).unwrap();

        let input = protection.hidden_input(&token);
        assert!(input.contains("type=\"hidden\""));
        assert!(input.contains("name=\"csrf_token\""));
        assert!(input.contains(&token.value));
    }

    #[test]
    fn test_middleware_exempt_get() {
        let middleware = CsrfMiddleware::new(CsrfProtection::new(CsrfConfig::default()));

        let result = middleware
            .process_request(
                HttpMethod::Get,
                "/any/path",
                &HashMap::new(),
                &HashMap::new(),
                &HashMap::new(),
            )
            .unwrap();

        matches!(result, MiddlewareResult::Continue);
    }

    #[test]
    fn test_middleware_reject_missing_token() {
        let middleware = CsrfMiddleware::new(CsrfProtection::new(CsrfConfig::default()));

        let result = middleware
            .process_request(
                HttpMethod::Post,
                "/api/users",
                &HashMap::new(),
                &HashMap::new(),
                &HashMap::new(),
            )
            .unwrap();

        matches!(
            result,
            MiddlewareResult::Reject(InvalidReason::MissingHeader)
        );
    }
}
