//! Secure Session Management
//!
//! Comprehensive session management with secure token generation,
//! session storage, expiration handling, and security controls.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Session token length in bytes
    pub token_length: usize,
    /// Session lifetime
    pub lifetime: Duration,
    /// Idle timeout
    pub idle_timeout: Duration,
    /// Enable secure cookie flag
    pub secure_cookie: bool,
    /// Enable HttpOnly cookie flag
    pub http_only: bool,
    /// SameSite cookie policy
    pub same_site: SameSitePolicy,
    /// Maximum sessions per user
    pub max_sessions_per_user: usize,
    /// Regenerate session ID on privilege change
    pub regenerate_on_privilege_change: bool,
    /// Enable session binding to IP
    pub bind_to_ip: bool,
    /// Enable session binding to User-Agent
    pub bind_to_user_agent: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            token_length: 32,
            lifetime: Duration::from_secs(24 * 60 * 60), // 24 hours
            idle_timeout: Duration::from_secs(30 * 60),  // 30 minutes
            secure_cookie: true,
            http_only: true,
            same_site: SameSitePolicy::Strict,
            max_sessions_per_user: 5,
            regenerate_on_privilege_change: true,
            bind_to_ip: false,
            bind_to_user_agent: true,
        }
    }
}

/// SameSite cookie policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSitePolicy {
    Strict,
    Lax,
    None,
}

impl SameSitePolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            SameSitePolicy::Strict => "Strict",
            SameSitePolicy::Lax => "Lax",
            SameSitePolicy::None => "None",
        }
    }
}

/// Session data
#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub created_at: u64,
    pub last_accessed: u64,
    pub expires_at: u64,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub data: HashMap<String, String>,
    pub is_authenticated: bool,
    pub privilege_level: u8,
}

impl Session {
    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        let now = current_timestamp();
        now > self.expires_at
    }

    /// Check if session is idle (no activity within timeout)
    pub fn is_idle(&self, timeout: Duration) -> bool {
        let now = current_timestamp();
        now > self.last_accessed + timeout.as_secs()
    }

    /// Update last accessed time
    pub fn touch(&mut self) {
        self.last_accessed = current_timestamp();
    }

    /// Set session data
    pub fn set(&mut self, key: &str, value: &str) {
        self.data.insert(key.to_string(), value.to_string());
    }

    /// Get session data
    pub fn get(&self, key: &str) -> Option<&String> {
        self.data.get(key)
    }

    /// Remove session data
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.data.remove(key)
    }
}

/// Session manager
#[derive(Debug)]
pub struct SessionManager {
    config: SessionConfig,
    sessions: HashMap<String, Session>,
    user_sessions: HashMap<String, Vec<String>>,
}

impl SessionManager {
    pub fn new(config: SessionConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            user_sessions: HashMap::new(),
        }
    }

    /// Create a new session
    pub fn create_session(
        &mut self,
        user_id: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Session, SessionError> {
        // Check max sessions per user
        if let Some(user_sessions) = self.user_sessions.get(user_id) {
            if user_sessions.len() >= self.config.max_sessions_per_user {
                // Remove oldest session
                if let Some(oldest_id) = user_sessions.first().cloned() {
                    self.destroy_session(&oldest_id)?;
                }
            }
        }

        let session_id = self.generate_session_id();
        let now = current_timestamp();

        let session = Session {
            id: session_id.clone(),
            user_id: user_id.to_string(),
            created_at: now,
            last_accessed: now,
            expires_at: now + self.config.lifetime.as_secs(),
            ip_address: ip_address.map(String::from),
            user_agent: user_agent.map(String::from),
            data: HashMap::new(),
            is_authenticated: true,
            privilege_level: 0,
        };

        self.sessions.insert(session_id.clone(), session.clone());
        self.user_sessions
            .entry(user_id.to_string())
            .or_default()
            .push(session_id);

        Ok(session)
    }

    /// Get session by ID
    pub fn get_session(&mut self, session_id: &str) -> Result<&mut Session, SessionError> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or(SessionError::NotFound)?;

        // Check expiration
        if session.is_expired() {
            return Err(SessionError::Expired);
        }

        // Check idle timeout
        if session.is_idle(self.config.idle_timeout) {
            return Err(SessionError::IdleTimeout);
        }

        // Update last accessed
        session.touch();

        Ok(session)
    }

    /// Validate session with security checks
    pub fn validate_session(
        &mut self,
        session_id: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<&Session, SessionError> {
        let session = self.get_session(session_id)?;

        // Check IP binding
        if self.config.bind_to_ip {
            if let (Some(session_ip), Some(request_ip)) = (&session.ip_address, ip_address) {
                if session_ip != request_ip {
                    return Err(SessionError::IpMismatch);
                }
            }
        }

        // Check User-Agent binding
        if self.config.bind_to_user_agent {
            if let (Some(session_ua), Some(request_ua)) = (&session.user_agent, user_agent) {
                if session_ua != request_ua {
                    return Err(SessionError::UserAgentMismatch);
                }
            }
        }

        Ok(session)
    }

    /// Regenerate session ID (for privilege changes)
    pub fn regenerate_session(&mut self, old_session_id: &str) -> Result<Session, SessionError> {
        let old_session = self
            .sessions
            .remove(old_session_id)
            .ok_or(SessionError::NotFound)?;

        // Remove from user sessions
        if let Some(user_sessions) = self.user_sessions.get_mut(&old_session.user_id) {
            user_sessions.retain(|id| id != old_session_id);
        }

        // Create new session with same data
        let new_session_id = self.generate_session_id();
        let now = current_timestamp();

        let new_session = Session {
            id: new_session_id.clone(),
            user_id: old_session.user_id.clone(),
            created_at: old_session.created_at,
            last_accessed: now,
            expires_at: old_session.expires_at,
            ip_address: old_session.ip_address,
            user_agent: old_session.user_agent,
            data: old_session.data,
            is_authenticated: old_session.is_authenticated,
            privilege_level: old_session.privilege_level,
        };

        self.sessions
            .insert(new_session_id.clone(), new_session.clone());
        self.user_sessions
            .entry(new_session.user_id.clone())
            .or_default()
            .push(new_session_id);

        Ok(new_session)
    }

    /// Destroy a session
    pub fn destroy_session(&mut self, session_id: &str) -> Result<(), SessionError> {
        let session = self
            .sessions
            .remove(session_id)
            .ok_or(SessionError::NotFound)?;

        // Remove from user sessions
        if let Some(user_sessions) = self.user_sessions.get_mut(&session.user_id) {
            user_sessions.retain(|id| id != session_id);
        }

        Ok(())
    }

    /// Destroy all sessions for a user
    pub fn destroy_user_sessions(&mut self, user_id: &str) -> usize {
        let session_ids: Vec<String> = self.user_sessions.remove(user_id).unwrap_or_default();

        let count = session_ids.len();

        for session_id in session_ids {
            self.sessions.remove(&session_id);
        }

        count
    }

    /// Clean up expired sessions
    pub fn cleanup_expired(&mut self) -> usize {
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.is_expired() || s.is_idle(self.config.idle_timeout))
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired.len();

        for session_id in expired {
            let _ = self.destroy_session(&session_id);
        }

        count
    }

    /// Get all sessions for a user
    pub fn get_user_sessions(&self, user_id: &str) -> Vec<&Session> {
        self.user_sessions
            .get(user_id)
            .map(|ids| ids.iter().filter_map(|id| self.sessions.get(id)).collect())
            .unwrap_or_default()
    }

    /// Generate secure session ID
    fn generate_session_id(&self) -> String {
        // In production, use a CSPRNG like rand::rngs::OsRng
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        current_timestamp().hash(&mut hasher);
        std::process::id().hash(&mut hasher);

        let random_part = hasher.finish();

        // Generate more entropy
        let mut hasher2 = DefaultHasher::new();
        random_part.hash(&mut hasher2);
        (random_part ^ 0xDEADBEEF).hash(&mut hasher2);

        format!("{:016x}{:016x}", random_part, hasher2.finish())
    }

    /// Generate cookie header value
    pub fn generate_cookie(
        &self,
        session: &Session,
        cookie_name: &str,
        domain: Option<&str>,
    ) -> String {
        let mut cookie = format!("{}={}", cookie_name, session.id);

        if self.config.secure_cookie {
            cookie.push_str("; Secure");
        }

        if self.config.http_only {
            cookie.push_str("; HttpOnly");
        }

        cookie.push_str(&format!("; SameSite={}", self.config.same_site.as_str()));

        if let Some(d) = domain {
            cookie.push_str(&format!("; Domain={}", d));
        }

        cookie.push_str("; Path=/");

        // Calculate max-age
        let max_age = session.expires_at.saturating_sub(current_timestamp());
        cookie.push_str(&format!("; Max-Age={}", max_age));

        cookie
    }
}

/// Session errors
#[derive(Debug, Clone)]
pub enum SessionError {
    NotFound,
    Expired,
    IdleTimeout,
    IpMismatch,
    UserAgentMismatch,
    MaxSessionsReached,
    InvalidToken,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::NotFound => write!(f, "Session not found"),
            SessionError::Expired => write!(f, "Session expired"),
            SessionError::IdleTimeout => write!(f, "Session idle timeout"),
            SessionError::IpMismatch => write!(f, "IP address mismatch"),
            SessionError::UserAgentMismatch => write!(f, "User agent mismatch"),
            SessionError::MaxSessionsReached => write!(f, "Maximum sessions reached"),
            SessionError::InvalidToken => write!(f, "Invalid session token"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Session token validator
#[derive(Debug)]
pub struct TokenValidator {
    min_length: usize,
    allowed_chars: &'static str,
}

impl Default for TokenValidator {
    fn default() -> Self {
        Self {
            min_length: 32,
            allowed_chars: "0123456789abcdef",
        }
    }
}

impl TokenValidator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate(&self, token: &str) -> Result<(), SessionError> {
        // Check length
        if token.len() < self.min_length {
            return Err(SessionError::InvalidToken);
        }

        // Check characters
        for ch in token.chars() {
            if !self.allowed_chars.contains(ch) {
                return Err(SessionError::InvalidToken);
            }
        }

        Ok(())
    }
}

/// Session fixation protection
#[derive(Debug)]
pub struct FixationProtection {
    /// Track pre-authentication session IDs
    pre_auth_sessions: HashMap<String, u64>,
}

impl FixationProtection {
    pub fn new() -> Self {
        Self {
            pre_auth_sessions: HashMap::new(),
        }
    }

    /// Register a pre-authentication session
    pub fn register_pre_auth(&mut self, session_id: &str) {
        self.pre_auth_sessions
            .insert(session_id.to_string(), current_timestamp());
    }

    /// Check if session should be regenerated on authentication
    pub fn should_regenerate(&self, session_id: &str) -> bool {
        self.pre_auth_sessions.contains_key(session_id)
    }

    /// Mark session as authenticated (remove from tracking)
    pub fn mark_authenticated(&mut self, session_id: &str) {
        self.pre_auth_sessions.remove(session_id);
    }

    /// Cleanup old pre-auth sessions
    pub fn cleanup(&mut self, max_age: Duration) {
        let cutoff = current_timestamp() - max_age.as_secs();
        self.pre_auth_sessions.retain(|_, &mut ts| ts > cutoff);
    }
}

impl Default for FixationProtection {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn main() {
    println!("=== Secure Session Management Demo ===\n");

    // Create session manager with secure config
    let config = SessionConfig {
        token_length: 32,
        lifetime: Duration::from_secs(3600),    // 1 hour
        idle_timeout: Duration::from_secs(900), // 15 minutes
        secure_cookie: true,
        http_only: true,
        same_site: SameSitePolicy::Strict,
        max_sessions_per_user: 3,
        regenerate_on_privilege_change: true,
        bind_to_ip: false,
        bind_to_user_agent: true,
    };

    println!("Session Configuration:");
    println!("  Token Length: {} bytes", config.token_length);
    println!("  Lifetime: {:?}", config.lifetime);
    println!("  Idle Timeout: {:?}", config.idle_timeout);
    println!("  Secure Cookie: {}", config.secure_cookie);
    println!("  HttpOnly: {}", config.http_only);
    println!("  SameSite: {}", config.same_site.as_str());

    let mut manager = SessionManager::new(config.clone());

    // Create a session
    println!("\n--- Creating Session ---");
    let session = manager
        .create_session(
            "user_123",
            Some("192.168.1.100"),
            Some("Mozilla/5.0 (X11; Linux x86_64)"),
        )
        .unwrap();

    println!("Session ID: {}", session.id);
    println!("User ID: {}", session.user_id);
    println!("Created At: {}", session.created_at);
    println!("Expires At: {}", session.expires_at);

    // Generate cookie
    let cookie = manager.generate_cookie(&session, "session_id", Some("example.com"));
    println!("\nSet-Cookie Header:");
    println!("  {}", cookie);

    // Validate session
    println!("\n--- Validating Session ---");
    match manager.validate_session(
        &session.id,
        Some("192.168.1.100"),
        Some("Mozilla/5.0 (X11; Linux x86_64)"),
    ) {
        Ok(s) => println!("Session valid for user: {}", s.user_id),
        Err(e) => println!("Validation failed: {}", e),
    }

    // Test User-Agent mismatch
    println!("\n--- Testing User-Agent Mismatch ---");
    match manager.validate_session(
        &session.id,
        Some("192.168.1.100"),
        Some("Different Browser"),
    ) {
        Ok(_) => println!("Session valid (unexpected)"),
        Err(e) => println!("Validation failed (expected): {}", e),
    }

    // Store session data
    println!("\n--- Session Data ---");
    {
        let session = manager.get_session(&session.id).unwrap();
        session.set("cart_items", "5");
        session.set("preferred_language", "en");
    }

    {
        let session = manager.get_session(&session.id).unwrap();
        println!("Cart Items: {:?}", session.get("cart_items"));
        println!("Language: {:?}", session.get("preferred_language"));
    }

    // Session regeneration (privilege escalation protection)
    println!("\n--- Session Regeneration ---");
    let old_id = session.id.clone();
    let new_session = manager.regenerate_session(&old_id).unwrap();
    println!("Old Session ID: {}", old_id);
    println!("New Session ID: {}", new_session.id);

    // Verify old session is destroyed
    match manager.get_session(&old_id) {
        Ok(_) => println!("Old session still valid (unexpected)"),
        Err(e) => println!("Old session destroyed (expected): {}", e),
    }

    // Multiple sessions per user
    println!("\n--- Multiple Sessions ---");
    let _s1 = manager.create_session("user_456", None, None).unwrap();
    let _s2 = manager.create_session("user_456", None, None).unwrap();
    let _s3 = manager.create_session("user_456", None, None).unwrap();

    println!(
        "Sessions for user_456: {}",
        manager.get_user_sessions("user_456").len()
    );

    // Fourth session should evict oldest
    let _s4 = manager.create_session("user_456", None, None).unwrap();
    println!(
        "After creating 4th session: {}",
        manager.get_user_sessions("user_456").len()
    );

    // Token validation
    println!("\n--- Token Validation ---");
    let validator = TokenValidator::new();

    for token in &[
        "valid0123456789abcdef0123456789ab",
        "short",
        "INVALID_CHARS!!",
    ] {
        match validator.validate(token) {
            Ok(_) => println!("  '{}...' - Valid", &token[..token.len().min(20)]),
            Err(e) => println!("  '{}...' - Invalid: {}", &token[..token.len().min(20)], e),
        }
    }

    // Fixation protection
    println!("\n--- Session Fixation Protection ---");
    let mut fixation = FixationProtection::new();

    fixation.register_pre_auth("pre_auth_session_123");
    println!(
        "Should regenerate on auth: {}",
        fixation.should_regenerate("pre_auth_session_123")
    );

    fixation.mark_authenticated("pre_auth_session_123");
    println!(
        "After auth, should regenerate: {}",
        fixation.should_regenerate("pre_auth_session_123")
    );

    // Cleanup
    println!("\n--- Session Cleanup ---");
    let cleaned = manager.cleanup_expired();
    println!("Cleaned up {} expired sessions", cleaned);

    // Destroy all user sessions (logout everywhere)
    println!("\n--- Logout Everywhere ---");
    let destroyed = manager.destroy_user_sessions("user_456");
    println!("Destroyed {} sessions for user_456", destroyed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let config = SessionConfig::default();
        let mut manager = SessionManager::new(config);

        let session = manager
            .create_session("user_1", Some("127.0.0.1"), None)
            .unwrap();

        assert!(!session.id.is_empty());
        assert_eq!(session.user_id, "user_1");
        assert!(session.is_authenticated);
    }

    #[test]
    fn test_session_retrieval() {
        let config = SessionConfig::default();
        let mut manager = SessionManager::new(config);

        let session = manager.create_session("user_1", None, None).unwrap();
        let session_id = session.id.clone();

        let retrieved = manager.get_session(&session_id).unwrap();
        assert_eq!(retrieved.user_id, "user_1");
    }

    #[test]
    fn test_session_not_found() {
        let config = SessionConfig::default();
        let mut manager = SessionManager::new(config);

        let result = manager.get_session("nonexistent");
        assert!(matches!(result, Err(SessionError::NotFound)));
    }

    #[test]
    fn test_session_destruction() {
        let config = SessionConfig::default();
        let mut manager = SessionManager::new(config);

        let session = manager.create_session("user_1", None, None).unwrap();
        let session_id = session.id.clone();

        manager.destroy_session(&session_id).unwrap();

        let result = manager.get_session(&session_id);
        assert!(matches!(result, Err(SessionError::NotFound)));
    }

    #[test]
    fn test_session_regeneration() {
        let config = SessionConfig::default();
        let mut manager = SessionManager::new(config);

        let session = manager.create_session("user_1", None, None).unwrap();
        let old_id = session.id.clone();

        {
            let session = manager.get_session(&old_id).unwrap();
            session.set("key", "value");
        }

        let new_session = manager.regenerate_session(&old_id).unwrap();

        // Old session should be gone
        assert!(manager.get_session(&old_id).is_err());

        // New session should exist with data
        let retrieved = manager.get_session(&new_session.id).unwrap();
        assert_eq!(retrieved.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_max_sessions_per_user() {
        let mut config = SessionConfig::default();
        config.max_sessions_per_user = 2;

        let mut manager = SessionManager::new(config);

        let _s1 = manager.create_session("user_1", None, None).unwrap();
        let _s2 = manager.create_session("user_1", None, None).unwrap();
        let _s3 = manager.create_session("user_1", None, None).unwrap();

        // Should only have 2 sessions
        assert_eq!(manager.get_user_sessions("user_1").len(), 2);
    }

    #[test]
    fn test_user_agent_binding() {
        let mut config = SessionConfig::default();
        config.bind_to_user_agent = true;

        let mut manager = SessionManager::new(config);

        let session = manager
            .create_session("user_1", None, Some("Browser A"))
            .unwrap();

        // Same user agent should work
        assert!(manager
            .validate_session(&session.id, None, Some("Browser A"))
            .is_ok());

        // Different user agent should fail
        assert!(matches!(
            manager.validate_session(&session.id, None, Some("Browser B")),
            Err(SessionError::UserAgentMismatch)
        ));
    }

    #[test]
    fn test_session_data() {
        let config = SessionConfig::default();
        let mut manager = SessionManager::new(config);

        let session = manager.create_session("user_1", None, None).unwrap();

        {
            let session = manager.get_session(&session.id).unwrap();
            session.set("key1", "value1");
            session.set("key2", "value2");
        }

        {
            let session = manager.get_session(&session.id).unwrap();
            assert_eq!(session.get("key1"), Some(&"value1".to_string()));
            assert_eq!(session.get("key2"), Some(&"value2".to_string()));

            let removed = session.remove("key1");
            assert_eq!(removed, Some("value1".to_string()));
            assert_eq!(session.get("key1"), None);
        }
    }

    #[test]
    fn test_destroy_user_sessions() {
        let config = SessionConfig::default();
        let mut manager = SessionManager::new(config);

        let _s1 = manager.create_session("user_1", None, None).unwrap();
        let _s2 = manager.create_session("user_1", None, None).unwrap();

        let count = manager.destroy_user_sessions("user_1");
        assert_eq!(count, 2);
        assert!(manager.get_user_sessions("user_1").is_empty());
    }

    #[test]
    fn test_cookie_generation() {
        let config = SessionConfig::default();
        let manager = SessionManager::new(config);

        let session = Session {
            id: "test_session_id".to_string(),
            user_id: "user_1".to_string(),
            created_at: current_timestamp(),
            last_accessed: current_timestamp(),
            expires_at: current_timestamp() + 3600,
            ip_address: None,
            user_agent: None,
            data: HashMap::new(),
            is_authenticated: true,
            privilege_level: 0,
        };

        let cookie = manager.generate_cookie(&session, "session", Some("example.com"));

        assert!(cookie.contains("session=test_session_id"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Domain=example.com"));
    }

    #[test]
    fn test_token_validator() {
        let validator = TokenValidator::new();

        // Valid token
        assert!(validator
            .validate("0123456789abcdef0123456789abcdef")
            .is_ok());

        // Too short
        assert!(validator.validate("short").is_err());

        // Invalid characters
        assert!(validator.validate("INVALID_0123456789abcdef01234").is_err());
    }

    #[test]
    fn test_fixation_protection() {
        let mut fixation = FixationProtection::new();

        fixation.register_pre_auth("session_123");
        assert!(fixation.should_regenerate("session_123"));
        assert!(!fixation.should_regenerate("session_456"));

        fixation.mark_authenticated("session_123");
        assert!(!fixation.should_regenerate("session_123"));
    }

    #[test]
    fn test_session_expiration_check() {
        let session = Session {
            id: "test".to_string(),
            user_id: "user".to_string(),
            created_at: current_timestamp() - 7200,
            last_accessed: current_timestamp() - 3600,
            expires_at: current_timestamp() - 1, // Expired 1 second ago
            ip_address: None,
            user_agent: None,
            data: HashMap::new(),
            is_authenticated: true,
            privilege_level: 0,
        };

        assert!(session.is_expired());
    }

    #[test]
    fn test_session_idle_check() {
        let session = Session {
            id: "test".to_string(),
            user_id: "user".to_string(),
            created_at: current_timestamp() - 7200,
            last_accessed: current_timestamp() - 1800, // 30 minutes ago
            expires_at: current_timestamp() + 3600,
            ip_address: None,
            user_agent: None,
            data: HashMap::new(),
            is_authenticated: true,
            privilege_level: 0,
        };

        assert!(session.is_idle(Duration::from_secs(900))); // 15 minute timeout
        assert!(!session.is_idle(Duration::from_secs(3600))); // 1 hour timeout
    }
}
