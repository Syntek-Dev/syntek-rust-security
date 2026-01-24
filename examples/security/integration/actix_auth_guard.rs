//! Actix Web Authentication Guard Example
//!
//! Demonstrates implementing authentication and authorization guards
//! for Actix Web applications with JWT and session-based auth.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// JWT claims structure
#[derive(Debug, Clone)]
pub struct Claims {
    pub sub: String, // Subject (user ID)
    pub exp: u64,    // Expiration time
    pub iat: u64,    // Issued at
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

impl Claims {
    pub fn new(user_id: &str, roles: Vec<String>, ttl: Duration) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            sub: user_id.to_string(),
            exp: now + ttl.as_secs(),
            iat: now,
            roles,
            permissions: Vec::new(),
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.exp < now
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission)
    }

    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|r| self.has_role(r))
    }
}

/// JWT validator with signature verification
pub struct JwtValidator {
    secret: Vec<u8>,
    issuer: Option<String>,
    audience: Option<String>,
    leeway_secs: u64,
}

impl JwtValidator {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
            issuer: None,
            audience: None,
            leeway_secs: 60,
        }
    }

    pub fn with_issuer(mut self, issuer: &str) -> Self {
        self.issuer = Some(issuer.to_string());
        self
    }

    pub fn with_audience(mut self, audience: &str) -> Self {
        self.audience = Some(audience.to_string());
        self
    }

    pub fn with_leeway(mut self, secs: u64) -> Self {
        self.leeway_secs = secs;
        self
    }

    /// Validate JWT token (simplified - real implementation would use proper JWT library)
    pub fn validate(&self, token: &str) -> Result<Claims, AuthError> {
        // Check token format
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::InvalidToken("Invalid JWT format".to_string()));
        }

        // In real implementation: decode and verify signature using HMAC-SHA256
        // This is a simplified demonstration

        // Simulate decoded claims
        let claims = Claims {
            sub: "user123".to_string(),
            exp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            iat: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            roles: vec!["user".to_string()],
            permissions: vec!["read".to_string()],
        };

        // Check expiration with leeway
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if claims.exp + self.leeway_secs < now {
            return Err(AuthError::TokenExpired);
        }

        Ok(claims)
    }
}

/// Role-based access control
#[derive(Debug, Clone)]
pub struct RbacPolicy {
    roles: HashMap<String, HashSet<String>>, // role -> permissions
    role_hierarchy: HashMap<String, Vec<String>>, // role -> parent roles
}

impl Default for RbacPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl RbacPolicy {
    pub fn new() -> Self {
        Self {
            roles: HashMap::new(),
            role_hierarchy: HashMap::new(),
        }
    }

    pub fn add_role(&mut self, role: &str, permissions: Vec<&str>) -> &mut Self {
        self.roles.insert(
            role.to_string(),
            permissions.iter().map(|p| p.to_string()).collect(),
        );
        self
    }

    pub fn set_role_parent(&mut self, role: &str, parent: &str) -> &mut Self {
        self.role_hierarchy
            .entry(role.to_string())
            .or_default()
            .push(parent.to_string());
        self
    }

    pub fn get_permissions(&self, role: &str) -> HashSet<String> {
        let mut permissions = HashSet::new();

        // Direct permissions
        if let Some(perms) = self.roles.get(role) {
            permissions.extend(perms.clone());
        }

        // Inherited permissions
        if let Some(parents) = self.role_hierarchy.get(role) {
            for parent in parents {
                permissions.extend(self.get_permissions(parent));
            }
        }

        permissions
    }

    pub fn check_permission(&self, claims: &Claims, required: &str) -> bool {
        // Check direct permissions in claims
        if claims.has_permission(required) {
            return true;
        }

        // Check permissions from roles
        for role in &claims.roles {
            let perms = self.get_permissions(role);
            if perms.contains(required) {
                return true;
            }
        }

        false
    }
}

/// Authentication guard for route protection
pub struct AuthGuard {
    validator: JwtValidator,
    required_roles: Vec<String>,
    required_permissions: Vec<String>,
    rbac: Option<RbacPolicy>,
}

impl AuthGuard {
    pub fn new(validator: JwtValidator) -> Self {
        Self {
            validator,
            required_roles: Vec::new(),
            required_permissions: Vec::new(),
            rbac: None,
        }
    }

    pub fn require_role(mut self, role: &str) -> Self {
        self.required_roles.push(role.to_string());
        self
    }

    pub fn require_permission(mut self, permission: &str) -> Self {
        self.required_permissions.push(permission.to_string());
        self
    }

    pub fn with_rbac(mut self, rbac: RbacPolicy) -> Self {
        self.rbac = Some(rbac);
        self
    }

    /// Check authorization from request
    pub fn check(&self, auth_header: Option<&str>) -> Result<Claims, AuthError> {
        // Extract token from Authorization header
        let token = auth_header
            .ok_or(AuthError::MissingToken)?
            .strip_prefix("Bearer ")
            .ok_or(AuthError::InvalidToken("Missing Bearer prefix".to_string()))?;

        // Validate token
        let claims = self.validator.validate(token)?;

        // Check required roles
        if !self.required_roles.is_empty() {
            let role_strs: Vec<&str> = self.required_roles.iter().map(|s| s.as_str()).collect();
            if !claims.has_any_role(&role_strs) {
                return Err(AuthError::InsufficientRole);
            }
        }

        // Check required permissions
        for permission in &self.required_permissions {
            let has_perm = if let Some(ref rbac) = self.rbac {
                rbac.check_permission(&claims, permission)
            } else {
                claims.has_permission(permission)
            };

            if !has_perm {
                return Err(AuthError::InsufficientPermission(permission.clone()));
            }
        }

        Ok(claims)
    }
}

/// Session-based authentication
pub struct SessionStore {
    sessions: HashMap<String, SessionData>,
    ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct SessionData {
    pub user_id: String,
    pub roles: Vec<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            ttl,
        }
    }

    pub fn create_session(&mut self, user_id: &str, roles: Vec<String>) -> String {
        let session_id = generate_session_id();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.sessions.insert(
            session_id.clone(),
            SessionData {
                user_id: user_id.to_string(),
                roles,
                created_at: now,
                expires_at: now + self.ttl.as_secs(),
                ip_address: None,
                user_agent: None,
            },
        );

        session_id
    }

    pub fn get_session(&self, session_id: &str) -> Option<&SessionData> {
        let session = self.sessions.get(session_id)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if session.expires_at < now {
            return None;
        }

        Some(session)
    }

    pub fn invalidate(&mut self, session_id: &str) -> bool {
        self.sessions.remove(session_id).is_some()
    }

    pub fn invalidate_user_sessions(&mut self, user_id: &str) {
        self.sessions.retain(|_, data| data.user_id != user_id);
    }

    pub fn cleanup_expired(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.sessions.retain(|_, data| data.expires_at > now);
    }
}

fn generate_session_id() -> String {
    // In production, use cryptographically secure random
    format!("sess_{:016x}", rand_u64())
}

fn rand_u64() -> u64 {
    // Simplified - use proper random in production
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

#[derive(Debug)]
pub enum AuthError {
    MissingToken,
    InvalidToken(String),
    TokenExpired,
    InsufficientRole,
    InsufficientPermission(String),
    SessionNotFound,
    SessionExpired,
}

fn main() {
    println!("Actix Web Authentication Guard Example");
    println!("=======================================\n");

    // Create JWT validator
    let validator = JwtValidator::new(b"super_secret_key_32_bytes_long!!")
        .with_issuer("my-app")
        .with_audience("my-api")
        .with_leeway(60);

    // Create RBAC policy
    let mut rbac = RbacPolicy::new();
    rbac.add_role("admin", vec!["read", "write", "delete", "manage_users"])
        .add_role("editor", vec!["read", "write"])
        .add_role("viewer", vec!["read"])
        .set_role_parent("admin", "editor")
        .set_role_parent("editor", "viewer");

    // Create auth guard
    let guard = AuthGuard::new(validator)
        .require_role("editor")
        .require_permission("write")
        .with_rbac(rbac.clone());

    // Test authentication
    println!("Testing JWT Authentication:");
    println!("---------------------------");

    // Valid token
    let valid_header =
        Some("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature");
    match guard.check(valid_header) {
        Ok(claims) => println!(
            "  Valid token - User: {}, Roles: {:?}",
            claims.sub, claims.roles
        ),
        Err(e) => println!("  Auth failed: {:?}", e),
    }

    // Missing token
    match guard.check(None) {
        Ok(_) => println!("  Unexpected success"),
        Err(e) => println!("  Missing token: {:?}", e),
    }

    // Invalid format
    match guard.check(Some("InvalidToken")) {
        Ok(_) => println!("  Unexpected success"),
        Err(e) => println!("  Invalid format: {:?}", e),
    }

    // Test RBAC
    println!("\nRBAC Permission Check:");
    println!("-----------------------");

    let admin_claims = Claims {
        sub: "admin_user".to_string(),
        exp: u64::MAX,
        iat: 0,
        roles: vec!["admin".to_string()],
        permissions: vec![],
    };

    let viewer_claims = Claims {
        sub: "viewer_user".to_string(),
        exp: u64::MAX,
        iat: 0,
        roles: vec!["viewer".to_string()],
        permissions: vec![],
    };

    for perm in ["read", "write", "delete", "manage_users"] {
        let admin_has = rbac.check_permission(&admin_claims, perm);
        let viewer_has = rbac.check_permission(&viewer_claims, perm);
        println!("  {} - Admin: {}, Viewer: {}", perm, admin_has, viewer_has);
    }

    // Test session store
    println!("\nSession Management:");
    println!("-------------------");

    let mut sessions = SessionStore::new(Duration::from_secs(3600));

    let session_id = sessions.create_session("user123", vec!["user".to_string()]);
    println!("  Created session: {}", session_id);

    if let Some(session) = sessions.get_session(&session_id) {
        println!("  Session user: {}", session.user_id);
        println!("  Session roles: {:?}", session.roles);
    }

    sessions.invalidate(&session_id);
    println!("  Session invalidated");

    if sessions.get_session(&session_id).is_none() {
        println!("  Session not found (as expected)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claims_creation() {
        let claims = Claims::new(
            "user123",
            vec!["admin".to_string()],
            Duration::from_secs(3600),
        );

        assert_eq!(claims.sub, "user123");
        assert!(claims.has_role("admin"));
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_claims_expired() {
        let claims = Claims {
            sub: "user".to_string(),
            exp: 0, // Expired
            iat: 0,
            roles: vec![],
            permissions: vec![],
        };

        assert!(claims.is_expired());
    }

    #[test]
    fn test_claims_has_any_role() {
        let claims = Claims {
            sub: "user".to_string(),
            exp: u64::MAX,
            iat: 0,
            roles: vec!["editor".to_string()],
            permissions: vec![],
        };

        assert!(claims.has_any_role(&["admin", "editor"]));
        assert!(!claims.has_any_role(&["admin", "superuser"]));
    }

    #[test]
    fn test_rbac_direct_permissions() {
        let mut rbac = RbacPolicy::new();
        rbac.add_role("editor", vec!["read", "write"]);

        let perms = rbac.get_permissions("editor");
        assert!(perms.contains("read"));
        assert!(perms.contains("write"));
        assert!(!perms.contains("delete"));
    }

    #[test]
    fn test_rbac_inherited_permissions() {
        let mut rbac = RbacPolicy::new();
        rbac.add_role("viewer", vec!["read"])
            .add_role("editor", vec!["write"])
            .set_role_parent("editor", "viewer");

        let perms = rbac.get_permissions("editor");
        assert!(perms.contains("read")); // Inherited
        assert!(perms.contains("write")); // Direct
    }

    #[test]
    fn test_rbac_check_permission() {
        let mut rbac = RbacPolicy::new();
        rbac.add_role("admin", vec!["manage"]);

        let claims = Claims {
            sub: "admin_user".to_string(),
            exp: u64::MAX,
            iat: 0,
            roles: vec!["admin".to_string()],
            permissions: vec![],
        };

        assert!(rbac.check_permission(&claims, "manage"));
        assert!(!rbac.check_permission(&claims, "superadmin"));
    }

    #[test]
    fn test_auth_guard_missing_token() {
        let validator = JwtValidator::new(b"secret");
        let guard = AuthGuard::new(validator);

        assert!(matches!(guard.check(None), Err(AuthError::MissingToken)));
    }

    #[test]
    fn test_auth_guard_invalid_format() {
        let validator = JwtValidator::new(b"secret");
        let guard = AuthGuard::new(validator);

        assert!(matches!(
            guard.check(Some("NoBearer token")),
            Err(AuthError::InvalidToken(_))
        ));
    }

    #[test]
    fn test_session_store() {
        let mut store = SessionStore::new(Duration::from_secs(3600));

        let session_id = store.create_session("user1", vec!["user".to_string()]);
        assert!(store.get_session(&session_id).is_some());

        store.invalidate(&session_id);
        assert!(store.get_session(&session_id).is_none());
    }

    #[test]
    fn test_session_invalidate_user() {
        let mut store = SessionStore::new(Duration::from_secs(3600));

        let s1 = store.create_session("user1", vec![]);
        let s2 = store.create_session("user1", vec![]);
        let s3 = store.create_session("user2", vec![]);

        store.invalidate_user_sessions("user1");

        assert!(store.get_session(&s1).is_none());
        assert!(store.get_session(&s2).is_none());
        assert!(store.get_session(&s3).is_some());
    }

    #[test]
    fn test_jwt_validator_format() {
        let validator = JwtValidator::new(b"secret");

        // Invalid format
        assert!(matches!(
            validator.validate("not.valid"),
            Err(AuthError::InvalidToken(_))
        ));
    }
}
