//! GraphQL Security Middleware
//!
//! Provides secure resolver patterns for async-graphql with:
//! - Query depth limiting
//! - Query complexity analysis
//! - Field-level authorization
//! - Input validation and sanitization
//! - Rate limiting per operation

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// ============================================================================
// Security Context
// ============================================================================

/// User role for authorization
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Role {
    Anonymous,
    User,
    Admin,
    SuperAdmin,
}

impl Role {
    fn level(&self) -> u8 {
        match self {
            Role::Anonymous => 0,
            Role::User => 1,
            Role::Admin => 2,
            Role::SuperAdmin => 3,
        }
    }

    fn has_permission(&self, required: &Role) -> bool {
        self.level() >= required.level()
    }
}

/// Security context passed through resolvers
#[derive(Debug, Clone)]
pub struct SecurityContext {
    pub user_id: Option<String>,
    pub role: Role,
    pub permissions: Vec<String>,
    pub ip_address: String,
    pub request_id: String,
}

impl SecurityContext {
    pub fn anonymous(ip: &str, request_id: &str) -> Self {
        Self {
            user_id: None,
            role: Role::Anonymous,
            permissions: vec![],
            ip_address: ip.to_string(),
            request_id: request_id.to_string(),
        }
    }

    pub fn authenticated(
        user_id: &str,
        role: Role,
        permissions: Vec<String>,
        ip: &str,
        request_id: &str,
    ) -> Self {
        Self {
            user_id: Some(user_id.to_string()),
            role,
            permissions,
            ip_address: ip.to_string(),
            request_id: request_id.to_string(),
        }
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission || p == "*")
    }
}

// ============================================================================
// Query Complexity Analysis
// ============================================================================

/// Query complexity configuration
#[derive(Debug, Clone)]
pub struct ComplexityConfig {
    /// Maximum allowed query depth
    pub max_depth: usize,
    /// Maximum total complexity score
    pub max_complexity: u64,
    /// Default complexity per field
    pub default_field_complexity: u64,
    /// Complexity multiplier for list fields
    pub list_multiplier: u64,
}

impl Default for ComplexityConfig {
    fn default() -> Self {
        Self {
            max_depth: 10,
            max_complexity: 1000,
            default_field_complexity: 1,
            list_multiplier: 10,
        }
    }
}

/// Field complexity metadata
#[derive(Debug, Clone)]
pub struct FieldComplexity {
    pub base_cost: u64,
    pub is_list: bool,
    pub requires_auth: bool,
    pub minimum_role: Role,
}

impl Default for FieldComplexity {
    fn default() -> Self {
        Self {
            base_cost: 1,
            is_list: false,
            requires_auth: false,
            minimum_role: Role::Anonymous,
        }
    }
}

/// Analyzes GraphQL query complexity
pub struct ComplexityAnalyzer {
    config: ComplexityConfig,
    field_costs: HashMap<String, FieldComplexity>,
}

impl ComplexityAnalyzer {
    pub fn new(config: ComplexityConfig) -> Self {
        Self {
            config,
            field_costs: HashMap::new(),
        }
    }

    pub fn register_field(
        &mut self,
        type_name: &str,
        field_name: &str,
        complexity: FieldComplexity,
    ) {
        let key = format!("{}.{}", type_name, field_name);
        self.field_costs.insert(key, complexity);
    }

    /// Analyze a parsed query AST (simplified representation)
    pub fn analyze(&self, query: &QueryNode) -> Result<ComplexityResult, ComplexityError> {
        let mut result = ComplexityResult::default();
        self.analyze_node(query, 0, &mut result)?;

        if result.depth > self.config.max_depth {
            return Err(ComplexityError::DepthExceeded {
                max: self.config.max_depth,
                actual: result.depth,
            });
        }

        if result.total_complexity > self.config.max_complexity {
            return Err(ComplexityError::ComplexityExceeded {
                max: self.config.max_complexity,
                actual: result.total_complexity,
            });
        }

        Ok(result)
    }

    fn analyze_node(
        &self,
        node: &QueryNode,
        depth: usize,
        result: &mut ComplexityResult,
    ) -> Result<(), ComplexityError> {
        result.depth = result.depth.max(depth);
        result.field_count += 1;

        let key = format!("{}.{}", node.type_name, node.field_name);
        let complexity = self
            .field_costs
            .get(&key)
            .cloned()
            .unwrap_or_else(|| FieldComplexity {
                base_cost: self.config.default_field_complexity,
                ..Default::default()
            });

        let mut cost = complexity.base_cost;
        if complexity.is_list {
            let limit = node
                .arguments
                .get("limit")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(self.config.list_multiplier);
            cost *= limit.min(100); // Cap multiplier
        }

        result.total_complexity += cost;
        result.field_complexities.push((key, cost));

        for child in &node.children {
            self.analyze_node(child, depth + 1, result)?;
        }

        Ok(())
    }
}

/// Simplified query node representation
#[derive(Debug, Clone)]
pub struct QueryNode {
    pub type_name: String,
    pub field_name: String,
    pub arguments: HashMap<String, String>,
    pub children: Vec<QueryNode>,
}

#[derive(Debug, Default)]
pub struct ComplexityResult {
    pub depth: usize,
    pub total_complexity: u64,
    pub field_count: usize,
    pub field_complexities: Vec<(String, u64)>,
}

#[derive(Debug)]
pub enum ComplexityError {
    DepthExceeded { max: usize, actual: usize },
    ComplexityExceeded { max: u64, actual: u64 },
}

impl std::fmt::Display for ComplexityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DepthExceeded { max, actual } => {
                write!(f, "Query depth {} exceeds maximum allowed {}", actual, max)
            }
            Self::ComplexityExceeded { max, actual } => {
                write!(
                    f,
                    "Query complexity {} exceeds maximum allowed {}",
                    actual, max
                )
            }
        }
    }
}

// ============================================================================
// Field-Level Authorization
// ============================================================================

/// Authorization rule for a field
#[derive(Debug, Clone)]
pub struct AuthRule {
    pub minimum_role: Role,
    pub required_permissions: Vec<String>,
    pub owner_field: Option<String>,
    pub custom_check: Option<String>,
}

impl AuthRule {
    pub fn public() -> Self {
        Self {
            minimum_role: Role::Anonymous,
            required_permissions: vec![],
            owner_field: None,
            custom_check: None,
        }
    }

    pub fn authenticated() -> Self {
        Self {
            minimum_role: Role::User,
            required_permissions: vec![],
            owner_field: None,
            custom_check: None,
        }
    }

    pub fn admin() -> Self {
        Self {
            minimum_role: Role::Admin,
            required_permissions: vec![],
            owner_field: None,
            custom_check: None,
        }
    }

    pub fn with_permission(mut self, permission: &str) -> Self {
        self.required_permissions.push(permission.to_string());
        self
    }

    pub fn owner_only(mut self, owner_field: &str) -> Self {
        self.owner_field = Some(owner_field.to_string());
        self
    }
}

/// Authorization checker
pub struct Authorizer {
    rules: HashMap<String, AuthRule>,
}

impl Authorizer {
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
        }
    }

    pub fn register_rule(&mut self, type_name: &str, field_name: &str, rule: AuthRule) {
        let key = format!("{}.{}", type_name, field_name);
        self.rules.insert(key, rule);
    }

    pub fn check(
        &self,
        ctx: &SecurityContext,
        type_name: &str,
        field_name: &str,
        object_owner_id: Option<&str>,
    ) -> Result<(), AuthError> {
        let key = format!("{}.{}", type_name, field_name);
        let rule = self
            .rules
            .get(&key)
            .cloned()
            .unwrap_or_else(AuthRule::public);

        // Check role
        if !ctx.role.has_permission(&rule.minimum_role) {
            return Err(AuthError::InsufficientRole {
                field: key,
                required: rule.minimum_role,
                actual: ctx.role.clone(),
            });
        }

        // Check permissions
        for permission in &rule.required_permissions {
            if !ctx.has_permission(permission) {
                return Err(AuthError::MissingPermission {
                    field: key,
                    permission: permission.clone(),
                });
            }
        }

        // Check ownership
        if let Some(owner_field) = &rule.owner_field {
            if let Some(owner_id) = object_owner_id {
                if ctx.user_id.as_deref() != Some(owner_id) && ctx.role != Role::SuperAdmin {
                    return Err(AuthError::NotOwner {
                        field: key,
                        owner_field: owner_field.clone(),
                    });
                }
            }
        }

        Ok(())
    }
}

impl Default for Authorizer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum AuthError {
    InsufficientRole {
        field: String,
        required: Role,
        actual: Role,
    },
    MissingPermission {
        field: String,
        permission: String,
    },
    NotOwner {
        field: String,
        owner_field: String,
    },
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientRole {
                field,
                required,
                actual,
            } => {
                write!(
                    f,
                    "Insufficient role for {}: required {:?}, have {:?}",
                    field, required, actual
                )
            }
            Self::MissingPermission { field, permission } => {
                write!(f, "Missing permission '{}' for field {}", permission, field)
            }
            Self::NotOwner { field, owner_field } => {
                write!(f, "Must be owner ({}) to access {}", owner_field, field)
            }
        }
    }
}

// ============================================================================
// Input Validation
// ============================================================================

/// Input validation rules
#[derive(Debug, Clone)]
pub struct ValidationRule {
    pub max_length: Option<usize>,
    pub min_length: Option<usize>,
    pub pattern: Option<String>,
    pub sanitize: bool,
    pub allowed_values: Option<Vec<String>>,
}

impl ValidationRule {
    pub fn string() -> Self {
        Self {
            max_length: Some(1000),
            min_length: None,
            pattern: None,
            sanitize: true,
            allowed_values: None,
        }
    }

    pub fn email() -> Self {
        Self {
            max_length: Some(254),
            min_length: Some(5),
            pattern: Some(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$".to_string()),
            sanitize: false,
            allowed_values: None,
        }
    }

    pub fn id() -> Self {
        Self {
            max_length: Some(36),
            min_length: Some(1),
            pattern: Some(r"^[a-zA-Z0-9_-]+$".to_string()),
            sanitize: false,
            allowed_values: None,
        }
    }

    pub fn max_length(mut self, len: usize) -> Self {
        self.max_length = Some(len);
        self
    }

    pub fn min_length(mut self, len: usize) -> Self {
        self.min_length = Some(len);
        self
    }
}

/// Input validator
pub struct InputValidator {
    rules: HashMap<String, ValidationRule>,
}

impl InputValidator {
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
        }
    }

    pub fn register_rule(&mut self, input_name: &str, field_name: &str, rule: ValidationRule) {
        let key = format!("{}.{}", input_name, field_name);
        self.rules.insert(key, rule);
    }

    pub fn validate(
        &self,
        input_name: &str,
        field_name: &str,
        value: &str,
    ) -> Result<String, ValidationError> {
        let key = format!("{}.{}", input_name, field_name);
        let rule = self
            .rules
            .get(&key)
            .cloned()
            .unwrap_or_else(ValidationRule::string);

        // Length checks
        if let Some(max) = rule.max_length {
            if value.len() > max {
                return Err(ValidationError::TooLong {
                    field: key,
                    max,
                    actual: value.len(),
                });
            }
        }

        if let Some(min) = rule.min_length {
            if value.len() < min {
                return Err(ValidationError::TooShort {
                    field: key,
                    min,
                    actual: value.len(),
                });
            }
        }

        // Allowed values check
        if let Some(allowed) = &rule.allowed_values {
            if !allowed.iter().any(|v| v == value) {
                return Err(ValidationError::InvalidValue {
                    field: key,
                    value: value.to_string(),
                });
            }
        }

        // Sanitize if required
        let result = if rule.sanitize {
            sanitize_input(value)
        } else {
            value.to_string()
        };

        Ok(result)
    }
}

impl Default for InputValidator {
    fn default() -> Self {
        Self::new()
    }
}

fn sanitize_input(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .map(|c| match c {
            '<' => ' ',
            '>' => ' ',
            '&' => ' ',
            '"' => ' ',
            '\'' => ' ',
            _ => c,
        })
        .collect()
}

#[derive(Debug)]
pub enum ValidationError {
    TooLong {
        field: String,
        max: usize,
        actual: usize,
    },
    TooShort {
        field: String,
        min: usize,
        actual: usize,
    },
    InvalidPattern {
        field: String,
        pattern: String,
    },
    InvalidValue {
        field: String,
        value: String,
    },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong { field, max, actual } => {
                write!(f, "Field {} too long: max {}, got {}", field, max, actual)
            }
            Self::TooShort { field, min, actual } => {
                write!(f, "Field {} too short: min {}, got {}", field, min, actual)
            }
            Self::InvalidPattern { field, pattern } => {
                write!(f, "Field {} does not match pattern {}", field, pattern)
            }
            Self::InvalidValue { field, value } => {
                write!(f, "Invalid value '{}' for field {}", value, field)
            }
        }
    }
}

// ============================================================================
// Operation Rate Limiting
// ============================================================================

/// Rate limit configuration per operation
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_minute: u64,
    pub burst_size: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            burst_size: 10,
        }
    }
}

/// Token bucket rate limiter
pub struct OperationRateLimiter {
    configs: HashMap<String, RateLimitConfig>,
    buckets: HashMap<String, Arc<TokenBucket>>,
}

struct TokenBucket {
    tokens: AtomicU64,
    last_refill: AtomicU64,
    capacity: u64,
    refill_rate: f64, // tokens per second
}

impl TokenBucket {
    fn new(capacity: u64, refill_rate: f64) -> Self {
        Self {
            tokens: AtomicU64::new(capacity),
            last_refill: AtomicU64::new(current_timestamp()),
            capacity,
            refill_rate,
        }
    }

    fn try_acquire(&self) -> bool {
        let now = current_timestamp();
        let last = self.last_refill.load(Ordering::Relaxed);
        let elapsed = (now - last) as f64 / 1000.0; // seconds

        let refill = (elapsed * self.refill_rate) as u64;
        if refill > 0 {
            self.last_refill.store(now, Ordering::Relaxed);
            let current = self.tokens.load(Ordering::Relaxed);
            let new_tokens = (current + refill).min(self.capacity);
            self.tokens.store(new_tokens, Ordering::Relaxed);
        }

        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            if current == 0 {
                return false;
            }
            if self
                .tokens
                .compare_exchange(current, current - 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

impl OperationRateLimiter {
    pub fn new() -> Self {
        Self {
            configs: HashMap::new(),
            buckets: HashMap::new(),
        }
    }

    pub fn configure_operation(&mut self, operation: &str, config: RateLimitConfig) {
        self.configs.insert(operation.to_string(), config);
    }

    pub fn check(&mut self, operation: &str, client_id: &str) -> Result<(), RateLimitError> {
        let config = self.configs.get(operation).cloned().unwrap_or_default();
        let key = format!("{}:{}", operation, client_id);

        let bucket = self.buckets.entry(key.clone()).or_insert_with(|| {
            Arc::new(TokenBucket::new(
                config.burst_size,
                config.requests_per_minute as f64 / 60.0,
            ))
        });

        if bucket.try_acquire() {
            Ok(())
        } else {
            Err(RateLimitError::LimitExceeded {
                operation: operation.to_string(),
                limit: config.requests_per_minute,
            })
        }
    }
}

impl Default for OperationRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct RateLimitError {
    pub operation: String,
    pub limit: u64,
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Rate limit exceeded for operation '{}': {} requests/minute allowed",
            self.operation, self.limit
        )
    }
}

// ============================================================================
// Complete Security Middleware
// ============================================================================

/// Combined security middleware for GraphQL
pub struct GraphQLSecurityMiddleware {
    pub complexity_analyzer: ComplexityAnalyzer,
    pub authorizer: Authorizer,
    pub validator: InputValidator,
    pub rate_limiter: OperationRateLimiter,
}

impl GraphQLSecurityMiddleware {
    pub fn new(complexity_config: ComplexityConfig) -> Self {
        Self {
            complexity_analyzer: ComplexityAnalyzer::new(complexity_config),
            authorizer: Authorizer::new(),
            validator: InputValidator::new(),
            rate_limiter: OperationRateLimiter::new(),
        }
    }

    /// Check all security rules before executing a query
    pub fn check_request(
        &mut self,
        ctx: &SecurityContext,
        query: &QueryNode,
        operation_name: &str,
    ) -> Result<ComplexityResult, SecurityError> {
        // Rate limiting
        self.rate_limiter
            .check(operation_name, &ctx.ip_address)
            .map_err(|e| SecurityError::RateLimited(e.to_string()))?;

        // Complexity analysis
        let complexity = self
            .complexity_analyzer
            .analyze(query)
            .map_err(|e| SecurityError::ComplexityExceeded(e.to_string()))?;

        // Authorization will be checked per-field during resolution
        Ok(complexity)
    }
}

#[derive(Debug)]
pub enum SecurityError {
    RateLimited(String),
    ComplexityExceeded(String),
    Unauthorized(String),
    ValidationFailed(String),
}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimited(msg) => write!(f, "Rate limited: {}", msg),
            Self::ComplexityExceeded(msg) => write!(f, "Query too complex: {}", msg),
            Self::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            Self::ValidationFailed(msg) => write!(f, "Validation failed: {}", msg),
        }
    }
}

// ============================================================================
// Main and Tests
// ============================================================================

fn main() {
    println!("GraphQL Security Middleware Example\n");

    // Create security middleware
    let mut middleware = GraphQLSecurityMiddleware::new(ComplexityConfig {
        max_depth: 5,
        max_complexity: 100,
        default_field_complexity: 1,
        list_multiplier: 10,
    });

    // Configure field complexities
    middleware.complexity_analyzer.register_field(
        "Query",
        "users",
        FieldComplexity {
            base_cost: 5,
            is_list: true,
            requires_auth: true,
            minimum_role: Role::Admin,
        },
    );

    // Configure authorization rules
    middleware.authorizer.register_rule(
        "User",
        "email",
        AuthRule::authenticated().owner_only("id"),
    );
    middleware
        .authorizer
        .register_rule("User", "password_hash", AuthRule::admin());

    // Configure input validation
    middleware
        .validator
        .register_rule("CreateUserInput", "email", ValidationRule::email());
    middleware.validator.register_rule(
        "CreateUserInput",
        "name",
        ValidationRule::string().max_length(100).min_length(2),
    );

    // Configure rate limiting
    middleware.rate_limiter.configure_operation(
        "createUser",
        RateLimitConfig {
            requests_per_minute: 10,
            burst_size: 3,
        },
    );

    // Simulate a query
    let query = QueryNode {
        type_name: "Query".to_string(),
        field_name: "users".to_string(),
        arguments: [("limit".to_string(), "10".to_string())]
            .into_iter()
            .collect(),
        children: vec![
            QueryNode {
                type_name: "User".to_string(),
                field_name: "id".to_string(),
                arguments: HashMap::new(),
                children: vec![],
            },
            QueryNode {
                type_name: "User".to_string(),
                field_name: "name".to_string(),
                arguments: HashMap::new(),
                children: vec![],
            },
        ],
    };

    // Create security context for authenticated user
    let ctx = SecurityContext::authenticated(
        "user-123",
        Role::Admin,
        vec!["read:users".to_string()],
        "192.168.1.1",
        "req-456",
    );

    // Check request
    match middleware.check_request(&ctx, &query, "getUsers") {
        Ok(result) => {
            println!("Query allowed!");
            println!("  Depth: {}", result.depth);
            println!("  Complexity: {}", result.total_complexity);
            println!("  Fields: {}", result.field_count);
        }
        Err(e) => {
            println!("Query rejected: {}", e);
        }
    }

    // Check field authorization
    println!("\nField Authorization Checks:");
    let fields = [
        ("User", "name", None),
        ("User", "email", Some("user-123")),
        ("User", "email", Some("other-user")),
    ];

    for (type_name, field_name, owner_id) in fields {
        match middleware
            .authorizer
            .check(&ctx, type_name, field_name, owner_id)
        {
            Ok(()) => println!("  {}.{}: Allowed", type_name, field_name),
            Err(e) => println!("  {}.{}: Denied - {}", type_name, field_name, e),
        }
    }

    // Validate input
    println!("\nInput Validation:");
    let inputs = [
        ("CreateUserInput", "email", "test@example.com"),
        ("CreateUserInput", "email", "invalid"),
        ("CreateUserInput", "name", "John Doe"),
        ("CreateUserInput", "name", "X"),
    ];

    for (input_name, field_name, value) in inputs {
        match middleware.validator.validate(input_name, field_name, value) {
            Ok(sanitized) => println!(
                "  {}.{} = '{}': Valid -> '{}'",
                input_name, field_name, value, sanitized
            ),
            Err(e) => println!(
                "  {}.{} = '{}': Invalid - {}",
                input_name, field_name, value, e
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_hierarchy() {
        assert!(Role::SuperAdmin.has_permission(&Role::Admin));
        assert!(Role::Admin.has_permission(&Role::User));
        assert!(Role::User.has_permission(&Role::Anonymous));
        assert!(!Role::User.has_permission(&Role::Admin));
    }

    #[test]
    fn test_complexity_analysis() {
        let mut analyzer = ComplexityAnalyzer::new(ComplexityConfig::default());
        analyzer.register_field(
            "Query",
            "users",
            FieldComplexity {
                base_cost: 5,
                is_list: true,
                ..Default::default()
            },
        );

        let query = QueryNode {
            type_name: "Query".to_string(),
            field_name: "users".to_string(),
            arguments: [("limit".to_string(), "20".to_string())]
                .into_iter()
                .collect(),
            children: vec![],
        };

        let result = analyzer.analyze(&query).unwrap();
        assert_eq!(result.total_complexity, 5 * 20); // 5 base * 20 limit
    }

    #[test]
    fn test_depth_limit() {
        let analyzer = ComplexityAnalyzer::new(ComplexityConfig {
            max_depth: 2,
            ..Default::default()
        });

        let deep_query = QueryNode {
            type_name: "Query".to_string(),
            field_name: "a".to_string(),
            arguments: HashMap::new(),
            children: vec![QueryNode {
                type_name: "A".to_string(),
                field_name: "b".to_string(),
                arguments: HashMap::new(),
                children: vec![QueryNode {
                    type_name: "B".to_string(),
                    field_name: "c".to_string(),
                    arguments: HashMap::new(),
                    children: vec![],
                }],
            }],
        };

        let result = analyzer.analyze(&deep_query);
        assert!(matches!(result, Err(ComplexityError::DepthExceeded { .. })));
    }

    #[test]
    fn test_authorization() {
        let mut auth = Authorizer::new();
        auth.register_rule("User", "secret", AuthRule::admin());

        let user_ctx =
            SecurityContext::authenticated("user-1", Role::User, vec![], "127.0.0.1", "req-1");

        let admin_ctx =
            SecurityContext::authenticated("admin-1", Role::Admin, vec![], "127.0.0.1", "req-2");

        assert!(auth.check(&user_ctx, "User", "secret", None).is_err());
        assert!(auth.check(&admin_ctx, "User", "secret", None).is_ok());
    }

    #[test]
    fn test_owner_authorization() {
        let mut auth = Authorizer::new();
        auth.register_rule("User", "email", AuthRule::authenticated().owner_only("id"));

        let ctx =
            SecurityContext::authenticated("user-123", Role::User, vec![], "127.0.0.1", "req-1");

        // Own data - allowed
        assert!(auth.check(&ctx, "User", "email", Some("user-123")).is_ok());
        // Other's data - denied
        assert!(auth.check(&ctx, "User", "email", Some("user-456")).is_err());
    }

    #[test]
    fn test_input_validation() {
        let mut validator = InputValidator::new();
        validator.register_rule("Input", "name", ValidationRule::string().max_length(10));

        assert!(validator.validate("Input", "name", "Short").is_ok());
        assert!(validator
            .validate("Input", "name", "This is way too long")
            .is_err());
    }

    #[test]
    fn test_input_sanitization() {
        let validator = InputValidator::new();
        let result = validator
            .validate("Any", "field", "Hello <script>alert()</script>")
            .unwrap();
        assert!(!result.contains('<'));
        assert!(!result.contains('>'));
    }

    #[test]
    fn test_rate_limiting() {
        let mut limiter = OperationRateLimiter::new();
        limiter.configure_operation(
            "test",
            RateLimitConfig {
                requests_per_minute: 60,
                burst_size: 2,
            },
        );

        // First two should succeed (burst)
        assert!(limiter.check("test", "client-1").is_ok());
        assert!(limiter.check("test", "client-1").is_ok());
        // Third should fail
        assert!(limiter.check("test", "client-1").is_err());
    }
}
