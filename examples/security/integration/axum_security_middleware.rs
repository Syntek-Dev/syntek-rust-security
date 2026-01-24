//! Axum Security Middleware Example
//!
//! Demonstrates implementing comprehensive security middleware
//! for Axum web applications.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Security headers configuration
#[derive(Debug, Clone)]
pub struct SecurityHeaders {
    pub content_security_policy: String,
    pub x_content_type_options: String,
    pub x_frame_options: String,
    pub x_xss_protection: String,
    pub strict_transport_security: String,
    pub referrer_policy: String,
    pub permissions_policy: String,
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self {
            content_security_policy: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'".to_string(),
            x_content_type_options: "nosniff".to_string(),
            x_frame_options: "DENY".to_string(),
            x_xss_protection: "1; mode=block".to_string(),
            strict_transport_security: "max-age=31536000; includeSubDomains; preload".to_string(),
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
            permissions_policy: "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()".to_string(),
        }
    }
}

impl SecurityHeaders {
    /// Create strict CSP for API-only services
    pub fn api_only() -> Self {
        Self {
            content_security_policy: "default-src 'none'; frame-ancestors 'none'".to_string(),
            ..Default::default()
        }
    }

    /// Convert to header map
    pub fn to_headers(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "Content-Security-Policy",
                self.content_security_policy.clone(),
            ),
            (
                "X-Content-Type-Options",
                self.x_content_type_options.clone(),
            ),
            ("X-Frame-Options", self.x_frame_options.clone()),
            ("X-XSS-Protection", self.x_xss_protection.clone()),
            (
                "Strict-Transport-Security",
                self.strict_transport_security.clone(),
            ),
            ("Referrer-Policy", self.referrer_policy.clone()),
            ("Permissions-Policy", self.permissions_policy.clone()),
        ]
    }
}

/// Rate limiter using token bucket algorithm
#[derive(Debug)]
pub struct RateLimiter {
    buckets: std::sync::Mutex<HashMap<IpAddr, TokenBucket>>,
    capacity: u32,
    refill_rate: f64, // tokens per second
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            buckets: std::sync::Mutex::new(HashMap::new()),
            capacity: requests_per_minute,
            refill_rate: requests_per_minute as f64 / 60.0,
        }
    }

    pub fn check(&self, ip: IpAddr) -> RateLimitResult {
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();

        let bucket = buckets.entry(ip).or_insert(TokenBucket {
            tokens: self.capacity as f64,
            last_update: now,
        });

        // Refill tokens
        let elapsed = now.duration_since(bucket.last_update).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_rate).min(self.capacity as f64);
        bucket.last_update = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            RateLimitResult::Allowed {
                remaining: bucket.tokens as u32,
                reset_after: Duration::from_secs_f64(1.0 / self.refill_rate),
            }
        } else {
            let wait_time = (1.0 - bucket.tokens) / self.refill_rate;
            RateLimitResult::Limited {
                retry_after: Duration::from_secs_f64(wait_time),
            }
        }
    }

    pub fn cleanup_old_entries(&self, max_age: Duration) {
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();

        buckets.retain(|_, bucket| now.duration_since(bucket.last_update) < max_age);
    }
}

#[derive(Debug)]
pub enum RateLimitResult {
    Allowed {
        remaining: u32,
        reset_after: Duration,
    },
    Limited {
        retry_after: Duration,
    },
}

/// Request validation middleware
#[derive(Debug, Clone)]
pub struct RequestValidator {
    max_body_size: usize,
    allowed_content_types: Vec<String>,
    required_headers: Vec<String>,
}

impl Default for RequestValidator {
    fn default() -> Self {
        Self {
            max_body_size: 1024 * 1024, // 1MB
            allowed_content_types: vec![
                "application/json".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ],
            required_headers: vec![],
        }
    }
}

impl RequestValidator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = size;
        self
    }

    pub fn with_content_type(mut self, content_type: &str) -> Self {
        self.allowed_content_types.push(content_type.to_string());
        self
    }

    pub fn require_header(mut self, header: &str) -> Self {
        self.required_headers.push(header.to_string());
        self
    }

    pub fn validate(&self, request: &MockRequest) -> Result<(), ValidationError> {
        // Check body size
        if request.body_size > self.max_body_size {
            return Err(ValidationError::BodyTooLarge {
                max: self.max_body_size,
                actual: request.body_size,
            });
        }

        // Check content type
        if let Some(ref ct) = request.content_type {
            if !self
                .allowed_content_types
                .iter()
                .any(|allowed| ct.starts_with(allowed))
            {
                return Err(ValidationError::InvalidContentType(ct.clone()));
            }
        }

        // Check required headers
        for required in &self.required_headers {
            if !request.headers.contains_key(required) {
                return Err(ValidationError::MissingHeader(required.clone()));
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum ValidationError {
    BodyTooLarge { max: usize, actual: usize },
    InvalidContentType(String),
    MissingHeader(String),
}

/// Mock request for demonstration
#[derive(Debug)]
pub struct MockRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub content_type: Option<String>,
    pub body_size: usize,
    pub ip: IpAddr,
}

/// CORS configuration
#[derive(Debug, Clone)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    pub max_age: u64,
    pub allow_credentials: bool,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec![],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
            ],
            allowed_headers: vec!["Content-Type".to_string(), "Authorization".to_string()],
            expose_headers: vec![],
            max_age: 86400,
            allow_credentials: false,
        }
    }
}

impl CorsConfig {
    pub fn permissive() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec!["*".to_string()],
            allowed_headers: vec!["*".to_string()],
            ..Default::default()
        }
    }

    pub fn strict(allowed_origin: &str) -> Self {
        Self {
            allowed_origins: vec![allowed_origin.to_string()],
            allow_credentials: true,
            ..Default::default()
        }
    }

    pub fn check_origin(&self, origin: &str) -> bool {
        if self.allowed_origins.contains(&"*".to_string()) {
            return true;
        }
        self.allowed_origins.iter().any(|allowed| allowed == origin)
    }

    pub fn to_headers(&self, request_origin: Option<&str>) -> Vec<(&'static str, String)> {
        let mut headers = Vec::new();

        if let Some(origin) = request_origin {
            if self.check_origin(origin) {
                headers.push(("Access-Control-Allow-Origin", origin.to_string()));
            }
        } else if self.allowed_origins.contains(&"*".to_string()) {
            headers.push(("Access-Control-Allow-Origin", "*".to_string()));
        }

        headers.push((
            "Access-Control-Allow-Methods",
            self.allowed_methods.join(", "),
        ));

        headers.push((
            "Access-Control-Allow-Headers",
            self.allowed_headers.join(", "),
        ));

        if !self.expose_headers.is_empty() {
            headers.push((
                "Access-Control-Expose-Headers",
                self.expose_headers.join(", "),
            ));
        }

        headers.push(("Access-Control-Max-Age", self.max_age.to_string()));

        if self.allow_credentials {
            headers.push(("Access-Control-Allow-Credentials", "true".to_string()));
        }

        headers
    }
}

/// Security middleware stack
pub struct SecurityMiddleware {
    pub headers: SecurityHeaders,
    pub rate_limiter: Arc<RateLimiter>,
    pub validator: RequestValidator,
    pub cors: CorsConfig,
}

impl SecurityMiddleware {
    pub fn new() -> Self {
        Self {
            headers: SecurityHeaders::default(),
            rate_limiter: Arc::new(RateLimiter::new(100)),
            validator: RequestValidator::default(),
            cors: CorsConfig::default(),
        }
    }

    pub fn process(
        &self,
        request: &MockRequest,
    ) -> Result<Vec<(&'static str, String)>, MiddlewareError> {
        // Check rate limit
        match self.rate_limiter.check(request.ip) {
            RateLimitResult::Allowed { .. } => {}
            RateLimitResult::Limited { retry_after } => {
                return Err(MiddlewareError::RateLimited {
                    retry_after_secs: retry_after.as_secs(),
                });
            }
        }

        // Validate request
        self.validator
            .validate(request)
            .map_err(MiddlewareError::Validation)?;

        // Collect response headers
        let mut headers = self.headers.to_headers();

        // Add CORS headers if origin present
        if let Some(origin) = request.headers.get("Origin") {
            headers.extend(self.cors.to_headers(Some(origin)));
        }

        // Add rate limit headers
        if let RateLimitResult::Allowed {
            remaining,
            reset_after,
        } = self.rate_limiter.check(request.ip)
        {
            headers.push(("X-RateLimit-Remaining", remaining.to_string()));
            headers.push(("X-RateLimit-Reset", reset_after.as_secs().to_string()));
        }

        Ok(headers)
    }
}

impl Default for SecurityMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum MiddlewareError {
    RateLimited { retry_after_secs: u64 },
    Validation(ValidationError),
}

fn main() {
    println!("Axum Security Middleware Example");
    println!("=================================\n");

    // Create security middleware
    let middleware = SecurityMiddleware {
        headers: SecurityHeaders::default(),
        rate_limiter: Arc::new(RateLimiter::new(60)), // 60 requests/minute
        validator: RequestValidator::new()
            .with_max_body_size(512 * 1024) // 512KB
            .require_header("User-Agent"),
        cors: CorsConfig::strict("https://example.com"),
    };

    // Create mock request
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), "Mozilla/5.0".to_string());
    headers.insert("Origin".to_string(), "https://example.com".to_string());

    let request = MockRequest {
        method: "POST".to_string(),
        path: "/api/data".to_string(),
        headers,
        content_type: Some("application/json".to_string()),
        body_size: 1024,
        ip: "192.168.1.1".parse().unwrap(),
    };

    // Process request
    match middleware.process(&request) {
        Ok(headers) => {
            println!("Request allowed. Response headers:");
            for (name, value) in headers {
                println!("  {}: {}", name, value);
            }
        }
        Err(e) => {
            println!("Request blocked: {:?}", e);
        }
    }

    // Show security headers
    println!("\n\nDefault Security Headers:");
    println!("==========================");
    for (name, value) in SecurityHeaders::default().to_headers() {
        println!("  {}: {}", name, value);
    }

    // Show rate limiting
    println!("\n\nRate Limiting Demo:");
    println!("====================");
    let limiter = RateLimiter::new(5); // 5 per minute for demo
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    for i in 1..=8 {
        match limiter.check(ip) {
            RateLimitResult::Allowed { remaining, .. } => {
                println!("  Request {}: Allowed ({} remaining)", i, remaining);
            }
            RateLimitResult::Limited { retry_after } => {
                println!("  Request {}: BLOCKED (retry after {:?})", i, retry_after);
            }
        }
    }

    // CORS configuration
    println!("\n\nCORS Configuration:");
    println!("===================");
    let cors = CorsConfig::strict("https://myapp.com");
    println!("  Allowed origins: {:?}", cors.allowed_origins);
    println!("  Allowed methods: {:?}", cors.allowed_methods);
    println!("  Allow credentials: {}", cors.allow_credentials);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_headers_default() {
        let headers = SecurityHeaders::default();
        let header_map = headers.to_headers();

        assert!(header_map
            .iter()
            .any(|(k, _)| *k == "Content-Security-Policy"));
        assert!(header_map.iter().any(|(k, _)| *k == "X-Frame-Options"));
        assert!(header_map
            .iter()
            .any(|(k, _)| *k == "Strict-Transport-Security"));
    }

    #[test]
    fn test_rate_limiter_allows_requests() {
        let limiter = RateLimiter::new(10);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        for _ in 0..10 {
            match limiter.check(ip) {
                RateLimitResult::Allowed { .. } => {}
                RateLimitResult::Limited { .. } => panic!("Should be allowed"),
            }
        }
    }

    #[test]
    fn test_rate_limiter_blocks_excess() {
        let limiter = RateLimiter::new(2);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        // Use up tokens
        limiter.check(ip);
        limiter.check(ip);

        // This should be limited
        match limiter.check(ip) {
            RateLimitResult::Limited { .. } => {}
            RateLimitResult::Allowed { .. } => panic!("Should be limited"),
        }
    }

    #[test]
    fn test_request_validator_body_size() {
        let validator = RequestValidator::new().with_max_body_size(100);

        let request = MockRequest {
            method: "POST".to_string(),
            path: "/".to_string(),
            headers: HashMap::new(),
            content_type: Some("application/json".to_string()),
            body_size: 200,
            ip: "1.2.3.4".parse().unwrap(),
        };

        assert!(matches!(
            validator.validate(&request),
            Err(ValidationError::BodyTooLarge { .. })
        ));
    }

    #[test]
    fn test_request_validator_content_type() {
        let validator = RequestValidator::new();

        let request = MockRequest {
            method: "POST".to_string(),
            path: "/".to_string(),
            headers: HashMap::new(),
            content_type: Some("text/xml".to_string()),
            body_size: 100,
            ip: "1.2.3.4".parse().unwrap(),
        };

        assert!(matches!(
            validator.validate(&request),
            Err(ValidationError::InvalidContentType(_))
        ));
    }

    #[test]
    fn test_request_validator_required_header() {
        let validator = RequestValidator::new().require_header("X-API-Key");

        let request = MockRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: HashMap::new(),
            content_type: None,
            body_size: 0,
            ip: "1.2.3.4".parse().unwrap(),
        };

        assert!(matches!(
            validator.validate(&request),
            Err(ValidationError::MissingHeader(_))
        ));
    }

    #[test]
    fn test_cors_check_origin() {
        let cors = CorsConfig::strict("https://example.com");

        assert!(cors.check_origin("https://example.com"));
        assert!(!cors.check_origin("https://malicious.com"));
    }

    #[test]
    fn test_cors_wildcard() {
        let cors = CorsConfig::permissive();

        assert!(cors.check_origin("https://any-origin.com"));
    }

    #[test]
    fn test_middleware_integration() {
        let middleware = SecurityMiddleware::new();

        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "Test".to_string());

        let request = MockRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers,
            content_type: None,
            body_size: 0,
            ip: "1.2.3.4".parse().unwrap(),
        };

        let result = middleware.process(&request);
        assert!(result.is_ok());
    }
}
