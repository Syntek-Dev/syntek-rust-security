# Rust Web Security Template

## Overview

This template provides a comprehensive security-hardened foundation for building web services and APIs in Rust. It covers the most popular async web frameworks (Actix Web, Axum, Rocket) with focus on OWASP Top 10 protection, authentication, authorization, input validation, and secure session management.

**Target Use Cases:**
- RESTful APIs
- GraphQL services
- Microservices
- Full-stack web applications
- WebSocket servers
- gRPC services

## Project Structure

```
my-web-service/
├── Cargo.toml
├── Cargo.lock
├── .cargo/
│   └── config.toml
├── src/
│   ├── main.rs                 # Entry point
│   ├── lib.rs                  # Library exports
│   ├── config.rs               # Configuration
│   ├── routes/                 # HTTP routes
│   │   ├── mod.rs
│   │   ├── auth.rs
│   │   ├── api.rs
│   │   └── health.rs
│   ├── middleware/             # HTTP middleware
│   │   ├── mod.rs
│   │   ├── auth.rs
│   │   ├── cors.rs
│   │   ├── csrf.rs
│   │   ├── rate_limit.rs
│   │   └── security_headers.rs
│   ├── models/                 # Data models
│   │   ├── mod.rs
│   │   └── user.rs
│   ├── db/                     # Database layer
│   │   ├── mod.rs
│   │   └── pool.rs
│   ├── auth/                   # Authentication
│   │   ├── mod.rs
│   │   ├── jwt.rs
│   │   ├── password.rs
│   │   └── session.rs
│   ├── validators/             # Input validation
│   │   ├── mod.rs
│   │   └── api.rs
│   ├── security/               # Security utilities
│   │   ├── mod.rs
│   │   ├── crypto.rs
│   │   ├── csrf.rs
│   │   └── sanitize.rs
│   └── error.rs                # Error types
├── migrations/                 # Database migrations
│   └── 001_initial.sql
├── tests/
│   ├── integration/
│   │   ├── auth_tests.rs
│   │   └── api_tests.rs
│   └── security/
│       └── owasp_tests.rs
├── .github/
│   └── workflows/
│       └── security.yml
├── deny.toml
├── .env.example
└── README.md
```

## Cargo.toml Template

```toml
[package]
name = "my-web-service"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"
authors = ["Your Name <you@example.com>"]
license = "MIT OR Apache-2.0"
description = "Security-hardened web service"

[dependencies]
# Web Framework (choose one)
# Option 1: Axum (recommended for new projects)
axum = { version = "0.7", features = ["macros"] }
axum-extra = { version = "0.9", features = ["cookie", "typed-header"] }

# Option 2: Actix Web
# actix-web = "4.9"
# actix-cors = "0.7"
# actix-session = { version = "0.10", features = ["cookie-session"] }

# Option 3: Rocket
# rocket = { version = "0.5", features = ["json", "secrets"] }

# Async runtime
tokio = { version = "1.42", features = ["full"] }
tower = { version = "0.5", features = ["limit", "timeout"] }
tower-http = { version = "0.6", features = ["cors", "compression-gzip", "trace", "request-id"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Database (choose one or both)
sqlx = { version = "0.8", features = ["runtime-tokio", "postgres", "migrate", "uuid", "time"] }
# diesel = { version = "2.2", features = ["postgres", "uuid", "chrono"] }

# Authentication & Authorization
jsonwebtoken = "9.3"
argon2 = { version = "0.5", features = ["std"] }
rand = "0.8"
uuid = { version = "1.11", features = ["v4", "serde"] }

# Security
secrecy = { version = "0.10", features = ["serde"] }
zeroize = "1.8"
sha2 = "0.10"
hmac = "0.12"
subtle = "2.6"

# CSRF protection
csrf = "0.4"

# Rate limiting
tower-governor = "0.4"

# Input validation
validator = { version = "0.18", features = ["derive"] }
regex = "1.11"

# CORS
tower-http = { version = "0.6", features = ["cors"] }

# Security headers
headers = "0.4"

# Error handling
anyhow = "1.0"
thiserror = "2.0"

# Logging & Tracing
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
tracing-appender = "0.2"

# Configuration
config = "0.14"
dotenvy = "0.15"

# Time utilities
time = { version = "0.3", features = ["serde", "macros"] }

# HTTP client (for external API calls)
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }

[dev-dependencies]
tokio-test = "0.4"
axum-test = "15.8"
fake = "2.10"
wiremock = "0.6"

[profile.release]
strip = true
lto = true
codegen-units = 1
panic = "abort"
overflow-checks = true

[profile.dev]
overflow-checks = true
```

## Security Considerations

### 1. OWASP Top 10 Protection

#### A01: Broken Access Control
- Implement role-based access control (RBAC)
- Validate permissions on every request
- Use secure session management
- **Enable PostgreSQL Row Level Security (RLS) on all tables containing user or tenant data** — this enforces data isolation at the database layer, independent of the application stack

```sql
-- migrations/001_initial.sql
-- Enable RLS on every table with user-scoped data
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

-- Policy: each user sees only their own rows
CREATE POLICY user_isolation ON documents
    FOR ALL
    TO app_user
    USING (owner_id = current_setting('app.current_user_id')::uuid);

-- For multi-tenant data, scope by tenant as well
CREATE POLICY tenant_isolation ON documents
    FOR ALL
    TO app_user
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
```

```rust
// src/db/rls.rs — set session variables before every query
pub async fn set_rls_context(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('app.current_user_id', $1, true)")
        .bind(user_id.to_string())
        .execute(tx.as_mut())
        .await?;
    Ok(())
}
```

#### A02: Cryptographic Failures
- Use Argon2 for password hashing
- Use TLS 1.3 for transport encryption
- Secure JWT signing with HS256/RS256

#### A03: Injection
- Use parameterized queries (SQLx/Diesel)
- Validate and sanitize all inputs
- Use prepared statements

#### A04: Insecure Design
- Defense in depth
- Fail securely
- Principle of least privilege

#### A05: Security Misconfiguration
- Secure default configuration
- Security headers (CSP, HSTS, etc.)
- Disable debug endpoints in production

#### A06: Vulnerable Components
- Use cargo-audit in CI/CD
- Regular dependency updates
- Monitor RustSec advisories

#### A07: Authentication Failures
- Strong password policies
- Rate limiting on auth endpoints
- Secure session management
- MFA support

#### A08: Software and Data Integrity
- Sign JWT tokens
- Validate all external data
- Integrity checks on critical operations

#### A09: Logging Failures
- Comprehensive audit logging
- No secrets in logs
- Log security events

#### A10: Server-Side Request Forgery
- Validate URLs
- Allowlist external domains
- Network segmentation

### 2. Authentication Security
- Argon2id for password hashing
- Secure JWT with short expiry
- HttpOnly, Secure, SameSite cookies
- Session timeout
- CSRF protection

### 3. Input Validation
- Validate at API boundary
- Use type-safe validators
- Reject invalid data early
- Sanitize HTML/SQL inputs

### 4. Rate Limiting
- Per-IP rate limits
- Per-user rate limits
- Adaptive rate limiting
- Fail2ban integration

### 5. Security Headers
- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- X-XSS-Protection

## Required Dependencies

### Core Web Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `axum` | 0.7+ | Web framework |
| `tokio` | 1.42+ | Async runtime |
| `tower` | 0.5+ | Middleware |
| `tower-http` | 0.6+ | HTTP middleware |

### Security Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `argon2` | 0.5+ | Password hashing |
| `jsonwebtoken` | 9.3+ | JWT authentication |
| `secrecy` | 0.10+ | Secret management |
| `validator` | 0.18+ | Input validation |
| `csrf` | 0.4+ | CSRF protection |
| `tower-governor` | 0.4+ | Rate limiting |

### Database Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `sqlx` | 0.8+ | SQL database (async) |
| `uuid` | 1.11+ | UUID generation |

## Code Examples

### Example 1: Secure Axum Server Setup

```rust
// src/main.rs
use axum::{
    Router,
    routing::{get, post},
};
use tower::ServiceBuilder;
use tower_http::{
    trace::TraceLayer,
    compression::CompressionLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
};
use std::net::SocketAddr;
use std::time::Duration;

mod routes;
mod middleware;
mod config;
mod auth;
mod db;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Load configuration
    let config = config::load()?;

    // Initialize database pool
    let db_pool = db::create_pool(&config.database_url).await?;

    // Run migrations
    sqlx::migrate!("./migrations").run(&db_pool).await?;

    // Build application
    let app = Router::new()
        // Public routes
        .route("/health", get(routes::health::health_check))
        .route("/api/v1/auth/login", post(routes::auth::login))
        .route("/api/v1/auth/register", post(routes::auth::register))
        // Protected routes
        .route("/api/v1/users/me", get(routes::api::get_current_user))
        .layer(
            ServiceBuilder::new()
                // Request ID
                .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
                .layer(PropagateRequestIdLayer::x_request_id())
                // Security middleware
                .layer(middleware::security_headers::SecurityHeadersLayer)
                .layer(middleware::cors::cors_layer())
                .layer(middleware::rate_limit::rate_limit_layer())
                // Compression
                .layer(CompressionLayer::new())
                // Tracing
                .layer(TraceLayer::new_for_http())
                // Timeout
                .timeout(Duration::from_secs(30))
        )
        .with_state(AppState {
            db: db_pool,
            config: config.clone(),
        });

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[derive(Clone)]
struct AppState {
    db: sqlx::PgPool,
    config: config::Config,
}
```

### Example 2: Password Hashing with Argon2

```rust
// src/auth/password.rs
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use secrecy::{ExposeSecret, Secret};
use anyhow::{Context, Result};

/// Hash a password using Argon2id
pub fn hash_password(password: &Secret<String>) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);

    // Argon2id with default params (recommended)
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.expose_secret().as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?
        .to_string();

    Ok(password_hash)
}

/// Verify a password against a hash
pub fn verify_password(password: &Secret<String>, password_hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(password_hash)
        .context("Failed to parse password hash")?;

    let argon2 = Argon2::default();

    match argon2.verify_password(password.expose_secret().as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(anyhow::anyhow!("Password verification error: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let password = Secret::new("MySecurePassword123!".to_string());
        let hash = hash_password(&password).unwrap();

        assert!(verify_password(&password, &hash).unwrap());

        let wrong_password = Secret::new("WrongPassword".to_string());
        assert!(!verify_password(&wrong_password, &hash).unwrap());
    }
}
```

### Example 3: JWT Authentication

```rust
// src/auth/jwt.rs
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,              // User ID
    pub exp: i64,               // Expiry time
    pub iat: i64,               // Issued at
    pub roles: Vec<String>,     // User roles
}

impl Claims {
    pub fn new(user_id: Uuid, roles: Vec<String>, duration: Duration) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            sub: user_id,
            iat: now.unix_timestamp(),
            exp: (now + duration).unix_timestamp(),
            roles,
        }
    }
}

pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtService {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
        }
    }

    pub fn generate_token(&self, user_id: Uuid, roles: Vec<String>) -> Result<String> {
        let claims = Claims::new(user_id, roles, Duration::hours(24));
        let token = encode(&Header::default(), &claims, &self.encoding_key)?;
        Ok(token)
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        let token_data = decode::<Claims>(
            token,
            &self.decoding_key,
            &Validation::default(),
        )?;
        Ok(token_data.claims)
    }
}

// Axum extractor for JWT authentication
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};

pub struct AuthUser {
    pub user_id: Uuid,
    pub roles: Vec<String>,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(StatusCode::UNAUTHORIZED)?;

        // Get JWT service from app state (simplified)
        let jwt_service = JwtService::new(b"your-secret-key"); // TODO: Get from config

        let claims = jwt_service
            .verify_token(token)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        Ok(AuthUser {
            user_id: claims.sub,
            roles: claims.roles,
        })
    }
}
```

### Example 4: Security Headers Middleware

```rust
// src/middleware/security_headers.rs
use axum::{
    body::Body,
    http::{Request, Response, header},
    middleware::Next,
};

pub async fn add_security_headers(
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // Content Security Policy
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );

    // Strict Transport Security (HSTS)
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        "max-age=31536000; includeSubDomains; preload"
            .parse()
            .unwrap(),
    );

    // X-Content-Type-Options
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().unwrap(),
    );

    // X-Frame-Options
    headers.insert(
        header::X_FRAME_OPTIONS,
        "DENY".parse().unwrap(),
    );

    // X-XSS-Protection
    headers.insert(
        "X-XSS-Protection".parse().unwrap(),
        "1; mode=block".parse().unwrap(),
    );

    // Referrer Policy
    headers.insert(
        header::REFERRER_POLICY,
        "strict-origin-when-cross-origin".parse().unwrap(),
    );

    // Permissions Policy
    headers.insert(
        "Permissions-Policy".parse().unwrap(),
        "geolocation=(), microphone=(), camera=()".parse().unwrap(),
    );

    response
}

// Layer wrapper
use tower::Layer;
use std::task::{Context, Poll};

#[derive(Clone)]
pub struct SecurityHeadersLayer;

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersMiddleware { inner }
    }
}

#[derive(Clone)]
pub struct SecurityHeadersMiddleware<S> {
    inner: S,
}

impl<S> tower::Service<Request<Body>> for SecurityHeadersMiddleware<S>
where
    S: tower::Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let mut response = inner.call(req).await?;

            // Add security headers
            let headers = response.headers_mut();
            headers.insert(header::STRICT_TRANSPORT_SECURITY, "max-age=31536000".parse().unwrap());
            headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());

            Ok(response)
        })
    }
}
```

### Example 5: Input Validation

```rust
// src/validators/api.rs
use validator::{Validate, ValidationError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email)]
    pub email: String,

    #[validate(length(min = 8, max = 128))]
    #[validate(custom = "validate_password_strength")]
    pub password: String,

    #[validate(length(min = 2, max = 50))]
    #[validate(regex = "USERNAME_REGEX")]
    pub username: String,
}

lazy_static::lazy_static! {
    static ref USERNAME_REGEX: regex::Regex = regex::Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap();
}

fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    if has_uppercase && has_lowercase && has_digit && has_special {
        Ok(())
    } else {
        Err(ValidationError::new("weak_password"))
    }
}

// Axum integration
use axum::{
    async_trait,
    extract::{FromRequest, Request},
    http::StatusCode,
    Json,
};

pub struct ValidatedJson<T>(pub T);

#[async_trait]
impl<T, S> FromRequest<S> for ValidatedJson<T>
where
    T: for<'de> Deserialize<'de> + Validate,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(data) = Json::<T>::from_request(req, state)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

        data.validate()
            .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;

        Ok(ValidatedJson(data))
    }
}
```

### Example 6: Row Level Security with SQLx

```rust
// src/db/rls.rs
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;
use anyhow::Result;

/// Every DB transaction that touches user-scoped data MUST call this first.
/// RLS policies on the DB enforce isolation regardless of application logic,
/// but the session variable must be set so policies can evaluate correctly.
pub async fn set_rls_context(tx: &mut Transaction<'_, Postgres>, user_id: Uuid) -> Result<()> {
    sqlx::query("SELECT set_config('app.current_user_id', $1, true)")
        .bind(user_id.to_string())
        .execute(tx.as_mut())
        .await?;
    Ok(())
}

/// Wrapper: begin a transaction and immediately set the RLS context.
pub async fn begin_with_rls(pool: &PgPool, user_id: Uuid) -> Result<Transaction<'_, Postgres>> {
    let mut tx = pool.begin().await?;
    set_rls_context(&mut tx, user_id).await?;
    Ok(tx)
}
```

```sql
-- migrations/001_rls.sql
-- ✅ RLS must be enabled on EVERY table that holds user or tenant data.
-- FORCE ensures even the table owner cannot bypass the policy.

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

CREATE POLICY documents_user_isolation ON documents
    FOR ALL TO app_user
    USING (owner_id = current_setting('app.current_user_id')::uuid);
```

```rust
// Usage: always go through begin_with_rls
pub async fn get_documents(pool: &PgPool, user: &AuthUser) -> Result<Vec<Document>> {
    let mut tx = begin_with_rls(pool, user.user_id).await?;
    let docs = sqlx::query_as::<_, Document>(
        "SELECT id, title, content FROM documents"
        // No WHERE owner_id = $1 needed — RLS enforces it at DB level
    )
    .fetch_all(tx.as_mut())
    .await?;
    tx.commit().await?;
    Ok(docs)
}
```

### Example 7: SQL Injection Prevention with SQLx

```rust
// src/db/user.rs
use sqlx::{PgPool, FromRow};
use uuid::Uuid;
use anyhow::Result;

#[derive(Debug, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub password_hash: String,
    pub created_at: time::OffsetDateTime,
}

pub async fn find_user_by_email(pool: &PgPool, email: &str) -> Result<Option<User>> {
    // ✅ SAFE: Parameterized query prevents SQL injection
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, username, password_hash, created_at
         FROM users
         WHERE email = $1"
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

pub async fn create_user(
    pool: &PgPool,
    email: &str,
    username: &str,
    password_hash: &str,
) -> Result<User> {
    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (id, email, username, password_hash)
         VALUES ($1, $2, $3, $4)
         RETURNING id, email, username, password_hash, created_at"
    )
    .bind(Uuid::new_v4())
    .bind(email)
    .bind(username)
    .bind(password_hash)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

// ❌ DANGEROUS: Example of what NOT to do
#[cfg(feature = "examples-unsafe")]
pub async fn find_user_unsafe(pool: &PgPool, email: &str) -> Result<Option<User>> {
    // This is vulnerable to SQL injection!
    let query = format!("SELECT * FROM users WHERE email = '{}'", email);
    // If email = "' OR '1'='1", this returns all users!
    let user = sqlx::query_as::<_, User>(&query).fetch_optional(pool).await?;
    Ok(user)
}
```

### Example 7: Rate Limiting

```rust
// src/middleware/rate_limit.rs
use tower_governor::{
    governor::GovernorConfigBuilder,
    key_extractor::SmartIpKeyExtractor,
    GovernorLayer,
};
use std::time::Duration;

pub fn rate_limit_layer() -> GovernorLayer<SmartIpKeyExtractor> {
    let config = GovernorConfigBuilder::default()
        .per_second(10)  // 10 requests per second
        .burst_size(20)  // Allow bursts up to 20 requests
        .finish()
        .unwrap();

    GovernorLayer {
        config: Box::leak(Box::new(config)),
    }
}

// Per-endpoint rate limiting
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;
use dashmap::DashMap;

#[derive(Clone)]
pub struct RateLimiter {
    limits: Arc<DashMap<String, (usize, std::time::Instant)>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            limits: Arc::new(DashMap::new()),
            max_requests,
            window,
        }
    }

    pub fn check(&self, key: &str) -> Result<(), StatusCode> {
        let now = std::time::Instant::now();

        let mut entry = self.limits.entry(key.to_string()).or_insert((0, now));

        // Reset counter if window expired
        if now.duration_since(entry.1) > self.window {
            entry.0 = 0;
            entry.1 = now;
        }

        // Check limit
        if entry.0 >= self.max_requests {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        entry.0 += 1;
        Ok(())
    }
}
```

## Common Vulnerabilities

### 1. SQL Injection
**Vulnerable:**
```rust
let query = format!("SELECT * FROM users WHERE id = {}", user_input);
```
**Secure:**
```rust
sqlx::query_as("SELECT * FROM users WHERE id = $1").bind(user_id)
```

### 2. XSS (Cross-Site Scripting)
**Vulnerable:**
```rust
format!("<div>{}</div>", user_input) // Raw HTML
```
**Secure:**
```rust
use askama::Template;
#[derive(Template)]
#[template(path = "user.html")]
struct UserTemplate { name: String }
// Templates auto-escape HTML
```

### 3. CSRF (Cross-Site Request Forgery)
**Vulnerable:**
```rust
// No CSRF protection on state-changing endpoints
```
**Secure:**
```rust
use axum_csrf::{CsrfConfig, CsrfLayer};
let csrf_config = CsrfConfig::default();
app.layer(CsrfLayer::new(csrf_config))
```

### 4. Insecure Direct Object References
**Vulnerable:**
```rust
async fn get_document(Path(id): Path<Uuid>) -> impl IntoResponse {
    // No authorization check!
    db::get_document(id).await
}
```
**Secure:**
```rust
async fn get_document(
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    let doc = db::get_document(id).await?;
    if doc.owner_id != auth.user_id {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Json(doc))
}
```

### 5. Weak Session Management
**Vulnerable:**
```rust
// Predictable session IDs
let session_id = format!("{}", user_id);
```
**Secure:**
```rust
use uuid::Uuid;
let session_id = Uuid::new_v4(); // Cryptographically random
```

## Testing Strategy

### Integration Tests

```rust
// tests/integration/auth_tests.rs
use axum_test::TestServer;

#[tokio::test]
async fn test_login_success() {
    let app = create_test_app().await;
    let server = TestServer::new(app).unwrap();

    let response = server
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({
            "email": "test@example.com",
            "password": "SecurePassword123!"
        }))
        .await;

    response.assert_status_ok();
    response.assert_json_contains(&serde_json::json!({
        "token": response.json::<serde_json::Value>()["token"]
    }));
}

#[tokio::test]
async fn test_login_rate_limit() {
    let server = TestServer::new(create_test_app().await).unwrap();

    // Make many requests
    for _ in 0..100 {
        let response = server
            .post("/api/v1/auth/login")
            .json(&serde_json::json!({
                "email": "test@example.com",
                "password": "wrong"
            }))
            .await;

        if response.status_code() == StatusCode::TOO_MANY_REQUESTS {
            return; // Rate limit triggered - test passed
        }
    }

    panic!("Rate limit not triggered");
}
```

### Security Tests

```rust
// tests/security/owasp_tests.rs
#[tokio::test]
async fn test_sql_injection_prevention() {
    let server = TestServer::new(create_test_app().await).unwrap();

    let malicious_inputs = vec![
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1' UNION SELECT * FROM users--",
    ];

    for input in malicious_inputs {
        let response = server
            .get(&format!("/api/v1/users?search={}", input))
            .await;

        // Should not return all users or cause error
        assert_ne!(response.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}

#[tokio::test]
async fn test_xss_prevention() {
    let server = TestServer::new(create_test_app().await).unwrap();

    let xss_payload = "<script>alert('XSS')</script>";

    let response = server
        .post("/api/v1/comments")
        .json(&serde_json::json!({
            "content": xss_payload
        }))
        .await;

    // Response should escape HTML
    let body = response.text();
    assert!(!body.contains("<script>"));
    assert!(body.contains("&lt;script&gt;") || body.contains("\\u003cscript\\u003e"));
}
```

## CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Security Audit

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: 1.92.0

      - name: Install cargo-audit
        run: cargo install cargo-audit

      - name: Run cargo audit
        run: cargo audit

      - name: Install cargo-deny
        run: cargo install cargo-deny

      - name: Run cargo deny
        run: cargo deny check

      - name: Run tests
        run: cargo test --all-features

      - name: Run security tests
        run: cargo test --test owasp_tests
```

## Best Practices

1. **Enable PostgreSQL RLS on all user/tenant tables** — `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY`; set `app.current_user_id` via `set_config` before every transaction
2. **Always use parameterized queries**
3. **Implement rate limiting on all endpoints**
4. **Use Argon2id for password hashing**
5. **Enable all security headers**
6. **Validate all inputs at API boundary**
7. **Use HTTPS/TLS in production**
8. **Implement CSRF protection**
9. **Use secure session management**
10. **Log security events**
11. **Regular security audits**

## Example Projects

- **Actix Example**: https://github.com/actix/examples
- **Axum Example**: https://github.com/tokio-rs/axum/tree/main/examples
- **RealWorld**: https://github.com/rust-lang/realworld
