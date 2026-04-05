# Rust GraphQL Middleware Template

## Overview

This template provides a security-focused GraphQL middleware implementation
using async-graphql and Axum. It enables field-level encryption, authorization,
rate limiting, and audit logging for GraphQL APIs with Rust performance and
memory safety.

**Target Use Cases:**

- Secure GraphQL APIs with field-level encryption
- Authorization and permission checks on resolvers
- Rate limiting per operation/field
- Audit logging of sensitive operations
- Request validation and sanitization

## Project Structure

```
my-graphql-security/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── schema/
│   │   ├── mod.rs
│   │   ├── query.rs
│   │   ├── mutation.rs
│   │   └── subscription.rs
│   ├── middleware/
│   │   ├── mod.rs
│   │   ├── auth.rs
│   │   ├── encryption.rs
│   │   ├── rate_limit.rs
│   │   ├── audit.rs
│   │   └── validation.rs
│   ├── guards/
│   │   ├── mod.rs
│   │   ├── role.rs
│   │   └── field_access.rs
│   ├── directives/
│   │   ├── mod.rs
│   │   ├── encrypted.rs
│   │   └── authorized.rs
│   ├── context/
│   │   ├── mod.rs
│   │   └── security.rs
│   └── crypto/
│       ├── mod.rs
│       └── field_encryption.rs
├── tests/
│   ├── auth_tests.rs
│   ├── encryption_tests.rs
│   └── rate_limit_tests.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-graphql-security"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"

[dependencies]
# GraphQL
async-graphql = { version = "7.0", features = ["chrono", "uuid", "tracing"] }
async-graphql-axum = "7.0"

# Web framework
axum = { version = "0.7", features = ["tracing"] }
tower = { version = "0.5", features = ["full"] }
tower-http = { version = "0.6", features = ["cors", "trace", "request-id"] }

# Async runtime
tokio = { version = "1.40", features = ["full"] }

# Cryptography
aes-gcm = "0.10"
argon2 = "0.5"
rand = "0.8"

# Secure memory
zeroize = { version = "1.8", features = ["derive"] }
secrecy = "0.10"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
base64 = "0.22"

# Authentication
jsonwebtoken = "9.3"

# Rate limiting
governor = "0.6"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Time
chrono = { version = "0.4", features = ["serde"] }

# UUID
uuid = { version = "1.10", features = ["v4", "serde"] }

# Error handling
thiserror = "2.0"
anyhow = "1.0"

[dev-dependencies]
tokio-test = "0.4"
wiremock = "0.6"

[profile.release]
lto = true
codegen-units = 1
```

## Core Implementation

### src/lib.rs

```rust
pub mod context;
pub mod crypto;
pub mod directives;
pub mod guards;
pub mod middleware;
pub mod schema;

pub use context::SecurityContext;
pub use middleware::{AuthLayer, AuditLayer, RateLimitLayer};
pub use schema::build_schema;
```

### src/main.rs

```rust
use anyhow::Result;
use axum::{Router, routing::get};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use my_graphql_security::{
    build_schema,
    middleware::{AuthLayer, AuditLayer, RateLimitLayer},
    SecurityContext,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Build GraphQL schema
    let schema = build_schema();

    // Build router with middleware
    let app = Router::new()
        .route("/graphql", get(graphql_playground).post(graphql_handler))
        .layer(CorsLayer::permissive())
        .layer(AuthLayer::new())
        .layer(AuditLayer::new())
        .layer(RateLimitLayer::new(100, 60)) // 100 requests per minute
        .with_state(schema);

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("GraphQL server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn graphql_playground() -> impl axum::response::IntoResponse {
    axum::response::Html(async_graphql::http::playground_source(
        async_graphql::http::GraphQLPlaygroundConfig::new("/graphql"),
    ))
}

async fn graphql_handler(
    axum::extract::State(schema): axum::extract::State<
        async_graphql::Schema<
            schema::QueryRoot,
            schema::MutationRoot,
            async_graphql::EmptySubscription,
        >,
    >,
    axum::Extension(security_ctx): axum::Extension<SecurityContext>,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let request = req.into_inner().data(security_ctx);
    schema.execute(request).await.into()
}
```

### src/schema/mod.rs

```rust
pub mod query;
pub mod mutation;

use async_graphql::{EmptySubscription, Schema};

pub use query::QueryRoot;
pub use mutation::MutationRoot;

pub type AppSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

pub fn build_schema() -> AppSchema {
    Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .extension(async_graphql::extensions::Tracing)
        .extension(async_graphql::extensions::ApolloTracing)
        .finish()
}
```

### src/context/mod.rs

```rust
pub mod security;

use chrono::{DateTime, Utc};
use std::collections::HashSet;
use uuid::Uuid;

/// Security context attached to each request
#[derive(Debug, Clone)]
pub struct SecurityContext {
    /// Request ID for tracing
    pub request_id: Uuid,

    /// Authenticated user ID (if any)
    pub user_id: Option<Uuid>,

    /// User roles
    pub roles: HashSet<String>,

    /// User permissions
    pub permissions: HashSet<String>,

    /// Request timestamp
    pub timestamp: DateTime<Utc>,

    /// Client IP address
    pub client_ip: Option<String>,

    /// Encryption key for field-level encryption
    pub encryption_key: Option<Vec<u8>>,
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self {
            request_id: Uuid::new_v4(),
            user_id: None,
            roles: HashSet::new(),
            permissions: HashSet::new(),
            timestamp: Utc::now(),
            client_ip: None,
            encryption_key: None,
        }
    }
}

impl SecurityContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_user(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles.into_iter().collect();
        self
    }

    pub fn with_permissions(mut self, permissions: Vec<String>) -> Self {
        self.permissions = permissions.into_iter().collect();
        self
    }

    pub fn with_encryption_key(mut self, key: Vec<u8>) -> Self {
        self.encryption_key = Some(key);
        self
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role)
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(permission)
    }

    pub fn is_authenticated(&self) -> bool {
        self.user_id.is_some()
    }
}
```

### src/guards/mod.rs

```rust
pub mod role;
pub mod field_access;

pub use role::RoleGuard;
pub use field_access::FieldAccessGuard;
```

### src/guards/role.rs

```rust
use async_graphql::{Context, Guard, Result};
use crate::context::SecurityContext;

/// Guard that requires specific roles
pub struct RoleGuard {
    roles: Vec<String>,
    require_all: bool,
}

impl RoleGuard {
    /// Require any of the specified roles
    pub fn any(roles: &[&str]) -> Self {
        Self {
            roles: roles.iter().map(|s| s.to_string()).collect(),
            require_all: false,
        }
    }

    /// Require all specified roles
    pub fn all(roles: &[&str]) -> Self {
        Self {
            roles: roles.iter().map(|s| s.to_string()).collect(),
            require_all: true,
        }
    }

    /// Require admin role
    pub fn admin() -> Self {
        Self::any(&["admin"])
    }
}

impl Guard for RoleGuard {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        let security_ctx = ctx.data::<SecurityContext>()?;

        if !security_ctx.is_authenticated() {
            return Err("Authentication required".into());
        }

        let has_access = if self.require_all {
            self.roles.iter().all(|r| security_ctx.has_role(r))
        } else {
            self.roles.iter().any(|r| security_ctx.has_role(r))
        };

        if !has_access {
            return Err(format!(
                "Required roles: {}",
                self.roles.join(", ")
            ).into());
        }

        Ok(())
    }
}

/// Guard that requires authentication
pub struct AuthGuard;

impl Guard for AuthGuard {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        let security_ctx = ctx.data::<SecurityContext>()?;

        if !security_ctx.is_authenticated() {
            return Err("Authentication required".into());
        }

        Ok(())
    }
}

/// Guard that requires specific permissions
pub struct PermissionGuard {
    permissions: Vec<String>,
}

impl PermissionGuard {
    pub fn new(permissions: &[&str]) -> Self {
        Self {
            permissions: permissions.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Guard for PermissionGuard {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        let security_ctx = ctx.data::<SecurityContext>()?;

        if !security_ctx.is_authenticated() {
            return Err("Authentication required".into());
        }

        let has_access = self.permissions.iter().any(|p| security_ctx.has_permission(p));

        if !has_access {
            return Err(format!(
                "Required permissions: {}",
                self.permissions.join(", ")
            ).into());
        }

        Ok(())
    }
}
```

### src/crypto/field_encryption.rs

```rust
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum FieldEncryptionError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid key")]
    InvalidKey,
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
}

/// Encrypt a field value
pub fn encrypt_field(plaintext: &str, key: &[u8]) -> Result<String, FieldEncryptionError> {
    if key.len() != 32 {
        return Err(FieldEncryptionError::InvalidKey);
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| FieldEncryptionError::InvalidKey)?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| FieldEncryptionError::EncryptionFailed)?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(base64::engine::general_purpose::STANDARD.encode(&result))
}

/// Decrypt a field value
pub fn decrypt_field(ciphertext: &str, key: &[u8]) -> Result<String, FieldEncryptionError> {
    if key.len() != 32 {
        return Err(FieldEncryptionError::InvalidKey);
    }

    let data = base64::engine::general_purpose::STANDARD
        .decode(ciphertext)
        .map_err(|_| FieldEncryptionError::InvalidCiphertext)?;

    if data.len() < 28 {
        return Err(FieldEncryptionError::InvalidCiphertext);
    }

    let (nonce_bytes, encrypted) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| FieldEncryptionError::InvalidKey)?;

    let plaintext = cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| FieldEncryptionError::DecryptionFailed)?;

    String::from_utf8(plaintext)
        .map_err(|_| FieldEncryptionError::DecryptionFailed)
}

/// Trait for types that can be encrypted/decrypted
pub trait FieldEncryptable {
    fn encrypt(&self, key: &[u8]) -> Result<String, FieldEncryptionError>;
    fn decrypt(ciphertext: &str, key: &[u8]) -> Result<Self, FieldEncryptionError>
    where
        Self: Sized;
}

impl FieldEncryptable for String {
    fn encrypt(&self, key: &[u8]) -> Result<String, FieldEncryptionError> {
        encrypt_field(self, key)
    }

    fn decrypt(ciphertext: &str, key: &[u8]) -> Result<Self, FieldEncryptionError> {
        decrypt_field(ciphertext, key)
    }
}
```

### src/middleware/auth.rs

```rust
use axum::{
    body::Body,
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tower::{Layer, Service};
use uuid::Uuid;

use crate::context::SecurityContext;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

#[derive(Clone)]
pub struct AuthLayer {
    secret: String,
}

impl AuthLayer {
    pub fn new() -> Self {
        Self {
            secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "development-secret-change-in-production".to_string()),
        }
    }

    pub fn with_secret(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
        }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware {
            inner,
            secret: self.secret.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    secret: String,
}

impl<S> Service<Request<Body>> for AuthMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let secret = self.secret.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Extract security context from JWT
            let security_ctx = extract_security_context(&req, &secret);

            // Add security context to request extensions
            req.extensions_mut().insert(security_ctx);

            inner.call(req).await
        })
    }
}

fn extract_security_context(req: &Request<Body>, secret: &str) -> SecurityContext {
    let mut ctx = SecurityContext::new();

    // Extract client IP
    ctx.client_ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string());

    // Extract and validate JWT
    if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                if let Ok(claims) = validate_jwt(token, secret) {
                    if let Ok(user_id) = Uuid::parse_str(&claims.sub) {
                        ctx = ctx.with_user(user_id);
                    }
                    ctx = ctx.with_roles(claims.roles);
                    ctx = ctx.with_permissions(claims.permissions);
                }
            }
        }
    }

    ctx
}

fn validate_jwt(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let validation = Validation::new(Algorithm::HS256);
    let token_data = decode::<Claims>(token, &key, &validation)?;
    Ok(token_data.claims)
}
```

### src/middleware/rate_limit.rs

```rust
use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    response::Response,
};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::{num::NonZeroU32, sync::Arc, time::Duration};
use tower::{Layer, Service};

#[derive(Clone)]
pub struct RateLimitLayer {
    limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
}

impl RateLimitLayer {
    pub fn new(requests: u32, per_seconds: u64) -> Self {
        let quota = Quota::with_period(Duration::from_secs(per_seconds))
            .unwrap()
            .allow_burst(NonZeroU32::new(requests).unwrap());

        Self {
            limiter: Arc::new(RateLimiter::direct(quota)),
        }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitMiddleware {
            inner,
            limiter: self.limiter.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RateLimitMiddleware<S> {
    inner: S,
    limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
}

impl<S> Service<Request<Body>> for RateLimitMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let limiter = self.limiter.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Check rate limit
            if limiter.check().is_err() {
                return Ok(Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .header("Retry-After", "60")
                    .body(Body::from("Rate limit exceeded"))
                    .unwrap());
            }

            inner.call(req).await
        })
    }
}

/// Per-user rate limiter for GraphQL operations
pub struct UserRateLimiter {
    limiters: dashmap::DashMap<String, Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>>,
    quota: Quota,
}

impl UserRateLimiter {
    pub fn new(requests: u32, per_seconds: u64) -> Self {
        Self {
            limiters: dashmap::DashMap::new(),
            quota: Quota::with_period(Duration::from_secs(per_seconds))
                .unwrap()
                .allow_burst(NonZeroU32::new(requests).unwrap()),
        }
    }

    pub fn check(&self, user_id: &str) -> bool {
        let limiter = self.limiters
            .entry(user_id.to_string())
            .or_insert_with(|| Arc::new(RateLimiter::direct(self.quota)));

        limiter.check().is_ok()
    }
}
```

### src/middleware/audit.rs

```rust
use axum::{
    body::Body,
    extract::Request,
    response::Response,
};
use chrono::Utc;
use serde::Serialize;
use tower::{Layer, Service};
use tracing::{info, warn};
use uuid::Uuid;

use crate::context::SecurityContext;

#[derive(Debug, Serialize)]
pub struct AuditLog {
    pub id: Uuid,
    pub timestamp: String,
    pub user_id: Option<Uuid>,
    pub client_ip: Option<String>,
    pub operation: String,
    pub path: String,
    pub status: u16,
    pub duration_ms: u64,
}

#[derive(Clone)]
pub struct AuditLayer;

impl AuditLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for AuditLayer {
    type Service = AuditMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuditMiddleware { inner }
    }
}

#[derive(Clone)]
pub struct AuditMiddleware<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for AuditMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let start = std::time::Instant::now();
        let path = req.uri().path().to_string();
        let method = req.method().to_string();

        // Extract security context if available
        let security_ctx = req
            .extensions()
            .get::<SecurityContext>()
            .cloned()
            .unwrap_or_default();

        let mut inner = self.inner.clone();

        Box::pin(async move {
            let response = inner.call(req).await?;
            let duration = start.elapsed();

            let audit_log = AuditLog {
                id: Uuid::new_v4(),
                timestamp: Utc::now().to_rfc3339(),
                user_id: security_ctx.user_id,
                client_ip: security_ctx.client_ip,
                operation: method,
                path,
                status: response.status().as_u16(),
                duration_ms: duration.as_millis() as u64,
            };

            // Log audit entry
            if response.status().is_success() {
                info!(
                    audit = serde_json::to_string(&audit_log).unwrap_or_default(),
                    "Request completed"
                );
            } else {
                warn!(
                    audit = serde_json::to_string(&audit_log).unwrap_or_default(),
                    "Request failed"
                );
            }

            Ok(response)
        })
    }
}
```

### src/schema/query.rs

```rust
use async_graphql::{Context, Object, Result, SimpleObject};
use uuid::Uuid;

use crate::context::SecurityContext;
use crate::crypto::field_encryption::decrypt_field;
use crate::guards::{RoleGuard, AuthGuard, PermissionGuard};

#[derive(SimpleObject)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[graphql(guard = "RoleGuard::admin()")]
    pub admin_notes: Option<String>,
}

#[derive(SimpleObject)]
pub struct SecureDocument {
    pub id: Uuid,
    pub title: String,
    /// Encrypted content - requires decryption key in context
    pub content: String,
}

pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Get current user (requires authentication)
    #[graphql(guard = "AuthGuard")]
    async fn me(&self, ctx: &Context<'_>) -> Result<User> {
        let security_ctx = ctx.data::<SecurityContext>()?;
        let user_id = security_ctx.user_id.ok_or("Not authenticated")?;

        // Fetch user from database (mock)
        Ok(User {
            id: user_id,
            email: "user@example.com".to_string(),
            admin_notes: None,
        })
    }

    /// Get user by ID (admin only)
    #[graphql(guard = "RoleGuard::admin()")]
    async fn user(&self, _ctx: &Context<'_>, id: Uuid) -> Result<User> {
        // Fetch user from database (mock)
        Ok(User {
            id,
            email: "user@example.com".to_string(),
            admin_notes: Some("Admin notes here".to_string()),
        })
    }

    /// Get encrypted document
    #[graphql(guard = "PermissionGuard::new(&[\"read:documents\"])")]
    async fn document(&self, ctx: &Context<'_>, id: Uuid) -> Result<SecureDocument> {
        let security_ctx = ctx.data::<SecurityContext>()?;

        // Fetch encrypted document from database (mock)
        let encrypted_content = "base64-encrypted-content-here";

        // Decrypt if key is available
        let content = if let Some(key) = &security_ctx.encryption_key {
            decrypt_field(encrypted_content, key)
                .unwrap_or_else(|_| "[Decryption failed]".to_string())
        } else {
            "[Encrypted - key required]".to_string()
        };

        Ok(SecureDocument {
            id,
            title: "Secure Document".to_string(),
            content,
        })
    }

    /// List documents with pagination
    #[graphql(guard = "AuthGuard")]
    async fn documents(
        &self,
        _ctx: &Context<'_>,
        #[graphql(default = 10)] limit: i32,
        #[graphql(default = 0)] offset: i32,
    ) -> Result<Vec<SecureDocument>> {
        // Validate pagination
        if limit < 1 || limit > 100 {
            return Err("Limit must be between 1 and 100".into());
        }
        if offset < 0 {
            return Err("Offset must be non-negative".into());
        }

        // Fetch documents from database (mock)
        Ok(vec![])
    }
}
```

### src/schema/mutation.rs

```rust
use async_graphql::{Context, InputObject, Object, Result, SimpleObject};
use uuid::Uuid;
use validator::Validate;

use crate::context::SecurityContext;
use crate::crypto::field_encryption::encrypt_field;
use crate::guards::{AuthGuard, PermissionGuard};

#[derive(InputObject, Validate)]
pub struct CreateDocumentInput {
    #[validate(length(min = 1, max = 255))]
    pub title: String,
    #[validate(length(min = 1, max = 65536))]
    pub content: String,
}

#[derive(SimpleObject)]
pub struct CreateDocumentPayload {
    pub success: bool,
    pub document_id: Option<Uuid>,
    pub error: Option<String>,
}

pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Create a new encrypted document
    #[graphql(guard = "PermissionGuard::new(&[\"write:documents\"])")]
    async fn create_document(
        &self,
        ctx: &Context<'_>,
        input: CreateDocumentInput,
    ) -> Result<CreateDocumentPayload> {
        // Validate input
        if let Err(errors) = input.validate() {
            return Ok(CreateDocumentPayload {
                success: false,
                document_id: None,
                error: Some(format!("Validation failed: {:?}", errors)),
            });
        }

        let security_ctx = ctx.data::<SecurityContext>()?;

        // Encrypt content before storing
        let encrypted_content = if let Some(key) = &security_ctx.encryption_key {
            encrypt_field(&input.content, key)
                .map_err(|e| async_graphql::Error::new(format!("Encryption failed: {}", e)))?
        } else {
            return Ok(CreateDocumentPayload {
                success: false,
                document_id: None,
                error: Some("Encryption key required".to_string()),
            });
        };

        // Store document in database (mock)
        let document_id = Uuid::new_v4();

        // Audit log
        tracing::info!(
            user_id = ?security_ctx.user_id,
            document_id = %document_id,
            "Document created"
        );

        Ok(CreateDocumentPayload {
            success: true,
            document_id: Some(document_id),
            error: None,
        })
    }

    /// Delete a document
    #[graphql(guard = "PermissionGuard::new(&[\"delete:documents\"])")]
    async fn delete_document(
        &self,
        ctx: &Context<'_>,
        id: Uuid,
    ) -> Result<bool> {
        let security_ctx = ctx.data::<SecurityContext>()?;

        // Check ownership or admin role
        // ... ownership check logic ...

        // Delete document (mock)
        tracing::info!(
            user_id = ?security_ctx.user_id,
            document_id = %id,
            "Document deleted"
        );

        Ok(true)
    }
}
```

## Testing

### tests/auth_tests.rs

```rust
use my_graphql_security::{
    context::SecurityContext,
    guards::{RoleGuard, AuthGuard},
};
use async_graphql::{EmptyMutation, EmptySubscription, Object, Schema};
use uuid::Uuid;

struct TestQuery;

#[Object]
impl TestQuery {
    #[graphql(guard = "AuthGuard")]
    async fn protected(&self) -> &str {
        "protected data"
    }

    #[graphql(guard = "RoleGuard::admin()")]
    async fn admin_only(&self) -> &str {
        "admin data"
    }
}

#[tokio::test]
async fn test_auth_guard_blocks_unauthenticated() {
    let schema = Schema::new(TestQuery, EmptyMutation, EmptySubscription);

    let ctx = SecurityContext::new();
    let result = schema
        .execute(async_graphql::Request::new("{ protected }").data(ctx))
        .await;

    assert!(result.errors.len() > 0);
}

#[tokio::test]
async fn test_auth_guard_allows_authenticated() {
    let schema = Schema::new(TestQuery, EmptyMutation, EmptySubscription);

    let ctx = SecurityContext::new().with_user(Uuid::new_v4());
    let result = schema
        .execute(async_graphql::Request::new("{ protected }").data(ctx))
        .await;

    assert!(result.errors.is_empty());
}

#[tokio::test]
async fn test_role_guard_blocks_non_admin() {
    let schema = Schema::new(TestQuery, EmptyMutation, EmptySubscription);

    let ctx = SecurityContext::new()
        .with_user(Uuid::new_v4())
        .with_roles(vec!["user".to_string()]);

    let result = schema
        .execute(async_graphql::Request::new("{ adminOnly }").data(ctx))
        .await;

    assert!(result.errors.len() > 0);
}

#[tokio::test]
async fn test_role_guard_allows_admin() {
    let schema = Schema::new(TestQuery, EmptyMutation, EmptySubscription);

    let ctx = SecurityContext::new()
        .with_user(Uuid::new_v4())
        .with_roles(vec!["admin".to_string()]);

    let result = schema
        .execute(async_graphql::Request::new("{ adminOnly }").data(ctx))
        .await;

    assert!(result.errors.is_empty());
}
```

## Row Level Security (PostgreSQL)

RLS must be enforced at the database layer on all tables queried by GraphQL
resolvers. This prevents cross-user data leakage even if a resolver has a
missing authorization guard.

```sql
-- migrations/001_rls.sql
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;

CREATE POLICY documents_user_isolation ON documents
    FOR ALL TO app_user
    USING (owner_id = current_setting('app.current_user_id')::uuid);

-- Admins may read all rows via a separate high-privilege DB role,
-- NOT by disabling RLS.
```

```rust
// src/db/rls.rs — called inside every resolver that touches user data
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub async fn set_rls_context(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> async_graphql::Result<()> {
    sqlx::query("SELECT set_config('app.current_user_id', $1, true)")
        .bind(user_id.to_string())
        .execute(tx.as_mut())
        .await
        .map_err(|e| async_graphql::Error::new(format!("RLS context error: {}", e)))?;
    Ok(())
}
```

```rust
// src/schema/query.rs — resolver usage
#[graphql(guard = "AuthGuard")]
async fn documents(&self, ctx: &Context<'_>) -> Result<Vec<SecureDocument>> {
    let security_ctx = ctx.data::<SecurityContext>()?;
    let user_id = security_ctx.user_id.ok_or("Not authenticated")?;
    let pool = ctx.data::<sqlx::PgPool>()?;

    let mut tx = pool.begin().await?;
    set_rls_context(&mut tx, user_id).await?;

    // RLS policy filters rows — no WHERE owner_id clause needed in SQL
    let docs = sqlx::query_as::<_, SecureDocument>(
        "SELECT id, title, content FROM documents"
    )
    .fetch_all(tx.as_mut())
    .await?;

    tx.commit().await?;
    Ok(docs)
}
```

## Security Checklist

- [ ] PostgreSQL RLS enabled (`ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY`) on all user/tenant tables
- [ ] `set_rls_context` called at the start of every transaction in user-scoped resolvers
- [ ] Admin access uses a separate DB role with elevated privileges, not by bypassing RLS
- [ ] JWT tokens validated with proper algorithm
- [ ] Role-based access control on all sensitive resolvers
- [ ] Field-level encryption for sensitive data
- [ ] Rate limiting configured per user and globally
- [ ] Audit logging for all mutations
- [ ] Input validation on all inputs
- [ ] Query depth limiting enabled
- [ ] Query complexity limiting enabled
- [ ] Introspection disabled in production
- [ ] Error messages don't leak sensitive information
- [ ] CORS configured appropriately
- [ ] HTTPS enforced
