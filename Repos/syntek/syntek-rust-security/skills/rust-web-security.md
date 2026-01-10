# Rust Web Security Skills

This skill provides security analysis and best practices for Rust web applications built with Actix, Rocket, Axum, and other frameworks.

## Overview

Web application security for Rust frameworks including:
- **Actix Web**: Actor-based framework
- **Rocket**: Type-safe routing
- **Axum**: Tokio-based async framework
- **Warp**: Composable web framework

## Common Web Security Concerns

### 1. Authentication & Authorization

#### JWT Authentication (Actix Web)
```rust
use actix_web::{web, HttpRequest, Error};
use jsonwebtoken::{decode, DecodingKey, Validation};

async fn protected_route(req: HttpRequest) -> Result<String, Error> {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| Error::Unauthorized)?;

    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(SECRET),
        &Validation::default()
    ).map_err(|_| Error::Unauthorized)?;

    // Verify claims
    Ok("Protected content".to_string())
}
```

#### Role-Based Access Control
```rust
use axum::{
    middleware,
    extract::Extension,
    http::{Request, StatusCode},
};

async fn require_role<B>(
    Extension(user): Extension<User>,
    req: Request<B>,
    next: middleware::Next<B>,
) -> Result<Response, StatusCode> {
    if user.has_role("admin") {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}
```

### 2. SQL Injection Prevention

```rust
use sqlx::{PgPool, query_as};

// ✅ SECURE: Parameterized queries
async fn get_user(pool: &PgPool, username: &str) -> Result<User, Error> {
    query_as!(
        User,
        "SELECT * FROM users WHERE username = $1",
        username
    )
    .fetch_one(pool)
    .await
}

// ❌ VULNERABLE: String interpolation
async fn get_user_unsafe(pool: &PgPool, username: &str) -> Result<User, Error> {
    let query = format!("SELECT * FROM users WHERE username = '{}'", username);
    // DON'T DO THIS!
}
```

### 3. XSS Prevention

#### Template Escaping (Askama)
```rust
use askama::Template;

#[derive(Template)]
#[template(path = "user.html")]
struct UserTemplate {
    name: String,  // Automatically HTML-escaped
    bio: String,
}

// Template (user.html):
// <h1>{{ name }}</h1>
// <p>{{ bio }}</p>
```

#### API Responses (Serde)
```rust
use serde::Serialize;

#[derive(Serialize)]
struct ApiResponse {
    message: String,  // JSON-encoded, safe from XSS
}

// Returns JSON, not HTML
async fn api_handler() -> Json<ApiResponse> {
    Json(ApiResponse {
        message: user_input.to_string()
    })
}
```

### 4. CSRF Protection

```rust
use actix_web::{web, HttpResponse, HttpRequest};
use csrf::{CsrfToken, CsrfMiddleware};

async fn form_page(csrf_token: CsrfToken) -> HttpResponse {
    let token = csrf_token.token();
    HttpResponse::Ok().body(format!(
        r#"<form method="POST">
            <input type="hidden" name="csrf_token" value="{}" />
            <button type="submit">Submit</button>
        </form>"#,
        token
    ))
}

async fn form_handler(
    form: web::Form<FormData>,
    csrf_token: CsrfToken,
) -> Result<HttpResponse, Error> {
    csrf_token.verify(&form.csrf_token)?;
    // Process form
    Ok(HttpResponse::Ok().finish())
}
```

### 5. Input Validation

```rust
use validator::{Validate, ValidationError};

#[derive(Debug, Validate, Deserialize)]
struct RegisterForm {
    #[validate(email)]
    email: String,

    #[validate(length(min = 8, max = 100))]
    password: String,

    #[validate(length(min = 2, max = 50))]
    username: String,
}

async fn register(
    form: web::Json<RegisterForm>
) -> Result<HttpResponse, Error> {
    form.validate()
        .map_err(|e| Error::BadRequest(e))?;

    // Process registration
    Ok(HttpResponse::Ok().finish())
}
```

### 6. Secure Headers

```rust
use actix_web::{middleware, HttpResponse};

// Security headers middleware
fn security_headers() -> middleware::DefaultHeaders {
    middleware::DefaultHeaders::new()
        .add(("X-Content-Type-Options", "nosniff"))
        .add(("X-Frame-Options", "DENY"))
        .add(("X-XSS-Protection", "1; mode=block"))
        .add(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
        .add(("Content-Security-Policy", "default-src 'self'"))
}

// In main:
App::new()
    .wrap(security_headers())
```

### 7. Rate Limiting

```rust
use actix_limitation::{Limiter, RateLimiter};
use actix_web::{web, App};

#[actix_web::main]
async fn main() {
    let limiter = Limiter::builder("redis://127.0.0.1")
        .limit(100)  // 100 requests
        .period(Duration::from_secs(60))  // per minute
        .build()
        .unwrap();

    App::new()
        .app_data(web::Data::new(limiter.clone()))
        .wrap(RateLimiter::default())
}
```

### 8. Password Hashing

```rust
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2
};
use rand::rngs::OsRng;

fn hash_password(password: &str) -> Result<String, Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

fn verify_password(password: &str, hash: &str) -> Result<bool, Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    let argon2 = Argon2::default();

    Ok(argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}
```

## OWASP Top 10 for Rust Web Apps

### A01: Broken Access Control
- ✅ Implement RBAC middleware
- ✅ Verify user permissions on every request
- ✅ Use type-safe session management

### A02: Cryptographic Failures
- ✅ Use Argon2 for password hashing
- ✅ HTTPS/TLS for all traffic
- ✅ Secure cookie flags (HttpOnly, Secure, SameSite)

### A03: Injection
- ✅ Parameterized queries (sqlx, diesel)
- ✅ Template escaping (askama, tera)
- ✅ Input validation

### A04: Insecure Design
- ✅ Security requirements in design
- ✅ Threat modeling
- ✅ Secure defaults

### A05: Security Misconfiguration
- ✅ Security headers
- ✅ Disable debug in production
- ✅ Error messages don't leak info

### A06: Vulnerable Components
- ✅ cargo-audit for dependencies
- ✅ Keep dependencies updated
- ✅ Monitor RustSec advisories

### A07: Authentication Failures
- ✅ MFA support
- ✅ Strong password policy
- ✅ Rate limiting on login

### A08: Data Integrity Failures
- ✅ Verify signatures
- ✅ CSRF protection
- ✅ Secure deserialization

### A09: Logging Failures
- ✅ Log security events
- ✅ Don't log sensitive data
- ✅ Tamper-proof logs

### A10: SSRF
- ✅ Validate URLs
- ✅ Whitelist allowed hosts
- ✅ Use network policies

## Framework-Specific Guides

### Actix Web Security
```rust
use actix_web::{App, middleware};

App::new()
    .wrap(middleware::Logger::default())
    .wrap(security_headers())
    .wrap(RateLimiter::default())
    .wrap(CsrfMiddleware::new())
    .service(routes)
```

### Rocket Security
```rust
use rocket::{routes, fairing::AdHoc};

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(AdHoc::on_response("Security Headers", |_, res| {
            Box::pin(async move {
                res.set_raw_header("X-Frame-Options", "DENY");
            })
        }))
        .mount("/", routes![index])
}
```

### Axum Security
```rust
use axum::{Router, middleware};
use tower_http::limit::RequestBodyLimitLayer;

let app = Router::new()
    .route("/", get(handler))
    .layer(middleware::from_fn(auth_middleware))
    .layer(RequestBodyLimitLayer::new(1024 * 1024))  // 1MB limit
    .layer(security_headers_layer());
```

## Security Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;

    #[actix_web::test]
    async fn test_sql_injection() {
        let app = test::init_service(create_app()).await;

        // Test SQL injection attempt
        let req = test::TestRequest::get()
            .uri("/user?id=1' OR '1'='1")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);  // Should reject
    }

    #[actix_web::test]
    async fn test_csrf_protection() {
        // Verify CSRF token required
    }
}
```

## Best Practices

1. **Always use parameterized queries** - Prevent SQL injection
2. **Hash passwords with Argon2** - Never MD5/SHA256
3. **Enable HTTPS/TLS** - Use rustls or native-tls
4. **Set security headers** - CSP, HSTS, X-Frame-Options
5. **Validate all input** - Use validator crate
6. **Implement CSRF protection** - For state-changing operations
7. **Rate limit endpoints** - Prevent abuse
8. **Log security events** - Authentication, authorization failures
9. **Keep dependencies updated** - Run cargo-audit regularly
10. **Use framework security features** - Don't roll your own
