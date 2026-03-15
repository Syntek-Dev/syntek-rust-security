# API Design — my-security-project

**Last Updated:** 15/03/2026
**Version:** 1.0.0
**Maintained By:** Development Team

API design conventions and patterns for this project.

---

## Principles

- APIs are domain contracts, not schema mirrors. Model your domain first;
  derive the HTTP interface from that.
- Fail explicitly. Return a typed error with a machine-readable code, never a
  bare string or a 200 with an error body.
- Least privilege by default. Endpoints require authentication unless explicitly
  marked public. Never expose more data than the caller needs.
- Validate all input at the boundary. Trust nothing from the network.
- Never leak internal details in error responses — stack traces, SQL errors, and
  file paths are all information for attackers.

---

## REST API Conventions

### URL Structure

```
/api/v1/<resource>
/api/v1/<resource>/{id}
/api/v1/<resource>/{id}/<sub-resource>
```

- Use plural nouns: `/api/v1/users`, not `/api/v1/user`
- Use kebab-case for multi-word resources: `/api/v1/audit-events`
- Version prefix (`/api/v1/`) on all routes; never change a versioned URL

### HTTP Methods

| Method   | Semantics                          | Body  | Idempotent |
| -------- | ---------------------------------- | ----- | ---------- |
| `GET`    | Retrieve a resource or collection  | No    | Yes        |
| `POST`   | Create a resource                  | Yes   | No         |
| `PUT`    | Replace a resource (full update)   | Yes   | Yes        |
| `PATCH`  | Partial update                     | Yes   | No         |
| `DELETE` | Remove a resource                  | No    | Yes        |

### Status Codes

| Code  | Meaning                                          |
| ----- | ------------------------------------------------ |
| `200` | OK — successful GET, PATCH, PUT                  |
| `201` | Created — POST that creates a resource           |
| `204` | No Content — DELETE or action with no body       |
| `400` | Bad Request — invalid input, validation failure  |
| `401` | Unauthorised — missing or invalid credentials    |
| `403` | Forbidden — authenticated but not authorised     |
| `404` | Not Found — resource does not exist              |
| `409` | Conflict — duplicate or state conflict           |
| `422` | Unprocessable Entity — semantic validation error |
| `429` | Too Many Requests — rate limited                 |
| `500` | Internal Server Error — unexpected failure       |

### Request and Response Shapes

Use `serde` for JSON serialisation. Wrap all responses in a consistent envelope:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub data: T,
}

#[derive(Debug, Serialize)]
pub struct ApiListResponse<T: Serialize> {
    pub data: Vec<T>,
    pub pagination: PaginationMeta,
}

#[derive(Debug, Serialize)]
pub struct PaginationMeta {
    pub cursor: Option<String>,
    pub has_more: bool,
    pub total: Option<i64>,
}
```

**Naming in JSON:** `snake_case` for field names (consistent with Rust; Axum
and serde default).

### Pagination

Prefer cursor-based pagination for large collections. Offset pagination is
acceptable for small, bounded datasets.

```rust
#[derive(Debug, Deserialize)]
pub struct CursorPaginationParams {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

// Default and maximum page sizes
const DEFAULT_PAGE_SIZE: u32 = 20;
const MAX_PAGE_SIZE: u32 = 100;
```

### Filtering and Sorting

Accept filter and sort parameters as query strings. Use `serde_qs` for complex
nested structures, or manual extraction via Axum's `Query<T>`.

```rust
use axum::extract::Query;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct UserListParams {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub sort_by: Option<UserSortField>,
    pub sort_dir: Option<SortDirection>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserSortField {
    CreatedAt,
    Name,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortDirection {
    Asc,
    Desc,
}
```

---

## Error Response Format

Define error types with `thiserror`. Never include stack traces, internal paths,
or database query details in responses.

```rust
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("resource not found")]
    NotFound,
    #[error("validation failed: {field}")]
    Validation { field: String, message: String },
    #[error("authentication required")]
    Unauthenticated,
    #[error("insufficient permissions")]
    Forbidden,
    #[error("rate limit exceeded")]
    RateLimited,
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug, serde::Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<String>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message, field) = match &self {
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found", "Resource not found".to_string(), None),
            ApiError::Validation { field, message } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "validation_error",
                message.clone(),
                Some(field.clone()),
            ),
            ApiError::Unauthenticated => (StatusCode::UNAUTHORIZED, "unauthenticated", "Authentication required".to_string(), None),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "forbidden", "Insufficient permissions".to_string(), None),
            ApiError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Rate limit exceeded".to_string(), None),
            ApiError::Internal(err) => {
                // Log the real error; return a generic message to the caller
                tracing::error!(error = %err, "internal server error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "An unexpected error occurred".to_string(), None)
            }
        };

        let body = ErrorBody { code, message, field };
        (status, Json(body)).into_response()
    }
}
```

---

## Authentication

Use Bearer token middleware via a `tower::Layer`. API keys go in the
`X-API-Key` header for machine-to-machine access.

```rust
use axum::{extract::State, http::{HeaderMap, StatusCode}};
use std::sync::Arc;

// Bearer token extraction — return 401, never 403, for missing credentials
pub async fn require_auth(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, ApiError> {
    let token = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthenticated)?;

    let _claims = state.verify_token(token).await.map_err(|_| ApiError::Unauthenticated)?;
    Ok(next.run(request).await)
}
```

**Security rules:**
- Compare tokens with `subtle::ConstantTimeEq` to prevent timing attacks
- Invalidate tokens server-side on logout (do not rely on expiry alone)
- Use short-lived JWTs (TTL ≤ 15 minutes) with refresh token rotation
- Log all authentication failures at `WARN` level

---

## Rate Limiting

Use `tower_governor` for token bucket rate limiting, or implement a custom
`tower::Layer` against Redis for distributed rate limiting.

```rust
use tower_governor::{GovernorConfigBuilder, GovernorLayer};

let governor_config = GovernorConfigBuilder::default()
    .per_second(10)
    .burst_size(30)
    .finish()
    .expect("invalid governor config");

let app = Router::new()
    .route("/api/v1/users", get(list_users))
    .layer(GovernorLayer {
        config: Arc::new(governor_config),
    });
```

Return `429 Too Many Requests` with a `Retry-After` header.

---

## Versioning

URL-based versioning only: `/api/v1/`, `/api/v2/`. Never use `Accept` header
versioning — it is harder to observe, test, and proxy.

Maintain a previous version for at least one major release cycle. Mark
deprecated endpoints with a `Deprecation` response header.

---

## Webhooks

Sign all webhook payloads with HMAC-SHA256 using the `hmac` and `sha2` crates.
Include the signature in the `X-Webhook-Signature` header.

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn sign_webhook_payload(secret: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC accepts any key length");
    mac.update(payload);
    mac.finalize().into_bytes().to_vec()
}

pub fn verify_webhook_signature(
    secret: &[u8],
    payload: &[u8],
    provided_sig: &[u8],
) -> bool {
    use subtle::ConstantTimeEq;
    let expected = sign_webhook_payload(secret, payload);
    expected.ct_eq(provided_sig).into()
}
```

**Security rules:**
- Verify the signature before processing the payload
- Use constant-time comparison — never `==` on byte slices
- Include a timestamp in the payload and reject events older than 5 minutes
  to prevent replay attacks

---

## API Documentation

Use `utoipa` for OpenAPI 3.0 / Swagger documentation, or `aide` for Axum-native
schema generation.

```rust
use utoipa::{OpenApi, ToSchema};

#[derive(ToSchema, serde::Serialize)]
pub struct UserResponse {
    pub id: String,
    pub name: String,
    pub created_at: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/users/{id}",
    responses(
        (status = 200, description = "User found", body = UserResponse),
        (status = 404, description = "User not found"),
    ),
    params(("id" = String, Path, description = "User ID")),
)]
pub async fn get_user(/* ... */) -> impl IntoResponse {
    // ...
}
```

---

## HTTP Client Patterns

Use `reqwest` for outbound HTTP calls (AI provider APIs, Vault, Cloudflare,
etc.). Configure timeouts explicitly; never use defaults.

```rust
use reqwest::Client;
use std::time::Duration;

pub fn build_http_client() -> Client {
    Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(10)
        .https_only(true)
        .build()
        .expect("failed to build HTTP client")
}
```

**Rules:**
- Always set a connection timeout and a total request timeout
- Enable `https_only(true)` — never allow downgrade to plain HTTP
- Re-use a single `Client` instance per service (connection pool)
- Log request failures at `WARN`; never log request bodies that may contain secrets

---

## gRPC with tonic

Use gRPC when low-latency, strongly typed, binary protocol communication is
required (e.g., inter-service calls within a trusted network).

```rust
use tonic::{transport::Server, Request, Response, Status};

// Define service in a .proto file; generate Rust code with tonic-build
// in build.rs:
//   tonic_build::compile_protos("proto/service.proto")?;

pub struct MyService;

#[tonic::async_trait]
impl my_proto::my_service_server::MyService for MyService {
    async fn process(
        &self,
        request: Request<my_proto::ProcessRequest>,
    ) -> Result<Response<my_proto::ProcessResponse>, Status> {
        let req = request.into_inner();
        // Validate input — Status::invalid_argument for bad input
        if req.payload.is_empty() {
            return Err(Status::invalid_argument("payload must not be empty"));
        }
        Ok(Response::new(my_proto::ProcessResponse { /* ... */ }))
    }
}
```

**Rules:**
- Use TLS for all gRPC connections outside localhost
- Validate all fields in the request message — protobuf defaults are not safe
- Return appropriate `Status` codes: `NOT_FOUND`, `UNAUTHENTICATED`, `PERMISSION_DENIED`

---

## Axum Router Construction

Organise routes by resource. Group middleware by scope.

```rust
use axum::{middleware, Router};
use std::sync::Arc;

pub fn build_router(state: Arc<AppState>) -> Router {
    let public_routes = Router::new()
        .route("/api/v1/health", get(health_check))
        .route("/api/v1/auth/token", post(issue_token));

    let protected_routes = Router::new()
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/users/:id", get(get_user).patch(update_user).delete(delete_user))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(state)
}
```

---

## Tower Middleware Stack

Order matters. Outer layers wrap inner layers — the first layer added is the
outermost.

```rust
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    request_id::{MakeRequestUuid, SetRequestIdLayer, PropagateRequestIdLayer},
    trace::TraceLayer,
};

let app = Router::new()
    /* routes */
    .layer(
        ServiceBuilder::new()
            // Outermost: assign a request ID before any logging
            .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
            // Structured tracing — logs request/response with request_id
            .layer(TraceLayer::new_for_http())
            // Propagate the request ID to response headers
            .layer(PropagateRequestIdLayer::x_request_id())
            // CORS (evaluated before auth middleware)
            .layer(CorsLayer::permissive()),
    );
```

**Recommended order (outer → inner):**

1. `SetRequestIdLayer` — assign correlation ID
2. `TraceLayer` — structured request/response logging
3. `PropagateRequestIdLayer` — echo ID in response
4. `CorsLayer` — CORS headers
5. Auth middleware — reject unauthenticated requests
6. Rate limiting — reject overloaded requests

---

## API Design Checklist

- [ ] All endpoints require authentication unless explicitly marked public
- [ ] Input validated at the handler boundary before entering domain logic
- [ ] Error responses use typed `ApiError`, never raw strings or 200 + error body
- [ ] No internal detail (SQL error, file path, stack trace) in error responses
- [ ] Secrets compared with `subtle::ConstantTimeEq`
- [ ] HTTP client has explicit connect and request timeouts set
- [ ] Webhook signatures verified with constant-time comparison
- [ ] Rate limiting applied to all public-facing endpoints
- [ ] Pagination applied to all list endpoints (no unbounded queries)
- [ ] OpenAPI documentation generated for all endpoints
- [ ] All routes covered by integration tests (happy path, 401, 404, 422)
