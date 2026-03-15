# Data Structures — my-security-project

**Last Updated:** 15/03/2026
**Version:** 1.0.0
**Maintained By:** Development Team

Data structure selection, domain modelling patterns, and anti-patterns for
this project.

---

## Principle

Choose the right data structure and the algorithm becomes obvious (Rob Pike
Rule 5, Linus Torvalds Rule 1). Spend time here before writing any logic.

---

## Standard Collections

### `Vec<T>`

Ordered, growable, contiguous memory. The default choice.

- O(1) amortised push to the end
- O(n) insert or remove from the middle
- O(1) random access by index
- Best cache performance of any collection

Use when: order matters, or you need random access by position.

```rust
let mut events: Vec<AuditEvent> = Vec::with_capacity(64);
events.push(AuditEvent::new("login", user_id));
```

### `VecDeque<T>`

Double-ended queue backed by a ring buffer.

- O(1) push/pop at both the front and back
- Use instead of `Vec` when you need to remove from the front

```rust
use std::collections::VecDeque;

let mut work_queue: VecDeque<Job> = VecDeque::new();
work_queue.push_back(new_job);
let next = work_queue.pop_front();
```

### `HashMap<K, V>`

O(1) average lookup and insert. Keys are unordered.

- Use when key ordering is not required
- Default hasher (`SipHash`) is not the fastest but is DoS-resistant
- Use `ahash::AHashMap` when performance is critical and inputs are trusted

```rust
use std::collections::HashMap;

let mut sessions: HashMap<SessionId, Session> = HashMap::new();
sessions.insert(session_id, session);
```

### `BTreeMap<K, V>`

O(log n) lookup and insert. Keys are always sorted.

- Use when you need sorted iteration or range queries
- Better cache performance than a linked-list tree; worse than `HashMap`

```rust
use std::collections::BTreeMap;

// Sorted by timestamp for ordered log retrieval
let mut audit_log: BTreeMap<Timestamp, AuditEntry> = BTreeMap::new();

// Range query: entries in the last hour
let recent = audit_log.range(one_hour_ago..);
```

### `HashSet<T>` / `BTreeSet<T>`

Uniqueness guarantees. Backed by `HashMap` and `BTreeMap` respectively.

```rust
use std::collections::HashSet;

let mut seen_ips: HashSet<IpAddr> = HashSet::new();
if !seen_ips.insert(source_ip) {
    tracing::warn!(ip = %source_ip, "duplicate request from IP");
}
```

---

## Shared Ownership and Interior Mutability

### `Arc<T>`

Atomically reference-counted shared ownership across threads. Use in
`AppState` and anywhere a value must outlive a single owner.

```rust
use std::sync::Arc;

// Share the database pool across handlers
let pool: Arc<sqlx::PgPool> = Arc::new(pool);
```

### `Mutex<T>` and `RwLock<T>`

Interior mutability for shared mutable state.

- `Mutex<T>` — exclusive access; use for write-heavy state
- `RwLock<T>` — shared read access, exclusive write; use for read-heavy state

```rust
use std::sync::{Arc, RwLock};

let cache: Arc<RwLock<HashMap<String, CachedValue>>> =
    Arc::new(RwLock::new(HashMap::new()));

// Read path (multiple readers allowed)
let value = cache.read().unwrap().get(&key).cloned();

// Write path (exclusive)
cache.write().unwrap().insert(key, new_value);
```

**Important:** Never hold a lock across an `.await` point. Use
`tokio::sync::Mutex` or `tokio::sync::RwLock` in async code.

### `tokio::sync::RwLock`

Async-aware read/write lock. Correct choice for shared mutable state in async
code.

```rust
use tokio::sync::RwLock;
use std::sync::Arc;

let state: Arc<RwLock<AppCache>> = Arc::new(RwLock::new(AppCache::new()));

// In an async handler:
let read_guard = state.read().await;
let value = read_guard.lookup(&key);
drop(read_guard); // Release before any .await
```

### `dashmap::DashMap`

Concurrent `HashMap` with fine-grained sharding. Better throughput than
`RwLock<HashMap>` under high contention.

```rust
use dashmap::DashMap;
use std::sync::Arc;

let rate_limits: Arc<DashMap<IpAddr, RateLimitState>> =
    Arc::new(DashMap::new());

// Safe concurrent access — no explicit locking required
rate_limits.insert(source_ip, RateLimitState::new());
if let Some(mut state) = rate_limits.get_mut(&source_ip) {
    state.increment();
}
```

---

## Choosing the Right Structure

| Need                              | Use                           |
| --------------------------------- | ----------------------------- |
| Ordered list, random access       | `Vec<T>`                      |
| Queue (FIFO) or deque             | `VecDeque<T>`                 |
| Fast key lookup, order irrelevant | `HashMap<K, V>`               |
| Sorted keys, range queries        | `BTreeMap<K, V>`              |
| Uniqueness guarantee              | `HashSet<T>` / `BTreeSet<T>`  |
| Shared ownership (single thread)  | `Rc<T>`                       |
| Shared ownership (multi-thread)   | `Arc<T>`                      |
| Shared mutable state (sync)       | `Arc<Mutex<T>>`               |
| Read-heavy shared state (sync)    | `Arc<RwLock<T>>`              |
| Read-heavy shared state (async)   | `Arc<tokio::sync::RwLock<T>>` |
| High-concurrency map              | `Arc<DashMap<K, V>>`          |

---

## Domain Modelling

### Structs with Private Fields

Keep fields private. Provide a constructor that enforces invariants.

```rust
pub struct User {
    id: UserId,
    name: String,
    email: Email,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl User {
    pub fn new(name: String, email: Email) -> Result<Self, ValidationError> {
        if name.is_empty() {
            return Err(ValidationError::EmptyName);
        }
        Ok(User {
            id: UserId::generate(),
            name,
            email,
            created_at: chrono::Utc::now(),
        })
    }
}
```

### Newtype Pattern

Wrap primitive types to prevent confusion and enforce domain semantics. A
`UserId` and an `OrderId` are both `Uuid`s, but they are not interchangeable.

```rust
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OrderId(pub Uuid);

impl UserId {
    pub fn generate() -> Self {
        UserId(Uuid::new_v4())
    }

    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        Ok(UserId(s.parse()?))
    }
}

// The compiler prevents mixing up IDs
fn get_order(user: UserId, order: OrderId) { /* ... */ }
// get_order(order_id, user_id); // compile error
```

**Use newtypes for:**
- All ID types (`UserId`, `SessionId`, `TokenId`)
- Validated strings (`Email`, `Url`, `Hostname`)
- Security-sensitive types (`ApiKey`, `HashedPassword`)
- Units of measure (`Milliseconds`, `Bytes`)

### Enums as State Machines and Algebraic Types

Use enums to make illegal states unrepresentable.

```rust
// State machine — each variant carries only the data relevant to that state
pub enum ConnectionState {
    Connecting { attempt: u32, started_at: std::time::Instant },
    Connected { session_id: SessionId, established_at: std::time::Instant },
    Disconnecting { reason: DisconnectReason },
    Failed { error: ConnectionError, last_attempt: std::time::Instant },
}

// Algebraic type — replace Option<bool> with an explicit enum
pub enum AuditDecision {
    Allow,
    Deny { reason: DenyReason },
    Defer { review_by: chrono::DateTime<chrono::Utc> },
}
```

### Builder Pattern

Use the builder pattern for structs with many optional fields. Use
`derive_builder` or implement manually.

```rust
use derive_builder::Builder;

#[derive(Debug, Builder)]
#[builder(setter(into), build_fn(validate = "Self::validate"))]
pub struct RequestConfig {
    pub url: String,
    #[builder(default = "30")]
    pub timeout_secs: u64,
    #[builder(default = "3")]
    pub max_retries: u32,
    #[builder(default)]
    pub headers: Vec<(String, String)>,
}

impl RequestConfigBuilder {
    fn validate(&self) -> Result<(), String> {
        if let Some(url) = &self.url {
            if !url.starts_with("https://") {
                return Err("URL must use HTTPS".to_string());
            }
        }
        Ok(())
    }
}
```

### Type-State Pattern

Use phantom type parameters to enforce correct usage at compile time.

```rust
use std::marker::PhantomData;

pub struct Unvalidated;
pub struct Validated;

pub struct Input<State> {
    value: String,
    _state: PhantomData<State>,
}

impl Input<Unvalidated> {
    pub fn new(value: String) -> Self {
        Input { value, _state: PhantomData }
    }

    pub fn validate(self) -> Result<Input<Validated>, ValidationError> {
        if self.value.len() > 256 {
            return Err(ValidationError::TooLong);
        }
        Ok(Input { value: self.value, _state: PhantomData })
    }
}

impl Input<Validated> {
    // Only callable after validation
    pub fn value(&self) -> &str {
        &self.value
    }
}

// Function that only accepts validated input
fn process(input: Input<Validated>) { /* ... */ }
```

---

## Security-Specific Structures

### `secrecy::Secret<T>`

Wrap all sensitive values. `Secret<T>` does not implement `Debug` or
`Display`, so values are never accidentally logged or printed.

```rust
use secrecy::Secret;

pub struct ApiCredentials {
    pub key_id: String,             // Not secret — safe to log
    pub secret_key: Secret<String>, // Never logged or displayed
}
```

To access the inner value, use `expose_secret()` at the point of use, keeping
the exposure scope as narrow as possible.

```rust
use secrecy::ExposeSecret;

fn sign_request(creds: &ApiCredentials, payload: &[u8]) -> Vec<u8> {
    // Expose only in this scope
    let key_bytes = creds.secret_key.expose_secret().as_bytes();
    hmac_sign(key_bytes, payload)
}
```

### `zeroize::Zeroizing<T>`

For stack-allocated buffers holding key material. Zeroes memory on drop.

```rust
use zeroize::Zeroizing;

let mut key_buffer: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; 32]);
derive_key_into(&password, &salt, &mut key_buffer);
// key_buffer is zeroed when it goes out of scope
```

### Custom Types with `ZeroizeOnDrop`

Security-sensitive structs must derive `ZeroizeOnDrop`.

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey {
    bytes: [u8; 32],
}
```

### `subtle::ConstantTimeEq`

All comparisons involving secret values must be constant-time to prevent
timing attacks.

```rust
use subtle::ConstantTimeEq;

pub fn verify_mac(expected: &[u8], provided: &[u8]) -> bool {
    // CORRECT: constant-time comparison
    expected.ct_eq(provided).into()

    // WRONG: early exit leaks timing information
    // expected == provided
}
```

### Phantom Data for Type Tagging

Tag types to carry compile-time information without runtime overhead.

```rust
use std::marker::PhantomData;

pub struct Encrypted;
pub struct Plaintext;

pub struct Payload<State> {
    data: Vec<u8>,
    _state: PhantomData<State>,
}

// encrypt() produces Payload<Encrypted>
// decrypt() requires Payload<Encrypted>, produces Payload<Plaintext>
// Impossible to accidentally pass plaintext to a function expecting ciphertext
```

---

## Database Schema Considerations

Use strongly-typed IDs at the database boundary. Map Rust enums to database
columns with `sqlx`.

```rust
use sqlx::Type;
use uuid::Uuid;

// Strongly-typed ID — not just a raw Uuid at the database level
#[derive(Debug, Clone, Copy, sqlx::Type)]
#[sqlx(transparent)]
pub struct UserId(Uuid);

// Enum mapped to a database TEXT column
#[derive(Debug, sqlx::Type)]
#[sqlx(type_name = "user_status", rename_all = "lowercase")]
pub enum UserStatus {
    Active,
    Suspended,
    Deleted,
}

// Soft delete with optional timestamp
pub struct UserRow {
    pub id: Uuid,
    pub name: String,
    pub status: UserStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}
```

---

## Anti-Patterns to Avoid

| Anti-pattern                                | Problem                                    | Preferred alternative                       |
| ------------------------------------------- | ------------------------------------------ | ------------------------------------------- |
| `String` for IDs                            | Accidental mixing of ID types              | Newtype wrapper: `struct UserId(Uuid)`      |
| `Vec<String>` for tag lists                 | No uniqueness guarantee                    | `HashSet<Tag>`                              |
| `HashMap<String, String>` for typed data    | Stringly-typed, no compile-time validation | Typed structs with `serde`                  |
| `Option<Option<T>>`                         | Ambiguous semantics                        | Dedicated enum with explicit variants       |
| `bool` flags in structs                     | `(true, false, true)` is unreadable        | Named enums or type-state pattern           |
| Cloning everywhere to avoid lifetime errors | Unnecessary allocation, masks ownership    | Use references; redesign ownership          |
| `unwrap()` on `HashMap::get`                | Panics in production                       | Handle `None` explicitly with `?` or `ok_or`|
