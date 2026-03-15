# Performance — my-security-project

**Last Updated:** 15/03/2026
**Version:** 1.0.0
**Maintained By:** Development Team

Performance measurement, benchmarking, and optimisation guidelines for this
project.

---

## Rules

1. **Measure first.** Don't guess where the bottleneck is (Pike Rule 1).
2. **Don't tune for speed until you've measured** — and even then, only if one
   part overwhelms the rest (Pike Rule 2).
3. The fastest code is code that doesn't run. Remove unnecessary work before
   optimising what remains.
4. Write for correctness and clarity first. Make it better once it works
   (Torvalds Rule 6).

---

## Benchmarking with criterion.rs

All performance-sensitive functions must have a criterion benchmark. Commit
baseline numbers to the repository.

```rust
// benches/<subject>_bench.rs
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

pub fn bench_encrypt(c: &mut Criterion) {
    let key = build_test_key();
    let plaintext_1kb = vec![0u8; 1024];
    let plaintext_64kb = vec![0u8; 65536];

    let mut group = c.benchmark_group("aes_gcm_encrypt");
    for (label, data) in [("1kb", &plaintext_1kb), ("64kb", &plaintext_64kb)] {
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(BenchmarkId::new("encrypt", label), data, |b, plaintext| {
            b.iter(|| encrypt_data(&key, plaintext).expect("encryption failed"));
        });
    }
    group.finish();
}

pub fn bench_request_routing(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let app = runtime.block_on(build_test_app());

    c.bench_function("health_check_handler", |b| {
        b.to_async(&runtime).iter(|| async {
            let response = app
                .oneshot(
                    axum::http::Request::builder()
                        .uri("/api/v1/health")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
        });
    });
}

criterion_group!(benches, bench_encrypt, bench_request_routing);
criterion_main!(benches);
```

**Running benchmarks:**

```bash
# Run all benchmarks
cargo bench

# Run a specific benchmark
cargo bench -- aes_gcm_encrypt

# Save baseline
cargo bench -- --save-baseline main

# Compare against baseline
cargo bench -- --baseline main
```

---

## Profiling

Identify real bottlenecks before optimising.

```bash
# Flamegraph (Linux — requires perf)
cargo install flamegraph
cargo flamegraph --bin my_binary -- <args>

# cargo-instruments (macOS — requires Xcode)
cargo install cargo-instruments
cargo instruments -t time --bin my_binary -- <args>

# perf stat (Linux — hardware counters)
perf stat ./target/release/my_binary

# Heap profiling with heaptrack (Linux)
heaptrack ./target/release/my_binary
heaptrack_gui heaptrack.my_binary.*.gz
```

Build with debug symbols retained for accurate profiling:

```toml
# Cargo.toml — profile for profiling
[profile.profiling]
inherits = "release"
debug = true
```

```bash
cargo build --profile profiling
perf record ./target/profiling/my_binary
perf report
```

---

## Avoiding Unnecessary Allocations

Every heap allocation has a cost. Measure before reducing, but prefer
allocation-light patterns.

### Prefer `&str` Over `String`

```rust
// PREFERRED — borrows the existing string, no allocation
fn process(input: &str) -> Result<Output, Error> { /* ... */ }

// Only needed if you must own or mutate the string
fn build_path(base: &str, name: &str) -> String {
    format!("{}/{}", base, name)
}
```

### `Cow<'_, str>` for Conditionally Owned Strings

```rust
use std::borrow::Cow;

fn normalise_header(name: &str) -> Cow<'_, str> {
    if name.chars().all(|c| c.is_lowercase()) {
        // Borrow — no allocation
        Cow::Borrowed(name)
    } else {
        // Allocate only when necessary
        Cow::Owned(name.to_lowercase())
    }
}
```

### `SmallVec` for Typically Small Collections

```rust
use smallvec::SmallVec;

// Stores up to 4 items on the stack; spills to heap only if more are needed
type Tags = SmallVec<[Tag; 4]>;
```

### Pre-Allocate When Size Is Known

```rust
// Without capacity — may reallocate multiple times
let mut results = Vec::new();

// With capacity — single allocation
let mut results = Vec::with_capacity(expected_count);
```

### Avoid Clone — Pass References or Use `Arc`

```rust
// AVOID — clones the entire Vec
fn process_all(items: Vec<Item>) { /* ... */ }

// PREFERRED — borrow
fn process_all(items: &[Item]) { /* ... */ }

// For shared ownership across threads
fn spawn_worker(items: Arc<Vec<Item>>) { /* ... */ }
```

---

## Async Performance

### Don't Block the Executor

The Tokio runtime uses a fixed-size thread pool. A single blocking call stalls
all tasks on that thread.

```rust
// WRONG — blocks the executor thread
pub async fn hash_password(password: String) -> Result<String, HashError> {
    argon2_hash(&password)  // CPU-heavy, synchronous
}

// CORRECT — offload to the blocking thread pool
pub async fn hash_password(password: String) -> Result<String, HashError> {
    tokio::task::spawn_blocking(move || argon2_hash(&password))
        .await
        .map_err(|_| HashError::TaskPanicked)?
}
```

Also use `spawn_blocking` for:
- Synchronous file I/O (`std::fs`)
- Synchronous database drivers
- CPU-intensive cryptographic operations (key derivation, large-file encryption)

### Tune the Tokio Thread Pool

```bash
# Default: number of CPU cores
TOKIO_WORKER_THREADS=8 ./target/release/my_service

# Blocking thread pool (default: 512 max)
TOKIO_MAX_BLOCKING_THREADS=64 ./target/release/my_service
```

Configure in code for production services:

```rust
fn main() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_cpus::get())
        .max_blocking_threads(64)
        .enable_all()
        .build()?
        .block_on(run())
}
```

### Concurrent Operations with `tokio::select!` and `join!`

```rust
use tokio::try_join;

// Run both operations concurrently — total time = max(a, b), not a + b
let (user, permissions) = try_join!(
    user_service.get_user(user_id),
    auth_service.get_permissions(user_id),
)?;
```

### Never Hold a Lock Across `.await`

```rust
use tokio::sync::Mutex;

let cache = Arc::new(Mutex::new(HashMap::new()));

// WRONG — holds the lock while awaiting
{
    let mut guard = cache.lock().await;
    let value = fetch_from_remote().await;  // lock held here
    guard.insert(key, value);
}

// CORRECT — release the lock before awaiting
let cached = {
    cache.lock().await.get(&key).cloned()
};
if cached.is_none() {
    let value = fetch_from_remote().await;
    cache.lock().await.insert(key, value);
}
```

---

## Database Query Optimisation

```rust
// WRONG — retrieves all columns, including large blobs
sqlx::query_as!(UserRow, "SELECT * FROM users WHERE id = $1", id)

// CORRECT — select only what the caller needs
sqlx::query_as!(
    UserSummary,
    "SELECT id, name, email FROM users WHERE id = $1 AND deleted_at IS NULL",
    id
)
```

**Rules:**
- Always use specific column lists; never `SELECT *`
- Add `WHERE deleted_at IS NULL` to all soft-delete queries
- Use `LIMIT` on all list queries; never fetch unbounded rows
- Use `EXPLAIN ANALYZE` before adding an index
- Avoid N+1 queries — use JOINs or batch queries with `IN ($1, $2, ...)`

```rust
// Batch query to avoid N+1
let user_ids: Vec<Uuid> = orders.iter().map(|o| o.user_id).collect();
let users = sqlx::query_as!(
    UserRow,
    "SELECT id, name FROM users WHERE id = ANY($1)",
    &user_ids as &[Uuid]
)
.fetch_all(&pool)
.await?;
```

**Connection pooling:**

```rust
// Configure the pool at startup; use PgPool everywhere
let pool = sqlx::PgPool::connect_with(
    sqlx::postgres::PgConnectOptions::from_str(&database_url)?
        .application_name("my_service"),
)
.with_pool_options(
    sqlx::pool::PoolOptions::new()
        .max_connections(10)
        .min_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5)),
)
.await?;
```

---

## Caching

### In-Memory Cache with `moka`

```rust
use moka::future::Cache;
use std::time::Duration;

// Async-aware, TTL-bounded, size-bounded
let cache: Cache<UserId, User> = Cache::builder()
    .max_capacity(10_000)
    .time_to_live(Duration::from_secs(300))
    .time_to_idle(Duration::from_secs(60))
    .build();

// Get or load
let user = cache
    .get_with(user_id, async { fetch_user_from_db(user_id).await })
    .await;
```

### Redis Cache

```rust
use deadpool_redis::{Config, Pool, Runtime};

let cfg = Config::from_url("redis://127.0.0.1/");
let pool: Pool = cfg.create_pool(Some(Runtime::Tokio1))?;

let mut conn = pool.get().await?;
let _: () = redis::cmd("SETEX")
    .arg(&cache_key)
    .arg(300u64) // TTL in seconds — never cache without expiry
    .arg(&serialised_value)
    .query_async(&mut *conn)
    .await?;
```

**Cache rules:**
- Always include tenant or user scope in the cache key
- Always set an explicit TTL — never use `SET` without `EX`/`PX`/`EXAT`
- Log cache hit/miss rates with the `metrics` crate
- Never cache secrets or sensitive data in Redis without encryption

---

## HTTP Performance

### Connection Keep-Alive and HTTP/2

Axum/hyper enables keep-alive by default. For HTTP/2, use a TLS listener:

```rust
use axum_server::tls_rustls::RustlsConfig;

let config = RustlsConfig::from_pem_file("cert.pem", "key.pem").await?;
axum_server::bind_rustls(addr, config)
    .serve(app.into_make_service())
    .await?;
```

### Response Compression

```rust
use tower_http::compression::CompressionLayer;

let app = Router::new()
    /* routes */
    .layer(CompressionLayer::new());
```

### Streaming Responses for Large Payloads

```rust
use axum::response::sse::{Event, Sse};
use futures::stream;

pub async fn stream_events() -> Sse<impl futures::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let event_stream = stream::iter(vec![
        Ok(Event::default().data("chunk 1")),
        Ok(Event::default().data("chunk 2")),
    ]);
    Sse::new(event_stream)
}
```

### Timeout Configuration

```rust
use tower_http::timeout::TimeoutLayer;
use std::time::Duration;

let app = Router::new()
    /* routes */
    .layer(TimeoutLayer::new(Duration::from_secs(30)));
```

---

## Memory Allocation

For high-throughput services, replace the default system allocator with
`jemalloc` or `mimalloc`:

```toml
# Cargo.toml
[dependencies]
tikv-jemallocator = "0.6"
```

```rust
// src/main.rs
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;
```

Measure allocation rates before switching. On many workloads the default
`malloc` is adequate.

---

## Monitoring and Measurement

Export metrics with the `metrics` crate and a Prometheus exporter.

```rust
use metrics::{counter, histogram};
use std::time::Instant;

pub async fn process_request(req: Request) -> Response {
    let start = Instant::now();
    let result = handle(req).await;
    let duration = start.elapsed().as_secs_f64();

    histogram!("request_duration_seconds", "handler" => "process_request")
        .record(duration);

    match &result {
        Ok(_) => counter!("requests_total", "status" => "ok").increment(1),
        Err(_) => counter!("requests_total", "status" => "error").increment(1),
    }

    result
}
```

**Key metrics to track:**

| Metric                   | Target            |
| ------------------------ | ----------------- |
| Request latency p50      | < 10ms            |
| Request latency p95      | < 100ms           |
| Request latency p99      | < 500ms           |
| Error rate               | < 0.1%            |
| Allocations per request  | Measure baseline  |
| Active connections       | Monitor for leaks |
| Cache hit rate           | > 80% for hot data|
| DB query time p95        | < 20ms            |

---

## Performance Checklist

- [ ] Critical paths have criterion benchmarks committed to the repository
- [ ] Profiled with flamegraph or cargo-instruments before optimising
- [ ] No blocking calls on the async executor (use `spawn_blocking`)
- [ ] No `clone()` in hot paths — confirmed by profiling, not assumption
- [ ] Database queries use specific column lists, not `SELECT *`
- [ ] All list queries have a `LIMIT`
- [ ] Connection pools configured with appropriate `max_connections`
- [ ] In-memory caches have explicit TTL and size bounds
- [ ] Redis cache keys include tenant/user scope
- [ ] Metrics exported for latency, error rate, and allocation rate
- [ ] `Vec::with_capacity` used when collection size is known
