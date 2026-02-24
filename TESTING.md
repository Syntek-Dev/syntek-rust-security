# Testing Guide — Syntek Rust Security Plugin

**Purpose**: Reference document for all agents writing or reviewing tests.
Agents MUST follow these conventions, patterns, and examples.

---

## Table of Contents

- [Stack and Tooling](#stack-and-tooling)
- [Directory Structure](#directory-structure)
- [Naming Conventions](#naming-conventions)
- [The Testing Pyramid](#the-testing-pyramid)
  - [Unit Tests](#1-unit-tests)
  - [Integration Tests](#2-integration-tests)
  - [CLI Integration Tests](#3-cli-integration-tests)
  - [Property-Based Tests](#4-property-based-tests)
  - [Fuzz Tests](#5-fuzz-tests)
  - [Benchmark Tests](#6-benchmark-tests)
- [TDD Methodology](#tdd-test-driven-development)
- [Mocking Patterns](#mocking-patterns)
- [Test Data and Factories](#test-data-and-factories)
- [Async Testing](#async-testing)
- [Security-Critical Tests](#security-critical-tests)
- [FFI Boundary Tests](#ffi-boundary-tests)
- [Rules and Principles](#rules-and-principles)

---

## Stack and Tooling

| Tool                  | Purpose                                         | How to use                               |
| --------------------- | ----------------------------------------------- | ---------------------------------------- |
| **cargo test**        | Unit and integration test runner                | `cargo test -p <crate>`                  |
| **tokio::test**       | Async Rust tests                                | `#[tokio::test]` attribute               |
| **mockall**           | Trait-based mocking for unit tests              | `#[automock]` / `mock!` macro            |
| **wiremock**          | HTTP mock server for outbound call testing      | `MockServer::start().await`              |
| **proptest**          | Property-based testing (security-critical)      | `proptest!` macro                        |
| **cargo-fuzz**        | Coverage-guided fuzzing (libfuzzer)             | `cargo fuzz run <target>`                |
| **criterion**         | Statistical benchmarking                        | `#[criterion]` / `bench_function`        |
| **assert_cmd**        | CLI integration testing                         | `Command::cargo_bin("tool-name")`        |
| **tempfile**          | Temporary file/directory fixtures               | `tempdir()`                              |
| **rstest**            | Parameterised test cases                        | `#[rstest]` / `#[case]`                  |

**Running Rust tests:**

```bash
# Full test suite for all crates
cargo test --workspace

# Single crate
cargo test -p syntek-crypto

# Specific test by name pattern
cargo test -p syntek-vault fetch_secret

# With log output (useful for debugging failures)
RUST_LOG=debug cargo test -p syntek-monitor -- --nocapture

# Run only doc tests
cargo test --doc -p syntek-crypto

# Run with all features
cargo test --workspace --all-features
```

**Running fuzz tests:**

```bash
# Run a specific fuzz target
cargo fuzz run parse_token

# Run with a corpus
cargo fuzz run parse_token fuzz/corpus/parse_token/

# Minimise a crash input
cargo fuzz tmin parse_token fuzz/artifacts/parse_token/crash-*
```

**Running benchmarks:**

```bash
# Run all benchmarks
cargo bench --workspace

# Run a specific benchmark
cargo bench -p syntek-crypto aes_gcm_encrypt

# Compare against a baseline
cargo bench -- --save-baseline main
```

---

## Directory Structure

Unit tests live inline as `#[cfg(test)]` modules at the bottom of each source
file. Integration tests live in a `tests/` directory at the crate root. Fuzz
targets live in `fuzz/fuzz_targets/`. Benchmarks live in `benches/`.

```
syntek-rust-security/
├── src/
│   ├── lib.rs
│   ├── crypto/
│   │   ├── mod.rs           # Unit tests in #[cfg(test)] at the bottom
│   │   ├── aes_gcm.rs
│   │   └── key_derivation.rs
│   ├── vault/
│   │   ├── mod.rs
│   │   └── client.rs        # Unit tests inline
│   └── ssh/
│       ├── mod.rs
│       └── wrapper.rs
├── tests/
│   ├── crypto_integration.rs    # Integration: real crypto operations
│   ├── vault_integration.rs     # Integration: real Vault test instance
│   ├── cli_integration.rs       # Integration: full CLI invocation
│   └── ai_gateway_routing.rs    # Integration: request routing and auth
├── fuzz/
│   └── fuzz_targets/
│       ├── parse_token.rs       # Fuzz: token parser
│       ├── decrypt_payload.rs   # Fuzz: decryption input handling
│       └── parse_config.rs      # Fuzz: config file parsing
├── benches/
│   ├── crypto_bench.rs          # Criterion: encryption throughput
│   └── vault_bench.rs           # Criterion: Vault fetch latency
└── examples/
    └── encrypt_decrypt.rs       # Runnable examples
```

---

## Naming Conventions

| Convention           | Pattern                                        | Example                                               |
| -------------------- | ---------------------------------------------- | ----------------------------------------------------- |
| Rust unit test       | `test_<behaviour>_<condition>`                 | `test_aes_gcm_decrypt_fails_with_wrong_key`           |
| Rust integration     | `<module>_integration.rs`                      | `vault_integration.rs`                                |
| Fuzz target          | `<target>.rs`                                  | `parse_token.rs`                                      |
| Benchmark            | `<subject>_bench.rs`                           | `crypto_bench.rs`                                     |
| Test module          | `#[cfg(test)] mod tests { ... }`               | standard Rust convention                              |
| Logical grouping     | Nested `mod` by method or behaviour            | `mod encrypt { ... }` / `mod decrypt { ... }`         |
| Parameterised case   | `#[case(input, expected)]`                     | `#[case("valid-jwt", Ok(claims))]`                    |

Avoid:

- `test_1`, `test_2`, `test_thing` — no scenario is described
- Mirroring the function name without adding scenario context:
  `test_encrypt` is useless; `test_encrypt_returns_different_ciphertext_on_new_nonce`
  is not

---

## The Testing Pyramid

Write tests in this ratio: many unit, some integration, few fuzz/benchmark.

```
        /   Fuzz / Bench   \     <- Few, slow, high confidence (security & perf)
       /    Integration      \   <- Some, moderate speed (crate boundaries)
      /     Unit Tests        \  <- Many, fast, focused (function/method level)
```

### 1. Unit Tests

Test a single function or method in complete isolation. Mock all external
dependencies using `mockall`.

**What to unit test:**

- Vault client methods (`vault/client.rs`)
- Cryptographic helper functions (`crypto/`)
- Token parsing and validation (`auth/`)
- Certificate management logic (`cert/`)
- AI gateway routing decisions (`ai_gateway/routing.rs`)
- CLI argument parsing and dispatch (`cli/`)
- Any pure function with clear inputs and outputs

**Example — unit test with mockall:**

```rust
// src/vault/client.rs

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;

    #[test]
    fn test_fetch_secret_returns_value_when_path_exists() {
        let mut mock = MockVaultClient::new();
        mock.expect_kv_get()
            .with(eq("secret/data/api-key"))
            .returning(|_| Ok(Some("super-secret-value".to_string())));

        let result = mock.kv_get("secret/data/api-key");

        assert_eq!(result.unwrap(), Some("super-secret-value".to_string()));
    }

    #[test]
    fn test_fetch_secret_returns_none_when_path_missing() {
        let mut mock = MockVaultClient::new();
        mock.expect_kv_get().returning(|_| Ok(None));

        let result = mock.kv_get("secret/data/nonexistent");

        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_fetch_secret_returns_error_on_connection_failure() {
        let mut mock = MockVaultClient::new();
        mock.expect_kv_get()
            .returning(|_| Err(VaultError::ConnectionRefused));

        let result = mock.kv_get("secret/data/any");

        assert!(result.is_err());
    }

    #[test]
    fn test_fetch_secret_never_logs_secret_value_on_error() {
        // Verify that error messages do not include the secret value
        let err = VaultError::PermissionDenied { path: "secret/data/key".to_string() };
        let msg = err.to_string();
        assert!(!msg.contains("secret-value"));
    }
}
```

**Example — pure function unit test:**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation_produces_unique_values() {
        let nonce_a = generate_nonce();
        let nonce_b = generate_nonce();

        // Two independently generated nonces must not be equal
        assert_ne!(nonce_a, nonce_b);
    }

    #[test]
    fn test_nonce_generation_produces_correct_length() {
        let nonce = generate_nonce();

        assert_eq!(nonce.len(), 12); // AES-GCM requires 96-bit nonce
    }
}
```

### 2. Integration Tests

Verify that multiple crate-level units work together. Integration tests live in
`tests/` at the crate root and have access to the crate's public API only.

**What to integration test:**

- Full encrypt → decrypt round-trips
- Vault client against a local Vault dev instance
- AI gateway routing against mock upstream providers (wiremock)
- Certificate rotation workflows (mock Cloudflare API)
- SSH wrapper command filtering logic

**Example — crypto round-trip integration test:**

```rust
// tests/crypto_integration.rs

use syntek_crypto::{encrypt, decrypt, KeyDerivation};

#[test]
fn test_encrypt_decrypt_roundtrip_produces_original_plaintext() {
    let key = KeyDerivation::argon2id("password", b"testsalt1234567890123456")
        .expect("key derivation should succeed");
    let plaintext = b"sensitive data to protect";

    let ciphertext = encrypt(&key, plaintext).expect("encryption should succeed");
    let recovered = decrypt(&key, &ciphertext).expect("decryption should succeed");

    assert_eq!(recovered, plaintext);
}

#[test]
fn test_decrypt_fails_with_wrong_key() {
    let key_a = KeyDerivation::argon2id("password-a", b"testsalt1234567890123456")
        .expect("key derivation should succeed");
    let key_b = KeyDerivation::argon2id("password-b", b"testsalt1234567890123456")
        .expect("key derivation should succeed");
    let plaintext = b"sensitive data";

    let ciphertext = encrypt(&key_a, plaintext).expect("encryption should succeed");
    let result = decrypt(&key_b, &ciphertext);

    assert!(result.is_err(), "decryption with wrong key should fail");
}

#[test]
fn test_encrypt_produces_different_ciphertext_for_same_plaintext() {
    let key = KeyDerivation::argon2id("password", b"testsalt1234567890123456")
        .expect("key derivation should succeed");
    let plaintext = b"same input";

    let ciphertext_a = encrypt(&key, plaintext).expect("first encryption should succeed");
    let ciphertext_b = encrypt(&key, plaintext).expect("second encryption should succeed");

    // Nonces must differ, so ciphertexts must differ
    assert_ne!(ciphertext_a, ciphertext_b);
}
```

**Example — AI gateway integration test with wiremock:**

```rust
// tests/ai_gateway_routing.rs

use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::{method, path, header};
use syntek_ai_gateway::{Gateway, Provider};

#[tokio::test]
async fn test_gateway_routes_claude_model_to_anthropic() {
    let mock_anthropic = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", "test-anthropic-key"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "content": [{"type": "text", "text": "Hello"}]
            })))
        .mount(&mock_anthropic)
        .await;

    let gateway = Gateway::builder()
        .anthropic_endpoint(mock_anthropic.uri())
        .anthropic_key("test-anthropic-key")
        .build();

    let response = gateway
        .complete("claude-sonnet-4-6", "Hello", &[])
        .await
        .expect("request should succeed");

    assert_eq!(response.provider, Provider::Anthropic);
}

#[tokio::test]
async fn test_gateway_returns_error_without_api_key() {
    let gateway = Gateway::builder().build();

    let result = gateway.complete("claude-sonnet-4-6", "Hello", &[]).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), GatewayError::MissingApiKey { .. }));
}
```

### 3. CLI Integration Tests

Test CLI commands end-to-end using `assert_cmd`.

```rust
// tests/cli_integration.rs

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_vault_setup_exits_zero_with_valid_address() {
    Command::cargo_bin("syntek-security")
        .unwrap()
        .args(["vault", "setup", "--addr", "http://127.0.0.1:8200"])
        .env("VAULT_TOKEN", "test-root-token")
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault connection verified"));
}

#[test]
fn test_cert_rotate_rejects_missing_domain_argument() {
    Command::cargo_bin("syntek-security")
        .unwrap()
        .args(["cert", "rotate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("required argument"));
}

#[test]
fn test_scan_secrets_detects_hardcoded_api_key_in_file() {
    use tempfile::NamedTempFile;
    use std::io::Write;

    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, r#"let key = "sk-ant-api03-fake-key-12345";"#).unwrap();

    Command::cargo_bin("syntek-security")
        .unwrap()
        .args(["scan-secrets", "--path", file.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("Potential secret detected"));
}
```

### 4. Property-Based Tests

Use `proptest` for security-critical functions where manual test cases cannot
cover the full input space. Required for input validation, parsing, and any
function that processes untrusted external data.

**Example — property-based tests for cryptographic functions:**

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_encrypt_decrypt_roundtrip_holds_for_arbitrary_plaintext(
        plaintext in proptest::collection::vec(any::<u8>(), 0..4096),
        password in "[a-zA-Z0-9!@#$%^&*]{8,64}"
    ) {
        let key = KeyDerivation::argon2id(&password, b"fixed-test-salt-1234")
            .expect("key derivation should succeed");

        let ciphertext = encrypt(&key, &plaintext)
            .expect("encryption should not fail");
        let recovered = decrypt(&key, &ciphertext)
            .expect("decryption should not fail");

        prop_assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_token_parser_never_panics_on_arbitrary_input(input in ".*") {
        // Attacker controls the input — must return Err, never panic
        let _ = parse_auth_token(&input);
    }

    #[test]
    fn test_sanitise_log_value_never_leaks_secret_pattern(
        secret in "[a-zA-Z0-9]{16,64}"
    ) {
        let sanitised = sanitise_for_logging(&secret);
        prop_assert!(!sanitised.contains(&secret));
    }

    #[test]
    fn test_constant_time_eq_matches_equality_semantics(
        a in "[a-zA-Z0-9]{1,64}",
        b in "[a-zA-Z0-9]{1,64}"
    ) {
        let ct_result = constant_time_eq(a.as_bytes(), b.as_bytes());
        let expected = a == b;
        prop_assert_eq!(ct_result, expected);
    }
}
```

### 5. Fuzz Tests

Use `cargo-fuzz` for parsing, deserialization, and cryptographic input handling.

```rust
// fuzz/fuzz_targets/parse_token.rs
#![no_main]

use libfuzzer_sys::fuzz_target;
use syntek_auth::parse_auth_token;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        // Must not panic; may return Err
        let _ = parse_auth_token(input);
    }
});
```

```rust
// fuzz/fuzz_targets/decrypt_payload.rs
#![no_main]

use libfuzzer_sys::fuzz_target;
use syntek_crypto::{decrypt, KEY_BYTES};

fuzz_target!(|data: &[u8]| {
    let key = [0u8; KEY_BYTES];
    // Arbitrary ciphertext must be handled without panic
    let _ = decrypt(&key, data);
});
```

Set up fuzzing infrastructure:

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Create a new fuzz target
cargo fuzz add parse_token

# Run the fuzzer
cargo fuzz run parse_token -- -max_total_time=60

# Check existing corpus
cargo fuzz run parse_token fuzz/corpus/parse_token/
```

### 6. Benchmark Tests

Use `criterion` for performance-sensitive code. Required for cryptographic
functions to track regression.

```rust
// benches/crypto_bench.rs

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use syntek_crypto::{encrypt, KeyDerivation};

fn bench_aes_gcm_encrypt(c: &mut Criterion) {
    let key = KeyDerivation::argon2id("bench-password", b"bench-salt-1234567")
        .expect("key derivation should succeed");
    let plaintext = vec![0u8; 4096];

    let mut group = c.benchmark_group("aes_gcm");
    group.throughput(Throughput::Bytes(plaintext.len() as u64));

    group.bench_function("encrypt_4kb", |b| {
        b.iter(|| encrypt(black_box(&key), black_box(&plaintext)))
    });

    group.finish();
}

criterion_group!(benches, bench_aes_gcm_encrypt);
criterion_main!(benches);
```

---

## TDD (Test-Driven Development)

**Cycle:** Red → Green → Refactor

1. **Red** — Write a failing test for the next piece of behaviour.
2. **Green** — Write the minimum code to make it pass.
3. **Refactor** — Clean up without breaking the test.

**Use TDD for:**

- All Rust security functions
- CLI command handlers
- Vault client operations
- AI gateway routing logic
- Any pure function with clear inputs and outputs

**Example — building a token rotation function step by step:**

```rust
// Step 1: RED — write the failing test first

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotate_token_returns_new_token_different_from_old() {
        let old_token = Token::new("old-value-12345");
        let new_token = rotate_token(&old_token).expect("rotation should succeed");
        assert_ne!(new_token.value(), old_token.value());
    }

    #[test]
    fn test_rotate_token_zeroises_old_token_on_drop() {
        // Verify the old token is zeroised after rotation
        // This test exercises the Drop implementation
        let old_token = Token::new("sensitive-12345");
        let ptr = old_token.value().as_ptr();
        let len = old_token.value().len();

        let _new_token = rotate_token(&old_token).expect("rotation should succeed");
        drop(old_token);

        // After drop, memory at ptr should be zeroed
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert!(bytes.iter().all(|&b| b == 0), "old token was not zeroised");
    }

    #[test]
    fn test_rotate_token_returns_error_on_vault_unavailable() {
        let old_token = Token::new("old-value");
        let result = rotate_token_with_vault(&old_token, None);
        assert!(result.is_err());
    }
}

// Step 2: GREEN — implement the minimum code to make the tests pass
// Step 3: REFACTOR — simplify without breaking any test
```

---

## Mocking Patterns

### Trait-based mocking with mockall

Define a trait for every external dependency and annotate it with `#[automock]`:

```rust
use mockall::automock;

#[automock]
pub trait VaultClient {
    fn kv_get(&self, path: &str) -> Result<Option<String>, VaultError>;
    fn kv_put(&self, path: &str, value: &str) -> Result<(), VaultError>;
    fn renew_token(&self) -> Result<(), VaultError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_rotator_fetches_key_from_vault_on_rotation() {
        let mut mock = MockVaultClient::new();
        mock.expect_kv_get()
            .with(mockall::predicate::eq("secret/certs/origin-key"))
            .times(1)
            .returning(|_| Ok(Some("-----BEGIN PRIVATE KEY-----\n...".to_string())));

        let rotator = CertRotator::new(mock);
        let result = rotator.rotate("example.com");

        assert!(result.is_ok());
    }
}
```

### HTTP mocking with wiremock

For services making outbound HTTP calls (Vault HTTP API, Cloudflare API,
AI provider APIs), use `wiremock` to spin up a local mock server:

```rust
use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::{method, path, header};

#[tokio::test]
async fn test_cloudflare_dns_update_posts_to_correct_endpoint() {
    let mock_server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/client/v4/zones/zone-id/dns_records/record-id"))
        .and(header("Authorization", "Bearer test-cf-token"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({"success": true})))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = CloudflareClient::new("test-cf-token")
        .with_base_url(mock_server.uri());

    client
        .update_dns_record("zone-id", "record-id", "1.2.3.4")
        .await
        .expect("DNS update should succeed");

    mock_server.verify().await;
}
```

### General mocking rules

- Mock at the boundary closest to the unit under test.
- Never mock the module you are testing.
- Use `mockall` for trait-based mocking; use `wiremock` for HTTP boundaries.
- Always verify mock expectations (`.times(n)` with mockall;
  `mock_server.verify()` with wiremock).
- Each `#[test]` function creates its own fresh mock instances — there is no
  shared mock state between tests.

---

## Test Data and Factories

Use factory functions for consistent test data. Avoid constructing complex
structs inline in every test.

```rust
// src/test_helpers.rs — compiled only in test builds

#[cfg(test)]
pub mod factories {
    use crate::crypto::{EncryptedPayload, Key};
    use crate::vault::VaultSecret;

    pub fn build_test_key() -> Key {
        Key::from_bytes(&[0x42u8; 32]).expect("test key should be valid")
    }

    pub fn build_vault_secret(path: &str, value: &str) -> VaultSecret {
        VaultSecret {
            path: path.to_string(),
            value: value.to_string(),
            version: 1,
            created_at: 0,
        }
    }

    pub fn build_encrypted_payload(plaintext: &[u8]) -> EncryptedPayload {
        let key = build_test_key();
        crate::crypto::encrypt(&key, plaintext).expect("test encryption should succeed")
    }
}
```

---

## Async Testing

Use `#[tokio::test]` for all async unit and integration tests. Never use
`block_on` inside a test function.

```rust
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn test_vault_fetch_completes_within_deadline() {
    let client = build_test_vault_client().await;

    let result = timeout(
        Duration::from_secs(2),
        client.kv_get("secret/data/test-key"),
    )
    .await;

    assert!(result.is_ok(), "vault fetch exceeded 2s deadline");
}

#[tokio::test]
async fn test_concurrent_vault_requests_do_not_interfere() {
    let client = build_test_vault_client().await;

    let (r1, r2) = tokio::join!(
        client.kv_get("secret/data/key-1"),
        client.kv_get("secret/data/key-2"),
    );

    assert!(r1.is_ok());
    assert!(r2.is_ok());
}
```

---

## Security-Critical Tests

For cryptographic utilities, input validation, and authentication logic, use
`proptest` in addition to manual test cases.

**Required for:**

- Input sanitisation functions (header values, URL paths, query parameters)
- Token parsing and validation
- Any function that processes untrusted external data
- Constant-time comparison functions
- Decryption routines (must handle corrupted/malicious ciphertext gracefully)

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_hmac_verify_never_panics_on_arbitrary_input(
        token in ".*",
        secret in "[a-zA-Z0-9]{16,64}"
    ) {
        // Attacker controls both token and claimed secret in some scenarios
        let _ = verify_hmac_token(&token, &secret);
    }

    #[test]
    fn test_vault_path_sanitiser_rejects_path_traversal(
        suffix in "(\\.\\./|%2e%2e%2f|%252e%252e%252f).*"
    ) {
        let result = sanitise_vault_path("secret/data/", &suffix);
        prop_assert!(result.is_err(), "path traversal should be rejected");
    }
}
```

---

## FFI Boundary Tests

Test PyO3, Neon, UniFFI, and wasm-bindgen boundaries for memory safety and
correct error propagation. FFI functions must not panic — panics across FFI
boundaries are undefined behaviour.

```rust
#[cfg(test)]
mod tests {
    use pyo3::prelude::*;
    use pyo3::types::PyBytes;

    #[test]
    fn test_pyo3_encrypt_returns_bytes_not_panic() {
        Python::with_gil(|py| {
            let plaintext = PyBytes::new(py, b"test data");
            let key_bytes = PyBytes::new(py, &[0x42u8; 32]);

            let result = crate::ffi::py_encrypt(py, plaintext, key_bytes);

            assert!(result.is_ok(), "FFI encrypt should not panic: {:?}", result);
        });
    }

    #[test]
    fn test_pyo3_encrypt_raises_python_error_on_invalid_key() {
        Python::with_gil(|py| {
            let plaintext = PyBytes::new(py, b"test data");
            let short_key = PyBytes::new(py, &[0u8; 4]); // too short

            let result = crate::ffi::py_encrypt(py, plaintext, short_key);

            assert!(result.is_err(), "invalid key should raise Python error");
        });
    }
}
```

---

## Rules and Principles

1. **Every new public Rust function has at least one unit test.** No exceptions.

2. **Every new HTTP endpoint or CLI command has integration tests** covering at
   minimum: the happy path, a malformed request, an unauthenticated request,
   and a not-found/not-applicable case.

3. **Every new FFI export has a test** verifying it does not panic on valid
   input and returns an appropriate error on invalid input.

4. **Tests must be deterministic.** No reliance on real time, random values, or
   external network services. Mock everything at the boundary.

5. **Tests must be independent.** Each test sets up its own state and cleans up
   after itself. No test depends on another having run first.

6. **Follow Arrange-Act-Assert:**
   - **Arrange**: set up test data and mocks
   - **Act**: call the function or trigger the action
   - **Assert**: verify the outcome

7. **Test behaviour, not implementation.** Assert on outputs and observable
   side effects, not on which internal methods were called (unless verifying a
   critical security boundary such as audit logging or zeroisation).

8. **Keep unit tests fast.** Rust unit tests should complete in under 10ms each.
   If a test needs real network or disk I/O, it belongs in the integration
   tests directory.

9. **Security-critical functions use proptest** in addition to manual test
   cases. Manual cases alone do not cover the full input space.

10. **Sensitive test values must be clearly marked** as non-production values.
    Never use values that look like real API keys, passwords, or tokens — use
    obviously fake values like `"test-key-do-not-use"` or `[0x42u8; 32]`.

11. **Follow the coding principles** in `CODING-PRINCIPLES.md`: simple
    algorithms, descriptive names, short functions. Test code is held to the
    same standard as production code — a clear, slightly repetitive test is
    better than a clever abstraction that obscures what is being verified.
