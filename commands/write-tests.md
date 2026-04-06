# Write Tests Command

## Table of Contents

- [Overview](#overview)
- [When to Use](#when-to-use)
- [What It Does](#what-it-does)
- [Parameters](#parameters)
- [Output](#output)
- [Examples](#examples)
- [Best Practices](#best-practices)
- [Related Commands](#related-commands)

---

## Overview

**Command:** `/rust-security:write-tests`

Generates comprehensive test suites for Rust projects including unit tests, integration tests, property-based tests, doc tests, and security-focused tests. Follows TDD principles and ensures high code coverage with meaningful test cases.

**Agent:** `write-tests` (Sonnet - Standard Analysis)

---

## When to Use

Use this command when:

- **Implementing new features** - Generate tests before or during implementation (TDD)
- **Improving code coverage** - Add tests for untested code paths
- **Security testing** - Create tests for security-critical functions
- **Refactoring** - Ensure behavior preservation with comprehensive tests
- **Bug fixes** - Add regression tests for discovered bugs
- **Before releases** - Ensure comprehensive test coverage

---

## What It Does

1. **Analyzes code structure** to identify test opportunities
2. **Generates unit tests** for individual functions and methods
3. **Creates integration tests** for module interactions
4. **Implements property-based tests** using proptest
5. **Writes doc tests** for public API documentation
6. **Generates security tests** for authentication, crypto, and input validation
7. **Measures test coverage** and identifies gaps

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--type`           | string   | No       | `all`         | Test type: `unit`, `integration`, `property`, `doc`, `all` |
| `--target`         | string   | No       | All           | Specific module or file to test                  |
| `--coverage`       | boolean  | No       | `true`        | Measure code coverage                            |
| `--security-focus` | boolean  | No       | `true`        | Include security-specific tests                  |
| `--output-dir`     | string   | No       | `tests/`      | Test output directory                            |

---

## Output

### Console Output

```
🧪 Syntek Rust Security - Test Generation

📦 Project: auth-service v1.3.0
🎯 Test type: All tests
🔍 Target: Full project

┌─────────────────────────────────────────────────────────────┐
│ Generated Tests                                             │
├─────────────────────────────────────────────────────────────┤
│ Unit tests: 47 generated                                    │
│ Integration tests: 12 generated                             │
│ Property-based tests: 8 generated                           │
│ Doc tests: 23 generated                                     │
│ Security tests: 15 generated                                │
│ Total: 105 tests                                            │
└─────────────────────────────────────────────────────────────┘

✅ Test Files Created:

Unit Tests:
  - src/auth/mod.rs (15 tests)
  - src/crypto/hmac.rs (8 tests)
  - src/session/manager.rs (12 tests)
  - src/utils/validation.rs (12 tests)

Integration Tests:
  - tests/auth_flow.rs
  - tests/session_management.rs
  - tests/token_lifecycle.rs

Property-Based Tests:
  - tests/property_crypto.rs
  - tests/property_validation.rs

Security Tests:
  - tests/security/timing_attacks.rs
  - tests/security/injection.rs
  - tests/security/token_tampering.rs

📊 Coverage Analysis:
   - Line coverage: 94.7% (was 78.3%)
   - Branch coverage: 89.2% (was 71.5%)
   - Function coverage: 97.1% (was 83.4%)

🧪 Test Results:
   Running 105 tests...
   ✅ 105 passed, 0 failed

🚀 All tests passing! Coverage improved by +16.4%
```

---

## Examples

### Example 1: Generate All Tests

```bash
/rust-security:write-tests
```

Generates comprehensive test suite for entire project.

### Example 2: Unit Tests Only

```bash
/rust-security:write-tests --type=unit --target=src/crypto/
```

Generates unit tests for crypto module.

### Example 3: Security-Focused Tests

```bash
/rust-security:write-tests --type=all --security-focus=true
```

Generates tests with emphasis on security scenarios.

### Example 4: Property-Based Tests

```bash
/rust-security:write-tests --type=property --target=src/parser/
```

Generates property-based tests for parser module.

### Example 5: Integration Tests

```bash
/rust-security:write-tests --type=integration
```

Generates integration tests for module interactions.

---

## Best Practices

### Unit Test Example

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_verify_valid_signature() {
        let key = b"secret_key";
        let message = b"test message";
        let signature = compute_hmac(message, key).unwrap();

        let result = verify_hmac(message, &signature, key);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_hmac_verify_invalid_signature() {
        let key = b"secret_key";
        let message = b"test message";
        let wrong_signature = [0u8; 32];

        let result = verify_hmac(message, &wrong_signature, key);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_hmac_constant_time_comparison() {
        // Security test: ensure constant-time comparison
        let key = b"secret_key";
        let message = b"test message";
        let valid_sig = compute_hmac(message, key).unwrap();
        let mut invalid_sig = valid_sig.clone();
        invalid_sig[0] ^= 0xFF;

        let start = std::time::Instant::now();
        let _ = verify_hmac(message, &valid_sig, key);
        let valid_time = start.elapsed();

        let start = std::time::Instant::now();
        let _ = verify_hmac(message, &invalid_sig, key);
        let invalid_time = start.elapsed();

        // Timing should be similar (constant-time)
        let diff = (valid_time.as_nanos() as i64 - invalid_time.as_nanos() as i64).abs();
        assert!(diff < 1_000_000, "Timing difference too large: {}ns", diff);
    }
}
```

### Property-Based Test Example

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_encrypt_decrypt_roundtrip(plaintext: Vec<u8>) {
        let key = [0u8; 32]; // Fixed key for testing
        let ciphertext = encrypt(&plaintext, &key).unwrap();
        let decrypted = decrypt(&ciphertext, &key).unwrap();
        prop_assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_hmac_deterministic(message: Vec<u8>) {
        let key = [0u8; 32];
        let hmac1 = compute_hmac(&message, &key).unwrap();
        let hmac2 = compute_hmac(&message, &key).unwrap();
        prop_assert_eq!(hmac1, hmac2);
    }
}
```

### Integration Test Example

```rust
// tests/auth_flow.rs
use auth_service::*;

#[tokio::test]
async fn test_complete_auth_flow() {
    // Setup test database
    let db = setup_test_db().await;

    // Register user
    let user = create_user(&db, "test@example.com", "password123").await.unwrap();

    // Login
    let session = login(&db, "test@example.com", "password123").await.unwrap();
    assert!(session.is_valid());

    // Access protected resource
    let result = access_resource(&db, &session.token).await;
    assert!(result.is_ok());

    // Logout
    logout(&db, &session.token).await.unwrap();

    // Verify session invalidated
    let result = access_resource(&db, &session.token).await;
    assert!(result.is_err());

    // Cleanup
    teardown_test_db(db).await;
}
```

---

## Reference Documents

This command invokes the `rust-test-writer` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**

## Related Commands

- **[/rust-security:review-code](review-code.md)** - Review tests for completeness
- **[/rust-security:benchmark](benchmark.md)** - Performance testing
- **[/rust-security:fuzz-setup](fuzz-setup.md)** - Fuzzing infrastructure

---

**Note:** Generated tests should be reviewed and customized for specific requirements. Property-based tests require the `proptest` crate.
