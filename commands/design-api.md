# Design API Command

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

**Command:** `/rust-security:design-api`

Designs secure, idiomatic Rust APIs following API design guidelines, type safety best practices, and security-first principles. Creates type-safe interfaces, implements builder patterns, and ensures API usability while maintaining security guarantees.

**Agent:** `rust-api-designer` (Opus - Sophisticated API Design)

---

## When to Use

Use this command when:

- **Starting new library** - Design public API before implementation
- **Refactoring public API** - Improve existing API design
- **Security-critical interfaces** - Design crypto or auth APIs
- **Before 1.0 release** - Finalize API before stability guarantee
- **FFI boundaries** - Design safe Rust wrappers for C APIs
- **Library documentation** - Create comprehensive API examples

---

## What It Does

1. **Analyzes requirements** to design appropriate API surface
2. **Creates type-safe interfaces** using Rust's type system
3. **Implements builder patterns** for complex initialization
4. **Designs error handling** with descriptive error types
5. **Generates API examples** demonstrating usage patterns
6. **Documents safety invariants** for public APIs
7. **Validates API guidelines** following Rust API conventions

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--domain`         | string   | Yes      | N/A           | API domain: `crypto`, `auth`, `storage`, `network` |
| `--style`          | string   | No       | `builder`     | API style: `builder`, `functional`, `object`     |
| `--output`         | string   | No       | `api-design.md` | Output file path                               |
| `--examples`       | boolean  | No       | `true`        | Generate usage examples                          |
| `--zero-cost`      | boolean  | No       | `true`        | Ensure zero-cost abstractions                    |

---

## Output

### Console Output

```
🎨 Syntek Rust Security - API Design

📦 Domain: Cryptography
🎯 Style: Builder pattern
🔐 Security-first design

✅ Generated API Design:

Public API Surface:
  - 12 public types
  - 8 public traits
  - 24 public functions
  - 6 builder types

Type Safety Features:
  - Newtype wrappers for key material
  - Phantom types for compile-time validation
  - Const generics for buffer sizes
  - Zero-sized types for state machines

Security Guarantees:
  - Keys cannot be printed or logged
  - Compile-time algorithm verification
  - Constant-time operations enforced
  - No unsafe code in public API

📝 Files created:
  - src/api/crypto.rs (API definitions)
  - examples/api_usage.rs (Usage examples)
  - docs/API-DESIGN.md (Design rationale)

📚 Example usage:

```rust
use crypto_lib::{Cipher, Key, Nonce};

// Type-safe API prevents misuse
let key = Key::generate()?;
let nonce = Nonce::generate()?;

let cipher = Cipher::builder()
    .algorithm(Algorithm::Aes256Gcm)
    .key(key)
    .build()?;

let ciphertext = cipher.encrypt(&nonce, b"secret data")?;
let plaintext = cipher.decrypt(&nonce, &ciphertext)?;
```
```

---

## Examples

### Example 1: Cryptography API

```bash
/rust-security:design-api --domain=crypto --style=builder
```

Designs type-safe cryptography API with builder pattern.

### Example 2: Authentication API

```bash
/rust-security:design-api --domain=auth --examples=true
```

Designs authentication API with comprehensive examples.

### Example 3: Storage API

```bash
/rust-security:design-api --domain=storage --zero-cost=true
```

Designs zero-cost storage abstraction.

### Example 4: Network API

```bash
/rust-security:design-api --domain=network --style=functional
```

Designs functional-style network API.

---

## Best Practices

### Type-Safe Cryptography API

```rust
use std::marker::PhantomData;

/// Encryption key with compile-time algorithm tracking
pub struct Key<A: Algorithm> {
    bytes: Vec<u8>,
    _algorithm: PhantomData<A>,
}

/// Algorithm marker traits
pub trait Algorithm {
    const KEY_SIZE: usize;
    const NONCE_SIZE: usize;
}

pub struct Aes256Gcm;
impl Algorithm for Aes256Gcm {
    const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 12;
}

impl<A: Algorithm> Key<A> {
    /// Generate cryptographically secure key
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = vec![0u8; A::KEY_SIZE];
        getrandom::getrandom(&mut bytes)?;
        Ok(Self {
            bytes,
            _algorithm: PhantomData,
        })
    }

    /// Import key from bytes (constant-time)
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() != A::KEY_SIZE {
            return Err(Error::InvalidKeySize);
        }
        Ok(Self {
            bytes,
            _algorithm: PhantomData,
        })
    }
}

// Prevent accidental key disclosure
impl<A: Algorithm> Drop for Key<A> {
    fn drop(&mut self) {
        // Zero out key material
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}

// Prevent Debug printing of keys
impl<A: Algorithm> std::fmt::Debug for Key<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("algorithm", &std::any::type_name::<A>())
            .finish_non_exhaustive()
    }
}
```

### Builder Pattern for Complex APIs

```rust
/// Cipher builder with compile-time validation
pub struct CipherBuilder<A> {
    algorithm: PhantomData<A>,
    key: Option<Key<A>>,
    mode: Option<Mode>,
}

impl<A: Algorithm> CipherBuilder<A> {
    pub fn new() -> Self {
        Self {
            algorithm: PhantomData,
            key: None,
            mode: None,
        }
    }

    pub fn key(mut self, key: Key<A>) -> Self {
        self.key = Some(key);
        self
    }

    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = Some(mode);
        self
    }

    pub fn build(self) -> Result<Cipher<A>, Error> {
        let key = self.key.ok_or(Error::MissingKey)?;
        let mode = self.mode.unwrap_or(Mode::default());

        Ok(Cipher {
            key,
            mode,
            _algorithm: PhantomData,
        })
    }
}

/// Type-state pattern for API safety
pub struct Cipher<A: Algorithm> {
    key: Key<A>,
    mode: Mode,
    _algorithm: PhantomData<A>,
}

impl<A: Algorithm> Cipher<A> {
    pub fn builder() -> CipherBuilder<A> {
        CipherBuilder::new()
    }

    pub fn encrypt(&self, nonce: &Nonce<A>, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        // Implementation
    }

    pub fn decrypt(&self, nonce: &Nonce<A>, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        // Implementation
    }
}
```

### Error Design

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: authentication tag mismatch")]
    AuthenticationFailed,

    #[error("Random number generation failed")]
    RngError(#[from] getrandom::Error),

    #[error("Invalid nonce size")]
    InvalidNonceSize,
}
```

---

## Related Commands

- **[/rust-security:generate-docs](generate-docs.md)** - Document designed API
- **[/rust-security:write-tests](write-tests.md)** - Test API design
- **[/rust-security:review-code](review-code.md)** - Review API implementation

---

**Note:** This command uses Opus model for sophisticated API design following Rust API guidelines. Designs should be reviewed by domain experts before implementation.
