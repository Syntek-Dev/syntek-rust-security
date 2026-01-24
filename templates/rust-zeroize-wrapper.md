# Rust Zeroize Wrapper Template

## Overview

This template provides memory zeroization wrapper types for secure handling of
sensitive data, ensuring secrets are wiped from memory when no longer needed.

**Target Use Cases:**

- Secure password handling
- Encryption key management
- API token storage
- Sensitive configuration data

## Project Structure

```
my-zeroize-wrapper/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── types.rs
│   ├── allocator.rs
│   └── guards.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-zeroize-wrapper"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"

[dependencies]
zeroize = { version = "1.8", features = ["derive", "aarch64"] }
secrecy = { version = "0.10", features = ["serde"] }
serde = { version = "1.0", features = ["derive"] }
```

## Core Implementation

### src/types.rs

```rust
use secrecy::{ExposeSecret, Secret, Zeroize};
use std::fmt;

/// Secure string that zeroizes on drop
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecureString {
    inner: String,
}

impl SecureString {
    pub fn new(s: impl Into<String>) -> Self {
        Self { inner: s.into() }
    }

    pub fn expose(&self) -> &str {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureString([REDACTED])")
    }
}

/// Secure byte buffer that zeroizes on drop
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecureBytes {
    inner: Vec<u8>,
}

impl SecureBytes {
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self { inner: data.into() }
    }

    pub fn expose(&self) -> &[u8] {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureBytes([REDACTED, len={}])", self.inner.len())
    }
}

/// Fixed-size secure key (32 bytes)
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecureKey {
    inner: [u8; 32],
}

impl SecureKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { inner: key }
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(slice);
            Some(Self { inner: key })
        } else {
            None
        }
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.inner
    }
}

impl fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureKey([REDACTED])")
    }
}
```

### src/guards.rs

```rust
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// Guard that zeroizes data when dropped
pub struct ZeroizeGuard<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> ZeroizeGuard<T> {
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }
}

impl<T: Zeroize> Deref for ZeroizeGuard<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: Zeroize> DerefMut for ZeroizeGuard<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: Zeroize> Drop for ZeroizeGuard<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

/// Scope guard for temporary secret exposure
pub fn with_secret<T, R, F>(secret: &T, f: F) -> R
where
    T: Clone + Zeroize,
    F: FnOnce(&T) -> R,
{
    let result = f(secret);
    // Secret is not modified here, but pattern shows usage
    result
}
```

## Security Checklist

- [ ] All sensitive types derive Zeroize
- [ ] Drop implementations zeroize data
- [ ] Debug implementations redact secrets
- [ ] Clone implementations handle securely
- [ ] No accidental exposure in logs
