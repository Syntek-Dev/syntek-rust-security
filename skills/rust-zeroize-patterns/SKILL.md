# Rust Zeroize Patterns Skills

This skill provides patterns for secure memory management, automatic zeroization
of sensitive data, and preventing secrets from lingering in memory.

## Overview

Memory zeroization is critical for:

- **Cryptographic Keys**: Preventing key extraction from memory
- **Passwords**: Clearing authentication data
- **Sensitive Data**: PII, tokens, secrets
- **Buffer Handling**: Preventing information leakage
- **Crash Safety**: Ensuring secrets aren't in core dumps

## /zeroize-audit

Audit code for proper memory zeroization.

### Usage

```bash
/zeroize-audit [path]
```

### What It Does

1. Scans for secret-handling code
2. Verifies zeroize derives and implementations
3. Checks for Drop implementations
4. Identifies potential secret leakage
5. Suggests fixes for unsafe patterns

---

## Basic Zeroization Patterns

### Using Zeroize Derive

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

// Automatic zeroization on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ApiCredentials {
    api_key: String,
    api_secret: String,
}

// Manual zeroization
#[derive(Zeroize)]
pub struct TemporaryKey {
    key_material: Vec<u8>,
}

impl TemporaryKey {
    pub fn use_and_clear(&mut self) {
        // Use the key...
        do_something_with_key(&self.key_material);

        // Explicitly zeroize
        self.zeroize();
    }
}
```

### Zeroizing Wrapper

```rust
use zeroize::Zeroizing;

// Automatically zeroizes on drop
pub fn process_password(password: &str) {
    // Wrap sensitive data
    let password_bytes = Zeroizing::new(password.as_bytes().to_vec());

    // Process password
    let hash = hash_password(&password_bytes);

    // password_bytes automatically zeroized when dropped
}

// Function that handles secrets
pub fn get_api_key() -> Zeroizing<String> {
    let key = std::env::var("API_KEY").unwrap_or_default();
    Zeroizing::new(key)
}
```

### Custom Types with Zeroization

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone)]
pub struct SecretKey([u8; 32]);

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ZeroizeOnDrop marker for compile-time verification
unsafe impl ZeroizeOnDrop for SecretKey {}

impl SecretKey {
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("RNG failure");
        Self(key)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Some(Self(key))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
```

---

## Secrecy Crate Integration

### Using Secret<T>

```rust
use secrecy::{Secret, ExposeSecret, SecretString};

pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Secret<String>,  // Protected
}

impl DatabaseConfig {
    pub fn connection_string(&self) -> SecretString {
        SecretString::new(format!(
            "postgres://{}:{}@{}:{}",
            self.username,
            self.password.expose_secret(),  // Explicit access
            self.host,
            self.port
        ))
    }
}

// SecretString is automatically zeroized on drop
pub fn authenticate(username: &str, password: SecretString) -> Result<Token, Error> {
    let password_ref = password.expose_secret();

    // Use password for authentication
    let token = do_authentication(username, password_ref)?;

    // password is automatically zeroized when function returns
    Ok(token)
}
```

### Custom Secrecy Types

```rust
use secrecy::{CloneableSecret, DebugSecret, Secret, Zeroize};

#[derive(Clone)]
pub struct EncryptionKey(Vec<u8>);

impl Zeroize for EncryptionKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl CloneableSecret for EncryptionKey {}
impl DebugSecret for EncryptionKey {}

pub type SecretEncryptionKey = Secret<EncryptionKey>;

// Debug output shows "[REDACTED]" instead of actual key
// Clone is available but still protected
```

---

## Secure Memory Allocation

### Protected Memory with Memsec

```rust
// Note: memsec provides additional protections like mlock

use std::ops::{Deref, DerefMut};

pub struct LockedBuffer {
    ptr: *mut u8,
    len: usize,
}

impl LockedBuffer {
    pub fn new(size: usize) -> Result<Self, Error> {
        // Allocate memory
        let layout = std::alloc::Layout::from_size_align(size, 8)?;
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };

        if ptr.is_null() {
            return Err(Error::AllocationFailed);
        }

        // Lock memory to prevent swapping (requires privileges)
        #[cfg(unix)]
        unsafe {
            libc::mlock(ptr as *const libc::c_void, size);
        }

        Ok(Self { ptr, len: size })
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        // Zeroize before freeing
        unsafe {
            std::ptr::write_bytes(self.ptr, 0, self.len);
        }

        // Unlock memory
        #[cfg(unix)]
        unsafe {
            libc::munlock(self.ptr as *const libc::c_void, self.len);
        }

        // Free memory
        let layout = std::alloc::Layout::from_size_align(self.len, 8).unwrap();
        unsafe {
            std::alloc::dealloc(self.ptr, layout);
        }
    }
}
```

### Secure Temporary Buffer

```rust
use zeroize::Zeroize;

pub struct SecureTempBuffer<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> SecureTempBuffer<N> {
    pub fn new() -> Self {
        Self { data: [0u8; N] }
    }

    pub fn fill_with<F>(&mut self, f: F)
    where
        F: FnOnce(&mut [u8]),
    {
        f(&mut self.data);
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> Drop for SecureTempBuffer<N> {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

// Usage
fn derive_key(password: &[u8]) -> [u8; 32] {
    let mut buffer = SecureTempBuffer::<64>::new();

    // Use buffer for intermediate computations
    buffer.fill_with(|buf| {
        // Some key derivation operation...
    });

    let mut result = [0u8; 32];
    result.copy_from_slice(&buffer.as_slice()[..32]);

    // buffer automatically zeroized when dropped
    result
}
```

---

## Cryptographic Key Patterns

### Key Container

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, aead::Aead};

#[derive(ZeroizeOnDrop)]
pub struct KeyContainer {
    #[zeroize(skip)]  // ChaCha20Poly1305 handles its own cleanup
    cipher: ChaCha20Poly1305,
    key_bytes: [u8; 32],  // Keep for potential re-use
}

impl KeyContainer {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(key);

        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            key_bytes,
        }
    }

    pub fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.cipher
            .encrypt(nonce.into(), plaintext)
            .map_err(|_| Error::Encryption)
    }

    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.cipher
            .decrypt(nonce.into(), ciphertext)
            .map_err(|_| Error::Decryption)
    }
}
```

### Key Derivation with Zeroization

```rust
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use zeroize::Zeroizing;

pub fn derive_key_from_password(
    password: &str,
    salt: &[u8; 16],
) -> Zeroizing<[u8; 32]> {
    let mut derived_key = Zeroizing::new([0u8; 32]);

    Argon2::default()
        .hash_password_into(
            password.as_bytes(),
            salt,
            derived_key.as_mut(),
        )
        .expect("Key derivation failed");

    derived_key
}

pub fn hash_password_secure(password: Zeroizing<String>) -> String {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.expose_secret().as_bytes(), &salt)
        .expect("Password hashing failed")
        .to_string()

    // password automatically zeroized
}
```

---

## Preventing Compiler Optimizations

### Volatile Zeroization

```rust
use std::ptr;

/// Zeroize that can't be optimized away
pub fn secure_zeroize(data: &mut [u8]) {
    unsafe {
        ptr::write_volatile(data.as_mut_ptr(), 0);
        for i in 0..data.len() {
            ptr::write_volatile(data.as_mut_ptr().add(i), 0);
        }
        // Memory barrier to ensure writes complete
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Zeroize using assembly (x86_64)
#[cfg(target_arch = "x86_64")]
pub fn asm_zeroize(data: &mut [u8]) {
    unsafe {
        std::arch::asm!(
            "rep stosb",
            inout("rdi") data.as_mut_ptr() => _,
            inout("rcx") data.len() => _,
            in("al") 0u8,
            options(nostack)
        );
    }
}
```

### Constant-Time Comparison

```rust
use subtle::ConstantTimeEq;

pub fn verify_secret(provided: &[u8], expected: &[u8]) -> bool {
    // Constant-time comparison prevents timing attacks
    provided.ct_eq(expected).into()
}

pub fn verify_password_hash(
    password: &Zeroizing<String>,
    hash: &str,
) -> bool {
    use argon2::{Argon2, PasswordVerifier, PasswordHash};

    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}
```

---

## Audit Patterns

### Detecting Non-Zeroized Secrets

```rust
// Compile-time marker for types that must be zeroized
pub trait MustZeroize: Zeroize {}

// Runtime verification (debug builds)
#[cfg(debug_assertions)]
pub fn verify_zeroized(data: &[u8], name: &str) {
    let all_zero = data.iter().all(|&b| b == 0);
    if !all_zero {
        panic!("Security violation: {} was not properly zeroized", name);
    }
}

#[cfg(not(debug_assertions))]
pub fn verify_zeroized(_data: &[u8], _name: &str) {
    // No-op in release builds
}
```

### Audit Wrapper

```rust
use std::ops::{Deref, DerefMut};

pub struct AuditedSecret<T: Zeroize> {
    inner: T,
    #[cfg(debug_assertions)]
    accessed: std::cell::Cell<bool>,
}

impl<T: Zeroize> AuditedSecret<T> {
    pub fn new(value: T) -> Self {
        Self {
            inner: value,
            #[cfg(debug_assertions)]
            accessed: std::cell::Cell::new(false),
        }
    }

    pub fn expose(&self) -> &T {
        #[cfg(debug_assertions)]
        {
            self.accessed.set(true);
            tracing::trace!("Secret accessed at {:?}", std::backtrace::Backtrace::capture());
        }
        &self.inner
    }
}

impl<T: Zeroize> Drop for AuditedSecret<T> {
    fn drop(&mut self) {
        self.inner.zeroize();

        #[cfg(debug_assertions)]
        if !self.accessed.get() {
            tracing::warn!("Secret was created but never accessed - potential bug");
        }
    }
}
```

---

## Common Mistakes

### 1. Forgetting to Zeroize

```rust
// WRONG: Key not zeroized
fn bad_key_usage() {
    let key = get_encryption_key();
    encrypt_data(&key);
    // key goes out of scope without zeroization!
}

// CORRECT: Use Zeroizing wrapper
fn good_key_usage() {
    let key = Zeroizing::new(get_encryption_key());
    encrypt_data(&key);
    // key automatically zeroized on drop
}
```

### 2. Logging Secrets

```rust
// WRONG: Secret logged
tracing::info!("Processing with key: {:?}", api_key);

// CORRECT: Use Debug-redacting wrapper
#[derive(Debug)]
struct RedactedKey(SecretString);

impl std::fmt::Debug for RedactedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}
```

### 3. Cloning Without Zeroization

```rust
// WRONG: Clone doesn't zeroize original
let key_copy = key.clone();
// Now both key and key_copy have the secret

// CORRECT: Use types that track copies
use secrecy::Secret;
let key: Secret<Vec<u8>> = Secret::new(get_key());
// Clone is not available unless explicitly allowed
```

---

## Zeroization Checklist

### Code Review

- [ ] All secret types derive/implement `Zeroize`
- [ ] All secret types derive/implement `ZeroizeOnDrop` or have custom `Drop`
- [ ] Secrets wrapped in `Zeroizing<T>` or `Secret<T>`
- [ ] No secrets in debug output
- [ ] No secrets in error messages
- [ ] No secrets in logs

### Memory Safety

- [ ] Keys zeroized immediately after use
- [ ] Temporary buffers zeroized
- [ ] No secrets in string interpolation
- [ ] Secrets not passed through many layers

### Compiler Safety

- [ ] Volatile writes used where needed
- [ ] Memory barriers after zeroization
- [ ] No dead code elimination of zeroization

## Recommended Crates

- **zeroize**: Core zeroization functionality
- **secrecy**: Secret wrapping with controlled access
- **subtle**: Constant-time operations
- **argon2**: Password hashing with built-in zeroization

## Best Practices

1. **Default to zeroization** - Use `Zeroizing<T>` for all secrets
2. **Minimize secret lifetime** - Create, use, destroy quickly
3. **Use strong types** - Newtype wrappers for secret data
4. **Test zeroization** - Debug assertions for verification
5. **Audit regularly** - Review code for secret handling
6. **Don't trust optimizers** - Use volatile writes

## Integration Points

This skill works well with:

- `/crypto-review` - Review cryptographic key handling
- `/memory-audit` - Analyze unsafe code for memory safety
