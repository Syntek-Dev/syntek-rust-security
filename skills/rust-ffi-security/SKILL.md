# Rust FFI Security Skills

This skill provides security patterns for Foreign Function Interface (FFI)
boundaries including PyO3 (Python), Neon (Node.js), UniFFI (cross-platform), and
wasm-bindgen (WebAssembly).

## Overview

FFI boundaries are security-critical code paths where:

- **Memory ownership** crosses language boundaries
- **Type safety** may be compromised
- **Error handling** must be carefully managed
- **Lifetimes** cannot be enforced across languages

## /ffi-audit

Audit FFI boundaries for security vulnerabilities.

### Usage

```bash
/ffi-audit [path]
```

Examples:

```bash
/ffi-audit                     # Audit entire project
/ffi-audit src/python/         # Audit Python bindings
/ffi-audit src/ffi.rs          # Audit specific file
```

### What It Does

1. Scans for FFI boundary definitions
2. Verifies memory ownership is correctly transferred
3. Checks for null pointer handling
4. Reviews error propagation across boundaries
5. Validates string encoding (UTF-8/UTF-16)
6. Checks for use-after-free possibilities
7. Reviews thread safety in FFI calls

---

## PyO3 (Python) Security Patterns

### Safe Function Export

```rust
use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

/// Secure encryption function exposed to Python
#[pyfunction]
fn encrypt_data(py: Python<'_>, data: &[u8], key: &[u8]) -> PyResult<Vec<u8>> {
    // Validate inputs before processing
    if key.len() != 32 {
        return Err(PyValueError::new_err("Key must be 32 bytes"));
    }

    if data.is_empty() {
        return Err(PyValueError::new_err("Data cannot be empty"));
    }

    // Release GIL for CPU-intensive crypto
    py.allow_threads(|| {
        internal_encrypt(data, key)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    })
}
```

### Memory-Safe String Handling

```rust
use pyo3::prelude::*;

#[pyfunction]
fn process_string(input: &str) -> PyResult<String> {
    // PyO3 validates UTF-8 automatically
    // Input is guaranteed to be valid UTF-8

    // Process safely
    let result = input.to_uppercase();
    Ok(result)
}

// For bytes that may not be UTF-8:
#[pyfunction]
fn process_bytes(data: &[u8]) -> PyResult<Vec<u8>> {
    // Handle arbitrary bytes safely
    Ok(data.to_vec())
}
```

### Secure Key Handling with Zeroization

```rust
use pyo3::prelude::*;
use zeroize::Zeroizing;

#[pyclass]
struct SecureKey {
    key: Zeroizing<Vec<u8>>,
}

#[pymethods]
impl SecureKey {
    #[new]
    fn new(key_bytes: &[u8]) -> PyResult<Self> {
        if key_bytes.len() != 32 {
            return Err(PyValueError::new_err("Invalid key length"));
        }
        Ok(Self {
            key: Zeroizing::new(key_bytes.to_vec()),
        })
    }

    fn encrypt(&self, data: &[u8]) -> PyResult<Vec<u8>> {
        internal_encrypt(data, &self.key)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }
}

// Key material is automatically zeroized when SecureKey is dropped
```

### Thread Safety in PyO3

```rust
use pyo3::prelude::*;
use std::sync::{Arc, RwLock};

#[pyclass]
struct ThreadSafeConfig {
    inner: Arc<RwLock<ConfigInner>>,
}

#[pymethods]
impl ThreadSafeConfig {
    #[new]
    fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(ConfigInner::default())),
        }
    }

    fn get_value(&self, key: &str) -> PyResult<Option<String>> {
        let guard = self.inner.read()
            .map_err(|_| PyRuntimeError::new_err("Lock poisoned"))?;
        Ok(guard.get(key))
    }

    fn set_value(&self, key: &str, value: &str) -> PyResult<()> {
        let mut guard = self.inner.write()
            .map_err(|_| PyRuntimeError::new_err("Lock poisoned"))?;
        guard.set(key, value);
        Ok(())
    }
}
```

---

## Neon (Node.js) Security Patterns

### Safe Function Export

```rust
use neon::prelude::*;
use neon::types::buffer::TypedArray;

fn encrypt_buffer(mut cx: FunctionContext) -> JsResult<JsBuffer> {
    // Get and validate arguments
    let data = cx.argument::<JsBuffer>(0)?;
    let key = cx.argument::<JsBuffer>(1)?;

    let key_bytes = key.as_slice(&cx);
    if key_bytes.len() != 32 {
        return cx.throw_error("Key must be 32 bytes");
    }

    let data_bytes = data.as_slice(&cx);
    if data_bytes.is_empty() {
        return cx.throw_error("Data cannot be empty");
    }

    // Perform encryption
    let result = match internal_encrypt(data_bytes, key_bytes) {
        Ok(encrypted) => encrypted,
        Err(e) => return cx.throw_error(e.to_string()),
    };

    // Create result buffer
    let mut result_buffer = cx.buffer(result.len())?;
    result_buffer.as_mut_slice(&mut cx).copy_from_slice(&result);

    Ok(result_buffer)
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("encryptBuffer", encrypt_buffer)?;
    Ok(())
}
```

### Async Operations with Proper Error Handling

```rust
use neon::prelude::*;
use neon::types::Deferred;

fn async_encrypt(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let data = cx.argument::<JsBuffer>(0)?;
    let key = cx.argument::<JsBuffer>(1)?;

    // Copy data for async processing
    let data_vec = data.as_slice(&cx).to_vec();
    let key_vec = key.as_slice(&cx).to_vec();

    let channel = cx.channel();
    let (deferred, promise) = cx.promise();

    // Spawn async task
    std::thread::spawn(move || {
        let result = internal_encrypt(&data_vec, &key_vec);

        deferred.settle_with(&channel, move |mut cx| {
            match result {
                Ok(encrypted) => {
                    let mut buffer = cx.buffer(encrypted.len())?;
                    buffer.as_mut_slice(&mut cx).copy_from_slice(&encrypted);
                    Ok(buffer)
                }
                Err(e) => cx.throw_error(e.to_string()),
            }
        });
    });

    Ok(promise)
}
```

### Class with Proper Resource Management

```rust
use neon::prelude::*;
use std::cell::RefCell;

type BoxedCipher = JsBox<RefCell<CipherWrapper>>;

struct CipherWrapper {
    key: zeroize::Zeroizing<Vec<u8>>,
}

impl Finalize for CipherWrapper {
    fn finalize<'a, C: Context<'a>>(self, _: &mut C) {
        // Key is automatically zeroized on drop
    }
}

fn cipher_new(mut cx: FunctionContext) -> JsResult<BoxedCipher> {
    let key = cx.argument::<JsBuffer>(0)?;
    let key_bytes = key.as_slice(&cx);

    if key_bytes.len() != 32 {
        return cx.throw_error("Key must be 32 bytes");
    }

    let wrapper = CipherWrapper {
        key: zeroize::Zeroizing::new(key_bytes.to_vec()),
    };

    Ok(cx.boxed(RefCell::new(wrapper)))
}
```

---

## UniFFI (Cross-Platform) Security Patterns

### UDL Definition with Validation

```webidl
// crypto.udl
namespace crypto {
    [Throws=CryptoError]
    sequence<u8> encrypt(sequence<u8> data, sequence<u8> key);

    [Throws=CryptoError]
    sequence<u8> decrypt(sequence<u8> data, sequence<u8> key);
};

[Error]
enum CryptoError {
    "InvalidKeyLength",
    "InvalidData",
    "EncryptionFailed",
    "DecryptionFailed",
};

interface SecureVault {
    [Throws=CryptoError]
    constructor(sequence<u8> master_key);

    [Throws=CryptoError]
    sequence<u8> encrypt([ByRef] sequence<u8> data);

    [Throws=CryptoError]
    sequence<u8> decrypt([ByRef] sequence<u8> data);
};
```

### Rust Implementation

```rust
use uniffi;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CryptoError {
    #[error("Invalid key length: expected 32 bytes")]
    InvalidKeyLength,
    #[error("Invalid data")]
    InvalidData,
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
}

#[uniffi::export]
pub fn encrypt(data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength);
    }
    if data.is_empty() {
        return Err(CryptoError::InvalidData);
    }

    let key = Zeroizing::new(key);
    internal_encrypt(&data, &key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))
}

#[derive(uniffi::Object)]
pub struct SecureVault {
    key: Zeroizing<Vec<u8>>,
}

#[uniffi::export]
impl SecureVault {
    #[uniffi::constructor]
    pub fn new(master_key: Vec<u8>) -> Result<Self, CryptoError> {
        if master_key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }
        Ok(Self {
            key: Zeroizing::new(master_key),
        })
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        internal_encrypt(data, &self.key)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))
    }
}

uniffi::include_scaffolding!("crypto");
```

---

## wasm-bindgen (WebAssembly) Security Patterns

### Safe WASM Exports

```rust
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

#[wasm_bindgen]
pub fn encrypt_wasm(data: &[u8], key: &[u8]) -> Result<Vec<u8>, JsError> {
    if key.len() != 32 {
        return Err(JsError::new("Key must be 32 bytes"));
    }

    internal_encrypt(data, key)
        .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub struct WasmCipher {
    key: Vec<u8>,
}

#[wasm_bindgen]
impl WasmCipher {
    #[wasm_bindgen(constructor)]
    pub fn new(key: &[u8]) -> Result<WasmCipher, JsError> {
        if key.len() != 32 {
            return Err(JsError::new("Key must be 32 bytes"));
        }
        Ok(Self { key: key.to_vec() })
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, JsError> {
        internal_encrypt(data, &self.key)
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

impl Drop for WasmCipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
```

### Memory Safety in WASM

```rust
use wasm_bindgen::prelude::*;
use js_sys::Uint8Array;

#[wasm_bindgen]
pub fn process_large_data(data: Uint8Array) -> Result<Uint8Array, JsError> {
    // Copy data into Rust memory
    let rust_data = data.to_vec();

    // Process
    let result = process_internal(&rust_data)?;

    // Return as Uint8Array
    let output = Uint8Array::new_with_length(result.len() as u32);
    output.copy_from(&result);
    Ok(output)
}

// Zero-copy for performance-critical paths (use with caution)
#[wasm_bindgen]
pub fn hash_data(data: &[u8]) -> Vec<u8> {
    // data is borrowed directly from JS memory
    // Safe because we only read and don't store reference
    compute_hash(data)
}
```

---

## Common FFI Vulnerabilities

### 1. Use-After-Free

```rust
// VULNERABLE: Returning reference to local data
#[no_mangle]
pub extern "C" fn get_string() -> *const u8 {
    let s = String::from("hello");
    s.as_ptr()  // s is dropped, pointer is dangling!
}

// SECURE: Return owned data or use proper lifetime
#[no_mangle]
pub extern "C" fn get_string_safe(out: *mut u8, out_len: usize) -> i32 {
    let s = "hello";
    if s.len() > out_len {
        return -1;  // Buffer too small
    }
    unsafe {
        std::ptr::copy_nonoverlapping(s.as_ptr(), out, s.len());
    }
    s.len() as i32
}
```

### 2. Null Pointer Dereference

```rust
// VULNERABLE: No null check
#[no_mangle]
pub extern "C" fn process(ptr: *const u8, len: usize) {
    unsafe {
        let slice = std::slice::from_raw_parts(ptr, len);  // Crash if ptr is null!
    }
}

// SECURE: Check for null
#[no_mangle]
pub extern "C" fn process_safe(ptr: *const u8, len: usize) -> i32 {
    if ptr.is_null() {
        return -1;  // Error: null pointer
    }
    if len == 0 {
        return 0;  // Nothing to process
    }
    unsafe {
        let slice = std::slice::from_raw_parts(ptr, len);
        // Process slice...
    }
    0
}
```

### 3. Buffer Overflow

```rust
// VULNERABLE: No bounds checking
#[no_mangle]
pub extern "C" fn copy_data(src: *const u8, dst: *mut u8, len: usize) {
    unsafe {
        std::ptr::copy_nonoverlapping(src, dst, len);  // May overflow dst!
    }
}

// SECURE: Require destination length
#[no_mangle]
pub extern "C" fn copy_data_safe(
    src: *const u8,
    src_len: usize,
    dst: *mut u8,
    dst_len: usize,
) -> i32 {
    if src.is_null() || dst.is_null() {
        return -1;
    }
    if src_len > dst_len {
        return -2;  // Destination too small
    }
    unsafe {
        std::ptr::copy_nonoverlapping(src, dst, src_len);
    }
    src_len as i32
}
```

---

## FFI Security Checklist

### Input Validation

- [ ] All pointers checked for null
- [ ] All lengths validated
- [ ] String encoding verified (UTF-8)
- [ ] Numeric values checked for overflow

### Memory Safety

- [ ] No dangling pointers returned
- [ ] Ownership clearly transferred or borrowed
- [ ] Resources properly freed
- [ ] Keys/secrets zeroized on drop

### Thread Safety

- [ ] Concurrent access handled
- [ ] GIL released for long operations (Python)
- [ ] Locks used for shared state

### Database Access (PostgreSQL RLS)

When FFI code (PyO3, Neon, UniFFI) calls into Rust that queries PostgreSQL:

- [ ] `user_id` (or equivalent) passed through the FFI boundary into the Rust DB layer
- [ ] `set_config('app.current_user_id', $1, true)` called within every transaction before any user-scoped query
- [ ] PostgreSQL RLS policies enabled (`ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY`) on all relevant tables
- [ ] The DB connection pool does **not** use a superuser role (superusers bypass RLS unless `FORCE` is set; prefer `FORCE` + an `app_user` role)
- [ ] Tests verify cross-user data isolation at the DB level, not just at the application layer

```rust
// Pattern: PyO3 function receiving user_id and setting RLS before querying
#[pyfunction]
pub fn fetch_user_documents(
    py: Python<'_>,
    user_id: &str,
    pool: &PyAny,
) -> PyResult<Vec<String>> {
    // user_id comes from the authenticated Python session
    let uid: uuid::Uuid = user_id.parse()
        .map_err(|_| PyValueError::new_err("Invalid user_id"))?;

    py.allow_threads(|| {
        tokio::runtime::Handle::current().block_on(async {
            let pool = get_pool(); // retrieve sqlx pool
            let mut tx = pool.begin().await.map_err(|e| {
                PyRuntimeError::new_err(e.to_string())
            })?;
            // ✅ Set RLS context — must happen before any query
            sqlx::query("SELECT set_config('app.current_user_id', $1, true)")
                .bind(uid.to_string())
                .execute(tx.as_mut())
                .await
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

            let docs: Vec<String> = sqlx::query_scalar("SELECT title FROM documents")
                .fetch_all(tx.as_mut())
                .await
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

            tx.commit().await.map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            Ok(docs)
        })
    })
}
```

### Error Handling

- [ ] Errors properly propagated
- [ ] Panic boundaries established
- [ ] Error messages don't leak sensitive info

### Testing

- [ ] Fuzz testing FFI boundaries
- [ ] Memory sanitizers (ASAN, MSAN)
- [ ] Thread sanitizer (TSAN)
- [ ] Miri for undefined behavior

## Recommended Crates

- **pyo3**: Python bindings
- **neon**: Node.js bindings
- **uniffi**: Cross-platform bindings
- **wasm-bindgen**: WebAssembly bindings
- **cbindgen**: C header generation
- **zeroize**: Secure memory clearing
- **thiserror**: Error types

## Best Practices

1. **Validate all inputs** at FFI boundaries
2. **Use high-level bindings** (PyO3, Neon) over raw C FFI
3. **Zeroize sensitive data** when crossing boundaries
4. **Catch panics** at FFI boundaries
5. **Document ownership** semantics clearly
6. **Test with sanitizers** (ASAN, MSAN, TSAN)
7. **Fuzz test** FFI functions
8. **Minimize unsafe** code surface
