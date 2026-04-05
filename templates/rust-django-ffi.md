# Rust Django FFI Template

## Overview

This template provides a secure foundation for integrating Rust code into Django
applications using PyO3. It enables high-performance, memory-safe operations for
encryption, data processing, and security-critical functionality while
maintaining Python's developer experience.

**Target Use Cases:**

- Custom encryption/decryption in Django backends
- High-performance data processing
- Secure memory handling for sensitive data
- Cryptographic operations (key derivation, hashing)
- Performance-critical API endpoints

## Project Structure

```
my-django-rust/
├── Cargo.toml
├── pyproject.toml
├── src/
│   ├── lib.rs                 # PyO3 module entry point
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── encrypt.rs         # Encryption functions
│   │   ├── decrypt.rs         # Decryption functions
│   │   └── keys.rs            # Key management
│   ├── memory/
│   │   ├── mod.rs
│   │   ├── secure.rs          # Secure memory types
│   │   └── zeroize.rs         # Memory zeroization
│   ├── errors.rs              # Python-compatible errors
│   └── types.rs               # Type conversions
├── python/
│   └── my_django_rust/
│       ├── __init__.py        # Python package init
│       ├── crypto.py          # Python wrapper classes
│       └── py.typed           # PEP 561 marker
├── django_app/
│   ├── __init__.py
│   ├── models.py              # Encrypted field models
│   ├── middleware.py          # Security middleware
│   └── fields.py              # Custom Django fields
├── tests/
│   ├── test_crypto.py
│   └── test_integration.py
├── .github/
│   └── workflows/
│       └── ci.yml
└── README.md
```

## Cargo.toml Template

```toml
[package]
name = "my-django-rust"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"
license = "MIT"

[lib]
name = "my_django_rust"
crate-type = ["cdylib"]

[dependencies]
# PyO3 for Python bindings
pyo3 = { version = "0.22", features = ["extension-module", "abi3-py39"] }

# Cryptography
aes-gcm = "0.10"
chacha20poly1305 = "0.10"
argon2 = "0.5"
rand = "0.8"
x25519-dalek = "2.0"

# Secure memory
zeroize = { version = "1.8", features = ["derive"] }
secrecy = "0.10"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
base64 = "0.22"

# Error handling
thiserror = "2.0"

[dev-dependencies]
pyo3 = { version = "0.22", features = ["auto-initialize"] }

[profile.release]
lto = true
codegen-units = 1
strip = true
```

## pyproject.toml

```toml
[build-system]
requires = ["maturin>=1.7,<2.0"]
build-backend = "maturin"

[project]
name = "my-django-rust"
version = "0.1.0"
description = "Secure Rust extensions for Django"
requires-python = ">=3.9"
classifiers = [
    "Programming Language :: Rust",
    "Programming Language :: Python :: Implementation :: CPython",
    "Framework :: Django :: 4.2",
    "Framework :: Django :: 5.0",
]
dependencies = [
    "django>=4.2",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-django>=4.5",
    "maturin>=1.7",
]

[tool.maturin]
features = ["pyo3/extension-module"]
python-source = "python"
module-name = "my_django_rust._core"
```

## Core Implementation

### src/lib.rs - PyO3 Module Entry

```rust
use pyo3::prelude::*;

mod crypto;
mod errors;
mod memory;
mod types;

use crypto::{decrypt_data, encrypt_data, derive_key};
use errors::CryptoError;
use memory::{SecureBytes, SecureString};

/// Rust cryptographic functions for Django
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register exception types
    m.add("CryptoError", m.py().get_type::<CryptoError>())?;

    // Encryption functions
    m.add_function(wrap_pyfunction!(encrypt_data, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_data, m)?)?;
    m.add_function(wrap_pyfunction!(derive_key, m)?)?;

    // Secure memory types
    m.add_class::<SecureBytes>()?;
    m.add_class::<SecureString>()?;

    // Version info
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    Ok(())
}
```

### src/crypto/encrypt.rs

```rust
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use pyo3::prelude::*;
use rand::RngCore;
use zeroize::Zeroize;

use crate::errors::CryptoError;

/// Encrypt data using AES-256-GCM
///
/// Args:
///     plaintext: Data to encrypt (bytes)
///     key: 32-byte encryption key
///     associated_data: Optional AAD for authenticated encryption
///
/// Returns:
///     Encrypted data with prepended nonce (nonce || ciphertext || tag)
#[pyfunction]
#[pyo3(signature = (plaintext, key, associated_data=None))]
pub fn encrypt_data(
    py: Python<'_>,
    plaintext: &[u8],
    key: &[u8],
    associated_data: Option<&[u8]>,
) -> PyResult<Vec<u8>> {
    py.allow_threads(|| {
        encrypt_aes_gcm(plaintext, key, associated_data)
            .map_err(|e| CryptoError::new_err(e.to_string()))
    })
}

fn encrypt_aes_gcm(
    plaintext: &[u8],
    key: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, &'static str> {
    if key.len() != 32 {
        return Err("Key must be exactly 32 bytes");
    }

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "Invalid key")?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt with optional AAD
    let ciphertext = match aad {
        Some(aad_bytes) => cipher
            .encrypt(nonce, aes_gcm::aead::Payload {
                msg: plaintext,
                aad: aad_bytes,
            })
            .map_err(|_| "Encryption failed")?,
        None => cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| "Encryption failed")?,
    };

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Encrypt string data, returning base64-encoded result
#[pyfunction]
#[pyo3(signature = (plaintext, key, associated_data=None))]
pub fn encrypt_string(
    py: Python<'_>,
    plaintext: &str,
    key: &[u8],
    associated_data: Option<&[u8]>,
) -> PyResult<String> {
    let encrypted = encrypt_data(py, plaintext.as_bytes(), key, associated_data)?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &encrypted,
    ))
}
```

### src/crypto/decrypt.rs

```rust
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pyo3::prelude::*;
use zeroize::Zeroize;

use crate::errors::CryptoError;

/// Decrypt data encrypted with AES-256-GCM
///
/// Args:
///     ciphertext: Encrypted data (nonce || ciphertext || tag)
///     key: 32-byte decryption key
///     associated_data: Optional AAD (must match encryption)
///
/// Returns:
///     Decrypted plaintext
#[pyfunction]
#[pyo3(signature = (ciphertext, key, associated_data=None))]
pub fn decrypt_data(
    py: Python<'_>,
    ciphertext: &[u8],
    key: &[u8],
    associated_data: Option<&[u8]>,
) -> PyResult<Vec<u8>> {
    py.allow_threads(|| {
        decrypt_aes_gcm(ciphertext, key, associated_data)
            .map_err(|e| CryptoError::new_err(e.to_string()))
    })
}

fn decrypt_aes_gcm(
    ciphertext: &[u8],
    key: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, &'static str> {
    if key.len() != 32 {
        return Err("Key must be exactly 32 bytes");
    }

    if ciphertext.len() < 12 + 16 {
        return Err("Ciphertext too short (must include nonce and tag)");
    }

    // Extract nonce and actual ciphertext
    let (nonce_bytes, encrypted) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "Invalid key")?;

    // Decrypt with optional AAD
    let mut plaintext = match aad {
        Some(aad_bytes) => cipher
            .decrypt(nonce, aes_gcm::aead::Payload {
                msg: encrypted,
                aad: aad_bytes,
            })
            .map_err(|_| "Decryption failed - invalid key or corrupted data")?,
        None => cipher
            .decrypt(nonce, encrypted)
            .map_err(|_| "Decryption failed - invalid key or corrupted data")?,
    };

    Ok(plaintext)
}

/// Decrypt base64-encoded string data
#[pyfunction]
#[pyo3(signature = (ciphertext_b64, key, associated_data=None))]
pub fn decrypt_string(
    py: Python<'_>,
    ciphertext_b64: &str,
    key: &[u8],
    associated_data: Option<&[u8]>,
) -> PyResult<String> {
    use base64::Engine;

    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(ciphertext_b64)
        .map_err(|e| CryptoError::new_err(format!("Invalid base64: {}", e)))?;

    let plaintext = decrypt_data(py, &ciphertext, key, associated_data)?;

    String::from_utf8(plaintext)
        .map_err(|e| CryptoError::new_err(format!("Invalid UTF-8: {}", e)))
}
```

### src/crypto/keys.rs

```rust
use argon2::{Argon2, password_hash::SaltString};
use pyo3::prelude::*;
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::errors::CryptoError;

/// Derive a 32-byte encryption key from a password using Argon2id
///
/// Args:
///     password: User password
///     salt: 16+ byte salt (use os.urandom(16) if not provided)
///     memory_cost: Memory cost in KiB (default: 65536 = 64MB)
///     time_cost: Number of iterations (default: 3)
///     parallelism: Degree of parallelism (default: 4)
///
/// Returns:
///     32-byte derived key
#[pyfunction]
#[pyo3(signature = (password, salt, memory_cost=65536, time_cost=3, parallelism=4))]
pub fn derive_key(
    py: Python<'_>,
    password: &str,
    salt: &[u8],
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
) -> PyResult<Vec<u8>> {
    py.allow_threads(|| {
        derive_key_argon2(password, salt, memory_cost, time_cost, parallelism)
            .map_err(|e| CryptoError::new_err(e.to_string()))
    })
}

fn derive_key_argon2(
    password: &str,
    salt: &[u8],
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<Vec<u8>, String> {
    if salt.len() < 8 {
        return Err("Salt must be at least 8 bytes".to_string());
    }

    let params = argon2::Params::new(memory_cost, time_cost, parallelism, Some(32))
        .map_err(|e| format!("Invalid Argon2 parameters: {}", e))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut output = vec![0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| format!("Key derivation failed: {}", e))?;

    Ok(output)
}

/// Generate a random salt for key derivation
#[pyfunction]
#[pyo3(signature = (length=16))]
pub fn generate_salt(length: usize) -> PyResult<Vec<u8>> {
    use rand::RngCore;

    if length < 8 {
        return Err(CryptoError::new_err("Salt must be at least 8 bytes"));
    }

    let mut salt = vec![0u8; length];
    OsRng.fill_bytes(&mut salt);
    Ok(salt)
}

/// Generate a random 32-byte encryption key
#[pyfunction]
pub fn generate_key() -> PyResult<Vec<u8>> {
    use rand::RngCore;

    let mut key = vec![0u8; 32];
    OsRng.fill_bytes(&mut key);
    Ok(key)
}
```

### src/memory/secure.rs

```rust
use pyo3::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure byte buffer that is zeroized on drop
#[pyclass]
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecureBytes {
    #[pyo3(get)]
    len: usize,
    data: Vec<u8>,
}

#[pymethods]
impl SecureBytes {
    #[new]
    pub fn new(data: Vec<u8>) -> Self {
        let len = data.len();
        Self { len, data }
    }

    /// Access the underlying bytes (use sparingly)
    pub fn expose(&self) -> Vec<u8> {
        self.data.clone()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Explicitly zeroize the buffer
    pub fn clear(&mut self) {
        self.data.zeroize();
        self.len = 0;
    }

    fn __repr__(&self) -> String {
        format!("SecureBytes(len={})", self.len)
    }

    fn __len__(&self) -> usize {
        self.len
    }
}

/// Secure string that is zeroized on drop
#[pyclass]
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecureString {
    #[pyo3(get)]
    len: usize,
    data: String,
}

#[pymethods]
impl SecureString {
    #[new]
    pub fn new(data: String) -> Self {
        let len = data.len();
        Self { len, data }
    }

    /// Access the underlying string (use sparingly)
    pub fn expose(&self) -> String {
        self.data.clone()
    }

    /// Check if string is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Explicitly zeroize the string
    pub fn clear(&mut self) {
        self.data.zeroize();
        self.len = 0;
    }

    fn __repr__(&self) -> String {
        format!("SecureString(len={})", self.len)
    }

    fn __len__(&self) -> usize {
        self.len
    }
}
```

### src/errors.rs

```rust
use pyo3::create_exception;
use pyo3::prelude::*;

// Create Python exception types
create_exception!(my_django_rust, CryptoError, pyo3::exceptions::PyException);
create_exception!(my_django_rust, KeyDerivationError, CryptoError);
create_exception!(my_django_rust, EncryptionError, CryptoError);
create_exception!(my_django_rust, DecryptionError, CryptoError);
```

## Django Integration

### python/my_django_rust/**init**.py

```python
"""Secure Rust extensions for Django."""

from ._core import (
    encrypt_data,
    decrypt_data,
    derive_key,
    generate_key,
    generate_salt,
    SecureBytes,
    SecureString,
    CryptoError,
    __version__,
)

__all__ = [
    "encrypt_data",
    "decrypt_data",
    "derive_key",
    "generate_key",
    "generate_salt",
    "SecureBytes",
    "SecureString",
    "CryptoError",
    "__version__",
]
```

### django_app/fields.py - Encrypted Django Fields

```python
"""Custom Django model fields with transparent encryption."""

from django.db import models
from django.conf import settings
from typing import Any, Optional
import my_django_rust as rust_crypto


class EncryptedTextField(models.TextField):
    """TextField that encrypts data at rest using AES-256-GCM."""

    description = "Encrypted text field"

    def __init__(self, *args, **kwargs):
        self.key_name = kwargs.pop("key_name", "DEFAULT_ENCRYPTION_KEY")
        super().__init__(*args, **kwargs)

    def _get_key(self) -> bytes:
        """Retrieve encryption key from settings."""
        key = getattr(settings, self.key_name, None)
        if key is None:
            raise ValueError(f"Encryption key '{self.key_name}' not configured")
        if isinstance(key, str):
            key = bytes.fromhex(key)
        if len(key) != 32:
            raise ValueError("Encryption key must be 32 bytes")
        return key

    def get_prep_value(self, value: Optional[str]) -> Optional[str]:
        """Encrypt value before saving to database."""
        if value is None:
            return None

        key = self._get_key()
        encrypted = rust_crypto.encrypt_data(value.encode("utf-8"), key)
        return encrypted.hex()

    def from_db_value(
        self, value: Optional[str], expression, connection
    ) -> Optional[str]:
        """Decrypt value when loading from database."""
        if value is None:
            return None

        key = self._get_key()
        encrypted = bytes.fromhex(value)
        decrypted = rust_crypto.decrypt_data(encrypted, key)
        return decrypted.decode("utf-8")

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        if self.key_name != "DEFAULT_ENCRYPTION_KEY":
            kwargs["key_name"] = self.key_name
        return name, path, args, kwargs


class EncryptedCharField(models.CharField):
    """CharField that encrypts data at rest."""

    description = "Encrypted char field"

    def __init__(self, *args, **kwargs):
        self.key_name = kwargs.pop("key_name", "DEFAULT_ENCRYPTION_KEY")
        # Encrypted data is longer than plaintext
        kwargs.setdefault("max_length", 512)
        super().__init__(*args, **kwargs)

    def _get_key(self) -> bytes:
        key = getattr(settings, self.key_name, None)
        if key is None:
            raise ValueError(f"Encryption key '{self.key_name}' not configured")
        if isinstance(key, str):
            key = bytes.fromhex(key)
        return key

    def get_prep_value(self, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        key = self._get_key()
        encrypted = rust_crypto.encrypt_data(value.encode("utf-8"), key)
        return encrypted.hex()

    def from_db_value(
        self, value: Optional[str], expression, connection
    ) -> Optional[str]:
        if value is None:
            return None

        key = self._get_key()
        encrypted = bytes.fromhex(value)
        decrypted = rust_crypto.decrypt_data(encrypted, key)
        return decrypted.decode("utf-8")


class EncryptedJSONField(models.JSONField):
    """JSONField that encrypts data at rest."""

    description = "Encrypted JSON field"

    def __init__(self, *args, **kwargs):
        self.key_name = kwargs.pop("key_name", "DEFAULT_ENCRYPTION_KEY")
        super().__init__(*args, **kwargs)

    def _get_key(self) -> bytes:
        key = getattr(settings, self.key_name, None)
        if key is None:
            raise ValueError(f"Encryption key '{self.key_name}' not configured")
        if isinstance(key, str):
            key = bytes.fromhex(key)
        return key

    def get_prep_value(self, value: Any) -> Optional[str]:
        if value is None:
            return None

        import json
        json_str = json.dumps(value)
        key = self._get_key()
        encrypted = rust_crypto.encrypt_data(json_str.encode("utf-8"), key)
        return encrypted.hex()

    def from_db_value(
        self, value: Optional[str], expression, connection
    ) -> Any:
        if value is None:
            return None

        import json
        key = self._get_key()
        encrypted = bytes.fromhex(value)
        decrypted = rust_crypto.decrypt_data(encrypted, key)
        return json.loads(decrypted.decode("utf-8"))
```

### django_app/models.py - Example Models

```python
"""Example Django models using encrypted fields."""

from django.db import models
from .fields import EncryptedTextField, EncryptedCharField, EncryptedJSONField


class SecureUserProfile(models.Model):
    """User profile with encrypted sensitive data."""

    user = models.OneToOneField(
        "auth.User",
        on_delete=models.CASCADE,
        related_name="secure_profile"
    )

    # Encrypted fields
    ssn = EncryptedCharField(
        max_length=256,
        blank=True,
        null=True,
        help_text="Social Security Number (encrypted)"
    )

    medical_notes = EncryptedTextField(
        blank=True,
        null=True,
        help_text="Medical notes (encrypted)"
    )

    payment_info = EncryptedJSONField(
        default=dict,
        blank=True,
        help_text="Payment information (encrypted)"
    )

    # Non-encrypted fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Secure User Profile"
        verbose_name_plural = "Secure User Profiles"

    def __str__(self):
        return f"SecureProfile for {self.user.username}"


class SecureDocument(models.Model):
    """Document with encrypted content."""

    title = models.CharField(max_length=255)

    content = EncryptedTextField(
        help_text="Document content (encrypted)"
    )

    metadata = EncryptedJSONField(
        default=dict,
        help_text="Document metadata (encrypted)"
    )

    owner = models.ForeignKey(
        "auth.User",
        on_delete=models.CASCADE,
        related_name="secure_documents"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Secure Document"
        verbose_name_plural = "Secure Documents"

    def __str__(self):
        return self.title
```

### django_app/middleware.py - Security Middleware

```python
"""Security middleware using Rust crypto."""

import logging
from django.http import HttpRequest, HttpResponse
from typing import Callable
import my_django_rust as rust_crypto

logger = logging.getLogger(__name__)


class RequestEncryptionMiddleware:
    """Middleware to handle encrypted request/response data."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Process request
        self._process_request(request)

        # Get response
        response = self.get_response(request)

        # Process response
        return self._process_response(request, response)

    def _process_request(self, request: HttpRequest) -> None:
        """Decrypt encrypted request body if present."""
        if request.content_type == "application/x-encrypted":
            try:
                from django.conf import settings
                key = bytes.fromhex(settings.REQUEST_ENCRYPTION_KEY)
                encrypted_body = request.body
                decrypted = rust_crypto.decrypt_data(encrypted_body, key)
                request._body = decrypted
                request.content_type = "application/json"
            except Exception as e:
                logger.warning(f"Failed to decrypt request: {e}")

    def _process_response(
        self, request: HttpRequest, response: HttpResponse
    ) -> HttpResponse:
        """Encrypt response if client supports it."""
        if request.headers.get("Accept-Encryption") == "aes-256-gcm":
            try:
                from django.conf import settings
                key = bytes.fromhex(settings.RESPONSE_ENCRYPTION_KEY)
                encrypted = rust_crypto.encrypt_data(response.content, key)
                response.content = encrypted
                response["Content-Type"] = "application/x-encrypted"
            except Exception as e:
                logger.warning(f"Failed to encrypt response: {e}")

        return response
```

## Configuration

### Django settings.py

```python
# Encryption keys (store securely - use Vault in production)
# Generate with: python -c "import os; print(os.urandom(32).hex())"
DEFAULT_ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
REQUEST_ENCRYPTION_KEY = os.environ.get("REQUEST_ENCRYPTION_KEY")
RESPONSE_ENCRYPTION_KEY = os.environ.get("RESPONSE_ENCRYPTION_KEY")

# Middleware
MIDDLEWARE = [
    # ... other middleware ...
    "django_app.middleware.RequestEncryptionMiddleware",
]

# Installed apps
INSTALLED_APPS = [
    # ... other apps ...
    "django_app",
]
```

## Build and Installation

### Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install maturin
pip install maturin

# Build and install in development mode
maturin develop

# Run tests
pytest tests/
```

### Production Build

```bash
# Build wheel
maturin build --release

# Install wheel
pip install target/wheels/my_django_rust-*.whl
```

## Testing

### tests/test_crypto.py

```python
"""Tests for Rust crypto functions."""

import pytest
import my_django_rust as rust_crypto


class TestEncryption:
    """Test encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Test that encrypt then decrypt returns original data."""
        key = rust_crypto.generate_key()
        plaintext = b"Hello, World!"

        encrypted = rust_crypto.encrypt_data(plaintext, key)
        decrypted = rust_crypto.decrypt_data(encrypted, key)

        assert decrypted == plaintext

    def test_encrypt_with_aad(self):
        """Test authenticated encryption with AAD."""
        key = rust_crypto.generate_key()
        plaintext = b"Secret message"
        aad = b"context-data"

        encrypted = rust_crypto.encrypt_data(plaintext, key, aad)
        decrypted = rust_crypto.decrypt_data(encrypted, key, aad)

        assert decrypted == plaintext

    def test_wrong_aad_fails(self):
        """Test that wrong AAD causes decryption failure."""
        key = rust_crypto.generate_key()
        plaintext = b"Secret message"
        aad = b"context-data"

        encrypted = rust_crypto.encrypt_data(plaintext, key, aad)

        with pytest.raises(rust_crypto.CryptoError):
            rust_crypto.decrypt_data(encrypted, key, b"wrong-aad")

    def test_wrong_key_fails(self):
        """Test that wrong key causes decryption failure."""
        key1 = rust_crypto.generate_key()
        key2 = rust_crypto.generate_key()
        plaintext = b"Secret message"

        encrypted = rust_crypto.encrypt_data(plaintext, key1)

        with pytest.raises(rust_crypto.CryptoError):
            rust_crypto.decrypt_data(encrypted, key2)


class TestKeyDerivation:
    """Test key derivation."""

    def test_derive_key(self):
        """Test password-based key derivation."""
        password = "secure_password_123"
        salt = rust_crypto.generate_salt(16)

        key = rust_crypto.derive_key(password, salt)

        assert len(key) == 32

    def test_derive_key_deterministic(self):
        """Test that same password and salt produce same key."""
        password = "secure_password_123"
        salt = rust_crypto.generate_salt(16)

        key1 = rust_crypto.derive_key(password, salt)
        key2 = rust_crypto.derive_key(password, salt)

        assert key1 == key2

    def test_different_salt_different_key(self):
        """Test that different salts produce different keys."""
        password = "secure_password_123"
        salt1 = rust_crypto.generate_salt(16)
        salt2 = rust_crypto.generate_salt(16)

        key1 = rust_crypto.derive_key(password, salt1)
        key2 = rust_crypto.derive_key(password, salt2)

        assert key1 != key2


class TestSecureMemory:
    """Test secure memory types."""

    def test_secure_bytes(self):
        """Test SecureBytes type."""
        data = b"sensitive data"
        secure = rust_crypto.SecureBytes(data)

        assert len(secure) == len(data)
        assert secure.expose() == data

        secure.clear()
        assert len(secure) == 0

    def test_secure_string(self):
        """Test SecureString type."""
        data = "sensitive string"
        secure = rust_crypto.SecureString(data)

        assert len(secure) == len(data)
        assert secure.expose() == data

        secure.clear()
        assert len(secure) == 0
```

## Row Level Security (PostgreSQL)

RLS must be enabled on all tables containing user or tenant data. This enforces
data isolation at the database layer — independent of Django ORM, PyO3 bindings,
or any application code.

### Migration

```sql
-- migrations/0002_rls.sql
ALTER TABLE django_app_secureuserprofile ENABLE ROW LEVEL SECURITY;
ALTER TABLE django_app_secureuserprofile FORCE ROW LEVEL SECURITY;

ALTER TABLE django_app_securedocument ENABLE ROW LEVEL SECURITY;
ALTER TABLE django_app_securedocument FORCE ROW LEVEL SECURITY;

-- Policy: each user can only access their own rows
CREATE POLICY user_isolation ON django_app_secureuserprofile
    FOR ALL TO app_user
    USING (user_id = current_setting('app.current_user_id')::integer);

CREATE POLICY user_isolation ON django_app_securedocument
    FOR ALL TO app_user
    USING (owner_id = current_setting('app.current_user_id')::integer);
```

### Django Middleware to Set RLS Context

```python
# django_app/middleware.py (add alongside RequestEncryptionMiddleware)
from django.db import connection


class RLSMiddleware:
    """Set PostgreSQL session variable for Row Level Security on every request."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT set_config('app.current_user_id', %s, false)",
                    [str(request.user.pk)],
                )
        return self.get_response(request)
```

```python
# settings.py
MIDDLEWARE = [
    # Must come AFTER authentication middleware
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_app.middleware.RLSMiddleware",
    "django_app.middleware.RequestEncryptionMiddleware",
]
```

## Security Checklist

- [ ] PostgreSQL RLS enabled (`ENABLE ROW LEVEL SECURITY`) on all user/tenant tables
- [ ] `FORCE ROW LEVEL SECURITY` set so table owner cannot bypass policies
- [ ] `RLSMiddleware` sets `app.current_user_id` on every authenticated request
- [ ] RLS migration runs before any data is inserted
- [ ] Encryption keys stored securely (Vault, env vars, KMS)
- [ ] Keys rotated periodically
- [ ] AAD used for context binding where appropriate
- [ ] Secure memory types used for sensitive data
- [ ] Encrypted fields not used in database indexes
- [ ] Key derivation uses appropriate cost parameters
- [ ] Error messages don't leak sensitive information
- [ ] Audit logging for encryption/decryption operations
- [ ] Tests cover all crypto operations
- [ ] Dependencies audited with cargo-audit
