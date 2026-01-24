//! PyO3 Django Encrypted Field Integration
//!
//! Rust encryption for Django model fields via PyO3.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::RngCore;

/// Encryption context for a Django application
#[pyclass]
pub struct DjangoEncryption {
    cipher: Aes256Gcm,
}

#[pymethods]
impl DjangoEncryption {
    /// Create new encryption context with a 32-byte key
    #[new]
    pub fn new(key: &[u8]) -> PyResult<Self> {
        if key.len() != 32 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Key must be exactly 32 bytes",
            ));
        }

        let key = Key::<Aes256Gcm>::from_slice(key);
        Ok(Self {
            cipher: Aes256Gcm::new(key),
        })
    }

    /// Encrypt data for storage in Django model
    /// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
    pub fn encrypt<'py>(&self, py: Python<'py>, plaintext: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Encryption failed"))?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);

        Ok(PyBytes::new(py, &result))
    }

    /// Decrypt data from Django model
    pub fn decrypt<'py>(
        &self,
        py: Python<'py>,
        ciphertext: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        if ciphertext.len() < 28 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Ciphertext too short",
            ));
        }

        let nonce = Nonce::from_slice(&ciphertext[..12]);

        let plaintext = self.cipher.decrypt(nonce, &ciphertext[12..]).map_err(|_| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "Decryption failed - data may be corrupted or tampered",
            )
        })?;

        Ok(PyBytes::new(py, &plaintext))
    }

    /// Encrypt a string field
    pub fn encrypt_string<'py>(
        &self,
        py: Python<'py>,
        value: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        self.encrypt(py, value.as_bytes())
    }

    /// Decrypt to a string field
    pub fn decrypt_string(&self, ciphertext: &[u8]) -> PyResult<String> {
        if ciphertext.len() < 28 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Ciphertext too short",
            ));
        }

        let nonce = Nonce::from_slice(&ciphertext[..12]);

        let plaintext = self
            .cipher
            .decrypt(nonce, &ciphertext[12..])
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Decryption failed"))?;

        String::from_utf8(plaintext)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid UTF-8"))
    }
}

/// Generate a random 32-byte encryption key
#[pyfunction]
pub fn generate_key(py: Python<'_>) -> Bound<'_, PyBytes> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    PyBytes::new(py, &key)
}

/// Python module definition
#[pymodule]
fn django_encryption(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<DjangoEncryption>()?;
    m.add_function(wrap_pyfunction!(generate_key, m)?)?;
    Ok(())
}

/*
Django Usage Example:

```python
# settings.py
from django_encryption import DjangoEncryption, generate_key
import os

# Load key from environment or generate
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', generate_key())
ENCRYPTOR = DjangoEncryption(ENCRYPTION_KEY)

# models.py
from django.db import models
from django.conf import settings
import base64

class EncryptedTextField(models.BinaryField):
    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return settings.ENCRYPTOR.decrypt_string(value)

    def get_prep_value(self, value):
        if value is None:
            return value
        return settings.ENCRYPTOR.encrypt_string(value)

class User(models.Model):
    email = models.EmailField()
    ssn = EncryptedTextField()  # Encrypted at rest

# Usage
user = User.objects.create(
    email="test@example.com",
    ssn="123-45-6789"  # Automatically encrypted
)
print(user.ssn)  # Automatically decrypted: "123-45-6789"
```
*/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        pyo3::prepare_freethreaded_python();

        Python::with_gil(|py| {
            let key = [0u8; 32];
            let enc = DjangoEncryption::new(&key).unwrap();

            let plaintext = b"sensitive data";
            let ciphertext = enc.encrypt(py, plaintext).unwrap();
            let decrypted = enc.decrypt(py, ciphertext.as_bytes()).unwrap();

            assert_eq!(plaintext.as_slice(), decrypted.as_bytes());
        });
    }

    #[test]
    fn test_string_encrypt_decrypt() {
        pyo3::prepare_freethreaded_python();

        Python::with_gil(|py| {
            let key = [0u8; 32];
            let enc = DjangoEncryption::new(&key).unwrap();

            let value = "123-45-6789";
            let ciphertext = enc.encrypt_string(py, value).unwrap();
            let decrypted = enc.decrypt_string(ciphertext.as_bytes()).unwrap();

            assert_eq!(value, decrypted);
        });
    }

    #[test]
    fn test_invalid_key_length() {
        let result = DjangoEncryption::new(&[0u8; 16]);
        assert!(result.is_err());
    }
}
