//! Secure String Implementation
//!
//! Demonstrates secure handling of sensitive strings with automatic zeroization.

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A string that is automatically zeroized when dropped
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecureString {
    inner: String,
}

impl SecureString {
    pub fn new(s: &str) -> Self {
        Self {
            inner: s.to_string(),
        }
    }

    pub fn from_string(s: String) -> Self {
        Self { inner: s }
    }

    pub fn as_str(&self) -> &str {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Expose the inner value temporarily
    pub fn expose<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&str) -> R,
    {
        f(&self.inner)
    }
}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureString([REDACTED, {} bytes])", self.inner.len())
    }
}

impl fmt::Display for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl PartialEq for SecureString {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison
        use subtle::ConstantTimeEq;
        self.inner.as_bytes().ct_eq(other.inner.as_bytes()).into()
    }
}

impl Eq for SecureString {}

/// Secure bytes that are automatically zeroized
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecureBytes {
    inner: Vec<u8>,
}

impl SecureBytes {
    pub fn new(data: &[u8]) -> Self {
        Self {
            inner: data.to_vec(),
        }
    }

    pub fn from_vec(data: Vec<u8>) -> Self {
        Self { inner: data }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn expose<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.inner)
    }
}

impl fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureBytes([REDACTED, {} bytes])", self.inner.len())
    }
}

/// A secret key with automatic zeroization
#[derive(ZeroizeOnDrop)]
pub struct SecretKey<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecretKey<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; N];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    pub fn expose<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8; N]) -> R,
    {
        f(&self.bytes)
    }
}

impl<const N: usize> fmt::Debug for SecretKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey<{}>([REDACTED])", N)
    }
}

impl<const N: usize> Clone for SecretKey<N> {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes }
    }
}

/// Demonstrates that memory is actually zeroized
#[cfg(test)]
fn demonstrate_zeroization() {
    use std::ptr;

    let ptr: *const u8;
    let original_value: u8;

    {
        let secret = SecureString::new("secret_password");
        ptr = secret.as_str().as_ptr();
        original_value = unsafe { *ptr };
        assert_eq!(original_value, b's');
    } // secret dropped and zeroized here

    // After drop, memory should be zeroed
    // Note: This is for demonstration - accessing freed memory is UB
    // In practice, zeroize ensures the memory is cleared before deallocation
}

fn main() {
    println!("=== Secure String Demo ===\n");

    // SecureString
    let password = SecureString::new("my_secret_password");
    println!("Password debug: {:?}", password);
    println!("Password display: {}", password);
    println!("Password length: {}", password.len());

    // Expose for use
    password.expose(|p| {
        println!("Exposed (only in closure): starts with '{}'", &p[..2]);
    });

    // SecureBytes
    let api_key = SecureBytes::new(b"sk-1234567890abcdef");
    println!("\nAPI Key debug: {:?}", api_key);

    // SecretKey
    let encryption_key: SecretKey<32> = SecretKey::generate();
    println!("Encryption key: {:?}", encryption_key);

    encryption_key.expose(|key| {
        println!("Key first byte: 0x{:02x}", key[0]);
    });

    // Constant-time comparison
    println!("\n--- Constant-Time Comparison ---");
    let pw1 = SecureString::new("password123");
    let pw2 = SecureString::new("password123");
    let pw3 = SecureString::new("password124");

    println!("pw1 == pw2: {}", pw1 == pw2);
    println!("pw1 == pw3: {}", pw1 == pw3);

    // Cloning creates independent copy
    let pw_clone = pw1.clone();
    drop(pw1);
    println!("Clone still valid: {:?}", pw_clone);

    println!("\n=== Memory Safety Notes ===");
    println!("1. Values are automatically zeroized on drop");
    println!("2. Debug/Display never reveal contents");
    println!("3. Comparison uses constant-time algorithm");
    println!("4. expose() limits access scope");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string_redaction() {
        let s = SecureString::new("secret");
        assert_eq!(format!("{}", s), "[REDACTED]");
        assert!(format!("{:?}", s).contains("REDACTED"));
    }

    #[test]
    fn test_secure_string_expose() {
        let s = SecureString::new("secret");
        let result = s.expose(|inner| inner.to_uppercase());
        assert_eq!(result, "SECRET");
    }

    #[test]
    fn test_constant_time_eq() {
        let a = SecureString::new("password");
        let b = SecureString::new("password");
        let c = SecureString::new("Password");

        assert!(a == b);
        assert!(a != c);
    }

    #[test]
    fn test_secret_key_generation() {
        let key1: SecretKey<32> = SecretKey::generate();
        let key2: SecretKey<32> = SecretKey::generate();

        // Keys should be different
        let mut same = true;
        key1.expose(|k1| {
            key2.expose(|k2| {
                same = k1 == k2;
            });
        });
        assert!(!same);
    }

    #[test]
    fn test_secure_bytes() {
        let data = SecureBytes::new(&[1, 2, 3, 4]);
        assert_eq!(data.len(), 4);
        data.expose(|d| {
            assert_eq!(d, &[1, 2, 3, 4]);
        });
    }
}
