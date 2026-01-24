# Rust Embedded Security Skills

This skill provides security analysis for embedded Rust systems, no_std environments, and hardware security modules.

## Overview

Embedded systems have unique security requirements:
- **No_std environments**: Limited standard library
- **Hardware constraints**: Memory, CPU, power limitations
- **Physical access**: Side-channel attacks, fault injection
- **Real-time requirements**: Timing-critical operations
- **Long deployment**: Devices in the field for years

## Key Security Concerns

### 1. No_std Safety
```rust
#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
```

### 2. Hardware RNG Integration
```rust
// Secure random number generation from hardware
use rand_core::{RngCore, CryptoRng};

pub struct HardwareRng;

impl RngCore for HardwareRng {
    fn next_u32(&mut self) -> u32 {
        // Read from hardware RNG register
        unsafe { read_volatile(RNG_DATA_REG) }
    }

    fn next_u64(&mut self) -> u64 {
        // Implementation
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Implementation
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        // Implementation
    }
}

impl CryptoRng for HardwareRng {}
```

### 3. Secure Boot
```rust
// Verify firmware signature before execution
fn verify_firmware(firmware: &[u8], signature: &[u8]) -> Result<(), Error> {
    use ed25519_dalek::{PublicKey, Signature, Verifier};

    let public_key = PublicKey::from_bytes(PUBLIC_KEY)?;
    let sig = Signature::from_bytes(signature)?;

    public_key.verify(firmware, &sig)
        .map_err(|_| Error::InvalidSignature)
}
```

### 4. Side-Channel Resistance
```rust
// Constant-time operations for embedded crypto
use subtle::ConstantTimeEq;

fn verify_pin(input: &[u8; 4], stored: &[u8; 4]) -> bool {
    input.ct_eq(stored).into()
}
```

### 5. Memory Protection
```rust
// Stack canary for embedded systems
#[no_mangle]
pub static __stack_chk_guard: usize = 0xDEADBEEF;

#[no_mangle]
pub extern "C" fn __stack_chk_fail() {
    panic!("Stack overflow detected");
}
```

## Embedded Cryptography

### Recommended No_std Crates
- **chacha20poly1305**: AEAD cipher for no_std
- **ed25519-dalek**: Digital signatures
- **sha2**: Hashing (no_std compatible)
- **aes**: Block cipher
- **rand_core**: RNG traits for no_std
- **zeroize**: Secure memory clearing

### Example: Encrypted Storage
```rust
#![no_std]

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce
};
use zeroize::Zeroize;

pub struct SecureStorage {
    cipher: ChaCha20Poly1305,
}

impl SecureStorage {
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(key.into());
        Self { cipher }
    }

    pub fn encrypt(&self, data: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>, Error> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher.encrypt(nonce, data)
            .map_err(|_| Error::EncryptionFailed)
    }

    pub fn decrypt(&self, data: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>, Error> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher.decrypt(nonce, data)
            .map_err(|_| Error::DecryptionFailed)
    }
}

impl Drop for SecureStorage {
    fn drop(&mut self) {
        // Zeroize key material
        // Implementation depends on cipher internals
    }
}
```

## Hardware Security Modules (HSM)

### HSM Integration Patterns
```rust
// Abstract HSM operations
pub trait HsmOperations {
    fn generate_key(&self, key_type: KeyType) -> Result<KeyHandle, Error>;
    fn sign(&self, key: KeyHandle, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn verify(&self, key: KeyHandle, data: &[u8], sig: &[u8]) -> Result<bool, Error>;
    fn encrypt(&self, key: KeyHandle, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn decrypt(&self, key: KeyHandle, data: &[u8]) -> Result<Vec<u8>, Error>;
}
```

## Security Checklist for Embedded Rust

### Boot Security
- [ ] Secure boot implementation
- [ ] Firmware signature verification
- [ ] Rollback protection
- [ ] Debug interface disabled in production

### Cryptography
- [ ] Hardware RNG used
- [ ] Constant-time operations
- [ ] Key material zeroized
- [ ] Side-channel resistant code

### Memory Safety
- [ ] Stack overflow protection
- [ ] Heap allocation controlled
- [ ] No buffer overflows
- [ ] Bounds checking

### Side-Channel Protection
- [ ] Timing attacks mitigated
- [ ] Power analysis resistant
- [ ] Cache timing safe
- [ ] Fault injection hardened

### Update Mechanism
- [ ] Secure firmware updates
- [ ] Signature verification
- [ ] Encrypted transport
- [ ] Atomic updates (no bricking)

## Common Embedded Vulnerabilities

### 1. Insufficient Randomness
```rust
// ❌ VULNERABLE: Weak seeding
let seed = unsafe { read_volatile(TIME_REG) as u64 };

// ✅ SECURE: Hardware RNG
let mut rng = HardwareRng::new();
let random_bytes = rng.gen::<[u8; 32]>();
```

### 2. Debug Interfaces Left Enabled
```rust
// Disable JTAG in production
#[cfg(not(debug_assertions))]
fn disable_debug_interfaces() {
    unsafe {
        write_volatile(DEBUG_CONTROL_REG, 0x00);
    }
}
```

### 3. Unencrypted Storage
```rust
// ❌ VULNERABLE: Plaintext secrets
const API_KEY: &[u8] = b"secret_key_123";

// ✅ SECURE: Encrypted with device-specific key
lazy_static! {
    static ref API_KEY: Vec<u8> = {
        let device_key = get_device_unique_key();
        decrypt_with_device_key(ENCRYPTED_API_KEY, &device_key)
    };
}
```

## Best Practices

1. **Use no_std crypto crates**: Prefer audited, no_std compatible crates
2. **Hardware RNG**: Always use hardware RNG for cryptographic operations
3. **Zeroize secrets**: Clear sensitive data from memory
4. **Constant-time ops**: Prevent timing attacks in crypto code
5. **Secure boot**: Verify firmware before execution
6. **Disable debug**: Turn off JTAG/SWD in production
7. **Update securely**: Sign and encrypt firmware updates
8. **Test thoroughly**: Use fuzzing and formal verification where possible
