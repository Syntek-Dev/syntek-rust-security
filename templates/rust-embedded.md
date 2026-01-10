# Rust Embedded Security Template

## Overview

This template provides a security-hardened foundation for embedded systems development in Rust using `no_std` environments. It focuses on memory safety, secure boot, hardware security features, cryptographic acceleration, and protection against physical attacks in resource-constrained devices.

**Target Use Cases:**
- IoT devices
- Microcontroller applications
- Automotive embedded systems
- Industrial control systems
- Medical devices
- Security tokens and smart cards

## Project Structure

```
my-embedded-device/
├── Cargo.toml
├── .cargo/
│   └── config.toml           # Target configuration
├── memory.x                  # Linker script
├── build.rs                  # Build script
├── src/
│   ├── main.rs              # Entry point
│   ├── lib.rs               # Library exports
│   ├── hal/                 # Hardware Abstraction Layer
│   │   ├── mod.rs
│   │   ├── gpio.rs
│   │   ├── uart.rs
│   │   └── spi.rs
│   ├── crypto/              # Cryptographic operations
│   │   ├── mod.rs
│   │   ├── aes.rs
│   │   ├── sha.rs
│   │   └── rng.rs
│   ├── secure_boot/         # Secure boot implementation
│   │   ├── mod.rs
│   │   └── verify.rs
│   ├── storage/             # Secure storage
│   │   ├── mod.rs
│   │   └── flash.rs
│   ├── comms/               # Communication protocols
│   │   ├── mod.rs
│   │   └── protocol.rs
│   └── panic.rs             # Panic handler
├── tests/
│   └── integration.rs
├── examples/
│   └── blinky.rs
├── .github/
│   └── workflows/
│       └── embedded.yml
└── README.md
```

## Cargo.toml Template

```toml
[package]
name = "my-embedded-device"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"
authors = ["Your Name <you@example.com>"]
license = "MIT OR Apache-2.0"

[dependencies]
# Core embedded dependencies
cortex-m = "0.7"
cortex-m-rt = "0.7"

# HAL for your specific chip (example: STM32)
# stm32f4xx-hal = { version = "0.21", features = ["stm32f407"] }

# Embedded HAL traits
embedded-hal = "1.0"
embedded-io = "0.6"

# no_std compatible utilities
heapless = "0.8"           # Static data structures
defmt = "0.3"              # Logging
defmt-rtt = "0.4"          # RTT transport

# Cryptography (no_std)
aes = { version = "0.8", default-features = false }
sha2 = { version = "0.10", default-features = false }
hmac = { version = "0.12", default-features = false }
chacha20poly1305 = { version = "0.10", default-features = false }
ed25519-dalek = { version = "2.1", default-features = false, features = ["rand_core"] }

# Random number generation
rand_core = { version = "0.6", default-features = false }
rand_chacha = { version = "0.3", default-features = false }

# Memory safety
critical-section = "1.2"
portable-atomic = { version = "1.9", features = ["critical-section"] }

# Error handling
nb = "1.1"

# Serialization
serde = { version = "1.0", default-features = false, features = ["derive"] }
postcard = { version = "1.0", features = ["heapless"] }

[dev-dependencies]
defmt-test = "0.3"

[profile.release]
# Optimize for size (critical for embedded)
opt-level = "z"          # Optimize for size
lto = true               # Link-time optimization
codegen-units = 1        # Single codegen unit
strip = true             # Strip symbols
panic = "abort"          # Abort on panic (no unwinding)
overflow-checks = true   # Keep overflow checks

[profile.dev]
opt-level = 1            # Some optimization for development
overflow-checks = true

# Memory protection profile
[profile.secure]
inherits = "release"
opt-level = "z"
lto = "fat"
overflow-checks = true
debug-assertions = true

[features]
default = []
# Hardware security features
hw-crypto = []           # Use hardware crypto acceleration
secure-boot = []         # Enable secure boot verification
mpu = []                 # Memory Protection Unit
trustzone = []           # ARM TrustZone support
```

## .cargo/config.toml

```toml
[build]
# Target for ARM Cortex-M4F (example)
target = "thumbv7em-none-eabihf"

[target.thumbv7em-none-eabihf]
runner = "probe-rs run --chip STM32F407VGTx"
rustflags = [
    "-C", "link-arg=-Tlink.x",
    "-C", "link-arg=-Tdefmt.x",
    # Stack protection
    "-C", "stack-protector=all",
    # Position independent code
    "-C", "relocation-model=pic",
]

[target.'cfg(all(target_arch = "arm", target_os = "none"))']
runner = "probe-rs run"
```

## Security Considerations

### 1. Memory Safety in no_std
- No dynamic allocation (use `heapless` collections)
- Stack overflow protection
- Memory Protection Unit (MPU) configuration
- Prevent buffer overflows with bounds checking

### 2. Secure Boot
- Verify firmware signatures before execution
- Chain of trust from bootloader to application
- Anti-rollback protection
- Secure firmware updates (OTA)

### 3. Cryptographic Operations
- Use hardware crypto accelerators when available
- Constant-time implementations to prevent timing attacks
- Secure random number generation (TRNG)
- Key management and storage

### 4. Physical Security
- Side-channel attack mitigation
- Fault injection protection
- Debug port protection
- Tamper detection

### 5. Communication Security
- Encrypted communication channels
- Mutual authentication
- Message integrity verification
- Replay attack prevention

### 6. Power Management
- Secure power state transitions
- Memory clearing on power down
- Prevent cold boot attacks

## Required Dependencies

### Core Embedded Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `cortex-m` | 0.7+ | Cortex-M processor support |
| `cortex-m-rt` | 0.7+ | Runtime and startup code |
| `embedded-hal` | 1.0+ | Hardware abstraction traits |
| `heapless` | 0.8+ | Static data structures |
| `defmt` | 0.3+ | Efficient logging |

### Cryptography Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `aes` | 0.8+ | AES encryption |
| `sha2` | 0.10+ | SHA-256/512 hashing |
| `chacha20poly1305` | 0.10+ | AEAD cipher |
| `ed25519-dalek` | 2.1+ | Digital signatures |

### Security Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `rand_core` | 0.6+ | RNG traits |
| `critical-section` | 1.2+ | Atomic operations |
| `portable-atomic` | 1.9+ | Atomic primitives |

## Code Examples

### Example 1: Secure Boot Verification

```rust
// src/secure_boot/verify.rs
#![no_std]

use ed25519_dalek::{PublicKey, Signature, Verifier};
use sha2::{Sha256, Digest};

// Public key embedded in bootloader (const)
const FIRMWARE_PUBLIC_KEY: [u8; 32] = [
    // Your public key bytes here
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

#[repr(C)]
pub struct FirmwareHeader {
    pub magic: u32,
    pub version: u32,
    pub size: u32,
    pub signature: [u8; 64],
    pub hash: [u8; 32],
}

pub enum VerifyError {
    InvalidMagic,
    InvalidSignature,
    InvalidHash,
}

/// Verify firmware signature before executing
pub fn verify_firmware(
    header: &FirmwareHeader,
    firmware_data: &[u8],
) -> Result<(), VerifyError> {
    // Check magic number
    if header.magic != 0xDEADBEEF {
        return Err(VerifyError::InvalidMagic);
    }

    // Verify hash
    let mut hasher = Sha256::new();
    hasher.update(firmware_data);
    let computed_hash = hasher.finalize();

    if computed_hash.as_slice() != header.hash {
        return Err(VerifyError::InvalidHash);
    }

    // Verify signature
    let public_key = PublicKey::from_bytes(&FIRMWARE_PUBLIC_KEY)
        .map_err(|_| VerifyError::InvalidSignature)?;

    let signature = Signature::from_bytes(&header.signature)
        .map_err(|_| VerifyError::InvalidSignature)?;

    public_key
        .verify(&header.hash, &signature)
        .map_err(|_| VerifyError::InvalidSignature)?;

    Ok(())
}

/// Bootloader entry point
#[no_mangle]
pub unsafe extern "C" fn bootloader_main() -> ! {
    // Get firmware header from flash
    let header_ptr = 0x0800_8000 as *const FirmwareHeader;
    let header = &*header_ptr;

    let firmware_ptr = 0x0800_8100 as *const u8;
    let firmware_data = core::slice::from_raw_parts(firmware_ptr, header.size as usize);

    // Verify firmware
    match verify_firmware(header, firmware_data) {
        Ok(()) => {
            // Jump to application
            let app_entry = *(0x0800_8004 as *const u32);
            let app_fn: extern "C" fn() -> ! = core::mem::transmute(app_entry);
            app_fn();
        }
        Err(_) => {
            // Verification failed - halt
            loop {
                cortex_m::asm::wfi();
            }
        }
    }
}
```

### Example 2: Secure Random Number Generation

```rust
// src/crypto/rng.rs
#![no_std]

use rand_core::{RngCore, CryptoRng};

/// Hardware RNG wrapper (using MCU's TRNG)
pub struct HardwareRng {
    // Peripheral access (example)
    // rng: stm32f4xx_hal::rng::Rng,
}

impl HardwareRng {
    pub fn new(/* rng peripheral */) -> Self {
        // Initialize hardware RNG
        Self { /* rng */ }
    }

    /// Get random bytes from hardware TRNG
    fn get_random_u32(&mut self) -> u32 {
        // Wait for RNG ready and read
        // self.rng.read().unwrap()
        // Placeholder:
        0x12345678
    }
}

impl RngCore for HardwareRng {
    fn next_u32(&mut self) -> u32 {
        self.get_random_u32()
    }

    fn next_u64(&mut self) -> u64 {
        let hi = self.next_u32() as u64;
        let lo = self.next_u32() as u64;
        (hi << 32) | lo
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(4) {
            let random = self.next_u32().to_le_bytes();
            chunk.copy_from_slice(&random[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for HardwareRng {}

/// Example: Generate random key
pub fn generate_key<const N: usize>(rng: &mut HardwareRng) -> [u8; N] {
    let mut key = [0u8; N];
    rng.fill_bytes(&mut key);
    key
}
```

### Example 3: Secure Storage in Flash

```rust
// src/storage/flash.rs
#![no_std]

use aes::Aes256;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;
use core::mem;

/// Secure storage manager with encryption
pub struct SecureStorage {
    key: [u8; 32],
    flash_address: u32,
}

impl SecureStorage {
    pub fn new(key: [u8; 32], flash_address: u32) -> Self {
        Self { key, flash_address }
    }

    /// Write encrypted data to flash
    pub fn write_encrypted(&self, data: &[u8]) -> Result<(), StorageError> {
        if data.len() > 4096 {
            return Err(StorageError::TooLarge);
        }

        // Pad data to 16-byte blocks
        let mut buffer = [0u8; 4096];
        buffer[..data.len()].copy_from_slice(data);

        // Encrypt in-place
        let cipher = Aes256::new(GenericArray::from_slice(&self.key));

        for chunk in buffer.chunks_exact_mut(16) {
            let block = GenericArray::from_mut_slice(chunk);
            cipher.encrypt_block(block);
        }

        // Write to flash (platform-specific)
        self.write_flash(&buffer)?;

        Ok(())
    }

    /// Read and decrypt data from flash
    pub fn read_decrypted(&self, output: &mut [u8]) -> Result<usize, StorageError> {
        let mut buffer = [0u8; 4096];

        // Read from flash
        self.read_flash(&mut buffer)?;

        // Decrypt
        let cipher = Aes256::new(GenericArray::from_slice(&self.key));

        for chunk in buffer.chunks_exact_mut(16) {
            let block = GenericArray::from_mut_slice(chunk);
            cipher.decrypt_block(block);
        }

        // Copy to output
        let len = output.len().min(buffer.len());
        output[..len].copy_from_slice(&buffer[..len]);

        Ok(len)
    }

    fn write_flash(&self, data: &[u8]) -> Result<(), StorageError> {
        // Platform-specific flash write
        // Ensure flash is unlocked, erase sector, write data
        Ok(())
    }

    fn read_flash(&self, buffer: &mut [u8]) -> Result<(), StorageError> {
        // Platform-specific flash read
        // unsafe { core::ptr::copy_nonoverlapping(...) }
        Ok(())
    }
}

#[derive(Debug)]
pub enum StorageError {
    TooLarge,
    FlashError,
}

impl Drop for SecureStorage {
    fn drop(&mut self) {
        // Zeroize key from memory
        self.key.iter_mut().for_each(|b| *b = 0);
    }
}
```

### Example 4: Memory Protection Unit (MPU) Configuration

```rust
// src/hal/mpu.rs
#![no_std]

use cortex_m::peripheral::MPU;

/// MPU region attributes
#[derive(Clone, Copy)]
pub struct MpuRegion {
    pub base_address: u32,
    pub size: MpuSize,
    pub access: MpuAccess,
    pub executable: bool,
}

#[repr(u8)]
pub enum MpuSize {
    Size256B = 7,
    Size512B = 8,
    Size1KB = 9,
    Size2KB = 10,
    Size4KB = 11,
    Size8KB = 12,
    Size16KB = 13,
    Size32KB = 14,
    Size64KB = 15,
    Size128KB = 16,
    Size256KB = 17,
    Size512KB = 18,
    Size1MB = 19,
    Size2MB = 20,
    Size4MB = 21,
}

#[repr(u8)]
pub enum MpuAccess {
    NoAccess = 0b000,
    PrivilegedRW = 0b001,
    PrivilegedRWUserRO = 0b010,
    FullAccess = 0b011,
    PrivilegedRO = 0b101,
    ReadOnly = 0b110,
}

/// Configure MPU for secure execution
pub fn configure_mpu(mpu: &mut MPU) {
    // Disable MPU during configuration
    mpu.ctrl.write(0);

    // Region 0: Flash (executable, read-only)
    configure_region(
        mpu,
        0,
        MpuRegion {
            base_address: 0x0800_0000,
            size: MpuSize::Size1MB,
            access: MpuAccess::ReadOnly,
            executable: true,
        },
    );

    // Region 1: RAM (read-write, non-executable)
    configure_region(
        mpu,
        1,
        MpuRegion {
            base_address: 0x2000_0000,
            size: MpuSize::Size128KB,
            access: MpuAccess::FullAccess,
            executable: false,
        },
    );

    // Region 2: Peripheral region (read-write, non-executable)
    configure_region(
        mpu,
        2,
        MpuRegion {
            base_address: 0x4000_0000,
            size: MpuSize::Size512MB,
            access: MpuAccess::FullAccess,
            executable: false,
        },
    );

    // Enable MPU with default memory map as background
    mpu.ctrl.write(0x5); // ENABLE | PRIVDEFENA
}

fn configure_region(mpu: &mut MPU, region: u8, config: MpuRegion) {
    let size_bits = config.size as u32;
    let access_bits = config.access as u32;
    let xn_bit = if config.executable { 0 } else { 1 << 28 };

    // Set region number
    mpu.rnr.write(region as u32);

    // Set base address (must be aligned to region size)
    mpu.rbar.write(config.base_address | (1 << 4) | region as u32);

    // Set attributes
    let rasr = (1 << 0)                   // ENABLE
             | (size_bits << 1)           // SIZE
             | (access_bits << 24)        // AP
             | xn_bit;                    // XN

    mpu.rasr.write(rasr);
}
```

### Example 5: Side-Channel Attack Mitigation

```rust
// src/crypto/constant_time.rs
#![no_std]

use subtle::ConstantTimeEq;

/// Constant-time comparison to prevent timing attacks
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.ct_eq(b).into()
}

/// Constant-time conditional copy
pub fn constant_time_select(condition: bool, a: &[u8], b: &[u8], output: &mut [u8]) {
    let mask = if condition { 0xFF } else { 0x00 };

    for i in 0..output.len() {
        output[i] = (a[i] & mask) | (b[i] & !mask);
    }
}

/// AES implementation with constant-time guarantees
pub fn aes_encrypt_constant_time(key: &[u8; 32], plaintext: &[u8; 16]) -> [u8; 16] {
    use aes::Aes256;
    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::cipher::generic_array::GenericArray;

    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut block = *GenericArray::from_slice(plaintext);
    cipher.encrypt_block(&mut block);

    block.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_compare() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
    }
}
```

### Example 6: Secure Communication Protocol

```rust
// src/comms/protocol.rs
#![no_std]

use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::aead::generic_array::GenericArray;
use heapless::Vec;

pub const MAX_MESSAGE_SIZE: usize = 256;

#[derive(Debug)]
pub struct SecureChannel {
    cipher: ChaCha20Poly1305,
    nonce_counter: u64,
}

impl SecureChannel {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(GenericArray::from_slice(key)),
            nonce_counter: 0,
        }
    }

    /// Encrypt and authenticate message
    pub fn send(&mut self, message: &[u8]) -> Result<Vec<u8, MAX_MESSAGE_SIZE>, EncryptError> {
        if message.len() > MAX_MESSAGE_SIZE - 28 {
            return Err(EncryptError::MessageTooLarge);
        }

        // Generate nonce (96-bit)
        let nonce = self.next_nonce();

        // Encrypt with AEAD
        let ciphertext = self.cipher
            .encrypt(&nonce, Payload {
                msg: message,
                aad: &[],
            })
            .map_err(|_| EncryptError::EncryptionFailed)?;

        // Prepend nonce to ciphertext
        let mut output = Vec::new();
        output.extend_from_slice(&self.nonce_counter.to_le_bytes()).ok();
        output.extend_from_slice(&ciphertext).ok();

        Ok(output)
    }

    /// Decrypt and verify message
    pub fn receive(&mut self, message: &[u8]) -> Result<Vec<u8, MAX_MESSAGE_SIZE>, DecryptError> {
        if message.len() < 8 {
            return Err(DecryptError::InvalidFormat);
        }

        // Extract nonce
        let nonce_bytes: [u8; 8] = message[..8].try_into().unwrap();
        let nonce_value = u64::from_le_bytes(nonce_bytes);

        // Verify nonce is not replayed
        if nonce_value <= self.nonce_counter {
            return Err(DecryptError::ReplayAttack);
        }

        let nonce = self.nonce_from_counter(nonce_value);

        // Decrypt
        let plaintext = self.cipher
            .decrypt(&nonce, Payload {
                msg: &message[8..],
                aad: &[],
            })
            .map_err(|_| DecryptError::AuthenticationFailed)?;

        // Update nonce counter
        self.nonce_counter = nonce_value;

        let mut output = Vec::new();
        output.extend_from_slice(&plaintext).ok();
        Ok(output)
    }

    fn next_nonce(&mut self) -> GenericArray<u8, chacha20poly1305::aead::consts::U12> {
        self.nonce_counter += 1;
        self.nonce_from_counter(self.nonce_counter)
    }

    fn nonce_from_counter(&self, counter: u64) -> GenericArray<u8, chacha20poly1305::aead::consts::U12> {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        *GenericArray::from_slice(&nonce)
    }
}

#[derive(Debug)]
pub enum EncryptError {
    MessageTooLarge,
    EncryptionFailed,
}

#[derive(Debug)]
pub enum DecryptError {
    InvalidFormat,
    ReplayAttack,
    AuthenticationFailed,
}
```

## Common Vulnerabilities

### 1. Buffer Overflows
**Vulnerable:**
```rust
let mut buffer = [0u8; 64];
// No bounds checking!
buffer[user_index] = user_value;
```
**Secure:**
```rust
let mut buffer = [0u8; 64];
if user_index < buffer.len() {
    buffer[user_index] = user_value;
}
```

### 2. Integer Overflows
**Vulnerable:**
```rust
let total = count * size; // May overflow!
```
**Secure:**
```rust
let total = count.checked_mul(size).expect("Overflow");
```

### 3. Uninitialized Memory
**Vulnerable:**
```rust
let buffer: [u8; 256];
// buffer contains garbage!
```
**Secure:**
```rust
let buffer = [0u8; 256];
// Or use MaybeUninit
```

### 4. Timing Attacks
**Vulnerable:**
```rust
fn verify_password(input: &[u8], expected: &[u8]) -> bool {
    input == expected // Early exit on mismatch!
}
```
**Secure:**
```rust
fn verify_password(input: &[u8], expected: &[u8]) -> bool {
    input.ct_eq(expected).into()
}
```

### 5. Insecure RNG
**Vulnerable:**
```rust
let key = 0x12345678; // Fixed "random" value
```
**Secure:**
```rust
let mut rng = HardwareRng::new();
let key = rng.next_u32();
```

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let key = [0x42; 32];
        let mut channel = SecureChannel::new(&key);

        let message = b"Hello, secure world!";
        let encrypted = channel.send(message).unwrap();
        let decrypted = channel.receive(&encrypted).unwrap();

        assert_eq!(message, decrypted.as_slice());
    }

    #[test]
    fn test_replay_attack_prevention() {
        let key = [0x42; 32];
        let mut channel = SecureChannel::new(&key);

        let message = b"Test message";
        let encrypted = channel.send(message).unwrap();

        // First decryption succeeds
        assert!(channel.receive(&encrypted).is_ok());

        // Replay attack fails
        assert!(matches!(
            channel.receive(&encrypted),
            Err(DecryptError::ReplayAttack)
        ));
    }
}
```

### Hardware-in-the-Loop Testing

```rust
// tests/integration.rs
#![no_std]
#![no_main]

use defmt_test as _;

#[defmt_test::tests]
mod tests {
    use defmt::assert;

    #[test]
    fn test_hardware_rng() {
        let mut rng = HardwareRng::new();
        let val1 = rng.next_u32();
        let val2 = rng.next_u32();

        // Values should be different (with very high probability)
        assert!(val1 != val2);
    }

    #[test]
    fn test_flash_write_read() {
        let key = [0x42; 32];
        let storage = SecureStorage::new(key, 0x0801_0000);

        let data = b"Test data";
        storage.write_encrypted(data).unwrap();

        let mut buffer = [0u8; 64];
        let len = storage.read_decrypted(&mut buffer).unwrap();

        assert!(buffer[..len] == *data);
    }
}
```

## CI/CD Integration

```yaml
# .github/workflows/embedded.yml
name: Embedded Security

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: 1.92.0
          targets: thumbv7em-none-eabihf

      - name: Install cargo-binutils
        run: cargo install cargo-binutils

      - name: Build release
        run: cargo build --release --target thumbv7em-none-eabihf

      - name: Check binary size
        run: |
          cargo size --release --target thumbv7em-none-eabihf -- -A
          SIZE=$(cargo size --release --target thumbv7em-none-eabihf | grep .text | awk '{print $2}')
          if [ $SIZE -gt 262144 ]; then
            echo "Binary too large: $SIZE bytes"
            exit 1
          fi

      - name: Run tests
        run: cargo test --lib

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: cargo-audit
        run: cargo audit

      - name: cargo-geiger
        run: |
          cargo install cargo-geiger
          cargo geiger
```

## Best Practices

1. **Use `no_std` and avoid dynamic allocation**
2. **Enable MPU for memory protection**
3. **Implement secure boot with signature verification**
4. **Use hardware crypto accelerators**
5. **Constant-time cryptographic operations**
6. **Zeroize sensitive data from memory**
7. **Implement anti-rollback protection**
8. **Disable debug ports in production**
9. **Use secure RNG (TRNG)**
10. **Regular security audits and penetration testing**

## Example Projects

1. **Embassy**: https://github.com/embassy-rs/embassy
2. **RTIC**: https://github.com/rtic-rs/rtic
3. **Embedded Rust Book**: https://rust-embedded.github.io/book/
4. **Tock OS**: https://github.com/tock/tock
