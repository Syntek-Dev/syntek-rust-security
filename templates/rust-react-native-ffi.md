# Rust React Native FFI Template

## Overview

This template provides a secure foundation for integrating Rust code into React
Native applications using UniFFI bindings. It enables high-performance,
memory-safe cryptographic operations on both iOS and Android platforms with a
unified TypeScript interface.

**Target Use Cases:**

- Mobile app encryption/decryption
- Secure local storage encryption
- Biometric-protected key derivation
- End-to-end encryption for messaging
- Secure data synchronization

## Project Structure

```
my-react-native-rust/
├── rust/
│   ├── Cargo.toml
│   ├── uniffi.toml
│   ├── src/
│   │   ├── lib.rs              # UniFFI entry point
│   │   ├── crypto.udl          # UniFFI interface definition
│   │   ├── crypto/
│   │   │   ├── mod.rs
│   │   │   ├── encrypt.rs
│   │   │   ├── decrypt.rs
│   │   │   └── keys.rs
│   │   └── error.rs
│   ├── ios/                    # iOS framework output
│   └── android/                # Android library output
├── src/
│   ├── crypto/
│   │   ├── index.ts            # TypeScript bindings
│   │   ├── types.ts            # Type definitions
│   │   └── native.ts           # Native module bridge
│   ├── hooks/
│   │   └── useCrypto.ts        # React hooks
│   └── components/
│       └── SecureInput.tsx
├── ios/
│   └── MyCrypto.swift          # iOS bridge
├── android/
│   └── src/main/java/
│       └── com/myapp/
│           └── MyCryptoModule.kt
├── package.json
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-react-native-rust"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"

[lib]
crate-type = ["cdylib", "staticlib"]
name = "my_crypto"

[dependencies]
# UniFFI for cross-platform bindings
uniffi = { version = "0.28" }

# Cryptography
aes-gcm = "0.10"
chacha20poly1305 = "0.10"
argon2 = "0.5"
rand = "0.8"
x25519-dalek = "2.0"
ed25519-dalek = "2.1"

# Secure memory
zeroize = { version = "1.8", features = ["derive"] }
secrecy = "0.10"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
base64 = "0.22"

# Error handling
thiserror = "2.0"

[build-dependencies]
uniffi = { version = "0.28", features = ["build"] }

[profile.release]
lto = true
codegen-units = 1
opt-level = "z"
strip = true

# iOS-specific optimizations
[profile.release.package.my-react-native-rust]
opt-level = "z"
```

## UniFFI Interface Definition

### src/crypto.udl

```
namespace crypto {
    // Key generation
    sequence<u8> generate_key();
    sequence<u8> generate_salt(u16 length);

    // Encryption
    [Throws=CryptoError]
    sequence<u8> encrypt(sequence<u8> plaintext, sequence<u8> key, sequence<u8>? aad);

    [Throws=CryptoError]
    string encrypt_string(string plaintext, sequence<u8> key, sequence<u8>? aad);

    // Decryption
    [Throws=CryptoError]
    sequence<u8> decrypt(sequence<u8> ciphertext, sequence<u8> key, sequence<u8>? aad);

    [Throws=CryptoError]
    string decrypt_string(string ciphertext, sequence<u8> key, sequence<u8>? aad);

    // Key derivation
    [Throws=CryptoError]
    sequence<u8> derive_key(string password, sequence<u8> salt, KeyDerivationParams params);

    // Key exchange
    KeyPair generate_key_pair();

    [Throws=CryptoError]
    sequence<u8> compute_shared_secret(sequence<u8> private_key, sequence<u8> public_key);
};

[Error]
enum CryptoError {
    "InvalidKey",
    "InvalidData",
    "EncryptionFailed",
    "DecryptionFailed",
    "KeyDerivationFailed",
    "InvalidParameters",
};

dictionary KeyDerivationParams {
    u32 memory_cost;
    u32 time_cost;
    u32 parallelism;
};

dictionary KeyPair {
    sequence<u8> public_key;
    sequence<u8> private_key;
};
```

## Rust Implementation

### src/lib.rs

```rust
use uniffi;

mod crypto;
mod error;

pub use crypto::*;
pub use error::CryptoError;

uniffi::include_scaffolding!("crypto");
```

### src/error.rs

```rust
use thiserror::Error;

#[derive(Debug, Error, uniffi::Error)]
pub enum CryptoError {
    #[error("Invalid key: key must be 32 bytes")]
    InvalidKey,

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed - invalid key or corrupted data")]
    DecryptionFailed,

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
}
```

### src/crypto/mod.rs

```rust
pub mod encrypt;
pub mod decrypt;
pub mod keys;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use rand::RngCore;
use zeroize::Zeroize;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::error::CryptoError;

/// Key derivation parameters
#[derive(Debug, Clone, uniffi::Record)]
pub struct KeyDerivationParams {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for KeyDerivationParams {
    fn default() -> Self {
        Self {
            memory_cost: 65536, // 64MB
            time_cost: 3,
            parallelism: 4,
        }
    }
}

/// Key pair for X25519 key exchange
#[derive(Debug, Clone, uniffi::Record)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

/// Generate a random 32-byte encryption key
#[uniffi::export]
pub fn generate_key() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Generate a random salt
#[uniffi::export]
pub fn generate_salt(length: u16) -> Vec<u8> {
    let mut salt = vec![0u8; length as usize];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Encrypt data using AES-256-GCM
#[uniffi::export]
pub fn encrypt(
    plaintext: Vec<u8>,
    key: Vec<u8>,
    aad: Option<Vec<u8>>,
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| CryptoError::InvalidKey)?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = match aad {
        Some(aad_bytes) => cipher
            .encrypt(nonce, aes_gcm::aead::Payload {
                msg: &plaintext,
                aad: &aad_bytes,
            })
            .map_err(|_| CryptoError::EncryptionFailed)?,
        None => cipher
            .encrypt(nonce, plaintext.as_slice())
            .map_err(|_| CryptoError::EncryptionFailed)?,
    };

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Encrypt string and return base64
#[uniffi::export]
pub fn encrypt_string(
    plaintext: String,
    key: Vec<u8>,
    aad: Option<Vec<u8>>,
) -> Result<String, CryptoError> {
    let encrypted = encrypt(plaintext.into_bytes(), key, aad)?;
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(&encrypted))
}

/// Decrypt data using AES-256-GCM
#[uniffi::export]
pub fn decrypt(
    ciphertext: Vec<u8>,
    key: Vec<u8>,
    aad: Option<Vec<u8>>,
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    if ciphertext.len() < 28 {
        return Err(CryptoError::InvalidData("Ciphertext too short".to_string()));
    }

    let (nonce_bytes, encrypted) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| CryptoError::InvalidKey)?;

    let plaintext = match aad {
        Some(aad_bytes) => cipher
            .decrypt(nonce, aes_gcm::aead::Payload {
                msg: encrypted,
                aad: &aad_bytes,
            })
            .map_err(|_| CryptoError::DecryptionFailed)?,
        None => cipher
            .decrypt(nonce, encrypted)
            .map_err(|_| CryptoError::DecryptionFailed)?,
    };

    Ok(plaintext)
}

/// Decrypt base64 string
#[uniffi::export]
pub fn decrypt_string(
    ciphertext: String,
    key: Vec<u8>,
    aad: Option<Vec<u8>>,
) -> Result<String, CryptoError> {
    use base64::Engine;
    let encrypted = base64::engine::general_purpose::STANDARD
        .decode(&ciphertext)
        .map_err(|e| CryptoError::InvalidData(format!("Invalid base64: {}", e)))?;

    let decrypted = decrypt(encrypted, key, aad)?;

    String::from_utf8(decrypted)
        .map_err(|e| CryptoError::InvalidData(format!("Invalid UTF-8: {}", e)))
}

/// Derive key from password using Argon2id
#[uniffi::export]
pub fn derive_key(
    password: String,
    salt: Vec<u8>,
    params: KeyDerivationParams,
) -> Result<Vec<u8>, CryptoError> {
    if salt.len() < 8 {
        return Err(CryptoError::InvalidParameters(
            "Salt must be at least 8 bytes".to_string()
        ));
    }

    let argon2_params = argon2::Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(32),
    ).map_err(|e| CryptoError::InvalidParameters(e.to_string()))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params,
    );

    let mut output = vec![0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut output)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(output)
}

/// Generate X25519 key pair for key exchange
#[uniffi::export]
pub fn generate_key_pair() -> KeyPair {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);

    KeyPair {
        public_key: public.as_bytes().to_vec(),
        private_key: private.as_bytes().to_vec(),
    }
}

/// Compute shared secret using X25519
#[uniffi::export]
pub fn compute_shared_secret(
    private_key: Vec<u8>,
    public_key: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    if private_key.len() != 32 || public_key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    let private_bytes: [u8; 32] = private_key.try_into()
        .map_err(|_| CryptoError::InvalidKey)?;
    let public_bytes: [u8; 32] = public_key.try_into()
        .map_err(|_| CryptoError::InvalidKey)?;

    let private = StaticSecret::from(private_bytes);
    let public = PublicKey::from(public_bytes);

    let shared = private.diffie_hellman(&public);
    Ok(shared.as_bytes().to_vec())
}
```

### build.rs

```rust
fn main() {
    uniffi::generate_scaffolding("src/crypto.udl").unwrap();
}
```

## iOS Integration

### ios/MyCrypto.swift

```swift
import Foundation
import MyCryptoFFI

@objc(MyCrypto)
class MyCrypto: NSObject {

    @objc
    static func requiresMainQueueSetup() -> Bool {
        return false
    }

    @objc
    func generateKey(_ resolve: @escaping RCTPromiseResolveBlock,
                     reject: @escaping RCTPromiseRejectBlock) {
        DispatchQueue.global(qos: .userInitiated).async {
            let key = Crypto.generateKey()
            resolve(key.base64EncodedString())
        }
    }

    @objc
    func generateSalt(_ length: NSNumber,
                      resolve: @escaping RCTPromiseResolveBlock,
                      reject: @escaping RCTPromiseRejectBlock) {
        DispatchQueue.global(qos: .userInitiated).async {
            let salt = Crypto.generateSalt(length: UInt16(truncating: length))
            resolve(salt.base64EncodedString())
        }
    }

    @objc
    func encrypt(_ plaintext: String,
                 key: String,
                 aad: String?,
                 resolve: @escaping RCTPromiseResolveBlock,
                 reject: @escaping RCTPromiseRejectBlock) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                guard let keyData = Data(base64Encoded: key) else {
                    reject("INVALID_KEY", "Invalid base64 key", nil)
                    return
                }

                let aadData = aad.flatMap { Data(base64Encoded: $0) }

                let encrypted = try Crypto.encryptString(
                    plaintext: plaintext,
                    key: [UInt8](keyData),
                    aad: aadData.map { [UInt8]($0) }
                )

                resolve(encrypted)
            } catch let error as CryptoError {
                reject("CRYPTO_ERROR", error.localizedDescription, nil)
            } catch {
                reject("UNKNOWN_ERROR", error.localizedDescription, nil)
            }
        }
    }

    @objc
    func decrypt(_ ciphertext: String,
                 key: String,
                 aad: String?,
                 resolve: @escaping RCTPromiseResolveBlock,
                 reject: @escaping RCTPromiseRejectBlock) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                guard let keyData = Data(base64Encoded: key) else {
                    reject("INVALID_KEY", "Invalid base64 key", nil)
                    return
                }

                let aadData = aad.flatMap { Data(base64Encoded: $0) }

                let decrypted = try Crypto.decryptString(
                    ciphertext: ciphertext,
                    key: [UInt8](keyData),
                    aad: aadData.map { [UInt8]($0) }
                )

                resolve(decrypted)
            } catch let error as CryptoError {
                reject("CRYPTO_ERROR", error.localizedDescription, nil)
            } catch {
                reject("UNKNOWN_ERROR", error.localizedDescription, nil)
            }
        }
    }

    @objc
    func deriveKey(_ password: String,
                   salt: String,
                   memoryCost: NSNumber,
                   timeCost: NSNumber,
                   parallelism: NSNumber,
                   resolve: @escaping RCTPromiseResolveBlock,
                   reject: @escaping RCTPromiseRejectBlock) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                guard let saltData = Data(base64Encoded: salt) else {
                    reject("INVALID_SALT", "Invalid base64 salt", nil)
                    return
                }

                let params = KeyDerivationParams(
                    memoryCost: UInt32(truncating: memoryCost),
                    timeCost: UInt32(truncating: timeCost),
                    parallelism: UInt32(truncating: parallelism)
                )

                let key = try Crypto.deriveKey(
                    password: password,
                    salt: [UInt8](saltData),
                    params: params
                )

                resolve(Data(key).base64EncodedString())
            } catch let error as CryptoError {
                reject("CRYPTO_ERROR", error.localizedDescription, nil)
            } catch {
                reject("UNKNOWN_ERROR", error.localizedDescription, nil)
            }
        }
    }

    @objc
    func generateKeyPair(_ resolve: @escaping RCTPromiseResolveBlock,
                         reject: @escaping RCTPromiseRejectBlock) {
        DispatchQueue.global(qos: .userInitiated).async {
            let keyPair = Crypto.generateKeyPair()
            resolve([
                "publicKey": Data(keyPair.publicKey).base64EncodedString(),
                "privateKey": Data(keyPair.privateKey).base64EncodedString()
            ])
        }
    }

    @objc
    func computeSharedSecret(_ privateKey: String,
                             publicKey: String,
                             resolve: @escaping RCTPromiseResolveBlock,
                             reject: @escaping RCTPromiseRejectBlock) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                guard let privateData = Data(base64Encoded: privateKey),
                      let publicData = Data(base64Encoded: publicKey) else {
                    reject("INVALID_KEY", "Invalid base64 key", nil)
                    return
                }

                let secret = try Crypto.computeSharedSecret(
                    privateKey: [UInt8](privateData),
                    publicKey: [UInt8](publicData)
                )

                resolve(Data(secret).base64EncodedString())
            } catch let error as CryptoError {
                reject("CRYPTO_ERROR", error.localizedDescription, nil)
            } catch {
                reject("UNKNOWN_ERROR", error.localizedDescription, nil)
            }
        }
    }
}
```

## Android Integration

### android/src/main/java/com/myapp/MyCryptoModule.kt

```kotlin
package com.myapp.mycrypto

import com.facebook.react.bridge.*
import kotlinx.coroutines.*
import uniffi.my_crypto.*
import android.util.Base64

class MyCryptoModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    private val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    override fun getName() = "MyCrypto"

    @ReactMethod
    fun generateKey(promise: Promise) {
        scope.launch {
            try {
                val key = generateKey()
                promise.resolve(Base64.encodeToString(key.toByteArray(), Base64.NO_WRAP))
            } catch (e: Exception) {
                promise.reject("CRYPTO_ERROR", e.message)
            }
        }
    }

    @ReactMethod
    fun generateSalt(length: Int, promise: Promise) {
        scope.launch {
            try {
                val salt = generateSalt(length.toUShort())
                promise.resolve(Base64.encodeToString(salt.toByteArray(), Base64.NO_WRAP))
            } catch (e: Exception) {
                promise.reject("CRYPTO_ERROR", e.message)
            }
        }
    }

    @ReactMethod
    fun encrypt(plaintext: String, keyBase64: String, aadBase64: String?, promise: Promise) {
        scope.launch {
            try {
                val key = Base64.decode(keyBase64, Base64.NO_WRAP).toUByteArray().toList()
                val aad = aadBase64?.let { Base64.decode(it, Base64.NO_WRAP).toUByteArray().toList() }

                val encrypted = encryptString(plaintext, key, aad)
                promise.resolve(encrypted)
            } catch (e: CryptoException) {
                promise.reject("CRYPTO_ERROR", e.message)
            } catch (e: Exception) {
                promise.reject("UNKNOWN_ERROR", e.message)
            }
        }
    }

    @ReactMethod
    fun decrypt(ciphertext: String, keyBase64: String, aadBase64: String?, promise: Promise) {
        scope.launch {
            try {
                val key = Base64.decode(keyBase64, Base64.NO_WRAP).toUByteArray().toList()
                val aad = aadBase64?.let { Base64.decode(it, Base64.NO_WRAP).toUByteArray().toList() }

                val decrypted = decryptString(ciphertext, key, aad)
                promise.resolve(decrypted)
            } catch (e: CryptoException) {
                promise.reject("CRYPTO_ERROR", e.message)
            } catch (e: Exception) {
                promise.reject("UNKNOWN_ERROR", e.message)
            }
        }
    }

    @ReactMethod
    fun deriveKey(
        password: String,
        saltBase64: String,
        memoryCost: Int,
        timeCost: Int,
        parallelism: Int,
        promise: Promise
    ) {
        scope.launch {
            try {
                val salt = Base64.decode(saltBase64, Base64.NO_WRAP).toUByteArray().toList()
                val params = KeyDerivationParams(
                    memoryCost = memoryCost.toUInt(),
                    timeCost = timeCost.toUInt(),
                    parallelism = parallelism.toUInt()
                )

                val key = deriveKey(password, salt, params)
                promise.resolve(Base64.encodeToString(key.toByteArray(), Base64.NO_WRAP))
            } catch (e: CryptoException) {
                promise.reject("CRYPTO_ERROR", e.message)
            } catch (e: Exception) {
                promise.reject("UNKNOWN_ERROR", e.message)
            }
        }
    }

    @ReactMethod
    fun generateKeyPair(promise: Promise) {
        scope.launch {
            try {
                val keyPair = generateKeyPair()
                val result = Arguments.createMap().apply {
                    putString("publicKey", Base64.encodeToString(
                        keyPair.publicKey.toByteArray(), Base64.NO_WRAP))
                    putString("privateKey", Base64.encodeToString(
                        keyPair.privateKey.toByteArray(), Base64.NO_WRAP))
                }
                promise.resolve(result)
            } catch (e: Exception) {
                promise.reject("CRYPTO_ERROR", e.message)
            }
        }
    }

    @ReactMethod
    fun computeSharedSecret(privateKeyBase64: String, publicKeyBase64: String, promise: Promise) {
        scope.launch {
            try {
                val privateKey = Base64.decode(privateKeyBase64, Base64.NO_WRAP).toUByteArray().toList()
                val publicKey = Base64.decode(publicKeyBase64, Base64.NO_WRAP).toUByteArray().toList()

                val secret = computeSharedSecret(privateKey, publicKey)
                promise.resolve(Base64.encodeToString(secret.toByteArray(), Base64.NO_WRAP))
            } catch (e: CryptoException) {
                promise.reject("CRYPTO_ERROR", e.message)
            } catch (e: Exception) {
                promise.reject("UNKNOWN_ERROR", e.message)
            }
        }
    }

    private fun List<UByte>.toByteArray(): ByteArray {
        return this.map { it.toByte() }.toByteArray()
    }

    private fun ByteArray.toUByteArray(): UByteArray {
        return this.map { it.toUByte() }.toUByteArray()
    }
}
```

## TypeScript Bindings

### src/crypto/types.ts

```typescript
export interface KeyDerivationParams {
  memoryCost?: number;
  timeCost?: number;
  parallelism?: number;
}

export interface KeyPair {
  publicKey: string; // base64
  privateKey: string; // base64
}

export interface CryptoModule {
  generateKey(): Promise<string>;
  generateSalt(length: number): Promise<string>;
  encrypt(plaintext: string, key: string, aad?: string): Promise<string>;
  decrypt(ciphertext: string, key: string, aad?: string): Promise<string>;
  deriveKey(
    password: string,
    salt: string,
    memoryCost: number,
    timeCost: number,
    parallelism: number
  ): Promise<string>;
  generateKeyPair(): Promise<KeyPair>;
  computeSharedSecret(privateKey: string, publicKey: string): Promise<string>;
}
```

### src/crypto/native.ts

```typescript
import { NativeModules, Platform } from 'react-native';
import type { CryptoModule } from './types';

const LINKING_ERROR =
  `The package 'my-react-native-rust' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n';

const MyCrypto: CryptoModule = NativeModules.MyCrypto
  ? NativeModules.MyCrypto
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    );

export default MyCrypto;
```

### src/crypto/index.ts

```typescript
import MyCrypto from './native';
import type { KeyDerivationParams, KeyPair } from './types';

export { KeyDerivationParams, KeyPair };

/**
 * Generate a random 32-byte encryption key
 * @returns Base64-encoded key
 */
export async function generateKey(): Promise<string> {
  return MyCrypto.generateKey();
}

/**
 * Generate a random salt
 * @param length Salt length in bytes (default: 16)
 * @returns Base64-encoded salt
 */
export async function generateSalt(length: number = 16): Promise<string> {
  return MyCrypto.generateSalt(length);
}

/**
 * Encrypt a string using AES-256-GCM
 * @param plaintext String to encrypt
 * @param key Base64-encoded 32-byte key
 * @param aad Optional additional authenticated data (base64)
 * @returns Base64-encoded ciphertext
 */
export async function encrypt(
  plaintext: string,
  key: string,
  aad?: string
): Promise<string> {
  return MyCrypto.encrypt(plaintext, key, aad);
}

/**
 * Decrypt a string using AES-256-GCM
 * @param ciphertext Base64-encoded ciphertext
 * @param key Base64-encoded 32-byte key
 * @param aad Optional additional authenticated data (base64)
 * @returns Decrypted string
 */
export async function decrypt(
  ciphertext: string,
  key: string,
  aad?: string
): Promise<string> {
  return MyCrypto.decrypt(ciphertext, key, aad);
}

/**
 * Derive a key from a password using Argon2id
 * @param password User password
 * @param salt Base64-encoded salt
 * @param params Key derivation parameters
 * @returns Base64-encoded 32-byte key
 */
export async function deriveKey(
  password: string,
  salt: string,
  params: KeyDerivationParams = {}
): Promise<string> {
  const { memoryCost = 65536, timeCost = 3, parallelism = 4 } = params;

  return MyCrypto.deriveKey(password, salt, memoryCost, timeCost, parallelism);
}

/**
 * Generate an X25519 key pair for key exchange
 * @returns Key pair with base64-encoded keys
 */
export async function generateKeyPair(): Promise<KeyPair> {
  return MyCrypto.generateKeyPair();
}

/**
 * Compute a shared secret using X25519 ECDH
 * @param privateKey Base64-encoded private key
 * @param publicKey Base64-encoded public key
 * @returns Base64-encoded shared secret
 */
export async function computeSharedSecret(
  privateKey: string,
  publicKey: string
): Promise<string> {
  return MyCrypto.computeSharedSecret(privateKey, publicKey);
}

/**
 * Encrypt with password (derives key internally)
 */
export async function encryptWithPassword(
  plaintext: string,
  password: string,
  params: KeyDerivationParams = {}
): Promise<{ ciphertext: string; salt: string }> {
  const salt = await generateSalt(16);
  const key = await deriveKey(password, salt, params);
  const ciphertext = await encrypt(plaintext, key);
  return { ciphertext, salt };
}

/**
 * Decrypt with password
 */
export async function decryptWithPassword(
  ciphertext: string,
  password: string,
  salt: string,
  params: KeyDerivationParams = {}
): Promise<string> {
  const key = await deriveKey(password, salt, params);
  return decrypt(ciphertext, key);
}
```

### src/hooks/useCrypto.ts

```typescript
import { useState, useCallback } from 'react';
import * as Crypto from '../crypto';
import type { KeyDerivationParams } from '../crypto';

interface UseCryptoState {
  loading: boolean;
  error: string | null;
}

export function useCrypto() {
  const [state, setState] = useState<UseCryptoState>({
    loading: false,
    error: null,
  });

  const wrapAsync = useCallback(
    async <T>(operation: () => Promise<T>): Promise<T | null> => {
      setState({ loading: true, error: null });
      try {
        const result = await operation();
        setState({ loading: false, error: null });
        return result;
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        setState({ loading: false, error: message });
        return null;
      }
    },
    []
  );

  const generateKey = useCallback(() => {
    return wrapAsync(() => Crypto.generateKey());
  }, [wrapAsync]);

  const encrypt = useCallback(
    (plaintext: string, key: string, aad?: string) => {
      return wrapAsync(() => Crypto.encrypt(plaintext, key, aad));
    },
    [wrapAsync]
  );

  const decrypt = useCallback(
    (ciphertext: string, key: string, aad?: string) => {
      return wrapAsync(() => Crypto.decrypt(ciphertext, key, aad));
    },
    [wrapAsync]
  );

  const deriveKey = useCallback(
    (password: string, salt: string, params?: KeyDerivationParams) => {
      return wrapAsync(() => Crypto.deriveKey(password, salt, params));
    },
    [wrapAsync]
  );

  const encryptWithPassword = useCallback(
    (plaintext: string, password: string, params?: KeyDerivationParams) => {
      return wrapAsync(() =>
        Crypto.encryptWithPassword(plaintext, password, params)
      );
    },
    [wrapAsync]
  );

  const decryptWithPassword = useCallback(
    (
      ciphertext: string,
      password: string,
      salt: string,
      params?: KeyDerivationParams
    ) => {
      return wrapAsync(() =>
        Crypto.decryptWithPassword(ciphertext, password, salt, params)
      );
    },
    [wrapAsync]
  );

  return {
    ...state,
    generateKey,
    encrypt,
    decrypt,
    deriveKey,
    encryptWithPassword,
    decryptWithPassword,
  };
}
```

## Build Scripts

### Build for iOS

```bash
#!/bin/bash
# build-ios.sh

cd rust

# Build for iOS targets
cargo build --release --target aarch64-apple-ios
cargo build --release --target x86_64-apple-ios  # Simulator

# Generate Swift bindings
cargo run --bin uniffi-bindgen generate \
    --library target/aarch64-apple-ios/release/libmy_crypto.a \
    --language swift \
    --out-dir ios

# Create XCFramework
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libmy_crypto.a \
    -headers ios/my_cryptoFFI.h \
    -library target/x86_64-apple-ios/release/libmy_crypto.a \
    -headers ios/my_cryptoFFI.h \
    -output ios/MyCryptoFFI.xcframework
```

### Build for Android

```bash
#!/bin/bash
# build-android.sh

cd rust

# Add Android targets
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android

# Set up Android NDK paths
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/26.1.10909125
export PATH=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH

# Build for all Android architectures
cargo build --release --target aarch64-linux-android
cargo build --release --target armv7-linux-androideabi
cargo build --release --target x86_64-linux-android
cargo build --release --target i686-linux-android

# Generate Kotlin bindings
cargo run --bin uniffi-bindgen generate \
    --library target/aarch64-linux-android/release/libmy_crypto.so \
    --language kotlin \
    --out-dir android/src/main/java

# Copy libraries to jniLibs
mkdir -p android/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64,x86}
cp target/aarch64-linux-android/release/libmy_crypto.so android/src/main/jniLibs/arm64-v8a/
cp target/armv7-linux-androideabi/release/libmy_crypto.so android/src/main/jniLibs/armeabi-v7a/
cp target/x86_64-linux-android/release/libmy_crypto.so android/src/main/jniLibs/x86_64/
cp target/i686-linux-android/release/libmy_crypto.so android/src/main/jniLibs/x86/
```

## Security Checklist

- [ ] Keys stored in secure storage (Keychain/Keystore)
- [ ] Biometric authentication for key access
- [ ] Memory zeroized after use
- [ ] No keys logged or displayed
- [ ] Certificate pinning for API communication
- [ ] Jailbreak/root detection
- [ ] Code obfuscation enabled
- [ ] ProGuard/R8 rules configured for Android
- [ ] App Transport Security configured for iOS
- [ ] No sensitive data in app bundle
