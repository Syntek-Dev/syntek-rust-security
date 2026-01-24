# Rust Next.js FFI Template

## Overview

This template provides a secure foundation for integrating Rust code into
Next.js applications using Neon bindings for Node.js and wasm-bindgen for
browser-side WebAssembly. It enables high-performance, memory-safe cryptographic
operations across both server-side (API routes) and client-side (browser)
contexts.

**Target Use Cases:**

- Server-side encryption in Next.js API routes
- Client-side encryption in React components
- Secure key derivation and management
- High-performance data processing
- End-to-end encryption implementations

## Project Structure

```
my-nextjs-rust/
├── rust/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs              # Neon/WASM entry point
│   │   ├── crypto/
│   │   │   ├── mod.rs
│   │   │   ├── encrypt.rs
│   │   │   └── decrypt.rs
│   │   ├── node/               # Node.js specific (Neon)
│   │   │   ├── mod.rs
│   │   │   └── bindings.rs
│   │   └── wasm/               # Browser specific (wasm-bindgen)
│   │       ├── mod.rs
│   │       └── bindings.rs
│   └── pkg/                    # WASM build output
├── src/
│   ├── app/
│   │   ├── layout.tsx
│   │   ├── page.tsx
│   │   └── api/
│   │       └── encrypt/
│   │           └── route.ts
│   ├── lib/
│   │   ├── crypto-server.ts    # Server-side Rust bindings
│   │   ├── crypto-client.ts    # Client-side WASM bindings
│   │   └── crypto.ts           # Unified crypto interface
│   └── components/
│       └── EncryptedForm.tsx
├── package.json
├── tsconfig.json
├── next.config.js
└── README.md
```

## Cargo.toml - Rust Configuration

```toml
[package]
name = "my-nextjs-rust"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"
license = "MIT"

[lib]
crate-type = ["cdylib"]

[features]
default = []
node = ["neon"]
wasm = ["wasm-bindgen", "console_error_panic_hook", "getrandom/js"]

[dependencies]
# Cryptography
aes-gcm = "0.10"
chacha20poly1305 = "0.10"
argon2 = "0.5"
rand = "0.8"
getrandom = { version = "0.2", optional = true }

# Secure memory
zeroize = { version = "1.8", features = ["derive"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
base64 = "0.22"

# Error handling
thiserror = "2.0"

# Node.js bindings (Neon)
neon = { version = "1.0", optional = true, default-features = false, features = ["napi-6"] }

# WebAssembly bindings
wasm-bindgen = { version = "0.2", optional = true }
console_error_panic_hook = { version = "0.1", optional = true }
js-sys = { version = "0.3", optional = true }
web-sys = { version = "0.3", optional = true }

[profile.release]
lto = true
opt-level = "z"
codegen-units = 1

[profile.release.package.my-nextjs-rust]
opt-level = "z"
```

## Rust Implementation

### src/lib.rs - Entry Point

```rust
#![cfg_attr(target_arch = "wasm32", no_std)]

pub mod crypto;

#[cfg(feature = "node")]
pub mod node;

#[cfg(feature = "wasm")]
pub mod wasm;

// Re-exports
pub use crypto::{encrypt_aes_gcm, decrypt_aes_gcm, derive_key_argon2};
```

### src/crypto/mod.rs - Core Crypto

```rust
pub mod encrypt;
pub mod decrypt;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use rand::RngCore;
use zeroize::Zeroize;

/// Encrypt data using AES-256-GCM
pub fn encrypt_aes_gcm(
    plaintext: &[u8],
    key: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("Key must be exactly 32 bytes".to_string());
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "Invalid key")?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

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

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data using AES-256-GCM
pub fn decrypt_aes_gcm(
    ciphertext: &[u8],
    key: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("Key must be exactly 32 bytes".to_string());
    }

    if ciphertext.len() < 28 {
        return Err("Ciphertext too short".to_string());
    }

    let (nonce_bytes, encrypted) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "Invalid key")?;

    let plaintext = match aad {
        Some(aad_bytes) => cipher
            .decrypt(nonce, aes_gcm::aead::Payload {
                msg: encrypted,
                aad: aad_bytes,
            })
            .map_err(|_| "Decryption failed")?,
        None => cipher
            .decrypt(nonce, encrypted)
            .map_err(|_| "Decryption failed")?,
    };

    Ok(plaintext)
}

/// Derive key using Argon2id
pub fn derive_key_argon2(
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
        .map_err(|e| format!("Invalid parameters: {}", e))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut output = vec![0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| format!("Key derivation failed: {}", e))?;

    Ok(output)
}

/// Generate random bytes
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
```

### src/node/bindings.rs - Neon Node.js Bindings

```rust
use neon::prelude::*;
use crate::crypto::{encrypt_aes_gcm, decrypt_aes_gcm, derive_key_argon2, generate_random_bytes};

/// Encrypt data (Node.js)
fn js_encrypt(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let plaintext = cx.argument::<JsArrayBuffer>(0)?;
    let key = cx.argument::<JsArrayBuffer>(1)?;
    let aad = cx.argument_opt(2);

    let plaintext_bytes = plaintext.as_slice(&cx);
    let key_bytes = key.as_slice(&cx);

    let aad_bytes: Option<Vec<u8>> = aad.and_then(|v| {
        v.downcast::<JsArrayBuffer, _>(&mut cx).ok()
            .map(|buf| buf.as_slice(&cx).to_vec())
    });

    let result = encrypt_aes_gcm(
        plaintext_bytes,
        key_bytes,
        aad_bytes.as_deref(),
    ).or_else(|e| cx.throw_error(e))?;

    let mut buffer = cx.array_buffer(result.len())?;
    buffer.as_mut_slice(&mut cx).copy_from_slice(&result);
    Ok(buffer)
}

/// Decrypt data (Node.js)
fn js_decrypt(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let ciphertext = cx.argument::<JsArrayBuffer>(0)?;
    let key = cx.argument::<JsArrayBuffer>(1)?;
    let aad = cx.argument_opt(2);

    let ciphertext_bytes = ciphertext.as_slice(&cx);
    let key_bytes = key.as_slice(&cx);

    let aad_bytes: Option<Vec<u8>> = aad.and_then(|v| {
        v.downcast::<JsArrayBuffer, _>(&mut cx).ok()
            .map(|buf| buf.as_slice(&cx).to_vec())
    });

    let result = decrypt_aes_gcm(
        ciphertext_bytes,
        key_bytes,
        aad_bytes.as_deref(),
    ).or_else(|e| cx.throw_error(e))?;

    let mut buffer = cx.array_buffer(result.len())?;
    buffer.as_mut_slice(&mut cx).copy_from_slice(&result);
    Ok(buffer)
}

/// Derive key from password (Node.js)
fn js_derive_key(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let password = cx.argument::<JsString>(0)?.value(&mut cx);
    let salt = cx.argument::<JsArrayBuffer>(1)?;
    let memory_cost = cx.argument::<JsNumber>(2)?.value(&mut cx) as u32;
    let time_cost = cx.argument::<JsNumber>(3)?.value(&mut cx) as u32;
    let parallelism = cx.argument::<JsNumber>(4)?.value(&mut cx) as u32;

    let salt_bytes = salt.as_slice(&cx);

    let key = derive_key_argon2(
        &password,
        salt_bytes,
        memory_cost,
        time_cost,
        parallelism,
    ).or_else(|e| cx.throw_error(e))?;

    let mut buffer = cx.array_buffer(32)?;
    buffer.as_mut_slice(&mut cx).copy_from_slice(&key);
    Ok(buffer)
}

/// Generate random key (Node.js)
fn js_generate_key(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let key = generate_random_bytes(32);
    let mut buffer = cx.array_buffer(32)?;
    buffer.as_mut_slice(&mut cx).copy_from_slice(&key);
    Ok(buffer)
}

/// Generate random salt (Node.js)
fn js_generate_salt(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let len = cx.argument_opt(0)
        .and_then(|v| v.downcast::<JsNumber, _>(&mut cx).ok())
        .map(|n| n.value(&mut cx) as usize)
        .unwrap_or(16);

    let salt = generate_random_bytes(len);
    let mut buffer = cx.array_buffer(len)?;
    buffer.as_mut_slice(&mut cx).copy_from_slice(&salt);
    Ok(buffer)
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("encrypt", js_encrypt)?;
    cx.export_function("decrypt", js_decrypt)?;
    cx.export_function("deriveKey", js_derive_key)?;
    cx.export_function("generateKey", js_generate_key)?;
    cx.export_function("generateSalt", js_generate_salt)?;
    Ok(())
}
```

### src/wasm/bindings.rs - WASM Browser Bindings

```rust
use wasm_bindgen::prelude::*;
use crate::crypto::{encrypt_aes_gcm, decrypt_aes_gcm, derive_key_argon2, generate_random_bytes};

#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Encrypt data (WASM)
#[wasm_bindgen(js_name = encrypt)]
pub fn wasm_encrypt(
    plaintext: &[u8],
    key: &[u8],
    aad: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    encrypt_aes_gcm(plaintext, key, aad.as_deref())
        .map_err(|e| JsValue::from_str(&e))
}

/// Decrypt data (WASM)
#[wasm_bindgen(js_name = decrypt)]
pub fn wasm_decrypt(
    ciphertext: &[u8],
    key: &[u8],
    aad: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    decrypt_aes_gcm(ciphertext, key, aad.as_deref())
        .map_err(|e| JsValue::from_str(&e))
}

/// Derive key from password (WASM)
#[wasm_bindgen(js_name = deriveKey)]
pub fn wasm_derive_key(
    password: &str,
    salt: &[u8],
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<Vec<u8>, JsValue> {
    derive_key_argon2(password, salt, memory_cost, time_cost, parallelism)
        .map_err(|e| JsValue::from_str(&e))
}

/// Generate random key (WASM)
#[wasm_bindgen(js_name = generateKey)]
pub fn wasm_generate_key() -> Vec<u8> {
    generate_random_bytes(32)
}

/// Generate random salt (WASM)
#[wasm_bindgen(js_name = generateSalt)]
pub fn wasm_generate_salt(len: Option<usize>) -> Vec<u8> {
    generate_random_bytes(len.unwrap_or(16))
}

/// Encode bytes as base64
#[wasm_bindgen(js_name = toBase64)]
pub fn wasm_to_base64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Decode base64 to bytes
#[wasm_bindgen(js_name = fromBase64)]
pub fn wasm_from_base64(data: &str) -> Result<Vec<u8>, JsValue> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| JsValue::from_str(&format!("Invalid base64: {}", e)))
}
```

## TypeScript Integration

### src/lib/crypto-server.ts - Server-Side Bindings

```typescript
/**
 * Server-side crypto using Neon bindings
 * Only import this in API routes or server components
 */

// Import native module (built with Neon)
const native = require('../../rust/index.node');

export interface CryptoOptions {
  aad?: Uint8Array;
}

export interface KeyDerivationOptions {
  memoryCost?: number;
  timeCost?: number;
  parallelism?: number;
}

/**
 * Encrypt data using AES-256-GCM (server-side)
 */
export function encrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  options?: CryptoOptions
): Uint8Array {
  const result = native.encrypt(
    plaintext.buffer,
    key.buffer,
    options?.aad?.buffer
  );
  return new Uint8Array(result);
}

/**
 * Decrypt data using AES-256-GCM (server-side)
 */
export function decrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  options?: CryptoOptions
): Uint8Array {
  const result = native.decrypt(
    ciphertext.buffer,
    key.buffer,
    options?.aad?.buffer
  );
  return new Uint8Array(result);
}

/**
 * Derive key from password using Argon2id (server-side)
 */
export function deriveKey(
  password: string,
  salt: Uint8Array,
  options?: KeyDerivationOptions
): Uint8Array {
  const memoryCost = options?.memoryCost ?? 65536;
  const timeCost = options?.timeCost ?? 3;
  const parallelism = options?.parallelism ?? 4;

  const result = native.deriveKey(
    password,
    salt.buffer,
    memoryCost,
    timeCost,
    parallelism
  );
  return new Uint8Array(result);
}

/**
 * Generate random encryption key (server-side)
 */
export function generateKey(): Uint8Array {
  return new Uint8Array(native.generateKey());
}

/**
 * Generate random salt (server-side)
 */
export function generateSalt(length: number = 16): Uint8Array {
  return new Uint8Array(native.generateSalt(length));
}

/**
 * Encrypt string, return base64 (server-side)
 */
export function encryptString(
  plaintext: string,
  key: Uint8Array,
  options?: CryptoOptions
): string {
  const encoder = new TextEncoder();
  const encrypted = encrypt(encoder.encode(plaintext), key, options);
  return Buffer.from(encrypted).toString('base64');
}

/**
 * Decrypt base64 string (server-side)
 */
export function decryptString(
  ciphertext: string,
  key: Uint8Array,
  options?: CryptoOptions
): string {
  const encrypted = new Uint8Array(Buffer.from(ciphertext, 'base64'));
  const decrypted = decrypt(encrypted, key, options);
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}
```

### src/lib/crypto-client.ts - Client-Side WASM Bindings

```typescript
/**
 * Client-side crypto using WebAssembly
 * Safe to import in browser components
 */

import init, {
  encrypt as wasmEncrypt,
  decrypt as wasmDecrypt,
  deriveKey as wasmDeriveKey,
  generateKey as wasmGenerateKey,
  generateSalt as wasmGenerateSalt,
  toBase64,
  fromBase64,
} from '../../rust/pkg/my_nextjs_rust';

let initialized = false;

/**
 * Initialize WASM module (call once at app startup)
 */
export async function initCrypto(): Promise<void> {
  if (!initialized) {
    await init();
    initialized = true;
  }
}

export interface CryptoOptions {
  aad?: Uint8Array;
}

export interface KeyDerivationOptions {
  memoryCost?: number;
  timeCost?: number;
  parallelism?: number;
}

/**
 * Encrypt data using AES-256-GCM (client-side)
 */
export function encrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  options?: CryptoOptions
): Uint8Array {
  if (!initialized) {
    throw new Error('Crypto not initialized. Call initCrypto() first.');
  }
  return new Uint8Array(wasmEncrypt(plaintext, key, options?.aad));
}

/**
 * Decrypt data using AES-256-GCM (client-side)
 */
export function decrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  options?: CryptoOptions
): Uint8Array {
  if (!initialized) {
    throw new Error('Crypto not initialized. Call initCrypto() first.');
  }
  return new Uint8Array(wasmDecrypt(ciphertext, key, options?.aad));
}

/**
 * Derive key from password using Argon2id (client-side)
 * Note: Use lower cost parameters for browser to avoid UI blocking
 */
export function deriveKey(
  password: string,
  salt: Uint8Array,
  options?: KeyDerivationOptions
): Uint8Array {
  if (!initialized) {
    throw new Error('Crypto not initialized. Call initCrypto() first.');
  }

  // Lower defaults for browser (to avoid blocking UI)
  const memoryCost = options?.memoryCost ?? 16384; // 16MB
  const timeCost = options?.timeCost ?? 2;
  const parallelism = options?.parallelism ?? 1;

  return new Uint8Array(
    wasmDeriveKey(password, salt, memoryCost, timeCost, parallelism)
  );
}

/**
 * Generate random encryption key (client-side)
 */
export function generateKey(): Uint8Array {
  if (!initialized) {
    throw new Error('Crypto not initialized. Call initCrypto() first.');
  }
  return new Uint8Array(wasmGenerateKey());
}

/**
 * Generate random salt (client-side)
 */
export function generateSalt(length: number = 16): Uint8Array {
  if (!initialized) {
    throw new Error('Crypto not initialized. Call initCrypto() first.');
  }
  return new Uint8Array(wasmGenerateSalt(length));
}

/**
 * Encrypt string, return base64 (client-side)
 */
export function encryptString(
  plaintext: string,
  key: Uint8Array,
  options?: CryptoOptions
): string {
  const encoder = new TextEncoder();
  const encrypted = encrypt(encoder.encode(plaintext), key, options);
  return toBase64(encrypted);
}

/**
 * Decrypt base64 string (client-side)
 */
export function decryptString(
  ciphertext: string,
  key: Uint8Array,
  options?: CryptoOptions
): string {
  const encrypted = new Uint8Array(fromBase64(ciphertext));
  const decrypted = decrypt(encrypted, key, options);
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}
```

### src/lib/crypto.ts - Unified Interface

```typescript
/**
 * Unified crypto interface that works on both server and client
 */

export interface CryptoOptions {
  aad?: Uint8Array;
}

export interface KeyDerivationOptions {
  memoryCost?: number;
  timeCost?: number;
  parallelism?: number;
}

// Detect environment
const isServer = typeof window === 'undefined';

// Dynamic imports based on environment
let serverCrypto: typeof import('./crypto-server') | null = null;
let clientCrypto: typeof import('./crypto-client') | null = null;

/**
 * Initialize crypto module
 */
export async function initCrypto(): Promise<void> {
  if (isServer) {
    serverCrypto = await import('./crypto-server');
  } else {
    clientCrypto = await import('./crypto-client');
    await clientCrypto.initCrypto();
  }
}

/**
 * Encrypt data
 */
export function encrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  options?: CryptoOptions
): Uint8Array {
  if (isServer && serverCrypto) {
    return serverCrypto.encrypt(plaintext, key, options);
  } else if (clientCrypto) {
    return clientCrypto.encrypt(plaintext, key, options);
  }
  throw new Error('Crypto not initialized');
}

/**
 * Decrypt data
 */
export function decrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  options?: CryptoOptions
): Uint8Array {
  if (isServer && serverCrypto) {
    return serverCrypto.decrypt(ciphertext, key, options);
  } else if (clientCrypto) {
    return clientCrypto.decrypt(ciphertext, key, options);
  }
  throw new Error('Crypto not initialized');
}

/**
 * Derive key from password
 */
export function deriveKey(
  password: string,
  salt: Uint8Array,
  options?: KeyDerivationOptions
): Uint8Array {
  if (isServer && serverCrypto) {
    return serverCrypto.deriveKey(password, salt, options);
  } else if (clientCrypto) {
    return clientCrypto.deriveKey(password, salt, options);
  }
  throw new Error('Crypto not initialized');
}

/**
 * Generate random key
 */
export function generateKey(): Uint8Array {
  if (isServer && serverCrypto) {
    return serverCrypto.generateKey();
  } else if (clientCrypto) {
    return clientCrypto.generateKey();
  }
  throw new Error('Crypto not initialized');
}

/**
 * Generate random salt
 */
export function generateSalt(length: number = 16): Uint8Array {
  if (isServer && serverCrypto) {
    return serverCrypto.generateSalt(length);
  } else if (clientCrypto) {
    return clientCrypto.generateSalt(length);
  }
  throw new Error('Crypto not initialized');
}

/**
 * Encrypt string to base64
 */
export function encryptString(
  plaintext: string,
  key: Uint8Array,
  options?: CryptoOptions
): string {
  if (isServer && serverCrypto) {
    return serverCrypto.encryptString(plaintext, key, options);
  } else if (clientCrypto) {
    return clientCrypto.encryptString(plaintext, key, options);
  }
  throw new Error('Crypto not initialized');
}

/**
 * Decrypt base64 to string
 */
export function decryptString(
  ciphertext: string,
  key: Uint8Array,
  options?: CryptoOptions
): string {
  if (isServer && serverCrypto) {
    return serverCrypto.decryptString(ciphertext, key, options);
  } else if (clientCrypto) {
    return clientCrypto.decryptString(ciphertext, key, options);
  }
  throw new Error('Crypto not initialized');
}
```

## Next.js API Route

### src/app/api/encrypt/route.ts

```typescript
import { NextRequest, NextResponse } from 'next/server';
import * as crypto from '@/lib/crypto-server';

export async function POST(request: NextRequest) {
  try {
    const { data, keyHex } = await request.json();

    if (!data || !keyHex) {
      return NextResponse.json(
        { error: 'Missing data or key' },
        { status: 400 }
      );
    }

    // Convert hex key to bytes
    const key = new Uint8Array(
      keyHex.match(/.{2}/g)!.map((byte: string) => parseInt(byte, 16))
    );

    if (key.length !== 32) {
      return NextResponse.json(
        { error: 'Key must be 32 bytes (64 hex characters)' },
        { status: 400 }
      );
    }

    // Encrypt data
    const encrypted = crypto.encryptString(data, key);

    return NextResponse.json({ encrypted });
  } catch (error) {
    console.error('Encryption error:', error);
    return NextResponse.json({ error: 'Encryption failed' }, { status: 500 });
  }
}
```

## React Component

### src/components/EncryptedForm.tsx

```tsx
'use client';

import { useState, useEffect } from 'react';
import * as crypto from '@/lib/crypto-client';

interface EncryptedFormProps {
  onSubmit: (encryptedData: string) => void;
}

export function EncryptedForm({ onSubmit }: EncryptedFormProps) {
  const [initialized, setInitialized] = useState(false);
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState<string | null>(null);

  // Initialize WASM on mount
  useEffect(() => {
    crypto
      .initCrypto()
      .then(() => setInitialized(true))
      .catch(err => setError(`Failed to initialize crypto: ${err.message}`));
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!initialized) {
      setError('Crypto not initialized');
      return;
    }

    try {
      // Derive key from password
      const salt = crypto.generateSalt(16);
      const key = crypto.deriveKey(password, salt);

      // Encrypt message
      const encrypted = crypto.encryptString(message, key);

      // Combine salt and encrypted data for transmission
      const saltBase64 = btoa(String.fromCharCode(...salt));
      const payload = JSON.stringify({
        salt: saltBase64,
        data: encrypted,
      });

      onSubmit(payload);
    } catch (err) {
      setError(`Encryption failed: ${(err as Error).message}`);
    }
  };

  if (!initialized) {
    return <div>Loading crypto module...</div>;
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {error && <div className="text-red-500 text-sm">{error}</div>}

      <div>
        <label htmlFor="password" className="block text-sm font-medium">
          Password
        </label>
        <input
          type="password"
          id="password"
          value={password}
          onChange={e => setPassword(e.target.value)}
          className="mt-1 block w-full rounded border-gray-300 shadow-sm"
          required
          minLength={8}
        />
      </div>

      <div>
        <label htmlFor="message" className="block text-sm font-medium">
          Message
        </label>
        <textarea
          id="message"
          value={message}
          onChange={e => setMessage(e.target.value)}
          className="mt-1 block w-full rounded border-gray-300 shadow-sm"
          rows={4}
          required
        />
      </div>

      <button
        type="submit"
        className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
      >
        Encrypt & Submit
      </button>
    </form>
  );
}
```

## Build Scripts

### package.json

```json
{
  "name": "my-nextjs-rust",
  "version": "0.1.0",
  "scripts": {
    "dev": "next dev",
    "build": "npm run build:rust && next build",
    "build:rust": "npm run build:neon && npm run build:wasm",
    "build:neon": "cd rust && cargo build --release --features node && cp target/release/libmy_nextjs_rust.so ../index.node",
    "build:wasm": "cd rust && wasm-pack build --target web --features wasm --out-dir pkg",
    "test": "npm run test:rust && npm run test:js",
    "test:rust": "cd rust && cargo test",
    "test:js": "jest"
  },
  "dependencies": {
    "next": "14.2.0",
    "react": "18.3.0",
    "react-dom": "18.3.0"
  },
  "devDependencies": {
    "@types/node": "20.14.0",
    "@types/react": "18.3.0",
    "typescript": "5.5.0",
    "jest": "29.7.0",
    "@testing-library/react": "16.0.0"
  }
}
```

### next.config.js

```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
  webpack: (config, { isServer }) => {
    // Handle native modules
    if (isServer) {
      config.externals.push({
        './index.node': 'commonjs ./index.node',
      });
    }

    // Handle WASM
    config.experiments = {
      ...config.experiments,
      asyncWebAssembly: true,
    };

    return config;
  },
};

module.exports = nextConfig;
```

## Security Checklist

- [ ] WASM module loaded securely (integrity checks)
- [ ] Keys never logged or exposed to client in plaintext
- [ ] Salt stored/transmitted with encrypted data
- [ ] Key derivation cost appropriate for environment (higher on server)
- [ ] Error messages don't leak sensitive information
- [ ] HTTPS enforced for all API routes
- [ ] CSP headers configured for WASM
- [ ] Input validation on all API endpoints
- [ ] Rate limiting on encryption endpoints
- [ ] Audit logging for crypto operations
