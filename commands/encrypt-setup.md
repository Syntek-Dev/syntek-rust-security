# Encrypt Setup Command

## Overview

**Command:** `/rust-security:encrypt-setup`

Initialises custom encryption infrastructure for Rust applications, including
envelope encryption, key derivation, and secure key storage patterns with
HashiCorp Vault integration.

**Agent:** `encryption-architect` (Opus - Deep Reasoning)

---

## When to Use

- Setting up encryption for a new Rust project
- Adding client-side encryption to full-stack applications
- Implementing envelope encryption patterns
- Creating encryption wrappers for FFI (PyO3, Neon, UniFFI)
- Integrating with HashiCorp Vault for key management

---

## What It Does

1. **Analyses project structure** - Detects stack (server, Django FFI, Next.js
   FFI, React Native)
2. **Selects encryption algorithms** - AES-256-GCM, ChaCha20-Poly1305, or
   XChaCha20-Poly1305
3. **Generates key derivation** - Argon2id configuration for password-based
   encryption
4. **Creates envelope encryption** - Data Encryption Key (DEK) / Key Encryption
   Key (KEK) pattern
5. **Implements Vault integration** - Transit secrets engine for key management
6. **Generates FFI bindings** - If targeting Django/Next.js/React Native
7. **Creates test suite** - Encryption round-trip tests

---

## Parameters

| Parameter     | Type    | Required | Default       | Description                                                                    |
| ------------- | ------- | -------- | ------------- | ------------------------------------------------------------------------------ |
| `--algorithm` | string  | No       | `aes-256-gcm` | Encryption algorithm: `aes-256-gcm`, `chacha20-poly1305`, `xchacha20-poly1305` |
| `--target`    | string  | No       | `server`      | Target: `server`, `django`, `nextjs`, `react-native`, `wasm`                   |
| `--vault`     | boolean | No       | `true`        | Enable HashiCorp Vault integration                                             |
| `--kdf`       | string  | No       | `argon2id`    | Key derivation: `argon2id`, `scrypt`, `pbkdf2`                                 |
| `--output`    | string  | No       | `src/crypto/` | Output directory for generated code                                            |

---

## Output

Creates encryption module with:

- `src/crypto/mod.rs` - Module exports
- `src/crypto/encryption.rs` - Core encryption/decryption functions
- `src/crypto/keys.rs` - Key generation and derivation
- `src/crypto/envelope.rs` - Envelope encryption pattern
- `src/crypto/vault.rs` - Vault integration (if enabled)
- `src/crypto/ffi.rs` - FFI bindings (if target requires)
- `tests/crypto_tests.rs` - Comprehensive test suite

---

## Examples

### Example 1: Server-Side Encryption

```bash
/rust-security:encrypt-setup
```

### Example 2: Django Integration via PyO3

```bash
/rust-security:encrypt-setup --target=django --algorithm=chacha20-poly1305
```

### Example 3: React Native with XChaCha20

```bash
/rust-security:encrypt-setup --target=react-native --algorithm=xchacha20-poly1305
```

---

## Reference Documents

This command invokes the `encryption-architect` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[ENCRYPTION-GUIDE.md](.claude/ENCRYPTION-GUIDE.md)**
- **[API-DESIGN.md](.claude/API-DESIGN.md)**
- **[ARCHITECTURE-PATTERNS.md](.claude/ARCHITECTURE-PATTERNS.md)**
- **[DATA-STRUCTURES.md](.claude/DATA-STRUCTURES.md)**
- **[PERFORMANCE.md](.claude/PERFORMANCE.md)**

## Related Commands

- **[/rust-security:decrypt-setup](decrypt-setup.md)** - Decryption
  infrastructure
- **[/rust-security:vault-setup](vault-setup.md)** - HashiCorp Vault integration
- **[/rust-security:zeroize-audit](zeroize-audit.md)** - Memory zeroisation
  audit
- **[/rust-security:ffi-audit](ffi-audit.md)** - FFI security audit
