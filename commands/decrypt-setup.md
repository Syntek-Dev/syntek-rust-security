# Decrypt Setup Command

## Overview

**Command:** `/rust-security:decrypt-setup`

Initialises custom decryption infrastructure for Rust applications,
complementing the encryption setup with secure decryption patterns, key
retrieval, and authenticated decryption verification.

**Agent:** `encrypt-setup` (Opus - Deep Reasoning)

---

## When to Use

- Setting up decryption for encrypted data at rest
- Adding client-side decryption to full-stack applications
- Implementing secure key retrieval from Vault
- Creating decryption wrappers for FFI consumers
- Handling legacy encrypted data migration

---

## What It Does

1. **Detects existing encryption setup** - Reads encryption configuration
2. **Generates decryption functions** - Matching algorithm implementations
3. **Implements key retrieval** - From Vault or local secure storage
4. **Adds authentication verification** - AEAD tag validation
5. **Creates error handling** - Secure error messages without information
   leakage
6. **Generates FFI bindings** - If targeting Django/Next.js/React Native
7. **Creates test suite** - Decryption and error case tests

---

## Parameters

| Parameter  | Type    | Required | Default       | Description                                                  |
| ---------- | ------- | -------- | ------------- | ------------------------------------------------------------ |
| `--target` | string  | No       | `server`      | Target: `server`, `django`, `nextjs`, `react-native`, `wasm` |
| `--vault`  | boolean | No       | `true`        | Enable HashiCorp Vault key retrieval                         |
| `--legacy` | boolean | No       | `false`       | Support legacy encryption formats                            |
| `--output` | string  | No       | `src/crypto/` | Output directory for generated code                          |

---

## Output

Creates/updates decryption module with:

- `src/crypto/decryption.rs` - Core decryption functions
- `src/crypto/key_retrieval.rs` - Secure key retrieval logic
- `src/crypto/errors.rs` - Cryptographic error types
- `src/crypto/migration.rs` - Legacy format support (if enabled)
- `tests/decryption_tests.rs` - Decryption test suite

---

## Examples

### Example 1: Server-Side Decryption

```bash
/rust-security:decrypt-setup
```

### Example 2: Django Integration

```bash
/rust-security:decrypt-setup --target=django
```

### Example 3: With Legacy Support

```bash
/rust-security:decrypt-setup --legacy=true
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

- **[/rust-security:encrypt-setup](encrypt-setup.md)** - Encryption
  infrastructure
- **[/rust-security:vault-setup](vault-setup.md)** - HashiCorp Vault integration
- **[/rust-security:zeroize-audit](zeroize-audit.md)** - Memory zeroisation
  audit
