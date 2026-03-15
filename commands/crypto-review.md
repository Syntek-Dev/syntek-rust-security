# Cryptographic Review Command

## Table of Contents

- [Overview](#overview)
- [When to Use](#when-to-use)
- [What It Does](#what-it-does)
- [Parameters](#parameters)
- [Output](#output)
- [Examples](#examples)
- [Best Practices](#best-practices)
- [Related Commands](#related-commands)

---

## Overview

**Command:** `/rust-security:crypto-review`

Performs expert-level cryptographic implementation review, analyzing encryption algorithms, key management, random number generation, side-channel resistance, and compliance with cryptographic best practices.

**Agent:** `crypto-reviewer` (Opus - Expert Reasoning)

---

## When to Use

Use this command when:

- **Implementing cryptographic primitives** - Review custom crypto code before deployment
- **Using cryptographic libraries** - Verify correct usage of ring, RustCrypto, sodiumoxide
- **Handling sensitive data** - Encryption, hashing, key derivation implementations
- **Authentication systems** - Password hashing, token generation, signature verification
- **TLS/SSL implementations** - Secure transport layer configuration
- **Compliance requirements** - FIPS 140-2, PCI-DSS, HIPAA cryptographic standards
- **Before security audits** - Pre-audit self-assessment

---

## What It Does

1. **Identifies cryptographic code** - Scans for crypto library usage and custom implementations
2. **Analyzes algorithm selection** - Verifies modern, secure algorithms are used
3. **Reviews key management** - Checks key generation, storage, rotation, and destruction
4. **Audits randomness sources** - Validates use of cryptographically secure RNGs
5. **Checks for common vulnerabilities** - Timing attacks, padding oracle, weak modes
6. **Validates parameters** - Key sizes, IV generation, salt usage, iteration counts
7. **Reviews side-channel resistance** - Constant-time operations, secret-dependent branching
8. **Generates recommendations** - Specific fixes for identified cryptographic issues

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--scope`          | string   | No       | `full`        | Scan scope: `full`, `module`, `file`             |
| `--files`          | string[] | No       | All           | Specific files to review                         |
| `--strict`         | boolean  | No       | `false`       | Enable strict mode (flag deprecated algorithms)  |
| `--standards`      | string[] | No       | All           | Compliance standards: `fips`, `pci-dss`, `hipaa` |
| `--output`         | string   | No       | `docs/security/CRYPTO-REVIEW.md` | Output path |
| `--format`         | string   | No       | `markdown`    | Output format: `markdown`, `json`, `html`        |
| `--include-deps`   | boolean  | No       | `false`       | Review cryptographic dependencies                |

---

## Output

### Console Output

```
🔐 Syntek Rust Security - Cryptographic Review

🔍 Scanning for cryptographic code...
   ✓ Found 8 crypto-related files
   ✓ Detected libraries: ring, sha2, argon2, aes-gcm

📊 Analysis Results:

┌─────────────────────────────────────────────────────────────┐
│ CRITICAL ISSUES                                             │
├─────────────────────────────────────────────────────────────┤
│ ❌ src/auth/password.rs:45                                  │
│    Issue: Using MD5 for password hashing                    │
│    Risk: Cryptographically broken, vulnerable to collisions │
│    Fix: Replace with Argon2id or bcrypt                     │
│                                                             │
│ ❌ src/crypto/aes.rs:78                                     │
│    Issue: AES-ECB mode used for encryption                  │
│    Risk: Reveals patterns in plaintext                      │
│    Fix: Use AES-GCM or ChaCha20-Poly1305                    │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ HIGH SEVERITY WARNINGS                                      │
├─────────────────────────────────────────────────────────────┤
│ ⚠️  src/crypto/keys.rs:102                                  │
│    Issue: Hardcoded AES key in source code                  │
│    Risk: Key compromise if source code is leaked            │
│    Fix: Load keys from environment or secure key management │
│                                                             │
│ ⚠️  src/random.rs:34                                        │
│    Issue: Using thread_rng() for cryptographic operations   │
│    Risk: Not guaranteed to be cryptographically secure      │
│    Fix: Use OsRng from getrandom crate                      │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ RECOMMENDATIONS                                             │
├─────────────────────────────────────────────────────────────┤
│ ✓ Use constant-time comparison for HMAC verification        │
│ ✓ Implement key rotation mechanism                          │
│ ✓ Add zeroize for sensitive data cleanup                    │
│ ✓ Document cryptographic design decisions                   │
└─────────────────────────────────────────────────────────────┘

📄 Detailed report: docs/security/CRYPTO-REVIEW.md
```

### Generated Report

Creates `docs/security/CRYPTO-REVIEW.md` with:

- **Executive Summary** - High-level cryptographic posture assessment
- **Algorithm Inventory** - All cryptographic algorithms in use
- **Vulnerability Analysis** - Detailed explanation of each issue
- **Side-Channel Analysis** - Timing attack and power analysis concerns
- **Key Management Review** - Key lifecycle assessment
- **Compliance Mapping** - FIPS/PCI-DSS/HIPAA requirement coverage
- **Remediation Roadmap** - Prioritized fixes with code examples
- **Best Practice Guidelines** - Rust-specific crypto recommendations

---

## Examples

### Example 1: Full Project Review

```bash
/rust-security:crypto-review
```

Comprehensive cryptographic review of entire codebase.

### Example 2: Specific Module Review

```bash
/rust-security:crypto-review --scope=module --files=src/auth,src/crypto
```

Reviews only authentication and cryptography modules.

### Example 3: Strict Compliance Mode

```bash
/rust-security:crypto-review --strict --standards=fips,pci-dss
```

Enforces strict FIPS 140-2 and PCI-DSS cryptographic requirements.

### Example 4: Dependency Crypto Review

```bash
/rust-security:crypto-review --include-deps --format=json
```

Reviews cryptographic usage in dependencies, outputs JSON for processing.

### Example 5: Pre-Audit Assessment

```bash
/rust-security:crypto-review --strict --standards=fips --output=audit-prep.md
```

Generates comprehensive report for external security audit preparation.

---

## Best Practices

### Recommended Cryptographic Libraries

| Use Case                  | Recommended Library      | Why                                          |
| ------------------------- | ------------------------ | -------------------------------------------- |
| **General Crypto**        | `ring`                   | Audited, fast, minimal API surface           |
| **Password Hashing**      | `argon2`                 | Modern, memory-hard, side-channel resistant  |
| **Symmetric Encryption**  | `aes-gcm`, `chacha20poly1305` | Authenticated encryption (AEAD)    |
| **Hashing**               | `sha2`, `blake3`         | Secure, fast, well-tested                    |
| **Key Derivation**        | `hkdf`, `pbkdf2`         | Standard KDFs with proper parameters         |
| **Random Numbers**        | `getrandom`, `rand_core` | Cryptographically secure RNG                 |
| **Constant-Time Ops**     | `subtle`                 | Prevent timing attacks                       |
| **Key Zeroing**           | `zeroize`                | Securely clear sensitive memory              |

### Common Cryptographic Mistakes

#### ❌ Bad: Weak Hashing

```rust
use md5::{Md5, Digest};

fn hash_password(password: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}
```

#### ✅ Good: Secure Password Hashing

```rust
use argon2::{Argon2, PasswordHasher, PasswordHash};
use argon2::password_hash::SaltString;
use rand_core::OsRng;

fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}
```

#### ❌ Bad: Insecure Random Numbers

```rust
use rand::thread_rng;

fn generate_session_token() -> String {
    let mut rng = thread_rng();
    format!("{:x}", rng.gen::<u128>())
}
```

#### ✅ Good: Cryptographically Secure RNG

```rust
use rand_core::{OsRng, RngCore};

fn generate_session_token() -> String {
    let mut token = [0u8; 32];
    OsRng.fill_bytes(&mut token);
    hex::encode(token)
}
```

#### ❌ Bad: ECB Mode Encryption

```rust
use aes::Aes256;
use block_modes::{BlockMode, Ecb};
use block_modes::block_padding::Pkcs7;

type Aes256Ecb = Ecb<Aes256, Pkcs7>;

fn encrypt_data(key: &[u8], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256Ecb::new_from_slices(key, &[]).unwrap();
    cipher.encrypt_vec(data)
}
```

#### ✅ Good: GCM Mode Authenticated Encryption

```rust
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use rand_core::{OsRng, RngCore};

fn encrypt_data(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let key = Key::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut ciphertext = cipher.encrypt(nonce, data)?;
    ciphertext.splice(0..0, nonce_bytes.iter().copied());
    Ok(ciphertext)
}
```

### Development Workflow

```bash
# 1. Implement cryptographic feature
[Development work]

# 2. Review crypto implementation
/rust-security:crypto-review --scope=module --files=src/crypto

# 3. Fix identified issues
[Fix critical and high severity issues]

# 4. Re-review
/rust-security:crypto-review --strict

# 5. Additional security checks
/rust-security:memory-audit
/rust-security:vuln-scan

# 6. Final review before merge
/rust-security:rust-review
```

---

## Reference Documents

This command invokes the `crypto-reviewer` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[ENCRYPTION-GUIDE.md](.claude/ENCRYPTION-GUIDE.md)**
- **[DATA-STRUCTURES.md](.claude/DATA-STRUCTURES.md)**

## Related Commands

- **[/rust-security:memory-audit](memory-audit.md)** - Audit memory safety of crypto code
- **[/rust-security:vuln-scan](vuln-scan.md)** - Scan crypto dependencies for vulnerabilities
- **[/rust-security:compliance-report](compliance-report.md)** - Generate cryptographic compliance reports
- **[/rust-security:threat-model](threat-model.md)** - Threat model cryptographic components

---

**Note:** This command uses the Opus model for expert cryptographic analysis and may take 30-90 seconds for comprehensive reviews.
