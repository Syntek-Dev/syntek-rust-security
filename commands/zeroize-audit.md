# Zeroize Audit Command

## Overview

**Command:** `/rust-security:zeroize-audit`

Audits Rust code for proper memory zeroisation of sensitive data, ensuring
secrets are securely wiped from memory after use to prevent information leakage.

**Agent:** `zeroize-audit` (Opus - Deep Reasoning)

---

## When to Use

- Reviewing cryptographic code for secure memory handling
- Auditing authentication systems handling passwords/tokens
- Verifying sensitive data cleanup in FFI boundaries
- Pre-release security audits for memory safety
- Compliance requirements (PCI-DSS, GDPR data protection)

---

## What It Does

1. **Scans for sensitive types** - Identifies String, Vec<u8>, arrays holding
   secrets
2. **Checks zeroize usage** - Verifies `zeroize` and `secrecy` crate patterns
3. **Analyses drop implementations** - Ensures custom Drop traits zeroize data
4. **Reviews FFI boundaries** - Checks data is zeroized before crossing FFI
5. **Detects compiler optimizations** - Identifies potential dead store
   elimination
6. **Generates remediation** - Creates code fixes for missing zeroisation
7. **Creates audit report** - Documents findings in
   `docs/security/ZEROIZE-AUDIT.md`

---

## Parameters

| Parameter   | Type    | Required | Default                          | Description                             |
| ----------- | ------- | -------- | -------------------------------- | --------------------------------------- |
| `--fix`     | boolean | No       | `false`                          | Automatically apply fixes               |
| `--strict`  | boolean | No       | `false`                          | Strict mode - flag all potential issues |
| `--output`  | string  | No       | `docs/security/ZEROIZE-AUDIT.md` | Output report path                      |
| `--include` | string  | No       | `src/`                           | Directories to scan                     |

---

## Output

### Console Output

```
🔐 Syntek Rust Security - Zeroize Audit

📂 Scanning src/ for sensitive data handling...

⚠️  Issues Found: 4

┌─────────────────────────────────────────────────────────────┐
│ HIGH: Unzeroized password in memory                         │
├─────────────────────────────────────────────────────────────┤
│ File:     src/auth/login.rs:45                              │
│ Type:     String (password)                                 │
│ Issue:    Password stored in String without zeroize         │
│ Fix:      Use secrecy::SecretString instead                 │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ MEDIUM: Vec<u8> may contain key material                    │
├─────────────────────────────────────────────────────────────┤
│ File:     src/crypto/keys.rs:23                             │
│ Type:     Vec<u8> (encryption_key)                          │
│ Issue:    Key material in Vec without Zeroizing wrapper     │
│ Fix:      Use zeroize::Zeroizing<Vec<u8>>                   │
└─────────────────────────────────────────────────────────────┘

📊 Summary:
   High:   1
   Medium: 2
   Low:    1

📄 Detailed report: docs/security/ZEROIZE-AUDIT.md
```

---

## Examples

### Example 1: Standard Audit

```bash
/rust-security:zeroize-audit
```

### Example 2: Auto-Fix Issues

```bash
/rust-security:zeroize-audit --fix
```

### Example 3: Strict Mode

```bash
/rust-security:zeroize-audit --strict
```

---

## Reference Documents

This command invokes the `zeroize-auditor` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[ENCRYPTION-GUIDE.md](.claude/ENCRYPTION-GUIDE.md)**
- **[DATA-STRUCTURES.md](.claude/DATA-STRUCTURES.md)**

## Related Commands

- **[/rust-security:encrypt-setup](encrypt-setup.md)** - Encryption
  infrastructure
- **[/rust-security:memory-audit](memory-audit.md)** - Memory safety audit
- **[/rust-security:crypto-review](crypto-review.md)** - Cryptographic review
