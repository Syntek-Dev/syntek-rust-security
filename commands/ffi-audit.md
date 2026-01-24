# FFI Audit Command

## Overview

**Command:** `/rust-security:ffi-audit`

Audits Foreign Function Interface (FFI) boundaries for security vulnerabilities,
memory safety issues, and data handling problems in PyO3, Neon, UniFFI, and
wasm-bindgen code.

**Agent:** `ffi-security-reviewer` (Opus - Deep Reasoning)

---

## When to Use

- Reviewing Rust FFI code for security issues
- Auditing PyO3 bindings for Django integration
- Checking Neon bindings for Node.js/Next.js
- Reviewing UniFFI for React Native
- Validating wasm-bindgen for WebAssembly

---

## What It Does

1. **Scans FFI boundaries** - Identifies all FFI entry points
2. **Checks memory safety** - Validates ownership across boundaries
3. **Reviews data validation** - Input validation at FFI boundaries
4. **Audits error handling** - Panic safety and error propagation
5. **Checks lifetime management** - Dangling pointer detection
6. **Reviews string handling** - UTF-8 validation and null termination
7. **Generates security report** - Documents findings

---

## Parameters

| Parameter  | Type    | Required | Default          | Description                                     |
| ---------- | ------- | -------- | ---------------- | ----------------------------------------------- |
| `--target` | string  | No       | `all`            | Target: `pyo3`, `neon`, `uniffi`, `wasm`, `all` |
| `--strict` | boolean | No       | `false`          | Strict mode - flag all potential issues         |
| `--fix`    | boolean | No       | `false`          | Generate fix suggestions                        |
| `--output` | string  | No       | `docs/security/` | Output directory                                |

---

## Output

### Console Output

```
🔗 Syntek Rust Security - FFI Audit

📂 Scanning FFI boundaries...
   Found: 12 PyO3 functions, 8 Neon functions

⚠️  Issues Found: 5

┌─────────────────────────────────────────────────────────────┐
│ HIGH: Unvalidated string from Python                        │
├─────────────────────────────────────────────────────────────┤
│ File:     src/ffi/pyo3_bindings.rs:45                       │
│ Function: encrypt_data(data: &str)                          │
│ Issue:    Python string passed without length validation    │
│ Fix:      Add maximum length check before processing        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ MEDIUM: Panic possible in FFI function                      │
├─────────────────────────────────────────────────────────────┤
│ File:     src/ffi/neon_bindings.rs:23                       │
│ Function: parse_json(input: String)                         │
│ Issue:    unwrap() can panic, crossing FFI boundary         │
│ Fix:      Use Result and convert to JavaScript error        │
└─────────────────────────────────────────────────────────────┘

📊 Summary:
   High:   2
   Medium: 2
   Low:    1

📄 Report: docs/security/FFI-AUDIT.md
```

---

## Examples

### Example 1: Audit All FFI

```bash
/rust-security:ffi-audit
```

### Example 2: PyO3 Only

```bash
/rust-security:ffi-audit --target=pyo3
```

### Example 3: Strict Mode with Fixes

```bash
/rust-security:ffi-audit --strict --fix
```

---

## Related Commands

- **[/rust-security:encrypt-setup](encrypt-setup.md)** - FFI encryption setup
- **[/rust-security:memory-audit](memory-audit.md)** - Memory safety audit
- **[/rust-security:zeroize-audit](zeroize-audit.md)** - Zeroisation audit
