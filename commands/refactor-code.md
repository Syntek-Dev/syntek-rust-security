# Refactor Code Command

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

**Command:** `/rust-security:refactor-code`

Performs intelligent code refactoring for Rust projects with focus on improving security, ownership patterns, error handling, and code maintainability. Handles complex Rust-specific transformations including borrow checker optimizations and unsafe code elimination.

**Agent:** `rust-refactor` (Opus - Complex Ownership Transformations)

---

## When to Use

Use this command when:

- **Improving code quality** - Refactor for better readability and maintainability
- **Eliminating unsafe code** - Convert unsafe blocks to safe alternatives
- **Optimizing ownership** - Improve borrow checker interactions
- **Error handling improvements** - Convert unwrap() to proper error handling
- **Security hardening** - Refactor code to eliminate security vulnerabilities
- **Before major releases** - Clean up technical debt

---

## What It Does

1. **Analyzes code structure** to identify refactoring opportunities
2. **Improves ownership patterns** to reduce clones and lifetime issues
3. **Eliminates unsafe code** where safe alternatives exist
4. **Enhances error handling** replacing panics with Result types
5. **Optimizes performance** through zero-cost abstractions
6. **Improves type safety** using newtype patterns and type aliases
7. **Validates refactoring** ensuring no behavioral changes

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--scope`          | string   | No       | `project`     | Scope: `project`, `module`, `function`           |
| `--target`         | string   | No       | All           | Specific module or file to refactor              |
| `--focus`          | string   | No       | `all`         | Focus: `unsafe`, `errors`, `ownership`, `all`    |
| `--aggressive`     | boolean  | No       | `false`       | Enable aggressive refactoring                    |
| `--preserve-api`   | boolean  | No       | `true`        | Preserve public API compatibility                |
| `--dry-run`        | boolean  | No       | `false`       | Preview changes without applying                 |

---

## Output

### Console Output

```
🔧 Syntek Rust Security - Code Refactoring

📦 Project: crypto-lib v1.2.0
🎯 Focus: Unsafe code elimination
🔍 Scope: Full project

┌─────────────────────────────────────────────────────────────┐
│ Refactoring Opportunities                                   │
├─────────────────────────────────────────────────────────────┤
│ Unsafe blocks: 12 (8 can be eliminated)                     │
│ Unwrap calls: 34 (all can be converted to Result)           │
│ Clone usage: 67 (23 unnecessary)                            │
│ Lifetime issues: 5 (all resolvable)                         │
│ Type safety improvements: 15 opportunities                  │
└─────────────────────────────────────────────────────────────┘

✅ Refactorings Applied:

1. src/crypto/aes.rs:42-58
   - Eliminated unsafe block using safe slice operations
   - Before: unsafe { std::slice::from_raw_parts(...) }
   - After: Safe slice indexing with bounds checks

2. src/utils/encoding.rs:23
   - Replaced unwrap() with proper error handling
   - Before: data.parse().unwrap()
   - After: data.parse().map_err(|e| Error::ParseError(e))?

3. src/auth/session.rs:89-102
   - Removed unnecessary clones
   - Reduced heap allocations by 34%
   - Improved borrow checker usage

4. src/crypto/hmac.rs:15-30
   - Enhanced type safety with newtype pattern
   - Before: fn verify(key: &[u8], msg: &[u8]) -> bool
   - After: fn verify(key: &HmacKey, msg: &Message) -> Result<bool>

📊 Impact Analysis:
   - Binary size: -2.3% (improved)
   - Compile time: +1.2% (minor increase)
   - Runtime performance: +0.8% (improved)
   - Unsafe code: -66.7% (8 blocks eliminated)
   - Test coverage: Same (100% tests passing)

🔍 Verification:
   ✅ All tests passing (342/342)
   ✅ No clippy warnings
   ✅ Public API unchanged
   ✅ Documentation updated
```

---

## Examples

### Example 1: Eliminate Unsafe Code

```bash
/rust-security:refactor-code --focus=unsafe
```

Refactors to eliminate unnecessary unsafe blocks.

### Example 2: Improve Error Handling

```bash
/rust-security:refactor-code --focus=errors --target=src/parser/
```

Converts unwrap/expect calls to proper Result handling in parser module.

### Example 3: Optimize Ownership

```bash
/rust-security:refactor-code --focus=ownership --aggressive=true
```

Aggressively optimizes ownership patterns to reduce clones.

### Example 4: Module-Specific Refactoring

```bash
/rust-security:refactor-code --scope=module --target=crypto
```

Refactors only the crypto module.

### Example 5: Preview Changes

```bash
/rust-security:refactor-code --dry-run=true
```

Previews refactoring suggestions without applying changes.

---

## Best Practices

### Before Refactoring

```rust
// BEFORE: Unsafe code with potential UB
pub fn decode_string(bytes: &[u8]) -> String {
    unsafe {
        String::from_utf8_unchecked(bytes.to_vec())
    }
}

// BEFORE: Unwrap that can panic
pub fn parse_config(s: &str) -> Config {
    serde_json::from_str(s).unwrap()
}

// BEFORE: Unnecessary clones
pub fn process_data(data: Vec<u8>) -> Vec<u8> {
    let backup = data.clone(); // Unnecessary
    transform(data)
}
```

### After Refactoring

```rust
// AFTER: Safe UTF-8 validation
pub fn decode_string(bytes: &[u8]) -> Result<String, DecodeError> {
    String::from_utf8(bytes.to_vec())
        .map_err(|e| DecodeError::InvalidUtf8(e))
}

// AFTER: Proper error handling
pub fn parse_config(s: &str) -> Result<Config, ConfigError> {
    serde_json::from_str(s)
        .map_err(|e| ConfigError::ParseError(e))
}

// AFTER: Ownership optimization
pub fn process_data(data: Vec<u8>) -> Vec<u8> {
    transform(data) // Consume data directly
}
```

### Newtype Pattern for Type Safety

```rust
// BEFORE: Prone to mixing up parameters
fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> { }

// AFTER: Type-safe with newtypes
#[derive(Clone)]
pub struct EncryptionKey([u8; 32]);

#[derive(Clone)]
pub struct Nonce([u8; 12]);

pub struct Plaintext(Vec<u8>);
pub struct Ciphertext(Vec<u8>);

fn encrypt(key: &EncryptionKey, nonce: &Nonce, plaintext: Plaintext) -> Ciphertext {
    // Compiler prevents parameter confusion
}
```

---

## Related Commands

- **[/rust-security:minimize-unsafe](minimize-unsafe.md)** - Focused unsafe code reduction
- **[/rust-security:review-code](review-code.md)** - Code review after refactoring
- **[/rust-security:write-tests](write-tests.md)** - Generate tests for refactored code

---

**Note:** This command uses Opus model for complex ownership and borrowing transformations. Always run full test suite after refactoring to verify correctness.
