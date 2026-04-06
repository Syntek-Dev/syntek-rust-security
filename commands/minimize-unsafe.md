# Minimize Unsafe Command

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

**Command:** `/rust-security:minimize-unsafe`

Analyzes and minimizes unsafe code in Rust projects. Identifies unnecessary unsafe blocks, suggests safe alternatives, audits remaining unsafe code for undefined behavior, and documents safety invariants for required unsafe code.

**Agent:** `minimize-unsafe` (Opus - Deep Memory Safety Reasoning)

---

## When to Use

Use this command when:

- **Improving memory safety** - Reduce unsafe code surface area
- **Security hardening** - Eliminate potential undefined behavior
- **Before security audits** - Minimize unsafe code for review
- **After refactoring** - Check if unsafe code still necessary
- **FFI boundary review** - Audit foreign function interfaces
- **Pre-production deployment** - Final unsafe code verification

---

## What It Does

1. **Identifies all unsafe code** using cargo-geiger
2. **Analyzes necessity** of each unsafe block
3. **Suggests safe alternatives** where possible
4. **Audits undefined behavior** risks in remaining unsafe code
5. **Documents safety invariants** for required unsafe blocks
6. **Generates safety proofs** for complex unsafe operations
7. **Creates audit report** with recommendations

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--scope`          | string   | No       | `project`     | Scope: `project`, `module`, `function`           |
| `--target`         | string   | No       | All           | Specific file or module to analyze               |
| `--aggressive`     | boolean  | No       | `false`       | Enable aggressive unsafe elimination             |
| `--output`         | string   | No       | `unsafe-audit.md` | Output file path                             |

---

## Output

### Console Output

```
🛡️  Syntek Rust Security - Unsafe Code Minimization

📦 Project: crypto-lib v1.2.0
🔍 Unsafe code analysis

┌─────────────────────────────────────────────────────────────┐
│ Unsafe Code Inventory                                       │
├─────────────────────────────────────────────────────────────┤
│ Total unsafe blocks: 18                                     │
│ Can be eliminated: 12 (67%)                                 │
│ Required (FFI): 4 (22%)                                     │
│ Required (performance): 2 (11%)                             │
└─────────────────────────────────────────────────────────────┘

✅ Eliminable Unsafe Code:

1. src/crypto/aes.rs:42-47
   Category: Unnecessary unsafe

   Current (UNSAFE):
   ```rust
   unsafe {
       std::slice::from_raw_parts(ptr, len)
   }
   ```

   Safe Alternative:
   ```rust
   // Use safe slice operations
   &buffer[start..end]
   ```

   Justification: Bounds already checked by caller

2. src/utils/encoding.rs:89-92
   Category: Safe alternative available

   Current (UNSAFE):
   ```rust
   unsafe {
       String::from_utf8_unchecked(bytes)
   }
   ```

   Safe Alternative:
   ```rust
   String::from_utf8(bytes)
       .map_err(|e| Error::InvalidUtf8(e))?
   ```

   Justification: UTF-8 validation adds minimal overhead

⚠️  Required Unsafe Code (needs documentation):

3. src/ffi/bindings.rs:23-45
   Category: FFI boundary

   ```rust
   unsafe {
       libc::memcpy(dest, src, len)
   }
   ```

   Safety Invariants Required:
   - dest and src must be valid pointers
   - dest and src must not overlap
   - len must not exceed buffer sizes

   Recommendation: Add SAFETY comment documenting invariants

4. src/crypto/simd.rs:67-82
   Category: Performance-critical

   ```rust
   unsafe {
       _mm256_xor_si256(a, b)
   }
   ```

   Safety Invariants Required:
   - CPU must support AVX2
   - Pointers must be properly aligned

   Recommendation: Add runtime CPU feature detection

📊 Impact of Minimization:

Before:
  - Unsafe blocks: 18
  - Lines of unsafe code: 247
  - Unsafe surface area: HIGH

After:
  - Unsafe blocks: 6 (-67%)
  - Lines of unsafe code: 89 (-64%)
  - Unsafe surface area: LOW

🔐 Security Benefits:
  - Reduced undefined behavior risk: -67%
  - Improved audit surface: -64% code to review
  - Better memory safety guarantees

📝 Detailed audit: unsafe-audit.md
```

---

## Examples

### Example 1: Full Project Analysis

```bash
/rust-security:minimize-unsafe
```

Analyzes entire project for unsafe code minimization.

### Example 2: Aggressive Elimination

```bash
/rust-security:minimize-unsafe --aggressive=true
```

Aggressively eliminates unsafe code, even if minor performance cost.

### Example 3: Module-Specific Analysis

```bash
/rust-security:minimize-unsafe --scope=module --target=crypto
```

Analyzes only the crypto module.

### Example 4: FFI Boundary Audit

```bash
/rust-security:minimize-unsafe --target=src/ffi/
```

Focuses on FFI boundary safety.

---

## Best Practices

### Documenting Required Unsafe Code

```rust
/// Copies data from source to destination using platform-optimized memcpy.
///
/// # Safety
///
/// Callers must ensure:
/// 1. `src` points to a valid allocation of at least `len` bytes
/// 2. `dest` points to a valid allocation of at least `len` bytes
/// 3. `src` and `dest` do not overlap (use memmove for overlapping regions)
/// 4. Both pointers are properly aligned for their types
/// 5. The memory regions remain valid for the duration of the call
///
/// # Undefined Behavior
///
/// This function will cause undefined behavior if:
/// - Either pointer is null or dangling
/// - Either pointer is misaligned
/// - Either buffer is smaller than `len` bytes
/// - The buffers overlap (use memmove instead)
pub unsafe fn fast_copy(dest: *mut u8, src: *const u8, len: usize) {
    // SAFETY: Caller guarantees all safety invariants
    std::ptr::copy_nonoverlapping(src, dest, len);
}
```

### Safe Alternatives

```rust
// ❌ BEFORE: Unnecessary unsafe
unsafe {
    let s = std::str::from_utf8_unchecked(&bytes);
}

// ✅ AFTER: Safe with error handling
let s = std::str::from_utf8(&bytes)
    .map_err(|e| Error::InvalidUtf8(e))?;

// ❌ BEFORE: Unsafe pointer arithmetic
unsafe {
    let ptr = data.as_ptr().add(offset);
    *ptr
}

// ✅ AFTER: Safe indexing
data.get(offset)
    .copied()
    .ok_or(Error::OutOfBounds)?

// ❌ BEFORE: Unsafe uninitialized memory
let mut buffer = unsafe {
    let mut buf: [u8; 1024] = std::mem::uninitialized();
    buf
};

// ✅ AFTER: Safe initialization
let mut buffer = [0u8; 1024];
// or
let mut buffer = vec![0u8; 1024];
```

### FFI Safety Patterns

```rust
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Safe wrapper around C FFI function
pub fn safe_c_function(input: &str) -> Result<String, Error> {
    // Convert Rust string to C string safely
    let c_input = CString::new(input)
        .map_err(|_| Error::NullByte)?;

    // Call unsafe C function
    let result_ptr = unsafe {
        // SAFETY: c_input is a valid null-terminated C string
        c_function(c_input.as_ptr())
    };

    // Check for null pointer
    if result_ptr.is_null() {
        return Err(Error::NullPointer);
    }

    // Convert C string back to Rust safely
    let result = unsafe {
        // SAFETY: result_ptr is checked for null above
        CStr::from_ptr(result_ptr)
    }
    .to_str()
    .map_err(|_| Error::InvalidUtf8)?
    .to_owned();

    // Free C memory
    unsafe {
        // SAFETY: result_ptr was allocated by c_function
        libc::free(result_ptr as *mut _);
    }

    Ok(result)
}

extern "C" {
    fn c_function(input: *const c_char) -> *mut c_char;
}
```

---

## Reference Documents

This command invokes the `rust-unsafe-minimiser` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[DATA-STRUCTURES.md](.claude/DATA-STRUCTURES.md)**
- **[ENCRYPTION-GUIDE.md](.claude/ENCRYPTION-GUIDE.md)**

## Related Commands

- **[/rust-security:memory-audit](memory-audit.md)** - Comprehensive memory safety audit
- **[/rust-security:refactor-code](refactor-code.md)** - Refactor unsafe to safe code
- **[/rust-security:review-code](review-code.md)** - Review remaining unsafe code

---

**Note:** This command uses Opus model for deep reasoning about memory safety and undefined behavior. All unsafe code elimination should be thoroughly tested.
