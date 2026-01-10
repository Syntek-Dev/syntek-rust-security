# Memory Audit Command

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

**Command:** `/rust-security:memory-audit`

Performs comprehensive memory safety analysis, auditing unsafe code blocks, raw pointer usage, FFI boundaries, and potential undefined behavior to ensure memory safety guarantees are maintained.

**Agent:** `memory-auditor` (Sonnet - Standard Analysis)

---

## When to Use

Use this command when:

- **Writing unsafe code** - Before merging any code containing `unsafe` blocks
- **FFI implementations** - Interacting with C libraries or Python via PyO3
- **Performance optimizations** - Manual memory management for performance-critical code
- **Custom allocators** - Implementing global allocators or memory pools
- **No-std environments** - Embedded systems with manual memory management
- **Pre-release audits** - Comprehensive memory safety verification
- **After refactoring** - Ensure memory safety after significant changes

---

## What It Does

1. **Scans for unsafe code** - Identifies all `unsafe` blocks, functions, and traits
2. **Analyzes raw pointer usage** - Validates dereferencing, alignment, and lifetime correctness
3. **Reviews FFI boundaries** - Checks C interop, null pointer handling, and data layout
4. **Detects undefined behavior** - Data races, use-after-free, double-free patterns
5. **Validates invariants** - Ensures safety invariants are documented and upheld
6. **Checks aliasing rules** - Mutable reference exclusivity and aliasing violations
7. **Runs cargo-geiger** - Measures unsafe code usage across dependencies
8. **Generates safety report** - Detailed analysis with remediation recommendations

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--scope`          | string   | No       | `full`        | Analysis scope: `full`, `module`, `file`         |
| `--files`          | string[] | No       | All           | Specific files to audit                          |
| `--include-deps`   | boolean  | No       | `true`        | Analyze unsafe usage in dependencies             |
| `--strict`         | boolean  | No       | `false`       | Require safety documentation for all unsafe code |
| `--output`         | string   | No       | `docs/security/MEMORY-AUDIT.md` | Output path |
| `--format`         | string   | No       | `markdown`    | Output format: `markdown`, `json`, `html`        |
| `--geiger`         | boolean  | No       | `true`        | Run cargo-geiger analysis                        |

---

## Output

### Console Output

```
🔍 Syntek Rust Security - Memory Safety Audit

📦 Project: high-performance-parser v0.5.0
🔎 Analyzing memory safety...

┌─────────────────────────────────────────────────────────────┐
│ Unsafe Code Statistics                                     │
├─────────────────────────────────────────────────────────────┤
│ Unsafe blocks:        23                                    │
│ Unsafe functions:     8                                     │
│ Unsafe traits:        2                                     │
│ Raw pointer derefs:   45                                    │
│ FFI calls:            12                                    │
└─────────────────────────────────────────────────────────────┘

⚠️  CRITICAL ISSUES FOUND: 2

┌─────────────────────────────────────────────────────────────┐
│ CRITICAL: Potential Use-After-Free                         │
├─────────────────────────────────────────────────────────────┤
│ File: src/parser/buffer.rs:156                              │
│                                                             │
│ unsafe {                                                    │
│     let ptr = self.buffer.as_ptr().add(offset);             │
│     *ptr = value; // Potential UAF if buffer reallocated    │
│ }                                                           │
│                                                             │
│ Issue: Pointer may be invalidated if buffer is reallocated  │
│        before dereference.                                  │
│                                                             │
│ Fix: Hold mutable reference to buffer or use safe indexing. │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ CRITICAL: Unaligned Pointer Dereference                    │
├─────────────────────────────────────────────────────────────┤
│ File: src/ffi/interop.rs:89                                 │
│                                                             │
│ unsafe {                                                    │
│     let value = *(data_ptr as *const u64); // Alignment?    │
│ }                                                           │
│                                                             │
│ Issue: Casting to u64 pointer without alignment check       │
│        causes undefined behavior on ARM/RISC-V.             │
│                                                             │
│ Fix: Use read_unaligned() or verify alignment first.        │
└─────────────────────────────────────────────────────────────┘

🔧 cargo-geiger Results:
   Total unsafe lines: 234 (2.3% of codebase)
   Dependencies with unsafe: 8/45 (17.7%)

📊 Risk Summary:
   Critical: 2
   High: 5
   Medium: 11
   Low: 5

📄 Detailed report: docs/security/MEMORY-AUDIT.md
```

### Generated Report

Creates `docs/security/MEMORY-AUDIT.md` with:

- **Executive Summary** - Memory safety posture overview
- **Unsafe Code Inventory** - Complete list of unsafe blocks with justifications
- **Critical Issues** - Detailed analysis of memory safety violations
- **FFI Boundary Analysis** - C interop safety review
- **Pointer Usage Patterns** - Raw pointer dereferencing analysis
- **Undefined Behavior Risks** - Potential UB scenarios
- **Dependency Audit** - Unsafe usage in third-party crates
- **Remediation Guide** - Step-by-step fixes for identified issues
- **Best Practices** - Memory-safe alternatives and patterns

---

## Examples

### Example 1: Full Project Audit

```bash
/rust-security:memory-audit
```

Comprehensive memory safety audit of entire project with dependency analysis.

### Example 2: Specific Module Audit

```bash
/rust-security:memory-audit --scope=module --files=src/ffi,src/unsafe_ops
```

Audits only FFI and unsafe operation modules.

### Example 3: Strict Mode (Require Documentation)

```bash
/rust-security:memory-audit --strict
```

Enforces that all unsafe code has accompanying safety documentation.

### Example 4: Quick Local Audit (No Dependencies)

```bash
/rust-security:memory-audit --include-deps=false --geiger=false
```

Fast audit of project code only, skipping dependency analysis.

### Example 5: JSON Output for CI/CD

```bash
/rust-security:memory-audit --format=json --output=memory-audit.json
```

Generates machine-readable JSON for automated CI/CD processing.

---

## Best Practices

### Writing Safe Unsafe Code

#### ❌ Bad: Undocumented Unsafe

```rust
fn parse_header(data: &[u8]) -> u32 {
    unsafe {
        *(data.as_ptr() as *const u32)
    }
}
```

#### ✅ Good: Documented and Validated

```rust
/// Parses a 4-byte header from the data slice.
///
/// # Safety
///
/// The caller must ensure:
/// - `data.len() >= 4`
/// - `data` is properly aligned for u32
fn parse_header(data: &[u8]) -> u32 {
    assert!(data.len() >= 4, "Data too short for header");

    // SAFETY: We've verified length >= 4, and read_unaligned
    // handles any alignment issues.
    unsafe {
        data.as_ptr().cast::<u32>().read_unaligned()
    }
}
```

### Common Memory Safety Patterns

#### Pattern 1: Safe Pointer Dereferencing

```rust
use std::ptr;

// ❌ Bad: Unchecked dereference
unsafe fn bad_deref(ptr: *const u8) -> u8 {
    *ptr
}

// ✅ Good: Null check and bounds validation
unsafe fn safe_deref(ptr: *const u8, len: usize, index: usize) -> Option<u8> {
    if ptr.is_null() || index >= len {
        return None;
    }

    // SAFETY: We've verified pointer is non-null and index is in bounds
    Some(*ptr.add(index))
}
```

#### Pattern 2: FFI Boundary Safety

```rust
// ❌ Bad: Direct FFI without validation
extern "C" {
    fn external_function(data: *mut u8, len: usize);
}

pub fn call_external(data: &mut [u8]) {
    unsafe {
        external_function(data.as_mut_ptr(), data.len());
    }
}

// ✅ Good: Validated FFI with error handling
extern "C" {
    fn external_function(data: *mut u8, len: usize) -> i32;
}

pub fn call_external(data: &mut [u8]) -> Result<(), &'static str> {
    if data.is_empty() {
        return Err("Data cannot be empty");
    }

    // SAFETY:
    // - data.as_mut_ptr() is valid for data.len() bytes
    // - data lives for the duration of this call
    // - external_function documented to not store the pointer
    let result = unsafe {
        external_function(data.as_mut_ptr(), data.len())
    };

    if result == 0 {
        Ok(())
    } else {
        Err("External function failed")
    }
}
```

#### Pattern 3: Custom Smart Pointers

```rust
use std::ptr::NonNull;
use std::marker::PhantomData;

// ✅ Good: Type-safe smart pointer with proper Drop
pub struct Buffer<T> {
    ptr: NonNull<T>,
    capacity: usize,
    _marker: PhantomData<T>,
}

impl<T> Buffer<T> {
    pub fn new(capacity: usize) -> Self {
        let layout = std::alloc::Layout::array::<T>(capacity).unwrap();

        // SAFETY: Layout is valid, and we check for null
        let ptr = unsafe {
            let ptr = std::alloc::alloc(layout) as *mut T;
            NonNull::new(ptr).expect("Allocation failed")
        };

        Self {
            ptr,
            capacity,
            _marker: PhantomData,
        }
    }
}

impl<T> Drop for Buffer<T> {
    fn drop(&mut self) {
        let layout = std::alloc::Layout::array::<T>(self.capacity).unwrap();

        // SAFETY: ptr was allocated with this layout in new()
        unsafe {
            std::alloc::dealloc(self.ptr.as_ptr() as *mut u8, layout);
        }
    }
}
```

### Unsafe Code Documentation Template

```rust
/// Brief description of what the unsafe code does.
///
/// # Safety
///
/// The caller must ensure the following invariants:
/// - Invariant 1: Description and why it matters
/// - Invariant 2: Description and why it matters
///
/// # Undefined Behavior
///
/// This function causes undefined behavior if:
/// - Condition 1
/// - Condition 2
///
/// # Example
///
/// ```
/// // Safe usage example
/// ```
unsafe fn example_unsafe_function() {
    // SAFETY: Inline justification for each unsafe operation
    unsafe {
        // unsafe operation
    }
}
```

### Development Workflow

```bash
# 1. Implement feature with unsafe code
[Development work]

# 2. Run memory audit
/rust-security:memory-audit --scope=module --files=src/new_feature

# 3. Fix critical issues
[Address use-after-free, alignment issues, etc.]

# 4. Add safety documentation
[Document all unsafe invariants]

# 5. Re-audit with strict mode
/rust-security:memory-audit --strict --files=src/new_feature

# 6. Additional checks
/rust-security:minimize-unsafe --files=src/new_feature

# 7. Final review
/rust-security:rust-review
```

---

## Related Commands

- **[/rust-security:minimize-unsafe](minimize-unsafe.md)** - Reduce unsafe code usage
- **[/rust-security:fuzz-setup](fuzz-setup.md)** - Set up fuzzing to find memory bugs
- **[/rust-security:rust-review](review-code.md)** - Comprehensive code review
- **[/rust-security:threat-model](threat-model.md)** - Threat model memory safety issues

---

**Note:** This command requires `cargo-geiger`. Install with:
```bash
cargo install cargo-geiger
```
