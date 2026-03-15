# Binary Check Command

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

**Command:** `/rust-security:binary-check`

Analyzes compiled Rust binaries for security hardening features, anti-exploitation mechanisms, and binary security best practices. Verifies ASLR, DEP/NX, stack canaries, RELRO, PIE, and other runtime protections are properly enabled.

**Agent:** `binary-analyser` (Sonnet - Standard Analysis)

---

## When to Use

Use this command when:

- **Before production deployment** - Verify binary hardening is enabled
- **After compilation configuration changes** - Validate security flags
- **Security compliance requirements** - Document binary protection mechanisms
- **Investigating security incidents** - Analyze binary for exploitation mitigations
- **Cross-platform builds** - Verify hardening on different targets
- **Release preparation** - Final security check before distribution

---

## What It Does

1. **Analyzes ELF/PE/Mach-O headers** for security attributes
2. **Verifies ASLR (Address Space Layout Randomization)** is enabled
3. **Checks DEP/NX (Data Execution Prevention)** protection
4. **Validates stack canaries** for buffer overflow protection
5. **Inspects RELRO (Relocation Read-Only)** configuration
6. **Verifies PIE (Position Independent Executable)** compilation
7. **Analyzes symbol table** for sensitive information leakage
8. **Checks for debug symbols** in release builds

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--binary`         | string   | No       | `target/release/` | Binary file or directory to analyze          |
| `--output`         | string   | No       | `docs/security/BINARY-ANALYSIS.md` | Output file path |
| `--format`         | string   | No       | `markdown`    | Output format: `markdown`, `json`, `sarif`       |
| `--platform`       | string   | No       | Auto-detect   | Target platform: `linux`, `windows`, `macos`     |
| `--strict`         | boolean  | No       | `false`       | Fail on any missing hardening feature            |
| `--check-symbols`  | boolean  | No       | `true`        | Analyze symbol table for leaks                   |

---

## Output

### Console Output

```
🛡️  Syntek Rust Security - Binary Security Analysis

📦 Binary: target/release/secure-app
🏗️  Platform: Linux x86_64
📏 Binary size: 8.4 MB
🔍 Analysis mode: Standard

┌─────────────────────────────────────────────────────────────┐
│ Security Hardening Status                                   │
├─────────────────────────────────────────────────────────────┤
│ ✅ PIE (Position Independent Executable): ENABLED           │
│ ✅ Stack Canaries: ENABLED                                  │
│ ✅ NX (Non-Executable Stack): ENABLED                       │
│ ✅ RELRO (Relocation Read-Only): Full RELRO                 │
│ ✅ ASLR (Address Space Layout Randomization): ENABLED       │
│ ✅ FORTIFY_SOURCE: Level 2                                  │
│ ⚠️  Symbol Table: NOT STRIPPED (potential information leak) │
│ ❌ Debug Symbols: PRESENT (should be removed for release)   │
└─────────────────────────────────────────────────────────────┘

🔐 Runtime Protections:
   - Control Flow Integrity: Enabled (via LLVM CFI)
   - Shadow Stack: Enabled (CET on supported CPUs)
   - Memory Tagging: Enabled (MTE on ARM64)

⚠️  Recommendations:

1. Strip debug symbols for release builds
   → cargo build --release
   → strip target/release/secure-app

2. Strip symbol table to reduce information leakage
   → Add to Cargo.toml:
     [profile.release]
     strip = true

📝 Detailed report: docs/security/BINARY-ANALYSIS.md
```

### Generated Documentation

Creates `docs/security/BINARY-ANALYSIS.md` with:

- **Executive Summary** - Binary security posture overview
- **Hardening Features** - Detailed analysis of each protection mechanism
- **Platform-Specific Protections** - OS and architecture-specific features
- **Symbol Table Analysis** - Exported symbols and potential leaks
- **Comparison Matrix** - Binary security across different builds
- **Remediation Steps** - Configuration changes to improve hardening
- **Compliance Checklist** - Security standards verification

---

## Examples

### Example 1: Analyze Release Binary

```bash
/rust-security:binary-check
```

Analyzes default release binary in `target/release/` directory.

### Example 2: Analyze Specific Binary

```bash
/rust-security:binary-check --binary=target/x86_64-unknown-linux-musl/release/app
```

Analyzes cross-compiled musl binary.

### Example 3: Strict Mode for CI/CD

```bash
/rust-security:binary-check --strict=true --format=json
```

Fails build if any hardening feature is missing, outputs JSON for CI integration.

### Example 4: Symbol Table Analysis

```bash
/rust-security:binary-check --check-symbols=true --output=symbols-audit.md
```

Performs detailed symbol table analysis for information leakage.

### Example 5: Multi-Platform Analysis

```bash
/rust-security:binary-check --binary=dist/ --platform=linux
/rust-security:binary-check --binary=dist/ --platform=windows
/rust-security:binary-check --binary=dist/ --platform=macos
```

Analyzes binaries for all supported platforms.

---

## Best Practices

### Before Running

1. **Compile in release mode** - `cargo build --release`
2. **Enable LTO (Link-Time Optimization)** - Improves security and performance
3. **Configure rustc flags** - Set appropriate security flags
4. **Strip debug symbols** - Remove debugging information from production builds

### Recommended Cargo.toml Configuration

```toml
[profile.release]
# Enable link-time optimization
lto = true

# Remove debug symbols
strip = true

# Enable overflow checks even in release mode
overflow-checks = true

# Enable CFI (Control Flow Integrity)
# Requires nightly: RUSTFLAGS="-Zsanitizer=cfi"
# cfi = true

# Optimize for size (optional, reduces attack surface)
# opt-level = "z"

# Panic = abort (smaller binary, no unwinding)
panic = "abort"

[profile.release.package."*"]
# Enable overflow checks for all dependencies
overflow-checks = true
```

### RUSTFLAGS Environment Variables

```bash
# Linux: Enable all hardening features
export RUSTFLAGS="-C relocation-model=pic -C link-arg=-pie -C link-arg=-Wl,-z,relro,-z,now"

# Enable stack canaries (default on most platforms)
export RUSTFLAGS="$RUSTFLAGS -C stack-protector=all"

# Enable CFI (nightly only)
export RUSTFLAGS="$RUSTFLAGS -Zsanitizer=cfi -Clto"

# Compile with hardening
cargo build --release
```

### Platform-Specific Hardening

**Linux (ELF)**
```bash
# Verify hardening with checksec
checksec --file=target/release/app

# Expected output:
# RELRO: Full RELRO
# Stack: Canary found
# NX: NX enabled
# PIE: PIE enabled
# FORTIFY: Enabled
```

**Windows (PE)**
```powershell
# Verify DEP and ASLR
Get-ProcessMitigation -Name app.exe

# Enable CFG (Control Flow Guard)
$env:RUSTFLAGS="-C link-args=/GUARD:CF"
cargo build --release
```

**macOS (Mach-O)**
```bash
# Verify hardening with otool
otool -hv target/release/app | grep PIE

# Check for stack canaries
otool -I target/release/app | grep stack_chk
```

### Integration with Build Pipeline

```bash
# 1. Configure hardening in Cargo.toml
cat >> Cargo.toml << 'EOF'
[profile.release]
lto = true
strip = true
overflow-checks = true
panic = "abort"
EOF

# 2. Set RUSTFLAGS for maximum hardening
export RUSTFLAGS="-C relocation-model=pic -C link-arg=-pie -C link-arg=-Wl,-z,relro,-z,now -C stack-protector=all"

# 3. Build release binary
cargo build --release

# 4. Verify hardening
/rust-security:binary-check --strict=true

# 5. If passed, proceed with deployment
if [ $? -eq 0 ]; then
  echo "Binary hardening verified ✅"
  # Deploy binary
else
  echo "Binary hardening failed ❌"
  exit 1
fi
```

### Common Issues and Fixes

**Missing PIE**
```toml
# Add to .cargo/config.toml
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "relocation-model=pic", "-C", "link-arg=-pie"]
```

**Partial RELRO**
```toml
# Add to .cargo/config.toml
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "link-arg=-Wl,-z,relro,-z,now"]
```

**Debug Symbols in Release**
```toml
# Add to Cargo.toml
[profile.release]
strip = true  # Automatically strip symbols
```

**Large Binary Size**
```toml
# Reduce binary size while maintaining security
[profile.release]
opt-level = "z"  # Optimize for size
lto = true
codegen-units = 1
strip = true
```

---

## Reference Documents

This command invokes the `binary-analyser` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[ARCHITECTURE-PATTERNS.md](.claude/ARCHITECTURE-PATTERNS.md)**

## Related Commands

- **[/rust-security:memory-audit](memory-audit.md)** - Audit unsafe code before binary analysis
- **[/rust-security:compliance-report](compliance-report.md)** - Generate compliance reports
- **[/rust-security:review-code](review-code.md)** - Code review before compilation
- **[/rust-security:benchmark](benchmark.md)** - Performance testing after hardening

---

**Note:** Binary hardening analysis requires platform-specific tools (checksec, otool, dumpbin). Some features may require nightly Rust or specific LLVM versions.
