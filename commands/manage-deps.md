# Manage Dependencies Command

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

**Command:** `/rust-security:manage-deps`

Manages Rust dependencies with security-first approach. Updates dependencies, optimizes feature flags, removes unused dependencies, analyzes bloat, and ensures minimal attack surface through dependency management.

**Agent:** `rust-dependency-manager` (Sonnet - Standard Analysis)

---

## When to Use

Use this command when:

- **Updating dependencies** - Safely update to latest versions
- **Optimizing binary size** - Remove unused dependencies and features
- **Security maintenance** - Update vulnerable dependencies
- **Reducing compile times** - Optimize dependency tree
- **Before releases** - Clean up dependency management
- **Feature flag optimization** - Enable only required features

---

## What It Does

1. **Analyzes dependency tree** for optimization opportunities
2. **Updates outdated dependencies** with compatibility checks
3. **Removes unused dependencies** through cargo-udeps
4. **Optimizes feature flags** to reduce binary size
5. **Detects duplicate dependencies** and suggests deduplication
6. **Analyzes compilation impact** of dependencies
7. **Generates dependency report** with security recommendations

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--action`         | string   | No       | `analyze`     | Action: `analyze`, `update`, `optimize`, `clean` |
| `--aggressive`     | boolean  | No       | `false`       | Enable aggressive optimization                   |
| `--security-only`  | boolean  | No       | `false`       | Update only security-critical dependencies       |
| `--output`         | string   | No       | `deps-report.md` | Output file path                              |

---

## Output

### Console Output

```
📦 Syntek Rust Security - Dependency Management

📊 Dependency Analysis:

Current state:
  - Total dependencies: 87
  - Direct dependencies: 23
  - Transitive dependencies: 64
  - Outdated: 12
  - Vulnerable: 2 (CRITICAL)

┌─────────────────────────────────────────────────────────────┐
│ Optimization Opportunities                                  │
├─────────────────────────────────────────────────────────────┤
│ Unused dependencies: 4                                      │
│ Duplicate dependencies: 6 versions of 3 crates              │
│ Oversized dependencies: 3 (alternatives available)          │
│ Unused features: 18 features across 8 crates                │
└─────────────────────────────────────────────────────────────┘

🔴 Security-Critical Updates:

1. tokio 1.28.0 → 1.35.1
   - CVE-2024-XXXX: Denial of service in runtime
   - Severity: HIGH
   - Action: UPDATE IMMEDIATELY

2. serde_json 1.0.95 → 1.0.111
   - RUSTSEC-2024-0001: Stack overflow in deep nesting
   - Severity: MEDIUM
   - Action: UPDATE RECOMMENDED

📊 Impact Analysis:

Removing unused dependencies:
  - Binary size: -2.3 MB (-12%)
  - Compile time: -8.4s (-15%)
  - Dependencies: 87 → 83 (-4)

Optimizing features:
  - Binary size: -1.8 MB (-9%)
  - Removed unused features: 18

Total improvement:
  - Binary size: -4.1 MB (-21%)
  - Compile time: -12.1s (-22%)

🔧 Recommended Actions:

1. Update vulnerable dependencies
   cargo update tokio serde_json

2. Remove unused dependencies
   - rand_core (not used)
   - lazy_static (replaced by once_cell)
   - chrono (only using time crate)

3. Optimize features
   [dependencies]
   tokio = { version = "1.35", features = ["rt-multi-thread", "macros"] }
   # Remove: "fs", "process", "signal" (unused)

4. Deduplicate dependencies
   Use cargo-tree to resolve version conflicts
```

---

## Examples

### Example 1: Analyze Dependencies

```bash
/rust-security:manage-deps --action=analyze
```

Analyzes dependency tree for optimization opportunities.

### Example 2: Update All Dependencies

```bash
/rust-security:manage-deps --action=update
```

Updates all outdated dependencies.

### Example 3: Security Updates Only

```bash
/rust-security:manage-deps --action=update --security-only=true
```

Updates only dependencies with security vulnerabilities.

### Example 4: Aggressive Optimization

```bash
/rust-security:manage-deps --action=optimize --aggressive=true
```

Aggressively optimizes dependencies and features.

### Example 5: Clean Unused Dependencies

```bash
/rust-security:manage-deps --action=clean
```

Removes unused dependencies from Cargo.toml.

---

## Best Practices

### Minimal Feature Flags

```toml
# Before optimization
[dependencies]
tokio = { version = "1.35", features = ["full"] }  # ❌ Includes everything

# After optimization
[dependencies]
tokio = { version = "1.35", features = ["rt-multi-thread", "macros"] }  # ✅ Only what's needed
```

### Dependency Deduplication

```bash
# Find duplicate dependencies
cargo tree --duplicates

# Example output:
# serde v1.0.195
# └── project
# serde v1.0.189
# └── old-dep v0.1.0
#     └── project

# Fix: Update old-dep or use patch
[patch.crates-io]
serde = "=1.0.195"
```

### Replacing Heavy Dependencies

```toml
# Before: Heavy dependency
[dependencies]
chrono = "0.4"  # 500KB, many features

# After: Lightweight alternative
[dependencies]
time = { version = "0.3", features = ["macros"] }  # 150KB
```

---

## Reference Documents

This command invokes the `rust-dependency-manager` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**

## Related Commands

- **[/rust-security:vuln-scan](vuln-scan.md)** - Scan for vulnerable dependencies
- **[/rust-security:supply-chain-audit](supply-chain-audit.md)** - Audit supply chain
- **[/rust-security:binary-check](binary-check.md)** - Verify binary size optimization

---

**Note:** Dependency updates should be tested thoroughly. Always run full test suite after updating dependencies.
