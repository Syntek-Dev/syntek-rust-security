# Benchmark Command

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

**Command:** `/rust-security:benchmark`

Creates and runs performance benchmarks for Rust projects using criterion.rs. Generates statistical analysis of performance characteristics, identifies regressions, and provides optimization recommendations with security-aware performance testing.

**Agent:** `rust-benchmarker` (Sonnet - Standard Analysis)

---

## When to Use

Use this command when:

- **Optimizing performance** - Measure before and after optimization
- **Preventing regressions** - Detect performance degradation in CI
- **Comparing algorithms** - Choose fastest implementation
- **Cryptographic operations** - Ensure constant-time execution
- **Before releases** - Validate performance requirements
- **Hardware optimization** - Test SIMD and platform-specific code

---

## What It Does

1. **Generates benchmark suite** using criterion.rs framework
2. **Runs performance tests** with statistical analysis
3. **Detects performance regressions** comparing against baselines
4. **Analyzes constant-time execution** for security-critical functions
5. **Identifies optimization opportunities** through profiling
6. **Generates performance reports** with charts and statistics
7. **Tests across different input sizes** for scalability analysis

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--target`         | string   | No       | All           | Specific function or module to benchmark         |
| `--output-dir`     | string   | No       | `target/criterion/` | Benchmark output directory                 |
| `--baseline`       | string   | No       | None          | Baseline name for comparison                     |
| `--security-check` | boolean  | No       | `true`        | Check constant-time execution for crypto         |
| `--sample-size`    | number   | No       | 100           | Number of samples per benchmark                  |

---

## Output

### Console Output

```
⚡ Syntek Rust Security - Performance Benchmarking

📦 Project: crypto-lib v1.5.0
🎯 Target: Cryptographic functions
📊 Sample size: 100 iterations

┌─────────────────────────────────────────────────────────────┐
│ Benchmark Results                                           │
├─────────────────────────────────────────────────────────────┤
│ aes_256_gcm_encrypt        842.3 ns   ±12.4 ns              │
│ aes_256_gcm_decrypt        856.1 ns   ±15.2 ns              │
│ sha256_hash                124.7 ns   ±2.1 ns               │
│ hmac_sha256_verify         145.3 ns   ±3.4 ns               │
│ ed25519_sign               18.4 μs    ±0.8 μs               │
│ ed25519_verify             52.7 μs    ±1.2 μs               │
└─────────────────────────────────────────────────────────────┘

🔐 Constant-Time Analysis:

✅ hmac_sha256_verify
   - Timing variance: 2.3% (acceptable)
   - Constant-time verified

⚠️  password_compare
   - Timing variance: 15.7% (HIGH)
   - SECURITY RISK: Potential timing attack
   - Recommendation: Use constant-time comparison

📈 Performance Comparison (vs baseline):

  aes_256_gcm_encrypt:  842.3 ns  (↓ 5.2% faster)
  sha256_hash:          124.7 ns  (→ no change)
  ed25519_verify:       52.7 μs   (↑ 2.1% slower) ⚠️

⚡ Optimization Opportunities:

1. ed25519_verify regression detected
   - Previous: 51.6 μs
   - Current: 52.7 μs (+2.1%)
   - Investigate recent changes in signature verification

2. Consider SIMD optimization for SHA-256
   - Current: 124.7 ns
   - Potential: ~80 ns (35% improvement)

📝 Detailed report: target/criterion/report/index.html
```

---

## Examples

### Example 1: Benchmark All Functions

```bash
/rust-security:benchmark
```

Runs benchmarks for entire project.

### Example 2: Benchmark Specific Module

```bash
/rust-security:benchmark --target=crypto::aes
```

Benchmarks only AES encryption functions.

### Example 3: Regression Detection

```bash
/rust-security:benchmark --baseline=v1.4.0
```

Compares current performance against v1.4.0 baseline.

### Example 4: Security-Focused Benchmarking

```bash
/rust-security:benchmark --security-check=true --target=crypto
```

Benchmarks crypto functions with constant-time verification.

### Example 5: High-Precision Benchmarking

```bash
/rust-security:benchmark --sample-size=1000 --target=critical_path
```

Runs high-precision benchmarks with 1000 samples.

---

## Best Practices

### Benchmark Example

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

fn benchmark_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_256_gcm");

    // Test different input sizes
    for size in [64, 256, 1024, 4096, 16384].iter() {
        let plaintext = vec![0u8; *size];
        let key = [0u8; 32];
        let nonce = [0u8; 12];

        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            |b, &_size| {
                b.iter(|| {
                    encrypt(
                        black_box(&plaintext),
                        black_box(&key),
                        black_box(&nonce)
                    )
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, benchmark_encryption);
criterion_main!(benches);
```

### Constant-Time Benchmark

```rust
fn benchmark_constant_time_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("constant_time");

    let valid_hmac = [0x12, 0x34, 0x56, 0x78];
    let mut invalid_hmac = valid_hmac.clone();
    invalid_hmac[0] = 0xFF;

    // Both comparisons should take the same time
    group.bench_function("compare_valid", |b| {
        b.iter(|| constant_time_compare(black_box(&valid_hmac), black_box(&valid_hmac)))
    });

    group.bench_function("compare_invalid", |b| {
        b.iter(|| constant_time_compare(black_box(&valid_hmac), black_box(&invalid_hmac)))
    });

    group.finish();
}
```

---

## Reference Documents

This command invokes the `rust-benchmarker` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[PERFORMANCE.md](.claude/PERFORMANCE.md)**
- **[DATA-STRUCTURES.md](.claude/DATA-STRUCTURES.md)**

## Related Commands

- **[/rust-security:review-code](review-code.md)** - Review performance-critical code
- **[/rust-security:write-tests](write-tests.md)** - Generate performance tests
- **[/rust-security:refactor-code](refactor-code.md)** - Optimize based on benchmarks

---

**Note:** Benchmarks should be run on dedicated hardware in a quiet environment for consistent results. Use `cargo bench` to run generated benchmarks.
