# Fuzz Setup Command

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

**Command:** `/rust-security:fuzz-setup`

Sets up comprehensive fuzzing infrastructure for Rust projects using libFuzzer, AFL++, or honggfuzz. Automatically creates fuzz targets, configures corpus management, and establishes continuous fuzzing workflows to discover crashes, hangs, and edge cases.

**Agent:** `fuzzer` (Sonnet - Standard Analysis)

---

## When to Use

Use this command when:

- **Initializing fuzzing for the first time** - Set up infrastructure from scratch
- **Adding new fuzz targets** - Create fuzzing harnesses for specific functions
- **Testing parsers and deserializers** - Validate input handling robustness
- **Before production deployment** - Discover edge cases and crashes
- **After refactoring unsafe code** - Verify memory safety under fuzzing
- **Implementing custom protocols** - Test protocol state machines

---

## What It Does

1. **Analyzes project structure** to identify fuzzable functions and entry points
2. **Creates fuzz targets** in `fuzz/fuzz_targets/` directory
3. **Configures fuzzing engine** (libFuzzer, AFL++, or honggfuzz)
4. **Sets up corpus management** with seed inputs and minimization
5. **Generates CI/CD integration** for continuous fuzzing
6. **Creates fuzzing documentation** with usage instructions
7. **Configures sanitizers** (AddressSanitizer, MemorySanitizer, UndefinedBehaviorSanitizer)

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--engine`         | string   | No       | `libfuzzer`   | Fuzzing engine: `libfuzzer`, `afl`, `honggfuzz`  |
| `--targets`        | string[] | No       | Auto-detect   | Specific functions to fuzz                       |
| `--corpus-dir`     | string   | No       | `fuzz/corpus` | Corpus storage directory                         |
| `--sanitizer`      | string   | No       | `address`     | Sanitizer: `address`, `memory`, `undefined`, `thread` |
| `--max-len`        | number   | No       | 4096          | Maximum input length in bytes                    |
| `--ci-integration` | boolean  | No       | `true`        | Generate CI/CD fuzzing configuration             |

---

## Output

### Console Output

```
🔍 Syntek Rust Security - Fuzzing Infrastructure Setup

📦 Project: web-parser v0.5.0
🎯 Fuzzing Engine: libFuzzer (cargo-fuzz)
🧪 Sanitizer: AddressSanitizer

┌─────────────────────────────────────────────────────────────┐
│ Fuzz Targets Created                                        │
├─────────────────────────────────────────────────────────────┤
│ ✓ fuzz_parse_http_request                                   │
│ ✓ fuzz_parse_json_body                                      │
│ ✓ fuzz_url_decode                                           │
│ ✓ fuzz_header_parsing                                       │
│ ✓ fuzz_cookie_parsing                                       │
└─────────────────────────────────────────────────────────────┘

📊 Configuration:
   - Corpus directory: fuzz/corpus/
   - Max input length: 4096 bytes
   - Sanitizer: AddressSanitizer
   - CI integration: Enabled

📝 Files created:
   - fuzz/Cargo.toml
   - fuzz/fuzz_targets/*.rs (5 targets)
   - .github/workflows/fuzzing.yml
   - docs/fuzzing/FUZZING-GUIDE.md

🚀 Quick start:
   cargo fuzz run fuzz_parse_http_request
```

### Generated Files

Creates fuzzing infrastructure:

- **fuzz/Cargo.toml** - Fuzzing workspace configuration
- **fuzz/fuzz_targets/*.rs** - Individual fuzz target harnesses
- **fuzz/corpus/** - Seed corpus directory structure
- **.github/workflows/fuzzing.yml** - CI/CD fuzzing workflow
- **docs/fuzzing/FUZZING-GUIDE.md** - Fuzzing documentation

---

## Examples

### Example 1: Basic Setup with libFuzzer

```bash
/rust-security:fuzz-setup
```

Automatically detects fuzzable functions and sets up libFuzzer with default configuration.

### Example 2: AFL++ with Custom Targets

```bash
/rust-security:fuzz-setup --engine=afl --targets=parse_packet,decode_base64
```

Sets up AFL++ fuzzing for specific parsing functions.

### Example 3: Memory Sanitizer for Unsafe Code

```bash
/rust-security:fuzz-setup --sanitizer=memory --max-len=1024
```

Configures fuzzing with MemorySanitizer to detect uninitialized memory reads in unsafe blocks.

### Example 4: Honggfuzz for Multithreaded Code

```bash
/rust-security:fuzz-setup --engine=honggfuzz --sanitizer=thread
```

Sets up honggfuzz with ThreadSanitizer for concurrent fuzzing.

### Example 5: CI-Only Fuzzing Setup

```bash
/rust-security:fuzz-setup --ci-integration=true --corpus-dir=/tmp/fuzz-corpus
```

Creates fuzzing configuration optimized for CI/CD environments.

---

## Best Practices

### Before Running

1. **Identify fuzzable surfaces** - Focus on parsers, deserializers, and input validators
2. **Review dependencies** - Ensure fuzz-compatible dependencies (no I/O, deterministic)
3. **Create seed corpus** - Provide valid input samples for coverage-guided fuzzing
4. **Enable nightly toolchain** - Some fuzzing features require nightly Rust

### During Setup

1. **Start with small targets** - Fuzz individual functions before complex workflows
2. **Use multiple sanitizers** - Run separate fuzzing campaigns with different sanitizers
3. **Configure timeouts** - Set execution timeouts to detect hanging inputs
4. **Enable coverage tracking** - Monitor code coverage growth over time

### After Setup

1. **Run continuous fuzzing** - Integrate into CI/CD for ongoing testing
2. **Minimize corpus** - Regularly minimize corpus to reduce redundant inputs
3. **Analyze crashes** - Reproduce and debug all discovered crashes
4. **Update seed corpus** - Add interesting inputs discovered during fuzzing

### Integration with Development Workflow

```bash
# 1. Set up fuzzing infrastructure
/rust-security:fuzz-setup --engine=libfuzzer

# 2. Run initial fuzzing campaign
cargo fuzz run fuzz_target -- -max_total_time=3600

# 3. Analyze crashes
cargo fuzz cmin fuzz_target  # Minimize corpus
ls fuzz/artifacts/fuzz_target/  # Check for crashes

# 4. Fix issues and verify
/rust-security:memory-audit
cargo fuzz run fuzz_target -- -runs=1000000

# 5. Integrate into CI
git add fuzz/ .github/workflows/fuzzing.yml
git commit -m "Add fuzzing infrastructure"
```

### Fuzzing Strategies

**Coverage-Guided Fuzzing (libFuzzer)**
- Best for general-purpose fuzzing
- Automatic input mutation based on coverage feedback
- Fast iteration with in-process fuzzing

**Mutation-Based Fuzzing (AFL++)**
- Best for complex input formats
- Hardware-assisted instrumentation
- Parallel fuzzing support

**Evolutionary Fuzzing (honggfuzz)**
- Best for multithreaded code
- Feedback-driven generation
- Real-time coverage tracking

---

## Related Commands

- **[/rust-security:memory-audit](memory-audit.md)** - Audit unsafe code before fuzzing
- **[/rust-security:write-tests](write-tests.md)** - Generate unit tests from fuzzing crashes
- **[/rust-security:benchmark](benchmark.md)** - Performance testing after fuzzing optimizations
- **[/rust-security:review-code](review-code.md)** - Review code changes from fuzzing fixes
- **[/rust-security:supply-chain-audit](supply-chain-audit.md)** - Verify fuzz dependencies

---

**Note:** Fuzzing requires nightly Rust toolchain. Install with `rustup install nightly` and cargo-fuzz with `cargo install cargo-fuzz`.
