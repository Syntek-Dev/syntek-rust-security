# Review Code Command

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

**Command:** `/rust-security:review-code`

Performs comprehensive code review for Rust projects with security-first approach. Analyzes code for vulnerabilities, anti-patterns, performance issues, and adherence to Rust idioms. Provides detailed feedback with severity ratings and remediation suggestions.

**Agent:** `rust-review` (Opus - Expert Code Review)

---

## When to Use

Use this command when:

- **Before pull request merge** - Final code review before merging
- **Security-critical changes** - Review authentication, cryptography, or unsafe code
- **Pre-production deployment** - Final code quality check
- **After dependency updates** - Review integration with new dependencies
- **Refactoring validation** - Ensure refactoring maintains security
- **Learning and mentorship** - Get detailed feedback on code quality

---

## What It Does

1. **Analyzes code security** for vulnerabilities and attack vectors
2. **Reviews unsafe code** for memory safety and undefined behavior
3. **Checks Rust idioms** and best practices adherence
4. **Validates error handling** patterns and panic safety
5. **Reviews cryptographic code** for implementation flaws
6. **Analyzes performance** patterns and optimization opportunities
7. **Generates review report** with prioritized issues

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--scope`          | string   | No       | `changes`     | Scope: `changes`, `module`, `full`               |
| `--focus`          | string   | No       | `security`    | Focus: `security`, `performance`, `style`, `all` |
| `--severity`       | string   | No       | `all`         | Minimum severity: `low`, `medium`, `high`, `critical` |
| `--output`         | string   | No       | `code-review.md` | Output file path                              |
| `--format`         | string   | No       | `markdown`    | Format: `markdown`, `json`, `sarif`              |

---

## Output

### Console Output

```
🔍 Syntek Rust Security - Code Review

📦 Project: payment-processor v2.5.0
🎯 Review scope: Recent changes (127 lines)
🔐 Focus: Security

┌─────────────────────────────────────────────────────────────┐
│ Review Summary                                              │
├─────────────────────────────────────────────────────────────┤
│ 🔴 CRITICAL: 1 issue                                        │
│ 🟠 HIGH: 3 issues                                           │
│ 🟡 MEDIUM: 7 issues                                         │
│ 🟢 LOW: 12 issues                                           │
│ ℹ️  INFO: 8 suggestions                                     │
└─────────────────────────────────────────────────────────────┘

🔴 CRITICAL Issues:

1. src/payment/processor.rs:89-94
   Severity: CRITICAL
   Category: SQL Injection

   ```rust
   let query = format!("SELECT * FROM transactions WHERE user_id = {}", user_id);
   db.execute(&query).await?;
   ```

   Issue: Unsanitized user input in SQL query allows SQL injection
   Impact: Attacker can read/modify arbitrary database records

   Fix: Use parameterized queries
   ```rust
   let query = "SELECT * FROM transactions WHERE user_id = $1";
   db.execute(query, &[&user_id]).await?;
   ```

🟠 HIGH Severity Issues:

2. src/crypto/keys.rs:34-42
   Severity: HIGH
   Category: Weak Cryptography

   Issue: Using deprecated SHA-1 for signature verification
   Recommendation: Migrate to SHA-256 or SHA-3

3. src/auth/session.rs:67
   Severity: HIGH
   Category: Timing Attack

   ```rust
   if stored_token == provided_token { // Vulnerable to timing attacks
   ```

   Fix: Use constant-time comparison
   ```rust
   use ring::constant_time;
   if constant_time::verify_slices_are_equal(stored_token, provided_token).is_ok() {
   ```

📊 Code Quality Metrics:
   - Cyclomatic complexity: 4.2 (good)
   - Unsafe code: 2 blocks (needs review)
   - Test coverage: 87.3% (good)
   - Documentation: 94.1% (excellent)
   - Dependencies: 45 (5 outdated)

✅ Positive Observations:
   - Excellent error handling patterns
   - Good use of type system for safety
   - Comprehensive doc comments
   - Well-structured module organization

📝 Detailed report: code-review.md
```

---

## Examples

### Example 1: Review Recent Changes

```bash
/rust-security:review-code --scope=changes
```

Reviews git changes since last commit.

### Example 2: Security-Focused Review

```bash
/rust-security:review-code --focus=security --severity=high
```

Reviews security issues, showing only high and critical findings.

### Example 3: Full Project Review

```bash
/rust-security:review-code --scope=full --format=sarif
```

Reviews entire project, outputs SARIF for CI integration.

### Example 4: Module Review

```bash
/rust-security:review-code --scope=module --target=crypto
```

Reviews specific module (crypto).

### Example 5: Performance Review

```bash
/rust-security:review-code --focus=performance
```

Focuses on performance issues and optimization opportunities.

---

## Best Practices

### Security Review Checklist

**Input Validation**
- ✅ All user inputs validated
- ✅ SQL queries parameterized
- ✅ File paths sanitized
- ✅ Buffer sizes checked

**Cryptography**
- ✅ Using modern algorithms (AES-256-GCM, SHA-256, Ed25519)
- ✅ Cryptographically secure RNG
- ✅ Proper key management
- ✅ Constant-time operations

**Memory Safety**
- ✅ Minimal unsafe code
- ✅ No undefined behavior
- ✅ Proper bounds checking
- ✅ No memory leaks

**Error Handling**
- ✅ No unwrap() in production code
- ✅ Proper Result/Option usage
- ✅ Meaningful error messages
- ✅ No information leakage in errors

---

## Related Commands

- **[/rust-security:crypto-review](crypto-review.md)** - Detailed cryptography review
- **[/rust-security:memory-audit](memory-audit.md)** - Memory safety audit
- **[/rust-security:refactor-code](refactor-code.md)** - Apply refactoring suggestions

---

**Note:** This command uses Opus model for expert-level code review. Reviews focus on security but also cover general code quality, performance, and Rust best practices.
