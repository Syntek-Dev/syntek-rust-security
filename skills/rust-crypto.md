# Rust Cryptography Skills

This skill provides cryptographic implementation review and security analysis for Rust projects.

## /crypto-review

Review cryptographic implementations for timing attacks, side-channel vulnerabilities, and correct algorithm usage.

### Usage
```bash
/crypto-review [path]
```

Examples:
```bash
/crypto-review                    # Review entire project
/crypto-review src/crypto/        # Review specific directory
/crypto-review src/encrypt.rs     # Review specific file
```

### What It Does
1. Scans for cryptographic code patterns
2. Checks for constant-time operations
3. Verifies proper key zeroization
4. Analyzes randomness sources (CSPRNG vs non-cryptographic)
5. Reviews AEAD usage patterns
6. Checks for hardcoded secrets or keys
7. Validates cryptographic crate usage

### Detection Patterns

#### Timing Attacks
- Variable-time string comparisons
- Early returns in authentication
- Non-constant-time equality checks

#### Side-Channel Vulnerabilities
- Cache timing issues
- Branch prediction exploitation
- Memory access patterns

#### Implementation Errors
- Hardcoded keys or secrets
- IV/nonce reuse
- Weak key derivation
- Missing authentication tags
- Insecure randomness

### Output
- Security issues categorized by severity (Critical/High/Medium/Low)
- Vulnerable code locations with line numbers
- Detailed explanation of each issue
- Code fixes and recommendations
- Recommended crates for cryptographic operations

### Recommended Crates
- **ring**: Safe, fast, audited crypto
- **RustCrypto**: Pure Rust implementations
- **sodiumoxide**: libsodium bindings
- **orion**: Misuse-resistant crypto
- **zeroize**: Secure memory clearing
- **subtle**: Constant-time operations
- **argon2**: Password hashing

### Example Vulnerabilities Detected

#### Timing Attack
```rust
// ❌ VULNERABLE
if password == expected {
    return Ok(());
}

// ✅ SECURE
use subtle::ConstantTimeEq;
if password.ct_eq(&expected).into() {
    return Ok(());
}
```

#### Missing Zeroization
```rust
// ❌ VULNERABLE
let key = get_encryption_key();
encrypt_data(&key);
// key still in memory

// ✅ SECURE
use zeroize::Zeroize;
let mut key = get_encryption_key();
encrypt_data(&key);
key.zeroize();
```

#### Weak Randomness
```rust
// ❌ VULNERABLE
use rand::thread_rng;
let nonce = thread_rng().gen::<[u8; 12]>();

// ✅ SECURE
use rand::rngs::OsRng;
let nonce = OsRng.gen::<[u8; 12]>();
```

### Testing for Timing Vulnerabilities

The review includes recommendations for timing-safe testing:

```rust
#[test]
fn test_constant_time() {
    // Measure timing differences
    let iterations = 10_000;
    let time_correct = measure(|| compare(a, b_correct), iterations);
    let time_wrong = measure(|| compare(a, b_wrong), iterations);

    let diff = (time_correct as i64 - time_wrong as i64).abs();
    assert!(diff < threshold, "Timing leak detected");
}
```

### Report Format

```markdown
# Cryptographic Security Review

## Summary
- Files reviewed: X
- Critical issues: X
- High issues: X
- Medium issues: X
- Low issues: X

## Critical Issues

### Timing Attack in Password Verification
**File**: src/auth.rs:42
**Severity**: Critical
**Category**: Timing Attack

**Vulnerable Code**:
[code snippet]

**Issue**: [explanation]

**Fix**:
[corrected code]

**Impact**: [security impact]

## Recommendations
1. Immediate fixes required
2. Architectural improvements
3. Testing recommendations
4. Crate migrations
```

### Prerequisites
None - this skill uses code analysis patterns and doesn't require external tools.

### Best Practices
1. Run crypto review before production deployment
2. Review all cryptographic code changes
3. Use well-audited crates (ring, RustCrypto)
4. Never implement custom crypto primitives
5. Follow OWASP crypto guidelines
6. Test for timing vulnerabilities
7. Enable constant-time features in dependencies

### Integration Points

This skill works well with:
- `/vuln-scan` - Check for vulnerable crypto dependencies
- `/threat-model` - Include crypto threats in threat model
- `/memory-audit` - Verify key zeroization
