# Generate Docs Command

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

**Command:** `/rust-security:generate-docs`

Generates comprehensive Rust documentation using rustdoc, including API docs, security guides, architecture diagrams, and example code. Creates doc tests, validates documentation coverage, and publishes to docs.rs or custom hosting.

**Agent:** `generate-docs` (Sonnet - Standard Analysis)

---

## When to Use

Use this command when:

- **Preparing for release** - Generate complete API documentation
- **Onboarding new developers** - Create comprehensive guides
- **Publishing to crates.io** - Prepare docs.rs documentation
- **Security documentation** - Document security features and best practices
- **After API changes** - Update documentation to reflect new APIs
- **Writing tutorials** - Create code examples and guides

---

## What It Does

1. **Generates rustdoc documentation** for all public APIs
2. **Creates doc tests** from code examples in documentation
3. **Validates documentation coverage** for all public items
4. **Generates security guides** from threat models and audits
5. **Creates architecture diagrams** using code structure analysis
6. **Builds example code** and validates compilation
7. **Publishes documentation** to docs.rs or custom hosting

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--output-dir`     | string   | No       | `target/doc/` | Documentation output directory                   |
| `--scope`          | string   | No       | `all`         | Scope: `api`, `guides`, `examples`, `all`        |
| `--features`       | string[] | No       | Default       | Features to enable during doc generation         |
| `--coverage`       | boolean  | No       | `true`        | Check documentation coverage                     |
| `--doc-tests`      | boolean  | No       | `true`        | Run doc tests                                    |
| `--open`           | boolean  | No       | `false`       | Open docs in browser after generation            |

---

## Output

### Console Output

```
📚 Syntek Rust Security - Documentation Generation

📦 Project: secure-api v1.5.0
🎯 Scope: All documentation
✅ Features: default, tls, jwt

┌─────────────────────────────────────────────────────────────┐
│ Documentation Coverage                                      │
├─────────────────────────────────────────────────────────────┤
│ Public items: 247                                           │
│ Documented: 243 (98.4%)                                     │
│ Missing docs: 4                                             │
│ Doc tests: 156                                              │
│ Test results: 156 passed, 0 failed                          │
└─────────────────────────────────────────────────────────────┘

📝 Generated documentation:

API Documentation:
  - target/doc/secure_api/index.html
  - 247 documented items
  - 156 code examples

Security Guides:
  - docs/guides/SECURITY.md
  - docs/guides/CRYPTOGRAPHY.md
  - docs/guides/THREAT-MODEL.md
  - docs/guides/AUTHENTICATION.md

Architecture:
  - docs/architecture/DESIGN.md
  - docs/architecture/modules.svg

Examples:
  - examples/basic_usage.rs (✓ compiles)
  - examples/tls_setup.rs (✓ compiles)
  - examples/jwt_auth.rs (✓ compiles)

⚠️  Missing documentation:
  - src/internal/helper.rs:42: fn process_data
  - src/utils/mod.rs:18: pub struct Config
  - src/crypto/mod.rs:89: fn derive_key_internal
  - src/auth/session.rs:123: pub enum SessionState

🌐 Documentation published to: https://docs.rs/secure-api/1.5.0
```

### Generated Files

Creates comprehensive documentation:

- **target/doc/** - HTML API documentation
- **docs/guides/** - Security and usage guides
- **docs/architecture/** - Architecture documentation
- **examples/** - Compilable example code
- **README.md** - Updated with latest API examples

---

## Examples

### Example 1: Full Documentation Generation

```bash
/rust-security:generate-docs
```

Generates complete documentation including API docs, guides, and examples.

### Example 2: API Documentation Only

```bash
/rust-security:generate-docs --scope=api --open=true
```

Generates only API documentation and opens in browser.

### Example 3: Documentation with All Features

```bash
/rust-security:generate-docs --features=tls,jwt,redis --coverage=true
```

Generates docs with specific features enabled and checks coverage.

### Example 4: Security Guides Only

```bash
/rust-security:generate-docs --scope=guides
```

Generates only security guides and architectural documentation.

### Example 5: Pre-Release Documentation Check

```bash
/rust-security:generate-docs --doc-tests=true --coverage=true
```

Validates documentation coverage and runs all doc tests before release.

---

## Best Practices

### Writing Effective Rustdoc

```rust
/// Validates and verifies HMAC-SHA256 signatures for request authentication.
///
/// This function provides constant-time comparison to prevent timing attacks
/// and follows OWASP guidelines for secure HMAC validation.
///
/// # Arguments
///
/// * `message` - The message to verify
/// * `signature` - The HMAC signature to validate
/// * `key` - The secret key for HMAC verification
///
/// # Returns
///
/// Returns `Ok(true)` if signature is valid, `Ok(false)` if invalid,
/// or `Err` if verification fails due to cryptographic errors.
///
/// # Security Considerations
///
/// - Uses constant-time comparison via `ring::constant_time::verify_slices_are_equal`
/// - Keys should be at least 256 bits (32 bytes)
/// - Signatures are not malleable
/// - Resistant to timing attacks
///
/// # Examples
///
/// ```
/// use secure_api::crypto::verify_hmac;
///
/// let message = b"Hello, world!";
/// let key = b"super-secret-key-min-32-bytes!!";
/// let signature = b"..."; // Pre-computed HMAC
///
/// match verify_hmac(message, signature, key) {
///     Ok(true) => println!("Valid signature"),
///     Ok(false) => println!("Invalid signature"),
///     Err(e) => eprintln!("Verification error: {}", e),
/// }
/// ```
///
/// # See Also
///
/// - [`compute_hmac`] for HMAC generation
/// - [`KeyDerivation`] for secure key derivation
pub fn verify_hmac(
    message: &[u8],
    signature: &[u8],
    key: &[u8],
) -> Result<bool, CryptoError> {
    // Implementation
}
```

### Documentation Structure

```
project/
├── src/
│   └── lib.rs          // Module-level docs
├── docs/
│   ├── guides/
│   │   ├── SECURITY.md
│   │   ├── GETTING-STARTED.md
│   │   └── BEST-PRACTICES.md
│   ├── architecture/
│   │   ├── DESIGN.md
│   │   └── MODULES.md
│   └── tutorials/
│       └── TUTORIAL-01.md
├── examples/
│   ├── basic_usage.rs
│   └── advanced_features.rs
└── README.md
```

### Security Documentation Template

```markdown
# Security Guide

## Overview

Brief description of security features and threat model.

## Cryptography

### Algorithms

- Encryption: AES-256-GCM
- Hashing: SHA-256
- HMAC: HMAC-SHA256
- Key Derivation: PBKDF2

### Key Management

- Key generation
- Key rotation
- Secure storage

## Authentication

### Supported Methods

- JWT tokens
- API keys
- mTLS certificates

### Session Management

- Session lifetime
- Token refresh
- Revocation

## Common Vulnerabilities

### Mitigations

- Injection: Parameterized queries
- XSS: Output encoding
- CSRF: Token validation
- Timing attacks: Constant-time operations

## Security Best Practices

1. Always use TLS 1.3+
2. Rotate secrets regularly
3. Validate all inputs
4. Log security events
```

### Doc Test Best Practices

```rust
/// # Examples
///
/// Basic usage:
/// ```
/// use secure_api::encrypt;
///
/// let plaintext = b"secret message";
/// let key = [0u8; 32]; // In production, use proper key derivation
/// let ciphertext = encrypt(plaintext, &key)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// Using with error handling:
/// ```should_panic
/// use secure_api::encrypt;
///
/// // This will panic with invalid key size
/// let invalid_key = [0u8; 16]; // Too short!
/// encrypt(b"data", &invalid_key).unwrap();
/// ```
///
/// Advanced usage:
/// ```no_run
/// // This example requires external resources
/// use secure_api::{encrypt, load_key_from_file};
///
/// let key = load_key_from_file("/etc/secrets/key.bin")?;
/// let ciphertext = encrypt(b"data", &key)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
```

### Integration with Release Workflow

```bash
# Pre-release documentation workflow

# 1. Generate documentation with coverage check
/rust-security:generate-docs --coverage=true

# 2. Fix missing documentation
# Add docs to items flagged in output

# 3. Run doc tests
/rust-security:generate-docs --doc-tests=true

# 4. Generate security guides
/rust-security:generate-docs --scope=guides

# 5. Review generated docs
cargo doc --open

# 6. Publish to docs.rs (automatic on crates.io publish)
cargo publish

# 7. Update documentation site (if self-hosted)
cargo doc --no-deps
rsync -av target/doc/ user@docs-server:/var/www/docs/
```

### Cargo.toml Documentation Configuration

```toml
[package]
name = "secure-api"
documentation = "https://docs.rs/secure-api"

[package.metadata.docs.rs]
# Build docs with all features
all-features = true

# Specify features for docs.rs
features = ["tls", "jwt"]

# Use nightly for unstable features
rustdoc-args = ["--cfg", "docsrs"]

# Enable KaTeX for math in docs
rustdoc-args = ["--html-in-header", "katex-header.html"]
```

### Missing Documentation Warnings

```rust
// Enable missing docs warnings
#![warn(missing_docs)]
#![warn(missing_doc_code_examples)]

// Allows for internal items
#[allow(missing_docs)]
mod internal {
    // Private implementation details
}
```

---

## Reference Documents

This command invokes the `rust-docs` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[API-DESIGN.md](.claude/API-DESIGN.md)**

## Related Commands

- **[/rust-security:version-bump](version-bump.md)** - Version management before documentation
- **[/rust-security:write-support-article](write-support-article.md)** - User-facing documentation
- **[/rust-security:review-code](review-code.md)** - Code review including documentation
- **[/rust-security:write-tests](write-tests.md)** - Generate tests including doc tests

---

**Note:** Documentation is automatically published to docs.rs when publishing to crates.io. Ensure all doc tests pass before publishing with `cargo test --doc`.
