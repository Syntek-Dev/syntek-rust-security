# Syntek Rust Security Plugin

Comprehensive Rust security tooling for Claude Code - threat modeling, vulnerability scanning, cryptographic patterns, and memory-safe development.

## Overview

This plugin extends Claude Code with specialized security analysis capabilities for Rust projects, covering:

- Memory safety and unsafe code auditing
- Cryptographic implementation review
- Supply chain security analysis
- Vulnerability scanning
- Threat modeling (STRIDE)
- Binary hardening verification
- Fuzzing infrastructure
- Compliance auditing (OWASP/CWE)

## Features

### Security Agents

- **threat-modeller**: STRIDE threat analysis for Rust applications
- **vuln-scanner**: Dependency vulnerability scanning with cargo-audit
- **crypto-reviewer**: Cryptographic implementation review and timing attack detection
- **memory-safety**: Unsafe code auditing and memory safety verification
- **fuzzer**: Fuzzing infrastructure setup (libfuzzer, AFL++, honggfuzz)
- **secrets-auditor**: Secret detection and secure secrets management
- **supply-chain**: Supply chain security and dependency provenance
- **pentester**: Custom penetration testing tool development
- **binary-analyser**: Binary hardening verification and exploitation analysis
- **compliance-auditor**: OWASP/CWE compliance reporting

### Infrastructure Agents

- **rust-version**: Semantic versioning for Cargo.toml
- **rust-docs**: Rustdoc generation and doc tests
- **rust-review**: Code review with clippy and rustfmt
- **rust-test-writer**: Unit tests and property-based testing
- **rust-refactor**: Rust-specific refactoring
- **rust-unsafe-minimiser**: Reduce unsafe blocks
- **rust-api-designer**: Public API design

### User-Invocable Skills

- `/vuln-scan`: Scan project for known vulnerabilities
- `/crypto-review`: Review cryptographic implementations
- `/memory-audit`: Analyze unsafe code blocks
- `/threat-model`: Perform STRIDE threat analysis

## Installation

```bash
claude-code plugin install syntek-rust-security
```

## Requirements

- Claude Code >= 1.0.0
- syntek-dev-suite >= 1.0.0

## Usage

Invoke agents directly or use the shorthand skills:

```bash
# Quick vulnerability scan
/vuln-scan

# Review cryptographic code
/crypto-review

# Analyze memory safety
/memory-audit

# Generate threat model
/threat-model
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## Author

Syntek Studio - [https://syntek.dev](https://syntek.dev)
