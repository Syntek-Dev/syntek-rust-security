# Syntek Rust Security Plugin

> **Comprehensive Rust security tooling for Claude Code** - Threat modeling, vulnerability scanning, cryptographic patterns, and memory-safe development for Rust applications.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Marketplace](https://img.shields.io/badge/marketplace-syntek--marketplace-blue)](https://github.com/Syntek-Studio/syntek-marketplace)

## Overview

The Syntek Rust Security Plugin is a specialized Claude Code plugin designed for Rust security engineering. It provides 22 specialized agents covering security analysis, cryptographic patterns, memory safety, vulnerability scanning, and infrastructure tooling specifically adapted for Rust's unique safety guarantees and ecosystem.

## Why a Separate Plugin?

Rust security differs fundamentally from web application security:

- **Memory Safety**: Ownership, lifetimes, and unsafe code require specialized analysis
- **Cryptographic Correctness**: Side-channel attacks, timing-safe operations, constant-time crypto
- **FFI Safety**: Foreign function interfaces and language boundaries
- **Supply Chain**: Cargo-specific dependency management and provenance
- **Embedded/Systems**: No_std environments, hardware security modules, bare metal
- **Binary Security**: Hardening, RELRO, stack canaries, ASLR verification

## Features

### 10 Security-Focused Agents

- **threat-modeller** - STRIDE threat analysis for Rust applications
- **vuln-scanner** - Dependency vulnerability scanning with cargo-audit
- **crypto-reviewer** - Cryptographic implementation review and timing attack detection
- **memory-safety** - Unsafe code auditing and memory safety verification
- **fuzzer** - Fuzzing infrastructure setup (libfuzzer, AFL++, honggfuzz)
- **secrets-auditor** - Secret detection and secure secrets management
- **supply-chain** - Supply chain security and dependency provenance
- **pentester** - Custom penetration testing tool development
- **binary-analyser** - Binary hardening verification and exploitation analysis
- **compliance-auditor** - OWASP/CWE compliance reporting

### 12 Infrastructure Agents

- **rust-version** - Semantic versioning for Cargo.toml and workspace management
- **rust-docs** - Rustdoc generation, doc tests, and API documentation
- **rust-gdpr** - GDPR compliance patterns for Rust services
- **rust-support-articles** - User-facing documentation for security tools
- **rust-git** - Git workflows for Rust projects (Cargo.lock strategies)
- **rust-refactor** - Rust-specific refactoring (trait extraction, unsafe reduction)
- **rust-review** - Code review with clippy, rustfmt, and API guidelines
- **rust-test-writer** - Unit tests, doc tests, property-based testing
- **rust-benchmarker** - Performance benchmarking with criterion.rs
- **rust-dependency-manager** - Cargo dependency and feature flag management
- **rust-unsafe-minimiser** - Reduce unsafe blocks and verify safety invariants
- **rust-api-designer** - Public API design following Rust API guidelines

## Installation

### Prerequisites

- Claude Code CLI installed
- Rust toolchain (rustc, cargo)
- Recommended: cargo-audit, cargo-deny, clippy, rustfmt

### Install from Syntek Marketplace

```json
{
  "plugins": [
    "syntek-dev-suite@syntek-marketplace",
    "rust-security@syntek-marketplace"
  ]
}
```

Or install directly:

```bash
claude-code plugins install syntek-marketplace/rust-security
```

## Quick Start

### Vulnerability Scanning

```bash
/vuln-scan
```

Scans your Rust project for known vulnerabilities using cargo-audit and provides remediation guidance.

### Cryptographic Review

```bash
/crypto-review src/crypto/
```

Reviews cryptographic implementations for common pitfalls:
- Timing attacks
- Side-channel vulnerabilities
- Incorrect algorithm usage
- Key management issues

### Memory Safety Audit

```bash
/memory-audit
```

Analyzes unsafe code blocks and provides recommendations for:
- Reducing unsafe surface area
- Verifying safety invariants
- FFI boundary safety
- Panic safety

### Threat Modeling

```bash
/threat-model
```

Performs STRIDE threat analysis on your Rust application architecture.

## Use Cases

### 1. Web Application Security

Secure Rust web frameworks (Actix, Rocket, Axum):
- Authentication and authorization patterns
- Input validation and sanitization
- SQL injection prevention
- CSRF/XSS protection

### 2. Cryptographic Libraries

Build secure cryptographic implementations:
- AEAD encryption (AES-GCM, ChaCha20-Poly1305)
- Key derivation (Argon2, PBKDF2, scrypt)
- Digital signatures (Ed25519, ECDSA)
- Timing-safe operations

### 3. Django Integration

Create Rust-based cryptographic modules for Django:
- FFI safety via PyO3
- Password hashing extensions
- Custom encryption backends
- Performance-critical security operations

### 4. SaaS Security

Password managers, vault systems, secrets management:
- Secure memory handling with zeroize
- HSM integration
- Key rotation patterns
- Audit logging

### 5. NAS/Homeserver Protection

File encryption, network security:
- File-level encryption
- Network protocol hardening
- Access control systems
- Secure backup solutions

### 6. Embedded Systems

IoT device security, hardware security modules:
- No_std secure patterns
- Hardware RNG integration
- Secure boot verification
- Side-channel resistant code

## Architecture

```
syntek-rust-security/
├── agents/                  # 22 specialized agents
│   ├── security/           # 10 security-focused agents
│   └── infrastructure/     # 12 infrastructure agents
├── skills/                 # 4 skill systems
│   ├── rust-security-core.md
│   ├── rust-crypto.md
│   ├── rust-embedded.md
│   └── rust-web-security.md
├── templates/              # 9 project templates
├── examples/               # 100+ security examples
├── docs/                   # Documentation
│   ├── plans/             # Implementation plans
│   └── guides/            # User guides
└── plugin.json            # Plugin configuration
```

## Examples

### 100+ Security Examples

- **Cryptography** (10): AEAD, key derivation, signatures, timing attacks
- **Memory Safety** (8): Unsafe patterns, FFI safety, panic safety
- **Fuzzing** (6): libfuzzer, AFL++, honggfuzz configurations
- **Secrets Management** (5): Detection, keyring, HSM integration
- **Supply Chain** (5): Cargo-deny, provenance, reproducibility
- **Web Security** (8): Framework-specific patterns
- **Integration** (8): Django FFI, password managers, NAS encryption
- **Binary Hardening** (5): RELRO, PIE, stack canaries
- **Testing** (20): Unit, integration, doc tests, property-based
- **Benchmarking** (5): Criterion.rs, flamegraphs
- **Documentation** (10): Rustdoc patterns
- **Compliance** (10): GDPR, OWASP, CWE

## Templates

9 project templates for common security scenarios:

1. **Web Service Security** - Actix/Rocket/Axum hardened templates
2. **Cryptographic Library** - Side-channel resistant crypto
3. **CLI Security Tool** - Pentesting tool scaffolding
4. **Workspace Security** - Multi-crate security architecture
5. **FFI/PyO3 Integration** - Django integration templates
6. **Async Security** - Tokio/async-std secure patterns
7. **No_std Embedded** - Embedded systems security
8. **Password Manager** - Vault system template
9. **NAS Encryption** - File encryption service

## Development

### Building from Source

```bash
git clone https://github.com/Syntek-Studio/syntek-rust-security.git
cd syntek-rust-security
cargo build --release
```

### Running Tests

```bash
cargo test
cargo test --doc  # Run doc tests
```

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Roadmap

See [docs/plans/PLAN-RUST-SECURITY-PLUGIN.md](docs/plans/PLAN-RUST-SECURITY-PLUGIN.md) for the complete implementation plan.

### Phase 1: Core Infrastructure (Weeks 1-3)
- Repository setup
- Core security skills
- Basic agent framework

### Phase 2: Security Agents (Weeks 4-7)
- Vulnerability scanning
- Cryptographic review
- Memory safety auditing

### Phase 3: Infrastructure Agents (Weeks 8-11)
- Testing and documentation
- Version management
- Refactoring tools

### Phase 4: Integration (Weeks 12-14)
- Django/PyO3 examples
- NAS/Homeserver templates
- SaaS patterns

### Phase 5: Polish (Weeks 15-17)
- Documentation
- Examples library
- Performance optimization

## Comparison with Syntek Dev Suite

| Feature | Syntek Dev Suite | Rust Security Plugin |
|---------|------------------|---------------------|
| **Focus** | Web applications (Django, Laravel) | Rust security & systems |
| **Language** | Python, PHP, JavaScript | Rust |
| **Security** | OWASP Top 10, web vulnerabilities | Memory safety, crypto, supply chain |
| **Testing** | Jest, PHPUnit, pytest | cargo test, proptest, fuzzing |
| **Docs** | JSDoc, PHPDoc | rustdoc, doc tests |
| **Versioning** | package.json, composer.json | Cargo.toml, semver |

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/Syntek-Studio/syntek-rust-security/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Syntek-Studio/syntek-rust-security/discussions)
- **Marketplace**: [Syntek Marketplace](https://github.com/Syntek-Studio/syntek-marketplace)

## Related Projects

- [Syntek Dev Suite](https://github.com/Syntek-Studio/syntek-dev-suite) - Web application development toolkit
- [Syntek Marketplace](https://github.com/Syntek-Studio/syntek-marketplace) - Claude Code plugin marketplace

---

**Built by Syntek Studio** | [Website](https://syntek.dev) | [GitHub](https://github.com/Syntek-Studio)
