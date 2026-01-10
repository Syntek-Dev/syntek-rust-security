# Releases

Official release information for syntek-rust-security plugin.

---

## v0.1.0 - Initial Release (2026-01-10)

**Release Type**: Beta
**Stability**: Production-ready for testing
**Download**: [GitHub Releases](https://github.com/Syntek-Studio/syntek-rust-security/releases/tag/v0.1.0)

### Highlights

This initial release brings comprehensive Rust security tooling to Claude Code, featuring 22 specialized agents, 100 practical examples, and deep integration with the Rust ecosystem.

#### For Security Engineers
- **10 Security Agents**: From threat modelling to binary analysis
- **Cryptographic Review**: Opus-powered deep analysis of crypto implementations
- **Fuzzing Infrastructure**: One-command setup for libfuzzer, AFL++, honggfuzz
- **Supply Chain Security**: Dependency provenance and vulnerability tracking

#### For Rust Developers
- **12 Infrastructure Agents**: Version management, documentation, testing, refactoring
- **Memory Safety**: Automated unsafe code auditing and reduction
- **API Design**: Guidance following official Rust API guidelines
- **Performance**: Criterion.rs benchmarking with timing attack detection

#### For Teams
- **GDPR Compliance**: Privacy-by-design patterns for Rust services
- **Compliance Reporting**: OWASP, CWE, CVSS automated reporting
- **Documentation**: Auto-generated rustdoc with passing doc tests
- **Code Review**: Clippy integration with security-focused lints

### Quick Start

```bash
# Install plugin
claude-code plugin install syntek-rust-security

# Run vulnerability scan
/vuln-scan

# Review cryptographic code
/crypto-review

# Analyze memory safety
/memory-audit

# Generate threat model
/threat-model
```

### What's Included

- **22 Agents**: 10 security + 12 infrastructure
- **4 Skills**: Core security, cryptography, embedded, web security
- **6 Plugin Tools**: Python tools for Rust ecosystem integration
- **9 Templates**: Quick-start templates for common scenarios
- **100 Examples**: Practical, compilable code examples
- **5 Guides**: Comprehensive documentation

### System Requirements

- Claude Code >= 1.0.0
- syntek-dev-suite >= 1.0.0
- Rust toolchain (cargo, rustc, clippy)
- Python 3.8+ (for plugin tools)

### Optional Tools

For full functionality, install:
```bash
cargo install cargo-audit cargo-deny cargo-geiger cargo-fuzz
```

### Documentation

- [README.md](README.md) - Plugin overview
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [docs/guides/RUST-SECURITY-OVERVIEW.md](docs/guides/RUST-SECURITY-OVERVIEW.md) - Security overview
- [docs/guides/CARGO-AUDIT-GUIDE.md](docs/guides/CARGO-AUDIT-GUIDE.md) - Vulnerability scanning
- [docs/guides/FUZZING-GUIDE.md](docs/guides/FUZZING-GUIDE.md) - Fuzzing setup
- [docs/guides/THREAT-MODELLING-GUIDE.md](docs/guides/THREAT-MODELLING-GUIDE.md) - STRIDE analysis

### Breaking Changes

N/A (initial release)

### Deprecations

None

### Bug Fixes

N/A (initial release)

### Performance Improvements

- Incremental analysis for large codebases
- Parallel processing for dependency scanning
- Cached RustSec database for faster lookups

### Security

This release includes security tooling for:
- Memory safety verification
- Cryptographic implementation review
- Secret detection and management
- Supply chain attack prevention
- Binary hardening verification

### Credits

Developed by Syntek Studio with contributions from the Rust security community.

Special thanks to:
- RustSec Advisory Database maintainers
- cargo-audit, cargo-deny, cargo-geiger developers
- Rust security working group

### Support

- **Issues**: [GitHub Issues](https://github.com/Syntek-Studio/syntek-rust-security/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Syntek-Studio/syntek-rust-security/discussions)
- **Website**: [https://syntek.dev](https://syntek.dev)

### License

MIT License - See [LICENSE](LICENSE) for details

---

## Release Checksum

```
SHA256 (syntek-rust-security-0.1.0.tar.gz):
  [To be generated during build]
```

## GPG Signature

```
[To be signed during release process]
```

---

## Upcoming Releases

### v0.2.0 (Planned)

**Focus**: Enhanced fuzzing and additional Rust frameworks

- Async fuzzing support (tokio, async-std)
- Diesel ORM security patterns
- Rocket/Actix/Axum framework-specific agents
- WebAssembly security analysis
- SARIF output format support

### v1.0.0 (Planned)

**Focus**: Production stability and enterprise features

- Guaranteed API stability
- Enterprise compliance features
- CI/CD integration examples
- GitHub Security Advisories API integration
- Custom security rule DSL
- Web dashboard for metrics

---

**Note**: This is a beta release. While production-ready for testing, APIs may change before v1.0.0. Please report issues on GitHub.
