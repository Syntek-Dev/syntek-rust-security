# Changelog

All notable changes to the Syntek Rust Security Plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial plugin structure with 22 specialized agents
- 10 security agents for Rust threat analysis
- 12 infrastructure agents for Rust development workflows
- 4 core skills for security patterns
- Plugin tools for Rust ecosystem integration
- Comprehensive templates and examples library
- Documentation guides for security best practices

## [0.1.0] - 2026-01-10

### Added
- Initial release of syntek-rust-security plugin
- Security agents:
  - threat-modeller: STRIDE threat analysis
  - vuln-scanner: Dependency vulnerability scanning
  - crypto-reviewer: Cryptographic implementation review
  - memory-safety: Unsafe code auditing
  - fuzzer: Fuzzing infrastructure setup
  - secrets-auditor: Secret detection and management
  - supply-chain: Supply chain security analysis
  - pentester: Custom penetration testing tools
  - binary-analyser: Binary hardening verification
  - compliance-auditor: OWASP/CWE compliance reporting
- Infrastructure agents:
  - rust-version: Semantic versioning management
  - rust-docs: Rustdoc and doc test generation
  - rust-gdpr: GDPR compliance patterns
  - rust-support-articles: User-facing documentation
  - rust-git: Git workflows for Rust projects
  - rust-refactor: Rust-specific refactoring
  - rust-review: Code review with clippy/rustfmt
  - rust-test-writer: Test generation (unit, doc, property-based)
  - rust-benchmarker: Performance benchmarking
  - rust-dependency-manager: Cargo dependency management
  - rust-unsafe-minimiser: Unsafe code reduction
  - rust-api-designer: Public API design
- Skills:
  - rust-security-core: Core security patterns
  - rust-crypto: Cryptographic patterns
  - rust-embedded: Embedded systems security
  - rust-web-security: Web framework security
- User-invocable commands:
  - /vuln-scan: Quick vulnerability scanning
  - /crypto-review: Cryptographic code review
  - /memory-audit: Memory safety analysis
  - /threat-model: STRIDE threat modelling
- Plugin tools:
  - cargo-tool: Cargo metadata extraction
  - rustc-tool: Rust toolchain detection
  - vuln-db-tool: CVE database management
  - audit-tool: Security audit orchestration
  - fuzzer-tool: Fuzzing infrastructure management
  - compliance-tool: Compliance report generation
- Templates:
  - rust-cli-security: CLI application security
  - rust-web-security: Web service security
  - rust-embedded: Embedded system security
  - rust-crypto-lib: Cryptographic library development
  - rust-django-ffi: Django-Rust FFI integration
  - rust-workspace-security: Multi-crate workspace security
  - rust-ffi-python: PyO3 FFI security
  - rust-async-security: Async/await security patterns
  - rust-no-std-security: No-std embedded security
- Examples library:
  - 60 security examples across 10 categories
  - 40 infrastructure examples across 9 categories
  - Total: 100 practical, compilable examples
- Documentation:
  - Rust Security Overview guide
  - Cargo Audit usage guide
  - Fuzzing infrastructure guide
  - Threat modelling guide
  - Syntek Dev Suite integration guide

[Unreleased]: https://github.com/Syntek-Studio/syntek-rust-security/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Syntek-Studio/syntek-rust-security/releases/tag/v0.1.0
