# Claude Plugin Configuration

This file configures the Syntek Rust Security Plugin for Claude Code.

## Plugin Metadata

- **Name**: syntek-rust-security
- **Version**: 0.1.0
- **Type**: Security & Development Tools
- **Language**: Rust
- **Rust Version**: 1.92.0+ (released December 2025)
- **Target**: Security engineers, Rust developers, systems programmers

## Plugin Description

The Syntek Rust Security Plugin provides comprehensive security analysis, threat modelling, vulnerability scanning, and infrastructure automation for Rust projects. It extends Claude Code with 22 specialized agents, covering everything from cryptographic review to memory safety verification.

## Core Capabilities

### Security Analysis
- STRIDE threat modelling
- Dependency vulnerability scanning (cargo-audit, cargo-deny)
- Cryptographic implementation review
- Memory safety and unsafe code auditing
- Supply chain security analysis
- Secret detection and management
- Binary hardening verification
- Fuzzing infrastructure setup

### Infrastructure Automation
- Semantic versioning and changelog management
- Rustdoc and doc test generation
- Code review with clippy and rustfmt
- Test generation (unit, doc, property-based)
- Performance benchmarking with criterion.rs
- Dependency management and feature flag optimization
- Unsafe code minimization
- Public API design guidance

### Compliance & Reporting
- OWASP compliance reporting
- CWE vulnerability mapping
- CVSS score calculation
- GDPR compliance patterns
- Audit trail generation

## Agent Model Selection

This plugin uses two Claude models based on agent complexity:

### Opus Agents (Deep Reasoning Required)
- **threat-modeller**: Requires sophisticated architectural understanding for STRIDE analysis
- **crypto-reviewer**: Demands expert-level cryptographic knowledge and side-channel analysis
- **pentester**: Needs creative security thinking for custom tool development
- **rust-gdpr**: Requires legal/regulatory reasoning for compliance patterns
- **rust-refactor**: Complex ownership and borrowing transformations
- **rust-review**: Expert-level code review with security focus
- **rust-unsafe-minimiser**: Deep reasoning about memory safety and UB prevention
- **rust-api-designer**: Sophisticated API design following Rust guidelines

### Sonnet Agents (Standard Analysis)
All other agents use Sonnet for efficient analysis with good accuracy.

## Plugin Tools

Six Python tools provide integration with the Rust ecosystem:

1. **cargo-tool.py**: Project metadata extraction
2. **rustc-tool.py**: Toolchain version detection
3. **vuln-db-tool.py**: RustSec database management
4. **audit-tool.py**: Security audit orchestration
5. **fuzzer-tool.py**: Fuzzing infrastructure management
6. **compliance-tool.py**: Compliance report generation

## Skills System

Four core skills provide domain knowledge to agents:

1. **rust-security-core**: Memory safety, ownership patterns, unsafe guidelines
2. **rust-crypto**: Cryptographic implementation patterns and best practices
3. **rust-embedded**: Embedded systems security (no_std, hardware security)
4. **rust-web-security**: Web framework security (Actix, Rocket, Axum)

Skills are automatically loaded and provide context to agents.

## User-Invocable Commands

Quick-access commands for common security tasks:

- **/vuln-scan**: Run vulnerability scan (cargo-audit + cargo-deny)
- **/crypto-review**: Review cryptographic implementations
- **/memory-audit**: Analyze unsafe code and memory safety
- **/threat-model**: Perform STRIDE threat analysis

## Templates

Nine project templates provide quick-start configurations:

1. **rust-cli-security**: CLI application security patterns
2. **rust-web-security**: Web service security (Actix/Rocket/Axum)
3. **rust-embedded**: Embedded system security (no_std)
4. **rust-crypto-lib**: Cryptographic library development
5. **rust-django-ffi**: Django-Rust FFI integration (PyO3)
6. **rust-workspace-security**: Multi-crate workspace security
7. **rust-ffi-python**: Python FFI security patterns
8. **rust-async-security**: Async/await security (tokio, async-std)
9. **rust-no-std-security**: No-std embedded security

## Examples Library

100 practical, compilable examples organized by category:

### Security Examples (60)
- Threat Modelling (3)
- Cryptography (10)
- Memory Safety (8)
- Fuzzing (6)
- Secrets Management (5)
- Supply Chain (5)
- Web Security (8)
- Integration (8)
- Binary Hardening (5)
- Compliance (2)

### Infrastructure Examples (40)
- Version Management (4)
- Documentation (5)
- GDPR Compliance (6)
- Git Workflow (3)
- Refactoring (6)
- Code Review (4)
- Testing (6)
- Benchmarking (3)
- Dependency Management (3)

## Integration with Syntek Dev Suite

This plugin is designed to work alongside `syntek-dev-suite`:

- **Namespace Separation**: All agents prefixed with `rust-` or specific to Rust security
- **Complementary Functionality**: Web security (syntek-dev-suite) vs. systems security (this plugin)
- **Shared Workflows**: Version management, git workflows, documentation generation

Example combined workflow:
```
/syntek-dev-suite:plan        # Plan feature implementation
/rust-security:threat-model   # Model security threats
[Implement feature]
/rust-security:crypto-review  # Review cryptographic code
/rust-security:vuln-scan      # Scan for vulnerabilities
/syntek-dev-suite:review      # General code review
/rust-security:rust-review    # Rust-specific review
```

## Security Considerations

### Plugin Tool Sandboxing
Plugin tools run in a sandboxed environment with restricted access:
- Cannot access system directories (/etc, /var, /bin)
- Cannot access sensitive user directories (~/.ssh, ~/.aws)
- Limited to Rust toolchain commands (cargo, rustc, rustup)
- Cannot execute arbitrary shell commands

### Allowed Toolchain Commands
- cargo, rustc, rustup (core Rust toolchain)
- cargo-audit, cargo-deny, cargo-geiger (security tools)
- cargo-fuzz, cargo-semver-checks (testing tools)

### Data Privacy
- No code or vulnerability data sent to external services
- Local RustSec database for vulnerability scanning
- All analysis performed locally

## Performance Characteristics

- **Security Scan Time**: < 5 minutes for typical projects
- **False Positive Target**: < 10% for vulnerability detection
- **Agent Response Time**: 2-30 seconds (Sonnet vs Opus)
- **Memory Usage**: < 500MB for plugin tools

## Error Handling

Agents gracefully handle common scenarios:
- Missing Rust toolchain: Provide installation instructions
- Missing cargo tools: Suggest `cargo install` commands
- Outdated RustSec database: Auto-update or prompt user
- Compilation errors: Analyze and suggest fixes

## Versioning and Updates

- **Semantic Versioning**: Plugin follows SemVer 2.0.0
- **Auto-updates**: Check for updates on startup (optional)
- **Changelog**: All changes documented in CHANGELOG.md
- **Breaking Changes**: Clearly marked in version history

## Debugging and Logs

- **Debug Mode**: Set `RUST_SECURITY_DEBUG=1` for verbose logging
- **Log Location**: `~/.claude-code/plugins/syntek-rust-security/logs/`
- **Log Rotation**: Automatic rotation at 10MB
- **Privacy**: Logs exclude secrets and sensitive data

## Support and Resources

- **Documentation**: `docs/guides/` directory
- **Examples**: `examples/` directory with compilable code
- **Issues**: GitHub Issues for bug reports
- **Discussions**: GitHub Discussions for questions

## License

MIT License - See LICENSE file for details

---

**Note**: This plugin requires:
- Claude Code >= 1.0.0
- syntek-dev-suite >= 1.0.0
- Rust >= 1.92.0 (for latest security features and LLVM 20)
