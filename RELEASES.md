# Releases

Official release information for syntek-rust-security plugin.

---

## v1.0.0 - First Stable Public Release (15/03/2026)

**Release Type**: Major
**Stability**: Stable
**Download**: [GitHub Releases](https://github.com/Syntek-Studio/syntek-rust-security/releases/tag/v1.0.0)

### Highlights

This is the first stable public release of the Syntek Rust Security Plugin. The
plugin is now live and publicly available. The API is stable and guaranteed
forward-compatible within the 1.x series.

All features developed across the 0.x series are included and fully supported:
the complete agent suite, command suite, init template system, plugin tools,
and examples library.

#### Full Agent Suite (50 Agents)

- **8 Opus agents** for deep-reasoning tasks: threat-modeller, crypto-reviewer,
  pentester, rust-gdpr, rust-refactor, rust-review, rust-unsafe-minimiser,
  rust-api-designer
- **14 existing Sonnet agents** for standard analysis across vulnerability
  scanning, memory safety, fuzzing, secrets, supply chain, binary analysis,
  compliance, version management, documentation, testing, benchmarking, and
  dependency management
- **28 new agents** covering encryption architecture, FFI security review,
  server hardening, memory zeroisation, AI gateway design, threat detection,
  network security, SSH wrappers, certificate management, Vault integration,
  Cloudflare management, Docker security, backup management, token rotation,
  firewall integration, AI gateway building, Nginx/Gunicorn/Redis configuration,
  and DIY security appliance construction

#### Full Command Suite (51 Commands)

All 51 user-invocable commands are available, spanning:

- Vulnerability scanning, cryptographic review, memory audit, threat modelling
- Encryption and decryption setup, memory zeroisation audit
- Vault and secret management, token rotation
- SSH wrappers, certificate rotation, Cloudflare integration, Docker hardening,
  Backblaze B2 backup, firewall setup, server hardening, FFI audit
- AI gateway setup and provider management
- Nginx, Gunicorn, Redis, and systemd configuration
- DIY security appliance initialisation (router, NAS, homeserver, gateway)
- Malware scanner, IDS/IPS, DNS proxy, threat feeds, DPI, and quarantine setup

#### 9-Document Init Template System

Projects initialised with `/init` receive the full nine-document suite in
`.claude/`:

1. CODING-PRINCIPLES — coding standards, error handling, naming
2. TESTING — testing guide with cargo test, proptest, cargo-fuzz
3. SECURITY — memory safety, crypto standards, vault integration, hardening
4. DEVELOPMENT — dev workflow, prerequisites, git conventions
5. API-DESIGN — public API decisions, naming rationale, versioning strategy
6. ARCHITECTURE-PATTERNS — project structure, module organisation, design
   decisions
7. DATA-STRUCTURES — core types, invariants, ownership model
8. PERFORMANCE — timing targets, profiling notes, optimisation guidance
9. ENCRYPTION-GUIDE — algorithm selection, key management, usage patterns

All 50 agents and all 51 commands reference all nine documents via standardised
`## Required Reading` and `## Reference Documents` sections.

#### 6 Plugin Tools (Rust Binaries)

- **cargo-tool**: Project metadata extraction from Cargo.toml
- **rustc-tool**: Toolchain version detection and configuration
- **vuln-db-tool**: RustSec database management and CVE lookups
- **audit-tool**: Security audit orchestration (cargo-audit, cargo-deny,
  cargo-geiger)
- **fuzzer-tool**: Fuzzing infrastructure management (libfuzzer, AFL++,
  honggfuzz)
- **compliance-tool**: Compliance report generation (OWASP, CWE, CVSS)

All tools include shell wrapper scripts in `plugins/bin/` with auto-build
support and a `docs` subcommand for required documentation discovery.

### What's Changed Since 0.3.0

- Plugin stability promoted from Beta to Stable
- API stability guaranteed within the 1.x series
- No breaking changes relative to 0.3.0

### Breaking Changes

None. Existing projects and workflows continue to work without modification.

### System Requirements

- Claude Code >= 1.0.0
- syntek-dev-suite >= 1.0.0
- Rust >= 1.92.0

### Documentation

- [README.md](README.md) - Plugin overview
- [CHANGELOG.md](CHANGELOG.md) - Full change history
- [CLAUDE.md](CLAUDE.md) - Plugin configuration and agent reference
- [templates/init/](templates/init/) - All nine initialisation templates
- [examples/](examples/) - Compilable examples library

---

## v0.3.0 - Documentation Expansion (2026-03-15)

**Release Type**: Minor
**Stability**: Beta
**Download**: [GitHub Releases](https://github.com/Syntek-Studio/syntek-rust-security/releases/tag/v0.3.0)

### Highlights

This release expands the project initialisation system from four core documents
to nine, giving every initialised project a comprehensive documentation suite.
All 50 agents and 51 commands have been updated to reference the full document
set, and nine new setup examples provide ready-to-use documentation starters.

#### Expanded Required Reading System

- **9-Document Suite**: Projects now initialise with API-DESIGN,
  ARCHITECTURE-PATTERNS, DATA-STRUCTURES, PERFORMANCE, and ENCRYPTION-GUIDE
  alongside the original CODING-PRINCIPLES, TESTING, SECURITY, and DEVELOPMENT
- **5 New Init Templates**: All five new documentation types have corresponding
  `.template` files in `templates/init/`
- **9 New Setup Examples**: `examples/setup/` now contains a reference example
  for each of the nine documentation types

#### Comprehensive Agent and Command Updates

- **50 Agent Files**: Every agent now includes a `## Required Reading` section
  directing it to the nine documentation files in `.claude/`
- **51 Command Files**: Every command now includes a `## Reference Documents`
  section listing all nine documentation files

### What's Changed

- `templates/init/` — 5 new template files
- `examples/setup/` — 9 new example files
- `templates/init/CLAUDE.md.template` — Required Reading table expanded to 9
  rows
- `commands/init.md` — generates all 9 docs on initialisation
- `agents/setup/project-initializer.md` — references all 9 templates
- All 50 agent files — `## Required Reading` sections added
- All 51 command files — `## Reference Documents` sections added

### Breaking Changes

None. Existing projects continue to work without modification. Re-running
`/init` will add the five new documentation files to `.claude/`.

### System Requirements

- Claude Code >= 1.0.0
- syntek-dev-suite >= 1.0.0
- Rust >= 1.92.0

### Documentation

- [README.md](README.md) - Plugin overview
- [CHANGELOG.md](CHANGELOG.md) - Full change history
- [templates/init/](templates/init/) - All nine initialisation templates

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

### v1.1.0 (Planned)

**Focus**: Enhanced fuzzing and additional Rust frameworks

- Async fuzzing support (tokio, async-std)
- Diesel ORM security patterns
- Rocket/Actix/Axum framework-specific agents
- WebAssembly security analysis
- SARIF output format support

### v1.2.0 (Planned)

**Focus**: Enterprise features and integrations

- Enterprise compliance features
- CI/CD integration examples
- GitHub Security Advisories API integration
- Custom security rule DSL
- Web dashboard for metrics

---

**Note**: v1.0.0 is a stable release. The API is guaranteed stable within the
1.x series. Please report issues on GitHub.
