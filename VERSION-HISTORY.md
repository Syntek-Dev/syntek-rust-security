# Version History

**Maintained By**: Development Team **Language**: British English (en_GB)
**Timezone**: Europe/London

---

## Version 0.2.0 (2026-01-24)

**Type**: Minor Release **Stability**: Beta **Breaking Changes**: None

### Summary

Major expansion of the Syntek Rust Security Plugin with new agents, commands,
skills, templates, and examples. Adds comprehensive support for AI gateways,
server infrastructure, and DIY security appliances.

### Technical Details

#### Architecture Changes

- **Total Agents**: 50 (16 security + 34 infrastructure)
- **Skills**: 22 domain knowledge modules (expanded from 4)
- **Plugin Tools**: 6 Rust tools (converted from Python, with doc improvements)
- **Templates**: 36 project templates (expanded from 9)
- **Examples**: 159 compilable examples (expanded from 100)
- **Commands**: 52 total (23 implemented + 29 planned)

#### New Security Agents (Opus)

1. **encryption-architect**: Designs custom encryption systems using AES-GCM,
   ChaCha20-Poly1305, XChaCha20. Creates key management, envelope encryption,
   and secure key derivation infrastructure.

2. **ffi-security-reviewer**: Audits FFI boundaries for PyO3, Neon, UniFFI, and
   wasm-bindgen. Verifies memory safety, null pointer handling, and data
   validation across language boundaries.

3. **network-security-architect**: Designs deep packet inspection engines with
   protocol dissection, payload analysis, and real-time traffic classification.

4. **server-hardener**: Comprehensive infrastructure security hardening. Reviews
   SSH, firewall, intrusion detection, and generates hardening checklists.

5. **threat-detection-architect**: Designs malware and intrusion detection
   systems with YARA rules, signature matching, and behavioural analysis.

6. **zeroize-auditor**: Verifies memory zeroisation patterns ensuring sensitive
   data is securely wiped using zeroize and secrecy crates.

#### New Infrastructure Agents (22 Sonnet)

AI Gateway: ai-gateway-architect (Opus), ai-gateway-builder Server
Infrastructure: ssh-wrapper-generator, cert-manager, vault-integrator,
cloudflare-manager, docker-security, backup-manager, token-rotator,
firewall-integrator Server Stack: nginx-configurator, gunicorn-configurator,
redis-configurator, systemd-hardener DIY Security Appliances:
router-security-builder, nas-security-builder, homeserver-security-builder,
gateway-security-builder, malware-scanner-builder, dns-security-builder,
intrusion-detector-builder, threat-intel-integrator

#### Setup Agent

- **project-initializer**: Initialises Rust projects with the security plugin.
  Creates .claude/ directory with CLAUDE.md, security guide, settings, and
  plugin tools.

#### New Commands (30)

- /init: Project initialisation
- Encryption: /encrypt-setup, /decrypt-setup, /zeroize-audit
- Vault: /vault-setup, /token-rotate
- Infrastructure: /ssh-wrapper, /cert-rotate, /cloudflare-setup, /docker-harden,
  /backup-setup, /firewall-setup, /server-harden, /ffi-audit
- AI Gateway: /ai-gateway-setup, /ai-provider-add
- Server Stack: /nginx-config, /gunicorn-config, /redis-config, /systemd-harden
- DIY Appliances: /router-security-init, /nas-security-init,
  /homeserver-security-init, /gateway-security-init, /malware-scanner-setup,
  /ids-setup, /dns-proxy-setup, /threat-feeds-setup, /dpi-setup,
  /quarantine-setup

#### New Skills (18)

FFI & Integration: rust-ffi-security, rust-vault-integration, rust-ai-gateway
Server & Infrastructure: rust-server-security, rust-cloudflare-security,
rust-docker-security, rust-backup-security Memory & CLI: rust-zeroize-patterns,
rust-cli-patterns Server Stack: rust-nginx-patterns, rust-gunicorn-patterns,
rust-redis-patterns DIY Appliances: rust-threat-detection,
rust-network-inspection, rust-intrusion-detection, rust-dns-security,
rust-file-scanning, rust-threat-intelligence

#### Code Quality Improvements

- Converted all plugin tools to proper Rust doc comment style (//! and ///)
- Added comprehensive documentation to all structs and fields
- Fixed all clippy warnings:
  - rustc_tool.rs: Removed redundant if branches, moved regex outside loop
  - audit_tool.rs: Collapsed nested if statements
  - compliance_tool.rs: Removed needless borrow
  - cargo_tool.rs: Replaced useless format! macro

### Known Issues

- Markdownlint warnings in agent/command documentation (non-blocking)

### Migration Guide

No breaking changes. Existing projects continue to work. To use new features:

1. Run `/init` to set up project configuration
2. New commands and agents are immediately available

### Performance Characteristics

- **Security Scan Time**: < 5 minutes for typical projects
- **False Positive Rate**: < 10% target
- **Agent Response Time**: 2-30 seconds depending on model

### Contributors

- Syntek Studio Development Team

---

## Version 0.1.0 (2026-01-10)

**Type**: Initial Release **Stability**: Beta **Breaking Changes**: N/A (first
release)

### Summary

First public release of the Syntek Rust Security Plugin, providing comprehensive
security tooling and infrastructure agents for Rust development in Claude Code.

### Technical Details

#### Architecture

- **Total Agents**: 22 (10 security + 12 infrastructure)
- **Skills**: 4 core security skill modules
- **Plugin Tools**: 6 Python tools for Rust ecosystem integration
- **Templates**: 9 project templates
- **Examples**: 100 compilable examples

#### Security Agents

1. **threat-modeller** (Model: Opus)
   - STRIDE threat analysis framework
   - Attack surface mapping
   - Trust boundary identification
   - Threat prioritisation by CVSS scoring

2. **vuln-scanner** (Model: Sonnet)
   - cargo-audit integration
   - cargo-deny policy enforcement
   - RustSec Advisory Database scanning
   - Transitive dependency vulnerability detection

3. **crypto-reviewer** (Model: Opus)
   - Audited crate verification
   - Timing attack vulnerability detection
   - Side-channel resistance analysis
   - Key management pattern review

4. **memory-safety** (Model: Sonnet)
   - Unsafe block audit and justification
   - FFI boundary safety verification
   - Panic safety analysis
   - Send/Sync trait safety checks

5. **fuzzer** (Model: Sonnet)
   - cargo-fuzz/libfuzzer setup
   - AFL++ integration
   - honggfuzz configuration
   - Corpus management strategies

6. **secrets-auditor** (Model: Sonnet)
   - Hardcoded secret detection
   - Git history scanning
   - Environment variable security
   - Keyring integration patterns

7. **supply-chain** (Model: Sonnet)
   - Dependency graph analysis
   - Crate provenance verification
   - Build reproducibility checks
   - Typosquatting detection

8. **pentester** (Model: Opus)
   - Custom security tool development
   - Network fuzzer creation
   - Binary analysis utility generation
   - Protocol parser development

9. **binary-analyser** (Model: Sonnet)
   - ASLR/PIE/stack canary verification
   - ROP gadget analysis
   - Symbol table analysis
   - Binary permission checks

10. **compliance-auditor** (Model: Sonnet)
    - OWASP compliance reporting
    - CWE mapping
    - CVSS score calculation
    - Audit trail generation

#### Infrastructure Agents

11. **rust-version** (Model: Sonnet)
    - Workspace version synchronisation
    - SemVer compliance checking
    - cargo-semver-checks integration
    - Breaking change detection

12. **rust-docs** (Model: Sonnet)
    - Rustdoc comment generation
    - Doc test creation
    - API documentation structure
    - cargo-rdme integration

13. **rust-gdpr** (Model: Opus)
    - Consent management systems
    - Data export (right to portability)
    - Data deletion (right to be forgotten)
    - Privacy-preserving data structures

14. **rust-support-articles** (Model: Sonnet)
    - User-facing guides
    - Troubleshooting documentation
    - Integration tutorials
    - FAQ generation

15. **rust-git** (Model: Sonnet)
    - Cargo.lock strategy management
    - Workspace release workflows
    - Per-crate tagging
    - Breaking change commit detection

16. **rust-refactor** (Model: Opus)
    - Trait extraction
    - Generic type introduction
    - Unsafe code reduction
    - Builder pattern application

17. **rust-review** (Model: Opus)
    - Clippy security lints
    - Rustfmt verification
    - API guideline compliance
    - Unsafe code soundness review

18. **rust-test-writer** (Model: Sonnet)
    - Unit test generation
    - Doc test creation
    - Property-based testing (proptest)
    - Fuzzing harness generation

19. **rust-benchmarker** (Model: Sonnet)
    - Criterion.rs benchmark creation
    - Flamegraph generation
    - Timing attack detection
    - Performance regression tracking

20. **rust-dependency-manager** (Model: Sonnet)
    - Feature flag optimisation
    - Workspace dependency consolidation
    - cargo-deny configuration
    - Duplicate dependency elimination

21. **rust-unsafe-minimiser** (Model: Opus)
    - Unsafe block reduction strategies
    - Safety invariant verification
    - Miri integration for UB detection
    - Safe abstraction design

22. **rust-api-designer** (Model: Opus)
    - Rust API guideline compliance
    - Generic API design
    - Builder pattern design
    - Type state pattern implementation

#### Plugin Tools

1. **cargo-tool.py**
   - Project metadata extraction
   - Dependency tree analysis
   - Build target detection
   - Unsafe code counting

2. **rustc-tool.py**
   - Rustc version detection
   - Target triple identification
   - Channel detection (stable/beta/nightly)
   - Sysroot path resolution

3. **vuln-db-tool.py**
   - RustSec database synchronisation
   - CVE search functionality
   - Database statistics
   - Auto-update mechanism

4. **audit-tool.py**
   - Security audit orchestration
   - cargo-audit execution
   - cargo-deny enforcement
   - cargo-geiger unsafe detection
   - Report generation

5. **fuzzer-tool.py**
   - Fuzzing infrastructure initialisation
   - Fuzzer execution management
   - Corpus management
   - Crash analysis

6. **compliance-tool.py**
   - OWASP report generation
   - CWE mapping
   - CVSS scoring
   - Export to JSON/PDF/HTML

#### Dependencies

- **Required**: syntek-dev-suite >= 1.0.0
- **Rust Toolchain**: cargo, rustc, clippy
- **Optional Tools**: cargo-audit, cargo-deny, cargo-geiger, cargo-fuzz

### Known Issues

- None reported in initial release

### Migration Guide

N/A (first release)

### Performance Characteristics

- **Security Scan Time**: < 5 minutes for typical projects
- **False Positive Rate**: < 10% target
- **Agent Response Time**: 2-30 seconds depending on model (Sonnet vs Opus)

### Testing

- All 22 agents tested on sample Rust projects
- 100 examples verified to compile
- Integration tested with syntek-dev-suite v1.0.0

### Contributors

- Syntek Studio Development Team

---

## Versioning Strategy

This plugin follows [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR**: Breaking changes to agent interfaces or plugin structure
- **MINOR**: New agents, skills, or backwards-compatible features
- **PATCH**: Bug fixes, documentation updates, example improvements

### Version Metadata

```
VERSION: 0.1.0
RELEASE_DATE: 2026-01-10
STABILITY: beta
RUST_MSRV: 1.70.0
CLAUDE_CODE_VERSION: >=1.0.0
```
