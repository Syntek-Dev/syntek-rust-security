# Version History

**Last Updated**: 05/04/2026
**Version**: 1.1.0
**Maintained By**: Development Team
**Language**: British English (en_GB)
**Timezone**: Europe/London

---

## Table of Contents

- [Version 1.1.0 - 05/04/2026](#version-110---05042026)
- [Version 1.0.0 - 15/03/2026](#version-100---15032026)
- [Version 0.3.0 - 15/03/2026](#version-030---15032026)
- [Version 0.2.1 - 24/02/2026](#version-021---24022026)
- [Version 0.2.0 - 24/01/2026](#version-020---24012026)
- [Version 0.1.0 - 10/01/2026](#version-010---10012026)

---

## Version 1.1.0 (05/04/2026)

**Type**: Minor Release **Stability**: Stable **Breaking Changes**: None

### Summary

Adds PostgreSQL Row Level Security (RLS) requirements throughout the plugin.
Agents, skills, templates, and commands that interact with database-backed
applications now include RLS enforcement guidance. This ensures that projects
built with this plugin apply fine-grained access control at the database layer
for multi-tenant and GDPR-sensitive workloads.

### Technical Details

#### Files Changed

| File | Changes |
|------|---------|
| `templates/rust-web-security.md` | Added RLS requirements for web security templates using PostgreSQL backends |
| `templates/rust-django-ffi.md` | Added RLS enforcement patterns for Django-Rust FFI integrations |
| `templates/rust-graphql-middleware.md` | Added RLS context-setting guidance for GraphQL resolvers |
| `agents/security/compliance-auditor.md` | Added RLS policy audit checks to compliance review process |
| `agents/security/threat-modeller.md` | Added RLS bypass to STRIDE threat considerations |
| `agents/infrastructure/rust-gdpr.md` | Added RLS as a required data isolation mechanism for GDPR compliance |
| `agents/security/ffi-security-reviewer.md` | Added RLS boundary validation for FFI layers touching PostgreSQL |
| `agents/infrastructure/gunicorn-configurator.md` | Added RLS session variable configuration for Django/FastAPI deployments |
| `skills/rust-web-security/SKILL.md` | Added RLS patterns to web security knowledge base |
| `skills/rust-ffi-security/SKILL.md` | Added RLS boundary considerations to FFI security knowledge base |

#### Security Coverage Added

- **RLS Policy Enforcement**: Agents now verify that `SET LOCAL` and
  `SET app.current_user_id` patterns are used consistently before query
  execution in multi-tenant schemas.
- **GDPR Data Isolation**: `rust-gdpr` agent now requires RLS as a
  countermeasure for horizontal privilege escalation in multi-tenant databases.
- **Threat Modelling**: Threat modeller now includes RLS bypass as a spoofing
  and elevation-of-privilege threat in STRIDE analysis for PostgreSQL systems.
- **FFI Boundaries**: FFI security reviewer checks that database connections
  passed across language boundaries preserve the RLS session context.
- **GraphQL Middleware**: Templates enforce RLS context injection before
  resolver execution to prevent cross-tenant data leakage through the API layer.
- **Gunicorn Configuration**: Secure session variable setup added to connection
  pool initialisation for Django/FastAPI deployments.

#### Configuration Changes

No new configuration keys required. RLS guidance is applied at the code
generation and review level within affected agents and templates.

### Known Issues

- None

### Migration Guide

No breaking changes. Existing projects continue to work without modification.
Agents and templates updated in this release will now surface RLS guidance
when reviewing or generating code for PostgreSQL-backed applications.

### Contributors

- Syntek Studio Development Team

---

## Version 1.0.0 (2026-03-15)

**Type**: Major Release **Stability**: Stable **Breaking Changes**: None

### Summary

First stable public release. The plugin is now live and publicly available. API
stability is guaranteed within the 1.x series. All features developed across the
0.x series are included: full agent suite (50 agents), full command suite (51
commands), nine-document init template system, six Rust plugin tools with shell
wrappers, and a comprehensive examples library. The Required Reading pattern is
applied consistently across all agent and command files.

### Technical Details

#### Architecture

- **Total Agents**: 50 (8 Opus + 42 Sonnet, across security, infrastructure,
  FFI, AI gateway, server stack, and DIY security appliance domains)
- **Total Commands**: 51 user-invocable commands
- **Init Templates**: 9 documentation templates in `templates/init/`
- **Plugin Tools**: 6 Rust binaries with shell wrappers in `plugins/bin/`
- **Skills**: 22 domain knowledge modules
- **Templates**: 36 project scaffold templates
- **Examples**: 159+ compilable Rust examples

#### Stability Promotion

- Plugin stability promoted from Beta to Stable
- API interfaces for agents, commands, and plugin tools are now stable
- No breaking changes from 0.3.0; existing workflows continue unmodified

#### Complete Feature Set

**Agent Suite (50 agents)**

All agents from 0.x are included and stable:

- Security Opus agents (8): threat-modeller, crypto-reviewer, pentester,
  rust-gdpr, rust-refactor, rust-review, rust-unsafe-minimiser, rust-api-designer
- Infrastructure Sonnet agents (14): vuln-scanner, memory-safety, fuzzer,
  secrets-auditor, supply-chain, binary-analyser, compliance-auditor,
  rust-version, rust-docs, rust-support-articles, rust-git, rust-test-writer,
  rust-benchmarker, rust-dependency-manager
- New agents (28): encryption-architect, ffi-security-reviewer, server-hardener,
  zeroize-auditor, ai-gateway-architect, threat-detection-architect,
  network-security-architect, ai-gateway-builder, ssh-wrapper-generator,
  cert-manager, vault-integrator, cloudflare-manager, docker-security,
  backup-manager, token-rotator, firewall-integrator, nginx-configurator,
  gunicorn-configurator, redis-configurator, systemd-hardener,
  router-security-builder, nas-security-builder, homeserver-security-builder,
  gateway-security-builder, malware-scanner-builder, dns-security-builder,
  intrusion-detector-builder, threat-intel-integrator

**Command Suite (51 commands)**

All commands include `## Reference Documents` sections pointing to the nine
init documentation files.

**Init Template System (9 templates)**

CODING-PRINCIPLES, TESTING, SECURITY, DEVELOPMENT, API-DESIGN,
ARCHITECTURE-PATTERNS, DATA-STRUCTURES, PERFORMANCE, ENCRYPTION-GUIDE

**Plugin Tools (6 Rust binaries)**

cargo-tool, rustc-tool, vuln-db-tool, audit-tool, fuzzer-tool,
compliance-tool — each with a shell wrapper in `plugins/bin/` and a `docs`
subcommand for documentation discovery

**Required Reading Pattern**

All 50 agent files include `## Required Reading` sections. All 51 command files
include `## Reference Documents` sections. Both direct to the nine
documentation files in `.claude/`.

### Known Issues

- None

### Migration Guide

No breaking changes. Existing projects continue to work without modification.

### Performance Characteristics

- **Security Scan Time**: < 5 minutes for typical projects
- **False Positive Rate**: < 10% target
- **Agent Response Time**: 2-30 seconds depending on model

### Contributors

- Syntek Studio Development Team

---

## Version 0.3.0 (2026-03-15)

**Type**: Minor Release **Stability**: Beta **Breaking Changes**: None

### Summary

Expands the project initialisation system from four core documentation files to
nine. All agent and command files have been updated to reference the full
documentation suite, ensuring consistent access to project standards across
every interaction. Nine new setup examples provide ready-to-use documentation
starters for initialised projects.

### Technical Details

#### Architecture Changes

- **Init Templates**: 12 total (expanded from 7, adding 5 new templates)
- **Setup Examples**: 9 new examples covering all nine documentation types
- **Agent Files**: All 50 updated with `## Required Reading` sections
- **Command Files**: All 51 updated with `## Reference Documents` sections
- **Required Reading Table**: Expanded from 4 rows to 9 rows in CLAUDE.md
  template

#### New Init Templates (5)

1. **API-DESIGN.md.template**: API design standards and conventions — documents
   public API decisions, naming rationale, and versioning strategy for the
   project.

2. **ARCHITECTURE-PATTERNS.md.template**: Architectural pattern documentation —
   covers project structure, module organisation, and design decisions with
   rationale.

3. **DATA-STRUCTURES.md.template**: Core data structure documentation — defines
   key types, their invariants, ownership model, and the reasoning behind
   structural choices.

4. **PERFORMANCE.md.template**: Performance characteristics and benchmarking
   baselines — captures timing targets, profiling notes, and known
   optimisation considerations.

5. **ENCRYPTION-GUIDE.md.template**: Encryption implementation guide — covers
   algorithm selection, key management lifecycle, and usage patterns for the
   project's cryptographic operations.

#### New Setup Examples (9)

`examples/setup/` now contains one reference example per documentation type:

- `API-DESIGN.md` — example API design document
- `ARCHITECTURE-PATTERNS.md` — example architecture document
- `CODING-PRINCIPLES.md` — example coding principles document
- `DATA-STRUCTURES.md` — example data structures document
- `DEVELOPMENT.md` — example development workflow document
- `ENCRYPTION-GUIDE.md` — example encryption guide
- `PERFORMANCE.md` — example performance document
- `SECURITY.md` — example security document
- `TESTING.md` — example testing guide

#### Agent and Command Updates

- All 50 agent files: `## Required Reading` section added, listing all nine
  documentation files under `.claude/` with a note that agents must read them
  before writing or reviewing code.
- All 51 command files: `## Reference Documents` section added, listing all
  nine documentation files under `.claude/`.
- `agents/setup/project-initializer.md`: Updated to generate all nine files
  from the expanded template set.
- `commands/init.md`: Updated to document the generation of all nine files.
- `templates/init/CLAUDE.md.template`: Required Reading table expanded from
  4 rows to 9 rows.

### Known Issues

- None

### Migration Guide

No breaking changes. Existing projects continue to work. To add the five new
documentation files to an existing initialised project, re-run `/init` and
confirm overwrite, or manually copy the new templates from `templates/init/`.

### Performance Characteristics

- **Security Scan Time**: < 5 minutes for typical projects
- **False Positive Rate**: < 10% target
- **Agent Response Time**: 2-30 seconds depending on model

### Contributors

- Syntek Studio Development Team

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
VERSION: 1.1.0
RELEASE_DATE: 2026-04-05
STABILITY: stable
RUST_MSRV: 1.92.0
CLAUDE_CODE_VERSION: >=1.0.0
```
