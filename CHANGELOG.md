# Changelog

**Last Updated**: 06/04/2026
**Version**: 1.1.1
**Maintained By**: Development Team
**Language**: British English (en_GB)
**Timezone**: Europe/London

---

All notable changes to the Syntek Rust Security Plugin will be documented in
this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## Table of Contents

- [Unreleased](#unreleased)
- [1.1.1 - 06/04/2026](#111---06042026)
- [1.1.0 - 05/04/2026](#110---05042026)
- [1.0.0 - 15/03/2026](#100---15032026)

---

## [Unreleased]

### Added

- Nothing yet

---

## [1.1.1] - 06/04/2026

### Changed

- Flattened `agents/` directory structure — all agents moved from `agents/security/`,
  `agents/infrastructure/`, and `agents/setup/` subdirectories to `agents/` root
- Renamed all 51 agent files to match their corresponding command names exactly,
  eliminating duplicate entries in Claude Code's slash command autocomplete
- Updated all `**Agent:**` references in 51 command files to use new agent names
- Updated `agentConfiguration` in `config.json` with new agent names and added
  all previously unlisted agents to the opus/sonnet model assignments

---

## [1.1.0] - 05/04/2026

### Added

- Row Level Security (PostgreSQL RLS) requirements added across agents, skills,
  templates, and commands for projects using PostgreSQL backends
- RLS enforcement patterns in `agents/security/compliance-auditor.md` and
  `agents/security/threat-modeller.md`
- RLS guidance in `agents/infrastructure/rust-gdpr.md` for GDPR-aligned
  data isolation
- RLS boundary considerations in `agents/security/ffi-security-reviewer.md`
  for FFI integrations touching database layers
- RLS configuration guidance in `agents/infrastructure/gunicorn-configurator.md`
  for Django/FastAPI deployments
- RLS patterns in `skills/rust-web-security/SKILL.md` and
  `skills/rust-ffi-security/SKILL.md`
- RLS requirements in `templates/rust-web-security.md`,
  `templates/rust-django-ffi.md`, and `templates/rust-graphql-middleware.md`

---

## [1.0.0] - 15/03/2026

### Added

- First stable public release — the plugin is now live and publicly available
- Full agent suite: 50 agents (8 Opus deep-reasoning + 14 existing Sonnet + 28
  new agents covering encryption, FFI, server infrastructure, AI gateway, server
  stack, and DIY security appliances)
- Full command suite: 51 commands spanning vulnerability scanning, cryptography,
  memory safety, infrastructure automation, AI gateway, server stack, and DIY
  security appliance setup
- 9 init templates in `templates/init/`: CODING-PRINCIPLES, TESTING, SECURITY,
  DEVELOPMENT, API-DESIGN, ARCHITECTURE-PATTERNS, DATA-STRUCTURES, PERFORMANCE,
  ENCRYPTION-GUIDE
- 6 plugin tools (Rust binaries with shell wrappers): cargo-tool, rustc-tool,
  vuln-db-tool, audit-tool, fuzzer-tool, compliance-tool
- Examples library with compilable examples across security, FFI, AI gateway,
  server infrastructure, server stack, and DIY security appliance categories
- Required Reading pattern applied across all 50 agent files and all 51 command
  files, directing each to the nine project documentation files in `.claude/`

### Changed

- Plugin stability promoted from Beta to Stable
- API stability guaranteed from this release forward

### Breaking Changes

- None relative to 0.3.0. This release stabilises the existing API.

## [0.3.0] - 15/03/2026

### Added

#### Templates

- `templates/init/API-DESIGN.md.template`: Project API design standards and
  conventions for documenting public API decisions
- `templates/init/ARCHITECTURE-PATTERNS.md.template`: Architectural pattern
  documentation covering project structure and design decisions
- `templates/init/DATA-STRUCTURES.md.template`: Data structure documentation
  covering core types, their invariants, and design rationale
- `templates/init/PERFORMANCE.md.template`: Performance characteristics,
  benchmarking baselines, and optimisation guidance
- `templates/init/ENCRYPTION-GUIDE.md.template`: Encryption implementation
  guide covering algorithms, key management, and usage patterns

#### Examples

- 9 new setup examples in `examples/setup/` covering all nine required
  documentation types: API-DESIGN, ARCHITECTURE-PATTERNS, CODING-PRINCIPLES,
  DATA-STRUCTURES, DEVELOPMENT, ENCRYPTION-GUIDE, PERFORMANCE, SECURITY,
  TESTING

### Changed

- `templates/init/CLAUDE.md.template`: Required Reading table expanded from
  4 rows to 9 rows, incorporating API-DESIGN, ARCHITECTURE-PATTERNS,
  DATA-STRUCTURES, PERFORMANCE, and ENCRYPTION-GUIDE alongside the original
  four documents
- `commands/init.md`: Updated to generate all nine required documentation files
  in `.claude/` of the target project
- `agents/setup/project-initializer.md`: Updated to reference all nine
  documentation templates and the expanded Required Reading table
- All 50 agent files: Added `## Required Reading` sections pointing to the nine
  documentation files in `.claude/`
- All 51 command files: Added `## Reference Documents` sections listing the
  nine documentation files in `.claude/`

## [0.2.1] - 24/02/2026

### Added

- `plugins/bin/` directory with 6 shell wrapper scripts (cargo-tool, rustc-tool,
  vuln-db-tool, audit-tool, fuzzer-tool, compliance-tool)
- Each wrapper script dynamically resolves the compiled Rust binary path relative
  to its own location and auto-builds the binary if not present
- `docs` subcommand to all 6 plugin tools — discovers the four required project
  documentation files by searching `.claude/` then the project root

### Fixed

- `config.json` plugin tool scripts corrected from non-existent `plugins/<name>.py`
  Python paths to the correct `plugins/bin/<name>` shell wrapper paths
- Plugin tools are now portable and work on any device without hardcoded absolute
  paths

### Changed

- `config.json` version bumped from `0.1.0` to `0.2.1`
- `CLAUDE.md` version metadata updated to `0.2.1`
- `agents/setup/project-initializer.md` updated to reference new doc file
  templates and the Required Reading table in CLAUDE.md
- `commands/init.md` updated with improved project initialisation behaviour
- All 6 plugin Rust tools (`cargo_tool.rs`, `rustc_tool.rs`, `audit_tool.rs`,
  `vuln_db_tool.rs`, `fuzzer_tool.rs`, `compliance_tool.rs`) updated with `docs`
  subcommand support

## [0.2.0] - 2026-01-24

### Added

#### Agents

- 6 new Opus security agents:
  - encryption-architect: Custom encryption system design
  - ffi-security-reviewer: FFI boundary security review
  - network-security-architect: Deep packet inspection design
  - server-hardener: Infrastructure security hardening
  - threat-detection-architect: Malware/intrusion detection design
  - zeroize-auditor: Memory zeroisation verification
- 22 new infrastructure agents for server stack, AI gateway, and DIY security
  appliances
- project-initializer agent for /init command

#### Commands

- /init command for project initialisation
- 29 new commands for planned features (encryption, vault, infrastructure, AI
  gateway, server stack, DIY appliances)

#### Skills

- Expanded from 4 to 22 domain knowledge modules
- New skills for FFI, Vault, AI gateway, server security, and DIY appliances
- Reorganised skills into directory structure with SKILL.md files

#### Templates

- 32 new project templates covering FFI, infrastructure, AI gateway, and DIY
  appliances

#### Examples

- Expanded from 100 to 159 compilable Rust examples
- New examples for AI gateway, server infrastructure, and DIY security
  appliances

### Changed

- Plugin tools updated to proper Rust doc comment style (//! and ///)
- Fixed clippy warnings in all plugin tools
- Reorganised .claude-plugin/ directory structure
- Updated README with comprehensive agent/command reference

### Fixed

- rustc_tool.rs: Removed redundant if branches, moved regex compilation outside
  loop
- audit_tool.rs: Collapsed nested if statements
- compliance_tool.rs: Removed needless borrow
- cargo_tool.rs: Replaced useless format! macro

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

[Unreleased]:
  https://github.com/Syntek-Studio/syntek-rust-security/compare/v1.1.0...HEAD
[1.1.0]:
  https://github.com/Syntek-Studio/syntek-rust-security/compare/v1.0.0...v1.1.0
[1.0.0]:
  https://github.com/Syntek-Studio/syntek-rust-security/compare/v0.3.0...v1.0.0
[0.3.0]:
  https://github.com/Syntek-Studio/syntek-rust-security/compare/v0.2.1...v0.3.0
[0.2.1]:
  https://github.com/Syntek-Studio/syntek-rust-security/compare/v0.2.0...v0.2.1
[0.2.0]:
  https://github.com/Syntek-Studio/syntek-rust-security/compare/v0.1.0...v0.2.0
[0.1.0]:
  https://github.com/Syntek-Studio/syntek-rust-security/releases/tag/v0.1.0
