# Rust Security Plugin Implementation Plan

**Last Updated**: 10/01/2026
**Version**: 1.4.0
**Maintained By**: Development Team
**Language**: British English (en_GB)
**Timezone**: Europe/London

---

## Table of Contents

- [Rust Security Plugin Implementation Plan](#rust-security-plugin-implementation-plan)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Strategic Decision: Repository Architecture](#strategic-decision-repository-architecture)
    - [Option 1: Separate Repository (RECOMMENDED)](#option-1-separate-repository-recommended)
    - [Option 2: Integrated Plugin (NOT RECOMMENDED)](#option-2-integrated-plugin-not-recommended)
  - [Requirements](#requirements)
    - [Core Functional Requirements](#core-functional-requirements)
      - [Security Tooling Integration](#security-tooling-integration)
      - [Custom Penetration Testing Tools](#custom-penetration-testing-tools)
      - [Secrets Management](#secrets-management)
      - [Secure Code Patterns](#secure-code-patterns)
      - [Threat Intelligence Integration](#threat-intelligence-integration)
    - [Non-Functional Requirements](#non-functional-requirements)
    - [Integration Requirements](#integration-requirements)
  - [Technical Design](#technical-design)
    - [Repository Structure](#repository-structure)
    - [Agent Specialisations](#agent-specialisations)
      - [1. Threat Modeller Agent (`/rust-security:threat-model`)](#1-threat-modeller-agent-rust-securitythreat-model)
      - [2. Vulnerability Scanner Agent (`/rust-security:vuln-scan`)](#2-vulnerability-scanner-agent-rust-securityvuln-scan)
      - [3. Crypto Reviewer Agent (`/rust-security:crypto-review`)](#3-crypto-reviewer-agent-rust-securitycrypto-review)
      - [4. Memory Safety Agent (`/rust-security:memory-safety`)](#4-memory-safety-agent-rust-securitymemory-safety)
      - [5. Fuzzer Agent (`/rust-security:fuzz`)](#5-fuzzer-agent-rust-securityfuzz)
      - [6. Secrets Auditor Agent (`/rust-security:secrets-audit`)](#6-secrets-auditor-agent-rust-securitysecrets-audit)
      - [7. Supply Chain Agent (`/rust-security:supply-chain`)](#7-supply-chain-agent-rust-securitysupply-chain)
      - [8. Pentester Agent (`/rust-security:pentest`)](#8-pentester-agent-rust-securitypentest)
      - [9. Binary Analyser Agent (`/rust-security:binary-analysis`)](#9-binary-analyser-agent-rust-securitybinary-analysis)
      - [10. Compliance Auditor Agent (`/rust-security:compliance`)](#10-compliance-auditor-agent-rust-securitycompliance)
    - [Skills System](#skills-system)
      - [`rust-security-core/SKILL.md`](#rust-security-coreskillmd)
      - [`rust-crypto/SKILL.md`](#rust-cryptoskillmd)
      - [`rust-embedded/SKILL.md`](#rust-embeddedskillmd)
      - [`rust-web-security/SKILL.md`](#rust-web-securityskillmd)
    - [Plugin Tools](#plugin-tools)
      - [`cargo-tool.py`](#cargo-toolpy)
      - [`rustc-tool.py`](#rustc-toolpy)
      - [`vuln-db-tool.py`](#vuln-db-toolpy)
      - [`audit-tool.py`](#audit-toolpy)
      - [`fuzzer-tool.py`](#fuzzer-toolpy)
      - [`compliance-tool.py`](#compliance-toolpy)
    - [Templates](#templates)
      - [`rust-cli-security.md`](#rust-cli-securitymd)
      - [`rust-web-security.md`](#rust-web-securitymd)
      - [`rust-embedded.md`](#rust-embeddedmd)
      - [`rust-crypto-lib.md`](#rust-crypto-libmd)
      - [`rust-django-ffi.md`](#rust-django-ffimd)
    - [Examples Library](#examples-library)
  - [Implementation Phases](#implementation-phases)
    - [Phase 1: Repository Setup and Architecture](#phase-1-repository-setup-and-architecture)
    - [Phase 2: Core Rust Security Skills](#phase-2-core-rust-security-skills)
    - [Phase 3: Specialised Security Agents](#phase-3-specialised-security-agents)
    - [Phase 4: Plugin Tools for Rust](#phase-4-plugin-tools-for-rust)
    - [Phase 5: Templates and Examples](#phase-5-templates-and-examples)
    - [Phase 6: Integration with Syntek Dev Suite](#phase-6-integration-with-syntek-dev-suite)
    - [Phase 7: Documentation and Testing](#phase-7-documentation-and-testing)
  - [Risks and Mitigations](#risks-and-mitigations)
  - [Open Questions](#open-questions)
    - [Technical Questions](#technical-questions)
    - [UX Questions](#ux-questions)
    - [Integration Questions](#integration-questions)
    - [Prioritisation Questions](#prioritisation-questions)
  - [Success Criteria](#success-criteria)
    - [Functional Success Criteria](#functional-success-criteria)
    - [Non-Functional Success Criteria](#non-functional-success-criteria)
    - [Adoption Success Criteria](#adoption-success-criteria)
    - [Technical Success Criteria](#technical-success-criteria)
  - [Next Steps](#next-steps)
  - [Rust Infrastructure Agents](#rust-infrastructure-agents)
    - [Differences from Web Stack Equivalents](#differences-from-web-stack-equivalents)
  - [Infrastructure Agent Specifications](#infrastructure-agent-specifications)
    - [11. Version Management Agent (`/rust-security:version`)](#11-version-management-agent-rust-securityversion)
    - [12. Documentation Agent (`/rust-security:docs`)](#12-documentation-agent-rust-securitydocs)
    - [13. GDPR Compliance Agent (`/rust-security:gdpr`)](#13-gdpr-compliance-agent-rust-securitygdpr)
    - [14. Support Articles Agent (`/rust-security:support-articles`)](#14-support-articles-agent-rust-securitysupport-articles)
    - [15. Git Workflow Agent (`/rust-security:git`)](#15-git-workflow-agent-rust-securitygit)
    - [16. Refactoring Agent (`/rust-security:refactor`)](#16-refactoring-agent-rust-securityrefactor)
    - [17. Code Review Agent (`/rust-security:review`)](#17-code-review-agent-rust-securityreview)
    - [18. Test Writer Agent (`/rust-security:test-writer`)](#18-test-writer-agent-rust-securitytest-writer)
    - [19. Benchmarking Agent (`/rust-security:benchmark`)](#19-benchmarking-agent-rust-securitybenchmark)
    - [20. Dependency Manager Agent (`/rust-security:deps`)](#20-dependency-manager-agent-rust-securitydeps)
    - [21. Unsafe Code Minimiser Agent (`/rust-security:unsafe-minimiser`)](#21-unsafe-code-minimiser-agent-rust-securityunsafe-minimiser)
    - [22. API Designer Agent (`/rust-security:api-designer`)](#22-api-designer-agent-rust-securityapi-designer)
  - [Updated Agent Count and Implementation Phases](#updated-agent-count-and-implementation-phases)
    - [Agent Summary](#agent-summary)
  - [Updated Implementation Phases](#updated-implementation-phases)
    - [Phase 3: Specialised Security and Infrastructure Agents](#phase-3-specialised-security-and-infrastructure-agents)
    - [Phase 5: Templates and Examples](#phase-5-templates-and-examples-1)
  - [Additional Rust-Specific Templates](#additional-rust-specific-templates)
    - [New Templates](#new-templates)
  - [Updated Timeline](#updated-timeline)
  - [Updated Success Criteria](#updated-success-criteria)
    - [Functional Success Criteria](#functional-success-criteria-1)
    - [Infrastructure Agent Success Criteria](#infrastructure-agent-success-criteria)
  - [Updated Open Questions](#updated-open-questions)
    - [Infrastructure Questions](#infrastructure-questions)
  - [Agent Interaction Patterns](#agent-interaction-patterns)


---

## Overview

The Rust Security Plugin extends the Syntek Dev Suite to provide specialised security tooling, vulnerability scanning, threat modelling, and secure code patterns for Rust-based systems. This plugin differs fundamentally from web stack security by focusing on memory safety, systems programming security, cryptographic implementations, and low-level threat vectors unique to Rust environments.

**Key Differentiation:**
- Web security focuses on: OWASP Top 10, XSS, CSRF, SQL injection, session management
- Rust security focuses on: Memory safety, cryptographic correctness, FFI safety, supply chain attacks, embedded security, side-channel attacks

---

## Strategic Decision: Repository Architecture

### Option 1: Separate Repository (RECOMMENDED)

**Rationale:**
1. **Distinct Domain**: Rust security is fundamentally different from web application security
2. **Independent Versioning**: Security tooling evolves at a different pace than web development
3. **Specialised Dependencies**: Requires Rust toolchain, cargo, clippy, cargo-audit, cargo-deny
4. **Target Audience**: Appeals to security engineers, systems programmers, not just web developers
5. **Plugin Marketplace**: Can be listed as a separate plugin: `rust-security@syntek-marketplace`
6. **Clearer Scope**: Avoids confusion between web security patterns and systems security

**Repository Name:** `syntek-rust-security`

**Installation:**
```json
{
  "plugins": [
    "syntek-dev-suite@syntek-marketplace",
    "rust-security@syntek-marketplace"
  ]
}
```

### Option 2: Integrated Plugin (NOT RECOMMENDED)

**Why Not:**
- Would bloat syntek-dev-suite with Rust-specific tooling most users don't need
- Conflicts in terminology (e.g., "security" agent already exists for web)
- Harder to maintain separate update cycles
- Mixed concerns: web security vs systems security

**DECISION: Use separate repository architecture.**

---

## Requirements

### Core Functional Requirements

#### Security Tooling Integration
1. **Vulnerability Scanning**
   - Integration with `cargo-audit` for dependency vulnerabilities
   - `cargo-deny` for license and security policy enforcement
   - `cargo-outdated` for dependency freshness checks
   - Custom CVE database scanning for Rust crates

2. **Static Analysis**
   - `cargo-clippy` with security-focused lints
   - `cargo-geiger` for unsafe code detection
   - Custom taint analysis for user input flows
   - Memory safety pattern verification

3. **Threat Modelling**
   - STRIDE threat modelling for Rust systems
   - Attack surface analysis
   - Trust boundary mapping
   - Data flow diagram generation

4. **Cryptographic Review**
   - Verify usage of audited crates (e.g., `ring`, `rustls`, `sodiumoxide`)
   - Check for timing attack vulnerabilities
   - Side-channel resistance verification
   - Key management pattern analysis

#### Custom Penetration Testing Tools
1. **Fuzzing Infrastructure**
   - `cargo-fuzz` / `libfuzzer` integration
   - `honggfuzz` setup for complex targets
   - AFL++ Rust instrumentation
   - Corpus management and minimisation

2. **Binary Analysis**
   - DWARF debug info extraction for exploit development
   - Binary hardening verification (ASLR, PIE, stack canaries)
   - ROP gadget analysis
   - Symbol table scraping

3. **Network Security**
   - TLS/SSL configuration review
   - Network protocol implementation analysis
   - Zero-trust architecture patterns
   - mTLS implementation verification

#### Secrets Management
1. **Secret Detection**
   - Scan for hardcoded secrets in source code
   - Environment variable pattern enforcement
   - `.env` file security analysis
   - Git history scanning for leaked credentials

2. **Secure Storage Patterns**
   - OS keyring integration patterns
   - Hardware security module (HSM) integration
   - Encrypted configuration file patterns
   - Runtime secret injection strategies

#### Secure Code Patterns
1. **Memory Safety**
   - Ownership and borrowing pattern verification
   - `unsafe` code review and justification
   - FFI boundary safety patterns
   - Panic safety in critical sections

2. **Concurrency Safety**
   - Data race prevention patterns
   - `Send`/`Sync` trait safety verification
   - Lock-free algorithm review
   - Deadlock detection

3. **Error Handling**
   - Secrets in error messages detection
   - Panic-free critical path verification
   - Error propagation security review
   - Sensitive data in stack traces

#### Threat Intelligence Integration
1. **CVE Database**
   - RustSec Advisory Database integration
   - NIST NVD Rust vulnerability feed
   - Custom vulnerability database
   - Auto-update mechanisms

2. **Supply Chain Security**
   - Dependency graph analysis
   - Transitive dependency vulnerability scanning
   - Crate provenance verification
   - Build reproducibility checks

### Non-Functional Requirements

1. **Performance**
   - Security scans complete in < 5 minutes for typical projects
   - Incremental analysis for large codebases
   - Parallel processing where applicable

2. **Accuracy**
   - False positive rate < 10% for vulnerability detection
   - Zero false negatives for critical vulnerabilities
   - Clear severity classification (Critical, High, Medium, Low)

3. **Usability**
   - Clear, actionable security recommendations
   - One-command security audit: `/rust-security:audit`
   - Integration with existing CI/CD pipelines
   - Compliance report generation (OWASP, CWE mapping)

4. **Maintainability**
   - Plugin updates independent of syntek-dev-suite
   - Backward compatibility for security patterns
   - Versioned security rules and policies

### Integration Requirements

1. **Django Integration**
   - Rust cryptographic libraries for Django (e.g., encryption packages)
   - FFI safety patterns for Python-Rust interop
   - Performance-critical security modules in Rust

2. **SaaS Product Security**
   - Password manager implementations
   - Secure key derivation functions (Argon2, scrypt)
   - Encrypted database field handlers
   - Zero-knowledge architecture patterns

3. **NAS/Homeserver Protection**
   - File encryption patterns
   - Network security hardening
   - Intrusion detection integration
   - Secure remote access patterns

---

## Technical Design

### Repository Structure

```
syntek-rust-security/
├── .claude-plugin/
│   └── manifest.json           # Plugin metadata
├── agents/
│   ├── README.md
│   ├── threat-modeller.md      # STRIDE, attack surface analysis
│   ├── vuln-scanner.md         # cargo-audit, dependency scanning
│   ├── crypto-reviewer.md      # Cryptographic implementation review
│   ├── memory-safety.md        # Memory safety pattern verification
│   ├── fuzzer.md               # Fuzzing infrastructure setup
│   ├── secrets-auditor.md      # Secret detection and management
│   ├── supply-chain.md         # Dependency security analysis
│   ├── pentester.md            # Custom pentest tool development
│   ├── binary-analyser.md      # Binary hardening and exploitation
│   └── compliance-auditor.md   # Security compliance reporting
├── skills/
│   ├── README.md
│   ├── rust-security-core/
│   │   └── SKILL.md            # Core Rust security patterns
│   ├── rust-crypto/
│   │   └── SKILL.md            # Cryptographic implementation patterns
│   ├── rust-embedded/
│   │   └── SKILL.md            # Embedded systems security
│   └── rust-web-security/
│       └── SKILL.md            # Actix/Rocket/Axum security patterns
├── plugins/
│   ├── README.md
│   ├── cargo-tool.py           # Cargo metadata extraction
│   ├── rustc-tool.py           # Rustc version and target detection
│   ├── vuln-db-tool.py         # CVE database management
│   ├── audit-tool.py           # Security audit orchestration
│   ├── fuzzer-tool.py          # Fuzzing infrastructure management
│   └── compliance-tool.py      # Compliance report generation
├── templates/
│   ├── README.md
│   ├── rust-cli-security.md    # CLI app security template
│   ├── rust-web-security.md    # Web service security template
│   ├── rust-embedded.md        # Embedded system security template
│   ├── rust-crypto-lib.md      # Cryptographic library template
│   └── rust-django-ffi.md      # Django FFI integration template
├── examples/
│   ├── threat-modelling/
│   │   ├── STRIDE-EXAMPLE.md
│   │   ├── ATTACK-SURFACE.md
│   │   └── TRUST-BOUNDARIES.md
│   ├── cryptography/
│   │   ├── AEAD-ENCRYPTION.md
│   │   ├── KEY-DERIVATION.md
│   │   ├── PASSWORD-HASHING.md
│   │   ├── DIGITAL-SIGNATURES.md
│   │   └── TIMING-ATTACKS.md
│   ├── memory-safety/
│   │   ├── UNSAFE-PATTERNS.md
│   │   ├── FFI-SAFETY.md
│   │   ├── PANIC-SAFETY.md
│   │   └── OWNERSHIP-PATTERNS.md
│   ├── fuzzing/
│   │   ├── LIBFUZZER-SETUP.md
│   │   ├── AFL-INTEGRATION.md
│   │   ├── HONGGFUZZ-EXAMPLE.md
│   │   └── CORPUS-MANAGEMENT.md
│   ├── secrets/
│   │   ├── SECRET-DETECTION.md
│   │   ├── KEYRING-INTEGRATION.md
│   │   ├── ENV-PATTERNS.md
│   │   └── HSM-INTEGRATION.md
│   ├── supply-chain/
│   │   ├── DEPENDENCY-AUDIT.md
│   │   ├── CARGO-DENY-CONFIG.md
│   │   ├── PROVENANCE-VERIFICATION.md
│   │   └── BUILD-REPRODUCIBILITY.md
│   ├── web-security/
│   │   ├── ACTIX-SECURITY.md
│   │   ├── ROCKET-PATTERNS.md
│   │   ├── AXUM-SECURITY.md
│   │   └── TLS-CONFIGURATION.md
│   └── integration/
│       ├── DJANGO-FFI-CRYPTO.md
│       ├── PASSWORD-MANAGER.md
│       ├── NAS-ENCRYPTION.md
│       └── ZERO-KNOWLEDGE.md
├── commands/
│   ├── audit.md                # Run complete security audit
│   ├── threat-model.md         # Generate threat model
│   ├── fuzz.md                 # Set up fuzzing
│   ├── scan-secrets.md         # Scan for hardcoded secrets
│   ├── check-crypto.md         # Review cryptographic usage
│   └── compliance-report.md    # Generate compliance report
├── docs/
│   ├── GUIDES/
│   │   ├── RUST-SECURITY-OVERVIEW.md
│   │   ├── CARGO-AUDIT-GUIDE.md
│   │   ├── FUZZING-GUIDE.md
│   │   └── THREAT-MODELLING-GUIDE.md
│   ├── PLANS/
│   └── METRICS/
├── CLAUDE.md                   # Plugin configuration
├── README.md                   # Plugin documentation
├── CHANGELOG.md
├── VERSION
├── VERSION-HISTORY.md
├── RELEASES.md
└── config.json                 # Plugin configuration
```

### Agent Specialisations

#### 1. Threat Modeller Agent (`/rust-security:threat-model`)
**Purpose:** Systematic threat analysis using STRIDE methodology

**Capabilities:**
- Generate STRIDE threat models for Rust systems
- Identify trust boundaries and data flows
- Map attack surface
- Prioritise threats by exploitability and impact
- Generate threat mitigation recommendations

**Model:** Opus (requires deep reasoning about system architecture)

**Output:** `docs/SECURITY/THREAT-MODEL-[COMPONENT].md`

#### 2. Vulnerability Scanner Agent (`/rust-security:vuln-scan`)
**Purpose:** Automated vulnerability detection in dependencies and code

**Capabilities:**
- Run `cargo-audit` and parse results
- Run `cargo-deny` for policy enforcement
- Check for outdated dependencies
- Scan for known CVEs in dependency tree
- Verify crate provenance

**Model:** Sonnet

**Output:** `docs/SECURITY/VULNERABILITY-REPORT.md`

#### 3. Crypto Reviewer Agent (`/rust-security:crypto-review`)
**Purpose:** Cryptographic implementation security review

**Capabilities:**
- Verify usage of audited cryptographic crates
- Check for timing attack vulnerabilities
- Review key management patterns
- Verify random number generation
- Check for deprecated algorithms
- Side-channel resistance analysis

**Model:** Opus (cryptographic review requires deep expertise)

**Output:** `docs/SECURITY/CRYPTO-AUDIT.md`

#### 4. Memory Safety Agent (`/rust-security:memory-safety`)
**Purpose:** Memory safety and unsafe code review

**Capabilities:**
- Audit all `unsafe` blocks with justification
- Verify FFI boundary safety
- Check for panic safety in critical sections
- Review lifetime and ownership patterns
- Detect potential memory leaks
- Verify `Send`/`Sync` safety

**Model:** Sonnet

**Output:** `docs/SECURITY/MEMORY-SAFETY-AUDIT.md`

#### 5. Fuzzer Agent (`/rust-security:fuzz`)
**Purpose:** Fuzzing infrastructure setup and management

**Capabilities:**
- Set up `cargo-fuzz` / `libfuzzer`
- Configure AFL++ for Rust
- Set up `honggfuzz` for complex targets
- Generate fuzzing harnesses
- Manage fuzzing corpus
- Analyse crash dumps

**Model:** Sonnet

**Output:** `fuzz/` directory with harnesses

#### 6. Secrets Auditor Agent (`/rust-security:secrets-audit`)
**Purpose:** Secret detection and secure management

**Capabilities:**
- Scan for hardcoded secrets (API keys, passwords, tokens)
- Review `.env` file security
- Check Git history for leaked secrets
- Recommend keyring integration
- Verify secret rotation patterns
- Check for secrets in error messages

**Model:** Sonnet

**Output:** `docs/SECURITY/SECRETS-AUDIT.md`

#### 7. Supply Chain Agent (`/rust-security:supply-chain`)
**Purpose:** Dependency security and supply chain attack prevention

**Capabilities:**
- Analyse dependency graph for vulnerabilities
- Check for dependency confusion attacks
- Verify crate checksums and signatures
- Review transitive dependencies
- Check for typosquatting
- Verify build reproducibility

**Model:** Sonnet

**Output:** `docs/SECURITY/SUPPLY-CHAIN-AUDIT.md`

#### 8. Pentester Agent (`/rust-security:pentest`)
**Purpose:** Custom penetration testing tool development

**Capabilities:**
- Generate exploitation proof-of-concepts
- Develop custom security scanners
- Create network fuzzing tools
- Build binary analysis utilities
- Develop protocol parsers for security testing

**Model:** Opus (requires creative security thinking)

**Output:** Security testing tools in `tools/` directory

#### 9. Binary Analyser Agent (`/rust-security:binary-analysis`)
**Purpose:** Binary hardening and exploitation analysis

**Capabilities:**
- Verify ASLR, PIE, stack canaries
- Check for ROP gadgets
- Analyse DWARF debug information
- Verify symbol stripping
- Check binary permissions
- Analyse binary dependencies

**Model:** Sonnet

**Output:** `docs/SECURITY/BINARY-HARDENING.md`

#### 10. Compliance Auditor Agent (`/rust-security:compliance`)
**Purpose:** Security compliance reporting

**Capabilities:**
- Generate OWASP compliance reports
- Map vulnerabilities to CWE categories
- Generate CVSS scores
- Create audit trail documentation
- Export compliance reports (JSON, PDF, HTML)

**Model:** Sonnet

**Output:** `docs/SECURITY/COMPLIANCE-REPORT.md`

### Skills System

#### `rust-security-core/SKILL.md`
**Core Rust security patterns and best practices**

Contents:
- Memory safety enforcement patterns
- Ownership and borrowing security implications
- `unsafe` usage guidelines and audit requirements
- Panic safety in critical paths
- Error handling security (no secrets in errors)
- FFI safety patterns
- Concurrency safety (`Send`/`Sync`, data races)

#### `rust-crypto/SKILL.md`
**Cryptographic implementation patterns**

Contents:
- Recommended cryptographic crates (audited, maintained)
- Key derivation function selection (Argon2, scrypt, PBKDF2)
- Encryption patterns (AEAD: AES-GCM, ChaCha20-Poly1305)
- Digital signature patterns (Ed25519, RSA-PSS)
- Timing attack prevention
- Side-channel resistance patterns
- Random number generation (OsRng, ThreadRng)
- Constant-time operations
- Cryptographic protocol implementation (TLS, Noise)

#### `rust-embedded/SKILL.md`
**Embedded systems security**

Contents:
- No-std cryptographic patterns
- Embedded device hardening
- Secure boot implementation
- Flash memory encryption
- Hardware security module integration
- Side-channel attack mitigation
- Power analysis resistance
- Fault injection protection

#### `rust-web-security/SKILL.md`
**Web framework security (Actix, Rocket, Axum)**

Contents:
- Input validation and sanitisation
- SQL injection prevention (with diesel, sqlx)
- XSS prevention (template engines)
- CSRF protection patterns
- Authentication and authorisation
- Session management security
- TLS/SSL configuration
- Rate limiting and DDoS protection
- Secure header configuration

### Plugin Tools

#### `cargo-tool.py`
**Cargo metadata extraction and project analysis**

**Commands:**
```bash
./plugins/cargo-tool.py info        # Project metadata
./plugins/cargo-tool.py deps        # Dependency tree
./plugins/cargo-tool.py targets     # Build targets
./plugins/cargo-tool.py features    # Feature flags
./plugins/cargo-tool.py unsafe      # Count unsafe blocks
```

**Output:** JSON with project information

#### `rustc-tool.py`
**Rust toolchain detection and configuration**

**Commands:**
```bash
./plugins/rustc-tool.py version     # Rustc version
./plugins/rustc-tool.py target      # Target triple
./plugins/rustc-tool.py channel     # Stable/beta/nightly
./plugins/rustc-tool.py sysroot     # Sysroot path
```

#### `vuln-db-tool.py`
**CVE database management**

**Commands:**
```bash
./plugins/vuln-db-tool.py update    # Update vulnerability database
./plugins/vuln-db-tool.py search    # Search for CVEs
./plugins/vuln-db-tool.py stats     # Database statistics
```

#### `audit-tool.py`
**Security audit orchestration**

**Commands:**
```bash
./plugins/audit-tool.py run         # Run full audit
./plugins/audit-tool.py quick       # Quick scan
./plugins/audit-tool.py report      # Generate report
```

Orchestrates:
- `cargo-audit` (dependency vulnerabilities)
- `cargo-deny` (policy enforcement)
- `cargo-geiger` (unsafe code detection)
- `cargo-clippy` (security lints)
- Custom secret scanning
- Compliance checks

#### `fuzzer-tool.py`
**Fuzzing infrastructure management**

**Commands:**
```bash
./plugins/fuzzer-tool.py init       # Initialise fuzzing
./plugins/fuzzer-tool.py run        # Start fuzzing
./plugins/fuzzer-tool.py corpus     # Manage corpus
./plugins/fuzzer-tool.py crashes    # Analyse crashes
```

#### `compliance-tool.py`
**Compliance report generation**

**Commands:**
```bash
./plugins/compliance-tool.py owasp  # OWASP report
./plugins/compliance-tool.py cwe    # CWE mapping
./plugins/compliance-tool.py cvss   # CVSS scoring
./plugins/compliance-tool.py export # Export to JSON/PDF
```

### Templates

#### `rust-cli-security.md`
Template for CLI application security setup

**Includes:**
- Input validation patterns
- Argument parsing security
- File I/O safety
- Signal handling security
- Error message sanitisation

#### `rust-web-security.md`
Template for web service security

**Includes:**
- Framework selection (Actix/Rocket/Axum)
- Authentication setup
- Input validation middleware
- Database security (diesel/sqlx)
- TLS configuration
- Rate limiting

#### `rust-embedded.md`
Template for embedded system security

**Includes:**
- No-std environment setup
- Hardware security features
- Secure boot configuration
- Memory protection
- Cryptographic acceleration

#### `rust-crypto-lib.md`
Template for cryptographic library development

**Includes:**
- Audited crate dependencies
- Constant-time operation patterns
- Side-channel resistance
- Zeroization of secrets
- Testing infrastructure

#### `rust-django-ffi.md`
Template for Django-Rust FFI integration

**Includes:**
- PyO3 setup for cryptographic modules
- FFI safety patterns
- Error handling across FFI boundary
- Memory management
- Performance benchmarks

### Examples Library

**60+ examples organised by security domain:**

1. **Threat Modelling Examples** (3 examples)
   - STRIDE analysis template
   - Attack surface mapping
   - Trust boundary documentation

2. **Cryptography Examples** (10 examples)
   - AEAD encryption (AES-GCM, ChaCha20-Poly1305)
   - Key derivation (Argon2, scrypt)
   - Password hashing (Argon2id)
   - Digital signatures (Ed25519, RSA-PSS)
   - Timing attack prevention
   - Constant-time operations
   - Random number generation
   - TLS client/server configuration
   - Noise protocol implementation
   - Zero-knowledge proofs (basic)

3. **Memory Safety Examples** (8 examples)
   - `unsafe` usage justification templates
   - FFI boundary safety patterns
   - Panic safety in critical sections
   - Ownership and lifetime patterns
   - Memory leak detection
   - `Send`/`Sync` verification
   - Smart pointer safety (Arc, Rc)
   - Custom allocator security

4. **Fuzzing Examples** (6 examples)
   - `cargo-fuzz` setup and harness
   - AFL++ integration
   - `honggfuzz` configuration
   - Corpus management strategies
   - Crash triage and reproduction
   - Coverage-guided fuzzing

5. **Secrets Management Examples** (5 examples)
   - Secret detection patterns
   - OS keyring integration (keyring-rs)
   - Environment variable security
   - HSM integration (YubiHSM2)
   - Secret rotation patterns

6. **Supply Chain Examples** (5 examples)
   - `cargo-deny` configuration
   - Dependency audit automation
   - Crate provenance verification
   - Build reproducibility
   - Vendor directory security

7. **Web Security Examples** (8 examples)
   - Actix-web authentication
   - Rocket input validation
   - Axum middleware security
   - SQL injection prevention (diesel)
   - XSS prevention (template engines)
   - CSRF protection
   - Session management
   - Rate limiting

8. **Integration Examples** (8 examples)
   - Django FFI cryptographic module
   - Password manager implementation
   - NAS file encryption
   - Zero-knowledge authentication
   - Secure multi-party computation
   - Homomorphic encryption (basic)
   - Encrypted database fields
   - Secure logging patterns

9. **Binary Hardening Examples** (5 examples)
   - ASLR/PIE verification
   - Stack canary checks
   - Symbol stripping
   - Binary signing
   - Exploit mitigation verification

10. **Compliance Examples** (2 examples)
    - OWASP compliance checklist
    - CWE mapping template

**Total: 60 examples**

---

## Implementation Phases

### Phase 1: Repository Setup and Architecture
**Duration:** 1 week

**Tasks:**
- [ ] Create `syntek-rust-security` repository
- [ ] Set up `.claude-plugin/manifest.json` with metadata
- [ ] Create directory structure (agents, skills, plugins, templates, examples, docs)
- [ ] Set up `CLAUDE.md` with plugin configuration
- [ ] Create `README.md` with installation and usage instructions
- [ ] Initialise version files (VERSION, CHANGELOG.md, VERSION-HISTORY.md, RELEASES.md)
- [ ] Set up CI/CD pipeline for plugin distribution
- [ ] Create `.gitignore` for Rust artifacts

**Deliverable:** Repository structure ready for development, installable as a plugin

**Files Created:**
- `/syntek-rust-security/` (all scaffold files)
- `.claude-plugin/manifest.json`
- `CLAUDE.md`
- `README.md`
- `config.json`

### Phase 2: Core Rust Security Skills
**Duration:** 2 weeks

**Tasks:**
- [ ] Write `skills/rust-security-core/SKILL.md` (memory safety, unsafe patterns)
- [ ] Write `skills/rust-crypto/SKILL.md` (cryptographic patterns)
- [ ] Write `skills/rust-embedded/SKILL.md` (embedded security)
- [ ] Write `skills/rust-web-security/SKILL.md` (Actix/Rocket/Axum patterns)
- [ ] Create skill loading mechanism for agents
- [ ] Test skill integration with agent prompts

**Deliverable:** Complete skills library that agents reference for security patterns

**Files Created:**
- `skills/rust-security-core/SKILL.md` (~5000 words)
- `skills/rust-crypto/SKILL.md` (~4000 words)
- `skills/rust-embedded/SKILL.md` (~3000 words)
- `skills/rust-web-security/SKILL.md` (~3000 words)

### Phase 3: Specialised Security Agents
**Duration:** 4 weeks

**Tasks:**
- [ ] Create `agents/threat-modeller.md` (Opus model)
- [ ] Create `agents/vuln-scanner.md` (Sonnet model)
- [ ] Create `agents/crypto-reviewer.md` (Opus model)
- [ ] Create `agents/memory-safety.md` (Sonnet model)
- [ ] Create `agents/fuzzer.md` (Sonnet model)
- [ ] Create `agents/secrets-auditor.md` (Sonnet model)
- [ ] Create `agents/supply-chain.md` (Sonnet model)
- [ ] Create `agents/pentester.md` (Opus model)
- [ ] Create `agents/binary-analyser.md` (Sonnet model)
- [ ] Create `agents/compliance-auditor.md` (Sonnet model)
- [ ] Create corresponding command files in `commands/`
- [ ] Test each agent with sample Rust projects

**Deliverable:** 10 fully functional security agents with distinct specialisations

**Files Created:**
- 10 agent definition files in `agents/`
- 10 command files in `commands/`

### Phase 4: Plugin Tools for Rust
**Duration:** 2 weeks

**Tasks:**
- [ ] Create `plugins/cargo-tool.py` (metadata, deps, targets, unsafe count)
- [ ] Create `plugins/rustc-tool.py` (version, target, channel detection)
- [ ] Create `plugins/vuln-db-tool.py` (RustSec database integration)
- [ ] Create `plugins/audit-tool.py` (orchestrate cargo-audit, cargo-deny, clippy)
- [ ] Create `plugins/fuzzer-tool.py` (fuzzing infrastructure management)
- [ ] Create `plugins/compliance-tool.py` (OWASP, CWE, CVSS reporting)
- [ ] Integrate tools with `config.json` for agent access
- [ ] Test tools on Linux, macOS, Windows

**Deliverable:** Python tools providing Rust ecosystem information to agents

**Files Created:**
- 6 plugin tool files in `plugins/`
- Updated `config.json` with tool definitions

### Phase 5: Templates and Examples
**Duration:** 3 weeks

**Tasks:**
- [ ] Create 5 project templates in `templates/`
- [ ] Create 60 security examples organised by domain (as outlined above)
- [ ] Write comprehensive documentation for each example
- [ ] Add code snippets with inline security comments
- [ ] Test all examples compile and run
- [ ] Create quick reference guides in `docs/GUIDES/`

**Deliverable:** Complete library of templates and examples for all security domains

**Files Created:**
- 5 template files
- 60 example markdown files with code
- 4 guide documents

### Phase 6: Integration with Syntek Dev Suite
**Duration:** 1 week

**Tasks:**
- [ ] Test plugin installation alongside `syntek-dev-suite`
- [ ] Verify no command name conflicts
- [ ] Create integration examples (e.g., Django + Rust crypto module)
- [ ] Document how to use both plugins together
- [ ] Create workflow examples (e.g., plan with `/syntek-dev-suite:plan`, secure with `/rust-security:audit`)
- [ ] Test with real-world projects

**Deliverable:** Seamless integration between Syntek Dev Suite and Rust Security Plugin

**Files Created:**
- `docs/GUIDES/SYNTEK-INTEGRATION.md`
- Integration examples in `examples/integration/`

### Phase 7: Documentation and Testing
**Duration:** 1 week

**Tasks:**
- [ ] Write comprehensive `README.md` with installation and usage
- [ ] Create `docs/GUIDES/RUST-SECURITY-OVERVIEW.md`
- [ ] Create `docs/GUIDES/CARGO-AUDIT-GUIDE.md`
- [ ] Create `docs/GUIDES/FUZZING-GUIDE.md`
- [ ] Create `docs/GUIDES/THREAT-MODELLING-GUIDE.md`
- [ ] Test all agents on sample Rust projects
- [ ] Record demo videos for each agent
- [ ] Create changelog entries for initial release
- [ ] Prepare marketplace listing

**Deliverable:** Complete, documented, tested plugin ready for release

**Files Created:**
- `README.md` (comprehensive)
- 4 guide documents
- `CHANGELOG.md` (v1.0.0 release notes)
- Marketplace listing materials

---

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| **Rust toolchain compatibility issues** | Medium | High | Test with stable, beta, and nightly Rust. Document minimum supported Rust version (MSRV). |
| **False positives in vulnerability scanning** | High | Medium | Tune `cargo-audit` and `cargo-deny` configs. Provide suppression mechanisms. Allow user-defined ignore rules. |
| **Cryptographic review requires deep expertise** | Medium | High | Use Opus model for crypto reviewer. Provide extensive skill documentation. Link to audited crate documentation. |
| **Fuzzing infrastructure complexity** | Medium | Medium | Provide pre-configured fuzzing templates. Document common pitfalls. Automate corpus management. |
| **Integration with existing Syntek Dev Suite** | Low | High | Careful namespace management. Clear documentation on when to use which plugin. Avoid command conflicts. |
| **Python plugin tools fail on Windows** | Medium | Medium | Test all tools on Windows. Use cross-platform Python libraries. Provide fallback mechanisms. |
| **Agents recommend outdated security practices** | Medium | High | Regular security pattern reviews. Subscribe to Rust security mailing list. Update skills quarterly. |
| **Supply chain attack on plugin distribution** | Low | Critical | Sign plugin releases. Publish checksums. Use trusted marketplace. Verify plugin integrity. |
| **Performance impact of security scans** | Medium | Medium | Implement incremental analysis. Cache results. Provide quick scan option. Optimise Python tools. |
| **Lack of Rust expertise in user base** | High | Medium | Provide educational documentation. Link to external Rust security resources. Offer example-driven learning. |

---

## Open Questions

### Technical Questions
- [ ] Should we support WebAssembly security analysis (wasm32 target)?
- [ ] Should we integrate with GitHub Security Advisories API?
- [ ] Should we provide a local CVE mirror for air-gapped environments?
- [ ] Should we support custom security rules via a DSL?
- [ ] Should we integrate with SAST tools like Semgrep for Rust?

### UX Questions
- [ ] How verbose should security reports be? (Summary vs detailed)
- [ ] Should we provide auto-fix capabilities for common vulnerabilities?
- [ ] Should we integrate with IDE extensions (VS Code, IntelliJ)?
- [ ] Should we provide a web dashboard for security metrics?

### Integration Questions
- [ ] Should we provide a GitHub Action for CI/CD integration?
- [ ] Should we integrate with Dependabot for automated PR creation?
- [ ] Should we provide Slack/Discord notifications for security alerts?
- [ ] Should we integrate with SIEM systems for enterprise users?

### Prioritisation Questions
- [ ] Which 3 agents are most critical for MVP? (Recommendation: vuln-scanner, crypto-reviewer, secrets-auditor)
- [ ] Which examples are most valuable? (Recommendation: cryptography, web-security, integration)
- [ ] Should we target hobbyists, enterprises, or both?

---

## Success Criteria

### Functional Success Criteria
- [ ] All 10 security agents are functional and produce accurate results
- [ ] Plugin installs successfully on Linux, macOS, and Windows
- [ ] Security scans complete in < 5 minutes for typical Rust projects
- [ ] Vulnerability detection has < 10% false positive rate
- [ ] All 60 examples compile and run correctly
- [ ] Integration with syntek-dev-suite works without conflicts

### Non-Functional Success Criteria
- [ ] Documentation is comprehensive and accessible to Rust beginners
- [ ] Security recommendations are actionable and clear
- [ ] Plugin updates are backwards compatible
- [ ] Community feedback is positive (> 4.5/5 stars)

### Adoption Success Criteria
- [ ] 100 installations in first month
- [ ] 5 open-source projects using the plugin
- [ ] 10 GitHub stars in first quarter
- [ ] At least 1 case study published

### Technical Success Criteria
- [ ] Zero critical bugs in first release
- [ ] Test coverage > 80% for Python tools
- [ ] CI/CD pipeline completes in < 10 minutes
- [ ] Plugin size < 10MB for distribution

---

## Next Steps

1. **Validate requirements** with potential users (Rust developers, security engineers)
2. **Create proof-of-concept** for 3 core agents (vuln-scanner, crypto-reviewer, secrets-auditor)
3. **Set up repository** and basic structure
4. **Begin Phase 1** implementation
5. **Establish update cadence** for security patterns and CVE database

---

**Recommended First Actions:**

Run `/syntek-dev-suite:stories` to create user stories for each phase.
Run `/syntek-dev-suite:sprint` to organise stories into balanced sprints.
Run `/syntek-dev-suite:setup` to initialise the `syntek-rust-security` repository.
Run `/syntek-dev-suite:review` to review this plan before implementation begins.

---

## Rust Infrastructure Agents

In addition to the security-focused agents, the Rust Security Plugin includes Rust-specific versions of syntek-dev-suite's core infrastructure agents. These agents are adapted for Rust's ecosystem, tooling, and conventions.

**Total Infrastructure Agents:** 12

### Differences from Web Stack Equivalents

Rust infrastructure agents differ fundamentally from web-stack agents:

| Aspect | Web Stack (Django/Laravel) | Rust Ecosystem |
|--------|---------------------------|----------------|
| **Version Management** | `package.json`, `pyproject.toml` | `Cargo.toml` per crate, workspace management |
| **Documentation** | JSDoc, Sphinx, phpDocumentor | rustdoc with `///` comments, cargo doc |
| **Testing** | Jest, pytest, PHPUnit | `cargo test`, doc tests, integration tests |
| **Dependency Management** | npm, pip, composer | Cargo with feature flags and optional deps |
| **Code Review** | ESLint, Pylint, PHP-CS-Fixer | clippy, rustfmt, cargo-deny |
| **Refactoring** | Codemods, AST tools | Ownership-aware refactoring, trait extraction |
| **Git Workflows** | Standard Git + package lock files | Standard Git + Cargo.lock, workspace handling |
| **GDPR Compliance** | Django middleware, Laravel policies | Rust service patterns, FFI safety |

---

## Infrastructure Agent Specifications

### 11. Version Management Agent (`/rust-security:version`)

**Purpose:** Semantic versioning for Rust crates and workspaces

**Capabilities:**
- Manage `Cargo.toml` version fields for crates
- Handle workspace version synchronisation
- Update `CHANGELOG.md` following Keep a Changelog format
- Update `VERSION-HISTORY.md` with technical details
- Sync version across multiple crates in workspace
- Git tag creation following Rust conventions (`v1.0.0`, `crate-name-v1.0.0`)
- Detect breaking API changes via public API diffing
- SemVer compliance verification

**Rust-Specific Features:**
- Workspace version coordination (workspace.package.version)
- Per-crate versioning for workspace members
- API stability guarantees (pre-1.0 vs post-1.0)
- Breaking change detection via `cargo-semver-checks`
- Crate publication readiness checks

**Integrations:**
- `cargo-semver-checks` - Detect semver violations
- `cargo-release` - Automate release workflows
- Git tags for releases
- `crates.io` version comparison

**Model:** Sonnet

**Output Files:**
- Updated `Cargo.toml` files
- `CHANGELOG.md`
- `VERSION-HISTORY.md`
- Git tags

**Example Use Cases:**
- "Bump version to 1.2.3 for the workspace"
- "Prepare version 2.0.0 release with breaking changes documented"
- "Check if API changes require major version bump"
- "Sync all workspace member versions to 0.5.0"

---

### 12. Documentation Agent (`/rust-security:docs`)

**Purpose:** Generate and maintain Rust documentation

**Capabilities:**
- Generate rustdoc comments (`///`, `//!`)
- Create module-level documentation
- Write inline code examples with doc tests
- Generate `README.md` for crates following Rust conventions
- Create API documentation structure
- Write usage examples and tutorials
- Document `unsafe` code blocks with safety invariants
- Generate feature flag documentation
- Create migration guides for breaking changes

**Rust-Specific Features:**
- Doc test generation and verification
- Markdown link checking for rustdoc
- Example code must compile and pass tests
- Intra-doc link syntax (`[`Type`]`, `[method]`)
- Module hierarchy documentation
- Feature flag conditional documentation (`#[cfg_attr(feature = "...")]`)
- FFI documentation with safety guarantees

**Integrations:**
- `cargo doc` - Generate HTML documentation
- `cargo test --doc` - Verify doc tests compile and pass
- `cargo-rdme` - Sync README from lib.rs doc comments
- `cargo-deadlinks` - Check for broken links in docs

**Model:** Sonnet

**Output Files:**
- Rust source files with documentation comments
- `README.md` per crate
- `docs/` directory with additional guides
- `examples/` directory with example code

**Example Use Cases:**
- "Document the public API for the crypto module"
- "Add doc tests for all public functions"
- "Create README from lib.rs doc comments"
- "Document safety invariants for all unsafe blocks"

**Documentation Standards:**
```rust
/// Encrypts data using AES-256-GCM.
///
/// # Arguments
///
/// * `data` - The plaintext to encrypt
/// * `key` - A 256-bit encryption key
///
/// # Returns
///
/// Returns encrypted data with authentication tag.
///
/// # Examples
///
/// ```
/// use my_crate::encrypt;
///
/// let encrypted = encrypt(b"secret", &key);
/// assert!(encrypted.is_ok());
/// ```
///
/// # Panics
///
/// Panics if key length is invalid.
///
/// # Safety
///
/// This function uses unsafe FFI calls to OpenSSL.
pub fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    // ...
}
```

---

### 13. GDPR Compliance Agent (`/rust-security:gdpr`)

**Purpose:** Implement GDPR compliance patterns in Rust services

**Capabilities:**
- Implement data protection by design patterns
- Create consent management systems
- Build data export functionality (right to data portability)
- Implement data deletion workflows (right to be forgotten)
- Audit data processing activities
- Implement data minimisation patterns
- Create privacy-preserving data structures
- Implement encryption at rest and in transit
- Generate GDPR compliance reports

**Rust-Specific Features:**
- Type-safe consent state machines
- Zero-copy data export for efficiency
- Secure deletion with memory zeroization
- Cryptographic erasure patterns
- Privacy-preserving data structures (bloom filters, homomorphic encryption)
- Compile-time enforcement of data retention policies
- FFI safety for data handling in Python/Django integration

**Integrations:**
- Rust encryption crates (`ring`, `rustls`, `sodiumoxide`)
- Database ORMs (diesel, sqlx) for audit logging
- Serde for data export serialisation
- `zeroize` crate for secure memory clearing

**Model:** Opus (requires legal/regulatory reasoning)

**Output Files:**
- `src/gdpr/` module with compliance implementations
- `docs/SECURITY/GDPR-COMPLIANCE.md`
- Data processing inventory
- Privacy policy technical documentation

**Example Use Cases:**
- "Implement right to be forgotten for user deletion"
- "Create GDPR-compliant data export in JSON format"
- "Build consent management system with versioning"
- "Audit all data processing activities for GDPR compliance"

**GDPR Implementation Patterns:**
```rust
/// GDPR-compliant user data with automatic PII protection
#[derive(Debug, Clone)]
pub struct UserData {
    pub user_id: Uuid,

    #[gdpr(pii, encrypted)]
    pub email: EncryptedString,

    #[gdpr(pii, encrypted)]
    pub name: EncryptedString,

    #[gdpr(retention = "90 days")]
    pub session_data: Vec<SessionData>,

    pub consent: ConsentState,
}

impl UserData {
    /// Export user data in GDPR-compliant format
    pub fn export_gdpr(&self) -> GdprExport {
        // Right to data portability
    }

    /// Securely delete all user data
    pub fn forget(self) -> Result<(), GdprError> {
        // Right to be forgotten with zeroization
    }
}
```

---

### 14. Support Articles Agent (`/rust-security:support-articles`)

**Purpose:** Create user-facing documentation for Rust security tools

**Capabilities:**
- Write end-user guides for security tooling
- Create troubleshooting documentation
- Write security best practices guides
- Create integration tutorials (Django + Rust, NAS encryption)
- Generate FAQ documentation
- Write security incident response guides
- Create setup and configuration guides
- Document common security patterns for users

**Rust-Specific Features:**
- Explain Rust security concepts to non-Rust developers
- Write guides for integrating Rust crypto into Python/Django
- Document Rust security tool installation and usage
- Create guides for common security pitfalls in Rust
- Write comparisons (Rust vs other language security)

**Integrations:**
- Markdown documentation
- Code examples with explanations
- Screenshots and diagrams
- Video transcripts

**Model:** Sonnet

**Output Files:**
- `docs/GUIDES/` - End-user guides
- `docs/FAQ.md` - Frequently asked questions
- `docs/TROUBLESHOOTING.md` - Common issues and solutions
- `examples/` - Working examples with explanations

**Example Use Cases:**
- "Write a guide for integrating Rust password hashing into Django"
- "Create troubleshooting guide for cargo-audit failures"
- "Write FAQ about Rust memory safety guarantees"
- "Create setup guide for fuzzing infrastructure"

**Documentation Style:**
- Plain British English, non-technical where possible
- Step-by-step instructions with code examples
- Screenshots for GUI-based tools
- Troubleshooting sections with common errors
- Links to additional resources

---

### 15. Git Workflow Agent (`/rust-security:git`)

**Purpose:** Git workflow management for Rust projects

**Capabilities:**
- Manage Cargo.lock versioning strategy
- Handle workspace Git operations
- Create conventional commits for Rust projects
- Manage Git tags for crate releases
- Handle multi-crate release branches
- Merge strategy for workspace changes
- Detect breaking changes from Git diffs
- Integration with Version Agent for releases

**Rust-Specific Features:**
- Cargo.lock commit strategy (commit for binaries, gitignore for libraries)
- Workspace member synchronisation
- Per-crate release tags (`crate-name-v1.0.0`)
- Breaking change detection from public API diffs
- Feature flag branch management
- Rust-specific .gitignore patterns
- Dependency update branch workflows

**Integrations:**
- Git CLI
- Version Agent for version bumps before commits
- `cargo-semver-checks` for breaking change detection
- GitHub/GitLab/Gitea APIs for PR creation

**Model:** Sonnet

**Output:** Git commits, tags, branches, PRs

**Example Use Cases:**
- "Create release branch for workspace version 1.0.0"
- "Commit Cargo.lock with proper strategy for this crate"
- "Detect if these changes require a major version bump"
- "Create PR for security vulnerability fix in crypto module"

**Cargo.lock Strategy:**
| Crate Type | Cargo.lock Strategy |
|------------|-------------------|
| Binary (application) | **Commit** Cargo.lock for reproducible builds |
| Library (reusable crate) | **Gitignore** Cargo.lock, let dependents control versions |
| Workspace (mixed) | Commit workspace Cargo.lock if contains binaries |

---

### 16. Refactoring Agent (`/rust-security:refactor`)

**Purpose:** Rust-specific code refactoring without changing logic

**Capabilities:**
- Extract traits from common implementations
- Refactor generics for better code reuse
- Convert concrete types to generic implementations
- Extract modules from large files
- Introduce type aliases for complex types
- Refactor error types using `thiserror`
- Reduce unsafe code blocks
- Introduce zero-cost abstractions
- Apply Rust design patterns (builder, newtype, RAII)

**Rust-Specific Features:**
- Ownership-aware refactoring (borrow checker safe)
- Trait extraction and implementation
- Generic type parameter introduction
- Lifetime elision opportunities
- Const generic refactoring
- Async/await transformation
- Unsafe code reduction strategies
- Smart pointer refactoring (Box, Rc, Arc)

**Integrations:**
- `cargo-expand` - View macro expansions
- `cargo-clippy` - Identify refactoring opportunities
- `rustfmt` - Format after refactoring
- `cargo-edit` - Manage dependencies
- `rust-analyzer` - IDE support for refactoring

**Model:** Opus (requires deep Rust understanding)

**Output:** Refactored Rust source files

**Example Use Cases:**
- "Extract common error handling into a trait"
- "Refactor this function to use generics instead of concrete types"
- "Reduce unsafe blocks in this FFI module"
- "Apply the builder pattern to this configuration struct"

**Refactoring Patterns:**

**Before (Unsafe Code):**
```rust
pub fn parse_data(data: &[u8]) -> Result<Data, Error> {
    unsafe {
        let ptr = data.as_ptr() as *const DataStruct;
        Ok((*ptr).clone())
    }
}
```

**After (Safe Refactoring):**
```rust
pub fn parse_data(data: &[u8]) -> Result<Data, Error> {
    if data.len() < std::mem::size_of::<DataStruct>() {
        return Err(Error::InvalidLength);
    }

    // Safe: bounds checked, aligned properly
    let data_struct = bytemuck::try_from_bytes::<DataStruct>(data)?;
    Ok(data_struct.clone())
}
```

---

### 17. Code Review Agent (`/rust-security:review`)

**Purpose:** Comprehensive Rust code review with security focus

**Capabilities:**
- Run `cargo clippy` with security lints
- Run `rustfmt` to verify formatting
- Review unsafe code blocks for soundness
- Check API design against Rust API guidelines
- Review error handling patterns
- Detect common Rust anti-patterns
- Review dependency choices (audited crates)
- Check for panics in critical paths
- Review FFI safety
- Verify documentation coverage

**Rust-Specific Features:**
- Unsafe code justification verification
- API stability guarantees review
- Lifetime correctness review
- Send/Sync trait safety verification
- Panic safety analysis
- Const safety review
- Feature flag hygiene
- Edition 2021 idiom adoption

**Integrations:**
- `cargo clippy` - 600+ lints including security
- `rustfmt` - Code formatting verification
- `cargo-geiger` - Unsafe code detection
- `cargo-audit` - Dependency vulnerability scanning
- `cargo-deny` - License and security policy enforcement
- `cargo-outdated` - Dependency freshness checks

**Model:** Opus (requires expert code review skills)

**Output Files:**
- `docs/REVIEWS/CODE-REVIEW-[DATE].md`
- Inline code comments for issues
- Clippy lint recommendations
- Security findings report

**Example Use Cases:**
- "Review this cryptographic module for security issues"
- "Check if all unsafe blocks have proper justification"
- "Review this public API against Rust API guidelines"
- "Verify FFI safety in this Python binding"

**Review Checklist:**
- [ ] All unsafe blocks have safety comments
- [ ] Public API follows Rust naming conventions
- [ ] Error types implement `std::error::Error`
- [ ] No panics in library code (use Result)
- [ ] Documentation for all public items
- [ ] Examples compile and pass tests
- [ ] No deprecated dependencies
- [ ] Feature flags documented
- [ ] Cargo.toml metadata complete
- [ ] CI tests pass (cargo test, clippy, fmt)

---

### 18. Test Writer Agent (`/rust-security:test-writer`)

**Purpose:** Generate comprehensive tests for Rust code

**Capabilities:**
- Write unit tests (`#[test]`)
- Generate integration tests in `tests/`
- Create doc tests in documentation comments
- Write property-based tests with `proptest`
- Generate fuzzing harnesses
- Write benchmark tests with `criterion`
- Create mock implementations
- Write example code in `examples/`
- Test error conditions and edge cases

**Rust-Specific Features:**
- Doc test generation (tests in documentation)
- Property-based testing for invariants
- Fuzzing integration (cargo-fuzz)
- Compile-fail tests for type safety
- Feature flag test coverage
- Async test generation (tokio, async-std)
- Unsafe code testing
- FFI boundary testing

**Integrations:**
- `cargo test` - Run all tests
- `proptest` - Property-based testing
- `cargo-fuzz` - Fuzzing harness generation
- `criterion` - Benchmarking
- `mockall` - Mock generation
- `cargo-tarpaulin` - Code coverage

**Model:** Sonnet

**Output Files:**
- Unit tests in source files
- Integration tests in `tests/`
- Doc tests in documentation
- Fuzzing harnesses in `fuzz/`
- Benchmarks in `benches/`
- Examples in `examples/`

**Example Use Cases:**
- "Write comprehensive tests for the encryption module"
- "Generate property-based tests for the parser"
- "Create doc tests for all public functions"
- "Write integration tests for the API client"

**Test Pattern Examples:**

**Unit Test:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let key = generate_key();
        let plaintext = b"secret data";

        let ciphertext = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&ciphertext, &key).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    #[should_panic(expected = "Invalid key length")]
    fn test_invalid_key_panics() {
        let bad_key = [0u8; 10]; // Invalid length
        encrypt(b"data", &bad_key).unwrap();
    }
}
```

**Property-Based Test:**
```rust
#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_encryption_never_panics(data: Vec<u8>) {
            let key = generate_key();
            let _ = encrypt(&data, &key);
        }

        #[test]
        fn test_roundtrip_preserves_data(data: Vec<u8>) {
            let key = generate_key();
            let encrypted = encrypt(&data, &key).unwrap();
            let decrypted = decrypt(&encrypted, &key).unwrap();
            prop_assert_eq!(data, decrypted);
        }
    }
}
```

---

### 19. Benchmarking Agent (`/rust-security:benchmark`)

**Purpose:** Performance benchmarking and analysis for Rust code

**Capabilities:**
- Create criterion.rs benchmarks
- Generate performance comparison reports
- Identify performance regressions
- Create flamegraphs for profiling
- Analyse cryptographic operation timing
- Detect timing attack vulnerabilities
- Compare algorithm implementations
- Generate performance documentation

**Rust-Specific Features:**
- Criterion.rs integration for statistical benchmarking
- Compile-time vs runtime performance tradeoffs
- Const evaluation benchmarking
- SIMD optimisation opportunities
- Zero-cost abstraction verification
- Allocation profiling
- Cache performance analysis

**Integrations:**
- `criterion` - Benchmarking framework
- `cargo-flamegraph` - Generate flamegraphs
- `cargo-asm` - View assembly output
- `perf` - Linux performance counters
- `valgrind` - Memory profiling
- `cargo-llvm-lines` - Compile time profiling

**Model:** Sonnet

**Output Files:**
- Benchmarks in `benches/`
- `docs/PERFORMANCE/BENCHMARKS.md`
- Flamegraph SVG files
- Performance comparison reports

**Example Use Cases:**
- "Benchmark encryption performance for different key sizes"
- "Compare SIMD vs scalar implementation performance"
- "Detect timing attack vulnerabilities in this crypto function"
- "Profile memory allocations in the parser"

**Benchmark Example:**
```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_encryption(c: &mut Criterion) {
    let key = generate_key();
    let data = vec![0u8; 1024 * 1024]; // 1MB

    c.bench_function("encrypt 1MB", |b| {
        b.iter(|| encrypt(black_box(&data), black_box(&key)))
    });
}

criterion_group!(benches, benchmark_encryption);
criterion_main!(benches);
```

---

### 20. Dependency Manager Agent (`/rust-security:deps`)

**Purpose:** Cargo dependency management and security

**Capabilities:**
- Manage feature flags and optional dependencies
- Analyse workspace dependency graphs
- Update dependencies safely
- Check for duplicate dependencies
- Manage dependency versions
- Configure cargo-deny policies
- Audit dependency licenses
- Track transitive dependency security

**Rust-Specific Features:**
- Feature flag optimisation
- Workspace dependency consolidation
- Minimal versions testing
- Platform-specific dependencies
- Build dependency separation
- Patch section management
- Dependency aliasing
- Cargo resolver version selection

**Integrations:**
- `cargo-edit` - Add/remove/update dependencies
- `cargo-tree` - Visualise dependency tree
- `cargo-deny` - Dependency policy enforcement
- `cargo-outdated` - Check for updates
- `cargo-audit` - Security vulnerabilities
- `cargo-duplicate` - Find duplicate dependencies
- `cargo-minimal-versions` - Test minimum supported versions

**Model:** Sonnet

**Output Files:**
- Updated `Cargo.toml` files
- `docs/DEPENDENCIES/AUDIT.md`
- `deny.toml` policy configuration
- Dependency update reports

**Example Use Cases:**
- "Update all dependencies to latest compatible versions"
- "Optimise feature flags to reduce compile time"
- "Remove duplicate dependencies from workspace"
- "Audit all dependencies for security vulnerabilities"

**Dependency Best Practices:**
```toml
[dependencies]
# Use specific versions for security-critical crates
ring = "0.17"

# Optional dependencies reduce default build size
serde = { version = "1.0", optional = true }

# Platform-specific dependencies
[target.'cfg(windows)'.dependencies]
winapi = "0.3"

[features]
default = ["std"]
std = ["serde/std"]
json = ["serde", "serde_json"]
```

---

### 21. Unsafe Code Minimiser Agent (`/rust-security:unsafe-minimiser`)

**Purpose:** Reduce and validate unsafe code blocks

**Capabilities:**
- Identify reducible unsafe blocks
- Replace unsafe code with safe alternatives
- Verify safety invariants for required unsafe
- Document safety requirements
- Suggest safe library alternatives
- Audit unsafe FFI boundaries
- Check for undefined behaviour patterns
- Validate Send/Sync implementations

**Rust-Specific Features:**
- Ownership-based safety verification
- Lifetime correctness analysis
- FFI safety patterns (null checks, bounds checking)
- Safe abstraction design
- Miri integration for UB detection
- Stacked borrows verification
- Aliasing model compliance

**Integrations:**
- `cargo-geiger` - Count unsafe code
- `miri` - Detect undefined behaviour
- `cargo-careful` - Extra runtime checks
- `loom` - Concurrency testing
- `valgrind` - Memory safety verification

**Model:** Opus (requires expert unsafe reasoning)

**Output Files:**
- Refactored source files with reduced unsafe
- `docs/SECURITY/UNSAFE-AUDIT.md`
- Safety documentation for remaining unsafe

**Example Use Cases:**
- "Audit all unsafe blocks in this crate"
- "Replace unsafe pointer arithmetic with safe alternatives"
- "Verify FFI safety in Python bindings"
- "Document safety invariants for all unsafe code"

**Unsafe Reduction Pattern:**

**Before:**
```rust
pub fn read_u32(data: &[u8]) -> u32 {
    unsafe {
        let ptr = data.as_ptr() as *const u32;
        *ptr
    }
}
```

**After:**
```rust
pub fn read_u32(data: &[u8]) -> Result<u32, Error> {
    if data.len() < 4 {
        return Err(Error::InsufficientData);
    }

    // Safe: bounds checked, alignment verified
    let bytes: [u8; 4] = data[..4].try_into()?;
    Ok(u32::from_le_bytes(bytes))
}
```

---

### 22. API Designer Agent (`/rust-security:api-designer`)

**Purpose:** Design public APIs following Rust API guidelines

**Capabilities:**
- Design idiomatic Rust APIs
- Apply Rust naming conventions
- Design error types with proper hierarchy
- Create builder patterns for complex types
- Design trait-based abstractions
- Plan generic vs concrete types
- Design async APIs
- Plan backwards compatibility strategy
- Create type state patterns for safety

**Rust-Specific Features:**
- Zero-cost abstraction design
- Generic API design with trait bounds
- Lifetime parameter planning
- Associated type design
- Extension trait patterns
- Sealed trait implementation
- Const API design
- Feature flag API organisation

**Integrations:**
- Rust API Guidelines checklist
- `cargo-semver-checks` for compatibility
- `cargo-public-api` for API diffing
- Rustdoc for documentation generation

**Model:** Opus (requires expert API design skills)

**Output Files:**
- `docs/API/DESIGN.md` - API design documentation
- `docs/API/MIGRATION-GUIDES.md` - Upgrade guides
- Trait definitions and type signatures
- Example usage code

**Example Use Cases:**
- "Design a builder API for the configuration struct"
- "Create a trait abstraction for storage backends"
- "Design error types for the cryptographic module"
- "Plan API evolution for 1.0 to 2.0 migration"

**API Design Patterns:**

**Builder Pattern:**
```rust
pub struct ConfigBuilder {
    host: Option<String>,
    port: Option<u16>,
    timeout: Duration,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        Self {
            host: None,
            port: None,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn build(self) -> Result<Config, ConfigError> {
        Ok(Config {
            host: self.host.ok_or(ConfigError::MissingHost)?,
            port: self.port.unwrap_or(8080),
            timeout: self.timeout,
        })
    }
}
```

**Type State Pattern (Compile-Time Safety):**
```rust
pub struct Connection<S> {
    _state: PhantomData<S>,
}

pub struct Disconnected;
pub struct Connected;

impl Connection<Disconnected> {
    pub fn new() -> Self { /* ... */ }

    pub fn connect(self) -> Connection<Connected> {
        // Only valid transition
    }
}

impl Connection<Connected> {
    pub fn send(&self, data: &[u8]) -> Result<(), Error> {
        // Can only send when connected
    }
}
```

---

## Updated Agent Count and Implementation Phases

### Agent Summary

**Total Agents: 22**

| Category | Agents | Models |
|----------|--------|--------|
| **Security Agents** | 10 | 3 Opus, 7 Sonnet |
| **Infrastructure Agents** | 12 | 3 Opus, 9 Sonnet |

**Security Agents:**
1. Threat Modeller (Opus)
2. Vulnerability Scanner (Sonnet)
3. Crypto Reviewer (Opus)
4. Memory Safety (Sonnet)
5. Fuzzer (Sonnet)
6. Secrets Auditor (Sonnet)
7. Supply Chain (Sonnet)
8. Pentester (Opus)
9. Binary Analyser (Sonnet)
10. Compliance Auditor (Sonnet)

**Infrastructure Agents:**
11. Version Management (Sonnet)
12. Documentation (Sonnet)
13. GDPR Compliance (Opus)
14. Support Articles (Sonnet)
15. Git Workflow (Sonnet)
16. Refactoring (Opus)
17. Code Review (Opus)
18. Test Writer (Sonnet)
19. Benchmarking (Sonnet)
20. Dependency Manager (Sonnet)
21. Unsafe Code Minimiser (Opus)
22. API Designer (Opus)

---

## Updated Implementation Phases

### Phase 3: Specialised Security and Infrastructure Agents
**Duration:** 6 weeks (increased from 4 weeks)

**Tasks:**
- [ ] Create 10 security agent definition files in `agents/`
- [ ] Create 12 infrastructure agent definition files in `agents/`
- [ ] Create corresponding command files in `commands/` (22 total)
- [ ] Test each agent with sample Rust projects
- [ ] Create agent integration tests (agents calling other agents)
- [ ] Document agent interaction patterns

**Deliverable:** 22 fully functional agents with distinct specialisations

**Files Created:**
- 22 agent definition files in `agents/`
- 22 command files in `commands/`

---

### Phase 5: Templates and Examples
**Duration:** 4 weeks (increased from 3 weeks)

**Tasks:**
- [ ] Create 5 project templates in `templates/`
- [ ] Create 60 security examples organised by domain
- [ ] **Create 40 infrastructure examples for Rust patterns**
- [ ] Write comprehensive documentation for each example
- [ ] Add code snippets with inline security comments
- [ ] Test all examples compile and run
- [ ] Create quick reference guides in `docs/GUIDES/`

**Deliverable:** Complete library of templates and 100 examples

**New Infrastructure Examples (40 total):**

1. **Version Management Examples** (4)
   - Workspace version synchronisation
   - Per-crate versioning strategies
   - Breaking change detection workflow
   - Release tag creation

2. **Documentation Examples** (5)
   - Rustdoc comment patterns
   - Doc test generation
   - API documentation structure
   - README generation from lib.rs
   - Safety documentation for unsafe

3. **GDPR Compliance Examples** (6)
   - Consent management system
   - Data export (right to portability)
   - Data deletion (right to be forgotten)
   - Encrypted PII storage
   - Audit logging
   - Privacy-preserving data structures

4. **Git Workflow Examples** (3)
   - Cargo.lock strategy per project type
   - Multi-crate release workflow
   - Feature flag branching

5. **Refactoring Examples** (6)
   - Trait extraction
   - Generic introduction
   - Unsafe code reduction
   - Error type refactoring with thiserror
   - Builder pattern application
   - Type state pattern implementation

6. **Code Review Examples** (4)
   - Clippy integration in CI
   - Unsafe code review checklist
   - API guideline compliance
   - FFI safety review

7. **Testing Examples** (6)
   - Unit test patterns
   - Integration test structure
   - Doc test best practices
   - Property-based testing
   - Fuzzing harness creation
   - Async test patterns

8. **Benchmarking Examples** (3)
   - Criterion benchmark setup
   - Flamegraph generation
   - Timing attack detection

9. **Dependency Management Examples** (3)
   - Feature flag optimisation
   - Workspace dependency consolidation
   - cargo-deny configuration

**Total Examples: 100 (60 security + 40 infrastructure)**

---

## Additional Rust-Specific Templates

### New Templates

| Template | Purpose |
|----------|---------|
| `rust-workspace-security.md` | Multi-crate workspace security setup |
| `rust-ffi-python.md` | PyO3 FFI security template |
| `rust-async-security.md` | Tokio/async-std security patterns |
| `rust-no-std-security.md` | Embedded no_std security |

**Total Templates: 9 (5 original + 4 new)**

---

## Updated Timeline

| Phase | Original Duration | New Duration | Change |
|-------|------------------|--------------|--------|
| Phase 1 | 1 week | 1 week | - |
| Phase 2 | 2 weeks | 2 weeks | - |
| **Phase 3** | **4 weeks** | **6 weeks** | **+2 weeks** (22 agents) |
| Phase 4 | 2 weeks | 2 weeks | - |
| **Phase 5** | **3 weeks** | **4 weeks** | **+1 week** (100 examples) |
| Phase 6 | 1 week | 1 week | - |
| Phase 7 | 1 week | 1 week | - |
| **TOTAL** | **14 weeks** | **17 weeks** | **+3 weeks** |

---

## Updated Success Criteria

### Functional Success Criteria
- [ ] All **22** agents (10 security + 12 infrastructure) are functional
- [ ] Plugin installs successfully on Linux, macOS, and Windows
- [ ] Security scans complete in < 5 minutes for typical Rust projects
- [ ] Vulnerability detection has < 10% false positive rate
- [ ] All **100** examples (60 security + 40 infrastructure) compile and run correctly
- [ ] Integration with syntek-dev-suite works without conflicts

### Infrastructure Agent Success Criteria
- [ ] Version management correctly handles workspace synchronisation
- [ ] Documentation agent generates passing doc tests
- [ ] GDPR agent implements all required data rights (export, deletion)
- [ ] Git agent uses correct Cargo.lock strategy per project type
- [ ] Refactoring agent reduces unsafe code without breaking logic
- [ ] Code review agent catches common security and API issues
- [ ] Test writer generates comprehensive test coverage (>80%)
- [ ] Benchmarking agent detects timing attack vulnerabilities
- [ ] Dependency manager eliminates duplicate dependencies
- [ ] Unsafe minimiser reduces unsafe blocks by ≥50% where possible
- [ ] API designer follows all Rust API guidelines

---

## Updated Open Questions

### Infrastructure Questions
- [ ] Should the Version Agent support automatic changelog generation from Git history?
- [ ] Should the Documentation Agent integrate with mdBook for comprehensive docs sites?
- [ ] Should the GDPR Agent generate compliance reports for regulators?
- [ ] Should the Refactoring Agent support automated migrations for edition upgrades?
- [ ] Should the Test Writer Agent auto-generate mocks for traits?
- [ ] Should the Benchmarking Agent integrate with continuous benchmarking services?
- [ ] Should the API Designer Agent suggest feature flag organisation strategies?

---

## Agent Interaction Patterns

Infrastructure agents frequently call security agents and vice versa:

| Caller Agent | Called Agent | Use Case |
|-------------|--------------|----------|
| Version | Git | Tag creation for releases |
| Git | Version | Bump version before commit |
| Docs | Test Writer | Generate doc tests |
| Code Review | Crypto Reviewer | Review cryptographic code |
| Code Review | Memory Safety | Audit unsafe blocks |
| Refactor | Unsafe Minimiser | Reduce unsafe after refactoring |
| Refactor | Code Review | Verify refactoring correctness |
| API Designer | Code Review | Verify API guideline compliance |
| Test Writer | Fuzzer | Create fuzzing harnesses |
| Dependency Manager | Vuln Scanner | Audit updated dependencies |
| GDPR | Crypto Reviewer | Verify encryption implementations |

---

**Infrastructure Integration Complete.** The Rust Security Plugin now includes comprehensive infrastructure agents adapted specifically for the Rust ecosystem.
