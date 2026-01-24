# Syntek Rust Security Plugin

Comprehensive Rust security tooling for Claude Code - custom
encryption/decryption systems, server security wrappers, infrastructure
automation, and memory-safe development.

## Overview

This plugin extends Claude Code with specialized security capabilities for
building Rust-based security infrastructure, covering:

### Core Security

- Memory safety and unsafe code auditing
- Cryptographic implementation review (AES-GCM, ChaCha20-Poly1305, key
  derivation)
- Supply chain security analysis
- Vulnerability scanning (cargo-audit, cargo-deny, cargo-geiger)
- Threat modeling (STRIDE)
- Binary hardening verification
- Fuzzing infrastructure (libfuzzer, AFL++, honggfuzz)
- Compliance auditing (OWASP/CWE)

### Custom Encryption & Memory Security

- Server-side and client-side encryption/decryption implementations
- Memory zeroisation patterns (zeroize, secrecy crates)
- Secure memory storage for sensitive data
- HashiCorp Vault integration for secrets management

### FFI Integration (Full-Stack Apps)

- **Django/Python**: PyO3 integration for backend encryption
- **Next.js/React**: Neon/wasm-bindgen for frontend encryption
- **React Native**: UniFFI for mobile encryption
- **GraphQL**: Secure middleware patterns
- **Redis/Valkey**: Secure connection handling

### AI Gateway

- Unified Rust gateway for AI providers (Anthropic, OpenAI, Gemini, Azure,
  Perplexity)
- Rate limiting, circuit breakers, and retry logic
- Request/response logging and cost tracking
- Streaming support with backpressure handling

### Server & Infrastructure Security

- SSH access wrappers with comprehensive logging
- Cloudflare Origin/Edge certificate management (not Let's Encrypt)
- Certificate rotation with Vault integration
- Firewall/iptables Rust bindings
- Docker security hardening
- Cloudflare API integration (DNS, Workers, R2, certificates)
- Backblaze B2 encrypted backup patterns
- Token/secret rotation automation

### Server Stack Configuration

- Nginx security-hardened configuration generation
- Gunicorn + Uvicorn secure setup for Django/FastAPI
- Redis/Valkey secure configuration
- Systemd service hardening

### DIY Security Appliances (Router/NAS/Homeserver/Gateway)

Build Rust-based security wrappers that actively protect your infrastructure:

- **Router Security Wrapper**: Deep packet inspection, malicious IP/domain
  blocking, IDS/IPS, traffic anomaly detection
- **NAS Security Wrapper**: Real-time file scanning, malware quarantine,
  ransomware detection, integrity monitoring
- **Homeserver Security Wrapper**: Process monitoring, application firewall,
  rootkit detection, privilege escalation prevention
- **Internet Gateway Wrapper**: HTTPS inspection proxy, malicious link blocking,
  download scanning, phishing detection
- **Threat Intelligence**: Integration with threat feeds, YARA rules, IOC
  matching
- **DNS Security**: DoH/DoT proxy, sinkholing, ad blocking at network level

---

## Agents & Commands Reference

Each command invokes a specialized agent. Commands use the format
`/rust-security:<command>` or the shorthand `/<command>`.

### Setup

#### `/init` (project-initializer)

Initializes a Rust project with the Syntek Rust Security plugin. Creates a
`.claude/` directory containing project-specific Claude instructions, security
guidelines, local settings, and copies the plugin tools. Run this first in any
new Rust project to enable all security features.

---

### Security Analysis

#### `/threat-model` (threat-modeller) [Opus]

Performs comprehensive STRIDE threat analysis on your Rust application.
Identifies potential Spoofing, Tampering, Repudiation, Information Disclosure,
Denial of Service, and Elevation of Privilege threats. Generates a threat model
document with attack trees, trust boundaries, and prioritized mitigations
specific to Rust's memory safety guarantees.

#### `/vuln-scan` (vuln-scanner) [Sonnet]

Scans your project's dependencies for known security vulnerabilities using
cargo-audit and cargo-deny. Queries the RustSec Advisory Database, reports CVE
identifiers with CVSS scores, and suggests upgrade paths or patches. Ideal for
CI/CD integration and pre-release security checks.

#### `/crypto-review` (crypto-reviewer) [Opus]

Reviews cryptographic implementations for correctness and security. Checks for
timing side-channels, proper use of authenticated encryption (AES-GCM,
ChaCha20-Poly1305), secure key derivation (Argon2, scrypt), constant-time
comparisons, and correct nonce/IV handling. Flags dangerous patterns like ECB
mode or weak RNGs.

#### `/memory-audit` (memory-safety) [Sonnet]

Audits unsafe code blocks and memory safety patterns. Verifies that all unsafe
blocks have proper `// SAFETY:` comments, checks for use-after-free potential,
buffer overflows, and uninitialized memory access. Integrates with cargo-geiger
to measure unsafe code surface area across dependencies.

#### `/fuzz-setup` (fuzzer) [Sonnet]

Sets up fuzzing infrastructure for your Rust project using cargo-fuzz with
libFuzzer, AFL++, or honggfuzz backends. Generates fuzz harnesses for parsing
functions, serialization code, and cryptographic operations. Configures corpus
directories and provides guidance on effective fuzzing strategies.

#### `/scan-secrets` (secrets-auditor) [Sonnet]

Detects hardcoded secrets, API keys, passwords, and credentials in source code
and git history. Scans for high-entropy strings, common secret patterns, and
leaked credentials. Recommends migration to environment variables, HashiCorp
Vault, or the secrecy crate for runtime secret handling.

#### `/supply-chain-audit` (supply-chain) [Sonnet]

Analyzes dependency supply chain security risks. Checks for typosquatting,
unmaintained packages, excessive dependency trees, and suspicious version
changes. Integrates with cargo-vet for provenance verification and generates a
software bill of materials (SBOM).

#### `/pentest-tools` (pentester) [Opus]

Develops custom penetration testing tools in Rust for authorized security
assessments. Generates network scanners, protocol fuzzers, exploit frameworks,
and security testing utilities. Emphasizes memory-safe implementations and
proper error handling for reliable security tooling.

#### `/binary-check` (binary-analyser) [Sonnet]

Verifies binary hardening and security features in compiled Rust executables.
Checks for ASLR, DEP/NX, stack canaries, RELRO, PIE, and Fortify Source. Reports
on symbol stripping, debug info, and recommends Cargo profile settings for
security-hardened release builds.

#### `/compliance-report` (compliance-auditor) [Sonnet]

Generates compliance reports mapping vulnerabilities to OWASP Top 10 and CWE
categories. Calculates CVSS scores, produces executive summaries, and creates
audit-ready documentation. Supports JSON and Markdown output for integration
with security dashboards and compliance workflows.

---

### Code Quality & Review

#### `/review-code` (rust-review) [Opus]

Performs expert-level code review with security focus. Runs clippy with pedantic
lints, checks rustfmt compliance, and manually reviews for logic errors, race
conditions, and security anti-patterns. Provides actionable feedback on
ownership patterns, error handling, and API design.

#### `/refactor-code` (rust-refactor) [Opus]

Refactors Rust code to improve safety, performance, and maintainability.
Optimizes ownership and borrowing patterns, eliminates unnecessary clones,
converts unwrap calls to proper error handling, and applies idiomatic Rust
patterns while preserving behavior.

#### `/minimize-unsafe` (rust-unsafe-minimiser) [Opus]

Systematically reduces unsafe code surface area. Identifies unsafe blocks that
can be replaced with safe alternatives, encapsulates necessary unsafe code
behind safe APIs, and ensures remaining unsafe blocks have proper documentation
and minimal scope.

#### `/design-api` (rust-api-designer) [Opus]

Guides public API design following the Rust API Guidelines. Reviews type
signatures for ergonomics, suggests builder patterns, recommends appropriate
trait implementations (From, Into, AsRef), and ensures APIs are impossible to
misuse through Rust's type system.

---

### Testing & Performance

#### `/write-tests` (rust-test-writer) [Sonnet]

Generates comprehensive test suites including unit tests, integration tests, doc
tests, and property-based tests using proptest or quickcheck. Creates test
fixtures, mocks external dependencies, and ensures security-critical code paths
have thorough coverage.

#### `/benchmark` (rust-benchmarker) [Sonnet]

Sets up performance benchmarking using criterion.rs. Creates benchmark harnesses
for hot paths, cryptographic operations, and parsing code. Generates statistical
reports with confidence intervals and detects performance regressions in CI/CD
pipelines.

---

### Documentation & Versioning

#### `/generate-docs` (rust-docs) [Sonnet]

Generates comprehensive documentation using rustdoc. Creates module-level docs,
adds examples to public APIs, ensures doc tests compile and pass, and generates
documentation coverage reports. Produces security-focused documentation
highlighting safe usage patterns.

#### `/version-bump` (rust-version) [Sonnet]

Manages semantic versioning for Cargo.toml following SemVer 2.0.0. Detects
breaking changes using cargo-semver-checks, updates version numbers, generates
CHANGELOG.md entries, and creates git tags. Ensures security fixes are properly
versioned.

#### `/write-support-article` (rust-support-articles) [Sonnet]

Creates user-facing help documentation and support articles. Generates
installation guides, troubleshooting documentation, FAQ pages, and security best
practices guides for end users of your Rust libraries or applications.

#### `/git-workflow` (rust-git) [Sonnet]

Manages git workflows for Rust projects. Implements branch strategies (GitFlow,
GitHub Flow, trunk-based), configures commit hooks for clippy and rustfmt,
generates pull request templates with security checklists, and automates release
workflows.

---

### Dependency Management

#### `/manage-deps` (rust-dependency-manager) [Sonnet]

Manages Cargo dependencies and feature flags. Identifies outdated dependencies,
removes unused crates, optimizes feature flag combinations to reduce compile
times and binary size, and ensures minimal dependency surface for security.

---

### Compliance

#### `/gdpr-check` (rust-gdpr) [Opus]

Verifies GDPR compliance patterns in Rust applications. Reviews data handling
for consent management, right to erasure implementation, data portability,
breach notification patterns, and privacy by design. Generates compliance
documentation and code recommendations.

---

### Planned Commands

The following commands are planned for future releases:

#### Encryption & Memory

| Command          | Agent                       | Description                                                                                                                                                                                                 |
| ---------------- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/encrypt-setup` | encryption-architect [Opus] | Designs and implements custom encryption systems using AES-GCM, ChaCha20-Poly1305, or XChaCha20. Creates key management infrastructure, envelope encryption patterns, and secure key derivation.            |
| `/decrypt-setup` | encryption-architect [Opus] | Implements corresponding decryption infrastructure with authenticated decryption, key unwrapping, and secure error handling that doesn't leak information through timing or error messages.                 |
| `/zeroize-audit` | zeroize-auditor [Opus]      | Audits memory zeroisation patterns to ensure sensitive data is securely wiped. Verifies zeroize crate usage, checks for compiler optimizations that might skip zeroing, and reviews secrecy crate patterns. |

#### Secrets & Vault

| Command         | Agent                     | Description                                                                                                                                                                                                    |
| --------------- | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/vault-setup`  | vault-integrator [Sonnet] | Configures HashiCorp Vault integration using the vaultrs crate. Sets up authentication methods, secret engines, dynamic credentials, and implements secure secret retrieval patterns with caching and renewal. |
| `/token-rotate` | token-rotator [Sonnet]    | Automates rotation of API keys, tokens, and credentials. Implements zero-downtime rotation strategies, updates HashiCorp Vault, and manages credential lifecycle across services.                              |

#### Infrastructure

| Command             | Agent                          | Description                                                                                                                                                                                         |
| ------------------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/ssh-wrapper`      | ssh-wrapper-generator [Sonnet] | Generates Rust SSH access wrappers with comprehensive logging, command filtering, session recording, and access control. Creates audit trails for compliance requirements.                          |
| `/cert-rotate`      | cert-manager [Sonnet]          | Manages Cloudflare Origin/Edge certificate rotation. Automates certificate renewal, updates HashiCorp Vault, and coordinates certificate deployment across servers without downtime.                |
| `/cloudflare-setup` | cloudflare-manager [Sonnet]    | Integrates with Cloudflare APIs for DNS management, Workers deployment, R2 storage, and certificate operations. Generates type-safe API clients using cloudflare-rs.                                |
| `/docker-harden`    | docker-security [Sonnet]       | Hardens Docker configurations with security best practices. Generates secure Dockerfiles, implements least-privilege containers, configures seccomp profiles, and sets up container image scanning. |
| `/backup-setup`     | backup-manager [Sonnet]        | Configures encrypted backup systems using Backblaze B2. Implements client-side encryption before upload, manages backup rotation, and provides secure restore procedures.                           |
| `/firewall-setup`   | firewall-integrator [Sonnet]   | Creates Rust bindings for firewall management (iptables, nftables). Generates rule sets, implements dynamic blocking, and provides programmatic firewall control.                                   |
| `/server-harden`    | server-hardener [Opus]         | Comprehensive server security hardening. Reviews SSH configuration, implements fail2ban patterns, configures audit logging, sets up intrusion detection, and generates hardening checklists.        |
| `/ffi-audit`        | ffi-security-reviewer [Opus]   | Audits FFI boundaries for security issues. Reviews PyO3, Neon, UniFFI, and wasm-bindgen code for memory safety, null pointer handling, and data validation across language boundaries.              |

#### AI Gateway

| Command             | Agent                       | Description                                                                                                                                                                                  |
| ------------------- | --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/ai-gateway-setup` | ai-gateway-architect [Opus] | Designs unified AI API gateway architecture. Plans routing strategies, rate limiting, circuit breakers, cost tracking, and streaming support for multiple AI providers.                      |
| `/ai-provider-add`  | ai-gateway-builder [Sonnet] | Adds AI provider integrations (Anthropic, OpenAI, Gemini, Azure, Perplexity) to the gateway. Generates type-safe clients, implements retry logic, and configures provider-specific features. |

#### Server Stack

| Command            | Agent                          | Description                                                                                                                                                                                |
| ------------------ | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `/nginx-config`    | nginx-configurator [Sonnet]    | Generates security-hardened Nginx configurations. Implements TLS best practices, security headers, rate limiting, and WAF patterns. Creates configs optimized for Django/FastAPI backends. |
| `/gunicorn-config` | gunicorn-configurator [Sonnet] | Configures Gunicorn with Uvicorn workers for Django/FastAPI. Sets secure defaults, implements graceful shutdown, configures worker limits, and integrates with systemd.                    |
| `/redis-config`    | redis-configurator [Sonnet]    | Generates secure Redis/Valkey configurations. Implements TLS, ACLs, password authentication, persistence settings, and memory limits. Creates Rust connection pool configurations.         |
| `/systemd-harden`  | systemd-hardener [Sonnet]      | Creates hardened systemd service files. Implements sandboxing (namespaces, seccomp), capability dropping, resource limits, and security-focused service configurations.                    |

#### DIY Security Appliances

| Command                     | Agent                                | Description                                                                                                                                                      |
| --------------------------- | ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/router-security-init`     | router-security-builder [Sonnet]     | Initializes a Rust router security wrapper project with deep packet inspection, malicious traffic blocking, IDS/IPS capabilities, and traffic anomaly detection. |
| `/nas-security-init`        | nas-security-builder [Sonnet]        | Creates a NAS security wrapper with real-time file scanning, malware quarantine, ransomware detection (entropy analysis), and file integrity monitoring.         |
| `/homeserver-security-init` | homeserver-security-builder [Sonnet] | Builds homeserver protection with process monitoring, application-level firewall, rootkit detection, and privilege escalation prevention.                        |
| `/gateway-security-init`    | gateway-security-builder [Sonnet]    | Implements internet gateway security with HTTPS inspection proxy, download scanning, phishing detection, and content filtering.                                  |
| `/malware-scanner-setup`    | malware-scanner-builder [Sonnet]     | Sets up malware detection engine with ClamAV integration, YARA rule support, custom signature matching, and quarantine workflows.                                |
| `/ids-setup`                | intrusion-detector-builder [Sonnet]  | Configures intrusion detection with Snort/Suricata-compatible rule processing, alert management, and automatic blocking capabilities.                            |
| `/dns-proxy-setup`          | dns-security-builder [Sonnet]        | Creates secure DNS proxy with DoH/DoT support, malicious domain sinkholing, query logging, and ad/tracker blocking at network level.                             |
| `/threat-feeds-setup`       | threat-intel-integrator [Sonnet]     | Integrates threat intelligence feeds including malicious IP blocklists, domain reputation, YARA rules, and IOC (Indicators of Compromise) matching.              |
| `/dpi-setup`                | network-security-architect [Opus]    | Designs deep packet inspection engine with protocol dissection, payload analysis, and real-time traffic classification for threat detection.                     |
| `/quarantine-setup`         | nas-security-builder [Sonnet]        | Implements file quarantine system with isolated storage, admin notifications, analysis workflows, and secure restoration procedures.                             |

---

## Installation

```bash
claude-code plugin install syntek-rust-security
```

## Requirements

- Claude Code >= 1.0.0
- syntek-dev-suite >= 1.0.0
- Rust >= 1.92.0 (for latest security features)

## Quick Start

Initialize the plugin in your Rust project:

```bash
# Navigate to your Rust project
cd my-rust-project

# Initialize the Syntek Rust Security plugin
/rust-security:init
```

This creates a `.claude/` directory with:

- `CLAUDE.md` - Project-specific Claude instructions
- `SYNTEK-RUST-SECURITY-GUIDE.md` - Security guidelines and patterns
- `settings.local.json` - Local Claude Code settings
- `plugins/src/*.rs` - Security analysis tools

## Usage

Invoke agents directly or use the shorthand commands:

```bash
# Initialize the plugin
/init

# Run security analysis
/vuln-scan
/crypto-review
/memory-audit
/threat-model

# Generate compliance report
/compliance-report

# Set up fuzzing
/fuzz-setup
```

## Use Cases

This plugin is designed to help you build:

### Security Infrastructure

1. **Server Security Wrappers** - For hosting websites, cloud servers, Backblaze
   backups
2. **SSH Security** - Access management and comprehensive logging
3. **Custom Encryption/Decryption** - Server-side and client-side
   implementations
4. **Memory Zeroisation** - Secure memory wiping (zeroize patterns)
5. **Secure Memory Storage** - Protected storage for sensitive data
6. **Penetration Testing Tools** - Custom security testing infrastructure

### DIY Security Appliances (Router/NAS/Homeserver)

7. **Router Security Wrapper** - Deep packet inspection, IDS/IPS, malicious
   traffic blocking
8. **NAS Security Wrapper** - File scanning, malware quarantine, ransomware
   detection
9. **Homeserver Security Wrapper** - Process monitoring, rootkit detection, app
   firewall
10. **Internet Gateway Wrapper** - HTTPS inspection, download scanning, phishing
    blocking
11. **DNS Security Proxy** - DoH/DoT, sinkholing, ad blocking at network level

### Integration & Automation

12. **AI API Gateway** - Unified gateway for Anthropic, OpenAI, Gemini, Azure,
    Perplexity
13. **CLI Tooling** - Cloudflare, Docker, SSH, certificate and token management
14. **Server Stack Config** - Nginx, Gunicorn+Uvicorn, Redis/Valkey secure
    configuration

### Full-Stack Integration

The plugin supports FFI integration with your tech stack:

- **Backend**: Django/Postgres/GraphQL with Redis/Valkey
- **Web Frontend**: NextJS/NodeJS/React/TS/Tailwind
- **Mobile**: React Native/TS/Nativewind
- **Secrets**: HashiCorp Vault retrieval

### Certificate Management

Uses **Cloudflare Origin/Edge certificates** (not Let's Encrypt):

- Cloudflare Origin CA for origin server certificates
- Edge certificates managed via Cloudflare API
- Automatic rotation with Vault storage integration

### Integration with syntek-infra-plugin

The DIY Security Appliances are designed to work with `syntek-infra-plugin` for
NixOS/WireGuard deployment:

| This Plugin                    | syntek-infra-plugin                      |
| ------------------------------ | ---------------------------------------- |
| Builds Rust security binaries  | Deploys via NixOS modules                |
| Router/NAS/Homeserver wrappers | NixOS configs, firewall rules, WireGuard |
| IDS/IPS engine                 | nftables/iptables integration            |
| DNS proxy                      | NixOS DNS config, DoH/DoT                |

**Workflow**: Build Rust binaries here → Deploy declaratively with
syntek-infra-plugin.

## Project Structure

```
syntek-rust-security/
├── agents/
│   ├── security/       # Security-focused agents
│   ├── infrastructure/ # Infrastructure agents
│   └── setup/          # Project setup agents
├── commands/           # Command definitions
├── plugins/src/        # 6 Rust-based plugin tools
├── skills/             # Domain knowledge skills
├── templates/          # Project templates
├── examples/           # Compilable examples (159+)
└── docs/               # Documentation and guides
```

## Plugin Tools

Six Rust-based tools provide integration with the Rust ecosystem:

| Tool              | Purpose                                            |
| ----------------- | -------------------------------------------------- |
| `cargo-tool`      | Extracts project metadata from Cargo.toml          |
| `rustc-tool`      | Detects Rust toolchain version and configuration   |
| `vuln-db-tool`    | Manages RustSec advisory database and CVE lookups  |
| `audit-tool`      | Orchestrates cargo-audit, cargo-deny, cargo-geiger |
| `fuzzer-tool`     | Manages fuzzing infrastructure and crash analysis  |
| `compliance-tool` | Generates OWASP/CWE/CVSS compliance reports        |

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## Author

Syntek Studio - [https://syntek.dev](https://syntek.dev)
