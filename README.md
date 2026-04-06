# Syntek Rust Security Plugin

**Last Updated**: 06/04/2026
**Version**: 1.1.0
**Maintained By**: Development Team
**Language**: British English (en_GB)
**Timezone**: Europe/London

---

Comprehensive Rust security tooling for Claude Code - custom
encryption/decryption systems, server security wrappers, infrastructure
automation, and memory-safe development.

## Overview

This plugin extends Claude Code with specialised security capabilities for
building Rust-based security infrastructure, covering:

### Core Security

- Memory safety and unsafe code auditing
- Cryptographic implementation review (AES-GCM, ChaCha20-Poly1305, key
  derivation)
- Supply chain security analysis
- Vulnerability scanning (cargo-audit, cargo-deny, cargo-geiger)
- Threat modelling (STRIDE)
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

## How It Works

The plugin is built in three layers that work together:

```
You run a /command
    → which invokes an Agent (the specialist AI worker)
        → which loads relevant Skills (domain knowledge packs)
```

- **Commands** — what you type; ~51 slash commands covering every security task
- **Agents** — the AI workers behind each command; almost all use Claude Opus
  for deep reasoning
- **Skills** — domain knowledge packs loaded silently by agents to inform their
  work

---

## Commands & Agents Reference

Each command invokes a specialised agent. Commands use the format
`/syntek-rust-security:<command>` or the shorthand `/<command>`.

Model indicators: **[Opus]** = deep reasoning tasks, **[Sonnet]** = standard
analysis tasks.

---

### Setup

#### `/init` — Project Initialiser

Initialises a Rust project with the Syntek Rust Security plugin. Creates a
`.claude/` directory containing project-specific Claude instructions, security
guidelines, local settings, and copies the plugin tools. Run this first in any
new Rust project to enable all security features.

---

### Security Analysis

#### `/threat-model` [Opus]

Performs comprehensive STRIDE threat analysis on your Rust application.
Identifies potential Spoofing, Tampering, Repudiation, Information Disclosure,
Denial of Service, and Elevation of Privilege threats. Generates a threat model
document with attack trees, trust boundaries, and prioritised mitigations
specific to Rust's memory safety guarantees.

#### `/vuln-scan` [Opus]

Scans your project's dependencies for known security vulnerabilities using
cargo-audit and cargo-deny. Queries the RustSec Advisory Database, reports CVE
identifiers with CVSS scores, and suggests upgrade paths or patches. Outputs a
`VULN-REPORT.md` with remediation steps. Ideal for CI/CD integration and
pre-release security checks.

#### `/crypto-review` [Opus]

Reviews cryptographic implementations for correctness and security. Checks for
timing side-channels, proper use of authenticated encryption (AES-GCM,
ChaCha20-Poly1305), secure key derivation (Argon2, scrypt), constant-time
comparisons, and correct nonce/IV handling. Flags dangerous patterns like ECB
mode or weak RNGs. Outputs `CRYPTO-REVIEW.md`.

#### `/memory-audit` [Opus]

Audits unsafe code blocks and memory safety patterns. Verifies that all unsafe
blocks have proper `// SAFETY:` comments, checks for use-after-free potential,
buffer overflows, and uninitialised memory access. Integrates with cargo-geiger
to measure unsafe code surface area across dependencies. Outputs
`MEMORY-AUDIT.md`.

#### `/scan-secrets` [Opus]

Detects hardcoded secrets, API keys, passwords, and credentials in source code
and git history. Scans for high-entropy strings, common secret patterns, and
leaked credentials. Recommends migration to environment variables, HashiCorp
Vault, or the secrecy crate for runtime secret handling. Outputs
`SECRETS-AUDIT.md`.

#### `/supply-chain-audit` [Opus]

Analyses dependency supply chain security risks. Checks for typosquatting,
unmaintained packages, excessive dependency trees, and suspicious version
changes. Integrates with cargo-vet for provenance verification and generates a
software bill of materials (SBOM). Outputs `SUPPLY-CHAIN.md`.

#### `/binary-check` [Opus]

Verifies binary hardening and security features in compiled Rust executables.
Checks for ASLR, DEP/NX, stack canaries, RELRO, PIE, and Fortify Source.
Reports on symbol stripping, debug info, and recommends Cargo profile settings
for security-hardened release builds. Outputs `BINARY-ANALYSIS.md`.

#### `/compliance-report` [Opus]

Generates compliance reports mapping vulnerabilities to OWASP Top 10 and CWE
categories. Calculates CVSS scores, produces executive summaries, and creates
audit-ready documentation. Supports JSON and Markdown output for integration
with security dashboards and compliance workflows.

#### `/pentest-tools` [Opus]

Develops custom penetration testing tools in Rust for authorised security
assessments. Generates network scanners, protocol fuzzers, exploit frameworks,
and security testing utilities. Emphasises memory-safe implementations and
proper error handling for reliable security tooling.

#### `/fuzz-setup` [Opus]

Sets up fuzzing infrastructure for your Rust project using cargo-fuzz with
libFuzzer, AFL++, or honggfuzz backends. Generates fuzz harnesses for parsing
functions, serialisation code, and cryptographic operations. Configures corpus
directories and provides guidance on effective fuzzing strategies.

#### `/threat-feeds-setup` [Sonnet]

Configures integration with threat intelligence feeds including malicious IP
blocklists, domain reputation data, IOC (Indicators of Compromise) matching,
and STIX/TAXII protocol support. Provides a lookup API for runtime use and
manages automated feed updates.

---

### Cryptography & Memory Safety

#### `/encrypt-setup` [Opus]

Designs and implements custom encryption systems using AES-256-GCM,
ChaCha20-Poly1305, or XChaCha20. Creates envelope encryption patterns, secure
key derivation (Argon2), key management infrastructure, and generates FFI
bindings for Django/Next.js/React Native integration.

#### `/decrypt-setup` [Opus]

Implements corresponding decryption infrastructure with authenticated
decryption, key unwrapping from HashiCorp Vault, and secure error handling that
does not leak information through timing or error messages.

#### `/zeroize-audit` [Opus]

Audits memory zeroisation patterns to ensure sensitive data is securely wiped
from memory. Verifies `zeroize` crate usage, checks for compiler optimisations
that might skip zeroing, reviews `secrecy` crate patterns, and inspects FFI
boundaries for zeroisation gaps.

#### `/minimize-unsafe` [Opus]

Systematically reduces unsafe code surface area. Identifies unsafe blocks that
can be replaced with safe alternatives, encapsulates necessary unsafe code
behind safe APIs, and ensures remaining unsafe blocks have proper documentation,
minimal scope, and `// SAFETY:` comments. Outputs `unsafe-audit.md`.

#### `/ffi-audit` [Opus]

Audits FFI boundaries for security issues. Reviews PyO3, Neon, UniFFI, and
wasm-bindgen code for memory safety, null pointer handling, ownership violations,
panic safety, and data validation across language boundaries.

---

### Vault & Secrets

#### `/vault-setup` [Opus]

Configures HashiCorp Vault integration using the vaultrs crate. Sets up
AppRole, Kubernetes, or Token authentication methods. Supports KV v2, Transit
encryption, and PKI secrets engines. Implements secure secret retrieval with
caching, TTL management, and health checks.

#### `/token-rotate` [Opus]

Automates rotation of API keys, tokens, and credentials with zero-downtime
deployment strategies. Validates new credentials before switching, updates
HashiCorp Vault, creates audit logs, and supports rollback capabilities.

#### `/cert-rotate` [Opus]

Manages Cloudflare Origin/Edge certificate rotation with automated renewal.
Stores certificates in HashiCorp Vault, validates TLS handshakes after rotation,
and creates monitoring alerts. Uses Cloudflare Origin CA — not Let's Encrypt.

---

### Infrastructure

#### `/server-harden` [Opus]

Comprehensive server security hardening following CIS benchmarks. Reviews and
configures SSH, kernel parameters, disables unnecessary services, sets file
permissions, configures `auditd` rules, and generates a `HARDENING-REPORT.md`
with a prioritised remediation checklist.

#### `/ssh-wrapper` [Opus]

Generates Rust SSH access wrappers with comprehensive logging, command
filtering, session recording, and allowlist-based access control. Creates audit
trails and real-time logging pipelines for compliance requirements.

#### `/cloudflare-setup` [Opus]

Integrates with Cloudflare APIs for DNS management, Workers deployment, R2
object storage, and certificate operations. Generates type-safe Rust API clients
using cloudflare-rs with secure API token handling.

#### `/cert-rotate` [Opus]

See Vault & Secrets above. Also handles the Nginx/server-side certificate
deployment step after Vault storage.

#### `/docker-harden` [Opus]

Hardens Docker configurations using the bollard crate. Generates secure
Dockerfiles, implements least-privilege containers, configures seccomp/AppArmor
profiles, enables user namespace remapping, and sets up container image scanning
pipelines.

#### `/backup-setup` [Opus]

Configures encrypted backup systems using Backblaze B2. Implements client-side
AES-256-GCM encryption before upload, incremental backups with BLAKE3 integrity
hashing, retention policies, and secure restore procedures.

#### `/firewall-setup` [Opus]

Creates Rust bindings for firewall management (iptables, nftables). Generates
stateful rule sets, implements dynamic IP blocking, rate limiting, connection
tracking, and persists rules across reboots.

#### `/systemd-harden` [Opus]

Creates hardened systemd service files with sandboxing (namespaces, private
/tmp), capability restrictions, seccomp filters, AppArmor profiles, and resource
limits. Validates security score with `systemd-analyze security`.

---

### AI Gateway

#### `/ai-gateway-setup` [Opus]

Designs and initialises a unified Rust AI API gateway supporting Anthropic,
OpenAI, Google Gemini, Azure OpenAI, and Perplexity. Implements token bucket
rate limiting, circuit breakers, cost tracking, streaming with backpressure, and
HashiCorp Vault key management.

#### `/ai-provider-add` [Opus]

Adds a new AI provider to an existing gateway. Generates a type-safe Rust
client, updates routing configuration, implements retry logic with exponential
backoff, configures provider-specific rate limits, and adds cost tracking.

---

### Server Stack Configuration

#### `/nginx-config` [Opus]

Generates security-hardened Nginx configurations. Implements TLS best practices
(modern/intermediate/legacy profiles), security headers (CSP, HSTS, X-Frame),
rate limiting, WAF-like request filtering, and reverse proxy patterns optimised
for Django/FastAPI backends.

#### `/gunicorn-config` [Opus]

Configures Gunicorn with Uvicorn workers for Django/FastAPI. Sets worker class
(sync/gevent/uvicorn), timeouts, resource limits, health checks, graceful
shutdown, and integrates with systemd. Includes PostgreSQL RLS session variable
setup.

#### `/redis-config` [Opus]

Generates secure Redis/Valkey configurations. Implements TLS, ACL user
management, password authentication, command renaming, persistence security, and
memory limits. Outputs `redis.conf`, `users.acl`, and a hardened systemd
service file.

---

### DIY Security Appliances

These commands build complete Rust security wrappers designed to run on
physical or DIY hardware, with matching NixOS modules for deployment via
`syntek-infra-plugin`.

#### `/router-security-init` [Opus]

Initialises a Rust router security wrapper project with deep packet inspection,
malicious IP/domain blocking, IDS/IPS capabilities, traffic anomaly detection,
and bandwidth throttling. Creates a NixOS module for deployment.

#### `/nas-security-init` [Opus]

Creates a NAS security wrapper with real-time file scanning on write operations,
malware quarantine, ransomware detection via entropy analysis, file integrity
monitoring, and executable blocking in data directories. Creates a NixOS module.

#### `/homeserver-security-init` [Opus]

Builds host-level protection with process monitoring and anomaly detection, an
application-level firewall for outbound connections, rootkit detection, privilege
escalation monitoring, and seccomp-bpf system call filtering. Creates a NixOS
module.

#### `/gateway-security-init` [Opus]

Implements an internet gateway security wrapper with an HTTPS inspection proxy
(MITM for owned devices), download scanning, phishing site detection, ad/tracker
blocking, and content filtering policies. Creates a NixOS module.

#### `/malware-scanner-setup` [Opus]

Builds a malware scanning engine with ClamAV integration, YARA rule processing,
custom signature matching, entropy analysis for packed binaries, and heuristic
detection. Includes signature update automation.

#### `/ids-setup` [Sonnet]

Configures an intrusion detection and prevention system with
Snort/Suricata-compatible rule parsing, flow tracking, alert management,
automated blocking responses, and PCAP logging for forensic analysis.

#### `/dns-proxy-setup` [Opus]

Creates a secure DNS proxy with DoH/DoT upstream support (Cloudflare, Google,
Quad9, or custom), DNS sinkholing for known malicious domains, query logging,
DNSSEC validation, and ad/tracker blocking at the network level.

#### `/dpi-setup` [Opus]

Designs and implements a deep packet inspection engine with protocol dissection,
payload content analysis, real-time traffic classification, flow reassembly, and
PCAP export for forensic investigation.

#### `/quarantine-setup` [Opus]

Implements a file quarantine system with isolated encrypted storage, atomic move
operations, rich metadata tracking, admin notification workflows, and secure
restoration procedures with integrity verification.

---

### Code Quality & Review

#### `/review-code` [Opus]

Performs expert-level code review with a security-first focus. Runs clippy with
pedantic lints, checks rustfmt compliance, and reviews for logic errors, race
conditions, and security anti-patterns. Provides actionable feedback on
ownership patterns, error handling, and API design.

#### `/refactor-code` [Opus]

Refactors Rust code to improve safety, performance, and maintainability.
Optimises ownership and borrowing patterns, eliminates unnecessary clones,
converts `unwrap` calls to proper error handling, and applies idiomatic Rust
patterns while preserving behaviour.

#### `/design-api` [Opus]

Guides public API design following the Rust API Guidelines (RFC 1105). Reviews
type signatures for ergonomics, suggests builder patterns, recommends appropriate
trait implementations (From, Into, AsRef), and ensures APIs are impossible to
misuse through Rust's type system.

#### `/gdpr-check` [Opus]

Verifies GDPR compliance patterns in Rust applications. Reviews data handling
for consent management, right to erasure, data portability, breach notification
patterns, and privacy by design. Enforces PostgreSQL Row Level Security patterns.
Outputs `GDPR-AUDIT.md`.

---

### Testing & Performance

#### `/write-tests` [Opus]

Generates comprehensive test suites including unit tests, integration tests, doc
tests, and property-based tests using proptest or quickcheck. Creates test
fixtures, mocks external dependencies with mockall, and ensures
security-critical code paths have thorough coverage.

#### `/benchmark` [Opus]

Sets up performance benchmarking using criterion.rs. Creates benchmark harnesses
for hot paths, cryptographic operations, and parsing code. Generates statistical
reports with confidence intervals, detects performance regressions, and analyses
constant-time execution for security-critical functions.

---

### Documentation & Versioning

#### `/generate-docs` [Opus]

Generates comprehensive documentation using rustdoc. Creates module-level docs,
adds examples to public APIs, ensures doc tests compile and pass, and generates
documentation coverage reports. Produces security-focused documentation
highlighting safe usage patterns.

#### `/version-bump` [Opus]

Manages semantic versioning for Cargo.toml following SemVer 2.0.0. Detects
breaking changes using cargo-semver-checks, updates version numbers, generates
`CHANGELOG.md` entries, and creates git tags. Ensures security fixes are
properly versioned.

#### `/write-support-article` [Opus]

Creates user-facing help documentation and support articles. Generates
installation guides, troubleshooting documentation, FAQ pages, and security best
practices guides for end users of your Rust libraries or applications.

#### `/git-workflow` [Opus]

Manages git workflows for Rust projects. Implements branch strategies (GitFlow,
GitHub Flow, trunk-based), configures commit hooks for clippy and rustfmt,
generates pull request templates with security checklists, and automates release
workflows.

---

### Dependency Management

#### `/manage-deps` [Opus]

Manages Cargo dependencies and feature flags. Identifies outdated dependencies,
removes unused crates, optimises feature flag combinations to reduce compile
times and binary size, and ensures minimal dependency surface for security.
Outputs `deps-report.md`.

---

## Skills Reference

Skills are domain knowledge packs loaded silently by agents. You do not invoke
them directly — they run automatically in the background when an agent needs
specialist knowledge for a task.

| Skill | Domain Knowledge | Used By |
| --- | --- | --- |
| `rust-security-core` | Vulnerability scanning, unsafe code analysis, STRIDE threat modelling, cargo-audit/deny | vuln-scan, memory-audit, threat-model |
| `rust-crypto` | Timing attack detection, constant-time ops, AEAD validation, key zeroisation, side-channel analysis | crypto-review, encrypt-setup, decrypt-setup |
| `rust-embedded` | no_std security, secure boot, hardware RNG, HSM integration, side-channel resistance | Embedded security work |
| `rust-web-security` | Actix/Rocket/Axum security, auth/RBAC, SQL injection prevention, XSS/CSRF, PostgreSQL RLS | review-code, compliance-report, gdpr-check |
| `rust-ffi-security` | PyO3/Neon/UniFFI/wasm-bindgen boundaries, memory safety across FFI, panic safety, buffer overflows | ffi-audit, encrypt-setup |
| `rust-vault-integration` | AppRole/K8s/JWT auth, KV v2, Transit encryption, PKI, dynamic secrets, lease management | vault-setup, token-rotate, cert-rotate |
| `rust-ai-gateway` | Multi-provider API routing, rate limiting, circuit breakers, streaming, cost tracking | ai-gateway-setup, ai-provider-add |
| `rust-server-security` | SSH wrappers, iptables/nftables, seccomp, privilege management, audit logging | server-harden, ssh-wrapper, firewall-setup |
| `rust-cloudflare-security` | Origin/Edge certificate management, DNS, Workers, R2, API token security | cloudflare-setup, cert-rotate |
| `rust-docker-security` | Container isolation, image scanning (Trivy), seccomp/AppArmor profiles, runtime monitoring | docker-harden |
| `rust-backup-security` | Backblaze B2 integration, ChaCha20-Poly1305 client-side encryption, incremental backups, BLAKE3 integrity | backup-setup, quarantine-setup |
| `rust-cli-patterns` | Secure argument handling, password prompting, output redaction, privilege dropping, environment sanitisation | CLI tool development |
| `rust-zeroize-patterns` | `zeroize`/`secrecy` crate patterns, volatile memory ops, secure buffers, compiler optimisation prevention | zeroize-audit, encrypt-setup |
| `rust-nginx-patterns` | TLS hardening, CSP/HSTS security headers, rate limiting, WAF patterns, reverse proxy security | nginx-config |
| `rust-gunicorn-patterns` | Django/FastAPI worker management, SSL/TLS configuration, PostgreSQL RLS middleware | gunicorn-config |
| `rust-redis-patterns` | ACL user management, TLS configuration, persistence security, command renaming, memory limits | redis-config |
| `rust-dns-security` | DoH/DoT implementation, DNS sinkholing, DNSSEC validation, blocklist management, query logging | dns-proxy-setup |
| `rust-network-inspection` | Packet capture, protocol dissection, flow tracking, DPI pattern matching, traffic classification | dpi-setup, router-security-init |
| `rust-intrusion-detection` | Snort/Suricata rule parsing, signature matching, alert management, automated blocking, PCAP forensics | ids-setup |
| `rust-threat-detection` | YARA rule engine, entropy analysis, ClamAV integration, heuristics, IOC matching, behavioural analysis | malware-scanner-setup, threat-detection |
| `rust-threat-intelligence` | IP/domain blocklists, IOC aggregation, STIX/TAXII protocol, reputation scoring, feed freshness | threat-feeds-setup |
| `rust-file-scanning` | ClamAV integration, file type detection, real-time filesystem monitoring, encrypted quarantine | malware-scanner-setup, quarantine-setup |

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

Initialise the plugin in your Rust project:

```bash
# Navigate to your Rust project
cd my-rust-project

# Initialise the Syntek Rust Security plugin
/rust-security:init
```

This creates a `.claude/` directory with:

- `CLAUDE.md` - Project-specific Claude instructions
- `SYNTEK-RUST-SECURITY-GUIDE.md` - Security guidelines and patterns
- `settings.local.json` - Local Claude Code settings
- `plugins/src/*.rs` - Security analysis tools

## Usage

Invoke commands directly:

```bash
# Initialise the plugin
/init

# Run security analysis
/vuln-scan
/crypto-review
/memory-audit
/threat-model

# Set up encryption infrastructure
/encrypt-setup
/vault-setup

# Generate compliance report
/compliance-report

# Set up fuzzing
/fuzz-setup

# Harden your server stack
/nginx-config
/redis-config
/systemd-harden

# Build a DIY security appliance
/router-security-init
/ids-setup
/dns-proxy-setup
```

## Use Cases

### Security Infrastructure

1. **Server Security Wrappers** — For hosting websites, cloud servers, Backblaze
   backups
2. **SSH Security** — Access management and comprehensive logging
3. **Custom Encryption/Decryption** — Server-side and client-side
   implementations
4. **Memory Zeroisation** — Secure memory wiping (zeroize patterns)
5. **Secure Memory Storage** — Protected storage for sensitive data
6. **Penetration Testing Tools** — Custom security testing infrastructure

### DIY Security Appliances

7. **Router Security Wrapper** — Deep packet inspection, IDS/IPS, malicious
   traffic blocking
8. **NAS Security Wrapper** — File scanning, malware quarantine, ransomware
   detection
9. **Homeserver Security Wrapper** — Process monitoring, rootkit detection, app
   firewall
10. **Internet Gateway Wrapper** — HTTPS inspection, download scanning, phishing
    blocking
11. **DNS Security Proxy** — DoH/DoT, sinkholing, ad blocking at network level

### Integration & Automation

12. **AI API Gateway** — Unified gateway for Anthropic, OpenAI, Gemini, Azure,
    Perplexity
13. **CLI Tooling** — Cloudflare, Docker, SSH, certificate and token management
14. **Server Stack Config** — Nginx, Gunicorn+Uvicorn, Redis/Valkey secure
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

---

## Project Structure

```
syntek-rust-security/
├── agents/             # ~50 specialised AI agents (flat structure)
├── commands/           # ~51 command definitions
├── plugins/src/        # 6 Rust-based plugin tools
├── skills/             # 22 domain knowledge packs
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
