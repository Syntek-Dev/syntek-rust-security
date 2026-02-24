# Claude Plugin Configuration

This file configures the Syntek Rust Security Plugin for Claude Code.

## Plugin Metadata

- **Name**: syntek-rust-security
- **Version**: 0.2.1
- **Type**: Security & Development Tools
- **Language**: Rust
- **Rust Version**: 1.92.0+ (released December 2025)
- **Target**: Security engineers, Rust developers, systems programmers,
  DevOps/Infrastructure engineers

## Plugin Description

The Syntek Rust Security Plugin provides comprehensive security analysis, threat
modelling, vulnerability scanning, and infrastructure automation for Rust
projects. It extends Claude Code with specialized agents for building
security-focused Rust wrappers, custom encryption/decryption systems,
memory-safe tooling, and infrastructure security automation.

## Required Reading

All agents must read these four documents before writing or reviewing any code:

| Document | Purpose |
| -------- | ------- |
| **[CODING-PRINCIPLES.md](CODING-PRINCIPLES.md)** | Coding standards, error handling, naming, unsafe code, crypto, logging |
| **[TESTING.md](TESTING.md)** | Testing guide, patterns, and examples for Rust security projects |
| **[SECURITY.md](SECURITY.md)** | Memory safety, cryptographic standards, secrets management, hardening |
| **[DEVELOPMENT.md](DEVELOPMENT.md)** | Development workflow, tooling, git conventions, release process |

## Coding Principles

All code in this codebase follows two foundational sets of rules. Full details
in **[CODING-PRINCIPLES.md](CODING-PRINCIPLES.md)**.

**Rob Pike's 5 Rules (summary)**
1. Don't guess where bottlenecks are — measure first.
2. Don't tune for speed until you've measured.
3. Fancy algorithms are slow when N is small — keep it simple until N is proven large.
4. Fancy algorithms are buggy and hard to implement — prefer simple, reusable ones.
5. Data dominates — choose the right data structures and the algorithm becomes obvious.

**Linus Torvalds' Rules (summary)**
1. Data structures over algorithms — organise your data and the logic follows.
2. Good taste: remove special cases, simplify logic, reduce branches.
3. Readability: short functions, descriptive names, avoid deep nesting.
4. No multiple assignments on one line — one operation, one line.
5. Favour stability over cleverness.
6. Make it work first, then make it better — write for the next maintainer.

---

## Primary Use Cases

This plugin is designed to help create:

### Server & Infrastructure Security

1. **Rust Security Wrapper for Servers** - Hosting websites, cloud servers,
   Backblaze backups
2. **Rust Security Wrapper for Internet Access** - Inbound/outbound traffic on
   DIY routers, NAS, physical servers
3. **Rust Security Wrapper for SSH** - Access management and comprehensive
   logging

### Custom Cryptography

4. **Rust Custom Encryption on Servers** - Server-side encryption
   implementations
5. **Rust Custom Encryption in Apps** - Client-side encryption for full-stack
   applications:
   - Django/Postgres/GraphQL backend with Redis/Valkey
   - NextJS/NodeJS/React/TS/Tailwind web frontend
   - React Native/TS/Nativewind mobile frontend
   - HashiCorp Vault secret retrieval integration

6. **Rust Custom Decryption on Servers** - Server-side decryption
   implementations
7. **Rust Custom Decryption in Apps** - Client-side decryption for full-stack
   applications

### Memory Security

8. **Rust Custom Zeroising on Servers** - Secure memory wiping on servers
9. **Rust Custom Zeroising in Apps** - Secure memory wiping in applications
   (zeroize crate patterns)
10. **Rust Custom Memory Storage on Servers** - Secure memory management for
    sensitive data
11. **Rust Custom Memory Storage in Apps** - Client-side secure memory patterns

### Penetration Testing

12. **Rust Custom Pen Testing on Servers** - Server-side security testing tools
13. **Rust Custom Pen Testing in Apps** - Application security testing tools

### AI Gateway

15. **Rust AI API Gateway** - Unified gateway for AI provider APIs:
    - Anthropic Claude API integration
    - OpenAI API integration
    - Google Gemini API integration
    - Azure OpenAI / GitHub Copilot integration
    - Perplexity API integration
    - Other AI providers (Mistral, Cohere, etc.)
    - Rate limiting, retry logic, circuit breakers
    - Request/response logging and cost tracking
    - Streaming support with backpressure handling
    - Secret management via HashiCorp Vault

### CLI Tooling

16. **Rust Custom CLI Tooling on Servers** - Infrastructure automation:
    - Cloudflare CLI integration (DNS, Workers, R2, Origin/Edge certificates)
    - Docker management
    - SSH access management
    - Cloudflare Origin/Edge certificate rotation (not Let's Encrypt)
    - Certificate updates to HashiCorp Vault
    - Token/secret variable checks and rotation

### Server Stack Configuration

17. **Server Stack Security Configuration** - Secure configuration generation:
    - Nginx security-hardened configuration
    - Gunicorn + Uvicorn secure setup for Django/FastAPI
    - Redis/Valkey secure configuration
    - Integration with Rust security wrappers

### DIY Infrastructure Security Appliances

18. **Rust Router Security Wrapper** - Network-level threat protection:
    - Deep packet inspection for malware signatures
    - Malicious IP/domain blocking (threat intelligence feeds)
    - URL filtering and categorisation
    - DNS sinkholing for known malicious domains
    - Intrusion detection/prevention (IDS/IPS)
    - Traffic anomaly detection
    - Bandwidth throttling for suspicious connections

19. **Rust NAS Security Wrapper** - Storage-level threat protection:
    - Real-time file scanning on write operations
    - Malware signature detection (ClamAV integration or custom)
    - Quarantine system for infected files
    - File integrity monitoring (AIDE-like)
    - Ransomware detection (entropy analysis, rapid file changes)
    - Executable blocking in data directories
    - Audit logging for all file operations

20. **Rust Homeserver Security Wrapper** - Host-level threat protection:
    - Process monitoring and anomaly detection
    - Application-level firewall (outbound connection control)
    - Container security scanning
    - Rootkit detection
    - Privilege escalation monitoring
    - System call filtering (seccomp-bpf integration)
    - Memory corruption detection

21. **Rust Internet Gateway Security Wrapper** - Inbound/outbound protection:
    - HTTPS inspection proxy (MITM for owned devices)
    - Malicious link blocking before download
    - Download scanning (executables, archives, documents)
    - Phishing site detection
    - Ad/tracker blocking at network level
    - Content filtering policies
    - Safe browsing enforcement

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

### Cryptography & Memory Security

- Custom encryption/decryption implementations (AES-GCM, ChaCha20-Poly1305,
  XChaCha20)
- Secure key derivation (Argon2, scrypt, PBKDF2)
- Memory zeroisation patterns (zeroize crate integration)
- Secure memory storage (secrecy crate patterns)
- Side-channel attack prevention
- Constant-time comparison implementations
- Key rotation and lifecycle management

### FFI & Integration Security

- PyO3 integration for Django/Python backends
- Neon/wasm-bindgen for Node.js/React/Next.js frontends
- UniFFI for React Native mobile integration
- HashiCorp Vault client integration (vaultrs crate)
- Redis/Valkey secure connection patterns
- GraphQL security middleware

### AI Gateway & API Security

- Unified Rust gateway for AI providers (Anthropic, OpenAI, Gemini, Azure,
  Perplexity)
- Rate limiting with token bucket and sliding window algorithms
- Circuit breaker patterns for resilience
- Request/response audit logging
- Cost tracking and budget enforcement
- Streaming response handling with backpressure
- API key rotation via Vault

### Server & Network Security

- SSH wrapper implementations with comprehensive logging
- Firewall/iptables Rust bindings
- Cloudflare Origin/Edge certificate management (not Let's Encrypt)
- Certificate rotation with Vault integration
- Token/secret rotation automation
- Cloudflare API integration (cloudflare-rs) - DNS, Workers, R2
- Docker security hardening and management
- Backblaze B2 secure backup integration

### Server Stack Configuration

- Nginx security-hardened configuration generation
- Gunicorn + Uvicorn secure setup (Django/FastAPI)
- Redis/Valkey secure configuration
- Systemd service hardening
- Integration patterns with Rust security wrappers

### DIY Security Appliances

- **Threat Intelligence Integration**: Malicious IP/domain feeds, YARA rules,
  Sigma rules
- **Deep Packet Inspection**: Protocol dissection, malware signature matching in
  transit
- **File Scanning Engine**: ClamAV integration, custom signature matching,
  entropy analysis
- **Network Monitoring**: Traffic anomaly detection, bandwidth analysis,
  connection tracking
- **Intrusion Detection**: Snort/Suricata-compatible rule processing in Rust
- **DNS Security**: DoH/DoT proxying, sinkholing, query logging and analysis
- **HTTPS Inspection**: Transparent proxy with CA management for owned devices
- **Quarantine Systems**: Isolated storage, admin notification, restoration
  workflows
- **Audit Logging**: Comprehensive logging with tamper-evident storage

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

### Existing Opus Agents (8) - Deep Reasoning Required

- **threat-modeller**: Sophisticated architectural understanding for STRIDE
  analysis
- **crypto-reviewer**: Expert-level cryptographic knowledge and side-channel
  analysis
- **pentester**: Creative security thinking for custom tool development
- **rust-gdpr**: Legal/regulatory reasoning for compliance patterns
- **rust-refactor**: Complex ownership and borrowing transformations
- **rust-review**: Expert-level code review with security focus
- **rust-unsafe-minimiser**: Deep reasoning about memory safety and UB
  prevention
- **rust-api-designer**: Sophisticated API design following Rust guidelines

### Existing Sonnet Agents (14) - Standard Analysis

- vuln-scanner, memory-safety, fuzzer, secrets-auditor, supply-chain
- binary-analyser, compliance-auditor, rust-version, rust-docs
- rust-support-articles, rust-git, rust-test-writer, rust-benchmarker
- rust-dependency-manager

### Required New Agents (26)

#### New Opus Agents (7)

- **encryption-architect**: Custom encryption system design (deep crypto
  reasoning)
- **ffi-security-reviewer**: FFI boundary security review (complex
  memory/safety)
- **server-hardener**: Infrastructure security hardening (architectural
  decisions)
- **zeroize-auditor**: Memory zeroisation verification (UB prevention expertise)
- **ai-gateway-architect**: AI API gateway design (complex integration patterns)
- **threat-detection-architect**: Malware/intrusion detection system design
  (complex pattern matching)
- **network-security-architect**: Deep packet inspection and traffic analysis
  design

#### New Sonnet Agents (19)

- **ssh-wrapper-generator**: SSH wrapper implementation with logging
- **cert-manager**: Cloudflare Origin/Edge certificate management and Vault
  rotation
- **vault-integrator**: HashiCorp Vault integration patterns
- **cloudflare-manager**: Cloudflare API integration (DNS, Workers, R2,
  certificates)
- **docker-security**: Docker hardening and management
- **backup-manager**: Encrypted backup systems (Backblaze B2)
- **token-rotator**: Secret/token rotation automation
- **firewall-integrator**: Firewall/iptables/nftables Rust bindings
- **ai-gateway-builder**: AI provider API client implementation
- **nginx-configurator**: Security-hardened Nginx configuration
- **gunicorn-configurator**: Gunicorn + Uvicorn secure configuration
- **router-security-builder**: Router security wrapper implementation (DPI,
  IDS/IPS)
- **nas-security-builder**: NAS security wrapper implementation (file scanning,
  quarantine)
- **homeserver-security-builder**: Homeserver protection (process monitoring,
  app firewall)
- **gateway-security-builder**: Internet gateway wrapper (HTTPS inspection,
  download scanning)
- **malware-scanner-builder**: Malware detection engine (ClamAV integration,
  YARA rules)
- **dns-security-builder**: DNS security proxy (DoH/DoT, sinkholing, logging)
- **intrusion-detector-builder**: IDS/IPS rule engine (Snort/Suricata
  compatible)
- **threat-intel-integrator**: Threat intelligence feed integration (IP/domain
  blocklists)
- **redis-configurator**: Redis/Valkey secure configuration
- **systemd-hardener**: Systemd service security configuration

## Plugin Tools

Six Rust-based tools provide integration with the Rust ecosystem:

1. **cargo_tool.rs**: Project metadata extraction from Cargo.toml
2. **rustc_tool.rs**: Toolchain version detection and configuration
3. **vuln_db_tool.rs**: RustSec database management and CVE lookups
4. **audit_tool.rs**: Security audit orchestration (cargo-audit, cargo-deny,
   cargo-geiger)
5. **fuzzer_tool.rs**: Fuzzing infrastructure management (libfuzzer, AFL++,
   honggfuzz)
6. **compliance_tool.rs**: Compliance report generation (OWASP, CWE, CVSS)

## Skills System

Skills provide domain knowledge to agents and are automatically loaded:

### Existing Skills (4)

1. **rust-security-core**: Memory safety, ownership patterns, unsafe guidelines
2. **rust-crypto**: Cryptographic implementation patterns and best practices
3. **rust-embedded**: Embedded systems security (no_std, hardware security)
4. **rust-web-security**: Web framework security (Actix, Rocket, Axum)

### Required New Skills (18)

#### FFI & Integration Skills

5. **rust-ffi-security**: FFI patterns for PyO3, Neon, UniFFI, wasm-bindgen
6. **rust-vault-integration**: HashiCorp Vault patterns, secret retrieval,
   rotation
7. **rust-ai-gateway**: AI provider API patterns (Anthropic, OpenAI, Gemini,
   Azure, Perplexity)

#### Server & Infrastructure Skills

8. **rust-server-security**: Server hardening, SSH wrappers, firewall
   integration
9. **rust-cloudflare-security**: Cloudflare Origin/Edge certs, DNS, Workers, R2
   (not Let's Encrypt)
10. **rust-docker-security**: Docker management, container security, registry
    auth
11. **rust-backup-security**: Backblaze B2 integration, encrypted backup
    patterns

#### Memory & Crypto Skills

12. **rust-zeroize-patterns**: Memory zeroisation, secrecy crate, secure
    allocators
13. **rust-cli-patterns**: CLI security for infrastructure automation (clap,
    config)

#### Server Stack Skills

14. **rust-nginx-patterns**: Nginx security configuration patterns
15. **rust-gunicorn-patterns**: Gunicorn + Uvicorn security for Django/FastAPI
16. **rust-redis-patterns**: Redis/Valkey secure configuration and connection
    patterns

#### DIY Security Appliance Skills (NEW)

17. **rust-threat-detection**: Malware signatures, YARA rules, entropy analysis,
    heuristics
18. **rust-network-inspection**: Deep packet inspection, protocol dissection,
    traffic analysis
19. **rust-intrusion-detection**: IDS/IPS patterns, Snort/Suricata rule
    compatibility
20. **rust-dns-security**: DoH/DoT implementation, DNS sinkholing, query
    analysis
21. **rust-file-scanning**: ClamAV integration, file type detection, quarantine
    patterns
22. **rust-threat-intelligence**: Threat feed integration, IP/domain blocklists,
    IOC matching

## User-Invocable Commands

Quick-access commands for common security tasks:

### Existing Commands (23)

- **/vuln-scan**: Run vulnerability scan (cargo-audit + cargo-deny)
- **/crypto-review**: Review cryptographic implementations
- **/memory-audit**: Analyze unsafe code and memory safety
- **/threat-model**: Perform STRIDE threat analysis
- **/benchmark**: Performance benchmarking
- **/binary-check**: Binary hardening verification
- **/compliance-report**: Generate compliance reports
- **/design-api**: API design guidance
- **/fuzz-setup**: Fuzzing infrastructure setup
- **/gdpr-check**: GDPR compliance check
- **/generate-docs**: Documentation generation
- **/git-workflow**: Git workflow management
- **/manage-deps**: Dependency management
- **/minimize-unsafe**: Reduce unsafe code
- **/pentest-tools**: Penetration testing tools
- **/refactor-code**: Code refactoring
- **/review-code**: Code review
- **/scan-secrets**: Secret detection
- **/supply-chain-audit**: Supply chain analysis
- **/version-bump**: Version management
- **/write-support-article**: Support documentation
- **/write-tests**: Test generation

### Required New Commands (19)

#### Encryption & Memory Commands

- **/encrypt-setup**: Set up custom encryption infrastructure
- **/decrypt-setup**: Set up custom decryption infrastructure
- **/zeroize-audit**: Audit memory zeroisation patterns

#### Vault & Secrets Commands

- **/vault-setup**: Configure HashiCorp Vault integration
- **/token-rotate**: Token/secret rotation automation

#### Infrastructure Commands

- **/ssh-wrapper**: Generate SSH wrapper with logging
- **/cert-rotate**: Cloudflare Origin/Edge certificate rotation to Vault
- **/cloudflare-setup**: Cloudflare CLI integration (DNS, Workers, R2, certs)
- **/docker-harden**: Docker security hardening
- **/backup-setup**: Encrypted backup configuration (Backblaze B2)
- **/firewall-setup**: Firewall/iptables configuration
- **/server-harden**: Server security hardening checklist

#### FFI Commands

- **/ffi-audit**: FFI security audit (PyO3, Neon, UniFFI)

#### AI Gateway Commands

- **/ai-gateway-setup**: Initialize AI API gateway project
- **/ai-provider-add**: Add AI provider to gateway (anthropic, openai, gemini,
  azure, perplexity)

#### Server Stack Commands

- **/nginx-config**: Generate security-hardened Nginx configuration
- **/gunicorn-config**: Generate Gunicorn + Uvicorn secure configuration
- **/redis-config**: Generate Redis/Valkey secure configuration
- **/systemd-harden**: Generate hardened systemd service files

#### DIY Security Appliance Commands (NEW)

- **/router-security-init**: Initialize router security wrapper project
- **/nas-security-init**: Initialize NAS security wrapper project
- **/homeserver-security-init**: Initialize homeserver security wrapper project
- **/gateway-security-init**: Initialize internet gateway security wrapper
  project
- **/malware-scanner-setup**: Set up malware scanning engine (ClamAV, YARA)
- **/ids-setup**: Set up intrusion detection system (Snort/Suricata compatible)
- **/dns-proxy-setup**: Set up secure DNS proxy (DoH/DoT, sinkholing)
- **/threat-feeds-setup**: Configure threat intelligence feed integration
- **/dpi-setup**: Set up deep packet inspection engine
- **/quarantine-setup**: Configure file quarantine system

## Templates

### Existing Templates (4)

1. **rust-cli-security**: CLI application security patterns
2. **rust-web-security**: Web service security (Actix/Rocket/Axum)
3. **rust-embedded**: Embedded system security (no_std)
4. **rust-crypto-lib**: Cryptographic library development

### Required New Templates (22)

#### FFI Integration Templates

5. **rust-django-ffi**: Django-Rust FFI integration (PyO3) for backend
   encryption
6. **rust-nextjs-ffi**: Next.js/Node.js integration via Neon/wasm-bindgen
7. **rust-react-native-ffi**: React Native integration via UniFFI
8. **rust-graphql-middleware**: GraphQL security middleware (async-graphql)

#### Vault & Secrets Templates

9. **rust-vault-client**: HashiCorp Vault client library template
10. **rust-token-rotator**: Token/secret rotation automation

#### Infrastructure Templates

11. **rust-ssh-wrapper**: SSH access wrapper with logging
12. **rust-server-firewall**: Firewall/iptables integration template
13. **rust-cloudflare-cli**: Cloudflare CLI (DNS, Workers, R2, Origin/Edge
    certs)
14. **rust-cert-rotator**: Cloudflare certificate rotation with Vault storage
15. **rust-docker-manager**: Docker management CLI template
16. **rust-backup-client**: Backblaze B2 encrypted backup client

#### Memory Security Templates

17. **rust-zeroize-wrapper**: Memory zeroisation wrapper library
18. **rust-secure-memory**: Secure memory allocator patterns

#### AI Gateway Templates

19. **rust-ai-gateway**: Unified AI API gateway (all providers)
20. **rust-ai-client**: Single AI provider client template

#### Server Stack Templates

21. **rust-nginx-config**: Nginx security configuration generator
22. **rust-gunicorn-config**: Gunicorn + Uvicorn configuration generator
23. **rust-redis-config**: Redis/Valkey secure configuration generator
24. **rust-systemd-service**: Hardened systemd service template

#### Project Structure Templates

25. **rust-workspace-security**: Multi-crate workspace security
26. **rust-async-security**: Async/await security (tokio, async-std)

#### DIY Security Appliance Templates (NEW)

27. **rust-router-security**: Router security wrapper (DPI, IDS/IPS, traffic
    filtering)
28. **rust-nas-security**: NAS security wrapper (file scanning, quarantine,
    integrity)
29. **rust-homeserver-security**: Homeserver protection (process monitor, app
    firewall)
30. **rust-gateway-security**: Internet gateway (HTTPS inspection, download
    scanning)
31. **rust-malware-scanner**: Malware detection engine (ClamAV, YARA, custom
    signatures)
32. **rust-ids-engine**: Intrusion detection system (Snort/Suricata rule
    compatible)
33. **rust-dns-proxy**: Secure DNS proxy (DoH/DoT, sinkholing, logging)
34. **rust-threat-intel-client**: Threat intelligence feed client (blocklists,
    IOCs)
35. **rust-dpi-engine**: Deep packet inspection library
36. **rust-quarantine-system**: File quarantine and remediation system

## Examples Library

Practical, compilable examples organized by category (target: 200+ examples):

### Security Examples (60 planned)

- Threat Modelling (3)
- Cryptography (10) - AES-GCM, ChaCha20, key derivation, envelope encryption
- Memory Safety (8) - unsafe patterns, zeroize, secrecy crate
- Fuzzing (6) - libfuzzer, AFL++, honggfuzz setup
- Secrets Management (5) - Vault integration, secret rotation
- Supply Chain (5) - cargo-deny, cargo-vet patterns
- Web Security (8) - Actix/Rocket/Axum security middleware
- Integration (8) - FFI patterns
- Binary Hardening (5) - RELRO, PIE, stack canaries
- Compliance (2) - OWASP, CWE mapping

### FFI Integration Examples (30 required)

- PyO3 Django Integration (6) - encryption/decryption/zeroize in Django
- Neon Node.js Integration (6) - encryption for Next.js/React
- UniFFI React Native (6) - mobile encryption patterns
- wasm-bindgen Browser (6) - WebAssembly crypto
- GraphQL Middleware (3) - secure resolver patterns
- Redis/Valkey Security (3) - secure connection handling

### AI Gateway Examples (20 required - NEW)

- Anthropic Claude Integration (3) - streaming, function calling, vision
- OpenAI Integration (3) - GPT-4, embeddings, assistants API
- Google Gemini Integration (3) - multimodal, streaming
- Azure OpenAI / Copilot (3) - enterprise patterns
- Perplexity Integration (2) - search-augmented generation
- Multi-provider Routing (3) - load balancing, failover, cost optimization
- Rate Limiting & Circuit Breakers (3) - resilience patterns

### Server Infrastructure Examples (30 required)

- SSH Wrapper (5) - access logging, command filtering
- Certificate Management (5) - Cloudflare Origin/Edge rotation, Vault storage
- Firewall Integration (4) - iptables/nftables bindings
- Docker Security (4) - container management, registry auth
- Cloudflare Integration (4) - DNS, Workers, R2, certificate API
- Backblaze B2 (4) - encrypted backup patterns
- Token Rotation (4) - automated secret rotation

### Server Stack Configuration Examples (20 required)

- Nginx Security (5) - TLS hardening, rate limiting, headers, WAF patterns
- Gunicorn + Uvicorn (5) - Django/FastAPI secure deployment
- Redis/Valkey (5) - authentication, TLS, ACLs, persistence security
- Systemd Hardening (5) - sandboxing, capabilities, namespaces

### DIY Security Appliance Examples (40 required - NEW)

- Router Security Wrapper (8) - DPI setup, traffic filtering, IDS rules, anomaly
  detection
- NAS Security Wrapper (8) - file scanning, quarantine, integrity monitoring,
  ransomware detection
- Homeserver Security (6) - process monitoring, app firewall, rootkit detection
- Internet Gateway (6) - HTTPS inspection, download scanning, phishing detection
- Malware Scanner Engine (4) - ClamAV integration, YARA rules, signature updates
- IDS/IPS Engine (4) - Snort/Suricata rules, alert handling, blocking
- DNS Security Proxy (4) - DoH/DoT, sinkholing, query logging, ad blocking

### Infrastructure Examples (40 planned)

- Version Management (4)
- Documentation (5)
- GDPR Compliance (6)
- Git Workflow (3)
- Refactoring (6)
- Code Review (4)
- Testing (6)
- Benchmarking (3)
- Dependency Management (3)

## Integration with Syntek Plugins

This plugin is designed to work alongside other Syntek plugins:

### Integration with syntek-dev-suite

- **Namespace Separation**: All agents prefixed with `rust-` or specific to Rust
  security
- **Complementary Functionality**: Web security (syntek-dev-suite) vs. systems
  security (this plugin)
- **Shared Workflows**: Version management, git workflows, documentation
  generation

### Integration with syntek-infra-plugin (Planned)

The DIY Security Appliances in this plugin are designed to work hand-in-hand
with `syntek-infra-plugin` for NixOS and WireGuard configuration:

| This Plugin (syntek-rust-security)      | syntek-infra-plugin                                      |
| --------------------------------------- | -------------------------------------------------------- |
| Rust Router Security Wrapper binary     | NixOS router module, firewall rules, WireGuard config    |
| Rust NAS Security Wrapper binary        | NixOS NAS module, ZFS config, Samba/NFS security         |
| Rust Homeserver Security Wrapper binary | NixOS server module, systemd hardening, container config |
| Rust Internet Gateway binary            | NixOS gateway module, network segmentation               |
| Rust DNS Proxy binary                   | NixOS DNS config, DoH/DoT setup                          |
| Rust IDS/IPS engine                     | NixOS nftables/iptables rules integration                |

**Workflow**: This plugin builds the Rust security binaries; syntek-infra-plugin
deploys them declaratively via NixOS.

```
# Build security wrapper with this plugin
/rust-security:router-security-init    # Create Rust router security wrapper
/rust-security:ids-setup               # Add IDS/IPS capabilities
/rust-security:dns-proxy-setup         # Add DNS security proxy
cargo build --release                  # Build the binaries

# Deploy with syntek-infra-plugin
/syntek-infra:nixos-router             # Generate NixOS router configuration
/syntek-infra:wireguard-setup          # Configure WireGuard VPN
/syntek-infra:firewall-rules           # Generate nftables/iptables rules
/syntek-infra:deploy                   # Deploy to target machine
```

**Key Integration Points**:

- Rust binaries output to paths expected by NixOS modules
- Configuration files in formats NixOS can consume (TOML, JSON)
- Systemd service definitions compatible with NixOS
- Secrets managed via sops-nix/agenix with Vault bridge

### Example Combined Workflow (All Three Plugins)

```
/syntek-dev-suite:plan           # Plan feature implementation
/rust-security:threat-model      # Model security threats
/rust-security:router-security-init  # Create router security wrapper

[Implement Rust security wrapper]

/rust-security:crypto-review     # Review cryptographic code
/rust-security:vuln-scan         # Scan for vulnerabilities
/rust-security:ids-setup         # Add intrusion detection

[Build and test locally]

/syntek-infra:nixos-router       # Generate NixOS deployment config
/syntek-infra:wireguard-setup    # Add WireGuard VPN
/syntek-infra:deploy             # Deploy to router hardware
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
