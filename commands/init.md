# /init - Initialize Syntek Rust Security Plugin

Initialize a Rust project with the Syntek Rust Security plugin for Claude Code.

## Command

```
/init [--force] [--minimal]
```

## Arguments

- `--force` - Overwrite existing `.claude/` directory if it exists
- `--minimal` - Only create essential files (CLAUDE.md and settings.local.json)

## What This Command Does

This command sets up your Rust project to use the Syntek Rust Security plugin by
creating a `.claude/` directory with the following structure:

```
.claude/
├── CLAUDE.md                      # Project-specific Claude instructions
├── CODING-PRINCIPLES.md           # Coding standards and principles
├── TESTING.md                     # Testing guide and patterns
├── SECURITY.md                    # Security architecture and guidelines
├── DEVELOPMENT.md                 # Development workflow
├── API-DESIGN.md                  # Rust API design conventions
├── ARCHITECTURE-PATTERNS.md       # Service layer and workspace patterns
├── DATA-STRUCTURES.md             # Data structure selection and domain modelling
├── PERFORMANCE.md                 # Benchmarking, profiling, optimisation
├── ENCRYPTION-GUIDE.md            # Field-level encryption, HMAC tokens, key rotation
├── SYNTEK-RUST-SECURITY-GUIDE.md  # Security guidelines and patterns
├── settings.local.json            # Local Claude Code settings
└── plugins/
    └── src/
        ├── Cargo.toml             # Plugin tools package manifest
        ├── cargo_tool.rs          # Cargo metadata extraction
        ├── rustc_tool.rs          # Rust toolchain detection
        ├── vuln_db_tool.rs        # RustSec database management
        ├── audit_tool.rs          # Security audit orchestration
        ├── fuzzer_tool.rs         # Fuzzing infrastructure
        └── compliance_tool.rs     # Compliance report generation
```

## Execution Steps

1. **Check Prerequisites**
   - Verify this is a Rust project (Cargo.toml exists)
   - Check if `.claude/` already exists (abort unless `--force`)
   - Verify Rust toolchain >= 1.92.0

2. **Create Directory Structure**

   ```bash
   mkdir -p .claude/plugins/src
   ```

3. **Generate CLAUDE.md** Create project-specific instructions with:
   - Project name and description from Cargo.toml
   - References to all four required documents
   - Available security commands
   - Project-specific security considerations
   - Links to examples and documentation

4. **Generate CODING-PRINCIPLES.md** Create coding standards covering:
   - Rob Pike's 5 Rules and Linus Torvalds' principles
   - Rust-specific naming conventions and code structure
   - Error handling, unsafe code, and logging requirements
   - File length limits and DRY/WET rule of three

5. **Generate TESTING.md** Create testing guide covering:
   - Test tooling (cargo test, mockall, wiremock, proptest, cargo-fuzz)
   - Directory structure for unit, integration, and fuzz tests
   - TDD methodology and mocking patterns
   - Security-critical testing requirements

6. **Generate SECURITY.md** Create security guide covering:
   - Memory safety and zeroisation patterns (zeroize, secrecy)
   - Cryptographic standards and algorithm selection
   - Secrets management via HashiCorp Vault
   - Dependency security and supply chain management
   - Input validation and transport security

7. **Generate DEVELOPMENT.md** Create development guide covering:
   - Prerequisites and toolchain setup
   - Local build and test workflow
   - Security scanning commands
   - Git conventions and release process

8a. **Generate API-DESIGN.md** Create API design guide covering:
    - REST conventions with Axum (URL structure, HTTP methods, status codes)
    - Request/response shapes with serde, pagination, filtering
    - Error response format with thiserror — never leaking internals
    - Authentication middleware (Bearer tokens, API keys)
    - Rate limiting with tower_governor
    - Webhook HMAC-SHA256 signing
    - HTTP client patterns with reqwest
    - Axum router construction and tower middleware stack

8b. **Generate ARCHITECTURE-PATTERNS.md** Create architecture guide covering:
    - Trait-based service layer pattern
    - Repository pattern for database access
    - AppState pattern for Axum
    - Tower middleware pipeline (order and composition)
    - Background tasks with tokio::spawn and spawn_blocking
    - Cargo workspace organisation for multi-crate projects
    - Module visibility rules
    - Feature flags, configuration, graceful shutdown

8c. **Generate DATA-STRUCTURES.md** Create data structures guide covering:
    - Standard collections (Vec, VecDeque, HashMap, BTreeMap, HashSet)
    - Shared ownership and interior mutability (Arc, Mutex, RwLock, DashMap)
    - Domain modelling (structs with private fields, newtype pattern, enums)
    - Builder pattern and type-state pattern
    - Security-specific structures (secrecy::Secret, Zeroizing, ConstantTimeEq)
    - Database schema considerations with sqlx
    - Anti-patterns table

8e. **Generate ENCRYPTION-GUIDE.md** Create field-level encryption guide covering:
    - Approved algorithms (AES-256-GCM, ChaCha20-Poly1305) and banned algorithms
    - Zero-plaintext guarantee and the encryption boundary
    - What must and must not be encrypted
    - Key types, separation (FEK vs HMAC key), storage, rotation, and HKDF derivation
    - Versioned key ring and ciphertext format with key version prefix
    - Field-level encrypt/decrypt with AAD bound to model and field name
    - Batch operations for 3+ fields per model
    - Deterministic HMAC-SHA256 lookup tokens — why needed, generation, normalisation
    - Token column naming convention (`*_token`) and database lookup patterns
    - Implementation patterns: Direct Rust, Django/PyO3, Laravel FFI, GraphQL middleware
    - Nonce management rules (CSPRNG, no counter nonces in distributed systems)
    - Memory safety: `Zeroize`, `ZeroizeOnDrop`, `secrecy::Secret`, `ConstantTimeEq`
    - Migration strategy (add nullable → backfill → tighten constraints → drop old column)
    - Required tests per encrypted field including proptest round-trip properties
    - Encryption checklist

8d. **Generate PERFORMANCE.md** Create performance guide covering:
    - Measure-first rules (Pike Rules 1 and 2)
    - Benchmarking with criterion.rs
    - Profiling tools (flamegraph, cargo-instruments, perf)
    - Avoiding unnecessary allocations (Cow, SmallVec, with_capacity)
    - Async performance (spawn_blocking, tokio thread pool, concurrent joins)
    - Database query optimisation (no SELECT *, connection pooling)
    - Caching (moka, Redis) with explicit TTL rules
    - HTTP performance (HTTP/2, compression, streaming, timeouts)
    - Memory allocation (jemalloc/mimalloc)
    - Metrics and monitoring checklist

9. **Generate SYNTEK-RUST-SECURITY-GUIDE.md** Create security guidelines
   covering:
   - Memory safety patterns
   - Cryptographic best practices
   - Unsafe code guidelines
   - Dependency security
   - Common vulnerability patterns

9. **Generate settings.local.json** Configure Claude Code with:
   - Plugin path references
   - Security-focused default behaviors
   - Tool permissions

10. **Copy Plugin Tools** Copy the Rust plugin tools from the
   syntek-rust-security repository:
   - All `*.rs` files from `plugins/src/`
   - `Cargo.toml` for the plugin tools

11. **Build Plugin Tools (Optional)**
   ```bash
   cd .claude/plugins && cargo build --release
   ```

## Generated Files

### Required Documents

All eight required documents are generated from the plugin's templates and
adapted for the target project's characteristics:

| File | Template Source | Purpose |
| ---- | --------------- | ------- |
| `CODING-PRINCIPLES.md` | `templates/init/CODING-PRINCIPLES.md.template` | Coding standards |
| `TESTING.md` | `templates/init/TESTING.md.template` | Testing guide |
| `SECURITY.md` | `templates/init/SECURITY.md.template` | Security architecture |
| `DEVELOPMENT.md` | `templates/init/DEVELOPMENT.md.template` | Development workflow |
| `API-DESIGN.md` | `templates/init/API-DESIGN.md.template` | Rust API design conventions |
| `ARCHITECTURE-PATTERNS.md` | `templates/init/ARCHITECTURE-PATTERNS.md.template` | Service layer and workspace patterns |
| `DATA-STRUCTURES.md` | `templates/init/DATA-STRUCTURES.md.template` | Data structure selection and domain modelling |
| `PERFORMANCE.md` | `templates/init/PERFORMANCE.md.template` | Benchmarking, profiling, optimisation |
| `ENCRYPTION-GUIDE.md` | `templates/init/ENCRYPTION-GUIDE.md.template` | Field-level encryption, HMAC tokens, key rotation |

### CLAUDE.md Template

```markdown
# {project_name} - Claude Code Configuration

## Project Overview

This is a Rust project configured with the Syntek Rust Security plugin.

**Package**: {package_name} **Version**: {version} **Edition**: {edition}
**MSRV**: {rust_version}

## Required Reading

All agents must read these documents before writing or reviewing any code:

| Document | Purpose |
| -------- | ------- |
| **[CODING-PRINCIPLES.md](CODING-PRINCIPLES.md)** | Coding standards, error handling, naming, unsafe code, crypto, logging |
| **[TESTING.md](TESTING.md)** | Testing guide — cargo test, mockall, wiremock, proptest, cargo-fuzz |
| **[SECURITY.md](SECURITY.md)** | Memory safety, cryptographic standards, secrets management, hardening |
| **[DEVELOPMENT.md](DEVELOPMENT.md)** | Development workflow, tooling, git conventions, release process |
| **[API-DESIGN.md](API-DESIGN.md)** | Rust API design — Axum, tower middleware, error handling, rate limiting, webhooks |
| **[ARCHITECTURE-PATTERNS.md](ARCHITECTURE-PATTERNS.md)** | Service layer, workspace structure, async patterns, background tasks, configuration |
| **[DATA-STRUCTURES.md](DATA-STRUCTURES.md)** | Rust data structures, domain modelling, newtype pattern, security types |
| **[PERFORMANCE.md](PERFORMANCE.md)** | Benchmarking, profiling, async performance, caching, connection pooling |
| **[ENCRYPTION-GUIDE.md](ENCRYPTION-GUIDE.md)** | AES-256-GCM field encryption, HMAC lookup tokens, key rotation, migration strategy |

## Security Commands

Run these commands for security analysis:

- `/vuln-scan` - Scan for known vulnerabilities
- `/crypto-review` - Review cryptographic implementations
- `/memory-audit` - Audit unsafe code and memory safety
- `/threat-model` - Perform STRIDE threat analysis
- `/fuzz-setup` - Set up fuzzing infrastructure
- `/compliance-report` - Generate compliance reports

## Project Security Considerations

{auto_detected_considerations}

## Plugin Tools

The `.claude/plugins/` directory contains security analysis tools. Build with:
`cd .claude/plugins && cargo build --release`
```

### SYNTEK-RUST-SECURITY-GUIDE.md Template

See the full template in the generated file. Covers:

- Memory safety patterns
- Cryptographic guidelines
- Unsafe code best practices
- Dependency management
- Common vulnerability patterns
- Compliance requirements

### settings.local.json Template

```json
{
  "plugins": {
    "syntek-rust-security": {
      "enabled": true,
      "tools_path": ".claude/plugins/target/release"
    }
  },
  "security": {
    "audit_on_change": true,
    "block_known_vulnerable": true,
    "require_unsafe_justification": true
  },
  "rust": {
    "edition": "2021",
    "msrv": "1.92.0",
    "clippy_pedantic": true
  }
}
```

## Example Usage

### Basic Initialization

```bash
# In a Rust project directory
claude /init
```

### Force Overwrite

```bash
# Overwrite existing .claude/ directory
claude /init --force
```

### Minimal Setup

```bash
# Only essential files, no plugin tools
claude /init --minimal
```

## Post-Initialization

After running `/init`:

1. **Review Generated Files**
   - Check `.claude/CLAUDE.md` for accuracy
   - Review `.claude/CODING-PRINCIPLES.md` and adapt to project conventions
   - Review `.claude/SECURITY.md` and customise for project-specific threats
   - Review `.claude/DEVELOPMENT.md` and update prerequisites as needed
   - Review `.claude/API-DESIGN.md` and confirm conventions match your stack
   - Review `.claude/ARCHITECTURE-PATTERNS.md` and adjust for project structure
   - Review `.claude/DATA-STRUCTURES.md` for domain-relevant guidance
   - Review `.claude/PERFORMANCE.md` and commit initial benchmark baselines

2. **Build Plugin Tools**

   ```bash
   cd .claude/plugins && cargo build --release
   ```

3. **Run Initial Security Scan**

   ```bash
   claude /vuln-scan
   claude /memory-audit
   claude /supply-chain-audit
   ```

4. **Commit to Version Control**
   ```bash
   git add .claude/
   git commit -m "chore: initialize syntek-rust-security plugin"
   ```

## Troubleshooting

### "Not a Rust project"

Ensure `Cargo.toml` exists in the current directory.

### "Rust version too old"

Update your Rust toolchain:

```bash
rustup update stable
```

### "Plugin tools failed to build"

Check dependencies and try:

```bash
cd .claude/plugins
cargo clean
cargo build --release
```

## See Also

- `/vuln-scan` - Vulnerability scanning
- `/threat-model` - Threat modeling
- `/crypto-review` - Cryptographic review
