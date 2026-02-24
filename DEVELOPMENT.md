# Development Workflow

**Last Updated:** 2026-02-24

Development setup, tooling, testing workflow, and contribution guidelines for
the syntek-rust-security plugin.

---

## Getting Started

### Prerequisites

- **Rust 1.92.0+** — Install via [rustup](https://rustup.rs/)
- **Git** for version control
- **cargo-audit** — Vulnerability scanning (`cargo install cargo-audit`)
- **cargo-deny** — Dependency policy enforcement (`cargo install cargo-deny`)
- **cargo-fuzz** — Fuzz testing (`cargo install cargo-fuzz`)
- **cargo-geiger** — Unsafe code surface audit (`cargo install cargo-geiger`)

Optional but recommended:

- **cargo-expand** — Macro expansion (`cargo install cargo-expand`)
- **cargo-semver-checks** — Breaking change detection (`cargo install cargo-semver-checks`)
- **criterion** — Benchmarking (add as `dev-dependency`)

### 1. Install Rust

```bash
# Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Set the toolchain version for this project
rustup override set 1.92.0

# Verify
rustc --version  # Should show 1.92.0 or newer
cargo --version
```

### 2. Clone the Repository

```bash
git clone <repository-url> syntek-rust-security
cd syntek-rust-security
```

### 3. Install Security Tools

```bash
# Core security scanning tools
cargo install cargo-audit
cargo install cargo-deny
cargo install cargo-geiger

# Fuzzing support
cargo install cargo-fuzz

# Optional development tools
cargo install cargo-expand
cargo install cargo-semver-checks
cargo install cargo-watch  # Auto-recompile on save
```

### 4. Install Clippy and Rustfmt

```bash
# Clippy (linter) and rustfmt (formatter) come with rustup
rustup component add clippy
rustup component add rustfmt

# Verify
cargo clippy --version
cargo fmt --version
```

### 5. Verify Setup

```bash
# Build the workspace
cargo build --workspace

# Run all tests
cargo test --workspace

# Run clippy (strict mode)
cargo clippy --workspace --all-features -- -D warnings

# Run formatter check
cargo fmt --check

# Audit dependencies
cargo audit
cargo deny check
```

---

## Development Workflow

### 1. Local Development

All changes are made locally, tested, and linted before creating a pull request.

```bash
# Build the entire workspace
cargo build --workspace

# Watch for changes and auto-rebuild
cargo watch -x "build --workspace"

# Build with all feature flags
cargo build --workspace --all-features

# Build a release binary
cargo build --release -p syntek-security-cli
```

### 2. Running Tests

```bash
# Run all tests across all crates
cargo test --workspace

# Run tests for a specific crate
cargo test -p syntek-crypto

# Run a specific test by name pattern
cargo test -p syntek-vault fetch_secret

# Run with log output visible (useful for debugging)
RUST_LOG=debug cargo test -p syntek-monitor -- --nocapture

# Run integration tests only
cargo test --test '*' --workspace

# Run doc tests
cargo test --doc --workspace
```

### 3. Code Quality Checks

Run these before committing or opening a pull request:

```bash
# Format all code
cargo fmt --all

# Run clippy in pedantic mode (treat warnings as errors)
cargo clippy --workspace --all-features -- -D warnings -W clippy::pedantic

# Check for unused dependencies
cargo +nightly udeps --workspace

# Check for unsafe code surface area
cargo geiger --all-features

# Audit dependencies for known CVEs
cargo audit

# Enforce licence and dependency policies
cargo deny check

# Check for breaking API changes (on library crates)
cargo semver-checks check-release
```

### 4. Running Fuzz Tests

```bash
# List available fuzz targets
cargo fuzz list

# Run a fuzz target for 60 seconds
cargo fuzz run parse_token -- -max_total_time=60

# Run against an existing corpus
cargo fuzz run parse_token fuzz/corpus/parse_token/

# If a crash is found, minimise the input
cargo fuzz tmin parse_token fuzz/artifacts/parse_token/crash-*

# Generate coverage report from corpus
cargo fuzz coverage parse_token fuzz/corpus/parse_token/
```

### 5. Running Benchmarks

```bash
# Run all benchmarks
cargo bench --workspace

# Run a specific benchmark
cargo bench -p syntek-crypto aes_gcm

# Save a baseline for comparison
cargo bench -- --save-baseline main

# Compare against the saved baseline
cargo bench -- --baseline main
```

### 6. Security Scanning

```bash
# Full vulnerability scan (cargo-audit + cargo-deny + cargo-geiger)
/vuln-scan

# Review cryptographic implementations
/crypto-review

# Audit unsafe code and memory safety
/memory-audit

# Scan for hardcoded secrets and credentials
/scan-secrets

# Full supply chain audit
/supply-chain-audit
```

---

## Project Structure

```
syntek-rust-security/
├── agents/                  # Agent definitions (Markdown)
│   ├── infrastructure/      # Infrastructure agents
│   └── security/            # Security analysis agents
├── commands/                # User-invocable command definitions
├── docs/                    # Documentation and guides
│   ├── coding-principles.md # Original coding principles (brief)
│   ├── guides/              # Extended guides per topic
│   └── plans/               # Architectural planning documents
├── examples/                # Compilable Rust examples (200+ planned)
├── plugins/                 # Plugin tool source code (Rust)
│   └── src/
│       ├── cargo_tool.rs
│       ├── rustc_tool.rs
│       ├── vuln_db_tool.rs
│       ├── audit_tool.rs
│       ├── fuzzer_tool.rs
│       └── compliance_tool.rs
├── skills/                  # Skill definitions loaded by agents
├── templates/               # Project templates (36 planned)
│   └── init/                # Initialisation templates
├── CLAUDE.md                # Plugin configuration and agent reference
├── CODING-PRINCIPLES.md     # Coding standards (this plugin)
├── TESTING.md               # Testing guide (this plugin)
├── SECURITY.md              # Security architecture (this plugin)
├── DEVELOPMENT.md           # Development workflow (this document)
├── CHANGELOG.md             # Version history
└── README.md                # Plugin overview
```

---

## Adding a New Agent

1. Create the agent definition in the appropriate subdirectory:

   ```
   agents/security/<name>.md       # Security analysis agents
   agents/infrastructure/<name>.md # Infrastructure and tooling agents
   agents/setup/<name>.md          # Setup and initialisation agents
   ```

2. Follow the agent definition format:

   ```markdown
   # Agent Name

   Brief description of what this agent does.

   ## Agent Configuration

   - **Name**: agent-name
   - **Model**: sonnet | opus
   - **Type**: Security Agent | Infrastructure Agent | etc.

   ## Purpose

   Detailed description of the agent's purpose and scope.

   ## Execution Flow

   ### 1. Step Name
   ...

   ## Output Format
   ...

   ## Related Commands
   ...
   ```

3. Choose the model tier appropriately (see CLAUDE.md for guidance):
   - **Opus** — deep reasoning, architectural decisions, expert review
   - **Sonnet** — standard analysis, implementation, code generation

4. If the agent introduces a new user-invocable command, add it in `commands/`.

5. Update `IMPLEMENTATION-STATUS.md` to mark the new agent as implemented.

6. Update `README.md` to document the new agent.

---

## Adding a New Command

1. Create the command definition in `commands/<command-name>.md`:

   ```markdown
   # /command-name - Short Description

   One-line description of what this command does.

   ## Command

   ```
   /command-name [--option value]
   ```

   ## Arguments

   - `--option` - Description of the option

   ## What This Command Does

   Detailed explanation of the command workflow.

   ## Execution Steps

   1. **Step One** — Description
   2. **Step Two** — Description

   ## Example Usage

   ```bash
   /command-name --option value
   ```

   ## See Also

   - Related commands
   ```

2. Register the command in `config.json` under the appropriate category.

---

## Adding a New Template

1. Create the template in `templates/<template-name>.md`.

2. Include:
   - Cargo.toml with pinned dependencies
   - Recommended directory structure
   - Example source files with security patterns applied
   - Links to relevant agents and commands

3. Register the template in `config.json`.

---

## Adding Examples

Examples live in `examples/` and are organized by category. Each example must
be compilable and runnable.

```bash
# Test that all examples compile
cargo build --examples

# Run a specific example
cargo run --example encrypt_decrypt
```

Example naming convention:

```
examples/
├── crypto/
│   ├── 01_aes_gcm_encrypt.rs
│   ├── 02_chacha20_encrypt.rs
│   └── 03_key_derivation_argon2.rs
├── vault/
│   ├── 01_vault_kv_read.rs
│   └── 02_vault_token_renewal.rs
└── ssh/
    └── 01_ssh_wrapper_basic.rs
```

---

## Git Workflow

**Safety Protocol:**

- **NEVER** update git config
- **NEVER** run destructive git commands (`push --force`, `reset --hard`,
  `checkout .`, `restore .`, `clean -f`, `branch -D`) unless explicitly
  requested
- **NEVER** skip hooks (`--no-verify`, `--no-gpg-sign`, etc.)
- **NEVER** force push to `main`
- **CRITICAL:** Always create NEW commits rather than amending
- When staging files, prefer adding specific files by name rather than `git add -A`

### Creating Commits

```bash
# Check status and diff before staging
git status
git diff

# Review recent commits for style reference
git log --oneline -10

# Stage specific files
git add agents/security/new-agent.md
git add commands/new-command.md

# Create commit with Conventional Commits format
git commit -m "$(cat <<'EOF'
feat(agents): Add new-agent for XYZ security analysis

Brief explanation of why this was added and what problem it solves.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"

# Verify the commit succeeded
git status
git log --oneline -3
```

### Branch Naming

```
<story-id>/<short-description>

us042/vault-cert-rotation-agent
us043/add-ffi-security-examples
us044/update-ai-gateway-docs
```

### Pull Requests

A PR description must include:

1. Story reference (`STORY-042`)
2. What changed and why (not just what the diff shows)
3. Test plan: what was tested and how

---

## Release Process

Releases are managed by the `/version-bump` command and the `rust-version`
agent. See `VERSION-HISTORY.md` and `CHANGELOG.md` for history.

```bash
# Bump the version (patch/minor/major)
/version-bump --type minor

# This will:
# 1. Update VERSION file
# 2. Update config.json version
# 3. Add entry to CHANGELOG.md
# 4. Add entry to VERSION-HISTORY.md
# 5. Create a git commit and tag
```

---

## Troubleshooting

### Build Failures

```bash
# Clean build artefacts and rebuild
cargo clean && cargo build --workspace

# Check for conflicting dependency versions
cargo tree -d

# View expanded macros (useful for derive macro issues)
cargo expand -p syntek-crypto
```

### Test Failures

```bash
# Run a single failing test with full output
cargo test -p syntek-crypto test_name -- --nocapture --exact

# Increase stack size for deep recursion in tests
RUST_MIN_STACK=8388608 cargo test -p syntek-crypto

# Run tests single-threaded to isolate concurrency issues
cargo test -p syntek-vault -- --test-threads=1
```

### Clippy Warnings

```bash
# See all clippy suggestions with explanations
cargo clippy --workspace --all-features -- -D warnings 2>&1 | less

# Auto-fix what clippy can fix automatically
cargo clippy --fix --workspace --allow-staged
```

### Dependency Audit Failures

```bash
# See details on a specific advisory
cargo audit --json | jq '.vulnerabilities[]'

# Update a specific dependency to resolve an advisory
cargo update -p affected-crate

# Add an advisory to the ignore list (requires justification in deny.toml)
# [advisories]
# ignore = ["RUSTSEC-YYYY-NNNN"]
```

### Fuzz Crashes

```bash
# Reproduce a crash
cargo fuzz run parse_token fuzz/artifacts/parse_token/crash-*

# Minimise the crashing input
cargo fuzz tmin parse_token fuzz/artifacts/parse_token/crash-*

# Get a backtrace from the crash
RUST_BACKTRACE=1 cargo fuzz run parse_token fuzz/artifacts/parse_token/crash-*
```

---

## Related Documentation

- **[CODING-PRINCIPLES.md](CODING-PRINCIPLES.md)** — Coding standards and principles
- **[TESTING.md](TESTING.md)** — Testing guide, patterns, and examples
- **[SECURITY.md](SECURITY.md)** — Security architecture and cryptographic guidelines
- **[README.md](README.md)** — Plugin overview and agent reference
- **[CHANGELOG.md](CHANGELOG.md)** — Version history
- **[IMPLEMENTATION-STATUS.md](IMPLEMENTATION-STATUS.md)** — What is and isn't yet implemented
