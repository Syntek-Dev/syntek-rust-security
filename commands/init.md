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

8. **Generate SYNTEK-RUST-SECURITY-GUIDE.md** Create security guidelines
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

All four required documents are generated from the plugin's templates and
adapted for the target project's characteristics:

| File | Template Source | Purpose |
| ---- | --------------- | ------- |
| `CODING-PRINCIPLES.md` | `templates/init/CODING-PRINCIPLES.md.template` | Coding standards |
| `TESTING.md` | `templates/init/TESTING.md.template` | Testing guide |
| `SECURITY.md` | `templates/init/SECURITY.md.template` | Security architecture |
| `DEVELOPMENT.md` | `templates/init/DEVELOPMENT.md.template` | Development workflow |

### CLAUDE.md Template

```markdown
# {project_name} - Claude Code Configuration

## Project Overview

This is a Rust project configured with the Syntek Rust Security plugin.

**Package**: {package_name} **Version**: {version} **Edition**: {edition}
**MSRV**: {rust_version}

## Required Reading

All agents must read these four documents before writing or reviewing any code:

| Document | Purpose |
| -------- | ------- |
| **[CODING-PRINCIPLES.md](CODING-PRINCIPLES.md)** | Coding standards, error handling, naming, unsafe code |
| **[TESTING.md](TESTING.md)** | Testing guide, patterns, and examples |
| **[SECURITY.md](SECURITY.md)** | Memory safety, cryptographic standards, secrets management |
| **[DEVELOPMENT.md](DEVELOPMENT.md)** | Development workflow, tooling, git conventions |

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
