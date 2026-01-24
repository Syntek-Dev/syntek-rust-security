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
   - Available security commands
   - Project-specific security considerations
   - Links to examples and documentation

4. **Generate SYNTEK-RUST-SECURITY-GUIDE.md** Create security guidelines
   covering:
   - Memory safety patterns
   - Cryptographic best practices
   - Unsafe code guidelines
   - Dependency security
   - Common vulnerability patterns

5. **Generate settings.local.json** Configure Claude Code with:
   - Plugin path references
   - Security-focused default behaviors
   - Tool permissions

6. **Copy Plugin Tools** Copy the Rust plugin tools from the
   syntek-rust-security repository:
   - All `*.rs` files from `plugins/src/`
   - `Cargo.toml` for the plugin tools

7. **Build Plugin Tools (Optional)**
   ```bash
   cd .claude/plugins && cargo build --release
   ```

## Generated Files

### CLAUDE.md Template

```markdown
# {project_name} - Claude Code Configuration

## Project Overview

This is a Rust project configured with the Syntek Rust Security plugin.

**Package**: {package_name} **Version**: {version} **Edition**: {edition}
**MSRV**: {rust_version}

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

## Coding Guidelines

1. Prefer safe Rust patterns over unsafe code
2. Use established cryptographic libraries (ring, RustCrypto)
3. Validate all external inputs
4. Use `zeroize` for sensitive data
5. Keep dependencies updated and audited

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
   - Customize security guidelines as needed

2. **Build Plugin Tools**

   ```bash
   cd .claude/plugins && cargo build --release
   ```

3. **Run Initial Security Scan**

   ```bash
   claude /vuln-scan
   claude /memory-audit
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
