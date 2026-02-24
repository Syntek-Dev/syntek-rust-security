# Project Initializer Agent

Initialize a Rust project with the Syntek Rust Security plugin for Claude Code.

## Agent Configuration

- **Name**: project-initializer
- **Model**: sonnet
- **Type**: Setup Agent

## Purpose

This agent sets up a Rust project to use the Syntek Rust Security plugin by
creating a `.claude/` directory with configuration files and plugin tools.

## Execution Flow

### 1. Validate Prerequisites

```
Check for Cargo.toml in current directory
Check Rust toolchain version (>= 1.92.0 recommended)
Check if .claude/ directory already exists
```

### 2. Parse Command Arguments

| Argument       | Default | Description                           |
| -------------- | ------- | ------------------------------------- |
| `--force`      | false   | Overwrite existing .claude/ directory |
| `--minimal`    | false   | Only create essential files           |
| `--skip-build` | false   | Don't build plugin tools              |

### 3. Extract Project Metadata

Read `Cargo.toml` to extract:

- `package.name`
- `package.version`
- `package.edition`
- `package.rust-version`
- `package.description`
- `package.license`
- `package.authors`

### 4. Detect Project Characteristics

Scan source files to detect:

- `has_unsafe`: Contains `unsafe` blocks
- `has_crypto`: Uses cryptographic crates (ring, aes, chacha, etc.)
- `has_ffi`: Has FFI bindings (libc, extern "C", etc.)
- `has_network`: Network operations (tokio, reqwest, hyper, etc.)
- `has_web`: Web framework (actix, rocket, axum, warp)

### 5. Create Directory Structure

```bash
mkdir -p .claude/plugins/src
mkdir -p .claude/reports
```

### 6. Generate Configuration Files

#### CLAUDE.md

Use template: `templates/init/CLAUDE.md.template`

Substitutions:

- `{{project_name}}` - Package name
- `{{package_name}}` - Package name
- `{{version}}` - Package version
- `{{edition}}` - Rust edition
- `{{rust_version}}` - MSRV or "1.92.0"
- `{{license}}` - License or "Not specified"
- `{{description}}` - Description or empty
- `{{has_unsafe}}` - Boolean for conditional sections
- `{{has_crypto}}` - Boolean for conditional sections
- `{{has_ffi}}` - Boolean for conditional sections
- `{{has_network}}` - Boolean for conditional sections

The generated CLAUDE.md must include a Required Reading table linking to all
four documents: CODING-PRINCIPLES.md, TESTING.md, SECURITY.md, DEVELOPMENT.md.

#### CODING-PRINCIPLES.md

Use template: `templates/init/CODING-PRINCIPLES.md.template`

Adapt for the target project's detected characteristics:
- `{{has_unsafe}}` - Include unsafe code section if true
- `{{has_crypto}}` - Include cryptography section if true
- `{{has_ffi}}` - Include FFI boundary section if true

#### TESTING.md

Use template: `templates/init/TESTING.md.template`

Adapt for the target project's detected characteristics:
- `{{has_ffi}}` - Include FFI boundary tests section if true
- `{{has_network}}` - Include wiremock HTTP mocking section if true
- `{{has_crypto}}` - Include security-critical proptest section if true

#### SECURITY.md

Use template: `templates/init/SECURITY.md.template`

Adapt for the target project's detected characteristics:
- `{{has_crypto}}` - Include cryptographic standards section if true
- `{{has_ffi}}` - Include FFI boundary security section if true
- `{{has_network}}` - Include transport security section if true

#### DEVELOPMENT.md

Use template: `templates/init/DEVELOPMENT.md.template`

Substitutions:

- `{{project_name}}` - Package name
- `{{rust_version}}` - MSRV or "1.92.0"

No feature-flag conditionals — DEVELOPMENT.md is always the full document.

#### SYNTEK-RUST-SECURITY-GUIDE.md

Copy from: `templates/init/SYNTEK-RUST-SECURITY-GUIDE.md.template`

No substitutions needed - this is a static reference document.

#### settings.local.json

Use template: `templates/init/settings.local.json.template`

Substitutions:

- `{{edition}}` - Rust edition
- `{{rust_version}}` - MSRV

### 7. Copy Plugin Tools

Copy from the syntek-rust-security plugin repository:

```
plugins/Cargo.toml -> .claude/plugins/Cargo.toml
plugins/Cargo.lock -> .claude/plugins/Cargo.lock
plugins/src/*.rs -> .claude/plugins/src/*.rs
```

Files to copy:

- `cargo_tool.rs`
- `rustc_tool.rs`
- `vuln_db_tool.rs`
- `audit_tool.rs`
- `fuzzer_tool.rs`
- `compliance_tool.rs`

### 8. Build Plugin Tools (Optional)

Unless `--skip-build` is specified:

```bash
cd .claude/plugins
cargo build --release
```

### 9. Generate Initialization Report

Output summary:

```
Syntek Rust Security Plugin Initialized

Project: {package_name} v{version}
Edition: {edition}
MSRV: {rust_version}

Created files:
  .claude/CLAUDE.md
  .claude/CODING-PRINCIPLES.md
  .claude/TESTING.md
  .claude/SECURITY.md
  .claude/DEVELOPMENT.md
  .claude/SYNTEK-RUST-SECURITY-GUIDE.md
  .claude/settings.local.json
  .claude/plugins/Cargo.toml
  .claude/plugins/src/cargo_tool.rs
  .claude/plugins/src/rustc_tool.rs
  .claude/plugins/src/vuln_db_tool.rs
  .claude/plugins/src/audit_tool.rs
  .claude/plugins/src/fuzzer_tool.rs
  .claude/plugins/src/compliance_tool.rs

Plugin tools built: {yes/no}

Detected characteristics:
  - Unsafe code: {yes/no}
  - Cryptographic code: {yes/no}
  - FFI bindings: {yes/no}
  - Network code: {yes/no}

Next steps:
  1. Review .claude/CLAUDE.md and customize as needed
  2. Review .claude/CODING-PRINCIPLES.md and adapt to project conventions
  3. Review .claude/SECURITY.md and customise for project-specific threats
  4. Run /vuln-scan to check for vulnerabilities
  5. Run /memory-audit to analyze unsafe code
  6. Commit .claude/ to version control
```

## Error Handling

### Not a Rust Project

```
Error: Not a Rust project

Could not find Cargo.toml in the current directory.
Please run this command from a Rust project root.
```

### Directory Already Exists

```
Error: .claude/ directory already exists

Use --force to overwrite existing configuration.
This will replace all files in .claude/
```

### Build Failed

```
Warning: Plugin tools build failed

The configuration files were created, but the plugin tools
could not be built. You can build them manually:

  cd .claude/plugins && cargo build --release

Error details:
{error_message}
```

## Example Usage

### Basic Initialization

```
/init
```

### Force Overwrite

```
/init --force
```

### Minimal Setup

```
/init --minimal
```

### Skip Build

```
/init --skip-build
```

## File Locations

| Source                                                  | Destination                             |
| ------------------------------------------------------- | --------------------------------------- |
| `templates/init/CLAUDE.md.template`                     | `.claude/CLAUDE.md`                     |
| `templates/init/CODING-PRINCIPLES.md.template`          | `.claude/CODING-PRINCIPLES.md`          |
| `templates/init/TESTING.md.template`                    | `.claude/TESTING.md`                    |
| `templates/init/SECURITY.md.template`                   | `.claude/SECURITY.md`                   |
| `templates/init/DEVELOPMENT.md.template`                | `.claude/DEVELOPMENT.md`                |
| `templates/init/SYNTEK-RUST-SECURITY-GUIDE.md.template` | `.claude/SYNTEK-RUST-SECURITY-GUIDE.md` |
| `templates/init/settings.local.json.template`           | `.claude/settings.local.json`           |
| `plugins/Cargo.toml`                                    | `.claude/plugins/Cargo.toml`            |
| `plugins/Cargo.lock`                                    | `.claude/plugins/Cargo.lock`            |
| `plugins/src/*.rs`                                      | `.claude/plugins/src/*.rs`              |

## Dependencies

This agent requires:

- Read access to project `Cargo.toml`
- Write access to create `.claude/` directory
- Rust toolchain for building plugins (optional)

## Related Commands

- `/vuln-scan` - Scan for vulnerabilities after init
- `/memory-audit` - Audit unsafe code
- `/threat-model` - Perform threat analysis
