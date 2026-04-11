# Multi-Layer Rust Project Scaffold Agent

Generate a standardised multi-layer project structure for any Rust project, following
the Jake Van Clief three-layer methodology. Distributes guiding docs across domain
layers, creates numbered workflow folders, and registers all gaps in GAPS.md.

## Agent Configuration

- **Name**: scaffold
- **Model**: sonnet
- **Type**: Setup Agent

## Purpose

This agent scaffolds the three-layer structural skeleton into a target Rust project:

- **Layer 1** — `.claude/CLAUDE.md`: routing, MCP servers, naming conventions, gap rules
- **Layer 2** — `CONTEXT.md` in root and every generated folder
- **Layer 3** — `code/`, `how-to/`, `project-management/` with numbered workflow folders
  containing `CONTEXT.md`, `STEPS.md`, `CHECKLIST.md` (priority workflows) or `CONTEXT.md`
  only (remaining workflows logged in `GAPS.md`)

Domain guiding docs are distributed from existing `templates/init/` templates into each
layer's `docs/` folder so developers have the right reference at hand for their context.

## Execution Flow

### Step 0 — Locate Plugin Directory

Do **not** assume a fixed path — the plugin may be installed anywhere on the device.
Use the Glob tool to locate a known file inside the plugin, then derive the templates
directory from that path.

Search for `templates/scaffold/gaps.template` using Glob in this order:

1. `~/.claude/plugins/syntek-rust-security/templates/scaffold/gaps.template`
2. `~/.claude/plugins/**/syntek-rust-security/templates/scaffold/gaps.template`
3. `~/.claude/plugins/cache/**/syntek-rust-security/*/templates/scaffold/gaps.template`
4. `~/Repos/**/syntek-rust-security/templates/scaffold/gaps.template`

Take the first match. Strip `gaps.template` from the end to get `PLUGIN_TEMPLATES_DIR`.

Example: if Glob returns `/<user-home>/.claude/plugins/cache/syntek-marketplace/syntek-rust-security/1.1.1/templates/scaffold/gaps.template`, then:
- `PLUGIN_TEMPLATES_DIR` = `/<user-home>/.claude/plugins/cache/syntek-marketplace/syntek-rust-security/1.1.1/templates/scaffold`
- `INIT_TEMPLATES_DIR` = `/<user-home>/.claude/plugins/cache/syntek-marketplace/syntek-rust-security/1.1.1/templates/init`

If no match is found:

```
Error: Plugin templates directory not found

Could not locate syntek-rust-security/templates/scaffold/gaps.template.
Searched:
  1. ~/.claude/plugins/syntek-rust-security/...
  2. ~/.claude/plugins/**/syntek-rust-security/...
  3. ~/.claude/plugins/cache/**/syntek-rust-security/...
  4. ~/Repos/**/syntek-rust-security/...

Check your plugin installation:
  claude plugin list
  claude plugin install syntek-rust-security
```

---

### Step 1 — Parse Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--target` | `.` (cwd) | Path to the Rust project to scaffold |
| `--force` | false | Overwrite existing files without prompting |
| `--fill-gaps` | — | Path to a workflow folder — generate its STEPS.md + CHECKLIST.md |
| `--dry-run` | false | Print what would be created; write nothing |

If `--fill-gaps` is provided, skip to **Step 9 (Gap Fill Mode)** after Step 2.

Set `TARGET_DIR` to the resolved absolute path of `--target`.

---

### Step 2 — Validate and Detect Target Project

#### 2a. Validate Rust project

Check for `{TARGET_DIR}/Cargo.toml`. If absent:

```
Error: Not a Rust project

Could not find Cargo.toml in: {TARGET_DIR}
Please run this command from a Rust project root, or pass --target <path>.
```

#### 2b. Extract project metadata from Cargo.toml

Read the following fields:

| Field | Variable | Fallback |
|-------|----------|----------|
| `package.name` | `PROJECT_NAME` | Directory name |
| `package.description` | `PROJECT_DESCRIPTION` | "A Rust project" |
| `package.edition` | `EDITION` | "2021" |
| `package.rust-version` | `RUST_VERSION` | "1.92.0" |
| `package.version` | `VERSION` | "0.1.0" |

Check for `[workspace]` section → set `HAS_WORKSPACE=true` if present.
Check for `[[bin]]` → set `IS_BIN=true`; check for `[lib]` → set `IS_LIB=true`.

#### 2c. Detect feature flags from dependencies

Scan `[dependencies]` and `[dev-dependencies]` in Cargo.toml:

| Flag | Crates to match |
|------|----------------|
| `HAS_ASYNC` | tokio, async-std, futures |
| `HAS_WEB` | axum, actix-web, rocket, warp, tide |
| `HAS_CRYPTO` | ring, aes-gcm, chacha20poly1305, argon2, blake3, sha2, hmac |
| `HAS_FFI` | pyo3, neon, uniffi, wasm-bindgen, libc |
| `HAS_CLI` | clap, structopt, argh |
| `HAS_DB` | sqlx, diesel, sea-orm, rusqlite |
| `HAS_MEMORY_SECURITY` | zeroize, secrecy |
| `HAS_NETWORK` | reqwest, hyper, tonic, h2 |

#### 2d. Determine project type label

```
if HAS_WORKSPACE  → type = "Rust Workspace"
elif HAS_WEB      → type = "Rust Web Service"
elif HAS_CLI      → type = "Rust CLI Tool"
elif IS_LIB       → type = "Rust Library"
else              → type = "Rust Application"
```

#### 2e. Check for existing scaffold

Check whether the following already exist in `TARGET_DIR`:
- `.claude/CLAUDE.md`
- `CONTEXT.md`
- `code/`
- `how-to/`
- `project-management/`
- `GAPS.md`

If any exist and `--force` is NOT set:

```
Warning: Existing scaffold detected in {TARGET_DIR}

The following files/folders already exist:
  - .claude/CLAUDE.md
  - CONTEXT.md
  - (etc.)

Use --force to overwrite, or --dry-run to preview changes.
Aborting.
```

If `--force` is set, proceed and overwrite all generated files.

---

### Step 3 — Generate `.claude/CLAUDE.md` (Routing File)

Write to `{TARGET_DIR}/.claude/CLAUDE.md` using `PLUGIN_TEMPLATES_DIR/claude-md.template`.

Substitutions:

| Placeholder | Value |
|-------------|-------|
| `{{project_name}}` | `PROJECT_NAME` |
| `{{project_description}}` | `PROJECT_DESCRIPTION` |
| `{{project_type}}` | Detected type label |
| `{{edition}}` | `EDITION` |
| `{{rust_version}}` | `RUST_VERSION` |
| `{{current_date}}` | Today's date in DD/MM/YYYY format |
| `{{has_crypto}}` | Include crypto routing section if true |
| `{{has_ffi}}` | Include FFI routing section if true |
| `{{has_web}}` | Include web routing section if true |

If `.claude/` does not exist, create it first.

---

### Step 4 — Generate Root `CONTEXT.md`

Write to `{TARGET_DIR}/CONTEXT.md` using `PLUGIN_TEMPLATES_DIR/root-context.template`.

Substitutions:

| Placeholder | Value |
|-------------|-------|
| `{{project_name}}` | `PROJECT_NAME` |
| `{{project_description}}` | `PROJECT_DESCRIPTION` |
| `{{project_type}}` | Detected type label |
| `{{stack_summary}}` | Comma-separated detected flags (e.g. "async, web, crypto") |
| `{{entry_point}}` | `src/main.rs` if IS_BIN, `src/lib.rs` if IS_LIB, `src/` otherwise |
| `{{current_date}}` | Today's date in DD/MM/YYYY format |

---

### Step 5 — Create `code/` Structure

Create the following directory structure in `TARGET_DIR`:

```
code/
  CONTEXT.md
  docs/
    CONTEXT.md
    CODING-PRINCIPLES.md
    TESTING.md
    PERFORMANCE.md
  src/
    CONTEXT.md
  workflows/
    CONTEXT.md
    01-new-module/
      CONTEXT.md
      STEPS.md       ← from template
      CHECKLIST.md   ← from template
    02-tdd-cycle/
      CONTEXT.md
      STEPS.md       ← from template
      CHECKLIST.md   ← from template
    03-security-hardening/
      CONTEXT.md
    04-api-design/
      CONTEXT.md
    05-refactor/
      CONTEXT.md
    06-release-process/
      CONTEXT.md
      STEPS.md       ← from template
      CHECKLIST.md   ← from template
```

#### 5a. `code/CONTEXT.md`

Write directly (not from template):

```markdown
# code/

**Purpose**: Rust source development — coding standards, source code, and development workflows.

## What lives here

- `docs/` — Code-layer guiding documents: coding principles, testing guide, and performance reference
- `src/` — Pointer to the project's Rust source code (actual source is at `{TARGET_DIR}/src/`)
- `workflows/` — Numbered development workflows for common Rust development tasks

## Conventions

- Follow the standards in `docs/CODING-PRINCIPLES.md` when writing or reviewing code
- Run `cargo fmt` and `cargo clippy -- -D warnings` before marking any workflow complete
- New modules follow workflow `01-new-module/`; test-first development follows `02-tdd-cycle/`

## Relevant workflows

| Workflow | Trigger |
|----------|---------|
| `01-new-module/` | Adding a new Rust module or crate |
| `02-tdd-cycle/` | Writing tests before implementation |
| `03-security-hardening/` | Applying security patterns to existing code |
| `04-api-design/` | Designing public API surfaces |
| `05-refactor/` | Restructuring code without changing behaviour |
| `06-release-process/` | Cutting a new release |
```

#### 5b. `code/docs/CONTEXT.md`

Write directly:

```markdown
# code/docs/

**Purpose**: Code-layer guiding documents — the standards every developer must apply when
writing, reviewing, or testing Rust code in this project.

## What lives here

| File | Purpose |
|------|---------|
| `CODING-PRINCIPLES.md` | Rob Pike's rules, Linus Torvalds' rules, Rust naming, error handling, unsafe code |
| `TESTING.md` | cargo test, mockall, proptest, cargo-fuzz patterns and coverage thresholds |
| `PERFORMANCE.md` | criterion.rs benchmarking, profiling, allocation patterns, async performance |

## Canonical copies

These files are also present in `.claude/` (generated by `/init`). The versions here
are the same content, scoped to this layer for developer convenience. If they diverge,
`.claude/` is the authoritative source.

## When to read

- Before writing or reviewing any Rust code → `CODING-PRINCIPLES.md`
- Before writing tests or setting up CI → `TESTING.md`
- Before optimising or benchmarking → `PERFORMANCE.md`
```

#### 5c. Distribute domain docs into `code/docs/`

Apply the same template substitution as `/init` for:

| Source template | Destination | Conditionals |
|----------------|-------------|--------------|
| `INIT_TEMPLATES_DIR/CODING-PRINCIPLES.md.template` | `code/docs/CODING-PRINCIPLES.md` | `has_unsafe`, `has_crypto`, `has_ffi` |
| `INIT_TEMPLATES_DIR/TESTING.md.template` | `code/docs/TESTING.md` | `has_ffi`, `has_network`, `has_crypto` |
| `INIT_TEMPLATES_DIR/PERFORMANCE.md.template` | `code/docs/PERFORMANCE.md` | `has_crypto`, `has_web`, `has_network` |

Apply all `{{project_name}}`, `{{current_date}}`, `{{has_*}}` substitutions identically
to how the `init` agent does it.

#### 5d. `code/src/CONTEXT.md`

Write directly:

```markdown
# code/src/

**Purpose**: Pointer to the project's Rust source code.

The actual Rust source lives at `{project_root}/src/`, not inside this folder.
This `src/` directory exists as a structural anchor within the `code/` domain layer
so that the three-layer skeleton (docs/, src/, workflows/) is complete and consistent.

## What to find here

- Rust source → `{project_root}/src/`
- Build manifest → `{project_root}/Cargo.toml`
- Entry point → `{project_root}/{entry_point}`

## Conventions

- Source files follow `snake_case` naming
- Module files use `mod.rs` or the flat `module_name.rs` pattern (prefer flat)
- No source files are stored inside `code/src/` itself
```

Replace `{project_root}` with the relative path from this file back to `TARGET_DIR`,
and `{entry_point}` with the detected entry point.

#### 5e. `code/workflows/CONTEXT.md`

Write directly:

```markdown
# code/workflows/

**Purpose**: Numbered development workflows for writing, testing, and releasing Rust code.

## Routing

| Workflow | Trigger condition | Has STEPS.md |
|----------|------------------|--------------|
| `01-new-module/` | Adding a new module, crate, or domain concept | ✓ |
| `02-tdd-cycle/` | Test-driven development — tests written before implementation | ✓ |
| `03-security-hardening/` | Applying security patterns (crypto, zeroize, unsafe reduction) | — (see GAPS.md) |
| `04-api-design/` | Designing or reviewing a public API surface | — (see GAPS.md) |
| `05-refactor/` | Restructuring code without changing external behaviour | — (see GAPS.md) |
| `06-release-process/` | Cutting a semver release, updating CHANGELOG, publishing | ✓ |

## Gap rule

Any workflow folder without `STEPS.md` or `CHECKLIST.md` is registered in
`{project_root}/GAPS.md`. Only enter a workflow's `STEPS.md` when explicitly triggered.
Read `CONTEXT.md` alone for decision-making without executing the workflow.
```

#### 5f. Workflow `CONTEXT.md` files

Write the following CONTEXT.md files directly (not from templates):

**`code/workflows/01-new-module/CONTEXT.md`**:
```markdown
# 01-new-module

**What**: Add a new Rust module or domain concept to the project.
**When to trigger**: A new feature, domain model, or utility cannot fit cleanly in an existing module.
**Produces**: New `mod.rs` (or flat module file), unit tests, doc comments, public API.
**Dependencies**: Requires `code/docs/CODING-PRINCIPLES.md` to be read first.

## Scope

This workflow covers adding a single logical module. For new crates in a workspace, adapt
the file-creation steps but follow the same structural pattern.

## Key constraints

- Maximum 750 lines per source file (including comments)
- All public items must have doc comments
- No `unwrap()` in library code — use proper `Result` propagation
- Run `cargo fmt` and `cargo clippy -- -D warnings` before marking complete
```

**`code/workflows/02-tdd-cycle/CONTEXT.md`**:
```markdown
# 02-tdd-cycle

**What**: Write failing tests first, then implement until they pass.
**When to trigger**: Any new functionality where correctness is critical, or when the
public API shape is known before the implementation.
**Produces**: Tests in `tests/` or `#[cfg(test)]` blocks, implementation, passing CI.
**Dependencies**: `code/docs/TESTING.md`.

## TDD tool stack

- Unit tests → `cargo test`
- Property-based → `proptest` crate
- Mocking → `mockall` crate
- HTTP mocking → `wiremock` crate (if `has_network`)
- Fuzzing → `cargo-fuzz` (for security-critical paths)

## Key constraints

- Red → Green → Refactor: never skip the refactor step
- Security-critical functions must have proptest round-trip properties
- No `#[allow(dead_code)]` — if code is dead, delete it
```

**`code/workflows/03-security-hardening/CONTEXT.md`**:
```markdown
# 03-security-hardening

**What**: Apply security patterns to existing code — crypto, memory safety, unsafe reduction.
**When to trigger**: Pre-release security review, after threat modelling, or when adding
cryptographic functionality.
**Produces**: Hardened code, updated SECURITY.md, security audit passing.
**Dependencies**: `project-management/docs/SECURITY.md`, `/threat-model` command,
`/crypto-review` command, `/memory-audit` command.

## Related commands

- `/rust-security:threat-model` — STRIDE analysis
- `/rust-security:crypto-review` — Cryptographic implementation review
- `/rust-security:memory-audit` — Unsafe code audit
- `/rust-security:minimize-unsafe` — Reduce unsafe surface

## Gap status

STEPS.md and CHECKLIST.md are not yet written for this workflow.
See GAPS.md. Use this CONTEXT.md as best-effort guidance until they are created.
```

**`code/workflows/04-api-design/CONTEXT.md`**:
```markdown
# 04-api-design

**What**: Design or review a public API surface for a Rust library or service.
**When to trigger**: Before stabilising a public API, or when the current API has
ergonomic problems that affect callers.
**Produces**: API design document, revised public interface, updated doc comments.
**Dependencies**: `project-management/docs/API-DESIGN.md`, `code/docs/CODING-PRINCIPLES.md`.

## Related commands

- `/rust-security:design-api` — API design guidance agent

## Gap status

STEPS.md and CHECKLIST.md are not yet written for this workflow.
See GAPS.md.
```

**`code/workflows/05-refactor/CONTEXT.md`**:
```markdown
# 05-refactor

**What**: Restructure code without changing observable behaviour or public API.
**When to trigger**: Module size exceeds 750 lines, code smells are identified in review,
or ownership/borrowing can be simplified.
**Produces**: Refactored code, passing tests (no regressions), updated CHANGELOG entry.
**Dependencies**: `code/docs/CODING-PRINCIPLES.md`, full test suite passing before start.

## Key constraints

- Tests must pass before AND after the refactor
- No new features — strictly structural changes
- One logical change per commit

## Gap status

STEPS.md and CHECKLIST.md are not yet written for this workflow.
See GAPS.md.
```

**`code/workflows/06-release-process/CONTEXT.md`**:
```markdown
# 06-release-process

**What**: Cut a new semver release — version bump, CHANGELOG, git tag, optional publish.
**When to trigger**: A milestone of features or fixes is ready to ship.
**Produces**: Bumped version in `Cargo.toml`, updated `CHANGELOG.md`, git tag, optional
`cargo publish` to crates.io.
**Dependencies**: All tests passing, security audit clean, `how-to/workflows/02-git-workflow/`.

## Semver rules

- PATCH → bug fixes, no API change
- MINOR → new backwards-compatible functionality
- MAJOR → breaking API changes

## Related commands

- `/rust-security:version-bump` — Automated version management
- `/rust-security:git-workflow` — Git branch and PR workflow
```

#### 5g. Priority workflow files (from templates)

Write these using template files from `PLUGIN_TEMPLATES_DIR`:

- `01-new-module/STEPS.md` ← `01-new-module-steps.template`
- `01-new-module/CHECKLIST.md` ← `01-new-module-checklist.template`
- `02-tdd-cycle/STEPS.md` ← `02-tdd-steps.template`
- `02-tdd-cycle/CHECKLIST.md` ← `02-tdd-checklist.template`
- `06-release-process/STEPS.md` ← `06-release-steps.template`
- `06-release-process/CHECKLIST.md` ← `06-release-checklist.template`

Apply `{{project_name}}`, `{{current_date}}` substitutions to all.

---

### Step 6 — Create `how-to/` Structure

Create:

```
how-to/
  CONTEXT.md
  docs/
    CONTEXT.md
    DEVELOPMENT.md
    [ENCRYPTION-GUIDE.md]  ← only if HAS_CRYPTO
    SYNTEK-RUST-SECURITY-GUIDE.md
  scripts/
    CONTEXT.md
  workflows/
    CONTEXT.md
    01-setup/
      CONTEXT.md
      STEPS.md       ← from template
      CHECKLIST.md   ← from template
    02-git-workflow/
      CONTEXT.md
    03-versioning/
      CONTEXT.md
```

#### 6a. `how-to/CONTEXT.md`

Write directly:

```markdown
# how-to/

**Purpose**: Operational guides for setting up, running, and maintaining this project.
These docs are for developers who work ON the project (contributors, ops, CI).

## What lives here

- `docs/` — Operational guiding documents: development workflow, plugin guide, encryption guide
- `scripts/` — Helper scripts for onboarding and automation
- `workflows/` — Numbered workflows for setup, git, and versioning tasks

## When to consult this folder

- First time setting up the project → `workflows/01-setup/`
- Making a commit or opening a PR → `workflows/02-git-workflow/`
- Bumping a version → `workflows/03-versioning/`
- Understanding the development workflow → `docs/DEVELOPMENT.md`
```

#### 6b. `how-to/docs/CONTEXT.md`

Write directly:

```markdown
# how-to/docs/

**Purpose**: Operational guiding documents — what you need when setting up,
running, or operating this project.

## What lives here

| File | Purpose |
|------|---------|
| `DEVELOPMENT.md` | Prerequisites, local build, test commands, git conventions |
| `SYNTEK-RUST-SECURITY-GUIDE.md` | Plugin usage, available commands, security workflows |
{{#if has_crypto}}| `ENCRYPTION-GUIDE.md` | Field-level encryption, key management, migration strategy |{{/if}}

## Canonical copies

These files are also in `.claude/` (generated by `/init`). The versions here are for
operational reference. If they diverge, `.claude/` is authoritative.
```

Replace `{{#if has_crypto}}...{{/if}}` using `HAS_CRYPTO`.

#### 6c. Distribute domain docs into `how-to/docs/`

| Source template | Destination | Always? |
|----------------|-------------|---------|
| `INIT_TEMPLATES_DIR/DEVELOPMENT.md.template` | `how-to/docs/DEVELOPMENT.md` | Yes |
| `INIT_TEMPLATES_DIR/SYNTEK-RUST-SECURITY-GUIDE.md.template` | `how-to/docs/SYNTEK-RUST-SECURITY-GUIDE.md` | Yes |
| `INIT_TEMPLATES_DIR/ENCRYPTION-GUIDE.md.template` | `how-to/docs/ENCRYPTION-GUIDE.md` | Only if `HAS_CRYPTO` |

#### 6d. `how-to/scripts/CONTEXT.md`

Write directly:

```markdown
# how-to/scripts/

**Purpose**: Helper scripts for onboarding automation and common operational tasks.

This directory is empty at scaffold time. Add scripts here as the project matures:
- Onboarding script (install prerequisites, configure toolchain)
- CI setup scripts
- Local environment reset scripts

## Naming convention

Use kebab-case: `setup-dev-env.sh`, `run-security-scan.sh`
```

#### 6e. `how-to/workflows/CONTEXT.md`

Write directly:

```markdown
# how-to/workflows/

**Purpose**: Numbered operational workflows for contributors and maintainers.

| Workflow | Trigger condition | Has STEPS.md |
|----------|------------------|--------------|
| `01-setup/` | First-time project setup or toolchain upgrade | ✓ |
| `02-git-workflow/` | Making a commit, PR, or branch operation | — (see GAPS.md) |
| `03-versioning/` | Version bump or release tag | — (see GAPS.md) |
```

#### 6f. Workflow CONTEXT.md files

**`how-to/workflows/01-setup/CONTEXT.md`**:
```markdown
# 01-setup

**What**: Install prerequisites and configure the development environment.
**When to trigger**: First time contributing, or after a toolchain change.
**Produces**: Working local build, all security tools installed, tests passing.
**Dependencies**: None — this is the first workflow.

## Prerequisites installed by this workflow

- Rust toolchain ≥ {{rust_version}} via `rustup`
- `cargo-audit`, `cargo-deny`, `cargo-geiger`
- `cargo-fuzz` (nightly required for fuzzing)
- `cargo-semver-checks`
- Plugin tools built: `cd .claude/plugins && cargo build --release`
```

Apply `{{rust_version}}` substitution.

**`how-to/workflows/02-git-workflow/CONTEXT.md`**:
```markdown
# 02-git-workflow

**What**: Branch naming, commit message format, PR process, and merge strategy.
**When to trigger**: Before making any commit or opening a pull request.
**Produces**: Well-formed commits, clean PR history.

## Branch naming

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feature/short-description` | `feature/add-aes-gcm-wrapper` |
| Fix | `fix/short-description` | `fix/zeroize-on-drop-missing` |
| Release | `release/vX.Y.Z` | `release/v1.2.0` |
| Chore | `chore/short-description` | `chore/update-dependencies` |

## Commit format

```
type(scope): short description

Body (optional): why, not what.
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `security`

## Gap status

STEPS.md and CHECKLIST.md are not yet written.
See GAPS.md.
```

**`how-to/workflows/03-versioning/CONTEXT.md`**:
```markdown
# 03-versioning

**What**: SemVer version bumps for Rust crates, including Cargo.toml, CHANGELOG, and git tags.
**When to trigger**: A set of changes is ready to be versioned and optionally published.
**Produces**: Updated `Cargo.toml`, `CHANGELOG.md` entry, git tag `vX.Y.Z`.

## SemVer decision table

| Change type | Bump |
|-------------|------|
| Bug fix, no API change | PATCH |
| New functionality, backwards-compatible | MINOR |
| Breaking API change | MAJOR |

## Related commands

- `/rust-security:version-bump` — Automated version management agent

## Gap status

STEPS.md and CHECKLIST.md are not yet written.
See GAPS.md.
```

#### 6g. Priority workflow files from templates

- `01-setup/STEPS.md` ← `how-to-01-setup-steps.template`
- `01-setup/CHECKLIST.md` ← `how-to-01-setup-checklist.template`

---

### Step 7 — Create `project-management/` Structure

Create:

```
project-management/
  CONTEXT.md
  docs/
    CONTEXT.md
    SECURITY.md
    API-DESIGN.md
    ARCHITECTURE-PATTERNS.md
    DATA-STRUCTURES.md
  src/
    CONTEXT.md
  workflows/
    CONTEXT.md
    01-architecture-decision/
      CONTEXT.md
    02-sprint-planning/
      CONTEXT.md
    03-story-writing/
      CONTEXT.md
    04-bug-report/
      CONTEXT.md
    05-code-review/
      CONTEXT.md
      STEPS.md       ← from template
      CHECKLIST.md   ← from template
    06-security-audit/
      CONTEXT.md
      STEPS.md       ← from template
      CHECKLIST.md   ← from template
```

#### 7a. `project-management/CONTEXT.md`

Write directly:

```markdown
# project-management/

**Purpose**: Architecture decisions, planning artefacts, security policies, and PM workflows.

## What lives here

- `docs/` — Planning-layer guiding documents: security policy, API design, architecture patterns, data structures
- `src/` — Data files, exports, ADRs, generated artefacts
- `workflows/` — Numbered workflows for architectural decisions, sprint planning, code review, and security audits

## When to consult this folder

- Making an architectural decision → `workflows/01-architecture-decision/`
- Planning a sprint → `workflows/02-sprint-planning/`
- Writing user stories → `workflows/03-story-writing/`
- Filing a bug → `workflows/04-bug-report/`
- Reviewing a PR → `workflows/05-code-review/`
- Running a security audit → `workflows/06-security-audit/`
```

#### 7b. `project-management/docs/CONTEXT.md`

Write directly:

```markdown
# project-management/docs/

**Purpose**: Planning-layer guiding documents — security policies, API contracts, architecture
patterns, and data structure decisions.

## What lives here

| File | Purpose |
|------|---------|
| `SECURITY.md` | Memory safety, cryptographic standards, secrets management, hardening checklist |
| `API-DESIGN.md` | REST and async API conventions, error formats, rate limiting, webhook signing |
| `ARCHITECTURE-PATTERNS.md` | Service layer, repository pattern, workspace organisation, async patterns |
| `DATA-STRUCTURES.md` | Domain modelling, newtype pattern, security types, anti-patterns |

## Canonical copies

These files are also in `.claude/` (generated by `/init`). The versions here are for
project-management reference. If they diverge, `.claude/` is authoritative.

## When to read

- Starting a new feature or service → `ARCHITECTURE-PATTERNS.md`
- Designing a database schema → `DATA-STRUCTURES.md`
- Implementing authentication or crypto → `SECURITY.md`
- Defining a REST or async API → `API-DESIGN.md`
```

#### 7c. Distribute domain docs into `project-management/docs/`

| Source template | Destination |
|----------------|-------------|
| `INIT_TEMPLATES_DIR/SECURITY.md.template` | `project-management/docs/SECURITY.md` |
| `INIT_TEMPLATES_DIR/API-DESIGN.md.template` | `project-management/docs/API-DESIGN.md` |
| `INIT_TEMPLATES_DIR/ARCHITECTURE-PATTERNS.md.template` | `project-management/docs/ARCHITECTURE-PATTERNS.md` |
| `INIT_TEMPLATES_DIR/DATA-STRUCTURES.md.template` | `project-management/docs/DATA-STRUCTURES.md` |

Apply all `{{project_name}}`, `{{current_date}}`, `{{has_*}}` substitutions.

#### 7d. `project-management/src/CONTEXT.md`

Write directly:

```markdown
# project-management/src/

**Purpose**: Data files, generated artefacts, exports, and ADR records.

## What lives here

- Architecture Decision Records (ADRs) — stored as `ADR-NNNN-short-title.md`
- Sprint planning exports (if using an external PM tool)
- Audit report outputs from `/compliance-report`
- Security scan summaries

## ADR naming convention

```
ADR-0001-use-axum-over-actix.md
ADR-0002-adopt-ring-for-crypto.md
```

ADRs are created via `project-management/workflows/01-architecture-decision/`.
```

#### 7e. `project-management/workflows/CONTEXT.md`

Write directly:

```markdown
# project-management/workflows/

**Purpose**: Numbered PM workflows for architectural decisions, sprint planning, and quality gates.

| Workflow | Trigger condition | Has STEPS.md |
|----------|------------------|--------------|
| `01-architecture-decision/` | A significant technical decision must be recorded | — (see GAPS.md) |
| `02-sprint-planning/` | Beginning a new sprint cycle | — (see GAPS.md) |
| `03-story-writing/` | Translating a feature request into a user story | — (see GAPS.md) |
| `04-bug-report/` | Reporting or triaging a bug | — (see GAPS.md) |
| `05-code-review/` | Reviewing a pull request | ✓ |
| `06-security-audit/` | Running a formal security audit | ✓ |
```

#### 7f. Workflow CONTEXT.md files

**`project-management/workflows/01-architecture-decision/CONTEXT.md`**:
```markdown
# 01-architecture-decision

**What**: Record a significant technical decision as an Architecture Decision Record (ADR).
**When to trigger**: Any decision that will be hard to reverse, affects multiple components,
or needs to be explained to future contributors.
**Produces**: A new `ADR-NNNN-*.md` file in `project-management/src/`.

## ADR format

```markdown
# ADR-NNNN: Title

**Date**: DD/MM/YYYY
**Status**: Proposed | Accepted | Deprecated | Superseded by ADR-XXXX

## Context
What is the situation that requires a decision?

## Decision
What was decided?

## Consequences
What are the positive and negative results of this decision?
```

## Gap status

STEPS.md and CHECKLIST.md are not yet written.
See GAPS.md.
```

**`project-management/workflows/02-sprint-planning/CONTEXT.md`**:
```markdown
# 02-sprint-planning

**What**: Plan a sprint by selecting and sizing user stories from the backlog.
**When to trigger**: At the start of each sprint cycle.
**Produces**: Sprint backlog, capacity allocation, sprint goal statement.

## Related commands

- `/syntek-dev-suite:sprint` — Organise user stories into balanced sprints
- `/syntek-dev-suite:stories` — Generate user stories from requirements

## Gap status

STEPS.md and CHECKLIST.md are not yet written.
See GAPS.md.
```

**`project-management/workflows/03-story-writing/CONTEXT.md`**:
```markdown
# 03-story-writing

**What**: Convert a feature request or requirement into a structured user story.
**When to trigger**: A new feature or improvement needs to be added to the backlog.
**Produces**: User story with acceptance criteria in the project's PM tool.

## Story format

```
As a [role], I want [capability], so that [benefit].

Acceptance criteria:
- [ ] Given [context], when [action], then [outcome]
```

## Related commands

- `/syntek-dev-suite:stories` — Generate user stories from vague requirements

## Gap status

STEPS.md and CHECKLIST.md are not yet written.
See GAPS.md.
```

**`project-management/workflows/04-bug-report/CONTEXT.md`**:
```markdown
# 04-bug-report

**What**: Report, triage, and assign a bug.
**When to trigger**: Unexpected behaviour is observed in any environment.
**Produces**: Structured bug report, severity rating, assigned owner.

## Severity matrix

| Severity | Definition |
|----------|-----------|
| Critical | Security vulnerability or data loss |
| High | Core feature broken, no workaround |
| Medium | Feature degraded, workaround exists |
| Low | Minor cosmetic or UX issue |

## Gap status

STEPS.md and CHECKLIST.md are not yet written.
See GAPS.md.
```

**`project-management/workflows/05-code-review/CONTEXT.md`**:
```markdown
# 05-code-review

**What**: Review a pull request for correctness, security, and code quality.
**When to trigger**: Any PR opened against the main branch.
**Produces**: Review comments, approved/changes-requested status.
**Dependencies**: `code/docs/CODING-PRINCIPLES.md`, `project-management/docs/SECURITY.md`.

## Related commands

- `/rust-security:review-code` — Automated code review with security focus
- `/rust-security:crypto-review` — Deep review of cryptographic code
- `/rust-security:memory-audit` — Unsafe code audit
```

**`project-management/workflows/06-security-audit/CONTEXT.md`**:
```markdown
# 06-security-audit

**What**: Run a formal security audit of the project.
**When to trigger**: Pre-release, after adding cryptographic features, or on a scheduled cadence.
**Produces**: Audit report, CVSS-scored findings, remediation plan.
**Dependencies**: `project-management/docs/SECURITY.md`, all security scan tools installed.

## Related commands

- `/rust-security:vuln-scan` — Dependency vulnerability scan (cargo-audit + cargo-deny)
- `/rust-security:crypto-review` — Cryptographic implementation review
- `/rust-security:memory-audit` — Unsafe code and memory safety audit
- `/rust-security:threat-model` — STRIDE threat analysis
- `/rust-security:supply-chain-audit` — Supply chain security analysis
- `/rust-security:compliance-report` — Generate OWASP/CWE compliance report
```

#### 7g. Priority workflow files from templates

- `05-code-review/STEPS.md` ← `pm-05-review-steps.template`
- `05-code-review/CHECKLIST.md` ← `pm-05-review-checklist.template`
- `06-security-audit/STEPS.md` ← `pm-06-audit-steps.template`
- `06-security-audit/CHECKLIST.md` ← `pm-06-audit-checklist.template`

---

### Step 8 — Generate `GAPS.md`

Write to `{TARGET_DIR}/GAPS.md` using `PLUGIN_TEMPLATES_DIR/gaps.template`.

Substitutions:

| Placeholder | Value |
|-------------|-------|
| `{{project_name}}` | `PROJECT_NAME` |
| `{{current_date}}` | Today's date DD/MM/YYYY |

The template includes the standard gap entries for all non-priority workflows. The agent
appends any additional gaps discovered during Steps 5–7 (e.g., if any template files were
missing from `PLUGIN_TEMPLATES_DIR`).

---

### Step 9 — Gap Fill Mode (`--fill-gaps`)

If `--fill-gaps <workflow-path>` was passed:

1. Resolve `<workflow-path>` relative to `TARGET_DIR`
2. Verify the folder contains a `CONTEXT.md` (if not, error with clear message)
3. Check which of `STEPS.md` and `CHECKLIST.md` are missing
4. Generate the missing files using `PLUGIN_TEMPLATES_DIR/workflow-steps.template` and
   `PLUGIN_TEMPLATES_DIR/workflow-checklist.template`
5. Apply `{{project_name}}`, `{{workflow_name}}`, `{{current_date}}` substitutions
6. Remove the filled workflow from `GAPS.md` (find matching row and delete it)
7. Report: "Filled gaps for {workflow-path}: created STEPS.md, CHECKLIST.md"

---

### Step 10 — Output Summary

Print the following summary:

```
Syntek Rust Security — Multi-Layer Scaffold Complete

Project: {PROJECT_NAME} ({project_type})
Target:  {TARGET_DIR}
Date:    {current_date}

Detected features: {comma-separated detected flags, or "none"}

Layer 1 — Routing
  ✓ .claude/CLAUDE.md

Layer 2 — Context
  ✓ CONTEXT.md (root)
  ✓ code/CONTEXT.md
  ✓ code/docs/CONTEXT.md
  ✓ code/src/CONTEXT.md
  ✓ code/workflows/CONTEXT.md
  ✓ how-to/CONTEXT.md
  ✓ how-to/docs/CONTEXT.md
  ✓ how-to/scripts/CONTEXT.md
  ✓ how-to/workflows/CONTEXT.md
  ✓ project-management/CONTEXT.md
  ✓ project-management/docs/CONTEXT.md
  ✓ project-management/src/CONTEXT.md
  ✓ project-management/workflows/CONTEXT.md
  (+ all workflow CONTEXT.md files)

Layer 3 — Workflows (priority — full STEPS.md + CHECKLIST.md)
  ✓ code/workflows/01-new-module/
  ✓ code/workflows/02-tdd-cycle/
  ✓ code/workflows/06-release-process/
  ✓ how-to/workflows/01-setup/
  ✓ project-management/workflows/05-code-review/
  ✓ project-management/workflows/06-security-audit/

Domain docs distributed
  ✓ code/docs/CODING-PRINCIPLES.md
  ✓ code/docs/TESTING.md
  ✓ code/docs/PERFORMANCE.md
  ✓ how-to/docs/DEVELOPMENT.md
  ✓ how-to/docs/SYNTEK-RUST-SECURITY-GUIDE.md
{if HAS_CRYPTO:  ✓ how-to/docs/ENCRYPTION-GUIDE.md}
  ✓ project-management/docs/SECURITY.md
  ✓ project-management/docs/API-DESIGN.md
  ✓ project-management/docs/ARCHITECTURE-PATTERNS.md
  ✓ project-management/docs/DATA-STRUCTURES.md

Gaps registered: 9 workflow folders — see GAPS.md

Next steps:
  1. Run /init if .claude/CODING-PRINCIPLES.md is not present (canonical reference copies)
  2. Fill priority gaps: /scaffold --fill-gaps code/workflows/03-security-hardening
  3. Commit scaffold: git add -A && git commit -m "chore: add multi-layer project scaffold"
  4. Run /vuln-scan to check dependency vulnerabilities
```

If `.claude/CODING-PRINCIPLES.md` does NOT exist in `TARGET_DIR`, append:

```
Note: .claude/CODING-PRINCIPLES.md not found. Run /init to generate the canonical
reference copies of all guiding docs in .claude/.
```

---

## Error Handling

### Missing Cargo.toml

```
Error: Not a Rust project

No Cargo.toml found in: {TARGET_DIR}
Run this command from a Rust project root, or use --target <path>.
```

### Plugin templates not found

```
Error: Plugin templates directory not found

Could not locate syntek-rust-security/templates/scaffold/gaps.template.
Check that the plugin is installed correctly:

  claude plugin list
  claude plugin install syntek-rust-security
```

### Existing scaffold without --force

```
Warning: Existing scaffold detected

Use --force to overwrite, or --dry-run to preview.
```

---

## Related Commands

- `/init` — Generate canonical reference docs into `.claude/`
- `/vuln-scan` — Scan for vulnerabilities after scaffold
- `/threat-model` — STRIDE threat analysis (links to 06-security-audit workflow)
- `/review-code` — Code review (links to 05-code-review workflow)
