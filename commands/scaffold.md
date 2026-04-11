# /scaffold — Multi-Layer Rust Project Scaffold

Generate a standardised three-layer project structure in any Rust project, following the
Jake Van Clief multi-layer methodology. Distributes guiding docs across domain layers,
creates numbered workflow folders with `CONTEXT.md`, `STEPS.md`, and `CHECKLIST.md`,
and registers all workflow gaps in `GAPS.md`.

## Command

```
/scaffold [--target <path>] [--force] [--fill-gaps <workflow-path>] [--dry-run]
```

## Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--target <path>` | `.` (cwd) | Path to the Rust project to scaffold |
| `--force` | false | Overwrite existing scaffold files without prompting |
| `--fill-gaps <path>` | — | Generate `STEPS.md` + `CHECKLIST.md` for one workflow folder |
| `--dry-run` | false | Print what would be created without writing any files |

## What This Command Does

Scaffolds the complete three-layer structure into the target Rust project:

### Layer 1 — Routing (`.claude/CLAUDE.md`)

A project-specific routing and orchestration file containing:
- MCP server configuration (context7, docfork, claude-chrome, code-review-graph)
- Naming conventions (kebab-case files, `snake_case` Rust, `SCREAMING_SNAKE` constants)
- Routing table — which folder or workflow to consult for each task type
- Skills/commands rules — check `.claude/CLAUDE.md` before generating new tooling
- Gap registration rule — missing `STEPS.md` or `CHECKLIST.md` must be logged in `GAPS.md`

### Layer 2 — Context (`CONTEXT.md` in every folder)

A `CONTEXT.md` file in the project root and every generated folder, explaining:
- The purpose of that folder
- What files live inside it and why
- Constraints or conventions specific to that layer
- Which workflows are relevant to that folder's concerns

### Layer 3 — Domain folders with workflow structure

Three top-level domain folders, each with `docs/`, `src/` (or `scripts/`), and `workflows/`:

```
{project}/
├── .claude/
│   └── CLAUDE.md                    # Routing and orchestration
├── CONTEXT.md                       # Root project context
├── GAPS.md                          # Gap register
│
├── code/                            # Rust development layer
│   ├── CONTEXT.md
│   ├── docs/
│   │   ├── CONTEXT.md
│   │   ├── CODING-PRINCIPLES.md     # ← distributed from plugin templates
│   │   ├── TESTING.md               # ← distributed from plugin templates
│   │   └── PERFORMANCE.md           # ← distributed from plugin templates
│   ├── src/
│   │   └── CONTEXT.md               # Pointer to project root src/
│   └── workflows/
│       ├── CONTEXT.md
│       ├── 01-new-module/           # CONTEXT.md + STEPS.md + CHECKLIST.md ✓
│       ├── 02-tdd-cycle/            # CONTEXT.md + STEPS.md + CHECKLIST.md ✓
│       ├── 03-security-hardening/   # CONTEXT.md only (gap logged)
│       ├── 04-api-design/           # CONTEXT.md only (gap logged)
│       ├── 05-refactor/             # CONTEXT.md only (gap logged)
│       └── 06-release-process/      # CONTEXT.md + STEPS.md + CHECKLIST.md ✓
│
├── how-to/                          # Operational layer
│   ├── CONTEXT.md
│   ├── docs/
│   │   ├── CONTEXT.md
│   │   ├── DEVELOPMENT.md           # ← distributed from plugin templates
│   │   ├── SYNTEK-RUST-SECURITY-GUIDE.md
│   │   └── ENCRYPTION-GUIDE.md      # ← only if crypto deps detected
│   ├── scripts/
│   │   └── CONTEXT.md
│   └── workflows/
│       ├── CONTEXT.md
│       ├── 01-setup/                # CONTEXT.md + STEPS.md + CHECKLIST.md ✓
│       ├── 02-git-workflow/         # CONTEXT.md only (gap logged)
│       └── 03-versioning/           # CONTEXT.md only (gap logged)
│
└── project-management/              # PM and architecture layer
    ├── CONTEXT.md
    ├── docs/
    │   ├── CONTEXT.md
    │   ├── SECURITY.md              # ← distributed from plugin templates
    │   ├── API-DESIGN.md            # ← distributed from plugin templates
    │   ├── ARCHITECTURE-PATTERNS.md # ← distributed from plugin templates
    │   └── DATA-STRUCTURES.md       # ← distributed from plugin templates
    ├── src/
    │   └── CONTEXT.md               # ADRs, sprint artefacts, audit outputs
    └── workflows/
        ├── CONTEXT.md
        ├── 01-architecture-decision/ # CONTEXT.md only (gap logged)
        ├── 02-sprint-planning/       # CONTEXT.md only (gap logged)
        ├── 03-story-writing/         # CONTEXT.md only (gap logged)
        ├── 04-bug-report/            # CONTEXT.md only (gap logged)
        ├── 05-code-review/           # CONTEXT.md + STEPS.md + CHECKLIST.md ✓
        └── 06-security-audit/        # CONTEXT.md + STEPS.md + CHECKLIST.md ✓
```

### Domain docs distribution

The scaffold agent generates the relevant guiding docs into each domain layer using the
same templates as `/init` (with project-characteristic conditionals applied):

| Domain layer | Docs generated |
|---|---|
| `code/docs/` | `CODING-PRINCIPLES.md`, `TESTING.md`, `PERFORMANCE.md` |
| `how-to/docs/` | `DEVELOPMENT.md`, `SYNTEK-RUST-SECURITY-GUIDE.md`, `ENCRYPTION-GUIDE.md`* |
| `project-management/docs/` | `SECURITY.md`, `API-DESIGN.md`, `ARCHITECTURE-PATTERNS.md`, `DATA-STRUCTURES.md` |

\* `ENCRYPTION-GUIDE.md` is only generated if crypto dependencies are detected
(`ring`, `aes-gcm`, `chacha20poly1305`, `argon2`, `blake3`, `sha2`, or `hmac`).

---

## Execution Steps

1. **Locate plugin templates** — find `syntek-rust-security/templates/scaffold/`
2. **Validate target** — confirm `Cargo.toml` exists at `--target`
3. **Detect project** — extract metadata and feature flags from `Cargo.toml`
4. **Check for existing scaffold** — warn if present (use `--force` to overwrite)
5. **Generate `.claude/CLAUDE.md`** — routing file from `claude-md.template`
6. **Generate root `CONTEXT.md`** — from `root-context.template`
7. **Create `code/` structure** — folders, CONTEXT.md files, domain docs, priority workflows
8. **Create `how-to/` structure** — folders, CONTEXT.md files, domain docs, setup workflow
9. **Create `project-management/` structure** — folders, CONTEXT.md files, domain docs, review/audit workflows
10. **Generate `GAPS.md`** — log all workflow folders missing `STEPS.md` or `CHECKLIST.md`
11. **Print summary** — files created, gaps registered, next steps

---

## Examples

### Scaffold the current Rust project

```bash
/scaffold
```

Scaffolds the project in the current working directory.

### Scaffold an adjacent project

```bash
/scaffold --target ../my-rust-service
```

Scaffolds a project at the specified path.

### Preview without writing

```bash
/scaffold --dry-run
```

Prints all files that would be created without writing anything to disk.

### Force overwrite of existing scaffold

```bash
/scaffold --force
```

Overwrites all existing `CLAUDE.md`, `CONTEXT.md`, and workflow files.

### Fill a specific workflow gap

```bash
/scaffold --fill-gaps code/workflows/03-security-hardening
```

Generates `STEPS.md` and `CHECKLIST.md` for an existing CONTEXT.md-only workflow,
then removes it from `GAPS.md`.

---

## Priority Workflows

These 6 workflow folders receive complete `STEPS.md` + `CHECKLIST.md` at scaffold time:

| Workflow | Rationale |
|----------|-----------|
| `code/01-new-module` | Most frequent development operation |
| `code/02-tdd-cycle` | Rust TDD has specific tooling patterns (proptest, mockall) |
| `code/06-release-process` | Wrong steps lead to broken semver or failed publishes |
| `how-to/01-setup` | First-time contributor path — incomplete means blocked |
| `pm/05-code-review` | Active quality gate, used on every PR |
| `pm/06-security-audit` | Core value proposition of this plugin |

---

## Gap Handling

Any workflow folder containing only `CONTEXT.md` (missing `STEPS.md` or `CHECKLIST.md`)
is automatically logged in `GAPS.md` at the project root.

**Claude's behaviour with gap workflows:**
- May read `CONTEXT.md` for decision-making at any time
- Must NOT enter `STEPS.md` (which does not exist) — use `CONTEXT.md` as best-effort guidance
- Must log the gap before proceeding if asked to execute the workflow

To fill a gap:

```bash
/scaffold --fill-gaps <workflow-path>
```

---

## Relationship with `/init`

`/scaffold` and `/init` are complementary:

| Command | What it generates |
|---------|-------------------|
| `/init` | Canonical reference docs in `.claude/` (CODING-PRINCIPLES.md, TESTING.md, etc.) |
| `/scaffold` | Three-layer structural skeleton + distributes domain docs into each layer |

**`/scaffold` is self-contained** — it applies the same template substitutions as `/init`,
so it can run independently. Running both is idempotent with `--force`.

Recommended order:

```bash
/scaffold   # structure + domain docs in one pass
/init       # canonical copies in .claude/ (for plugin tools)
```

Or run `/scaffold` alone if you do not need the plugin tools (`.claude/plugins/`).

---

## Post-Scaffold Steps

After running `/scaffold`:

1. **Review `.claude/CLAUDE.md`** — customise routing rules and MCP server paths
2. **Review `GAPS.md`** — decide which gaps to prioritise
3. **Fill priority gaps** — run `/scaffold --fill-gaps <path>` for the most-used workflows
4. **Run `/init`** — if canonical `.claude/` reference docs are needed
5. **Run `/vuln-scan`** — check for dependency vulnerabilities
6. **Commit the scaffold**:
   ```bash
   git add .claude/ CONTEXT.md GAPS.md code/ how-to/ project-management/
   git commit -m "chore: add multi-layer project scaffold"
   ```

---

## Troubleshooting

### "Not a Rust project"

Ensure `Cargo.toml` exists at the target path:
```bash
ls Cargo.toml        # check current directory
ls ../my-crate/Cargo.toml   # or check specified target
```

### "Plugin templates directory not found"

Check that the plugin is installed and up to date:
```bash
claude plugin list
claude plugin install syntek-rust-security
```

### "Existing scaffold detected"

Use `--force` to overwrite, or `--dry-run` to preview what would change:
```bash
/scaffold --dry-run   # preview
/scaffold --force     # overwrite
```

### Template substitution variables not replaced

If you see `{{project_name}}` literally in generated files, the Cargo.toml could not
be parsed. Verify the file exists and has a `[package]` section.

---

## See Also

- `/init` — Generate canonical reference docs in `.claude/`
- `/vuln-scan` — Vulnerability scanning
- `/review-code` — Code review (uses `project-management/workflows/05-code-review/`)
- `/threat-model` — STRIDE threat analysis (uses `project-management/workflows/06-security-audit/`)
- `/version-bump` — Version management (uses `how-to/workflows/03-versioning/`)
