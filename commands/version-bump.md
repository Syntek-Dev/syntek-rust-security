# Version Bump Command

## Table of Contents

- [Overview](#overview)
- [When to Use](#when-to-use)
- [What It Does](#what-it-does)
- [Parameters](#parameters)
- [Output](#output)
- [Examples](#examples)
- [Best Practices](#best-practices)
- [Related Commands](#related-commands)

---

## Overview

**Command:** `/rust-security:version-bump`

Manages semantic versioning for Rust projects following SemVer 2.0.0 specification. Automatically updates version numbers in Cargo.toml, generates changelog entries, creates git tags, and ensures version consistency across workspaces and dependencies.

**Agent:** `rust-version` (Sonnet - Standard Analysis)

---

## When to Use

Use this command when:

- **Releasing new version** - Increment version following SemVer rules
- **After security fixes** - Document security patches with version bump
- **Breaking API changes** - Major version increment for incompatible changes
- **New features** - Minor version increment for backward-compatible additions
- **Bug fixes** - Patch version increment for backward-compatible fixes
- **Pre-release versions** - Manage alpha, beta, and RC versions

---

## What It Does

1. **Analyzes git history** to determine appropriate version increment
2. **Detects breaking changes** via API analysis and commit messages
3. **Updates Cargo.toml** version across all workspace members
4. **Generates CHANGELOG.md** entries from commit messages
5. **Creates git tags** following conventional tagging schemes
6. **Updates dependency versions** in workspace to match new version
7. **Validates SemVer compliance** before finalizing version

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--level`          | string   | No       | Auto-detect   | Version bump: `major`, `minor`, `patch`, `pre`   |
| `--pre-release`    | string   | No       | None          | Pre-release identifier: `alpha`, `beta`, `rc`    |
| `--changelog`      | boolean  | No       | `true`        | Generate changelog entry                         |
| `--tag`            | boolean  | No       | `true`        | Create git tag for release                       |
| `--workspace`      | boolean  | No       | `true`        | Update all workspace members                     |
| `--dry-run`        | boolean  | No       | `false`       | Preview changes without applying                 |

---

## Output

### Console Output

```
🔢 Syntek Rust Security - Version Management

📦 Current version: 1.4.2
🔍 Analyzing changes since last release...

┌─────────────────────────────────────────────────────────────┐
│ Change Analysis                                             │
├─────────────────────────────────────────────────────────────┤
│ Breaking changes: 0                                         │
│ New features: 3                                             │
│ Bug fixes: 7                                                │
│ Security fixes: 2                                           │
│ Documentation: 5                                            │
└─────────────────────────────────────────────────────────────┘

📈 Recommended version: 1.5.0 (MINOR)

Reasoning:
  - No breaking changes detected
  - New features added (backward-compatible)
  - Bug fixes included
  - Security patches applied

✅ Updates applied:

  - Cargo.toml: 1.4.2 → 1.5.0
  - workspace/auth/Cargo.toml: 1.4.2 → 1.5.0
  - workspace/crypto/Cargo.toml: 1.4.2 → 1.5.0
  - CHANGELOG.md: Entry added for v1.5.0
  - Git tag created: v1.5.0

📝 Changelog entry:

## [1.5.0] - 2026-01-10

### Added
- New HMAC verification API for request signing
- Support for Ed25519 signature validation
- Rate limiting middleware for API endpoints

### Fixed
- Memory leak in connection pool (CVE-2026-XXXX)
- Race condition in session management
- Integer overflow in timestamp validation

### Security
- Updated vulnerable dependencies (RUSTSEC-2026-001)
- Hardened cryptographic key derivation

🚀 Ready to publish! Run: cargo publish
```

### Generated Files

Updates version-related files:

- **Cargo.toml** - Updated version field
- **CHANGELOG.md** - New version entry with changes
- **Git tag** - Version tag (v1.5.0)
- **VERSION** - Plain text version file (optional)
- **VERSION-HISTORY.md** - Long-term version history

---

## Examples

### Example 1: Auto-Detect Version Bump

```bash
/rust-security:version-bump
```

Analyzes changes and automatically determines appropriate version increment.

### Example 2: Explicit Patch Release

```bash
/rust-security:version-bump --level=patch
```

Forces patch version increment (e.g., 1.4.2 → 1.4.3).

### Example 3: Major Breaking Change

```bash
/rust-security:version-bump --level=major
```

Increments major version for breaking API changes (e.g., 1.4.2 → 2.0.0).

### Example 4: Pre-Release Version

```bash
/rust-security:version-bump --level=minor --pre-release=beta
```

Creates pre-release version (e.g., 1.4.2 → 1.5.0-beta.1).

### Example 5: Dry Run Preview

```bash
/rust-security:version-bump --dry-run=true
```

Previews version changes without applying them.

---

## Best Practices

### Semantic Versioning Rules

**Given version: MAJOR.MINOR.PATCH**

**MAJOR (X.0.0) - Breaking Changes**
- Incompatible API changes
- Removal of public APIs
- Changed function signatures
- Altered behavior of existing functionality

**MINOR (0.X.0) - New Features**
- Backward-compatible new functionality
- New public APIs
- Deprecation of existing features (with compatibility)
- Substantial performance improvements

**PATCH (0.0.X) - Bug Fixes**
- Backward-compatible bug fixes
- Security patches
- Documentation updates
- Internal refactoring (no API changes)

### Pre-Release Versions

```
1.5.0-alpha.1    # Early development, API unstable
1.5.0-beta.1     # Feature complete, testing phase
1.5.0-rc.1       # Release candidate, final testing
1.5.0            # Stable release
```

### Detecting Breaking Changes

The agent analyzes:
- Public API changes via `cargo public-api`
- Commit messages with `BREAKING CHANGE:` footer
- Removed or renamed public functions
- Changed type signatures
- Altered trait definitions

### Changelog Format

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.5.0] - 2026-01-10

### Added
- New features

### Changed
- Changes to existing functionality

### Deprecated
- Soon-to-be removed features

### Removed
- Removed features

### Fixed
- Bug fixes

### Security
- Security fixes

## [1.4.2] - 2025-12-15
...
```

### Integration with Release Workflow

```bash
# Complete release workflow

# 1. Ensure clean working tree
git status

# 2. Run all security checks
/rust-security:vuln-scan
/rust-security:memory-audit
/rust-security:review-code

# 3. Run tests
cargo test --all-features

# 4. Bump version and generate changelog
/rust-security:version-bump

# 5. Commit version changes
git add Cargo.toml CHANGELOG.md
git commit -m "chore: release version 1.5.0"

# 6. Push with tags
git push origin main --tags

# 7. Publish to crates.io
cargo publish

# 8. Create GitHub release
gh release create v1.5.0 --notes-file CHANGELOG.md
```

### Workspace Version Management

For Cargo workspaces:

```toml
# Root Cargo.toml
[workspace]
members = ["crates/*"]

[workspace.package]
version = "1.5.0"
authors = ["Your Name"]
edition = "2021"

# Member Cargo.toml inherits workspace version
[package]
name = "workspace-member"
version.workspace = true
```

### Security Release Best Practices

```bash
# For security patches, always:

# 1. Create security advisory first
# 2. Prepare patch in private
# 3. Bump patch version
/rust-security:version-bump --level=patch

# 4. Document security fix in changelog
# CHANGELOG.md should include:
# - CVE identifier (if assigned)
# - Severity level
# - Affected versions
# - Mitigation steps

# 5. Release with security tag
git tag -s v1.4.3 -m "Security release: Fix CVE-2026-XXXX"

# 6. Publish immediately
cargo publish

# 7. Publish security advisory
gh security-advisory publish
```

### Commit Message Convention

Use Conventional Commits for automatic version detection:

```bash
# Breaking change (major version bump)
git commit -m "feat!: redesign authentication API

BREAKING CHANGE: AuthToken struct renamed to SessionToken"

# New feature (minor version bump)
git commit -m "feat: add support for Ed25519 signatures"

# Bug fix (patch version bump)
git commit -m "fix: correct integer overflow in timestamp validation"

# Security fix (patch version bump)
git commit -m "fix(security): prevent timing attacks in comparison

SECURITY: Fixes CVE-2026-XXXX"
```

---

## Reference Documents

This command invokes the `rust-version` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**

## Related Commands

- **[/rust-security:generate-docs](generate-docs.md)** - Generate documentation for new version
- **[/rust-security:git-workflow](git-workflow.md)** - Git workflow management and releases
- **[/rust-security:compliance-report](compliance-report.md)** - Compliance reporting for releases
- **[/rust-security:review-code](review-code.md)** - Pre-release code review

---

**Note:** Version bumps should be coordinated with team members in shared repositories. Always create a new branch for version changes and use pull requests for review.
