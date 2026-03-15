# Git Workflow Command

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

**Command:** `/rust-security:git-workflow`

Manages Git workflows for Rust projects including branch management, commit conventions, pull request creation, release tagging, and security-focused git history analysis. Ensures clean commit history and proper version control practices.

**Agent:** `rust-git` (Sonnet - Standard Analysis)

---

## When to Use

Use this command when:

- **Starting new features** - Create feature branches with proper naming
- **Preparing commits** - Format commits following conventions
- **Creating pull requests** - Generate PR with security checks
- **Releasing versions** - Tag releases and create changelogs
- **Code review preparation** - Organize commits for review
- **Cleaning git history** - Rebase and squash commits

---

## What It Does

1. **Creates and manages branches** following naming conventions
2. **Formats commit messages** using Conventional Commits
3. **Generates pull requests** with security checklists
4. **Creates release tags** with semantic versioning
5. **Analyzes commit history** for security issues
6. **Enforces git hooks** for pre-commit security checks
7. **Manages release branches** and hotfix workflows

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--action`         | string   | No       | `commit`      | Action: `commit`, `pr`, `release`, `branch`      |
| `--branch-type`    | string   | No       | `feature`     | Branch type: `feature`, `bugfix`, `hotfix`       |
| `--message`        | string   | No       | Interactive   | Commit message                                   |
| `--security-check` | boolean  | No       | `true`        | Run security checks before commit                |
| `--auto-tag`       | boolean  | No       | `true`        | Auto-create git tags for releases                |

---

## Output

### Console Output

```
🔀 Syntek Rust Security - Git Workflow Management

Action: Create Pull Request
Branch: feature/add-jwt-auth
Base: main

🔍 Pre-PR Security Checks:

✅ No hardcoded secrets detected
✅ All tests passing (247/247)
✅ Code coverage: 94.2%
✅ No clippy warnings
✅ Documentation updated

📝 Pull Request Created:

Title: Add JWT authentication support

Body:
## Summary
Implements JWT-based authentication with RS256 signing.

## Changes
- Add `jsonwebtoken` dependency
- Implement token generation and validation
- Add middleware for protected routes
- Update authentication documentation

## Security Considerations
- Uses RS256 for asymmetric signing
- Token expiration set to 1 hour
- Refresh tokens stored with secure httpOnly cookies
- Rate limiting on token endpoints

## Testing
- Unit tests for token generation/validation
- Integration tests for auth middleware
- Security tests for token tampering

## Checklist
- [x] Tests added and passing
- [x] Documentation updated
- [x] Security review completed
- [x] Breaking changes documented
- [x] CHANGELOG.md updated

🔗 Pull Request: https://github.com/org/repo/pull/123
```

---

## Examples

### Example 1: Create Feature Branch

```bash
/rust-security:git-workflow --action=branch --branch-type=feature
```

Creates feature branch with proper naming convention.

### Example 2: Security-Checked Commit

```bash
/rust-security:git-workflow --action=commit --security-check=true
```

Creates commit with pre-commit security validation.

### Example 3: Create Pull Request

```bash
/rust-security:git-workflow --action=pr
```

Generates pull request with security checklist.

### Example 4: Release Tagging

```bash
/rust-security:git-workflow --action=release --auto-tag=true
```

Creates release tag with version bump and changelog.

### Example 5: Hotfix Workflow

```bash
/rust-security:git-workflow --action=branch --branch-type=hotfix
```

Creates hotfix branch for security patches.

---

## Best Practices

### Branch Naming Convention

```bash
feature/add-encryption-support
bugfix/fix-timing-attack
hotfix/security-cve-2026-001
refactor/improve-crypto-api
docs/update-security-guide
```

### Conventional Commits

```bash
# Features
git commit -m "feat: add AES-256-GCM encryption support"

# Bug fixes
git commit -m "fix: prevent timing attack in HMAC validation"

# Security fixes
git commit -m "fix(security): sanitize user input in SQL queries

Fixes CVE-2026-XXXX by implementing parameterized queries"

# Breaking changes
git commit -m "feat!: redesign authentication API

BREAKING CHANGE: AuthToken renamed to SessionToken"

# Documentation
git commit -m "docs: add encryption usage examples"

# Performance
git commit -m "perf: optimize SHA-256 hashing with SIMD"

# Refactoring
git commit -m "refactor: extract crypto utilities to separate module"
```

### Pre-Commit Hooks

```bash
# .git/hooks/pre-commit
#!/bin/bash

# Run security scans
/rust-security:scan-secrets --scope=code
/rust-security:vuln-scan --quick

# Run tests
cargo test

# Check formatting
cargo fmt --check

# Run clippy
cargo clippy -- -D warnings

if [ $? -ne 0 ]; then
  echo "Pre-commit checks failed!"
  exit 1
fi
```

---

## Reference Documents

This command invokes the `rust-git` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**

## Related Commands

- **[/rust-security:version-bump](version-bump.md)** - Version management for releases
- **[/rust-security:scan-secrets](scan-secrets.md)** - Detect secrets before commit
- **[/rust-security:review-code](review-code.md)** - Code review for PRs

---

**Note:** Git workflows should be coordinated with team members. Always run security checks before creating pull requests.
