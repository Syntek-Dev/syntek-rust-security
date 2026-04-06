# Scan Secrets Command

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

**Command:** `/rust-security:scan-secrets`

Scans Rust projects for hardcoded secrets, API keys, passwords, tokens, and sensitive credentials. Detects secrets in source code, configuration files, commit history, and dependency trees to prevent credential leaks and security breaches.

**Agent:** `scan-secrets` (Sonnet - Standard Analysis)

---

## When to Use

Use this command when:

- **Before committing code** - Prevent accidental secret commits
- **During code review** - Identify hardcoded credentials
- **Pre-production deployment** - Final security check before release
- **After dependency updates** - Verify no secrets introduced via dependencies
- **Auditing legacy code** - Discover historical credential leaks
- **Compliance requirements** - Document secret management practices

---

## What It Does

1. **Scans source code** for hardcoded API keys, passwords, and tokens
2. **Analyzes configuration files** (.env, .toml, .yaml, .json) for credentials
3. **Inspects git history** to detect previously committed secrets
4. **Checks environment variables** referenced in code
5. **Reviews dependency sources** for embedded secrets
6. **Detects cryptographic keys** (private keys, certificates, JWT secrets)
7. **Generates remediation report** with secret rotation recommendations

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--scope`          | string   | No       | `all`         | Scan scope: `all`, `code`, `config`, `git`, `deps` |
| `--output`         | string   | No       | `docs/security/SECRETS-AUDIT.md` | Output file path |
| `--format`         | string   | No       | `markdown`    | Output format: `markdown`, `json`, `sarif`       |
| `--entropy-threshold` | number | No       | 3.5          | Minimum entropy for high-entropy string detection |
| `--git-depth`      | number   | No       | 100           | Git history depth to scan                        |
| `--exclude`        | string[] | No       | `[tests/, examples/]` | Directories to exclude       |

---

## Output

### Console Output

```
🔐 Syntek Rust Security - Secret Detection Scan

📦 Project: payment-api v2.1.0
🔍 Scan scope: All sources
📊 Files analyzed: 247

┌─────────────────────────────────────────────────────────────┐
│ Secrets Detected                                            │
├─────────────────────────────────────────────────────────────┤
│ ⛔ CRITICAL: 3 secrets found                                │
│ ⚠️  HIGH: 5 potential secrets                               │
│ ℹ️  MEDIUM: 12 suspicious strings                           │
└─────────────────────────────────────────────────────────────┘

🚨 Critical Findings:

1. AWS Access Key (src/config.rs:42)
   - Pattern: AKIA[0-9A-Z]{16}
   - Confidence: 100%
   - Action: ROTATE IMMEDIATELY

2. Stripe API Key (src/payment/mod.rs:18)
   - Pattern: sk_live_[0-9A-Za-z]{24}
   - Confidence: 100%
   - Action: ROTATE IMMEDIATELY

3. Private RSA Key (config/keys/private.pem)
   - Pattern: -----BEGIN PRIVATE KEY-----
   - Confidence: 100%
   - Action: REMOVE and use key management service

⚠️  High Entropy Strings:

- src/auth.rs:89 - High entropy string (entropy: 4.2)
- config/database.toml:5 - Possible password

📝 Detailed report: docs/security/SECRETS-AUDIT.md
🔄 Recommended actions: Rotate all detected secrets and implement secret management
```

### Generated Documentation

Creates `docs/security/SECRETS-AUDIT.md` with:

- **Executive Summary** - Secret detection overview
- **Critical Findings** - High-confidence secret matches
- **Potential Secrets** - Medium-confidence detections
- **Suspicious Patterns** - High-entropy strings and patterns
- **Git History Analysis** - Previously committed secrets
- **Remediation Steps** - Secret rotation and management recommendations
- **Secret Management Best Practices** - Implementation guidance

---

## Examples

### Example 1: Full Project Scan

```bash
/rust-security:scan-secrets
```

Scans entire project including source code, configuration, git history, and dependencies.

### Example 2: Code-Only Scan

```bash
/rust-security:scan-secrets --scope=code --exclude=tests/,examples/
```

Scans only source code, excluding test and example directories.

### Example 3: Git History Audit

```bash
/rust-security:scan-secrets --scope=git --git-depth=1000
```

Scans last 1000 git commits for historical secret leaks.

### Example 4: High-Sensitivity Scan

```bash
/rust-security:scan-secrets --entropy-threshold=3.0 --format=sarif
```

Lower entropy threshold for more sensitive detection, outputs SARIF format for CI integration.

### Example 5: Configuration File Scan

```bash
/rust-security:scan-secrets --scope=config --output=config-secrets.json --format=json
```

Scans only configuration files, outputs JSON for automated processing.

---

## Best Practices

### Before Running

1. **Ensure clean working directory** - Commit or stash changes
2. **Update .gitignore** - Verify sensitive files are excluded
3. **Document expected patterns** - Mark false positives with comments
4. **Review environment variable usage** - Ensure proper secret injection

### During Scan

1. **Review all findings** - Verify true positives vs. false positives
2. **Check git history** - Look for deleted secrets still in history
3. **Analyze entropy scores** - Investigate high-entropy strings
4. **Verify dependency secrets** - Check if dependencies leak credentials

### After Scan

1. **Rotate compromised secrets** - Immediately rotate any detected secrets
2. **Remove secrets from git history** - Use `git filter-branch` or BFG Repo-Cleaner
3. **Implement secret management** - Use environment variables or secret vaults
4. **Add pre-commit hooks** - Prevent future secret commits
5. **Update documentation** - Document secret management practices

### Secret Management Solutions

**Environment Variables**
```rust
// Good: Load from environment
let api_key = std::env::var("API_KEY")
    .expect("API_KEY must be set");
```

**Configuration Files (gitignored)**
```toml
# .env (in .gitignore)
API_KEY=sk_live_xxxxxxxxxxxx
DATABASE_URL=postgresql://user:pass@localhost/db
```

**Secret Management Services**
- HashiCorp Vault
- AWS Secrets Manager
- Azure Key Vault
- Google Secret Manager

**Rust Secret Management Crates**
- `secrecy` - Secret types that prevent accidental leaks
- `keyring` - OS keychain integration
- `vaultrs` - HashiCorp Vault client
- `aws-sdk-secretsmanager` - AWS Secrets Manager

### Integration with Development Workflow

```bash
# 1. Scan for secrets before commit
/rust-security:scan-secrets --scope=code

# 2. If secrets found, rotate and remove
# - Rotate secrets via provider dashboard
# - Remove from code and use environment variables

# 3. Clean git history (if needed)
# WARNING: Rewrites git history, coordinate with team
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch config/secrets.toml" \
  --prune-empty --tag-name-filter cat -- --all

# 4. Add pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
/rust-security:scan-secrets --scope=code --format=json
if [ $? -ne 0 ]; then
  echo "Secret detected! Commit aborted."
  exit 1
fi
EOF
chmod +x .git/hooks/pre-commit

# 5. Verify clean state
/rust-security:scan-secrets
```

---

## Reference Documents

This command invokes the `secrets-auditor` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[ENCRYPTION-GUIDE.md](.claude/ENCRYPTION-GUIDE.md)**

## Related Commands

- **[/rust-security:supply-chain-audit](supply-chain-audit.md)** - Audit dependencies for embedded secrets
- **[/rust-security:compliance-report](compliance-report.md)** - Generate compliance reports
- **[/rust-security:review-code](review-code.md)** - Code review including secret detection
- **[/rust-security:git-workflow](git-workflow.md)** - Git workflow management and history cleanup

---

**Note:** This command uses pattern matching and entropy analysis. Review all findings carefully to distinguish true positives from false positives (e.g., example API keys in tests).
