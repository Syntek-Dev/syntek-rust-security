# Supply Chain Audit Command

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

**Command:** `/rust-security:supply-chain-audit`

Performs comprehensive supply chain security analysis on Rust dependencies. Analyzes dependency trust, license compliance, maintainer reputation, typosquatting risks, and transitive dependency vulnerabilities to protect against supply chain attacks.

**Agent:** `supply-chain-audit` (Sonnet - Standard Analysis)

---

## When to Use

Use this command when:

- **Adding new dependencies** - Evaluate trust before adding to Cargo.toml
- **Before production deployment** - Final supply chain security check
- **After dependency updates** - Verify no malicious dependencies introduced
- **Compliance requirements** - Document dependency security posture
- **Security audits** - Generate supply chain risk reports
- **Investigating incidents** - Analyze dependency compromise scenarios

---

## What It Does

1. **Analyzes dependency tree** including all transitive dependencies
2. **Checks maintainer reputation** via crates.io metadata and GitHub activity
3. **Detects typosquatting** by comparing against popular crate names
4. **Verifies digital signatures** and crate checksums
5. **Analyzes license compliance** for legal and security risks
6. **Scans for malicious code patterns** in dependency sources
7. **Generates risk scorecard** with actionable recommendations

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--depth`          | string   | No       | `full`        | Analysis depth: `direct`, `full`, `critical`     |
| `--output`         | string   | No       | `docs/security/SUPPLY-CHAIN.md` | Output file path |
| `--format`         | string   | No       | `markdown`    | Output format: `markdown`, `json`, `sbom`        |
| `--risk-threshold` | string   | No       | `medium`      | Minimum risk level: `low`, `medium`, `high`      |
| `--check-licenses` | boolean  | No       | `true`        | Verify license compliance                        |
| `--download-deps`  | boolean  | No       | `false`       | Download and inspect source code                 |

---

## Output

### Console Output

```
🔗 Syntek Rust Security - Supply Chain Audit

📦 Project: web-framework v1.5.2
🌳 Dependency tree depth: 8 levels
📊 Total dependencies: 342 (87 direct, 255 transitive)

┌─────────────────────────────────────────────────────────────┐
│ Supply Chain Risk Assessment                                │
├─────────────────────────────────────────────────────────────┤
│ 🔴 CRITICAL: 2 high-risk dependencies                       │
│ 🟡 WARNING: 8 medium-risk dependencies                      │
│ 🟢 OK: 332 low-risk dependencies                            │
└─────────────────────────────────────────────────────────────┘

🚨 Critical Findings:

1. typo-reqwest v0.11.0 (TYPOSQUATTING)
   - Legitimate crate: reqwest
   - Risk: Dependency confusion attack
   - Downloads: 47 (reqwest: 50M+)
   - Action: REMOVE IMMEDIATELY

2. unmaintained-crypto v2.1.0 (UNMAINTAINED)
   - Last update: 3 years ago
   - Known vulnerabilities: CVE-2022-12345
   - Maintainer: Inactive
   - Action: Replace with actively maintained alternative

⚠️  Medium Risk Dependencies:

- deprecated-lib v1.0.0 - Marked as deprecated
- single-maintainer v0.5.0 - Bus factor = 1
- beta-quality v0.1.3 - Pre-1.0, frequent breaking changes

📊 License Analysis:
   - MIT: 245 dependencies
   - Apache-2.0: 82 dependencies
   - GPL-3.0: 1 dependency ⚠️  (copyleft license)
   - Unknown: 14 dependencies 🔴

📝 Detailed report: docs/security/SUPPLY-CHAIN.md
```

### Generated Documentation

Creates `docs/security/SUPPLY-CHAIN.md` with:

- **Executive Summary** - Supply chain risk overview
- **Dependency Tree Visualization** - Complete dependency graph
- **Risk Scorecard** - Per-dependency risk assessment
- **Typosquatting Analysis** - Suspicious package name detection
- **Maintainer Analysis** - Bus factor and reputation scoring
- **License Compliance** - License compatibility matrix
- **Remediation Plan** - Prioritized actions to reduce risk
- **SBOM (Software Bill of Materials)** - Complete dependency manifest

---

## Examples

### Example 1: Full Supply Chain Audit

```bash
/rust-security:supply-chain-audit
```

Analyzes entire dependency tree with comprehensive risk assessment.

### Example 2: Direct Dependencies Only

```bash
/rust-security:supply-chain-audit --depth=direct --risk-threshold=high
```

Audits only direct dependencies, showing high-risk findings only.

### Example 3: SBOM Generation

```bash
/rust-security:supply-chain-audit --format=sbom --output=sbom.json
```

Generates Software Bill of Materials in CycloneDX JSON format.

### Example 4: Deep Source Inspection

```bash
/rust-security:supply-chain-audit --download-deps=true --depth=critical
```

Downloads and inspects source code of critical dependencies.

### Example 5: License Audit Only

```bash
/rust-security:supply-chain-audit --check-licenses=true --format=json
```

Focuses on license compliance analysis with JSON output.

---

## Best Practices

### Before Running

1. **Update Cargo.lock** - Run `cargo update` for current dependency state
2. **Review Cargo.toml** - Understand direct dependency choices
3. **Check crates.io** - Verify popular dependencies are correctly spelled
4. **Document dependency rationale** - Comment why each dependency is needed

### During Audit

1. **Verify typosquatting alerts** - Check against official crate names
2. **Review maintainer activity** - Check GitHub profiles and commit history
3. **Analyze dependency freshness** - Prefer actively maintained crates
4. **Check bus factor** - Prefer dependencies with multiple active maintainers
5. **Validate licenses** - Ensure compatibility with project license

### After Audit

1. **Remove risky dependencies** - Replace or vendor critical dependencies
2. **Pin dependency versions** - Use exact versions for critical dependencies
3. **Set up monitoring** - Subscribe to RustSec advisories
4. **Document exceptions** - Justify acceptance of medium-risk dependencies
5. **Schedule regular audits** - Re-run quarterly or after major updates

### Supply Chain Security Best Practices

**Dependency Selection Criteria**
- Downloads > 100k (indicates community trust)
- Recent commit activity (< 6 months)
- Multiple maintainers (bus factor > 2)
- Comprehensive documentation
- Active issue tracker
- Verified maintainer accounts

**Cargo.toml Security**
```toml
[dependencies]
# Good: Use specific versions for critical dependencies
ring = "=0.17.7"

# Good: Use caret requirements for stable libraries
serde = "^1.0"

# Bad: Wildcard versions allow supply chain attacks
# suspicious = "*"

# Good: Use features to minimize attack surface
tokio = { version = "1.35", features = ["macros", "rt-multi-thread"] }
```

**Vendoring Critical Dependencies**
```bash
# Vendor dependencies for offline builds and security
cargo vendor
```

**Cargo.lock in Version Control**
```bash
# Always commit Cargo.lock for reproducible builds
git add Cargo.lock
git commit -m "Lock dependency versions for security"
```

### Integration with Development Workflow

```bash
# 1. Before adding dependency
/rust-security:supply-chain-audit --depth=direct

# 2. Add dependency with specific version
cargo add reqwest --version "=0.11.23"

# 3. Re-audit with new dependency
/rust-security:supply-chain-audit

# 4. If issues found, investigate alternatives
# Check crates.io for alternatives
# Review GitHub repositories
# Verify maintainer reputation

# 5. Commit with audit documentation
git add Cargo.toml Cargo.lock docs/security/SUPPLY-CHAIN.md
git commit -m "Add reqwest dependency (supply chain audit: PASS)"

# 6. Set up continuous monitoring
# Add to CI/CD pipeline
# Subscribe to RustSec advisories
```

### Detecting Malicious Dependencies

**Red Flags**
- Typosquatting (similar names to popular crates)
- Extremely low download counts
- Recent creation date with suspicious functionality
- Obfuscated code or heavy macro usage
- Network requests in build scripts
- File system access in unexpected places
- Unmaintained with known vulnerabilities

**Investigation Steps**
1. Check crates.io metadata and download statistics
2. Review GitHub repository and commit history
3. Inspect source code for suspicious patterns
4. Run `cargo geiger` to detect unsafe code usage
5. Check RustSec advisories for known issues
6. Search security forums for reports

---

## Reference Documents

This command invokes the `supply-chain` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**

## Related Commands

- **[/rust-security:vuln-scan](vuln-scan.md)** - Scan dependencies for known vulnerabilities
- **[/rust-security:scan-secrets](scan-secrets.md)** - Detect secrets in dependencies
- **[/rust-security:manage-deps](manage-deps.md)** - Dependency management and optimization
- **[/rust-security:compliance-report](compliance-report.md)** - Generate compliance reports
- **[/rust-security:review-code](review-code.md)** - Code review including dependency analysis

---

**Note:** Supply chain audits require internet access to query crates.io and GitHub APIs. Use `--download-deps=true` for offline source code inspection.
