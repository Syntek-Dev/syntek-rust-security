# Vulnerability Scan Command

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

**Command:** `/rust-security:vuln-scan`

Performs comprehensive vulnerability scanning of Rust dependencies using cargo-audit and cargo-deny, checking against the RustSec Advisory Database for known security vulnerabilities, unmaintained crates, and security best practices.

**Agent:** `vuln-scan` (Sonnet - Standard Analysis)

---

## When to Use

Use this command when:

- **Before every commit** - Catch vulnerabilities early in development
- **In CI/CD pipelines** - Automated security checks on every build
- **Reviewing dependencies** - Before adding or updating crate versions
- **Pre-release security audits** - Ensure no known vulnerabilities in production
- **After dependency updates** - Verify security after `cargo update`
- **Regular security maintenance** - Weekly or monthly scheduled scans

---

## What It Does

1. **Updates RustSec database** - Fetches latest vulnerability advisories
2. **Runs cargo-audit** - Scans dependencies for known CVEs
3. **Runs cargo-deny** - Checks for unmaintained crates, banned dependencies, and license issues
4. **Analyzes dependency tree** - Identifies vulnerable transitive dependencies
5. **Calculates CVSS scores** - Rates vulnerability severity
6. **Recommends fixes** - Suggests version updates or crate replacements
7. **Generates report** - Creates detailed vulnerability report in `docs/security/VULN-REPORT.md`

---

## Parameters

| Parameter         | Type     | Required | Default | Description                                       |
| ----------------- | -------- | -------- | ------- | ------------------------------------------------- |
| `--update-db`     | boolean  | No       | `true`  | Update RustSec database before scanning           |
| `--severity`      | string   | No       | `low`   | Minimum severity: `low`, `medium`, `high`, `critical` |
| `--ignore`        | string[] | No       | None    | Advisory IDs to ignore (e.g., RUSTSEC-2021-0001)  |
| `--output`        | string   | No       | `docs/security/VULN-REPORT.md` | Output file path |
| `--format`        | string   | No       | `markdown` | Output format: `markdown`, `json`, `sarif`     |
| `--include-yanked`| boolean  | No       | `true`  | Report yanked crate versions                      |
| `--check-licenses`| boolean  | No       | `true`  | Check for license compatibility issues            |

---

## Output

### Console Output

```
🔍 Syntek Rust Security - Vulnerability Scan

📦 Updating RustSec Advisory Database...
   ✓ Database updated (2,847 advisories)

🔎 Scanning dependencies...
   ✓ Analyzed 142 crates (including transitive dependencies)

⚠️  Vulnerabilities Detected: 3

┌─────────────────────────────────────────────────────────────┐
│ CRITICAL                                                    │
├─────────────────────────────────────────────────────────────┤
│ ID:       RUSTSEC-2023-0071                                 │
│ Package:  webpki 0.21.4                                     │
│ Title:    webpki: CPU denial of service in certificate path │
│           building                                          │
│ CVSS:     7.5 HIGH                                          │
│ Fix:      Upgrade to webpki >= 0.22.4                       │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ HIGH                                                        │
├─────────────────────────────────────────────────────────────┤
│ ID:       RUSTSEC-2023-0034                                 │
│ Package:  tokio 1.28.0                                      │
│ Title:    tokio: Data race in task abort notification      │
│ CVSS:     5.9 MEDIUM                                        │
│ Fix:      Upgrade to tokio >= 1.28.1                        │
└─────────────────────────────────────────────────────────────┘

🔧 Remediation Summary:
   Run: cargo update webpki tokio

📊 Additional Checks:
   ✓ No yanked crates detected
   ✓ No unmaintained dependencies
   ⚠  1 license compatibility warning

📄 Detailed report: docs/security/VULN-REPORT.md
```

### Generated Report

Creates `docs/security/VULN-REPORT.md` with:

- **Executive Summary** - Count of vulnerabilities by severity
- **Vulnerability Details** - Full advisory information for each CVE
- **Dependency Tree Analysis** - Where vulnerable crates are introduced
- **Remediation Steps** - Specific commands to fix vulnerabilities
- **Unmaintained Crates** - Dependencies with no recent updates
- **License Audit** - License compatibility issues
- **Supply Chain Risks** - Crates with known security concerns

---

## Examples

### Example 1: Standard Scan

```bash
/rust-security:vuln-scan
```

Runs full vulnerability scan with default settings, updating RustSec database first.

### Example 2: Critical Vulnerabilities Only

```bash
/rust-security:vuln-scan --severity=critical
```

Reports only critical severity vulnerabilities, useful for CI/CD blocking.

### Example 3: Scan with Ignored Advisories

```bash
/rust-security:vuln-scan --ignore=RUSTSEC-2023-0001,RUSTSEC-2023-0012
```

Ignores specific advisories (e.g., false positives or accepted risks with mitigations).

### Example 4: JSON Output for CI/CD

```bash
/rust-security:vuln-scan --format=json --output=vuln-scan.json
```

Generates machine-readable JSON output for automated CI/CD processing.

### Example 5: SARIF Format for GitHub

```bash
/rust-security:vuln-scan --format=sarif --output=results.sarif
```

Creates SARIF format report for GitHub Security tab integration.

### Example 6: Quick Scan (No DB Update)

```bash
/rust-security:vuln-scan --update-db=false
```

Skips database update for faster scans during development (not recommended for CI/CD).

---

## Best Practices

### CI/CD Integration

```yaml
# GitHub Actions example
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install Rust
        uses: actions-rs/toolchain@v1
      - name: Run vulnerability scan
        run: /rust-security:vuln-scan --severity=high --format=sarif --output=results.sarif
      - name: Upload results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### Development Workflow

```bash
# 1. Before adding new dependency
cargo add tokio
/rust-security:vuln-scan

# 2. After cargo update
cargo update
/rust-security:vuln-scan

# 3. Pre-commit hook
/rust-security:vuln-scan --severity=high
```

### Managing False Positives

Create `deny.toml` in project root:

```toml
[advisories]
ignore = [
    "RUSTSEC-2023-0001",  # False positive - we don't use affected feature
]

[licenses]
allow = ["MIT", "Apache-2.0", "BSD-3-Clause"]

[bans]
deny = [
    { name = "openssl-sys", deny-multiple-versions = true },
]
```

### Regular Maintenance

1. **Weekly scans** - Schedule automated scans in CI/CD
2. **Immediate fixes** - Address critical/high vulnerabilities within 24 hours
3. **Monthly reviews** - Review unmaintained dependencies
4. **Quarterly audits** - Full security audit including manual code review

### Interpreting CVSS Scores

| CVSS Score | Severity | Response Time | Action                                        |
| ---------- | -------- | ------------- | --------------------------------------------- |
| 9.0 - 10.0 | Critical | Immediate     | Emergency patch, consider rollback            |
| 7.0 - 8.9  | High     | 24 hours      | Priority fix, schedule urgent deployment      |
| 4.0 - 6.9  | Medium   | 1 week        | Plan fix in next sprint                       |
| 0.1 - 3.9  | Low      | 1 month       | Address in regular maintenance                |

---

## Reference Documents

This command invokes the `vuln-scanner` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**

## Related Commands

- **[/rust-security:supply-chain-audit](supply-chain-audit.md)** - Comprehensive supply chain security analysis
- **[/rust-security:threat-model](threat-model.md)** - STRIDE threat modelling
- **[/rust-security:compliance-report](compliance-report.md)** - Generate compliance reports
- **[/rust-security:manage-deps](manage-deps.md)** - Dependency management and optimization

---

**Note:** This command requires `cargo-audit` and `cargo-deny`. Install with:
```bash
cargo install cargo-audit cargo-deny
```
