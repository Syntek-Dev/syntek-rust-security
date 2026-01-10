# Compliance Report Command

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

**Command:** `/rust-security:compliance-report`

Generates comprehensive security compliance reports mapped to industry standards including OWASP Top 10, CWE (Common Weakness Enumeration), CVSS scoring, NIST frameworks, and regulatory requirements. Provides audit-ready documentation for security assessments.

**Agent:** `compliance-auditor` (Sonnet - Standard Analysis)

---

## When to Use

Use this command when:

- **Preparing for security audits** - Generate compliance documentation
- **Regulatory requirements** - Demonstrate adherence to security standards
- **Pre-production deployment** - Final compliance verification
- **Quarterly security reviews** - Scheduled compliance reporting
- **After security fixes** - Document remediation and current posture
- **Bug bounty submissions** - Provide CVSS scoring for vulnerability reports

---

## What It Does

1. **Scans project for security issues** across all vulnerability categories
2. **Maps findings to OWASP Top 10** categories
3. **Assigns CWE identifiers** to discovered weaknesses
4. **Calculates CVSS scores** for each vulnerability
5. **Generates compliance matrices** for regulatory frameworks
6. **Creates audit trail documentation** with timestamps and evidence
7. **Exports reports** in multiple formats (PDF, JSON, HTML, SARIF)

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--framework`      | string   | No       | `all`         | Framework: `owasp`, `cwe`, `nist`, `pci-dss`, `all` |
| `--output`         | string   | No       | `docs/compliance/` | Output directory                            |
| `--format`         | string   | No       | `markdown`    | Output format: `markdown`, `json`, `pdf`, `html`, `sarif` |
| `--severity`       | string   | No       | `all`         | Minimum severity: `low`, `medium`, `high`, `critical` |
| `--include-fixes`  | boolean  | No       | `true`        | Include remediation recommendations              |
| `--timestamps`     | boolean  | No       | `true`        | Include scan timestamps for audit trail         |

---

## Output

### Console Output

```
📊 Syntek Rust Security - Compliance Report Generation

📦 Project: payment-gateway v3.2.1
🔍 Framework: All standards
📅 Scan date: 2026-01-10 15:30:42 UTC

┌─────────────────────────────────────────────────────────────┐
│ OWASP Top 10 (2021) Compliance                              │
├─────────────────────────────────────────────────────────────┤
│ A01 - Broken Access Control:        ⚠️  2 findings         │
│ A02 - Cryptographic Failures:       ✅ 0 findings           │
│ A03 - Injection:                    ✅ 0 findings           │
│ A04 - Insecure Design:              ⚠️  1 finding          │
│ A05 - Security Misconfiguration:    ❌ 3 findings           │
│ A06 - Vulnerable Components:        ❌ 5 findings           │
│ A07 - Auth/Auth Failures:           ⚠️  1 finding          │
│ A08 - Software/Data Integrity:      ✅ 0 findings           │
│ A09 - Logging/Monitoring Failures:  ⚠️  2 findings         │
│ A10 - SSRF:                         ✅ 0 findings           │
└─────────────────────────────────────────────────────────────┘

📈 CVSS Score Summary:
   - Critical (9.0-10.0): 0 vulnerabilities
   - High (7.0-8.9): 3 vulnerabilities
   - Medium (4.0-6.9): 8 vulnerabilities
   - Low (0.1-3.9): 3 vulnerabilities

🏷️  CWE Categories:
   - CWE-200 (Information Exposure): 2 instances
   - CWE-327 (Broken Crypto): 1 instance
   - CWE-502 (Deserialization): 1 instance
   - CWE-611 (XXE): 0 instances

📝 Reports generated:
   - docs/compliance/OWASP-Top-10-Report.md
   - docs/compliance/CWE-Mapping.json
   - docs/compliance/CVSS-Scorecard.pdf
   - docs/compliance/NIST-Compliance.html
```

### Generated Documentation

Creates comprehensive compliance package:

- **OWASP-Top-10-Report.md** - OWASP Top 10 mapping with findings
- **CWE-Mapping.json** - Machine-readable CWE mappings
- **CVSS-Scorecard.pdf** - Professional CVSS scoring report
- **NIST-Compliance.html** - NIST framework compliance matrix
- **PCI-DSS-Checklist.md** - PCI-DSS requirements checklist
- **Audit-Trail.json** - Timestamped security scan history
- **Executive-Summary.pdf** - High-level compliance overview

---

## Examples

### Example 1: Full Compliance Report

```bash
/rust-security:compliance-report
```

Generates reports for all supported frameworks in markdown format.

### Example 2: OWASP Top 10 Only

```bash
/rust-security:compliance-report --framework=owasp --format=pdf
```

Creates PDF report focused on OWASP Top 10 compliance.

### Example 3: High-Severity Issues

```bash
/rust-security:compliance-report --severity=high --format=sarif
```

Generates SARIF report for CI/CD integration with high-severity findings only.

### Example 4: PCI-DSS Compliance

```bash
/rust-security:compliance-report --framework=pci-dss --output=audit/2026-q1/
```

Creates PCI-DSS compliance report for payment card industry requirements.

### Example 5: Audit Trail Generation

```bash
/rust-security:compliance-report --timestamps=true --format=json
```

Generates JSON report with full audit trail timestamps.

---

## Best Practices

### Before Running

1. **Run all security scans** - Complete vuln-scan, memory-audit, crypto-review first
2. **Update dependencies** - Ensure latest security patches applied
3. **Document fixes** - Record remediation efforts in git history
4. **Review threat model** - Validate architectural security controls

### Compliance Frameworks

**OWASP Top 10 (2021)**
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable and Outdated Components
- A07: Identification and Authentication Failures
- A08: Software and Data Integrity Failures
- A09: Security Logging and Monitoring Failures
- A10: Server-Side Request Forgery (SSRF)

**CWE Top 25 (2024)**
- CWE-787: Out-of-bounds Write
- CWE-79: Cross-site Scripting
- CWE-89: SQL Injection
- CWE-416: Use After Free
- CWE-78: OS Command Injection
- CWE-20: Improper Input Validation
- CWE-125: Out-of-bounds Read
- CWE-22: Path Traversal
- CWE-352: CSRF
- CWE-434: Unrestricted Upload

**NIST Cybersecurity Framework**
- Identify (ID)
- Protect (PR)
- Detect (DE)
- Respond (RS)
- Recover (RC)

**PCI-DSS Requirements**
- Requirement 1-6: Build and Maintain Secure Network
- Requirement 7-12: Maintain Vulnerability Management Program

### CVSS Scoring Guidelines

**CVSS v3.1 Base Metrics**
```
Attack Vector (AV): Network/Adjacent/Local/Physical
Attack Complexity (AC): Low/High
Privileges Required (PR): None/Low/High
User Interaction (UI): None/Required
Scope (S): Unchanged/Changed
Confidentiality (C): None/Low/High
Integrity (I): None/Low/High
Availability (A): None/Low/High
```

**Severity Ratings**
- 0.0: None
- 0.1-3.9: Low
- 4.0-6.9: Medium
- 7.0-8.9: High
- 9.0-10.0: Critical

### Integration with Security Workflow

```bash
# Comprehensive security compliance workflow

# 1. Run all security scans
/rust-security:vuln-scan
/rust-security:memory-audit
/rust-security:crypto-review
/rust-security:supply-chain-audit
/rust-security:scan-secrets

# 2. Generate compliance reports
/rust-security:compliance-report --framework=all --format=pdf

# 3. Review findings
cat docs/compliance/Executive-Summary.pdf

# 4. Prioritize remediation by CVSS score
jq '.vulnerabilities | sort_by(.cvss_score) | reverse' \
  docs/compliance/CWE-Mapping.json

# 5. Fix critical and high-severity issues
# [Implement security fixes]

# 6. Re-run compliance check
/rust-security:compliance-report --severity=high

# 7. Generate audit package for stakeholders
tar czf security-audit-2026-q1.tar.gz docs/compliance/

# 8. Commit compliance documentation
git add docs/compliance/
git commit -m "Security compliance report Q1 2026: PASS"
```

### Regulatory Compliance

**GDPR (Data Protection)**
```bash
/rust-security:gdpr-check
/rust-security:compliance-report --framework=all
```

**SOC 2 (Security Controls)**
```bash
/rust-security:compliance-report --framework=nist --include-fixes=true
```

**HIPAA (Healthcare)**
```bash
/rust-security:compliance-report --framework=all --output=hipaa-audit/
```

**ISO 27001 (Information Security)**
```bash
/rust-security:compliance-report --framework=all --format=pdf
```

### Report Interpretation

**Green (✅) - Compliant**
- No findings for this category
- Continue monitoring
- Maintain current controls

**Yellow (⚠️) - Needs Attention**
- Low to medium severity findings
- Schedule remediation
- Document accepted risks

**Red (❌) - Non-Compliant**
- High to critical severity findings
- Immediate remediation required
- Block production deployment

---

## Related Commands

- **[/rust-security:vuln-scan](vuln-scan.md)** - Vulnerability scanning for compliance
- **[/rust-security:threat-model](threat-model.md)** - Threat modeling for compliance
- **[/rust-security:crypto-review](crypto-review.md)** - Cryptographic compliance review
- **[/rust-security:memory-audit](memory-audit.md)** - Memory safety compliance
- **[/rust-security:gdpr-check](gdpr-check.md)** - GDPR compliance verification

---

**Note:** Compliance reports are point-in-time assessments. Schedule regular scans (weekly/monthly) to maintain compliance posture and track remediation progress.
