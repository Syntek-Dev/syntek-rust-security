# Threat Model Command

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

**Command:** `/rust-security:threat-model`

Performs comprehensive STRIDE threat analysis on Rust projects to identify potential security vulnerabilities across six threat categories: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.

**Agent:** `threat-modeller` (Opus - Deep Reasoning)

---

## When to Use

Use this command when:

- **Starting a new security-critical feature** - Identify threats before implementation
- **Designing system architecture** - Understand attack surfaces and trust boundaries
- **Pre-production security review** - Comprehensive threat assessment before deployment
- **Compliance requirements** - Generate threat models for security audits
- **After major architectural changes** - Re-evaluate security posture
- **Integrating third-party dependencies** - Assess supply chain risks

---

## What It Does

1. **Analyses project architecture** from Cargo.toml, source code, and dependencies
2. **Identifies trust boundaries** between components, modules, and external systems
3. **Maps attack surfaces** including network interfaces, file I/O, and user inputs
4. **Applies STRIDE methodology** to each component and data flow
5. **Generates threat scenarios** with likelihood and impact ratings
6. **Recommends mitigations** specific to Rust's security features
7. **Creates threat model documentation** in `docs/security/THREAT-MODEL.md`

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--scope`          | string   | No       | `full`        | Analysis scope: `full`, `crate`, `module`, `api` |
| `--output`         | string   | No       | `docs/security/THREAT-MODEL.md` | Output file path                |
| `--format`         | string   | No       | `markdown`    | Output format: `markdown`, `json`, `html`        |
| `--components`     | string[] | No       | All           | Specific components to analyze                   |
| `--include-deps`   | boolean  | No       | `true`        | Include dependency analysis                      |
| `--risk-threshold` | string   | No       | `medium`      | Minimum risk level: `low`, `medium`, `high`      |

---

## Output

### Console Output

```
🔒 Syntek Rust Security - STRIDE Threat Modelling

📦 Project: secure-api-server v1.2.0
🎯 Scope: Full project analysis
🔍 Components analyzed: 12
🌐 Attack surfaces identified: 8
⚠️  Threats discovered: 23

┌─────────────────────────────────────────────────────────────┐
│ STRIDE Category Breakdown                                   │
├─────────────────────────────────────────────────────────────┤
│ Spoofing (S):              4 threats - 2 high, 2 medium     │
│ Tampering (T):             6 threats - 1 high, 5 medium     │
│ Repudiation (R):           2 threats - 0 high, 2 medium     │
│ Information Disclosure (I): 5 threats - 3 high, 2 medium    │
│ Denial of Service (D):     4 threats - 1 high, 3 medium     │
│ Elevation of Privilege (E): 2 threats - 1 high, 1 medium    │
└─────────────────────────────────────────────────────────────┘

📊 Risk Summary:
   - Critical: 0
   - High: 7
   - Medium: 16
   - Low: 0

📄 Detailed report: docs/security/THREAT-MODEL.md
```

### Generated Documentation

Creates `docs/security/THREAT-MODEL.md` with:

- **Executive Summary** - High-level threat overview
- **System Architecture** - Component diagram with trust boundaries
- **Attack Surface Analysis** - External interfaces and entry points
- **STRIDE Analysis** - Detailed threats by category
- **Risk Assessment Matrix** - Likelihood vs Impact grid
- **Mitigation Recommendations** - Rust-specific security controls
- **Implementation Roadmap** - Prioritized security tasks

---

## Examples

### Example 1: Full Project Analysis

```bash
/rust-security:threat-model
```

Analyzes entire project with default settings, outputs to `docs/security/THREAT-MODEL.md`.

### Example 2: Specific Module Analysis

```bash
/rust-security:threat-model --scope=module --components=auth,session
```

Focuses threat analysis on authentication and session management modules only.

### Example 3: High-Risk Threats Only

```bash
/rust-security:threat-model --risk-threshold=high --format=json --output=security-report.json
```

Generates JSON report containing only high-risk threats for automated processing.

### Example 4: API Surface Analysis

```bash
/rust-security:threat-model --scope=api --include-deps=false
```

Analyzes only the public API surface without dependency analysis.

### Example 5: Web Service Threat Model

```bash
/rust-security:threat-model --components=http_server,database,auth --format=html
```

Creates HTML threat model for web service components (useful for stakeholder presentations).

---

## Best Practices

### Before Running

1. **Ensure project compiles** - Run `cargo check` first
2. **Update dependencies** - Run `cargo update` for accurate analysis
3. **Document architecture** - Add module-level docs explaining component relationships
4. **Define trust boundaries** - Comment code with `// TRUST BOUNDARY:` markers

### During Analysis

1. **Review all threat categories** - Don't dismiss seemingly low-risk threats
2. **Consider deployment context** - Cloud, on-premise, embedded systems have different threats
3. **Map data flows** - Understand where sensitive data moves through the system
4. **Identify external dependencies** - Third-party crates are potential attack vectors

### After Analysis

1. **Prioritize mitigations** - Address high-risk threats first
2. **Implement defense-in-depth** - Layer multiple security controls
3. **Update documentation** - Keep threat model current with code changes
4. **Schedule regular reviews** - Re-run threat modelling quarterly or after major changes

### Integration with Development Workflow

```bash
# 1. Plan feature
/syntek-dev-suite:plan

# 2. Threat model
/rust-security:threat-model --scope=module --components=new_feature

# 3. Implement with security controls
[Development work]

# 4. Verify mitigations
/rust-security:vuln-scan
/rust-security:crypto-review
/rust-security:memory-audit

# 5. Final review
/rust-security:rust-review
```

---

## Reference Documents

This command invokes the `threat-modeller` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[ARCHITECTURE-PATTERNS.md](.claude/ARCHITECTURE-PATTERNS.md)**
- **[DATA-STRUCTURES.md](.claude/DATA-STRUCTURES.md)**

## Related Commands

- **[/rust-security:vuln-scan](vuln-scan.md)** - Scan for known vulnerabilities in dependencies
- **[/rust-security:crypto-review](crypto-review.md)** - Review cryptographic implementations
- **[/rust-security:memory-audit](memory-audit.md)** - Audit unsafe code and memory safety
- **[/rust-security:supply-chain-audit](supply-chain-audit.md)** - Analyze supply chain risks
- **[/rust-security:compliance-report](compliance-report.md)** - Generate compliance reports

---

**Note:** This command uses the Opus model for deep security reasoning and may take 30-60 seconds for large projects.
