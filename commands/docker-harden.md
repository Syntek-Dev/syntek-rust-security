# Docker Harden Command

## Overview

**Command:** `/rust-security:docker-harden`

Audits and hardens Docker container configurations, implementing security best
practices for container isolation, resource limits, and runtime security.

**Agent:** `docker-harden` (Sonnet - Standard Analysis)

---

## When to Use

- Auditing Docker configurations for security issues
- Hardening Dockerfiles and compose files
- Implementing container security policies
- Setting up runtime security monitoring
- Compliance requirements for container security

---

## What It Does

1. **Audits Dockerfiles** - Checks for security anti-patterns
2. **Reviews compose files** - Validates security configurations
3. **Implements hardening** - Adds security directives
4. **Configures resource limits** - CPU, memory, PIDs limits
5. **Sets up user namespaces** - Non-root container execution
6. **Enables security scanning** - Image vulnerability scanning
7. **Generates security policy** - Seccomp and AppArmor profiles

---

## Parameters

| Parameter   | Type    | Required | Default          | Description                                      |
| ----------- | ------- | -------- | ---------------- | ------------------------------------------------ |
| `--fix`     | boolean | No       | `false`          | Automatically apply fixes                        |
| `--scan`    | boolean | No       | `true`           | Scan images for vulnerabilities                  |
| `--profile` | string  | No       | `default`        | Security profile: `minimal`, `default`, `strict` |
| `--output`  | string  | No       | `docs/security/` | Output directory for reports                     |

---

## Output

### Console Output

```
🐳 Syntek Rust Security - Docker Hardening

📂 Scanning Docker configurations...

⚠️  Issues Found: 6

┌─────────────────────────────────────────────────────────────┐
│ HIGH: Running as root                                       │
├─────────────────────────────────────────────────────────────┤
│ File:     Dockerfile:1                                      │
│ Issue:    No USER directive - container runs as root        │
│ Fix:      Add USER directive with non-root user             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ MEDIUM: No resource limits                                  │
├─────────────────────────────────────────────────────────────┤
│ File:     docker-compose.yml                                │
│ Issue:    No memory/CPU limits defined                      │
│ Fix:      Add deploy.resources.limits section               │
└─────────────────────────────────────────────────────────────┘

📊 Summary:
   High:   2
   Medium: 3
   Low:    1

📄 Report: docs/security/DOCKER-AUDIT.md
```

---

## Examples

### Example 1: Audit Only

```bash
/rust-security:docker-harden
```

### Example 2: Auto-Fix Issues

```bash
/rust-security:docker-harden --fix
```

### Example 3: Strict Security Profile

```bash
/rust-security:docker-harden --profile=strict --fix
```

---

## Reference Documents

This command invokes the `docker-security` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[ARCHITECTURE-PATTERNS.md](.claude/ARCHITECTURE-PATTERNS.md)**

## Related Commands

- **[/rust-security:server-harden](server-harden.md)** - Server hardening
- **[/rust-security:systemd-harden](systemd-harden.md)** - Systemd hardening
- **[/rust-security:vuln-scan](vuln-scan.md)** - Vulnerability scanning
