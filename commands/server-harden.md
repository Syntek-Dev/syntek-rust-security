# Server Harden Command

## Overview

**Command:** `/rust-security:server-harden`

Performs comprehensive server security hardening, implementing CIS benchmarks,
SSH hardening, kernel parameters, and service security.

**Agent:** `server-hardener` (Opus - Deep Reasoning)

---

## When to Use

- Setting up new production servers
- Security audits and remediation
- Compliance requirements (CIS, NIST)
- Pre-deployment security checks
- Regular security maintenance

---

## What It Does

1. **Audits current configuration** - Checks against CIS benchmarks
2. **Hardens SSH** - Disables root login, key-only auth
3. **Configures kernel parameters** - Secure sysctl settings
4. **Disables unnecessary services** - Minimises attack surface
5. **Sets file permissions** - Correct ownership and modes
6. **Configures audit logging** - auditd rules
7. **Generates compliance report** - Documents hardening status

---

## Parameters

| Parameter  | Type    | Required | Default          | Description                            |
| ---------- | ------- | -------- | ---------------- | -------------------------------------- |
| `--level`  | string  | No       | `standard`       | Level: `minimal`, `standard`, `strict` |
| `--apply`  | boolean | No       | `false`          | Apply changes (default is audit only)  |
| `--skip`   | string  | No       | None             | Checks to skip                         |
| `--output` | string  | No       | `docs/security/` | Output directory                       |

---

## Output

### Console Output

```
🔒 Syntek Rust Security - Server Hardening

📋 Hardening Checklist:

SSH Configuration:
  ✓ Root login disabled
  ✓ Password authentication disabled
  ✗ MaxAuthTries not set (recommend: 3)
  ✓ Protocol 2 only

Kernel Parameters:
  ✓ IP forwarding disabled
  ✗ SYN cookies not enabled
  ✓ ICMP redirects disabled
  ✓ Source routing disabled

Services:
  ✓ Unnecessary services disabled
  ⚠ Telnet service found (should be removed)

File Permissions:
  ✓ /etc/passwd permissions correct
  ✓ /etc/shadow permissions correct
  ✗ /etc/cron.d world-readable

📊 Summary:
   Passed:  18
   Failed:  4
   Warning: 1

📄 Report: docs/security/HARDENING-REPORT.md
```

---

## Examples

### Example 1: Audit Only

```bash
/rust-security:server-harden
```

### Example 2: Apply Standard Hardening

```bash
/rust-security:server-harden --apply --level=standard
```

### Example 3: Strict Hardening

```bash
/rust-security:server-harden --apply --level=strict
```

---

## Reference Documents

This command invokes the `server-hardener` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[API-DESIGN.md](.claude/API-DESIGN.md)**
- **[ARCHITECTURE-PATTERNS.md](.claude/ARCHITECTURE-PATTERNS.md)**

## Related Commands

- **[/rust-security:ssh-wrapper](ssh-wrapper.md)** - SSH security
- **[/rust-security:firewall-setup](firewall-setup.md)** - Firewall
  configuration
- **[/rust-security:systemd-harden](systemd-harden.md)** - Service hardening
- **[/rust-security:docker-harden](docker-harden.md)** - Container hardening
