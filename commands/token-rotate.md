# Token Rotate Command

## Overview

**Command:** `/rust-security:token-rotate`

Automates rotation of secrets, tokens, and API keys with zero-downtime
deployment support, audit logging, and rollback capabilities.

**Agent:** `token-rotator` (Sonnet - Standard Analysis)

---

## When to Use

- Scheduled secret rotation (API keys, tokens)
- Responding to potential secret compromise
- Compliance requirements for regular rotation
- Rotating database credentials
- Updating service-to-service authentication

---

## What It Does

1. **Identifies rotation targets** - Scans for secrets needing rotation
2. **Generates new secrets** - Cryptographically secure generation
3. **Updates Vault** - Stores new version in KV v2
4. **Updates services** - Pushes to dependent services
5. **Validates rotation** - Tests new credentials work
6. **Creates audit log** - Records rotation event
7. **Supports rollback** - Can revert to previous version

---

## Parameters

| Parameter    | Type    | Required | Default | Description                       |
| ------------ | ------- | -------- | ------- | --------------------------------- |
| `--target`   | string  | Yes      | None    | Secret path or pattern to rotate  |
| `--dry-run`  | boolean | No       | `false` | Preview rotation without applying |
| `--force`    | boolean | No       | `false` | Force rotation even if not due    |
| `--rollback` | boolean | No       | `false` | Rollback to previous version      |
| `--notify`   | string  | No       | None    | Notification webhook URL          |

---

## Output

### Console Output

```
🔄 Syntek Rust Security - Token Rotation

🔍 Scanning for rotation targets...

📋 Rotation Plan:
┌─────────────────────────────────────────────────────────────┐
│ Secret                    │ Last Rotated │ Status           │
├─────────────────────────────────────────────────────────────┤
│ secret/api/stripe-key     │ 45 days ago  │ Due for rotation │
│ secret/db/postgres-pass   │ 12 days ago  │ OK               │
│ secret/api/cloudflare-key │ 91 days ago  │ Overdue          │
└─────────────────────────────────────────────────────────────┘

🔄 Rotating secret/api/stripe-key...
   ✓ Generated new key
   ✓ Stored in Vault (version 4)
   ✓ Updated dependent services
   ✓ Validated new key works

🔄 Rotating secret/api/cloudflare-key...
   ✓ Generated new key
   ✓ Stored in Vault (version 7)
   ✓ Updated dependent services
   ✓ Validated new key works

✅ Rotation complete
   Rotated: 2 secrets
   Skipped: 1 secret (not due)

📄 Audit log: docs/security/ROTATION-LOG.md
```

---

## Examples

### Example 1: Rotate All Due Secrets

```bash
/rust-security:token-rotate --target="secret/api/*"
```

### Example 2: Dry Run Preview

```bash
/rust-security:token-rotate --target="secret/db/*" --dry-run
```

### Example 3: Force Immediate Rotation

```bash
/rust-security:token-rotate --target="secret/api/compromised-key" --force
```

### Example 4: Rollback

```bash
/rust-security:token-rotate --target="secret/api/stripe-key" --rollback
```

---

## Reference Documents

This command invokes the `token-rotator` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[ENCRYPTION-GUIDE.md](.claude/ENCRYPTION-GUIDE.md)**
- **[ARCHITECTURE-PATTERNS.md](.claude/ARCHITECTURE-PATTERNS.md)**

## Related Commands

- **[/rust-security:vault-setup](vault-setup.md)** - HashiCorp Vault integration
- **[/rust-security:cert-rotate](cert-rotate.md)** - Certificate rotation
- **[/rust-security:scan-secrets](scan-secrets.md)** - Secret detection
