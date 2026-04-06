# Backup Setup Command

## Overview

**Command:** `/rust-security:backup-setup`

Configures encrypted backup systems using Backblaze B2, with client-side
encryption, incremental backups, and retention policies.

**Agent:** `backup-setup` (Sonnet - Standard Analysis)

---

## When to Use

- Setting up encrypted backups for servers
- Configuring Backblaze B2 integration
- Implementing backup rotation and retention
- Creating disaster recovery procedures
- Compliance requirements for data backup

---

## What It Does

1. **Creates B2 client** - Authenticated Backblaze B2 client
2. **Implements encryption** - Client-side AES-256-GCM encryption
3. **Configures incremental backups** - Only changed files uploaded
4. **Sets retention policies** - Automated cleanup of old backups
5. **Creates backup schedules** - Cron/systemd timer configuration
6. **Implements verification** - Backup integrity checks
7. **Generates restore procedures** - Documented recovery steps

---

## Parameters

| Parameter     | Type   | Required | Default         | Description                                  |
| ------------- | ------ | -------- | --------------- | -------------------------------------------- |
| `--bucket`    | string | Yes      | None            | B2 bucket name                               |
| `--paths`     | string | No       | `/data,/config` | Paths to backup                              |
| `--retention` | string | No       | `30d`           | Retention period                             |
| `--schedule`  | string | No       | `daily`         | Backup schedule: `hourly`, `daily`, `weekly` |
| `--output`    | string | No       | `src/backup/`   | Output directory                             |

---

## Output

Creates backup module:

- `src/backup/mod.rs` - Module exports
- `src/backup/client.rs` - B2 client
- `src/backup/encryption.rs` - Client-side encryption
- `src/backup/incremental.rs` - Incremental backup logic
- `src/backup/retention.rs` - Retention policy enforcement
- `config/backup.toml` - Backup configuration
- `systemd/backup.timer` - Systemd timer for scheduling
- `docs/DISASTER-RECOVERY.md` - Recovery procedures

---

## Examples

### Example 1: Basic Setup

```bash
/rust-security:backup-setup --bucket=my-backups
```

### Example 2: Custom Paths and Retention

```bash
/rust-security:backup-setup --bucket=my-backups --paths="/var/lib/app,/etc/app" --retention=90d
```

### Example 3: Hourly Backups

```bash
/rust-security:backup-setup --bucket=critical-data --schedule=hourly
```

---

## Environment Variables

```bash
B2_APPLICATION_KEY_ID=xxx
B2_APPLICATION_KEY=xxx
BACKUP_ENCRYPTION_KEY=xxx  # Or retrieve from Vault
```

---

## Reference Documents

This command invokes the `backup-manager` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[ARCHITECTURE-PATTERNS.md](.claude/ARCHITECTURE-PATTERNS.md)**
- **[ENCRYPTION-GUIDE.md](.claude/ENCRYPTION-GUIDE.md)**

## Related Commands

- **[/rust-security:vault-setup](vault-setup.md)** - Key management
- **[/rust-security:encrypt-setup](encrypt-setup.md)** - Encryption patterns
- **[/rust-security:server-harden](server-harden.md)** - Server security
