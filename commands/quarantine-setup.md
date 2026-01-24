# Quarantine Setup Command

## Overview

**Command:** `/rust-security:quarantine-setup`

Configures file quarantine system with isolated storage, admin notifications,
and restoration workflows for detected threats.

**Agent:** `nas-security-builder` (Sonnet - Standard Analysis)

---

## When to Use

- Setting up quarantine for NAS security
- Implementing threat isolation
- Creating restoration workflows
- Admin notification for threats
- Compliance requirement for threat handling

---

## What It Does

1. **Creates quarantine storage** - Isolated directory with encryption
2. **Implements move logic** - Atomic move to quarantine
3. **Adds metadata tracking** - Original path, detection info
4. **Configures notifications** - Email/webhook alerts
5. **Implements restoration** - Safe restore workflow
6. **Creates retention policy** - Automatic cleanup
7. **Enables audit logging** - Quarantine actions logged

---

## Parameters

| Parameter     | Type    | Required | Default           | Description               |
| ------------- | ------- | -------- | ----------------- | ------------------------- |
| `--path`      | string  | No       | `/var/quarantine` | Quarantine directory      |
| `--encrypt`   | boolean | No       | `true`            | Encrypt quarantined files |
| `--retention` | string  | No       | `30d`             | Retention period          |
| `--notify`    | string  | No       | None              | Notification webhook URL  |
| `--output`    | string  | No       | `src/quarantine/` | Output directory          |

---

## Output

Creates quarantine module:

- `src/quarantine/mod.rs` - Module exports
- `src/quarantine/storage.rs` - Quarantine storage
- `src/quarantine/move.rs` - Move operations
- `src/quarantine/metadata.rs` - Metadata tracking
- `src/quarantine/notify.rs` - Notifications
- `src/quarantine/restore.rs` - Restoration
- `config/quarantine.toml` - Configuration

---

## Examples

### Example 1: Default Setup

```bash
/rust-security:quarantine-setup
```

### Example 2: With Notifications

```bash
/rust-security:quarantine-setup --notify=https://hooks.slack.com/xxx
```

### Example 3: Long Retention

```bash
/rust-security:quarantine-setup --retention=90d
```

---

## Quarantine Workflow

```
1. Threat detected by scanner
   ↓
2. File moved to quarantine (atomic)
   ↓
3. Metadata recorded (original path, threat name, time)
   ↓
4. Admin notified (if configured)
   ↓
5. File encrypted in quarantine
   ↓
6. After retention period: auto-delete
   OR
   Admin reviews and restores/deletes
```

---

## Related Commands

- **[/rust-security:malware-scanner-setup](malware-scanner-setup.md)** - Malware
  scanning
- **[/rust-security:nas-security-init](nas-security-init.md)** - NAS security
- **[/rust-security:threat-feeds-setup](threat-feeds-setup.md)** - Threat
  intelligence
