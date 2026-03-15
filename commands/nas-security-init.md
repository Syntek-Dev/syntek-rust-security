# NAS Security Init Command

## Overview

**Command:** `/rust-security:nas-security-init`

Initialises a Rust NAS security wrapper project with real-time file scanning,
malware detection, ransomware protection, and file integrity monitoring.

**Agent:** `nas-security-builder` (Sonnet - Standard Analysis)

---

## When to Use

- Building secure NAS with NixOS
- Implementing file-level threat protection
- Real-time malware scanning on write
- Ransomware detection and prevention
- File integrity monitoring (FIM)

---

## What It Does

1. **Creates project structure** - Cargo workspace for NAS security
2. **Implements file monitoring** - inotify/fanotify watchers
3. **Integrates malware scanning** - ClamAV and YARA rules
4. **Adds ransomware detection** - Entropy and behavior analysis
5. **Implements quarantine** - Isolated storage for threats
6. **Configures FIM** - File integrity monitoring
7. **Creates NixOS module** - Declarative deployment

---

## Parameters

| Parameter    | Type   | Required | Default               | Description        |
| ------------ | ------ | -------- | --------------------- | ------------------ |
| `--name`     | string | No       | `nas-security`        | Project name       |
| `--features` | string | No       | `scan,fim,quarantine` | Features to enable |
| `--paths`    | string | No       | `/data`               | Paths to monitor   |
| `--output`   | string | No       | `./`                  | Output directory   |

---

## Output

Creates NAS security project:

```
nas-security/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── monitor/          # File system monitoring
│   ├── scanner/          # Malware scanning
│   ├── ransomware/       # Ransomware detection
│   ├── quarantine/       # Quarantine system
│   ├── fim/              # File integrity monitoring
│   └── config.rs
├── signatures/
│   └── yara/             # YARA rules
├── config/
│   └── nas.toml
├── nixos/
│   └── module.nix
└── systemd/
    └── nas-security.service
```

---

## Examples

### Example 1: Full NAS Security

```bash
/rust-security:nas-security-init
```

### Example 2: Scanning Only

```bash
/rust-security:nas-security-init --features=scan
```

### Example 3: Custom Paths

```bash
/rust-security:nas-security-init --paths="/data,/media,/backups"
```

---

## Reference Documents

This command invokes the `nas-security-builder` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[ARCHITECTURE-PATTERNS.md](.claude/ARCHITECTURE-PATTERNS.md)**
- **[ENCRYPTION-GUIDE.md](.claude/ENCRYPTION-GUIDE.md)**

## Related Commands

- **[/rust-security:malware-scanner-setup](malware-scanner-setup.md)** - Scanner
  configuration
- **[/rust-security:quarantine-setup](quarantine-setup.md)** - Quarantine system
- **[/rust-security:threat-feeds-setup](threat-feeds-setup.md)** - Threat
  intelligence
