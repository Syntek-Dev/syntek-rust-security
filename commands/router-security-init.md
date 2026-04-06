# Router Security Init Command

## Overview

**Command:** `/rust-security:router-security-init`

Initialises a Rust router security wrapper project with deep packet inspection,
IDS/IPS capabilities, traffic filtering, and threat detection for DIY router
appliances.

**Agent:** `router-security-init` (Sonnet - Standard Analysis)

---

## When to Use

- Building a DIY secure router with NixOS
- Implementing network-level threat protection
- Creating a firewall with deep packet inspection
- Building an IDS/IPS appliance
- Traffic monitoring and anomaly detection

---

## What It Does

1. **Creates project structure** - Cargo workspace for router security
2. **Implements packet capture** - libpcap/AF_PACKET bindings
3. **Adds DPI engine** - Protocol dissection and analysis
4. **Integrates IDS rules** - Snort/Suricata compatible
5. **Implements traffic filtering** - IP/domain blocking
6. **Configures threat feeds** - Malicious IP/domain lists
7. **Creates NixOS module** - Declarative deployment

---

## Parameters

| Parameter     | Type   | Required | Default           | Description                                        |
| ------------- | ------ | -------- | ----------------- | -------------------------------------------------- |
| `--name`      | string | No       | `router-security` | Project name                                       |
| `--features`  | string | No       | `dpi,ids,filter`  | Features: `dpi`, `ids`, `filter`, `monitor`, `all` |
| `--interface` | string | No       | `eth0`            | Network interface to monitor                       |
| `--output`    | string | No       | `./`              | Output directory                                   |

---

## Output

Creates router security project:

```
router-security/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── capture/          # Packet capture
│   ├── dpi/              # Deep packet inspection
│   ├── ids/              # Intrusion detection
│   ├── filter/           # Traffic filtering
│   └── config.rs
├── rules/
│   └── default.rules     # IDS rules
├── config/
│   └── router.toml
├── nixos/
│   └── module.nix        # NixOS integration
└── systemd/
    └── router-security.service
```

---

## Examples

### Example 1: Full Featured Router Security

```bash
/rust-security:router-security-init
```

### Example 2: IDS Only

```bash
/rust-security:router-security-init --features=ids
```

### Example 3: Custom Interface

```bash
/rust-security:router-security-init --interface=br0 --name=home-router
```

---

## Reference Documents

This command invokes the `router-security-builder` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[ARCHITECTURE-PATTERNS.md](.claude/ARCHITECTURE-PATTERNS.md)**
- **[DATA-STRUCTURES.md](.claude/DATA-STRUCTURES.md)**
- **[PERFORMANCE.md](.claude/PERFORMANCE.md)**

## Related Commands

- **[/rust-security:ids-setup](ids-setup.md)** - IDS rule configuration
- **[/rust-security:dpi-setup](dpi-setup.md)** - Deep packet inspection
- **[/rust-security:threat-feeds-setup](threat-feeds-setup.md)** - Threat
  intelligence
- **[/rust-security:firewall-setup](firewall-setup.md)** - Firewall integration
