# IDS Setup Command

## Overview

**Command:** `/rust-security:ids-setup`

Configures intrusion detection/prevention system with Snort/Suricata-compatible
rules, alert management, and automated response.

**Agent:** `ids-setup` (Sonnet - Standard Analysis)

---

## When to Use

- Setting up IDS/IPS for router security
- Configuring Snort/Suricata rules
- Implementing alert management
- Building automated response systems
- Network threat detection

---

## What It Does

1. **Creates rule engine** - Snort/Suricata parser
2. **Implements packet matching** - Fast pattern matching
3. **Configures alerting** - Alert generation and logging
4. **Sets up IPS mode** - Automated blocking
5. **Implements flow tracking** - Connection state management
6. **Configures rule updates** - Emerging Threats integration
7. **Creates management API** - Rule management interface

---

## Parameters

| Parameter     | Type   | Required | Default            | Description                     |
| ------------- | ------ | -------- | ------------------ | ------------------------------- |
| `--mode`      | string | No       | `detection`        | Mode: `detection`, `prevention` |
| `--rules`     | string | No       | `emerging-threats` | Rule sources                    |
| `--interface` | string | No       | `eth0`             | Network interface               |
| `--output`    | string | No       | `src/ids/`         | Output directory                |

---

## Output

Creates IDS module:

- `src/ids/mod.rs` - Module exports
- `src/ids/rules.rs` - Rule parser
- `src/ids/engine.rs` - Matching engine
- `src/ids/alert.rs` - Alert management
- `src/ids/blocker.rs` - IPS blocking
- `rules/` - Rule directory
- `config/ids.toml` - IDS configuration

---

## Examples

### Example 1: IDS Mode

```bash
/rust-security:ids-setup
```

### Example 2: IPS Mode

```bash
/rust-security:ids-setup --mode=prevention
```

### Example 3: Custom Interface

```bash
/rust-security:ids-setup --interface=br0
```

---

## Reference Documents

This command invokes the `intrusion-detector-builder` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[ARCHITECTURE-PATTERNS.md](.claude/ARCHITECTURE-PATTERNS.md)**
- **[PERFORMANCE.md](.claude/PERFORMANCE.md)**

## Related Commands

- **[/rust-security:router-security-init](router-security-init.md)** - Router
  security
- **[/rust-security:dpi-setup](dpi-setup.md)** - Deep packet inspection
- **[/rust-security:firewall-setup](firewall-setup.md)** - Firewall integration
