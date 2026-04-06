# Firewall Setup Command

## Overview

**Command:** `/rust-security:firewall-setup`

Configures firewall rules using nftables or iptables via Rust bindings, with
stateful packet filtering, rate limiting, and logging.

**Agent:** `firewall-setup` (Sonnet - Standard Analysis)

---

## When to Use

- Setting up firewall rules for servers
- Implementing rate limiting for services
- Creating firewall management in Rust applications
- Building network security appliances
- Automating firewall configuration

---

## What It Does

1. **Creates firewall client** - nftables or iptables bindings
2. **Implements rule management** - Add, remove, list rules
3. **Configures stateful filtering** - Connection tracking
4. **Sets up rate limiting** - Per-IP rate limits
5. **Enables logging** - Packet logging for audit
6. **Creates default policies** - Secure default ruleset
7. **Generates persistence** - Rules survive reboot

---

## Parameters

| Parameter    | Type   | Required | Default          | Description                            |
| ------------ | ------ | -------- | ---------------- | -------------------------------------- |
| `--backend`  | string | No       | `nftables`       | Backend: `nftables`, `iptables`        |
| `--policy`   | string | No       | `default`        | Policy: `minimal`, `default`, `strict` |
| `--services` | string | No       | `ssh,http,https` | Allowed services                       |
| `--output`   | string | No       | `src/firewall/`  | Output directory                       |

---

## Output

Creates firewall module:

- `src/firewall/mod.rs` - Module exports
- `src/firewall/nftables.rs` - nftables bindings
- `src/firewall/rules.rs` - Rule management
- `src/firewall/ratelimit.rs` - Rate limiting
- `src/firewall/logging.rs` - Packet logging
- `config/firewall.toml` - Firewall configuration
- `nftables/ruleset.nft` - Generated nftables ruleset

---

## Examples

### Example 1: Default Setup

```bash
/rust-security:firewall-setup
```

### Example 2: Strict Policy with Custom Services

```bash
/rust-security:firewall-setup --policy=strict --services=ssh,https,8080
```

### Example 3: iptables Backend

```bash
/rust-security:firewall-setup --backend=iptables
```

---

## Reference Documents

This command invokes the `firewall-integrator` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[ARCHITECTURE-PATTERNS.md](.claude/ARCHITECTURE-PATTERNS.md)**

## Related Commands

- **[/rust-security:server-harden](server-harden.md)** - Server hardening
- **[/rust-security:router-security-init](router-security-init.md)** - Router
  security
- **[/rust-security:ids-setup](ids-setup.md)** - Intrusion detection
