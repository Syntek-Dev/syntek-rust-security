# SSH Wrapper Command

## Overview

**Command:** `/rust-security:ssh-wrapper`

Generates a Rust SSH wrapper with comprehensive session logging, command
filtering, and access control for secure remote access management.

**Agent:** `ssh-wrapper-generator` (Sonnet - Standard Analysis)

---

## When to Use

- Building SSH bastion/jump hosts
- Implementing audit logging for SSH sessions
- Creating command whitelisting for restricted access
- Building SSH proxies with session recording
- Compliance requirements for access logging

---

## What It Does

1. **Creates SSH proxy** - Rust-based SSH connection handler
2. **Implements logging** - Full session recording (commands, output)
3. **Adds command filtering** - Whitelist/blacklist command patterns
4. **Configures authentication** - Key-based auth with optional MFA
5. **Generates audit trails** - Tamper-evident logs
6. **Creates systemd service** - Production deployment configuration

---

## Parameters

| Parameter   | Type    | Required | Default    | Description                             |
| ----------- | ------- | -------- | ---------- | --------------------------------------- |
| `--mode`    | string  | No       | `proxy`    | Mode: `proxy`, `bastion`, `recorder`    |
| `--logging` | string  | No       | `full`     | Logging: `full`, `commands`, `metadata` |
| `--filter`  | boolean | No       | `true`     | Enable command filtering                |
| `--output`  | string  | No       | `src/ssh/` | Output directory                        |

---

## Output

Creates SSH wrapper module:

- `src/ssh/mod.rs` - Module exports
- `src/ssh/proxy.rs` - SSH proxy implementation
- `src/ssh/logger.rs` - Session logging
- `src/ssh/filter.rs` - Command filtering
- `src/ssh/auth.rs` - Authentication handlers
- `config/ssh-wrapper.toml` - Configuration file
- `systemd/ssh-wrapper.service` - Systemd unit file

---

## Examples

### Example 1: Full SSH Proxy

```bash
/rust-security:ssh-wrapper
```

### Example 2: Command Recording Only

```bash
/rust-security:ssh-wrapper --mode=recorder --logging=commands
```

### Example 3: Bastion Host

```bash
/rust-security:ssh-wrapper --mode=bastion
```

---

## Related Commands

- **[/rust-security:server-harden](server-harden.md)** - Server hardening
- **[/rust-security:firewall-setup](firewall-setup.md)** - Firewall
  configuration
- **[/rust-security:vault-setup](vault-setup.md)** - Key management via Vault
