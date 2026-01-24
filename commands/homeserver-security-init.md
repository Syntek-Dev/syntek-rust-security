# Homeserver Security Init Command

## Overview

**Command:** `/rust-security:homeserver-security-init`

Initialises a Rust homeserver security wrapper project with process monitoring,
application firewall, rootkit detection, and host-level threat protection.

**Agent:** `homeserver-security-builder` (Sonnet - Standard Analysis)

---

## When to Use

- Building secure homeserver with NixOS
- Implementing host-level threat protection
- Process monitoring and anomaly detection
- Application-level firewall (outbound control)
- Rootkit and privilege escalation detection

---

## What It Does

1. **Creates project structure** - Cargo workspace for homeserver security
2. **Implements process monitoring** - Process creation/termination tracking
3. **Adds application firewall** - Outbound connection control
4. **Integrates rootkit detection** - Hidden process/file detection
5. **Implements privilege monitoring** - Escalation detection
6. **Configures system call filtering** - seccomp-bpf integration
7. **Creates NixOS module** - Declarative deployment

---

## Parameters

| Parameter    | Type   | Required | Default                 | Description        |
| ------------ | ------ | -------- | ----------------------- | ------------------ |
| `--name`     | string | No       | `homeserver-security`   | Project name       |
| `--features` | string | No       | `procmon,appfw,rootkit` | Features to enable |
| `--output`   | string | No       | `./`                    | Output directory   |

---

## Output

Creates homeserver security project:

```
homeserver-security/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── procmon/          # Process monitoring
│   ├── appfw/            # Application firewall
│   ├── rootkit/          # Rootkit detection
│   ├── privilege/        # Privilege escalation detection
│   ├── seccomp/          # System call filtering
│   └── config.rs
├── rules/
│   └── process-whitelist.toml
├── config/
│   └── homeserver.toml
├── nixos/
│   └── module.nix
└── systemd/
    └── homeserver-security.service
```

---

## Examples

### Example 1: Full Homeserver Security

```bash
/rust-security:homeserver-security-init
```

### Example 2: Process Monitoring Only

```bash
/rust-security:homeserver-security-init --features=procmon
```

### Example 3: Custom Name

```bash
/rust-security:homeserver-security-init --name=media-server-security
```

---

## Related Commands

- **[/rust-security:server-harden](server-harden.md)** - Server hardening
- **[/rust-security:docker-harden](docker-harden.md)** - Container security
- **[/rust-security:ids-setup](ids-setup.md)** - Intrusion detection
