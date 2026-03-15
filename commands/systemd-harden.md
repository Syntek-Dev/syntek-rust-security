# Systemd Harden Command

## Overview

**Command:** `/rust-security:systemd-harden`

Generates hardened systemd service files with sandboxing, capability
restrictions, and resource limits for secure service deployment.

**Agent:** `systemd-hardener` (Sonnet - Standard Analysis)

---

## When to Use

- Creating secure systemd service files
- Hardening existing service configurations
- Implementing least-privilege execution
- Sandboxing applications with namespaces
- Production deployment of Rust services

---

## What It Does

1. **Analyses service requirements** - Detects needed capabilities
2. **Applies sandboxing** - Namespace and filesystem isolation
3. **Restricts capabilities** - Drops unnecessary capabilities
4. **Sets resource limits** - CPU, memory, file descriptors
5. **Configures security options** - Seccomp, AppArmor, SELinux
6. **Validates configuration** - systemd-analyze security
7. **Generates documentation** - Security posture documentation

---

## Parameters

| Parameter   | Type   | Required | Default      | Description                                |
| ----------- | ------ | -------- | ------------ | ------------------------------------------ |
| `--service` | string | Yes      | None         | Service name                               |
| `--exec`    | string | Yes      | None         | Executable path                            |
| `--level`   | string | No       | `standard`   | Hardening: `minimal`, `standard`, `strict` |
| `--user`    | string | No       | Service name | Run as user                                |
| `--output`  | string | No       | `systemd/`   | Output directory                           |

---

## Output

Creates systemd configuration:

- `systemd/{service}.service` - Hardened service file
- `systemd/{service}.socket` - Socket activation (if applicable)
- `systemd/conf.d/{service}.conf` - Override configuration
- `docs/SYSTEMD-SECURITY.md` - Security documentation

---

## Examples

### Example 1: Basic Service

```bash
/rust-security:systemd-harden --service=myapp --exec=/usr/local/bin/myapp
```

### Example 2: Strict Hardening

```bash
/rust-security:systemd-harden --service=myapp --exec=/usr/local/bin/myapp --level=strict
```

### Example 3: Custom User

```bash
/rust-security:systemd-harden --service=myapp --exec=/usr/local/bin/myapp --user=myapp
```

---

## Generated Security Options

```ini
[Service]
# User/Group
User=myapp
Group=myapp
DynamicUser=yes

# Sandboxing
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
NoNewPrivileges=yes

# Capabilities
CapabilityBoundingSet=
AmbientCapabilities=

# Namespaces
PrivateUsers=yes
ProtectHostname=yes
ProtectClock=yes

# Filesystem
ReadWritePaths=/var/lib/myapp
ReadOnlyPaths=/etc/myapp

# Network
RestrictAddressFamilies=AF_INET AF_INET6

# Seccomp
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

# Resource Limits
MemoryMax=512M
CPUQuota=50%
TasksMax=100
```

---

## Security Score

After generation, run:

```bash
systemd-analyze security myapp.service
```

Target: Score < 2.0 (SAFE)

---

## Reference Documents

This command invokes the `systemd-hardener` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[ARCHITECTURE-PATTERNS.md](.claude/ARCHITECTURE-PATTERNS.md)**

## Related Commands

- **[/rust-security:server-harden](server-harden.md)** - Server hardening
- **[/rust-security:docker-harden](docker-harden.md)** - Container hardening
- **[/rust-security:gunicorn-config](gunicorn-config.md)** - Application server
