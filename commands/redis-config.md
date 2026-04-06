# Redis Config Command

## Overview

**Command:** `/rust-security:redis-config`

Generates secure Redis/Valkey configuration with authentication, TLS encryption,
ACLs, and memory management for production deployments.

**Agent:** `redis-config` (Sonnet - Standard Analysis)

---

## When to Use

- Setting up Redis for production
- Configuring Valkey (Redis fork) securely
- Implementing Redis ACLs for access control
- Enabling TLS for Redis connections
- Hardening existing Redis deployments

---

## What It Does

1. **Generates redis.conf** - Secure base configuration
2. **Configures authentication** - Password and ACL setup
3. **Enables TLS** - Certificate configuration
4. **Sets memory limits** - Maxmemory and eviction policies
5. **Configures persistence** - RDB and AOF settings
6. **Creates ACL file** - Role-based access control
7. **Generates systemd service** - Production deployment

---

## Parameters

| Parameter       | Type    | Required | Default  | Description                               |
| --------------- | ------- | -------- | -------- | ----------------------------------------- |
| `--tls`         | boolean | No       | `true`   | Enable TLS encryption                     |
| `--acl`         | boolean | No       | `true`   | Enable ACL authentication                 |
| `--maxmemory`   | string  | No       | `256mb`  | Maximum memory limit                      |
| `--persistence` | string  | No       | `aof`    | Persistence: `none`, `rdb`, `aof`, `both` |
| `--output`      | string  | No       | `redis/` | Output directory                          |

---

## Output

Creates Redis configuration:

- `redis/redis.conf` - Main configuration
- `redis/users.acl` - ACL definitions
- `redis/tls/` - TLS certificate directory
- `systemd/redis.service` - Systemd service file
- `scripts/redis-healthcheck.sh` - Health check script

---

## Examples

### Example 1: Secure Default Setup

```bash
/rust-security:redis-config
```

### Example 2: High Memory, No TLS (Internal Network)

```bash
/rust-security:redis-config --maxmemory=2gb --tls=false
```

### Example 3: Cache Only (No Persistence)

```bash
/rust-security:redis-config --persistence=none --maxmemory=512mb
```

---

## Generated ACL Example

```
# users.acl
user default off
user admin on >strongpassword ~* &* +@all
user app on >apppassword ~app:* &* +@read +@write -@dangerous
user readonly on >readpassword ~* &* +@read -@write
```

---

## Security Features

- **No default user** - Default user disabled
- **Strong password required** - Enforced authentication
- **Dangerous commands disabled** - CONFIG, DEBUG, etc.
- **TLS encryption** - Encrypted connections
- **Bind to localhost** - No external access by default
- **Protected mode** - Enabled by default

---

## Reference Documents

This command invokes the `redis-configurator` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[ARCHITECTURE-PATTERNS.md](.claude/ARCHITECTURE-PATTERNS.md)**
- **[PERFORMANCE.md](.claude/PERFORMANCE.md)**

## Related Commands

- **[/rust-security:nginx-config](nginx-config.md)** - Frontend configuration
- **[/rust-security:vault-setup](vault-setup.md)** - Password management
- **[/rust-security:systemd-harden](systemd-harden.md)** - Service hardening
