# Cloudflare Setup Command

## Overview

**Command:** `/rust-security:cloudflare-setup`

Configures Cloudflare API integration for DNS management, Workers deployment, R2
storage, and Origin/Edge certificate management via Rust.

**Agent:** `cloudflare-setup` (Sonnet - Standard Analysis)

---

## When to Use

- Setting up Cloudflare API client in Rust
- Managing DNS records programmatically
- Deploying Cloudflare Workers
- Integrating R2 object storage
- Automating certificate management

---

## What It Does

1. **Creates Cloudflare client** - Authenticated API client
2. **Configures DNS management** - CRUD for DNS records
3. **Sets up Workers deployment** - Build and deploy pipeline
4. **Integrates R2 storage** - S3-compatible object storage
5. **Manages certificates** - Origin CA and Edge certificates
6. **Implements caching** - API response caching

---

## Parameters

| Parameter    | Type   | Required | Default           | Description                                      |
| ------------ | ------ | -------- | ----------------- | ------------------------------------------------ |
| `--features` | string | No       | `dns,certs`       | Features: `dns`, `workers`, `r2`, `certs`, `all` |
| `--zone`     | string | No       | From env          | Cloudflare Zone ID                               |
| `--output`   | string | No       | `src/cloudflare/` | Output directory                                 |

---

## Output

Creates Cloudflare integration module:

- `src/cloudflare/mod.rs` - Module exports
- `src/cloudflare/client.rs` - API client
- `src/cloudflare/dns.rs` - DNS record management
- `src/cloudflare/workers.rs` - Workers deployment (if enabled)
- `src/cloudflare/r2.rs` - R2 storage client (if enabled)
- `src/cloudflare/certs.rs` - Certificate management
- `config/cloudflare.toml` - Configuration file

---

## Examples

### Example 1: DNS and Certificates

```bash
/rust-security:cloudflare-setup
```

### Example 2: All Features

```bash
/rust-security:cloudflare-setup --features=all
```

### Example 3: R2 Storage Only

```bash
/rust-security:cloudflare-setup --features=r2
```

---

## Environment Variables

```bash
CLOUDFLARE_API_TOKEN=xxx
CLOUDFLARE_ZONE_ID=xxx
CLOUDFLARE_ACCOUNT_ID=xxx  # For Workers/R2
```

---

## Reference Documents

This command invokes the `cloudflare-manager` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[API-DESIGN.md](.claude/API-DESIGN.md)**
- **[ARCHITECTURE-PATTERNS.md](.claude/ARCHITECTURE-PATTERNS.md)**

## Related Commands

- **[/rust-security:cert-rotate](cert-rotate.md)** - Certificate rotation
- **[/rust-security:backup-setup](backup-setup.md)** - Backup configuration
- **[/rust-security:dns-proxy-setup](dns-proxy-setup.md)** - DNS security proxy
