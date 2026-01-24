# Certificate Rotate Command

## Overview

**Command:** `/rust-security:cert-rotate`

Manages Cloudflare Origin CA and Edge certificate rotation with automatic
renewal, Vault storage, and zero-downtime deployment.

**Agent:** `cert-manager` (Sonnet - Standard Analysis)

---

## When to Use

- Rotating expiring Cloudflare Origin certificates
- Automating certificate renewal workflows
- Storing certificates securely in Vault
- Managing Edge certificates for multiple domains
- Setting up certificate monitoring and alerts

---

## What It Does

1. **Checks certificate expiry** - Scans for certificates needing rotation
2. **Requests new certificates** - Via Cloudflare Origin CA API
3. **Stores in Vault** - PKI secrets engine or KV v2
4. **Updates services** - Pushes to Nginx/application servers
5. **Validates deployment** - Tests TLS handshake
6. **Creates audit log** - Records rotation events
7. **Configures monitoring** - Expiry alerts

---

## Parameters

| Parameter      | Type    | Required | Default         | Description                        |
| -------------- | ------- | -------- | --------------- | ---------------------------------- |
| `--domain`     | string  | No       | All domains     | Specific domain to rotate          |
| `--type`       | string  | No       | `origin`        | Certificate type: `origin`, `edge` |
| `--days`       | number  | No       | `30`            | Rotate if expiring within N days   |
| `--dry-run`    | boolean | No       | `false`         | Preview without applying           |
| `--vault-path` | string  | No       | `secret/certs/` | Vault storage path                 |

---

## Output

### Console Output

```
🔐 Syntek Rust Security - Certificate Rotation

🔍 Checking certificates...

📋 Certificate Status:
┌─────────────────────────────────────────────────────────────┐
│ Domain              │ Type   │ Expires     │ Status         │
├─────────────────────────────────────────────────────────────┤
│ example.com         │ Origin │ 15 days     │ Needs rotation │
│ api.example.com     │ Origin │ 89 days     │ OK             │
│ *.example.com       │ Edge   │ 22 days     │ Needs rotation │
└─────────────────────────────────────────────────────────────┘

🔄 Rotating example.com Origin certificate...
   ✓ Requested new certificate from Cloudflare
   ✓ Stored in Vault at secret/certs/example.com
   ✓ Updated Nginx configuration
   ✓ Reloaded Nginx
   ✓ Validated TLS handshake

🔄 Rotating *.example.com Edge certificate...
   ✓ Requested new certificate from Cloudflare
   ✓ Stored in Vault at secret/certs/wildcard.example.com
   ✓ Updated Cloudflare Edge settings

✅ Rotation complete
   Rotated: 2 certificates
   Skipped: 1 certificate (not due)
```

---

## Examples

### Example 1: Rotate All Due Certificates

```bash
/rust-security:cert-rotate
```

### Example 2: Specific Domain

```bash
/rust-security:cert-rotate --domain=api.example.com
```

### Example 3: Dry Run

```bash
/rust-security:cert-rotate --dry-run
```

### Example 4: Aggressive Rotation (60 days)

```bash
/rust-security:cert-rotate --days=60
```

---

## Environment Variables

```bash
CLOUDFLARE_API_TOKEN=xxx
CLOUDFLARE_ZONE_ID=xxx
VAULT_ADDR=https://vault.example.com:8200
VAULT_TOKEN=hvs.xxx
```

---

## Related Commands

- **[/rust-security:cloudflare-setup](cloudflare-setup.md)** - Cloudflare
  integration
- **[/rust-security:vault-setup](vault-setup.md)** - Vault configuration
- **[/rust-security:nginx-config](nginx-config.md)** - Nginx TLS configuration
