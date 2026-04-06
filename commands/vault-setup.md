# Vault Setup Command

## Overview

**Command:** `/rust-security:vault-setup`

Configures HashiCorp Vault integration for Rust applications, including client
setup, authentication methods, secrets engines, and secure secret retrieval
patterns.

**Agent:** `vault-setup` (Sonnet - Standard Analysis)

---

## When to Use

- Setting up Vault client in a new Rust project
- Configuring authentication (AppRole, Kubernetes, Token)
- Integrating Transit secrets engine for encryption
- Setting up KV secrets engine for configuration
- Implementing secret rotation patterns

---

## What It Does

1. **Adds dependencies** - `vaultrs` crate and TLS dependencies
2. **Creates Vault client** - Connection pool with retry logic
3. **Configures authentication** - AppRole, Kubernetes, or Token auth
4. **Sets up secrets engines** - KV v2, Transit, or PKI
5. **Implements caching** - Secret caching with TTL
6. **Creates health checks** - Vault connectivity monitoring
7. **Generates configuration** - Environment-based Vault config

---

## Parameters

| Parameter     | Type   | Required | Default      | Description                                   |
| ------------- | ------ | -------- | ------------ | --------------------------------------------- |
| `--auth`      | string | No       | `approle`    | Auth method: `approle`, `kubernetes`, `token` |
| `--engines`   | string | No       | `kv,transit` | Secrets engines to configure                  |
| `--namespace` | string | No       | None         | Vault namespace (Enterprise)                  |
| `--output`    | string | No       | `src/vault/` | Output directory                              |

---

## Output

Creates Vault integration module:

- `src/vault/mod.rs` - Module exports
- `src/vault/client.rs` - Vault client with connection pool
- `src/vault/auth.rs` - Authentication handlers
- `src/vault/secrets.rs` - Secret retrieval functions
- `src/vault/transit.rs` - Transit engine encryption/decryption
- `src/vault/config.rs` - Configuration from environment
- `tests/vault_tests.rs` - Integration tests (requires Vault dev server)

---

## Examples

### Example 1: Standard Setup with AppRole

```bash
/rust-security:vault-setup
```

### Example 2: Kubernetes Authentication

```bash
/rust-security:vault-setup --auth=kubernetes
```

### Example 3: Transit Engine Only

```bash
/rust-security:vault-setup --engines=transit
```

---

## Environment Variables

```bash
VAULT_ADDR=https://vault.example.com:8200
VAULT_TOKEN=hvs.xxx  # For token auth
VAULT_ROLE_ID=xxx    # For AppRole
VAULT_SECRET_ID=xxx  # For AppRole
VAULT_NAMESPACE=admin/team  # Enterprise only
```

---

## Reference Documents

This command invokes the `vault-integrator` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**
- **[ENCRYPTION-GUIDE.md](.claude/ENCRYPTION-GUIDE.md)**
- **[ARCHITECTURE-PATTERNS.md](.claude/ARCHITECTURE-PATTERNS.md)**

## Related Commands

- **[/rust-security:encrypt-setup](encrypt-setup.md)** - Encryption with Vault
  Transit
- **[/rust-security:token-rotate](token-rotate.md)** - Secret rotation
  automation
- **[/rust-security:cert-rotate](cert-rotate.md)** - Certificate rotation via
  Vault
