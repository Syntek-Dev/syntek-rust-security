# Security Architecture

**Last Updated:** 2026-02-24

Comprehensive security patterns, memory safety requirements, cryptographic
guidelines, and hardening strategies for the syntek-rust-security plugin and
all code it generates.

---

## Memory Safety and Zeroisation

### Sensitive Data in Memory

Rust does not automatically erase sensitive values when they are dropped. Every
type that holds a secret, key, password, or token must actively zero its memory.

**Required patterns:**

```rust
use secrecy::Secret;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Wrap sensitive primitives in Secret<T> to prevent debug/display leakage
let api_key: Secret<String> = Secret::new("sk-ant-api03-...".to_string());

// For custom types, derive ZeroizeOnDrop
#[derive(ZeroizeOnDrop)]
struct EncryptionKey {
    bytes: [u8; 32],
}

// For manual control, implement Zeroize
impl Zeroize for SensitiveBuffer {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}
```

**Checklist:**

- [ ] All cryptographic keys wrapped in `ZeroizeOnDrop` types
- [ ] Passwords and tokens wrapped in `secrecy::Secret`
- [ ] No sensitive values stored in `String` or `Vec<u8>` without a wrapper
- [ ] `Clone` implementations for sensitive types are also `ZeroizeOnDrop`
- [ ] FFI return values zero their source before returning

### Memory Safety Audit

Run `/memory-audit` to scan for:

- Unprotected sensitive values
- Unsafe blocks without `// SAFETY:` comments
- Missing `ZeroizeOnDrop` on key-holding types
- Use of `String::from_utf8_unchecked` with untrusted data

---

## Cryptographic Standards

### Algorithm Selection

| Use Case                  | Required Algorithm          | Forbidden Alternatives            |
| ------------------------- | --------------------------- | --------------------------------- |
| Symmetric encryption      | AES-256-GCM, ChaCha20-Poly1305 | AES-128, AES-ECB, RC4, 3DES    |
| Password hashing          | Argon2id                    | bcrypt, scrypt, MD5, SHA-1/256    |
| Key exchange              | X25519                      | RSA < 4096, DH with known params  |
| Digital signatures        | Ed25519                     | RSA-PKCS1, DSA                    |
| HMAC / MACs               | HMAC-SHA256, BLAKE3         | HMAC-MD5, CRC32                   |
| Key derivation (non-pwd)  | HKDF-SHA256                 | Direct key truncation/expansion   |
| Random nonce generation   | `OsRng` (cryptographically secure) | `thread_rng`, timestamp-based |
| Hashing (non-security)    | BLAKE3, SHA-256             | MD5, SHA-1                        |

### Nonce and IV Management

**Never reuse a nonce with the same key.** Nonce reuse with AES-GCM completely
breaks confidentiality and authentication.

```rust
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, OsRng, AeadCore}};

// CORRECT: Random nonce generated fresh for every encryption
let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())?;
// Store nonce alongside ciphertext: nonce || ciphertext

// WRONG: Fixed nonce, counter-based nonce without misuse resistance
// let nonce = [0u8; 12]; // NEVER DO THIS
```

For high-volume encryption where nonce collision risk is a concern, use
XChaCha20-Poly1305 (192-bit nonce eliminates practical collision risk).

### Constant-Time Comparisons

All comparisons involving secrets must be constant-time to prevent timing
side-channel attacks.

```rust
use subtle::ConstantTimeEq;

// CORRECT: Constant-time comparison
let is_valid = candidate_mac.ct_eq(&expected_mac).into();

// WRONG: Short-circuit comparison leaks timing information
// let is_valid = candidate_mac == expected_mac; // DO NOT USE FOR SECRETS
```

### Crate Selection

Preferred crates for cryptographic operations:

```toml
[dependencies]
# AES-GCM and ChaCha20
aes-gcm = "0.10"
chacha20poly1305 = "0.10"

# Key derivation
argon2 = "0.5"
hkdf = "0.12"

# Signatures and key exchange
ed25519-dalek = "2"
x25519-dalek = "2"

# HMAC and hashing
hmac = "0.12"
sha2 = "0.10"
blake3 = "1"

# Constant-time operations
subtle = "2"

# Memory safety
zeroize = { version = "1", features = ["derive"] }
secrecy = "0.8"

# Low-level cryptographic primitives (audited, performant)
ring = "0.17"
```

---

## Secrets Management

### HashiCorp Vault Integration

All secrets are retrieved from HashiCorp Vault at runtime. No secrets are
stored in environment variables, configuration files, or code.

**Vault access patterns:**

```rust
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::kv2;

// Retrieve a secret at startup — fail fast if unavailable
let client = VaultClient::new(
    VaultClientSettingsBuilder::default()
        .address(&vault_addr)
        .token(&vault_token)
        .build()?
)?;

// Fetch with context — the error message should identify the path, not the value
let api_key: Secret<String> = kv2::read(&client, "secret", "api/anthropic")
    .await
    .map(|s: ApiKeySecret| Secret::new(s.key))
    .context("failed to fetch Anthropic API key from Vault")?;
```

**Token lifecycle:**

- Use short-lived Vault tokens (TTL ≤ 1 hour for service tokens)
- Renew tokens before expiry; fail gracefully if renewal fails
- Revoke tokens on service shutdown
- Never log Vault tokens — use `secrecy::Secret` for all token values

**Vault policies follow least privilege:**

```hcl
# Example narrow policy for a certificate rotation service
path "secret/data/certs/origin-key" {
  capabilities = ["read"]
}

path "secret/metadata/certs/origin-key" {
  capabilities = ["read"]
}
```

### Secret Rotation

All secrets managed by this plugin support rotation without service downtime:

1. Write new secret to Vault at a versioned path
2. Service fetches new secret on next renewal cycle
3. Verify service health with new secret
4. Revoke old secret version after grace period

Token rotation automation is provided by the `/token-rotate` command and the
`token-rotator` agent.

---

## Dependency Security

### Supply Chain Management

Every dependency is a potential attack surface. Apply these controls:

```toml
# Cargo.deny configuration — run cargo deny check before merging
[advisories]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"

[licenses]
allow = ["MIT", "Apache-2.0", "MPL-2.0", "ISC", "BSD-2-Clause", "BSD-3-Clause"]
deny = ["GPL-2.0", "GPL-3.0", "AGPL-3.0"]

[bans]
multiple-versions = "warn"
wildcards = "deny"
```

**Before adding any dependency:**

1. Check the RustSec advisory database: `cargo audit`
2. Review the crate's security track record on crates.io and GitHub
3. Verify the licence is compatible (see CODING-PRINCIPLES.md)
4. Pin to a specific version in `Cargo.toml`
5. Run `/supply-chain-audit` to scan the full dependency tree

**Pinning in `Cargo.toml`:**

```toml
# Exact version pin for security-critical crates
aes-gcm = "=0.10.3"

# Allow patch releases for well-maintained utility crates
serde = "1.0"
tokio = { version = "1.36", features = ["full"] }
```

Commit `Cargo.lock` for all binary crates. This ensures reproducible builds
and prevents silent dependency upgrades.

### Vulnerability Scanning

Run on every dependency change and as part of CI:

```bash
# Audit against the RustSec advisory database
cargo audit

# Deny known vulnerabilities, check licences, detect duplicate crates
cargo deny check

# Scan for unsafe code surface area
cargo geiger --all-features

# Full plugin security scan
/supply-chain-audit
```

---

## Input Validation

### Treat All External Input as Hostile

External input includes: network data, files, environment variables, FFI
arguments, CLI arguments, and database query results from external systems.

```rust
// Validate at the boundary — before the value enters the system
fn validate_vault_path(path: &str) -> Result<ValidatedPath, ValidationError> {
    // Reject path traversal
    if path.contains("..") || path.contains("//") {
        return Err(ValidationError::PathTraversal);
    }

    // Reject null bytes and control characters
    if path.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(ValidationError::InvalidCharacter);
    }

    // Enforce maximum length
    if path.len() > MAX_VAULT_PATH_LEN {
        return Err(ValidationError::PathTooLong { len: path.len() });
    }

    Ok(ValidatedPath(path.to_string()))
}
```

### Newtype Pattern for Validated Values

Use newtypes to enforce that validation has occurred before a value is used:

```rust
/// A Vault path that has been validated. Cannot be constructed directly.
pub struct ValidatedVaultPath(String);

impl ValidatedVaultPath {
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        validate_vault_path(raw)?;
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Functions that require a valid path cannot accept raw &str
fn fetch_secret(path: &ValidatedVaultPath) -> Result<Secret<String>, VaultError> {
    // ...
}
```

---

## Transport Security

### TLS Configuration

All outbound connections must use TLS 1.2 or higher. Configure rustls directly
rather than relying on OpenSSL defaults:

```rust
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

let root_store = RootCertStore {
    roots: webpki_roots::TLS_SERVER_ROOTS.into(),
};

let tls_config = ClientConfig::builder()
    .with_root_certificates(root_store)
    .with_no_client_auth();

// Minimum TLS 1.2 is enforced by rustls by default
// TLS 1.3 is preferred automatically when supported by the server
```

### Certificate Validation

Never disable certificate verification, even in development:

```rust
// WRONG: Disables all certificate validation
// let config = ClientConfig::builder()
//     .dangerous()
//     .with_custom_certificate_verifier(Arc::new(NoVerifier));

// CORRECT: Use a test CA for development/testing environments
let mut root_store = RootCertStore::empty();
root_store.add_parsable_certificates(test_ca_certs);
```

For self-signed certificates in test environments, add the CA to the trust
store rather than disabling verification.

---

## Cloudflare Certificate Management

This plugin manages Cloudflare Origin and Edge certificates — not Let's Encrypt.

**Certificate types:**

| Type              | Validity  | Managed By           | Storage            |
| ----------------- | --------- | -------------------- | ------------------ |
| Cloudflare Origin | 15 years  | Cloudflare Dashboard | HashiCorp Vault    |
| Cloudflare Edge   | Auto      | Cloudflare (managed) | Cloudflare         |
| mTLS Client cert  | Configurable | Cloudflare mTLS   | HashiCorp Vault    |

**Rotation workflow (`/cert-rotate`):**

1. Fetch current certificate from Vault
2. Generate new certificate via Cloudflare API
3. Store new certificate and private key in Vault (versioned)
4. Update Nginx/service configuration to use new certificate
5. Verify TLS handshake succeeds with new certificate
6. Revoke previous certificate version after grace period

Private keys must be wrapped in `secrecy::Secret` and `ZeroizeOnDrop` types
throughout the rotation workflow. They must never appear in logs.

---

## SSH Security

### SSH Wrapper Requirements

SSH wrappers generated by `/ssh-wrapper` must enforce:

- **Comprehensive logging**: Every connection, command, and disconnection is
  logged with timestamp, source IP, username, and the full command string.
- **Command filtering**: Allowlist of permitted commands. Anything not on the
  list is rejected with a logged rejection event.
- **Key validation**: Verify host key fingerprints against a stored allowlist.
- **Timeout enforcement**: Idle connections terminated after configurable TTL.

**Logging format:**

```rust
// All SSH events must emit structured logs at INFO or above
tracing::info!(
    event = "ssh_command_executed",
    user = %username,
    source_ip = %source_ip,
    command = %sanitised_command, // Never log raw untrusted command without sanitisation
    session_id = %session_id,
);
```

---

## Server Hardening Checklist

Generated by `/server-harden` — verify each item before deployment.

### OS-Level Hardening

- [ ] Non-root service user with minimal permissions
- [ ] `NoNewPrivileges=true` in systemd unit
- [ ] `CapabilityBoundingSet` restricted to required capabilities
- [ ] `PrivateTmp=true` and `ProtectSystem=strict` in systemd unit
- [ ] Unnecessary services disabled

### Network Hardening

- [ ] Firewall rules whitelist required ports only
- [ ] All inbound traffic filtered before reaching the service
- [ ] Cloudflare Tunnel or VPN for management access (no public SSH port)
- [ ] Rate limiting on all public endpoints

### Application Hardening

- [ ] Binary compiled with stack canaries and ASLR: `RUSTFLAGS="-C relocation-model=pic"`
- [ ] Full RELRO enabled
- [ ] No debug symbols in production binary
- [ ] No hardcoded credentials or secrets in binary (run `/scan-secrets`)
- [ ] Dependency audit passing (`cargo audit`, `cargo deny check`)

---

## Penetration Testing

The `/pentest-tools` command provides Rust-based security testing utilities.

### Automated Test Schedule

| Test                    | What It Verifies                          | Frequency   |
| ----------------------- | ----------------------------------------- | ----------- |
| Port scanning           | External port exposure                    | Daily       |
| TLS validation          | Certificate validity and cipher suites    | Daily       |
| Auth bruteforce         | Login rate limiting and lockout           | Weekly      |
| Dependency audit        | Known CVEs in dependency tree             | On PR       |
| Secret scanning         | Leaked credentials in code/configs        | On commit   |
| Fuzz testing            | Parser and input handler robustness       | Weekly      |
| Privilege escalation    | Service permission boundaries             | Monthly     |

---

## Compliance References

| Standard    | Command              | What It Checks                              |
| ----------- | -------------------- | ------------------------------------------- |
| OWASP Top 10 | `/compliance-report` | Injection, broken auth, sensitive data, etc. |
| CWE Top 25  | `/compliance-report` | Memory safety, input validation, crypto      |
| GDPR        | `/gdpr-check`        | Data handling, retention, consent            |
| RustSec     | `/vuln-scan`         | CVEs in Rust dependency tree                 |

Run `/compliance-report` before any production release to generate a full
compliance summary with CWE mappings and CVSS scores for any findings.
