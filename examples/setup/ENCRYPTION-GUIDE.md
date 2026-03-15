# Encryption Guide

**Last Updated:** 15/03/2026
**Version:** 2.0.0
**Maintained By:** Development Team
**Language:** British English (en_GB)
**Timezone:** Europe/London
**Plugin Scope:** syntek-rust-security (any project using Rust-based field-level encryption)

---

## Table of Contents

- [Overview](#overview)
- [Standards and Approved Algorithms](#standards-and-approved-algorithms)
  - [Symmetric Encryption](#symmetric-encryption)
  - [HMAC and Deterministic Tokens](#hmac-and-deterministic-tokens)
  - [Banned Algorithms](#banned-algorithms)
- [Zero-Plaintext Guarantee](#zero-plaintext-guarantee)
- [What Must Be Encrypted](#what-must-be-encrypted)
- [What Must NOT Be Encrypted](#what-must-not-be-encrypted)
- [Key Management](#key-management)
  - [Key Types and Separation](#key-types-and-separation)
  - [Key Storage](#key-storage)
  - [Key Rotation](#key-rotation)
  - [Key Derivation](#key-derivation)
- [Field-Level Encryption](#field-level-encryption)
  - [Encrypted Field Rules](#encrypted-field-rules)
  - [Individual Field Encryption](#individual-field-encryption)
  - [Batch Field Encryption](#batch-field-encryption)
  - [Additional Authenticated Data (AAD)](#additional-authenticated-data-aad)
  - [Ciphertext Format](#ciphertext-format)
- [Deterministic Lookup Tokens](#deterministic-lookup-tokens)
  - [Why Tokens Are Needed](#why-tokens-are-needed)
  - [Token Generation](#token-generation)
  - [Token Column Naming](#token-column-naming)
  - [Token Normalisation Rules](#token-normalisation-rules)
  - [Database Lookups](#database-lookups)
- [Implementation Patterns](#implementation-patterns)
  - [Django with syntek-pyo3](#django-with-syntek-pyo3)
  - [Laravel with Rust FFI](#laravel-with-rust-ffi)
  - [Direct Rust Usage](#direct-rust-usage)
  - [GraphQL Middleware Integration](#graphql-middleware-integration)
- [Nonce and IV Management](#nonce-and-iv-management)
- [Memory Safety](#memory-safety)
- [Migration Strategy](#migration-strategy)
- [Testing Encrypted Fields](#testing-encrypted-fields)
- [Encryption Checklist](#encryption-checklist)

---

## Overview

This guide defines the encryption and decryption standards for field-level data
protection across any project that uses the Rust security layer. It is
framework-agnostic — the principles apply whether the consuming application is
Django, Laravel, a standalone Rust service, or any other stack that calls into
the Rust encryption library.

The guide aligns with the
[OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html),
the
[OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html),
and the OWASP Top 10:2025 A04 (Cryptographic Failures).

---

## Standards and Approved Algorithms

### Symmetric Encryption

Field-level encryption uses **AES-256-GCM** as the primary algorithm. This is
an Authenticated Encryption with Associated Data (AEAD) cipher that provides
confidentiality, integrity, and authenticity in a single operation.

| Property | Requirement |
|----------|-------------|
| Algorithm | AES-256-GCM (preferred) or ChaCha20-Poly1305 |
| Key size | 256 bits (32 bytes) |
| Nonce size | 96 bits (12 bytes) for AES-256-GCM; 192 bits (24 bytes) for XChaCha20-Poly1305 |
| Nonce generation | Cryptographically secure random (CSPRNG) per encryption operation |
| Authentication tag | 128 bits (16 bytes), included in the ciphertext |
| Associated data (AAD) | Model name + field name, bound to the ciphertext |

**When to use ChaCha20-Poly1305 instead of AES-256-GCM:**

- When running on hardware without AES-NI acceleration (some ARM devices, older
  servers).
- When nonce collision risk is a concern for high-volume systems — use
  XChaCha20-Poly1305 with its 192-bit nonce, which makes random nonce collision
  statistically negligible.

### HMAC and Deterministic Tokens

For deterministic lookup tokens (see
[Deterministic Lookup Tokens](#deterministic-lookup-tokens)):

| Property | Requirement |
|----------|-------------|
| Algorithm | HMAC-SHA256 |
| Key size | 256 bits (32 bytes) minimum |
| Output | 256-bit hex digest (64 characters) |

HMAC-SHA256 produces a deterministic, fixed-length output that is safe to index
and use in unique constraints. It does not reveal the plaintext but allows
equality comparisons.

### Banned Algorithms

The following must never be used for field-level encryption or token generation:

- **AES-ECB** — no diffusion; identical plaintexts produce identical
  ciphertexts. This directly defeats the purpose of encryption.
- **AES-CBC without authentication** — vulnerable to padding oracle attacks. If
  CBC must be used (legacy systems), always apply Encrypt-then-MAC with
  HMAC-SHA256.
- **MD5, SHA-1** — broken collision resistance. Not suitable for any security
  purpose.
- **DES, 3DES, RC4, Blowfish** — insufficient key length or known
  vulnerabilities.
- **Custom/proprietary algorithms** — never implement your own encryption. Use
  vetted, audited libraries.
- **Deterministic encryption (AES-SIV) for field storage** — unless
  specifically needed for equality search and the security trade-offs are
  documented and accepted. Use HMAC tokens for equality lookups instead.

---

## Zero-Plaintext Guarantee

**No plaintext sensitive data ever reaches the database.** This is a wholesale
security policy, not just a compliance measure. Any field whose exposure would
cause a security breach — regardless of whether it identifies a person — must
be encrypted at rest before the database write.

The three actors and their responsibilities:

| Actor | Responsibility |
|-------|---------------|
| **Database column** | Storage type only — holds ciphertext. Never constrained with `UNIQUE` or indexed directly. |
| **Service layer / application code** | Calls encrypt before save; calls decrypt after load. Owns the plaintext lifecycle. |
| **API / presentation layer** | Receives plaintext from the service layer. Never interacts with ciphertext directly. |

The encryption boundary is the service layer. Code above the service layer
(controllers, views, GraphQL resolvers, API resources) works with plaintext.
Code below it (models, repositories, the database) works with ciphertext. This
boundary is never crossed except through the service layer's encrypt/decrypt
operations.

---

## What Must Be Encrypted

Encrypt any field that, if read directly from the database, would cause a
security or privacy breach:

**PII (Personally Identifiable Information):**

- Name, email address, phone number, postal address.
- National identifiers: National Insurance number, SSN, passport number,
  driving licence number.
- Date of birth, place of birth.
- Any government-issued ID.
- Biometric identifiers.

**Long-lived cryptographic secrets:**

- TOTP secrets, authenticator seeds.
- API keys, OAuth client secrets, webhook signing keys.
- These are random (not PII) but a database read leaks them permanently,
  enabling ongoing attacks (e.g., a stolen TOTP secret allows indefinite MFA
  bypass).

**Session-adjacent secrets:**

- Anything whose exposure enables account takeover.
- Refresh tokens stored in the database (access tokens should not be stored at
  all).

**Financial and health data:**

- Bank account numbers, sort codes, IBANs.
- Credit card numbers (prefer tokenisation via a PCI-compliant provider over
  encryption).
- Health records, medical history, prescriptions.

**The test:** "If an attacker reads this value from a database dump, what can
they do?" If the answer is "access accounts", "impersonate users", "contact or
identify someone", or "cause financial harm", encrypt it.

---

## What Must NOT Be Encrypted

Do not encrypt fields that are:

- **Non-sensitive flags and metadata** — `is_active`, `is_staff`, `created_at`,
  `updated_at`, `status`.
- **Already hashed** — password hashes, backup code hashes. Hashing is
  non-reversible; there is no plaintext to protect. Do not double-encrypt hashed
  values.
- **Short-lived single-use tokens** — email verification tokens, password reset
  tokens (expire within minutes/hours and are single-use). These are
  high-entropy and become worthless shortly after creation. They may still need
  HMAC token companions for lookup purposes.
- **Foreign keys** — encrypt the referenced row's PII, not the FK integer.
- **Enum / choice fields** — `status`, `type`, `role` — low cardinality, no
  sensitive information.
- **Public data** — information that is intentionally exposed (public profile
  names, published content, product descriptions).

**Key distinction — random is not the same as safe:** a value being
cryptographically random does not make it safe to store as plaintext. A TOTP
secret is random, but it is also long-lived and its exposure enables indefinite
MFA bypass. Randomness speaks to unpredictability; encryption at rest speaks to
what happens if the database is compromised. Ask the consequence question, not
the derivation question.

---

## Key Management

### Key Types and Separation

Every project that uses field-level encryption requires at least two keys:

| Key | Purpose | Algorithm | Minimum size |
|-----|---------|-----------|-------------|
| **Field Encryption Key (FEK)** | Encrypts and decrypts sensitive field values | AES-256-GCM | 256 bits (32 bytes) |
| **HMAC Key** | Generates deterministic lookup tokens | HMAC-SHA256 | 256 bits (32 bytes) |

**These must be different keys.** Using the same key for both encryption and
HMAC is a cryptographic error — it creates a relationship between the ciphertext
and the token that could be exploited.

For projects with multiple domains (e.g., separate user data, payment data,
health data):

- Use separate FEK/HMAC key pairs per domain.
- A compromise of the payment encryption key should not expose user PII.
- Each key pair is stored, rotated, and revoked independently.

### Key Storage

Keys must never be hardcoded, committed to version control, or stored alongside
the data they protect.

| Environment | Key storage |
|-------------|-------------|
| Development | Environment variables (`.env` file, not committed) |
| Testing | Hardcoded test keys in test configuration only |
| Staging | Secrets manager (HashiCorp Vault, AWS Secrets Manager, or equivalent) |
| Production | Secrets manager with audit logging and access controls |

**Rules:**

- Load keys from environment variables at application startup. Fail fast with a
  clear error if a key is missing or too short.
- Validate key length at startup — AES-256 requires exactly 32 bytes. Reject
  keys that are too short.
- Keys in memory should be stored as byte arrays, not strings, to avoid encoding
  ambiguity and to enable zeroisation.
- In Rust, use the `zeroize` crate to zeroize keys when they are dropped. See
  [Memory Safety](#memory-safety).

### Key Rotation

Key rotation limits the window of exposure if a key is compromised and satisfies
compliance requirements (PCI DSS, GDPR best practices).

**Versioned key ring:**

The encryption layer maintains a key ring — an ordered collection of keys, each
identified by a version number. The most recent version is used for all new
encryptions. All versions are available for decryption.

```
KeyRing:
  Version 1: <original key>     — decrypt only
  Version 2: <rotated key>      — decrypt only
  Version 3: <current key>      — encrypt + decrypt (active)
```

**Rotation process:**

1. Generate a new key of the required size using a CSPRNG.
2. Add the new key to the key ring as the next version.
3. All new encryptions use the new version. All decryptions check the version
   embedded in the ciphertext and use the corresponding key.
4. Re-encrypt existing data in the background: read with old key, write with new
   key. This is a batched background job, not a blocking migration.
5. Once all data is re-encrypted, remove the old key from the key ring.

**Ciphertext must include the key version** so the decryption function knows
which key to use. See [Ciphertext Format](#ciphertext-format).

**Rotation schedule:**

- Rotate annually as a minimum.
- Rotate immediately if a key is suspected of being compromised.
- Rotate when an employee with key access leaves the organisation.
- Ensure the rotation process is automated and tested before it is needed.

### Key Derivation

If keys are derived from a master key (e.g., using HKDF), the derivation process
must use a unique context string per key purpose:

```rust
// Using the hkdf crate
let fek = Hkdf::<Sha256>::new(Some(salt), master_key)
    .expand(b"field-encryption-v1", &mut fek_bytes)
    .expect("HKDF expand failed");

let hmac_key = Hkdf::<Sha256>::new(Some(salt), master_key)
    .expand(b"hmac-lookup-v1", &mut hmac_bytes)
    .expect("HKDF expand failed");
```

Using different info parameters ensures that even with the same master key, the
derived keys are independent. The `salt` should be a random value stored
alongside the key ring metadata.

---

## Field-Level Encryption

### Encrypted Field Rules

- The database column type for encrypted fields is `TEXT` (or equivalent). The
  ciphertext is always longer than the plaintext.
- **Never set `UNIQUE` on an encrypted column.** AES-256-GCM uses a random
  nonce; the same plaintext encrypted twice produces different ciphertext. A
  UNIQUE constraint on ciphertext is meaningless. See
  [Deterministic Lookup Tokens](#deterministic-lookup-tokens).
- **Never set an index on an encrypted column.** The ciphertext is random and
  cannot be meaningfully ordered or searched.
- **Never set `max_length` on an encrypted column.** The ciphertext length
  varies with the plaintext length, the nonce, and the authentication tag.
- `NULL` is permitted for optional fields. A null value means "no data", not
  "encrypted empty string".

### Individual Field Encryption

Use individual encrypt/decrypt calls when a model has one or two sensitive
fields, or when fields use different keys.

```rust
use syntek_crypto::{KeyRing, encrypt_field, decrypt_field};

let ciphertext = encrypt_field(
    plaintext.as_bytes(),
    &ring,
    "User",   // model name — used as AAD
    "email",  // field name — used as AAD
)?;

let plaintext_bytes = decrypt_field(
    &ciphertext,
    &ring,
    "User",
    "email",
)?;
```

### Batch Field Encryption

Use batch encrypt/decrypt when a model has three or more sensitive fields sharing
the same key. Batch operations are more efficient — they reduce the number of
Rust↔host-language boundary crossings.

```rust
use syntek_crypto::{KeyRing, encrypt_fields_batch, decrypt_fields_batch};

let ciphertexts = encrypt_fields_batch(
    &[
        ("full_name", name.as_bytes()),
        ("address",   addr.as_bytes()),
        ("postcode",  postcode.as_bytes()),
    ],
    &ring,
    "User",
)?;

let plaintexts = decrypt_fields_batch(
    &[
        ("full_name", &ciphertexts[0]),
        ("address",   &ciphertexts[1]),
        ("postcode",  &ciphertexts[2]),
    ],
    &ring,
    "User",
)?;
```

| Number of encrypted fields | Use |
|---------------------------|-----|
| 1–2 | Individual encrypt/decrypt |
| 3 or more | Batch encrypt/decrypt |

### Additional Authenticated Data (AAD)

Every encryption operation binds the ciphertext to its context using AAD. The
AAD includes the model name and field name:

```
AAD = "{model_name}.{field_name}"
```

This prevents ciphertext replay attacks — a ciphertext encrypted for
`User.email` cannot be copied into `User.phone` and successfully decrypted,
because the AAD will not match.

**Rules:**

- AAD is not secret. It is transmitted alongside the ciphertext (or derived from
  the storage location).
- AAD must be consistent between encryption and decryption. If you rename a
  model or field, you must re-encrypt all existing data with the new AAD.
- AAD is verified during decryption. If it does not match, the decryption fails
  with an authentication error — this is the correct and expected behaviour.

### Ciphertext Format

The ciphertext stored in the database must be self-describing — it includes all
the information needed for decryption (except the key itself):

```
<version>.<nonce_b64>.<ciphertext_and_tag_b64>

Example:
v1.rN3kQ9wLmP6yHbXz.a7B2cD4eF6gH8iJ0kL2mN4oP6qR8sT0uV2wX4yZ6tA1gB2cD3eF4gH5i
```

| Component | Description |
|-----------|-------------|
| `version` | Key ring version (`v1`, `v2`). Determines which key to use for decryption. |
| `nonce_b64` | Base64url-encoded nonce used for this encryption. |
| `ciphertext_and_tag_b64` | Base64url-encoded ciphertext with authentication tag appended. |

The key version must always be present so that key rotation works transparently.

---

## Deterministic Lookup Tokens

### Why Tokens Are Needed

AES-256-GCM uses a random nonce per encryption. The same plaintext encrypted
twice produces different ciphertext. This means:

- A `UNIQUE` constraint on the ciphertext column is meaningless — the same email
  stored twice passes the constraint because the ciphertexts differ.
- A `WHERE` clause on the ciphertext column cannot find a record by its
  plaintext value — you would have to decrypt every row to compare.

**Solution:** every encrypted field that must support equality lookups or
uniqueness constraints gets a companion **lookup token** column. The token is a
deterministic HMAC-SHA256 of the normalised plaintext. The `UNIQUE` constraint
and database index go on the token column, never on the ciphertext column.

### Token Generation

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn generate_token(hmac_key: &[u8], normalised_value: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(hmac_key)
        .expect("HMAC key length invalid");
    mac.update(normalised_value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
```

The token is:

- **Deterministic** — the same normalised input always produces the same token.
- **Fixed-length** — 64 hex characters (256 bits), regardless of input length.
- **Non-reversible** — the HMAC cannot be inverted to recover the plaintext
  (assuming the key is secret).
- **Indexable** — safe to use in `UNIQUE` constraints, `WHERE` clauses, and
  database indexes.

### Token Column Naming

Every token column is named `{encrypted_field}_token`:

| Encrypted field | Token column |
|----------------|-------------|
| `email` | `email_token` |
| `phone` | `phone_token` |
| `national_insurance_number` | `national_insurance_number_token` |

For fields that do not require uniqueness or lookup, no token column is needed.
Only add tokens where you need to query by value or enforce uniqueness.

### Token Normalisation Rules

Before hashing, the plaintext must be normalised to ensure consistent tokens
regardless of input formatting:

| Field type | Normalisation |
|-----------|--------------|
| Email | `trim().to_lowercase()` |
| Phone | `trim()` (no reformatting — preserve country code format) |
| Username | `trim().to_lowercase()` unless case-sensitive lookups are required |
| National Insurance / SSN | `trim().to_uppercase().replace(' ', "")` |
| General identifiers | `trim()` — add lowercasing if case-insensitive lookups are needed |

**Rules:**

- Normalisation must be applied identically at write time and at query time.
- Document the normalisation rule for each token field. If the normalisation
  changes, all existing tokens must be regenerated.
- Normalisation is not validation. Validate the input before normalising and
  hashing.

### Database Lookups

**Never query against an encrypted column directly.** Always use the token:

```rust
// WRONG — ciphertext lookup, will never match
sqlx::query!("SELECT * FROM users WHERE email = $1", ciphertext)

// CORRECT — token lookup
let token = generate_token(&hmac_key, &normalise_email(email));
sqlx::query!("SELECT * FROM users WHERE email_token = $1", token)
```

### Write Path with Token

Every write operation that touches an encrypted field must compute both the
ciphertext and the token before saving:

```rust
// 1. Validate input
validate_email(&plaintext_email)?;

// 2. Compute token (use for lookup / uniqueness)
let token = generate_token(&hmac_key, &normalise_email(&plaintext_email));

// 3. Compute ciphertext (use for storage)
let ciphertext = encrypt_field(plaintext_email.as_bytes(), &ring, "User", "email")?;

// 4. Set both columns
sqlx::query!(
    "INSERT INTO users (email, email_token) VALUES ($1, $2)",
    ciphertext,
    token,
)
.execute(&pool)
.await?;
```

---

## Implementation Patterns

### Django with syntek-pyo3

```python
from syntek_pyo3 import KeyRing, encrypt_field, decrypt_field, encrypt_fields_batch

# Key setup — loaded once at module level from settings
_fek = settings.MY_MODULE["FIELD_KEY"].encode("utf-8")
_ring = KeyRing()
_ring.add(1, _fek)  # version 1; increment on rotation

# Individual encryption
ciphertext = encrypt_field(plaintext, _ring, "User", "email")
plaintext = decrypt_field(ciphertext, _ring, "User", "email")

# Batch encryption (3+ fields)
ciphertexts = encrypt_fields_batch(
    [("full_name", name), ("address", addr), ("postcode", postcode)],
    _ring,
    "User",
)
model.full_name, model.address, model.postcode = ciphertexts
```

### Laravel with Rust FFI

```php
use Syntek\Security\KeyRing;
use Syntek\Security\Encryption;

$ring = new KeyRing();
$ring->add(1, config('syntek.field_key'));

$ciphertext = Encryption::encryptField($plaintext, $ring, 'User', 'email');
$plaintext  = Encryption::decryptField($ciphertext, $ring, 'User', 'email');
```

### Direct Rust Usage

```rust
use syntek_crypto::{KeyRing, encrypt_field, decrypt_field};
use zeroize::Zeroizing;

let mut ring = KeyRing::new();
ring.add(1, &key_bytes)?;  // 32-byte key

let ciphertext = encrypt_field(plaintext.as_bytes(), &ring, "User", "email")?;

// Zeroize the decrypted output when done
let plaintext_bytes = Zeroizing::new(decrypt_field(&ciphertext, &ring, "User", "email")?);
```

### GraphQL Middleware Integration

A middleware layer can transparently decrypt fields marked with an `@encrypted`
directive so that resolvers return plaintext without explicit decrypt calls:

```python
# Strawberry GraphQL
@strawberry.type
class User:
    id: strawberry.ID
    email: str = strawberry.field(extensions=[Encrypted()])      # decrypted by middleware
    full_name: str = strawberry.field(extensions=[Encrypted()])  # decrypted by middleware
```

The middleware intercepts the resolver return value, identifies fields marked
`@encrypted`, and calls `decrypt_field` on each before returning the response
to the client.

---

## Nonce and IV Management

The nonce (Number Used Once) is critical to AES-GCM security. Nonce reuse with
the same key completely breaks confidentiality and authenticity guarantees.

**Rules:**

- Generate a fresh, random 96-bit nonce for every encryption operation using a
  CSPRNG (`OsRng` from the `rand` crate).
- Never reuse a nonce with the same key. Random 96-bit nonces provide a
  collision probability of approximately 2⁻³² after 2³² encryptions with the
  same key. For most applications, this is acceptable.
- If the application encrypts more than 2³² values with the same key, either
  rotate the key more frequently or switch to XChaCha20-Poly1305 with its
  192-bit nonce (collision probability ~2⁻⁹⁶ after 2³² encryptions).
- The nonce is not secret — it is stored alongside the ciphertext (see
  [Ciphertext Format](#ciphertext-format)).
- Never use a counter-based nonce in a multi-process or distributed environment.
  Use random nonces.

---

## Memory Safety

Sensitive data in memory is a risk if the process is compromised, swapped to
disk, or a core dump is triggered.

### Rust

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};
use secrecy::{Secret, ExposeSecret};

// Key material zeroized when dropped
#[derive(Zeroize, ZeroizeOnDrop)]
struct EncryptionKey {
    bytes: [u8; 32],
}

// Sensitive values wrapped in Secret — never printed or logged
let api_key: Secret<String> = Secret::new(raw_key_string);
let raw: &str = api_key.expose_secret();  // explicit, auditable access

// Decrypted output zeroized when out of scope
let plaintext = Zeroizing::new(decrypt_field(&ciphertext, &ring, "User", "email")?);
```

**Rules:**

- Derive `Zeroize` and `ZeroizeOnDrop` on all structs holding key material,
  plaintext, or decrypted data.
- Use `secrecy::Secret<T>` for key material that must not be accidentally logged
  or printed.
- Use `subtle::ConstantTimeEq` for HMAC verification and token comparison. Never
  use `==` on secrets.
- Avoid `String` for sensitive data where possible — `String` may leave copies
  in memory during reallocation. Use `Vec<u8>` with `Zeroize`.

### Python and PHP

Python and PHP runtimes do not guarantee memory zeroisation. Mitigations:

- Clear sensitive variables explicitly after use (`del variable` in Python,
  `unset($variable)` in PHP).
- Keep plaintext in scope for the minimum time necessary — decrypt, use, discard.
- The Rust layer handles key material in zeroised memory, limiting exposure in
  the host language to plaintext only.

---

## Migration Strategy

### New model (no existing data)

1. Add the encrypted column as `TEXT`, no `UNIQUE`, no index.
2. Add the token column as `VARCHAR(64)`, `UNIQUE`, indexed (if uniqueness is
   needed).
3. Application code encrypts on write and decrypts on read from the start.

### Existing model (backfilling encryption)

1. **Add columns:** add the encrypted column (`TEXT`, nullable) and the token
   column (`VARCHAR(64)`, nullable, no `UNIQUE` yet).
2. **Deploy:** deploy the code that writes to both old and new columns
   (dual-write).
3. **Backfill:** run a batched background job that reads each row, encrypts the
   plaintext, generates the token, and writes both new columns. Process in
   batches of 500–1,000 rows to avoid locking.
4. **Tighten constraints:** once all rows are backfilled, alter the token column
   to `NOT NULL` and add the `UNIQUE` constraint. Alter the encrypted column to
   `NOT NULL` if the field is required.
5. **Switch reads:** update application code to read from the encrypted column
   (via decrypt) instead of the old plaintext column.
6. **Remove old column:** drop the plaintext column in a subsequent migration.

**Rules:**

- Never store plaintext and ciphertext in the same column during migration. Use
  separate columns.
- The backfill job must be idempotent — running it twice on the same row
  produces the same result.
- Test the migration against a real database with production-like data volumes.
- For PostgreSQL: partial unique indexes exclude `NULL` values, so the `UNIQUE`
  constraint can be added before all rows are backfilled.

---

## Testing Encrypted Fields

### Test key setup

Use dedicated test keys — never production keys. Test keys should be hardcoded
in test configuration (not loaded from environment variables) so that tests are
deterministic and self-contained.

```rust
// In tests or test fixtures
const TEST_FEK: [u8; 32]  = [0xAA; 32];  // distinct from HMAC key
const TEST_HMAC: [u8; 32] = [0xBB; 32];

fn test_ring() -> KeyRing {
    let mut ring = KeyRing::new();
    ring.add(1, &TEST_FEK).unwrap();
    ring
}
```

### Required tests for every encrypted field

1. **Round-trip:** encrypt a value, decrypt it — verify the original plaintext
   is recovered.
2. **Different ciphertexts:** encrypt the same plaintext twice — verify the
   ciphertexts differ (random nonce).
3. **Tamper detection:** modify the ciphertext and attempt decryption — verify
   it fails with an authentication error.
4. **AAD binding:** encrypt for `Model.field_a`, attempt to decrypt as
   `Model.field_b` — verify it fails.
5. **Token consistency:** generate a token for the same input twice — verify the
   tokens are identical.
6. **Token uniqueness:** generate tokens for two different inputs — verify they
   differ.
7. **Lookup:** create a record, look it up by token — verify the record is found
   and the decrypted value matches.
8. **Key rotation:** encrypt with key version 1, add key version 2, decrypt the
   old ciphertext — verify it still works.

### Property-based testing with proptest

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn encrypt_decrypt_round_trip(plaintext in ".*") {
        let ring = test_ring();
        let ciphertext = encrypt_field(plaintext.as_bytes(), &ring, "Test", "field").unwrap();
        let result = decrypt_field(&ciphertext, &ring, "Test", "field").unwrap();
        prop_assert_eq!(result, plaintext.as_bytes());
    }

    #[test]
    fn same_plaintext_different_ciphertext(plaintext in ".+") {
        let ring = test_ring();
        let ct1 = encrypt_field(plaintext.as_bytes(), &ring, "Test", "field").unwrap();
        let ct2 = encrypt_field(plaintext.as_bytes(), &ring, "Test", "field").unwrap();
        prop_assert_ne!(ct1, ct2);
    }
}
```

---

## Encryption Checklist

When adding a new encrypted field to any model in any framework:

- [ ] Field uses a TEXT column — no `max_length`
- [ ] No `UNIQUE` constraint on the encrypted column
- [ ] No database index on the encrypted column
- [ ] If uniqueness required: companion `*_token` column added (`VARCHAR(64)`,
      `UNIQUE`, indexed)
- [ ] If lookups required: token computed on write, used in `WHERE` clauses
- [ ] Token generated with HMAC-SHA256 using the HMAC key (not the encryption
      key)
- [ ] Encryption key and HMAC key are different keys
- [ ] Both keys loaded from environment variables (or secrets manager),
      validated at startup
- [ ] Both keys are at least 32 bytes (256 bits)
- [ ] Encryption uses AES-256-GCM (or ChaCha20-Poly1305) with a random nonce
      per operation
- [ ] Ciphertext includes the key version for rotation support
- [ ] AAD includes model name and field name to prevent ciphertext replay
- [ ] 3+ encrypted fields on the same model use batch operations
- [ ] Migration follows the documented pattern (add nullable → backfill →
      tighten)
- [ ] Test keys are configured in test settings (separate from production)
- [ ] Round-trip, tamper detection, AAD binding, and token consistency tests
      written
- [ ] Rust key material uses `Zeroize` and `ZeroizeOnDrop`
- [ ] Constant-time comparison used for HMAC verification (`subtle::ConstantTimeEq`)
