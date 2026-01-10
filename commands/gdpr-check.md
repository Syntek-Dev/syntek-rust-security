# GDPR Check Command

## Table of Contents

- [Overview](#overview)
- [When to Use](#when-to-use)
- [What It Does](#what-it-does)
- [Parameters](#parameters)
- [Output](#output)
- [Examples](#examples)
- [Best Practices](#best-practices)
- [Related Commands](#related-commands)

---

## Overview

**Command:** `/rust-security:gdpr-check`

Analyzes Rust applications for GDPR (General Data Protection Regulation) compliance. Identifies personal data processing, validates consent mechanisms, audits data retention policies, and ensures proper data subject rights implementation (access, rectification, erasure, portability).

**Agent:** `rust-gdpr` (Opus - Legal/Regulatory Reasoning)

---

## When to Use

Use this command when:

- **Processing EU citizen data** - Ensure GDPR compliance before deployment
- **Implementing user data features** - Validate data handling practices
- **Pre-production compliance audit** - Final GDPR verification
- **After privacy policy changes** - Re-validate compliance
- **Data breach response** - Assess data protection measures
- **Regulatory audit preparation** - Generate compliance documentation

---

## What It Does

1. **Identifies personal data processing** in code and database schemas
2. **Validates consent mechanisms** for data collection and processing
3. **Audits data retention policies** and automatic deletion logic
4. **Verifies data subject rights** (access, rectification, erasure, portability)
5. **Checks encryption and pseudonymization** of personal data
6. **Analyzes third-party data sharing** and processor agreements
7. **Generates GDPR compliance report** with remediation steps

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--scope`          | string   | No       | `full`        | Scope: `full`, `data-mapping`, `rights`, `security` |
| `--output`         | string   | No       | `docs/compliance/GDPR-AUDIT.md` | Output file path |
| `--format`         | string   | No       | `markdown`    | Output format: `markdown`, `json`, `pdf`         |
| `--strict`         | boolean  | No       | `true`        | Fail on non-compliance issues                    |
| `--include-db`     | boolean  | No       | `true`        | Include database schema analysis                 |

---

## Output

### Console Output

```
🔒 Syntek Rust Security - GDPR Compliance Analysis

📦 Project: user-platform v2.1.0
🌍 Jurisdiction: EU (GDPR applicable)
📊 Personal data fields identified: 47

┌─────────────────────────────────────────────────────────────┐
│ GDPR Compliance Status                                      │
├─────────────────────────────────────────────────────────────┤
│ ✅ Article 6: Lawful basis for processing                   │
│ ✅ Article 7: Consent mechanisms                            │
│ ⚠️  Article 15: Right to access (partial implementation)    │
│ ✅ Article 16: Right to rectification                       │
│ ❌ Article 17: Right to erasure (NOT IMPLEMENTED)           │
│ ⚠️  Article 20: Right to data portability (incomplete)      │
│ ✅ Article 25: Data protection by design and default        │
│ ✅ Article 32: Security of processing                       │
│ ⚠️  Article 33: Breach notification (72h requirement)       │
└─────────────────────────────────────────────────────────────┘

🔍 Personal Data Inventory:

Identified in code:
  - src/models/user.rs: email, name, phone, address
  - src/models/profile.rs: date_of_birth, gender, preferences
  - src/analytics/tracker.rs: ip_address, user_agent, session_id

Database tables:
  - users: 12 PII fields
  - user_preferences: 8 PII fields
  - audit_logs: 5 PII fields

❌ Critical Non-Compliance Issues:

1. Right to Erasure (Art. 17) - NOT IMPLEMENTED
   - Location: No user deletion endpoint found
   - Impact: HIGH - Legal requirement violation
   - Recommendation: Implement DELETE /users/:id with cascade

2. Data Retention (Art. 5.1e) - MISSING POLICY
   - Location: No automatic deletion logic
   - Impact: MEDIUM - Violates storage limitation principle
   - Recommendation: Implement TTL and scheduled cleanup

3. Consent Withdrawal (Art. 7.3) - INCOMPLETE
   - Location: src/consent/mod.rs
   - Impact: HIGH - Users cannot withdraw consent easily
   - Recommendation: Add consent revocation API

📝 Detailed report: docs/compliance/GDPR-AUDIT.md
```

### Generated Documentation

Creates GDPR compliance package:

- **GDPR-AUDIT.md** - Complete compliance assessment
- **DATA-INVENTORY.json** - Personal data mapping
- **PRIVACY-IMPACT-ASSESSMENT.pdf** - DPIA template
- **DATA-SUBJECT-RIGHTS.md** - Implementation guide
- **PROCESSOR-AGREEMENTS.md** - Third-party processor checklist

---

## Examples

### Example 1: Full GDPR Audit

```bash
/rust-security:gdpr-check
```

Performs comprehensive GDPR compliance analysis.

### Example 2: Data Mapping Only

```bash
/rust-security:gdpr-check --scope=data-mapping --format=json
```

Generates JSON data inventory mapping all personal data fields.

### Example 3: Data Subject Rights Verification

```bash
/rust-security:gdpr-check --scope=rights
```

Validates implementation of GDPR data subject rights.

### Example 4: Security Measures Assessment

```bash
/rust-security:gdpr-check --scope=security --strict=true
```

Audits technical and organizational security measures (Article 32).

### Example 5: Database Schema Analysis

```bash
/rust-security:gdpr-check --include-db=true --output=db-gdpr-audit.md
```

Analyzes database schema for GDPR compliance.

---

## Best Practices

### GDPR Principles (Article 5)

1. **Lawfulness, fairness, transparency** - Clear consent and privacy notices
2. **Purpose limitation** - Process data only for stated purposes
3. **Data minimization** - Collect only necessary data
4. **Accuracy** - Keep personal data accurate and up-to-date
5. **Storage limitation** - Delete data when no longer needed
6. **Integrity and confidentiality** - Secure data processing
7. **Accountability** - Demonstrate compliance

### Implementing Data Subject Rights

**Right to Access (Article 15)**
```rust
#[get("/users/{id}/data-export")]
async fn export_user_data(
    user_id: Path<Uuid>,
    auth: AuthToken,
) -> Result<Json<UserDataExport>, ApiError> {
    // Verify user authorization
    if auth.user_id != *user_id {
        return Err(ApiError::Unauthorized);
    }

    // Collect all personal data
    let user_data = UserDataExport {
        profile: db.get_user_profile(*user_id).await?,
        preferences: db.get_preferences(*user_id).await?,
        history: db.get_user_history(*user_id).await?,
        consent_records: db.get_consents(*user_id).await?,
    };

    Ok(Json(user_data))
}
```

**Right to Erasure (Article 17)**
```rust
#[delete("/users/{id}")]
async fn delete_user_account(
    user_id: Path<Uuid>,
    auth: AuthToken,
) -> Result<StatusCode, ApiError> {
    // Verify authorization
    if auth.user_id != *user_id && !auth.is_admin {
        return Err(ApiError::Unauthorized);
    }

    // Cascade deletion of all personal data
    db.transaction(|tx| async move {
        tx.delete_user_profile(*user_id).await?;
        tx.delete_preferences(*user_id).await?;
        tx.anonymize_audit_logs(*user_id).await?; // Keep for legal requirements
        tx.delete_sessions(*user_id).await?;
        tx.revoke_consents(*user_id).await?;
        Ok(())
    }).await?;

    // Log deletion for accountability
    audit_log::record_deletion(*user_id, "user_requested").await?;

    Ok(StatusCode::NO_CONTENT)
}
```

**Right to Data Portability (Article 20)**
```rust
#[get("/users/{id}/data-export.json")]
async fn export_portable_data(
    user_id: Path<Uuid>,
    auth: AuthToken,
) -> Result<Json<Value>, ApiError> {
    // Export in machine-readable format (JSON)
    let portable_data = json!({
        "personal_info": db.get_user_profile(*user_id).await?,
        "preferences": db.get_preferences(*user_id).await?,
        "created_content": db.get_user_content(*user_id).await?,
        "export_date": chrono::Utc::now(),
        "format_version": "1.0",
    });

    Ok(Json(portable_data))
}
```

### Consent Management

```rust
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize)]
pub struct Consent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub purpose: ConsentPurpose,
    pub granted: bool,
    pub timestamp: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ConsentPurpose {
    Marketing,
    Analytics,
    ThirdPartySharing,
    ProfileEnrichment,
}

impl Consent {
    /// Record consent with audit trail (Article 7)
    pub async fn record(
        user_id: Uuid,
        purpose: ConsentPurpose,
        granted: bool,
        context: &RequestContext,
    ) -> Result<Self, DbError> {
        let consent = Self {
            id: Uuid::new_v4(),
            user_id,
            purpose,
            granted,
            timestamp: Utc::now(),
            ip_address: Some(context.ip_address.clone()),
            user_agent: Some(context.user_agent.clone()),
        };

        db.insert_consent(&consent).await?;
        Ok(consent)
    }

    /// Withdraw consent (Article 7.3)
    pub async fn withdraw(user_id: Uuid, purpose: ConsentPurpose) -> Result<(), DbError> {
        db.revoke_consent(user_id, purpose).await?;

        // Stop processing immediately
        processing::halt_for_purpose(user_id, purpose).await?;

        Ok(())
    }
}
```

### Data Retention Policies

```rust
/// Automatic data deletion based on retention policy (Article 5.1e)
#[tokio::main]
async fn scheduled_data_cleanup() {
    let retention_policies = vec![
        ("user_sessions", Duration::days(30)),
        ("analytics_events", Duration::days(90)),
        ("audit_logs", Duration::days(365 * 7)), // 7 years for legal compliance
        ("deleted_users", Duration::days(30)), // Grace period for account recovery
    ];

    for (table, retention_period) in retention_policies {
        let cutoff_date = Utc::now() - retention_period;

        match db.delete_old_records(table, cutoff_date).await {
            Ok(count) => info!("Deleted {} old records from {}", count, table),
            Err(e) => error!("Failed to delete old records from {}: {}", table, e),
        }
    }
}
```

### Encryption and Pseudonymization

```rust
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

/// Encrypt personal data at rest (Article 32)
pub fn encrypt_personal_data(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, key)?;
    let key = LessSafeKey::new(unbound_key);

    let nonce = generate_nonce();
    let mut ciphertext = plaintext.to_vec();

    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::empty(),
        &mut ciphertext,
    )?;

    Ok(ciphertext)
}

/// Pseudonymize user identifiers (Article 25)
pub fn pseudonymize_user_id(user_id: Uuid, pepper: &[u8]) -> String {
    use ring::digest;

    let mut context = digest::Context::new(&digest::SHA256);
    context.update(user_id.as_bytes());
    context.update(pepper);

    let digest = context.finish();
    hex::encode(digest.as_ref())
}
```

---

## Related Commands

- **[/rust-security:compliance-report](compliance-report.md)** - Generate compliance reports
- **[/rust-security:scan-secrets](scan-secrets.md)** - Detect exposed personal data
- **[/rust-security:crypto-review](crypto-review.md)** - Review encryption implementation
- **[/rust-security:review-code](review-code.md)** - Code review including GDPR compliance

---

**Note:** This command uses Opus model for legal/regulatory reasoning. GDPR compliance requires ongoing monitoring and legal review. Consult legal counsel for definitive compliance guidance.
