# Rust Certificate Rotator Template

## Overview

This template provides automated certificate rotation for Cloudflare Origin/Edge
certificates with secure storage in HashiCorp Vault. It handles certificate
lifecycle management, renewal, and distribution.

**Target Use Cases:**

- Automated Origin certificate rotation
- Edge certificate management
- Certificate storage in Vault
- Renewal notifications
- Multi-domain certificate handling

## Project Structure

```
my-cert-rotator/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── cloudflare/
│   │   ├── mod.rs
│   │   └── certificates.rs
│   ├── vault/
│   │   ├── mod.rs
│   │   └── pki.rs
│   ├── rotator.rs
│   ├── scheduler.rs
│   └── error.rs
├── config/
│   └── rotator.toml
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-cert-rotator"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"

[dependencies]
tokio = { version = "1.40", features = ["full"] }
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
vaultrs = "0.7"
serde = { version = "1.0", features = ["derive"] }
secrecy = { version = "0.10", features = ["serde"] }
zeroize = { version = "1.8", features = ["derive"] }
chrono = { version = "0.4", features = ["serde"] }
cron = "0.12"
thiserror = "2.0"
tracing = "0.1"
tracing-subscriber = "0.3"
clap = { version = "4.5", features = ["derive"] }
toml = "0.8"
```

## Core Implementation

### src/rotator.rs

```rust
use chrono::{DateTime, Utc, Duration};
use secrecy::Secret;
use tracing::{info, warn, error};
use crate::cloudflare::CertificateClient;
use crate::vault::VaultCertStore;
use crate::error::RotatorError;

pub struct CertificateRotator {
    cloudflare: CertificateClient,
    vault: VaultCertStore,
    renewal_threshold_days: i64,
}

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub id: String,
    pub hostnames: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub certificate: String,
    pub private_key: Secret<String>,
}

impl CertificateRotator {
    pub fn new(
        cloudflare: CertificateClient,
        vault: VaultCertStore,
        renewal_threshold_days: i64,
    ) -> Self {
        Self {
            cloudflare,
            vault,
            renewal_threshold_days,
        }
    }

    pub async fn check_and_rotate(&self, hostnames: &[String]) -> Result<Option<CertificateInfo>, RotatorError> {
        // Get current certificate from Vault
        let current = self.vault.get_certificate(hostnames).await?;

        let needs_rotation = match &current {
            Some(cert) => {
                let days_until_expiry = (cert.expires_at - Utc::now()).num_days();
                days_until_expiry <= self.renewal_threshold_days
            }
            None => true,
        };

        if needs_rotation {
            info!(hostnames = ?hostnames, "Certificate needs rotation");
            let new_cert = self.rotate(hostnames).await?;
            return Ok(Some(new_cert));
        }

        info!(hostnames = ?hostnames, "Certificate still valid");
        Ok(None)
    }

    pub async fn rotate(&self, hostnames: &[String]) -> Result<CertificateInfo, RotatorError> {
        // Request new certificate from Cloudflare
        let new_cert = self.cloudflare
            .create_origin_certificate(hostnames, 365)
            .await?;

        info!(
            hostnames = ?hostnames,
            cert_id = %new_cert.id,
            expires = %new_cert.expires_at,
            "Created new certificate"
        );

        // Store in Vault
        self.vault.store_certificate(&new_cert).await?;

        info!(hostnames = ?hostnames, "Stored certificate in Vault");

        // Revoke old certificate if exists
        if let Ok(Some(old_cert)) = self.vault.get_previous_certificate(hostnames).await {
            if let Err(e) = self.cloudflare.revoke_certificate(&old_cert.id).await {
                warn!(cert_id = %old_cert.id, error = %e, "Failed to revoke old certificate");
            }
        }

        Ok(new_cert)
    }

    pub async fn get_certificate(&self, hostnames: &[String]) -> Result<Option<CertificateInfo>, RotatorError> {
        self.vault.get_certificate(hostnames).await
    }
}
```

### src/vault/pki.rs

```rust
use secrecy::{ExposeSecret, Secret};
use vaultrs::client::VaultClient;
use vaultrs::kv2;
use std::collections::HashMap;
use crate::rotator::CertificateInfo;
use crate::error::RotatorError;

pub struct VaultCertStore {
    client: VaultClient,
    mount: String,
}

impl VaultCertStore {
    pub fn new(client: VaultClient, mount: &str) -> Self {
        Self {
            client,
            mount: mount.to_string(),
        }
    }

    pub async fn store_certificate(&self, cert: &CertificateInfo) -> Result<(), RotatorError> {
        let path = self.cert_path(&cert.hostnames);

        let mut data = HashMap::new();
        data.insert("id".to_string(), cert.id.clone());
        data.insert("certificate".to_string(), cert.certificate.clone());
        data.insert("private_key".to_string(), cert.private_key.expose_secret().clone());
        data.insert("expires_at".to_string(), cert.expires_at.to_rfc3339());
        data.insert("hostnames".to_string(), cert.hostnames.join(","));

        kv2::set(&self.client, &self.mount, &path, &data)
            .await
            .map_err(|e| RotatorError::VaultError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_certificate(&self, hostnames: &[String]) -> Result<Option<CertificateInfo>, RotatorError> {
        let path = self.cert_path(hostnames);

        let data: HashMap<String, String> = match kv2::read(&self.client, &self.mount, &path).await {
            Ok(d) => d,
            Err(_) => return Ok(None),
        };

        let cert = CertificateInfo {
            id: data.get("id").cloned().unwrap_or_default(),
            hostnames: data.get("hostnames")
                .map(|h| h.split(',').map(String::from).collect())
                .unwrap_or_default(),
            expires_at: data.get("expires_at")
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(chrono::Utc::now),
            certificate: data.get("certificate").cloned().unwrap_or_default(),
            private_key: Secret::new(data.get("private_key").cloned().unwrap_or_default()),
        };

        Ok(Some(cert))
    }

    pub async fn get_previous_certificate(&self, hostnames: &[String]) -> Result<Option<CertificateInfo>, RotatorError> {
        let path = format!("{}/previous", self.cert_path(hostnames));

        let data: HashMap<String, String> = match kv2::read(&self.client, &self.mount, &path).await {
            Ok(d) => d,
            Err(_) => return Ok(None),
        };

        Ok(Some(CertificateInfo {
            id: data.get("id").cloned().unwrap_or_default(),
            hostnames: hostnames.to_vec(),
            expires_at: chrono::Utc::now(),
            certificate: String::new(),
            private_key: Secret::new(String::new()),
        }))
    }

    fn cert_path(&self, hostnames: &[String]) -> String {
        let key = hostnames.join("_").replace("*", "wildcard").replace(".", "-");
        format!("certificates/{}", key)
    }
}
```

## Security Checklist

- [ ] Private keys never logged
- [ ] Vault access properly authenticated
- [ ] Old certificates revoked after rotation
- [ ] Rotation events audited
- [ ] Notifications on rotation failure
- [ ] Renewal threshold appropriate (30+ days)
- [ ] Certificate chain validated
