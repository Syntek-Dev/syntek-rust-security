# Rust HashiCorp Vault Integration Skills

This skill provides secure patterns for integrating Rust applications with
HashiCorp Vault for secret management, encryption as a service, and dynamic
credentials.

## Overview

HashiCorp Vault integration enables:

- **Secret Storage**: Secure key-value storage
- **Dynamic Secrets**: Database credentials, cloud provider keys
- **Encryption as a Service**: Transit secrets engine
- **PKI**: Certificate management
- **Authentication**: Multiple auth methods (AppRole, Kubernetes, JWT)

## /vault-setup

Set up HashiCorp Vault integration in a Rust project.

### Usage

```bash
/vault-setup
```

### What It Does

1. Adds vaultrs dependency to Cargo.toml
2. Creates Vault client configuration module
3. Sets up authentication method
4. Implements secret retrieval patterns
5. Adds error handling and retry logic
6. Creates integration tests

---

## Vault Client Configuration

### Basic Client Setup

```rust
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use std::env;

pub struct VaultConfig {
    pub address: String,
    pub namespace: Option<String>,
    pub token: Option<String>,
}

impl VaultConfig {
    pub fn from_env() -> Self {
        Self {
            address: env::var("VAULT_ADDR")
                .unwrap_or_else(|_| "https://vault.example.com:8200".to_string()),
            namespace: env::var("VAULT_NAMESPACE").ok(),
            token: env::var("VAULT_TOKEN").ok(),
        }
    }
}

pub fn create_vault_client(config: &VaultConfig) -> Result<VaultClient, Error> {
    let mut settings = VaultClientSettingsBuilder::default()
        .address(&config.address)
        .verify(true);  // Always verify TLS

    if let Some(ns) = &config.namespace {
        settings = settings.namespace(ns);
    }

    if let Some(token) = &config.token {
        settings = settings.token(token);
    }

    settings
        .build()
        .map(VaultClient::new)
        .map_err(Error::VaultConfig)
}
```

### TLS Configuration

```rust
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use reqwest::Certificate;
use std::fs;

pub fn create_vault_client_with_tls(
    address: &str,
    ca_cert_path: &str,
) -> Result<VaultClient, Error> {
    // Load CA certificate
    let ca_cert = fs::read(ca_cert_path)
        .map_err(|e| Error::CertificateLoad(e.to_string()))?;
    let ca_cert = Certificate::from_pem(&ca_cert)
        .map_err(|e| Error::CertificateParse(e.to_string()))?;

    let http_client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .build()
        .map_err(|e| Error::HttpClient(e.to_string()))?;

    let settings = VaultClientSettingsBuilder::default()
        .address(address)
        .build()
        .map_err(Error::VaultConfig)?;

    Ok(VaultClient::new_with_client(settings, http_client))
}
```

---

## Authentication Methods

### AppRole Authentication

```rust
use vaultrs::auth::approle;

pub struct AppRoleAuth {
    pub role_id: String,
    pub secret_id: zeroize::Zeroizing<String>,
}

impl AppRoleAuth {
    pub fn from_env() -> Result<Self, Error> {
        Ok(Self {
            role_id: env::var("VAULT_ROLE_ID")
                .map_err(|_| Error::MissingEnvVar("VAULT_ROLE_ID"))?,
            secret_id: zeroize::Zeroizing::new(
                env::var("VAULT_SECRET_ID")
                    .map_err(|_| Error::MissingEnvVar("VAULT_SECRET_ID"))?
            ),
        })
    }
}

pub async fn authenticate_approle(
    client: &VaultClient,
    auth: &AppRoleAuth,
) -> Result<String, Error> {
    let response = approle::login(
        client,
        "approle",  // mount path
        &auth.role_id,
        &auth.secret_id,
    )
    .await
    .map_err(Error::VaultAuth)?;

    Ok(response.client_token)
}
```

### Kubernetes Authentication

```rust
use vaultrs::auth::kubernetes;
use std::fs;

const SERVICE_ACCOUNT_TOKEN_PATH: &str =
    "/var/run/secrets/kubernetes.io/serviceaccount/token";

pub async fn authenticate_kubernetes(
    client: &VaultClient,
    role: &str,
) -> Result<String, Error> {
    // Read Kubernetes service account token
    let jwt = fs::read_to_string(SERVICE_ACCOUNT_TOKEN_PATH)
        .map_err(|e| Error::KubernetesToken(e.to_string()))?;

    let response = kubernetes::login(
        client,
        "kubernetes",  // mount path
        role,
        &jwt,
    )
    .await
    .map_err(Error::VaultAuth)?;

    Ok(response.client_token)
}
```

### JWT/OIDC Authentication

```rust
use vaultrs::auth::oidc;

pub async fn authenticate_jwt(
    client: &VaultClient,
    role: &str,
    jwt: &str,
) -> Result<String, Error> {
    let response = oidc::login(
        client,
        "jwt",  // mount path
        role,
        jwt,
    )
    .await
    .map_err(Error::VaultAuth)?;

    Ok(response.client_token)
}
```

---

## Secret Retrieval

### KV Version 2 (Recommended)

```rust
use vaultrs::kv2;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct DatabaseCredentials {
    pub username: String,
    pub password: String,
    pub host: String,
    pub port: u16,
}

pub async fn get_database_credentials(
    client: &VaultClient,
    path: &str,
) -> Result<DatabaseCredentials, Error> {
    kv2::read::<DatabaseCredentials>(client, "secret", path)
        .await
        .map_err(Error::VaultRead)
}

// With specific version
pub async fn get_credentials_version(
    client: &VaultClient,
    path: &str,
    version: u64,
) -> Result<DatabaseCredentials, Error> {
    kv2::read_version::<DatabaseCredentials>(client, "secret", path, version)
        .await
        .map_err(Error::VaultRead)
}
```

### Writing Secrets

```rust
use vaultrs::kv2;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize)]
pub struct ApiCredentials {
    pub api_key: String,
    pub api_secret: String,
}

pub async fn store_api_credentials(
    client: &VaultClient,
    path: &str,
    credentials: &ApiCredentials,
) -> Result<(), Error> {
    kv2::set(client, "secret", path, credentials)
        .await
        .map_err(Error::VaultWrite)
}

// With metadata
pub async fn store_with_metadata(
    client: &VaultClient,
    path: &str,
    credentials: &ApiCredentials,
    custom_metadata: HashMap<String, String>,
) -> Result<(), Error> {
    // Store secret
    kv2::set(client, "secret", path, credentials)
        .await
        .map_err(Error::VaultWrite)?;

    // Update metadata
    kv2::set_metadata(client, "secret", path, Some(&custom_metadata))
        .await
        .map_err(Error::VaultWrite)
}
```

---

## Transit Secrets Engine (Encryption as a Service)

### Encrypt Data

```rust
use vaultrs::transit;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

pub async fn encrypt_data(
    client: &VaultClient,
    key_name: &str,
    plaintext: &[u8],
) -> Result<String, Error> {
    let encoded = BASE64.encode(plaintext);

    let ciphertext = transit::encrypt(
        client,
        "transit",  // mount path
        key_name,
        &encoded,
        None,  // additional options
    )
    .await
    .map_err(Error::VaultTransit)?;

    Ok(ciphertext)
}

pub async fn decrypt_data(
    client: &VaultClient,
    key_name: &str,
    ciphertext: &str,
) -> Result<Vec<u8>, Error> {
    let plaintext_b64 = transit::decrypt(
        client,
        "transit",
        key_name,
        ciphertext,
        None,
    )
    .await
    .map_err(Error::VaultTransit)?;

    BASE64.decode(&plaintext_b64)
        .map_err(|e| Error::Base64Decode(e.to_string()))
}
```

### Key Rotation

```rust
use vaultrs::transit;

pub async fn rotate_encryption_key(
    client: &VaultClient,
    key_name: &str,
) -> Result<(), Error> {
    transit::rotate(client, "transit", key_name)
        .await
        .map_err(Error::VaultTransit)
}

pub async fn rewrap_data(
    client: &VaultClient,
    key_name: &str,
    ciphertext: &str,
) -> Result<String, Error> {
    // Re-encrypt with latest key version without exposing plaintext
    transit::rewrap(client, "transit", key_name, ciphertext, None)
        .await
        .map_err(Error::VaultTransit)
}
```

### Batch Operations

```rust
use vaultrs::transit;

pub async fn encrypt_batch(
    client: &VaultClient,
    key_name: &str,
    items: Vec<&[u8]>,
) -> Result<Vec<String>, Error> {
    let batch_input: Vec<_> = items
        .iter()
        .map(|data| transit::BatchInput {
            plaintext: Some(BASE64.encode(data)),
            ..Default::default()
        })
        .collect();

    let results = transit::encrypt_batch(
        client,
        "transit",
        key_name,
        batch_input,
        None,
    )
    .await
    .map_err(Error::VaultTransit)?;

    Ok(results.into_iter().map(|r| r.ciphertext).collect())
}
```

---

## Dynamic Secrets

### Database Credentials

```rust
use vaultrs::database;
use std::time::Duration;

#[derive(Debug)]
pub struct DynamicCredentials {
    pub username: String,
    pub password: zeroize::Zeroizing<String>,
    pub lease_id: String,
    pub lease_duration: Duration,
}

pub async fn get_dynamic_db_credentials(
    client: &VaultClient,
    role: &str,
) -> Result<DynamicCredentials, Error> {
    let creds = database::creds(client, "database", role)
        .await
        .map_err(Error::VaultDatabase)?;

    Ok(DynamicCredentials {
        username: creds.username,
        password: zeroize::Zeroizing::new(creds.password),
        lease_id: creds.lease_id,
        lease_duration: Duration::from_secs(creds.lease_duration as u64),
    })
}

pub async fn renew_lease(
    client: &VaultClient,
    lease_id: &str,
) -> Result<Duration, Error> {
    let response = vaultrs::sys::lease::renew(client, lease_id, None)
        .await
        .map_err(Error::VaultLease)?;

    Ok(Duration::from_secs(response.lease_duration as u64))
}

pub async fn revoke_lease(
    client: &VaultClient,
    lease_id: &str,
) -> Result<(), Error> {
    vaultrs::sys::lease::revoke(client, lease_id)
        .await
        .map_err(Error::VaultLease)
}
```

### AWS Dynamic Credentials

```rust
use vaultrs::aws;

#[derive(Debug)]
pub struct AwsCredentials {
    pub access_key: String,
    pub secret_key: zeroize::Zeroizing<String>,
    pub security_token: Option<String>,
    pub lease_id: String,
}

pub async fn get_aws_credentials(
    client: &VaultClient,
    role: &str,
) -> Result<AwsCredentials, Error> {
    let creds = aws::roles::credentials(client, "aws", role)
        .await
        .map_err(Error::VaultAws)?;

    Ok(AwsCredentials {
        access_key: creds.access_key,
        secret_key: zeroize::Zeroizing::new(creds.secret_key),
        security_token: creds.security_token,
        lease_id: creds.lease_id,
    })
}
```

---

## PKI (Certificate Management)

### Issue Certificate

```rust
use vaultrs::pki;

#[derive(Debug)]
pub struct IssuedCertificate {
    pub certificate: String,
    pub private_key: zeroize::Zeroizing<String>,
    pub ca_chain: Vec<String>,
    pub serial_number: String,
}

pub async fn issue_certificate(
    client: &VaultClient,
    role: &str,
    common_name: &str,
    ttl: &str,
) -> Result<IssuedCertificate, Error> {
    let cert = pki::issue(
        client,
        "pki",  // mount path
        role,
        common_name,
        Some(pki::IssueOptions {
            ttl: Some(ttl.to_string()),
            ..Default::default()
        }),
    )
    .await
    .map_err(Error::VaultPki)?;

    Ok(IssuedCertificate {
        certificate: cert.certificate,
        private_key: zeroize::Zeroizing::new(cert.private_key),
        ca_chain: cert.ca_chain,
        serial_number: cert.serial_number,
    })
}
```

### Revoke Certificate

```rust
pub async fn revoke_certificate(
    client: &VaultClient,
    serial_number: &str,
) -> Result<(), Error> {
    pki::revoke(client, "pki", serial_number)
        .await
        .map_err(Error::VaultPki)
}
```

---

## Token Management

### Token Renewal

```rust
use vaultrs::token;
use std::time::Duration;
use tokio::time::interval;

pub async fn start_token_renewal(
    client: VaultClient,
    renewal_interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(renewal_interval);

        loop {
            ticker.tick().await;

            match token::renew_self(&client, None).await {
                Ok(response) => {
                    tracing::info!(
                        "Token renewed, new TTL: {}s",
                        response.auth.lease_duration
                    );
                }
                Err(e) => {
                    tracing::error!("Failed to renew token: {}", e);
                    // Consider re-authentication here
                }
            }
        }
    })
}
```

---

## Error Handling

### Comprehensive Error Type

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Vault configuration error: {0}")]
    Config(String),

    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("Secret not found: {0}")]
    NotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Vault connection error: {0}")]
    Connection(String),

    #[error("Invalid secret format: {0}")]
    InvalidFormat(String),

    #[error("Lease expired: {0}")]
    LeaseExpired(String),

    #[error("Rate limited: retry after {0}s")]
    RateLimited(u64),
}

impl From<vaultrs::error::ClientError> for VaultError {
    fn from(err: vaultrs::error::ClientError) -> Self {
        match err {
            vaultrs::error::ClientError::APIError { code, .. } if code == 404 => {
                VaultError::NotFound(err.to_string())
            }
            vaultrs::error::ClientError::APIError { code, .. } if code == 403 => {
                VaultError::PermissionDenied(err.to_string())
            }
            _ => VaultError::Connection(err.to_string()),
        }
    }
}
```

### Retry Logic

```rust
use std::time::Duration;
use tokio::time::sleep;

pub async fn with_retry<T, F, Fut>(
    mut operation: F,
    max_retries: u32,
    initial_delay: Duration,
) -> Result<T, VaultError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, VaultError>>,
{
    let mut delay = initial_delay;

    for attempt in 0..max_retries {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(VaultError::RateLimited(wait)) => {
                tracing::warn!("Rate limited, waiting {}s", wait);
                sleep(Duration::from_secs(wait)).await;
            }
            Err(VaultError::Connection(_)) if attempt < max_retries - 1 => {
                tracing::warn!("Connection error, retrying in {:?}", delay);
                sleep(delay).await;
                delay *= 2;  // Exponential backoff
            }
            Err(e) => return Err(e),
        }
    }

    Err(VaultError::Connection("Max retries exceeded".to_string()))
}
```

---

## Security Best Practices

### 1. Never Log Secrets

```rust
use tracing::instrument;

#[instrument(skip(client, credentials))]
pub async fn store_credentials(
    client: &VaultClient,
    path: &str,
    credentials: &Credentials,
) -> Result<(), Error> {
    // Secrets are automatically excluded from traces
    kv2::set(client, "secret", path, credentials).await?;
    tracing::info!("Stored credentials at {}", path);
    Ok(())
}
```

### 2. Use Short-Lived Tokens

```rust
// Configure short TTL and wrap in renewal task
pub async fn create_short_lived_client(
    config: &VaultConfig,
) -> Result<(VaultClient, tokio::task::JoinHandle<()>), Error> {
    let client = create_vault_client(config)?;

    // Request token with short TTL
    let auth = AppRoleAuth::from_env()?;
    authenticate_approle(&client, &auth).await?;

    // Start renewal task
    let renewal_handle = start_token_renewal(
        client.clone(),
        Duration::from_secs(300),  // Renew every 5 minutes
    ).await;

    Ok((client, renewal_handle))
}
```

### 3. Zeroize All Secrets

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretData {
    api_key: String,
    api_secret: String,
}

// Secrets are automatically zeroized when dropped
```

---

## Vault Security Checklist

- [ ] TLS verification enabled
- [ ] Short-lived tokens with renewal
- [ ] Appropriate authentication method (AppRole, K8s, JWT)
- [ ] Least-privilege policies
- [ ] Secrets zeroized after use
- [ ] No secrets in logs
- [ ] Connection retry logic
- [ ] Lease renewal for dynamic secrets
- [ ] Audit logging enabled in Vault

## Recommended Crates

- **vaultrs**: Async Vault client
- **zeroize**: Secure memory clearing
- **tokio**: Async runtime
- **tracing**: Logging/tracing
- **thiserror**: Error types
- **serde**: Serialization

## Integration Points

This skill works well with:

- `/encrypt-setup` - Use Transit engine for encryption
- `/cert-rotate` - Use PKI engine for certificates
- `/token-rotate` - Automate secret rotation
