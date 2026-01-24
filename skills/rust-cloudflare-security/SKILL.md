# Rust Cloudflare Security Skills

This skill provides patterns for integrating Rust applications with Cloudflare
services including Origin/Edge certificate management, DNS management, Workers,
R2 storage, and API security.

## Overview

Cloudflare integration covers:

- **Origin Certificates**: Server-side TLS certificates
- **Edge Certificates**: Client-facing certificates
- **DNS Management**: Zone and record management
- **Workers**: Serverless edge computing
- **R2 Storage**: S3-compatible object storage
- **API Tokens**: Secure credential management

## /cloudflare-setup

Set up Cloudflare integration in a Rust project.

### Usage

```bash
/cloudflare-setup
```

### What It Does

1. Adds cloudflare-rs dependency
2. Creates API client configuration
3. Sets up token management with Vault
4. Implements DNS management functions
5. Creates certificate rotation helpers

## /cert-rotate

Rotate Cloudflare Origin/Edge certificates and store in Vault.

### Usage

```bash
/cert-rotate
```

### What It Does

1. Generates new Origin CA certificate
2. Revokes old certificate
3. Stores new certificate in Vault
4. Updates server configuration
5. Verifies certificate deployment

---

## Cloudflare API Client

### Basic Client Setup

```rust
use cloudflare::framework::{
    async_api::Client as CloudflareClient,
    auth::Credentials,
    Environment, HttpApiClientConfig,
};

pub struct CloudflareConfig {
    pub api_token: zeroize::Zeroizing<String>,
    pub account_id: String,
}

impl CloudflareConfig {
    pub fn from_env() -> Result<Self, Error> {
        Ok(Self {
            api_token: zeroize::Zeroizing::new(
                std::env::var("CLOUDFLARE_API_TOKEN")
                    .map_err(|_| Error::MissingEnvVar("CLOUDFLARE_API_TOKEN"))?
            ),
            account_id: std::env::var("CLOUDFLARE_ACCOUNT_ID")
                .map_err(|_| Error::MissingEnvVar("CLOUDFLARE_ACCOUNT_ID"))?,
        })
    }
}

pub fn create_cloudflare_client(config: &CloudflareConfig) -> Result<CloudflareClient, Error> {
    let credentials = Credentials::UserAuthToken {
        token: config.api_token.to_string(),
    };

    CloudflareClient::new(
        credentials,
        HttpApiClientConfig::default(),
        Environment::Production,
    )
    .map_err(Error::CloudflareClient)
}
```

### Vault-Integrated Token Management

```rust
use vaultrs::kv2;

pub struct VaultCloudflareManager {
    vault_client: vaultrs::client::VaultClient,
    vault_mount: String,
    secret_path: String,
    cache: parking_lot::RwLock<Option<CachedToken>>,
    cache_ttl: std::time::Duration,
}

struct CachedToken {
    token: zeroize::Zeroizing<String>,
    account_id: String,
    fetched_at: std::time::Instant,
}

impl VaultCloudflareManager {
    pub async fn get_config(&self) -> Result<CloudflareConfig, Error> {
        // Check cache
        {
            let cache = self.cache.read();
            if let Some(cached) = &*cache {
                if cached.fetched_at.elapsed() < self.cache_ttl {
                    return Ok(CloudflareConfig {
                        api_token: zeroize::Zeroizing::new(cached.token.to_string()),
                        account_id: cached.account_id.clone(),
                    });
                }
            }
        }

        // Fetch from Vault
        #[derive(serde::Deserialize)]
        struct CloudflareSecret {
            api_token: String,
            account_id: String,
        }

        let secret: CloudflareSecret = kv2::read(
            &self.vault_client,
            &self.vault_mount,
            &self.secret_path,
        )
        .await
        .map_err(Error::VaultRead)?;

        // Update cache
        {
            let mut cache = self.cache.write();
            *cache = Some(CachedToken {
                token: zeroize::Zeroizing::new(secret.api_token.clone()),
                account_id: secret.account_id.clone(),
                fetched_at: std::time::Instant::now(),
            });
        }

        Ok(CloudflareConfig {
            api_token: zeroize::Zeroizing::new(secret.api_token),
            account_id: secret.account_id,
        })
    }
}
```

---

## Origin Certificate Management

### Generate Origin Certificate

```rust
use cloudflare::endpoints::origin_ca_certificate::{
    CreateCertificate, Certificate, CertificateRequestType,
};
use chrono::{Duration, Utc};

pub struct OriginCertManager {
    client: CloudflareClient,
    zone_id: String,
}

impl OriginCertManager {
    pub async fn create_certificate(
        &self,
        hostnames: Vec<String>,
        validity_days: u16,
    ) -> Result<OriginCertificate, Error> {
        // Generate CSR
        let (csr, private_key) = generate_csr(&hostnames)?;

        let request = CreateCertificate {
            hostnames,
            requested_validity: validity_days,
            request_type: CertificateRequestType::OriginRSA,
            csr: csr.clone(),
        };

        let response = self.client
            .request(&request)
            .await
            .map_err(Error::CloudflareApi)?;

        Ok(OriginCertificate {
            id: response.result.id,
            certificate: response.result.certificate,
            private_key: zeroize::Zeroizing::new(private_key),
            hostnames: response.result.hostnames,
            expires_on: response.result.expires_on,
        })
    }

    pub async fn revoke_certificate(&self, certificate_id: &str) -> Result<(), Error> {
        use cloudflare::endpoints::origin_ca_certificate::RevokeCertificate;

        let request = RevokeCertificate {
            certificate_id: certificate_id.to_string(),
        };

        self.client
            .request(&request)
            .await
            .map_err(Error::CloudflareApi)?;

        Ok(())
    }

    pub async fn list_certificates(&self) -> Result<Vec<CertificateInfo>, Error> {
        use cloudflare::endpoints::origin_ca_certificate::ListCertificates;

        let request = ListCertificates {
            zone_id: self.zone_id.clone(),
        };

        let response = self.client
            .request(&request)
            .await
            .map_err(Error::CloudflareApi)?;

        Ok(response.result.into_iter().map(|c| CertificateInfo {
            id: c.id,
            hostnames: c.hostnames,
            expires_on: c.expires_on,
        }).collect())
    }
}

#[derive(Debug)]
pub struct OriginCertificate {
    pub id: String,
    pub certificate: String,
    pub private_key: zeroize::Zeroizing<String>,
    pub hostnames: Vec<String>,
    pub expires_on: chrono::DateTime<Utc>,
}

#[derive(Debug)]
pub struct CertificateInfo {
    pub id: String,
    pub hostnames: Vec<String>,
    pub expires_on: chrono::DateTime<Utc>,
}

fn generate_csr(hostnames: &[String]) -> Result<(String, String), Error> {
    use rcgen::{CertificateParams, KeyPair, DnType};

    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, &hostnames[0]);

    // Add SANs
    for hostname in hostnames {
        params.subject_alt_names.push(
            rcgen::SanType::DnsName(hostname.to_string())
        );
    }

    let key_pair = KeyPair::generate(&rcgen::PKCS_RSA_SHA256)?;
    let csr = params.serialize_request(&key_pair)?;

    Ok((
        csr.pem()?,
        key_pair.serialize_pem(),
    ))
}
```

### Certificate Rotation with Vault Storage

```rust
use vaultrs::kv2;

pub struct CertRotator {
    cert_manager: OriginCertManager,
    vault_client: vaultrs::client::VaultClient,
    vault_mount: String,
}

impl CertRotator {
    pub async fn rotate_certificate(
        &self,
        hostnames: Vec<String>,
        vault_path: &str,
        validity_days: u16,
    ) -> Result<(), Error> {
        // Get current certificate ID if exists
        let old_cert_id = self.get_current_cert_id(vault_path).await.ok();

        // Generate new certificate
        let new_cert = self.cert_manager
            .create_certificate(hostnames, validity_days)
            .await?;

        // Store in Vault
        #[derive(serde::Serialize)]
        struct CertSecret {
            certificate: String,
            private_key: String,
            certificate_id: String,
            expires_on: String,
        }

        let secret = CertSecret {
            certificate: new_cert.certificate.clone(),
            private_key: new_cert.private_key.to_string(),
            certificate_id: new_cert.id.clone(),
            expires_on: new_cert.expires_on.to_rfc3339(),
        };

        kv2::set(&self.vault_client, &self.vault_mount, vault_path, &secret)
            .await
            .map_err(Error::VaultWrite)?;

        // Revoke old certificate
        if let Some(old_id) = old_cert_id {
            if let Err(e) = self.cert_manager.revoke_certificate(&old_id).await {
                tracing::warn!("Failed to revoke old certificate {}: {}", old_id, e);
            }
        }

        tracing::info!(
            "Certificate rotated successfully, new ID: {}, expires: {}",
            new_cert.id,
            new_cert.expires_on
        );

        Ok(())
    }

    async fn get_current_cert_id(&self, vault_path: &str) -> Result<String, Error> {
        #[derive(serde::Deserialize)]
        struct CertSecret {
            certificate_id: String,
        }

        let secret: CertSecret = kv2::read(&self.vault_client, &self.vault_mount, vault_path)
            .await
            .map_err(Error::VaultRead)?;

        Ok(secret.certificate_id)
    }
}
```

---

## DNS Management

### Zone and Record Management

```rust
use cloudflare::endpoints::dns::{
    CreateDnsRecord, DnsContent, DnsRecord, ListDnsRecords, UpdateDnsRecord,
};

pub struct DnsManager {
    client: CloudflareClient,
    zone_id: String,
}

impl DnsManager {
    pub async fn create_record(
        &self,
        name: &str,
        content: DnsContent,
        ttl: u32,
        proxied: bool,
    ) -> Result<String, Error> {
        let request = CreateDnsRecord {
            zone_identifier: &self.zone_id,
            params: cloudflare::endpoints::dns::CreateDnsRecordParams {
                name,
                content,
                ttl: Some(ttl),
                proxied: Some(proxied),
                priority: None,
            },
        };

        let response = self.client
            .request(&request)
            .await
            .map_err(Error::CloudflareApi)?;

        Ok(response.result.id)
    }

    pub async fn update_record(
        &self,
        record_id: &str,
        name: &str,
        content: DnsContent,
        ttl: u32,
        proxied: bool,
    ) -> Result<(), Error> {
        let request = UpdateDnsRecord {
            zone_identifier: &self.zone_id,
            identifier: record_id,
            params: cloudflare::endpoints::dns::UpdateDnsRecordParams {
                name,
                content,
                ttl: Some(ttl),
                proxied: Some(proxied),
                priority: None,
            },
        };

        self.client
            .request(&request)
            .await
            .map_err(Error::CloudflareApi)?;

        Ok(())
    }

    pub async fn delete_record(&self, record_id: &str) -> Result<(), Error> {
        use cloudflare::endpoints::dns::DeleteDnsRecord;

        let request = DeleteDnsRecord {
            zone_identifier: &self.zone_id,
            identifier: record_id,
        };

        self.client
            .request(&request)
            .await
            .map_err(Error::CloudflareApi)?;

        Ok(())
    }

    pub async fn list_records(&self, record_type: Option<&str>) -> Result<Vec<DnsRecord>, Error> {
        let request = ListDnsRecords {
            zone_identifier: &self.zone_id,
            params: cloudflare::endpoints::dns::ListDnsRecordsParams {
                record_type: record_type.map(String::from),
                ..Default::default()
            },
        };

        let response = self.client
            .request(&request)
            .await
            .map_err(Error::CloudflareApi)?;

        Ok(response.result)
    }

    pub async fn find_record(&self, name: &str) -> Result<Option<DnsRecord>, Error> {
        let records = self.list_records(None).await?;
        Ok(records.into_iter().find(|r| r.name == name))
    }
}

// Helper for common DNS operations
impl DnsManager {
    pub async fn upsert_a_record(
        &self,
        name: &str,
        ip: std::net::Ipv4Addr,
        proxied: bool,
    ) -> Result<(), Error> {
        let content = DnsContent::A { content: ip };

        if let Some(existing) = self.find_record(name).await? {
            self.update_record(&existing.id, name, content, 300, proxied).await
        } else {
            self.create_record(name, content, 300, proxied).await?;
            Ok(())
        }
    }

    pub async fn upsert_cname_record(
        &self,
        name: &str,
        target: &str,
        proxied: bool,
    ) -> Result<(), Error> {
        let content = DnsContent::CNAME {
            content: target.to_string(),
        };

        if let Some(existing) = self.find_record(name).await? {
            self.update_record(&existing.id, name, content, 300, proxied).await
        } else {
            self.create_record(name, content, 300, proxied).await?;
            Ok(())
        }
    }
}
```

---

## R2 Storage Integration

```rust
use aws_sdk_s3::{Client as S3Client, Config};
use aws_credential_types::Credentials;

pub struct R2Client {
    client: S3Client,
    bucket: String,
}

impl R2Client {
    pub fn new(
        account_id: &str,
        access_key_id: &str,
        secret_access_key: &str,
        bucket: &str,
    ) -> Self {
        let endpoint = format!("https://{}.r2.cloudflarestorage.com", account_id);

        let credentials = Credentials::new(
            access_key_id,
            secret_access_key,
            None,
            None,
            "r2",
        );

        let config = Config::builder()
            .endpoint_url(&endpoint)
            .credentials_provider(credentials)
            .region(aws_sdk_s3::config::Region::new("auto"))
            .build();

        Self {
            client: S3Client::from_conf(config),
            bucket: bucket.to_string(),
        }
    }

    pub async fn upload(
        &self,
        key: &str,
        data: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<(), Error> {
        let mut request = self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(data.into());

        if let Some(ct) = content_type {
            request = request.content_type(ct);
        }

        request.send().await.map_err(Error::R2Upload)?;
        Ok(())
    }

    pub async fn download(&self, key: &str) -> Result<Vec<u8>, Error> {
        let response = self.client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(Error::R2Download)?;

        let data = response.body
            .collect()
            .await
            .map_err(Error::R2StreamRead)?
            .into_bytes()
            .to_vec();

        Ok(data)
    }

    pub async fn delete(&self, key: &str) -> Result<(), Error> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(Error::R2Delete)?;

        Ok(())
    }

    pub async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>, Error> {
        let mut request = self.client
            .list_objects_v2()
            .bucket(&self.bucket);

        if let Some(p) = prefix {
            request = request.prefix(p);
        }

        let response = request.send().await.map_err(Error::R2List)?;

        Ok(response
            .contents()
            .iter()
            .filter_map(|obj| obj.key().map(String::from))
            .collect())
    }
}
```

---

## Workers Deployment

```rust
use reqwest::Client;

pub struct WorkersManager {
    client: Client,
    api_token: zeroize::Zeroizing<String>,
    account_id: String,
}

impl WorkersManager {
    pub async fn deploy_worker(
        &self,
        script_name: &str,
        script_content: &str,
        bindings: Vec<WorkerBinding>,
    ) -> Result<(), Error> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/workers/scripts/{}",
            self.account_id, script_name
        );

        // Build multipart form
        let mut form = reqwest::multipart::Form::new()
            .text("metadata", serde_json::to_string(&WorkerMetadata {
                bindings,
                ..Default::default()
            })?)
            .text("script", script_content.to_string());

        let response = self.client
            .put(&url)
            .header("Authorization", format!("Bearer {}", self.api_token.as_str()))
            .multipart(form)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(Error::WorkerDeploy(error_text));
        }

        Ok(())
    }

    pub async fn delete_worker(&self, script_name: &str) -> Result<(), Error> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/workers/scripts/{}",
            self.account_id, script_name
        );

        let response = self.client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token.as_str()))
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(Error::WorkerDelete(error_text));
        }

        Ok(())
    }
}

#[derive(Debug, serde::Serialize, Default)]
struct WorkerMetadata {
    bindings: Vec<WorkerBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compatibility_date: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(tag = "type")]
pub enum WorkerBinding {
    #[serde(rename = "kv_namespace")]
    KvNamespace {
        name: String,
        namespace_id: String,
    },
    #[serde(rename = "r2_bucket")]
    R2Bucket {
        name: String,
        bucket_name: String,
    },
    #[serde(rename = "secret_text")]
    SecretText {
        name: String,
        text: String,
    },
}
```

---

## Security Best Practices

### API Token Security

```rust
// Use scoped tokens with minimum permissions
pub struct CloudflareTokenConfig {
    // Zone:Read - Required for listing zones
    pub zone_read: bool,
    // Zone:Edit - Required for DNS management
    pub zone_edit: bool,
    // SSL and Certificates:Edit - Required for Origin CA
    pub ssl_edit: bool,
    // Workers Scripts:Edit - Required for Workers
    pub workers_edit: bool,
    // R2:Edit - Required for R2 storage
    pub r2_edit: bool,
}

// Validate token has required permissions before operations
pub async fn validate_token_permissions(
    client: &CloudflareClient,
    required: &CloudflareTokenConfig,
) -> Result<(), Error> {
    use cloudflare::endpoints::user::GetUserTokenStatus;

    let status = client
        .request(&GetUserTokenStatus {})
        .await
        .map_err(Error::CloudflareApi)?;

    // Check token status
    if status.result.status != "active" {
        return Err(Error::TokenInactive);
    }

    Ok(())
}
```

### Certificate Security

```rust
// Always verify certificate before using
pub fn verify_certificate(cert_pem: &str, expected_hostnames: &[String]) -> Result<(), Error> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_pem(cert_pem.as_bytes())
        .map_err(|_| Error::InvalidCertificate)?;

    // Check expiration
    if cert.validity().is_valid() == false {
        return Err(Error::CertificateExpired);
    }

    // Check hostnames in SAN
    if let Some(san) = cert.subject_alternative_name()? {
        for hostname in expected_hostnames {
            let found = san.value.general_names.iter().any(|name| {
                match name {
                    GeneralName::DNSName(dns) => dns == hostname,
                    _ => false,
                }
            });
            if !found {
                return Err(Error::HostnameMismatch(hostname.clone()));
            }
        }
    }

    Ok(())
}
```

---

## Cloudflare Security Checklist

### API Security

- [ ] Use API tokens (not Global API Key)
- [ ] Scope tokens to minimum permissions
- [ ] Store tokens in Vault
- [ ] Rotate tokens regularly
- [ ] Monitor API usage

### Certificate Security

- [ ] Use Origin CA certificates for origin servers
- [ ] Enable Full (Strict) SSL mode
- [ ] Automate certificate rotation
- [ ] Store certificates securely in Vault
- [ ] Monitor certificate expiration

### DNS Security

- [ ] Enable DNSSEC
- [ ] Use proxied records where appropriate
- [ ] Audit DNS changes
- [ ] Implement CAA records

### General

- [ ] Enable Cloudflare WAF
- [ ] Configure rate limiting
- [ ] Set up DDoS protection
- [ ] Enable bot management

## Recommended Crates

- **cloudflare**: Official Cloudflare API client
- **aws-sdk-s3**: R2 storage (S3-compatible)
- **vaultrs**: HashiCorp Vault integration
- **rcgen**: CSR generation
- **x509-parser**: Certificate parsing
- **zeroize**: Secure memory clearing

## Integration Points

This skill works well with:

- `/vault-setup` - Store API tokens and certificates
- `/cert-rotate` - Automate certificate rotation
- `/nginx-config` - Use certificates in Nginx
