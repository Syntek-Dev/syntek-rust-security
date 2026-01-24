# Rust Cloudflare CLI Template

## Overview

This template provides a Cloudflare CLI tool for managing DNS records, Workers,
R2 storage, and Origin/Edge certificates programmatically with secure API token
handling.

**Target Use Cases:**

- DNS record management
- Workers deployment
- R2 bucket operations
- Origin/Edge certificate management
- Zone configuration

## Project Structure

```
my-cloudflare-cli/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── client.rs
│   ├── dns/
│   │   ├── mod.rs
│   │   └── records.rs
│   ├── workers/
│   │   ├── mod.rs
│   │   └── deploy.rs
│   ├── r2/
│   │   ├── mod.rs
│   │   └── bucket.rs
│   ├── certificates/
│   │   ├── mod.rs
│   │   ├── origin.rs
│   │   └── edge.rs
│   └── error.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-cloudflare-cli"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"

[dependencies]
tokio = { version = "1.40", features = ["full"] }
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
secrecy = { version = "0.10", features = ["serde"] }
clap = { version = "4.5", features = ["derive"] }
thiserror = "2.0"
tracing = "0.1"
tracing-subscriber = "0.3"
base64 = "0.22"
```

## Core Implementation

### src/client.rs

```rust
use reqwest::Client;
use secrecy::{ExposeSecret, Secret};
use serde::de::DeserializeOwned;
use crate::error::CloudflareError;

const API_BASE: &str = "https://api.cloudflare.com/client/v4";

pub struct CloudflareClient {
    client: Client,
    api_token: Secret<String>,
}

impl CloudflareClient {
    pub fn new(api_token: Secret<String>) -> Self {
        Self {
            client: Client::new(),
            api_token,
        }
    }

    pub async fn get<T: DeserializeOwned>(&self, endpoint: &str) -> Result<T, CloudflareError> {
        let response = self.client
            .get(format!("{}{}", API_BASE, endpoint))
            .bearer_auth(self.api_token.expose_secret())
            .send()
            .await?
            .json::<ApiResponse<T>>()
            .await?;

        if response.success {
            response.result.ok_or(CloudflareError::EmptyResponse)
        } else {
            Err(CloudflareError::ApiError(
                response.errors.into_iter().map(|e| e.message).collect::<Vec<_>>().join(", ")
            ))
        }
    }

    pub async fn post<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        endpoint: &str,
        body: &B,
    ) -> Result<T, CloudflareError> {
        let response = self.client
            .post(format!("{}{}", API_BASE, endpoint))
            .bearer_auth(self.api_token.expose_secret())
            .json(body)
            .send()
            .await?
            .json::<ApiResponse<T>>()
            .await?;

        if response.success {
            response.result.ok_or(CloudflareError::EmptyResponse)
        } else {
            Err(CloudflareError::ApiError(
                response.errors.into_iter().map(|e| e.message).collect::<Vec<_>>().join(", ")
            ))
        }
    }

    pub async fn delete(&self, endpoint: &str) -> Result<(), CloudflareError> {
        let response = self.client
            .delete(format!("{}{}", API_BASE, endpoint))
            .bearer_auth(self.api_token.expose_secret())
            .send()
            .await?
            .json::<ApiResponse<serde_json::Value>>()
            .await?;

        if response.success {
            Ok(())
        } else {
            Err(CloudflareError::ApiError(
                response.errors.into_iter().map(|e| e.message).collect::<Vec<_>>().join(", ")
            ))
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct ApiResponse<T> {
    success: bool,
    result: Option<T>,
    errors: Vec<ApiError>,
}

#[derive(Debug, serde::Deserialize)]
struct ApiError {
    message: String,
}
```

### src/dns/records.rs

```rust
use serde::{Deserialize, Serialize};
use crate::client::CloudflareClient;
use crate::error::CloudflareError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub content: String,
    pub ttl: u32,
    pub proxied: bool,
}

pub struct DnsManager<'a> {
    client: &'a CloudflareClient,
    zone_id: String,
}

impl<'a> DnsManager<'a> {
    pub fn new(client: &'a CloudflareClient, zone_id: &str) -> Self {
        Self {
            client,
            zone_id: zone_id.to_string(),
        }
    }

    pub async fn list(&self) -> Result<Vec<DnsRecord>, CloudflareError> {
        self.client
            .get(&format!("/zones/{}/dns_records", self.zone_id))
            .await
    }

    pub async fn create(&self, record: &DnsRecord) -> Result<DnsRecord, CloudflareError> {
        self.client
            .post(&format!("/zones/{}/dns_records", self.zone_id), record)
            .await
    }

    pub async fn delete(&self, record_id: &str) -> Result<(), CloudflareError> {
        self.client
            .delete(&format!("/zones/{}/dns_records/{}", self.zone_id, record_id))
            .await
    }
}
```

### src/certificates/origin.rs

```rust
use serde::{Deserialize, Serialize};
use crate::client::CloudflareClient;
use crate::error::CloudflareError;

#[derive(Debug, Serialize)]
pub struct OriginCertRequest {
    pub hostnames: Vec<String>,
    pub requested_validity: u32,
    pub request_type: String,
    pub csr: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OriginCertificate {
    pub id: String,
    pub certificate: String,
    pub private_key: Option<String>,
    pub hostnames: Vec<String>,
    pub expires_on: String,
}

pub struct OriginCertManager<'a> {
    client: &'a CloudflareClient,
}

impl<'a> OriginCertManager<'a> {
    pub fn new(client: &'a CloudflareClient) -> Self {
        Self { client }
    }

    pub async fn create(&self, request: &OriginCertRequest) -> Result<OriginCertificate, CloudflareError> {
        self.client.post("/certificates", request).await
    }

    pub async fn list(&self, zone_id: &str) -> Result<Vec<OriginCertificate>, CloudflareError> {
        self.client.get(&format!("/certificates?zone_id={}", zone_id)).await
    }

    pub async fn revoke(&self, cert_id: &str) -> Result<(), CloudflareError> {
        self.client.delete(&format!("/certificates/{}", cert_id)).await
    }
}
```

## Security Checklist

- [ ] API token stored securely
- [ ] Token has minimal required permissions
- [ ] All API calls over HTTPS
- [ ] Secrets never logged
- [ ] Certificate private keys protected
- [ ] Rate limiting respected
