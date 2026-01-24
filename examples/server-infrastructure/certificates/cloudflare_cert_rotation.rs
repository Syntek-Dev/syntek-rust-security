//! Cloudflare Certificate Rotation Example
//!
//! Demonstrates automated rotation of Cloudflare Origin/Edge certificates
//! with secure storage in HashiCorp Vault.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Certificate types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateType {
    Origin,
    Edge,
    ClientCertificate,
}

impl CertificateType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CertificateType::Origin => "origin",
            CertificateType::Edge => "edge",
            CertificateType::ClientCertificate => "client",
        }
    }
}

/// Certificate metadata
#[derive(Debug, Clone)]
pub struct Certificate {
    pub id: String,
    pub cert_type: CertificateType,
    pub zone_id: String,
    pub hostname: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub expires_on: u64,
    pub created_on: u64,
    pub status: CertStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    Active,
    Pending,
    Expired,
    Revoked,
}

impl Certificate {
    pub fn days_until_expiry(&self) -> i64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        ((self.expires_on - now) / 86400) as i64
    }

    pub fn needs_rotation(&self, threshold_days: i64) -> bool {
        self.days_until_expiry() < threshold_days
    }
}

/// Cloudflare API client for certificate management
pub struct CloudflareCertClient {
    api_token: String,
    base_url: String,
    account_id: String,
}

impl CloudflareCertClient {
    pub fn new(api_token: &str, account_id: &str) -> Self {
        Self {
            api_token: api_token.to_string(),
            base_url: "https://api.cloudflare.com/client/v4".to_string(),
            account_id: account_id.to_string(),
        }
    }

    /// List origin certificates for a zone
    pub fn list_origin_certificates(&self, zone_id: &str) -> Result<Vec<Certificate>, CertError> {
        // In real implementation, would call Cloudflare API
        let _endpoint = format!("{}/zones/{}/origin_tls_client_auth", self.base_url, zone_id);

        // Simulate response
        Ok(vec![Certificate {
            id: "cert_abc123".to_string(),
            cert_type: CertificateType::Origin,
            zone_id: zone_id.to_string(),
            hostname: "*.example.com".to_string(),
            certificate_pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
                .to_string(),
            private_key_pem: "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
                .to_string(),
            expires_on: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 86400 * 30, // 30 days from now
            created_on: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            status: CertStatus::Active,
        }])
    }

    /// Create new origin certificate
    pub fn create_origin_certificate(
        &self,
        zone_id: &str,
        hostnames: Vec<&str>,
        validity_days: u32,
    ) -> Result<Certificate, CertError> {
        if validity_days > 5475 {
            // Max 15 years
            return Err(CertError::InvalidValidity);
        }

        let _endpoint = format!("{}/certificates", self.base_url);

        // Simulate certificate generation
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Certificate {
            id: format!("cert_{}", generate_id()),
            cert_type: CertificateType::Origin,
            zone_id: zone_id.to_string(),
            hostname: hostnames.join(", "),
            certificate_pem: generate_mock_cert_pem(),
            private_key_pem: generate_mock_key_pem(),
            expires_on: now + (validity_days as u64 * 86400),
            created_on: now,
            status: CertStatus::Active,
        })
    }

    /// Revoke origin certificate
    pub fn revoke_certificate(&self, cert_id: &str) -> Result<(), CertError> {
        let _endpoint = format!("{}/certificates/{}", self.base_url, cert_id);

        // Simulate revocation
        Ok(())
    }

    /// Upload custom certificate
    pub fn upload_custom_certificate(
        &self,
        zone_id: &str,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<String, CertError> {
        // Validate PEM format
        if !cert_pem.contains("-----BEGIN CERTIFICATE-----") {
            return Err(CertError::InvalidCertificate(
                "Invalid PEM format".to_string(),
            ));
        }

        if !key_pem.contains("-----BEGIN") {
            return Err(CertError::InvalidPrivateKey);
        }

        let _endpoint = format!("{}/zones/{}/custom_certificates", self.base_url, zone_id);

        Ok(format!("custom_cert_{}", generate_id()))
    }
}

/// HashiCorp Vault client for secure certificate storage
pub struct VaultCertStorage {
    vault_addr: String,
    token: String,
    mount_path: String,
}

impl VaultCertStorage {
    pub fn new(vault_addr: &str, token: &str, mount_path: &str) -> Self {
        Self {
            vault_addr: vault_addr.to_string(),
            token: token.to_string(),
            mount_path: mount_path.to_string(),
        }
    }

    /// Store certificate in Vault
    pub fn store_certificate(&self, path: &str, cert: &Certificate) -> Result<(), VaultError> {
        let _endpoint = format!("{}/v1/{}/data/{}", self.vault_addr, self.mount_path, path);

        // In real implementation, would store with proper encryption
        println!(
            "Storing certificate {} at path {}/{}",
            cert.id, self.mount_path, path
        );

        Ok(())
    }

    /// Retrieve certificate from Vault
    pub fn get_certificate(&self, path: &str) -> Result<Certificate, VaultError> {
        let _endpoint = format!("{}/v1/{}/data/{}", self.vault_addr, self.mount_path, path);

        // Simulate retrieval
        Err(VaultError::NotFound(path.to_string()))
    }

    /// List certificates at path
    pub fn list_certificates(&self, path: &str) -> Result<Vec<String>, VaultError> {
        let _endpoint = format!(
            "{}/v1/{}/metadata/{}",
            self.vault_addr, self.mount_path, path
        );

        Ok(vec!["cert1".to_string(), "cert2".to_string()])
    }

    /// Delete certificate from Vault
    pub fn delete_certificate(&self, path: &str) -> Result<(), VaultError> {
        let _endpoint = format!("{}/v1/{}/data/{}", self.vault_addr, self.mount_path, path);

        Ok(())
    }
}

/// Certificate rotation manager
pub struct CertRotationManager {
    cloudflare: CloudflareCertClient,
    vault: VaultCertStorage,
    rotation_threshold_days: i64,
    validity_days: u32,
}

impl CertRotationManager {
    pub fn new(
        cloudflare: CloudflareCertClient,
        vault: VaultCertStorage,
        rotation_threshold_days: i64,
        validity_days: u32,
    ) -> Self {
        Self {
            cloudflare,
            vault,
            rotation_threshold_days,
            validity_days,
        }
    }

    /// Check and rotate certificates for a zone
    pub fn check_and_rotate(&self, zone_id: &str) -> Result<RotationReport, CertError> {
        let mut report = RotationReport::new(zone_id);

        // List existing certificates
        let certs = self.cloudflare.list_origin_certificates(zone_id)?;

        for cert in certs {
            report.checked += 1;

            if cert.needs_rotation(self.rotation_threshold_days) {
                // Rotate certificate
                match self.rotate_certificate(&cert) {
                    Ok(new_cert) => {
                        report.rotated += 1;
                        report.rotated_certs.push(RotatedCert {
                            old_id: cert.id.clone(),
                            new_id: new_cert.id.clone(),
                            hostname: cert.hostname.clone(),
                        });
                    }
                    Err(e) => {
                        report
                            .errors
                            .push(format!("Failed to rotate {}: {:?}", cert.id, e));
                    }
                }
            } else {
                report.skipped += 1;
            }
        }

        Ok(report)
    }

    /// Rotate a single certificate
    fn rotate_certificate(&self, old_cert: &Certificate) -> Result<Certificate, CertError> {
        // Parse hostnames from old cert
        let hostnames: Vec<&str> = old_cert.hostname.split(", ").collect();

        // Create new certificate
        let new_cert = self.cloudflare.create_origin_certificate(
            &old_cert.zone_id,
            hostnames,
            self.validity_days,
        )?;

        // Store in Vault
        let vault_path = format!("certificates/{}/{}", old_cert.zone_id, new_cert.id);
        self.vault
            .store_certificate(&vault_path, &new_cert)
            .map_err(|e| CertError::VaultError(format!("{:?}", e)))?;

        // Archive old certificate
        let archive_path = format!("certificates/{}/archive/{}", old_cert.zone_id, old_cert.id);
        let _ = self.vault.store_certificate(&archive_path, old_cert);

        // Revoke old certificate (optional, depends on use case)
        // self.cloudflare.revoke_certificate(&old_cert.id)?;

        Ok(new_cert)
    }

    /// Force rotate all certificates for a zone
    pub fn force_rotate_all(&self, zone_id: &str) -> Result<RotationReport, CertError> {
        let mut report = RotationReport::new(zone_id);

        let certs = self.cloudflare.list_origin_certificates(zone_id)?;

        for cert in certs {
            report.checked += 1;

            match self.rotate_certificate(&cert) {
                Ok(new_cert) => {
                    report.rotated += 1;
                    report.rotated_certs.push(RotatedCert {
                        old_id: cert.id.clone(),
                        new_id: new_cert.id.clone(),
                        hostname: cert.hostname.clone(),
                    });
                }
                Err(e) => {
                    report
                        .errors
                        .push(format!("Failed to rotate {}: {:?}", cert.id, e));
                }
            }
        }

        Ok(report)
    }
}

/// Rotation report
#[derive(Debug)]
pub struct RotationReport {
    pub zone_id: String,
    pub checked: u32,
    pub rotated: u32,
    pub skipped: u32,
    pub rotated_certs: Vec<RotatedCert>,
    pub errors: Vec<String>,
}

#[derive(Debug)]
pub struct RotatedCert {
    pub old_id: String,
    pub new_id: String,
    pub hostname: String,
}

impl RotationReport {
    fn new(zone_id: &str) -> Self {
        Self {
            zone_id: zone_id.to_string(),
            checked: 0,
            rotated: 0,
            skipped: 0,
            rotated_certs: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str(&format!("# Certificate Rotation Report\n\n"));
        md.push_str(&format!("**Zone**: {}\n\n", self.zone_id));
        md.push_str("## Summary\n\n");
        md.push_str(&format!("- Checked: {}\n", self.checked));
        md.push_str(&format!("- Rotated: {}\n", self.rotated));
        md.push_str(&format!("- Skipped: {}\n", self.skipped));
        md.push_str(&format!("- Errors: {}\n\n", self.errors.len()));

        if !self.rotated_certs.is_empty() {
            md.push_str("## Rotated Certificates\n\n");
            md.push_str("| Hostname | Old ID | New ID |\n");
            md.push_str("|----------|--------|--------|\n");
            for cert in &self.rotated_certs {
                md.push_str(&format!(
                    "| {} | {} | {} |\n",
                    cert.hostname, cert.old_id, cert.new_id
                ));
            }
        }

        if !self.errors.is_empty() {
            md.push_str("\n## Errors\n\n");
            for error in &self.errors {
                md.push_str(&format!("- {}\n", error));
            }
        }

        md
    }
}

#[derive(Debug)]
pub enum CertError {
    ApiError(String),
    InvalidCertificate(String),
    InvalidPrivateKey,
    InvalidValidity,
    NotFound,
    VaultError(String),
}

#[derive(Debug)]
pub enum VaultError {
    ConnectionError(String),
    AuthError,
    NotFound(String),
    WriteError(String),
}

fn generate_id() -> String {
    format!("{:016x}", rand_u64())
}

fn rand_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn generate_mock_cert_pem() -> String {
    "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnVu\ndXNlZDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM\nBnVudXNlZDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC5gV4hHx8h5VdV5V5V5V5V\n...\n-----END CERTIFICATE-----".to_string()
}

fn generate_mock_key_pem() -> String {
    "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAuYFeIR8fIeVXVeVe\n...\n-----END PRIVATE KEY-----".to_string()
}

fn main() {
    println!("Cloudflare Certificate Rotation Example");
    println!("========================================\n");

    // Create clients
    let cloudflare = CloudflareCertClient::new("cf-api-token-here", "account-id-here");

    let vault = VaultCertStorage::new(
        "https://vault.example.com:8200",
        "vault-token-here",
        "secret",
    );

    // Create rotation manager
    let manager = CertRotationManager::new(
        cloudflare, vault, 30,  // Rotate when < 30 days until expiry
        365, // New certs valid for 1 year
    );

    // Check and rotate certificates
    let zone_id = "zone123456789";

    println!("Checking certificates for zone {}...\n", zone_id);

    match manager.check_and_rotate(zone_id) {
        Ok(report) => {
            println!("Rotation Report:");
            println!("  Checked: {}", report.checked);
            println!("  Rotated: {}", report.rotated);
            println!("  Skipped: {}", report.skipped);

            if !report.rotated_certs.is_empty() {
                println!("\nRotated certificates:");
                for cert in &report.rotated_certs {
                    println!("  {} -> {} ({})", cert.old_id, cert.new_id, cert.hostname);
                }
            }

            if !report.errors.is_empty() {
                println!("\nErrors:");
                for error in &report.errors {
                    println!("  {}", error);
                }
            }

            println!("\n\nMarkdown Report:\n");
            println!("{}", report.to_markdown());
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_days_until_expiry() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cert = Certificate {
            id: "test".to_string(),
            cert_type: CertificateType::Origin,
            zone_id: "zone1".to_string(),
            hostname: "example.com".to_string(),
            certificate_pem: String::new(),
            private_key_pem: String::new(),
            expires_on: now + 86400 * 30, // 30 days
            created_on: now,
            status: CertStatus::Active,
        };

        let days = cert.days_until_expiry();
        assert!(days >= 29 && days <= 30);
    }

    #[test]
    fn test_needs_rotation() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cert = Certificate {
            id: "test".to_string(),
            cert_type: CertificateType::Origin,
            zone_id: "zone1".to_string(),
            hostname: "example.com".to_string(),
            certificate_pem: String::new(),
            private_key_pem: String::new(),
            expires_on: now + 86400 * 10, // 10 days
            created_on: now,
            status: CertStatus::Active,
        };

        assert!(cert.needs_rotation(30)); // Threshold 30 days
        assert!(!cert.needs_rotation(5)); // Threshold 5 days
    }

    #[test]
    fn test_cloudflare_client_creation() {
        let client = CloudflareCertClient::new("token", "account");
        assert_eq!(client.account_id, "account");
    }

    #[test]
    fn test_create_origin_certificate() {
        let client = CloudflareCertClient::new("token", "account");

        let cert = client
            .create_origin_certificate("zone1", vec!["*.example.com"], 365)
            .unwrap();

        assert_eq!(cert.cert_type, CertificateType::Origin);
        assert!(cert.certificate_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_invalid_validity() {
        let client = CloudflareCertClient::new("token", "account");

        let result = client.create_origin_certificate(
            "zone1",
            vec!["example.com"],
            10000, // > 5475 days
        );

        assert!(matches!(result, Err(CertError::InvalidValidity)));
    }

    #[test]
    fn test_upload_invalid_cert() {
        let client = CloudflareCertClient::new("token", "account");

        let result = client.upload_custom_certificate(
            "zone1",
            "not a valid cert",
            "-----BEGIN PRIVATE KEY-----\n...",
        );

        assert!(matches!(result, Err(CertError::InvalidCertificate(_))));
    }

    #[test]
    fn test_vault_storage() {
        let vault = VaultCertStorage::new("https://vault:8200", "token", "secret");

        let cert = Certificate {
            id: "test".to_string(),
            cert_type: CertificateType::Origin,
            zone_id: "zone1".to_string(),
            hostname: "example.com".to_string(),
            certificate_pem: String::new(),
            private_key_pem: String::new(),
            expires_on: 0,
            created_on: 0,
            status: CertStatus::Active,
        };

        assert!(vault.store_certificate("test/cert", &cert).is_ok());
    }

    #[test]
    fn test_rotation_report() {
        let report = RotationReport {
            zone_id: "zone1".to_string(),
            checked: 5,
            rotated: 2,
            skipped: 3,
            rotated_certs: vec![RotatedCert {
                old_id: "old1".to_string(),
                new_id: "new1".to_string(),
                hostname: "example.com".to_string(),
            }],
            errors: vec![],
        };

        let md = report.to_markdown();
        assert!(md.contains("zone1"));
        assert!(md.contains("Checked: 5"));
        assert!(md.contains("example.com"));
    }
}
