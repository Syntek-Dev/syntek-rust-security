//! Certificate Manager Implementation
//!
//! Comprehensive certificate management system for Cloudflare Origin/Edge certificates
//! with Vault integration and automated rotation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Certificate type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateType {
    Origin,
    Edge,
    ClientMtls,
    ServiceMesh,
}

impl CertificateType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CertificateType::Origin => "origin",
            CertificateType::Edge => "edge",
            CertificateType::ClientMtls => "client_mtls",
            CertificateType::ServiceMesh => "service_mesh",
        }
    }
}

/// Certificate status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateStatus {
    Active,
    Pending,
    Expiring,
    Expired,
    Revoked,
}

/// Key algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Rsa2048,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    Ed25519,
}

impl KeyAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyAlgorithm::Rsa2048 => "RSA-2048",
            KeyAlgorithm::Rsa4096 => "RSA-4096",
            KeyAlgorithm::EcdsaP256 => "ECDSA-P256",
            KeyAlgorithm::EcdsaP384 => "ECDSA-P384",
            KeyAlgorithm::Ed25519 => "Ed25519",
        }
    }

    pub fn key_bits(&self) -> u32 {
        match self {
            KeyAlgorithm::Rsa2048 => 2048,
            KeyAlgorithm::Rsa4096 => 4096,
            KeyAlgorithm::EcdsaP256 => 256,
            KeyAlgorithm::EcdsaP384 => 384,
            KeyAlgorithm::Ed25519 => 256,
        }
    }
}

/// Certificate information
#[derive(Debug, Clone)]
pub struct Certificate {
    pub id: String,
    pub cert_type: CertificateType,
    pub status: CertificateStatus,
    pub common_name: String,
    pub sans: Vec<String>,
    pub algorithm: KeyAlgorithm,
    pub not_before: u64,
    pub not_after: u64,
    pub serial_number: String,
    pub fingerprint_sha256: String,
    pub issuer: String,
    pub created_at: u64,
    pub last_rotated: Option<u64>,
    pub rotation_count: u32,
    pub pem_certificate: String,
    pub metadata: HashMap<String, String>,
}

impl Certificate {
    pub fn days_until_expiry(&self) -> i64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (self.not_after as i64 - now as i64) / 86400
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.not_after < now
    }

    pub fn is_expiring_soon(&self, days: u32) -> bool {
        self.days_until_expiry() < days as i64 && !self.is_expired()
    }

    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.not_before <= now && now < self.not_after && self.status == CertificateStatus::Active
    }
}

/// Certificate request for generation
#[derive(Debug, Clone)]
pub struct CertificateRequest {
    pub cert_type: CertificateType,
    pub common_name: String,
    pub sans: Vec<String>,
    pub algorithm: KeyAlgorithm,
    pub validity_days: u32,
    pub auto_rotate: bool,
    pub rotate_before_days: u32,
    pub metadata: HashMap<String, String>,
}

impl CertificateRequest {
    pub fn origin(common_name: impl Into<String>) -> Self {
        Self {
            cert_type: CertificateType::Origin,
            common_name: common_name.into(),
            sans: Vec::new(),
            algorithm: KeyAlgorithm::EcdsaP256,
            validity_days: 365,
            auto_rotate: true,
            rotate_before_days: 30,
            metadata: HashMap::new(),
        }
    }

    pub fn edge(common_name: impl Into<String>) -> Self {
        Self {
            cert_type: CertificateType::Edge,
            common_name: common_name.into(),
            sans: Vec::new(),
            algorithm: KeyAlgorithm::EcdsaP256,
            validity_days: 90,
            auto_rotate: true,
            rotate_before_days: 14,
            metadata: HashMap::new(),
        }
    }

    pub fn san(mut self, name: impl Into<String>) -> Self {
        self.sans.push(name.into());
        self
    }

    pub fn sans(mut self, names: Vec<String>) -> Self {
        self.sans.extend(names);
        self
    }

    pub fn algorithm(mut self, algo: KeyAlgorithm) -> Self {
        self.algorithm = algo;
        self
    }

    pub fn validity_days(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }

    pub fn rotate_before(mut self, days: u32) -> Self {
        self.rotate_before_days = days;
        self
    }

    pub fn auto_rotate(mut self, enable: bool) -> Self {
        self.auto_rotate = enable;
        self
    }

    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Rotation policy
#[derive(Debug, Clone)]
pub struct RotationPolicy {
    pub enabled: bool,
    pub check_interval: Duration,
    pub rotate_before_expiry_days: u32,
    pub max_rotation_attempts: u32,
    pub notify_on_rotation: bool,
    pub notify_on_failure: bool,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval: Duration::from_secs(3600), // 1 hour
            rotate_before_expiry_days: 30,
            max_rotation_attempts: 3,
            notify_on_rotation: true,
            notify_on_failure: true,
        }
    }
}

/// Rotation event
#[derive(Debug, Clone)]
pub struct RotationEvent {
    pub certificate_id: String,
    pub old_serial: String,
    pub new_serial: String,
    pub timestamp: u64,
    pub success: bool,
    pub error: Option<String>,
}

/// Vault configuration for certificate storage
#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub address: String,
    pub token: String,
    pub mount_path: String,
    pub secret_path: String,
    pub timeout: Duration,
}

impl VaultConfig {
    pub fn new(address: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            token: token.into(),
            mount_path: "secret".to_string(),
            secret_path: "certificates".to_string(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn mount_path(mut self, path: impl Into<String>) -> Self {
        self.mount_path = path.into();
        self
    }

    pub fn secret_path(mut self, path: impl Into<String>) -> Self {
        self.secret_path = path.into();
        self
    }
}

/// Vault client interface
pub trait VaultClient: Send + Sync {
    fn store_certificate(
        &self,
        path: &str,
        cert: &Certificate,
        private_key: &str,
    ) -> Result<(), VaultError>;
    fn retrieve_certificate(&self, path: &str) -> Result<(Certificate, String), VaultError>;
    fn delete_certificate(&self, path: &str) -> Result<(), VaultError>;
    fn list_certificates(&self, path: &str) -> Result<Vec<String>, VaultError>;
}

/// Mock Vault client for demonstration
pub struct MockVaultClient {
    storage: RwLock<HashMap<String, (Certificate, String)>>,
}

impl MockVaultClient {
    pub fn new() -> Self {
        Self {
            storage: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MockVaultClient {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultClient for MockVaultClient {
    fn store_certificate(
        &self,
        path: &str,
        cert: &Certificate,
        private_key: &str,
    ) -> Result<(), VaultError> {
        let mut storage = self.storage.write().unwrap();
        storage.insert(path.to_string(), (cert.clone(), private_key.to_string()));
        Ok(())
    }

    fn retrieve_certificate(&self, path: &str) -> Result<(Certificate, String), VaultError> {
        let storage = self.storage.read().unwrap();
        storage
            .get(path)
            .cloned()
            .ok_or_else(|| VaultError::NotFound(path.to_string()))
    }

    fn delete_certificate(&self, path: &str) -> Result<(), VaultError> {
        let mut storage = self.storage.write().unwrap();
        storage.remove(path);
        Ok(())
    }

    fn list_certificates(&self, _path: &str) -> Result<Vec<String>, VaultError> {
        let storage = self.storage.read().unwrap();
        Ok(storage.keys().cloned().collect())
    }
}

#[derive(Debug)]
pub enum VaultError {
    NotFound(String),
    ConnectionError(String),
    AuthenticationError(String),
    PermissionDenied(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::NotFound(path) => write!(f, "Certificate not found: {}", path),
            VaultError::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            VaultError::AuthenticationError(msg) => write!(f, "Auth error: {}", msg),
            VaultError::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
        }
    }
}

impl std::error::Error for VaultError {}

/// Cloudflare API interface
pub trait CloudflareApi: Send + Sync {
    fn create_origin_certificate(
        &self,
        request: &CertificateRequest,
    ) -> Result<(String, String), CloudflareError>;
    fn revoke_certificate(&self, cert_id: &str) -> Result<(), CloudflareError>;
    fn list_certificates(&self, zone_id: &str) -> Result<Vec<String>, CloudflareError>;
}

/// Mock Cloudflare API for demonstration
pub struct MockCloudflareApi {
    cert_counter: AtomicU64,
}

impl MockCloudflareApi {
    pub fn new() -> Self {
        Self {
            cert_counter: AtomicU64::new(1),
        }
    }
}

impl Default for MockCloudflareApi {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudflareApi for MockCloudflareApi {
    fn create_origin_certificate(
        &self,
        request: &CertificateRequest,
    ) -> Result<(String, String), CloudflareError> {
        let counter = self.cert_counter.fetch_add(1, Ordering::SeqCst);

        let cert_pem = format!(
            "-----BEGIN CERTIFICATE-----\nMOCK_CERT_{}\n-----END CERTIFICATE-----",
            counter
        );
        let key_pem = format!(
            "-----BEGIN PRIVATE KEY-----\nMOCK_KEY_{}\n-----END PRIVATE KEY-----",
            counter
        );

        Ok((cert_pem, key_pem))
    }

    fn revoke_certificate(&self, _cert_id: &str) -> Result<(), CloudflareError> {
        Ok(())
    }

    fn list_certificates(&self, _zone_id: &str) -> Result<Vec<String>, CloudflareError> {
        Ok(vec![])
    }
}

#[derive(Debug)]
pub enum CloudflareError {
    ApiError { code: u32, message: String },
    RateLimit,
    NetworkError(String),
}

impl std::fmt::Display for CloudflareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloudflareError::ApiError { code, message } => {
                write!(f, "Cloudflare API error ({}): {}", code, message)
            }
            CloudflareError::RateLimit => write!(f, "Rate limit exceeded"),
            CloudflareError::NetworkError(msg) => write!(f, "Network error: {}", msg),
        }
    }
}

impl std::error::Error for CloudflareError {}

/// Certificate manager
pub struct CertificateManager {
    certificates: Arc<RwLock<HashMap<String, Certificate>>>,
    vault: Arc<dyn VaultClient>,
    cloudflare: Arc<dyn CloudflareApi>,
    rotation_policy: RotationPolicy,
    rotation_history: Arc<RwLock<Vec<RotationEvent>>>,
    stats: ManagerStats,
}

pub struct ManagerStats {
    total_rotations: AtomicU64,
    failed_rotations: AtomicU64,
    active_certificates: AtomicU64,
}

impl ManagerStats {
    pub fn new() -> Self {
        Self {
            total_rotations: AtomicU64::new(0),
            failed_rotations: AtomicU64::new(0),
            active_certificates: AtomicU64::new(0),
        }
    }
}

impl Default for ManagerStats {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificateManager {
    pub fn new(vault: Arc<dyn VaultClient>, cloudflare: Arc<dyn CloudflareApi>) -> Self {
        Self {
            certificates: Arc::new(RwLock::new(HashMap::new())),
            vault,
            cloudflare,
            rotation_policy: RotationPolicy::default(),
            rotation_history: Arc::new(RwLock::new(Vec::new())),
            stats: ManagerStats::new(),
        }
    }

    pub fn with_rotation_policy(mut self, policy: RotationPolicy) -> Self {
        self.rotation_policy = policy;
        self
    }

    /// Issue a new certificate
    pub fn issue_certificate(
        &self,
        request: CertificateRequest,
    ) -> Result<Certificate, CertManagerError> {
        // Generate certificate via Cloudflare
        let (cert_pem, key_pem) = self
            .cloudflare
            .create_origin_certificate(&request)
            .map_err(|e| CertManagerError::CloudflareError(e.to_string()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cert_id = generate_cert_id();

        let certificate = Certificate {
            id: cert_id.clone(),
            cert_type: request.cert_type,
            status: CertificateStatus::Active,
            common_name: request.common_name.clone(),
            sans: request.sans.clone(),
            algorithm: request.algorithm,
            not_before: now,
            not_after: now + (request.validity_days as u64 * 86400),
            serial_number: generate_serial(),
            fingerprint_sha256: generate_fingerprint(),
            issuer: "Cloudflare Origin CA".to_string(),
            created_at: now,
            last_rotated: None,
            rotation_count: 0,
            pem_certificate: cert_pem.clone(),
            metadata: request.metadata,
        };

        // Store in Vault
        let vault_path = format!("{}/{}", request.cert_type.as_str(), cert_id);
        self.vault
            .store_certificate(&vault_path, &certificate, &key_pem)
            .map_err(|e| CertManagerError::VaultError(e.to_string()))?;

        // Store locally
        let mut certs = self.certificates.write().unwrap();
        certs.insert(cert_id.clone(), certificate.clone());

        self.stats
            .active_certificates
            .fetch_add(1, Ordering::SeqCst);

        Ok(certificate)
    }

    /// Rotate a certificate
    pub fn rotate_certificate(&self, cert_id: &str) -> Result<Certificate, CertManagerError> {
        let old_cert = {
            let certs = self.certificates.read().unwrap();
            certs
                .get(cert_id)
                .cloned()
                .ok_or_else(|| CertManagerError::NotFound(cert_id.to_string()))?
        };

        // Create new certificate request based on old cert
        let request = CertificateRequest {
            cert_type: old_cert.cert_type,
            common_name: old_cert.common_name.clone(),
            sans: old_cert.sans.clone(),
            algorithm: old_cert.algorithm,
            validity_days: 365,
            auto_rotate: true,
            rotate_before_days: self.rotation_policy.rotate_before_expiry_days,
            metadata: old_cert.metadata.clone(),
        };

        // Issue new certificate
        let (cert_pem, key_pem) = self
            .cloudflare
            .create_origin_certificate(&request)
            .map_err(|e| CertManagerError::CloudflareError(e.to_string()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let new_serial = generate_serial();

        let new_cert = Certificate {
            id: old_cert.id.clone(),
            cert_type: old_cert.cert_type,
            status: CertificateStatus::Active,
            common_name: old_cert.common_name,
            sans: old_cert.sans,
            algorithm: old_cert.algorithm,
            not_before: now,
            not_after: now + (request.validity_days as u64 * 86400),
            serial_number: new_serial.clone(),
            fingerprint_sha256: generate_fingerprint(),
            issuer: old_cert.issuer,
            created_at: old_cert.created_at,
            last_rotated: Some(now),
            rotation_count: old_cert.rotation_count + 1,
            pem_certificate: cert_pem.clone(),
            metadata: old_cert.metadata,
        };

        // Update in Vault
        let vault_path = format!("{}/{}", new_cert.cert_type.as_str(), cert_id);
        self.vault
            .store_certificate(&vault_path, &new_cert, &key_pem)
            .map_err(|e| CertManagerError::VaultError(e.to_string()))?;

        // Update locally
        let mut certs = self.certificates.write().unwrap();
        certs.insert(cert_id.to_string(), new_cert.clone());

        // Record rotation event
        let event = RotationEvent {
            certificate_id: cert_id.to_string(),
            old_serial: old_cert.serial_number,
            new_serial,
            timestamp: now,
            success: true,
            error: None,
        };

        let mut history = self.rotation_history.write().unwrap();
        history.push(event);

        self.stats.total_rotations.fetch_add(1, Ordering::SeqCst);

        Ok(new_cert)
    }

    /// Check for certificates needing rotation
    pub fn check_expiring(&self) -> Vec<Certificate> {
        let certs = self.certificates.read().unwrap();
        certs
            .values()
            .filter(|c| c.is_expiring_soon(self.rotation_policy.rotate_before_expiry_days))
            .cloned()
            .collect()
    }

    /// Rotate all expiring certificates
    pub fn rotate_expiring(&self) -> Vec<Result<Certificate, CertManagerError>> {
        let expiring = self.check_expiring();
        expiring
            .into_iter()
            .map(|cert| self.rotate_certificate(&cert.id))
            .collect()
    }

    /// Get certificate by ID
    pub fn get_certificate(&self, cert_id: &str) -> Option<Certificate> {
        let certs = self.certificates.read().unwrap();
        certs.get(cert_id).cloned()
    }

    /// List all certificates
    pub fn list_certificates(&self) -> Vec<Certificate> {
        let certs = self.certificates.read().unwrap();
        certs.values().cloned().collect()
    }

    /// List certificates by type
    pub fn list_by_type(&self, cert_type: CertificateType) -> Vec<Certificate> {
        let certs = self.certificates.read().unwrap();
        certs
            .values()
            .filter(|c| c.cert_type == cert_type)
            .cloned()
            .collect()
    }

    /// Revoke a certificate
    pub fn revoke_certificate(&self, cert_id: &str) -> Result<(), CertManagerError> {
        let mut certs = self.certificates.write().unwrap();
        let cert = certs
            .get_mut(cert_id)
            .ok_or_else(|| CertManagerError::NotFound(cert_id.to_string()))?;

        // Revoke via Cloudflare
        self.cloudflare
            .revoke_certificate(cert_id)
            .map_err(|e| CertManagerError::CloudflareError(e.to_string()))?;

        cert.status = CertificateStatus::Revoked;
        self.stats
            .active_certificates
            .fetch_sub(1, Ordering::SeqCst);

        Ok(())
    }

    /// Get rotation history
    pub fn rotation_history(&self) -> Vec<RotationEvent> {
        let history = self.rotation_history.read().unwrap();
        history.clone()
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.stats.total_rotations.load(Ordering::SeqCst),
            self.stats.failed_rotations.load(Ordering::SeqCst),
            self.stats.active_certificates.load(Ordering::SeqCst),
        )
    }
}

/// Certificate manager errors
#[derive(Debug)]
pub enum CertManagerError {
    NotFound(String),
    VaultError(String),
    CloudflareError(String),
    ValidationError(String),
    RotationFailed(String),
}

impl std::fmt::Display for CertManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertManagerError::NotFound(id) => write!(f, "Certificate not found: {}", id),
            CertManagerError::VaultError(msg) => write!(f, "Vault error: {}", msg),
            CertManagerError::CloudflareError(msg) => write!(f, "Cloudflare error: {}", msg),
            CertManagerError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            CertManagerError::RotationFailed(msg) => write!(f, "Rotation failed: {}", msg),
        }
    }
}

impl std::error::Error for CertManagerError {}

/// Generate unique certificate ID
fn generate_cert_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("cert-{:016x}", nanos)
}

/// Generate mock serial number
fn generate_serial() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:032X}", nanos)
}

/// Generate mock SHA256 fingerprint
fn generate_fingerprint() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("SHA256:{:064x}", nanos)
}

fn main() {
    println!("=== Certificate Manager Demo ===\n");

    // Create mock backends
    let vault: Arc<dyn VaultClient> = Arc::new(MockVaultClient::new());
    let cloudflare: Arc<dyn CloudflareApi> = Arc::new(MockCloudflareApi::new());

    // Create manager
    let rotation_policy = RotationPolicy {
        enabled: true,
        check_interval: Duration::from_secs(3600),
        rotate_before_expiry_days: 30,
        max_rotation_attempts: 3,
        notify_on_rotation: true,
        notify_on_failure: true,
    };

    let manager = CertificateManager::new(vault, cloudflare).with_rotation_policy(rotation_policy);

    // Issue origin certificate
    println!("1. Issuing origin certificate:");
    let request = CertificateRequest::origin("example.com")
        .san("*.example.com")
        .san("api.example.com")
        .algorithm(KeyAlgorithm::EcdsaP256)
        .validity_days(365)
        .rotate_before(30)
        .metadata("environment", "production")
        .metadata("owner", "platform-team");

    match manager.issue_certificate(request) {
        Ok(cert) => {
            println!("   ID: {}", cert.id);
            println!("   CN: {}", cert.common_name);
            println!("   SANs: {:?}", cert.sans);
            println!("   Algorithm: {}", cert.algorithm.as_str());
            println!("   Serial: {}", cert.serial_number);
            println!("   Days until expiry: {}", cert.days_until_expiry());
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Issue edge certificate
    println!("\n2. Issuing edge certificate:");
    let request = CertificateRequest::edge("cdn.example.com")
        .san("static.example.com")
        .algorithm(KeyAlgorithm::EcdsaP384)
        .validity_days(90);

    let edge_cert = manager.issue_certificate(request).unwrap();
    println!("   ID: {}", edge_cert.id);
    println!("   Type: {:?}", edge_cert.cert_type);
    println!("   Expires in {} days", edge_cert.days_until_expiry());

    // List certificates
    println!("\n3. List all certificates:");
    for cert in manager.list_certificates() {
        println!(
            "   - {} ({:?}): {} - {}",
            cert.id,
            cert.cert_type,
            cert.common_name,
            if cert.is_valid() { "Valid" } else { "Invalid" }
        );
    }

    // List by type
    println!("\n4. Origin certificates:");
    for cert in manager.list_by_type(CertificateType::Origin) {
        println!("   - {}: {}", cert.id, cert.common_name);
    }

    // Rotate certificate
    println!("\n5. Rotating certificate:");
    let cert_to_rotate = manager.list_certificates().first().unwrap().id.clone();
    match manager.rotate_certificate(&cert_to_rotate) {
        Ok(new_cert) => {
            println!("   Rotated: {}", new_cert.id);
            println!("   New serial: {}", new_cert.serial_number);
            println!("   Rotation count: {}", new_cert.rotation_count);
            println!(
                "   Last rotated: {:?}",
                new_cert.last_rotated.map(|t| format!(
                    "{} seconds ago",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        - t
                ))
            );
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Check rotation history
    println!("\n6. Rotation history:");
    for event in manager.rotation_history() {
        println!(
            "   - {}: {} -> {} (success: {})",
            event.certificate_id, event.old_serial, event.new_serial, event.success
        );
    }

    // Check expiring certificates
    println!("\n7. Checking expiring certificates:");
    let expiring = manager.check_expiring();
    if expiring.is_empty() {
        println!("   No certificates expiring soon");
    } else {
        for cert in expiring {
            println!(
                "   - {}: expires in {} days",
                cert.common_name,
                cert.days_until_expiry()
            );
        }
    }

    // Statistics
    println!("\n8. Statistics:");
    let (rotations, failed, active) = manager.stats();
    println!("   Total rotations: {}", rotations);
    println!("   Failed rotations: {}", failed);
    println!("   Active certificates: {}", active);

    // Algorithm comparison
    println!("\n9. Key algorithms:");
    for algo in [
        KeyAlgorithm::Rsa2048,
        KeyAlgorithm::Rsa4096,
        KeyAlgorithm::EcdsaP256,
        KeyAlgorithm::EcdsaP384,
        KeyAlgorithm::Ed25519,
    ] {
        println!("   {}: {} bits", algo.as_str(), algo.key_bits());
    }

    // Revoke certificate
    println!("\n10. Revoking certificate:");
    match manager.revoke_certificate(&edge_cert.id) {
        Ok(()) => {
            println!("   Certificate {} revoked", edge_cert.id);
            if let Some(cert) = manager.get_certificate(&edge_cert.id) {
                println!("   Status: {:?}", cert.status);
            }
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Final statistics
    println!("\n11. Final statistics:");
    let (rotations, failed, active) = manager.stats();
    println!("   Total rotations: {}", rotations);
    println!("   Failed rotations: {}", failed);
    println!("   Active certificates: {}", active);

    println!("\n=== Demo Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_manager() -> CertificateManager {
        let vault: Arc<dyn VaultClient> = Arc::new(MockVaultClient::new());
        let cloudflare: Arc<dyn CloudflareApi> = Arc::new(MockCloudflareApi::new());
        CertificateManager::new(vault, cloudflare)
    }

    #[test]
    fn test_issue_certificate() {
        let manager = create_test_manager();

        let request = CertificateRequest::origin("test.example.com");
        let cert = manager.issue_certificate(request).unwrap();

        assert_eq!(cert.common_name, "test.example.com");
        assert_eq!(cert.cert_type, CertificateType::Origin);
        assert_eq!(cert.status, CertificateStatus::Active);
    }

    #[test]
    fn test_issue_with_sans() {
        let manager = create_test_manager();

        let request = CertificateRequest::origin("example.com")
            .san("www.example.com")
            .san("api.example.com");

        let cert = manager.issue_certificate(request).unwrap();
        assert_eq!(cert.sans.len(), 2);
    }

    #[test]
    fn test_certificate_validity() {
        let manager = create_test_manager();

        let request = CertificateRequest::origin("test.com").validity_days(365);
        let cert = manager.issue_certificate(request).unwrap();

        assert!(cert.is_valid());
        assert!(!cert.is_expired());
        assert!(cert.days_until_expiry() > 360);
    }

    #[test]
    fn test_rotate_certificate() {
        let manager = create_test_manager();

        let request = CertificateRequest::origin("test.com");
        let cert = manager.issue_certificate(request).unwrap();
        let old_serial = cert.serial_number.clone();

        let rotated = manager.rotate_certificate(&cert.id).unwrap();

        assert_ne!(rotated.serial_number, old_serial);
        assert_eq!(rotated.rotation_count, 1);
        assert!(rotated.last_rotated.is_some());
    }

    #[test]
    fn test_list_certificates() {
        let manager = create_test_manager();

        manager
            .issue_certificate(CertificateRequest::origin("test1.com"))
            .unwrap();
        manager
            .issue_certificate(CertificateRequest::origin("test2.com"))
            .unwrap();

        let certs = manager.list_certificates();
        assert_eq!(certs.len(), 2);
    }

    #[test]
    fn test_list_by_type() {
        let manager = create_test_manager();

        manager
            .issue_certificate(CertificateRequest::origin("origin.com"))
            .unwrap();
        manager
            .issue_certificate(CertificateRequest::edge("edge.com"))
            .unwrap();

        let origin_certs = manager.list_by_type(CertificateType::Origin);
        let edge_certs = manager.list_by_type(CertificateType::Edge);

        assert_eq!(origin_certs.len(), 1);
        assert_eq!(edge_certs.len(), 1);
    }

    #[test]
    fn test_get_certificate() {
        let manager = create_test_manager();

        let request = CertificateRequest::origin("test.com");
        let cert = manager.issue_certificate(request).unwrap();

        let retrieved = manager.get_certificate(&cert.id).unwrap();
        assert_eq!(retrieved.common_name, "test.com");
    }

    #[test]
    fn test_revoke_certificate() {
        let manager = create_test_manager();

        let request = CertificateRequest::origin("test.com");
        let cert = manager.issue_certificate(request).unwrap();

        manager.revoke_certificate(&cert.id).unwrap();

        let revoked = manager.get_certificate(&cert.id).unwrap();
        assert_eq!(revoked.status, CertificateStatus::Revoked);
    }

    #[test]
    fn test_rotation_history() {
        let manager = create_test_manager();

        let request = CertificateRequest::origin("test.com");
        let cert = manager.issue_certificate(request).unwrap();

        manager.rotate_certificate(&cert.id).unwrap();

        let history = manager.rotation_history();
        assert_eq!(history.len(), 1);
        assert!(history[0].success);
    }

    #[test]
    fn test_statistics() {
        let manager = create_test_manager();

        manager
            .issue_certificate(CertificateRequest::origin("test1.com"))
            .unwrap();
        manager
            .issue_certificate(CertificateRequest::origin("test2.com"))
            .unwrap();

        let (rotations, failed, active) = manager.stats();
        assert_eq!(rotations, 0);
        assert_eq!(failed, 0);
        assert_eq!(active, 2);
    }

    #[test]
    fn test_key_algorithm() {
        assert_eq!(KeyAlgorithm::Rsa2048.key_bits(), 2048);
        assert_eq!(KeyAlgorithm::EcdsaP256.key_bits(), 256);
        assert_eq!(KeyAlgorithm::Ed25519.as_str(), "Ed25519");
    }

    #[test]
    fn test_certificate_request_builder() {
        let request = CertificateRequest::origin("test.com")
            .san("www.test.com")
            .algorithm(KeyAlgorithm::Rsa4096)
            .validity_days(90)
            .rotate_before(14)
            .auto_rotate(true)
            .metadata("env", "prod");

        assert_eq!(request.common_name, "test.com");
        assert_eq!(request.sans.len(), 1);
        assert_eq!(request.algorithm, KeyAlgorithm::Rsa4096);
        assert_eq!(request.validity_days, 90);
        assert_eq!(request.rotate_before_days, 14);
    }

    #[test]
    fn test_vault_config() {
        let config = VaultConfig::new("https://vault.example.com", "s.token123")
            .mount_path("pki")
            .secret_path("certs");

        assert_eq!(config.address, "https://vault.example.com");
        assert_eq!(config.mount_path, "pki");
        assert_eq!(config.secret_path, "certs");
    }

    #[test]
    fn test_mock_vault_operations() {
        let vault = MockVaultClient::new();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cert = Certificate {
            id: "test".to_string(),
            cert_type: CertificateType::Origin,
            status: CertificateStatus::Active,
            common_name: "test.com".to_string(),
            sans: vec![],
            algorithm: KeyAlgorithm::EcdsaP256,
            not_before: now,
            not_after: now + 86400,
            serial_number: "123".to_string(),
            fingerprint_sha256: "abc".to_string(),
            issuer: "Test CA".to_string(),
            created_at: now,
            last_rotated: None,
            rotation_count: 0,
            pem_certificate: "---BEGIN---".to_string(),
            metadata: HashMap::new(),
        };

        vault.store_certificate("test", &cert, "key").unwrap();
        let (retrieved, key) = vault.retrieve_certificate("test").unwrap();

        assert_eq!(retrieved.common_name, "test.com");
        assert_eq!(key, "key");
    }

    #[test]
    fn test_rotation_policy() {
        let policy = RotationPolicy {
            enabled: true,
            check_interval: Duration::from_secs(1800),
            rotate_before_expiry_days: 14,
            max_rotation_attempts: 5,
            notify_on_rotation: true,
            notify_on_failure: true,
        };

        assert!(policy.enabled);
        assert_eq!(policy.rotate_before_expiry_days, 14);
    }

    #[test]
    fn test_certificate_not_found() {
        let manager = create_test_manager();

        let result = manager.rotate_certificate("nonexistent");
        assert!(matches!(result, Err(CertManagerError::NotFound(_))));
    }

    #[test]
    fn test_days_until_expiry() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cert = Certificate {
            id: "test".to_string(),
            cert_type: CertificateType::Origin,
            status: CertificateStatus::Active,
            common_name: "test.com".to_string(),
            sans: vec![],
            algorithm: KeyAlgorithm::EcdsaP256,
            not_before: now,
            not_after: now + (30 * 86400), // 30 days
            serial_number: "123".to_string(),
            fingerprint_sha256: "abc".to_string(),
            issuer: "Test".to_string(),
            created_at: now,
            last_rotated: None,
            rotation_count: 0,
            pem_certificate: "".to_string(),
            metadata: HashMap::new(),
        };

        assert!(cert.days_until_expiry() >= 29);
        assert!(cert.days_until_expiry() <= 30);
    }

    #[test]
    fn test_certificate_types() {
        assert_eq!(CertificateType::Origin.as_str(), "origin");
        assert_eq!(CertificateType::Edge.as_str(), "edge");
        assert_eq!(CertificateType::ClientMtls.as_str(), "client_mtls");
    }
}
