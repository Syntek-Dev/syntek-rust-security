//! GDPR Compliance Framework
//!
//! Implementation of GDPR compliance patterns including data subject rights,
//! consent management, data retention, and audit logging.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Data processing legal basis under GDPR
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegalBasis {
    Consent,
    Contract,
    LegalObligation,
    VitalInterests,
    PublicTask,
    LegitimateInterests,
}

impl fmt::Display for LegalBasis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LegalBasis::Consent => write!(f, "Consent (Art. 6(1)(a))"),
            LegalBasis::Contract => write!(f, "Contract (Art. 6(1)(b))"),
            LegalBasis::LegalObligation => write!(f, "Legal Obligation (Art. 6(1)(c))"),
            LegalBasis::VitalInterests => write!(f, "Vital Interests (Art. 6(1)(d))"),
            LegalBasis::PublicTask => write!(f, "Public Task (Art. 6(1)(e))"),
            LegalBasis::LegitimateInterests => write!(f, "Legitimate Interests (Art. 6(1)(f))"),
        }
    }
}

/// Data categories for classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataCategory {
    /// Standard personal data
    Personal,
    /// Special category data (Art. 9)
    Sensitive,
    /// Financial data
    Financial,
    /// Health data
    Health,
    /// Biometric data
    Biometric,
    /// Genetic data
    Genetic,
    /// Location data
    Location,
    /// Online identifiers
    OnlineIdentifier,
    /// Children's data
    Child,
}

impl DataCategory {
    pub fn requires_explicit_consent(&self) -> bool {
        matches!(
            self,
            DataCategory::Sensitive
                | DataCategory::Health
                | DataCategory::Biometric
                | DataCategory::Genetic
        )
    }

    pub fn is_special_category(&self) -> bool {
        matches!(
            self,
            DataCategory::Sensitive
                | DataCategory::Health
                | DataCategory::Biometric
                | DataCategory::Genetic
        )
    }
}

/// Data subject rights under GDPR
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataSubjectRight {
    /// Right to access (Art. 15)
    Access,
    /// Right to rectification (Art. 16)
    Rectification,
    /// Right to erasure (Art. 17)
    Erasure,
    /// Right to restriction (Art. 18)
    Restriction,
    /// Right to portability (Art. 20)
    Portability,
    /// Right to object (Art. 21)
    Objection,
    /// Right not to be subject to automated decision-making (Art. 22)
    AutomatedDecision,
}

impl fmt::Display for DataSubjectRight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataSubjectRight::Access => write!(f, "Right of Access (Art. 15)"),
            DataSubjectRight::Rectification => write!(f, "Right to Rectification (Art. 16)"),
            DataSubjectRight::Erasure => write!(f, "Right to Erasure (Art. 17)"),
            DataSubjectRight::Restriction => write!(f, "Right to Restriction (Art. 18)"),
            DataSubjectRight::Portability => write!(f, "Right to Data Portability (Art. 20)"),
            DataSubjectRight::Objection => write!(f, "Right to Object (Art. 21)"),
            DataSubjectRight::AutomatedDecision => write!(f, "Automated Decision Rights (Art. 22)"),
        }
    }
}

/// Consent record
#[derive(Debug, Clone)]
pub struct ConsentRecord {
    pub id: String,
    pub data_subject_id: String,
    pub purpose: String,
    pub legal_basis: LegalBasis,
    pub data_categories: Vec<DataCategory>,
    pub given_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub withdrawn_at: Option<SystemTime>,
    pub version: u32,
    pub proof: ConsentProof,
}

/// Proof of consent collection
#[derive(Debug, Clone)]
pub struct ConsentProof {
    pub method: ConsentMethod,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub consent_text_hash: String,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentMethod {
    WebForm,
    MobileApp,
    Paper,
    Verbal,
    DoubleOptIn,
}

impl ConsentRecord {
    pub fn is_valid(&self) -> bool {
        // Not withdrawn
        if self.withdrawn_at.is_some() {
            return false;
        }

        // Not expired
        if let Some(expires) = self.expires_at {
            if SystemTime::now() > expires {
                return false;
            }
        }

        true
    }

    pub fn withdraw(&mut self) {
        self.withdrawn_at = Some(SystemTime::now());
    }
}

/// Data Subject Request (DSR)
#[derive(Debug, Clone)]
pub struct DataSubjectRequest {
    pub id: String,
    pub data_subject_id: String,
    pub right: DataSubjectRight,
    pub status: RequestStatus,
    pub submitted_at: SystemTime,
    pub acknowledged_at: Option<SystemTime>,
    pub completed_at: Option<SystemTime>,
    pub deadline: SystemTime,
    pub notes: Vec<String>,
    pub identity_verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestStatus {
    Pending,
    InProgress,
    IdentityVerificationRequired,
    Completed,
    Rejected,
    Extended,
}

impl DataSubjectRequest {
    pub fn new(data_subject_id: &str, right: DataSubjectRight) -> Self {
        let now = SystemTime::now();
        let deadline = now + Duration::from_secs(30 * 24 * 60 * 60); // 30 days

        Self {
            id: format!(
                "DSR-{}",
                now.duration_since(UNIX_EPOCH).unwrap().as_millis()
            ),
            data_subject_id: data_subject_id.into(),
            right,
            status: RequestStatus::Pending,
            submitted_at: now,
            acknowledged_at: None,
            completed_at: None,
            deadline,
            notes: vec![],
            identity_verified: false,
        }
    }

    pub fn acknowledge(&mut self) {
        self.acknowledged_at = Some(SystemTime::now());
        self.status = RequestStatus::InProgress;
    }

    pub fn complete(&mut self) {
        self.completed_at = Some(SystemTime::now());
        self.status = RequestStatus::Completed;
    }

    pub fn extend_deadline(&mut self, additional_days: u64) {
        self.deadline = self.deadline + Duration::from_secs(additional_days * 24 * 60 * 60);
        self.status = RequestStatus::Extended;
        self.notes
            .push(format!("Deadline extended by {} days", additional_days));
    }

    pub fn is_overdue(&self) -> bool {
        SystemTime::now() > self.deadline && self.status != RequestStatus::Completed
    }

    pub fn days_remaining(&self) -> i64 {
        let now = SystemTime::now();
        if let Ok(duration) = self.deadline.duration_since(now) {
            duration.as_secs() as i64 / (24 * 60 * 60)
        } else {
            -(now.duration_since(self.deadline).unwrap().as_secs() as i64 / (24 * 60 * 60))
        }
    }
}

/// Data retention policy
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    pub data_category: DataCategory,
    pub retention_period: Duration,
    pub legal_basis: LegalBasis,
    pub deletion_method: DeletionMethod,
    pub exceptions: Vec<RetentionException>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionMethod {
    HardDelete,
    SoftDelete,
    Anonymize,
    Pseudonymize,
    Archive,
}

#[derive(Debug, Clone)]
pub struct RetentionException {
    pub reason: String,
    pub legal_reference: String,
    pub extended_period: Option<Duration>,
}

/// Data processing record (Art. 30)
#[derive(Debug, Clone)]
pub struct ProcessingRecord {
    pub id: String,
    pub purpose: String,
    pub legal_basis: LegalBasis,
    pub data_categories: Vec<DataCategory>,
    pub data_subjects: Vec<String>,
    pub recipients: Vec<DataRecipient>,
    pub third_country_transfers: Vec<ThirdCountryTransfer>,
    pub retention_period: Duration,
    pub security_measures: Vec<String>,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

#[derive(Debug, Clone)]
pub struct DataRecipient {
    pub name: String,
    pub category: String,
    pub purpose: String,
    pub legal_basis: LegalBasis,
}

#[derive(Debug, Clone)]
pub struct ThirdCountryTransfer {
    pub country: String,
    pub recipient: String,
    pub safeguards: TransferSafeguard,
    pub derogation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferSafeguard {
    AdequacyDecision,
    StandardContractualClauses,
    BindingCorporateRules,
    Certification,
    CodeOfConduct,
    ExplicitConsent,
}

/// Data breach record
#[derive(Debug, Clone)]
pub struct DataBreach {
    pub id: String,
    pub detected_at: SystemTime,
    pub reported_to_authority_at: Option<SystemTime>,
    pub reported_to_subjects_at: Option<SystemTime>,
    pub nature: String,
    pub data_categories_affected: Vec<DataCategory>,
    pub approximate_subjects_affected: u64,
    pub consequences: Vec<String>,
    pub measures_taken: Vec<String>,
    pub severity: BreachSeverity,
    pub requires_notification: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BreachSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl DataBreach {
    pub fn new(nature: &str, subjects_affected: u64) -> Self {
        let now = SystemTime::now();
        Self {
            id: format!(
                "BREACH-{}",
                now.duration_since(UNIX_EPOCH).unwrap().as_millis()
            ),
            detected_at: now,
            reported_to_authority_at: None,
            reported_to_subjects_at: None,
            nature: nature.into(),
            data_categories_affected: vec![],
            approximate_subjects_affected: subjects_affected,
            consequences: vec![],
            measures_taken: vec![],
            severity: BreachSeverity::Medium,
            requires_notification: subjects_affected > 0,
        }
    }

    /// Must notify within 72 hours
    pub fn notification_deadline(&self) -> SystemTime {
        self.detected_at + Duration::from_secs(72 * 60 * 60)
    }

    pub fn is_notification_overdue(&self) -> bool {
        self.requires_notification
            && self.reported_to_authority_at.is_none()
            && SystemTime::now() > self.notification_deadline()
    }

    pub fn hours_until_deadline(&self) -> i64 {
        let now = SystemTime::now();
        let deadline = self.notification_deadline();
        if let Ok(duration) = deadline.duration_since(now) {
            duration.as_secs() as i64 / 3600
        } else {
            -(now.duration_since(deadline).unwrap().as_secs() as i64 / 3600)
        }
    }
}

/// Privacy Impact Assessment (DPIA)
#[derive(Debug, Clone)]
pub struct PrivacyImpactAssessment {
    pub id: String,
    pub project_name: String,
    pub description: String,
    pub data_categories: Vec<DataCategory>,
    pub processing_purposes: Vec<String>,
    pub risks: Vec<PrivacyRisk>,
    pub mitigations: Vec<String>,
    pub necessity_assessment: String,
    pub proportionality_assessment: String,
    pub dpo_opinion: Option<String>,
    pub created_at: SystemTime,
    pub approved: bool,
}

#[derive(Debug, Clone)]
pub struct PrivacyRisk {
    pub description: String,
    pub likelihood: RiskLevel,
    pub impact: RiskLevel,
    pub overall_risk: RiskLevel,
    pub mitigation: Option<String>,
    pub residual_risk: Option<RiskLevel>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    VeryHigh,
}

impl PrivacyRisk {
    pub fn calculate_overall_risk(likelihood: RiskLevel, impact: RiskLevel) -> RiskLevel {
        match (likelihood, impact) {
            (RiskLevel::VeryHigh, _) | (_, RiskLevel::VeryHigh) => RiskLevel::VeryHigh,
            (RiskLevel::High, RiskLevel::High) => RiskLevel::VeryHigh,
            (RiskLevel::High, _) | (_, RiskLevel::High) => RiskLevel::High,
            (RiskLevel::Medium, RiskLevel::Medium) => RiskLevel::Medium,
            (RiskLevel::Medium, _) | (_, RiskLevel::Medium) => RiskLevel::Medium,
            _ => RiskLevel::Low,
        }
    }
}

/// GDPR Compliance Manager
pub struct GdprComplianceManager {
    consents: Arc<RwLock<HashMap<String, Vec<ConsentRecord>>>>,
    requests: Arc<RwLock<Vec<DataSubjectRequest>>>,
    retention_policies: Arc<RwLock<HashMap<DataCategory, RetentionPolicy>>>,
    processing_records: Arc<RwLock<Vec<ProcessingRecord>>>,
    breaches: Arc<RwLock<Vec<DataBreach>>>,
    dpias: Arc<RwLock<Vec<PrivacyImpactAssessment>>>,
}

impl GdprComplianceManager {
    pub fn new() -> Self {
        Self {
            consents: Arc::new(RwLock::new(HashMap::new())),
            requests: Arc::new(RwLock::new(Vec::new())),
            retention_policies: Arc::new(RwLock::new(HashMap::new())),
            processing_records: Arc::new(RwLock::new(Vec::new())),
            breaches: Arc::new(RwLock::new(Vec::new())),
            dpias: Arc::new(RwLock::new(Vec::new())),
        }
    }

    // Consent Management

    pub fn record_consent(&self, consent: ConsentRecord) {
        let mut consents = self.consents.write().unwrap();
        consents
            .entry(consent.data_subject_id.clone())
            .or_insert_with(Vec::new)
            .push(consent);
    }

    pub fn withdraw_consent(&self, data_subject_id: &str, purpose: &str) -> bool {
        let mut consents = self.consents.write().unwrap();
        if let Some(records) = consents.get_mut(data_subject_id) {
            for record in records.iter_mut() {
                if record.purpose == purpose && record.is_valid() {
                    record.withdraw();
                    return true;
                }
            }
        }
        false
    }

    pub fn has_valid_consent(&self, data_subject_id: &str, purpose: &str) -> bool {
        let consents = self.consents.read().unwrap();
        if let Some(records) = consents.get(data_subject_id) {
            records.iter().any(|r| r.purpose == purpose && r.is_valid())
        } else {
            false
        }
    }

    pub fn get_consents(&self, data_subject_id: &str) -> Vec<ConsentRecord> {
        let consents = self.consents.read().unwrap();
        consents.get(data_subject_id).cloned().unwrap_or_default()
    }

    // Data Subject Requests

    pub fn submit_request(&self, request: DataSubjectRequest) -> String {
        let id = request.id.clone();
        let mut requests = self.requests.write().unwrap();
        requests.push(request);
        id
    }

    pub fn get_pending_requests(&self) -> Vec<DataSubjectRequest> {
        let requests = self.requests.read().unwrap();
        requests
            .iter()
            .filter(|r| r.status != RequestStatus::Completed && r.status != RequestStatus::Rejected)
            .cloned()
            .collect()
    }

    pub fn get_overdue_requests(&self) -> Vec<DataSubjectRequest> {
        let requests = self.requests.read().unwrap();
        requests
            .iter()
            .filter(|r| r.is_overdue())
            .cloned()
            .collect()
    }

    // Retention Policies

    pub fn set_retention_policy(&self, policy: RetentionPolicy) {
        let mut policies = self.retention_policies.write().unwrap();
        policies.insert(policy.data_category, policy);
    }

    pub fn get_retention_policy(&self, category: DataCategory) -> Option<RetentionPolicy> {
        let policies = self.retention_policies.read().unwrap();
        policies.get(&category).cloned()
    }

    // Data Breaches

    pub fn report_breach(&self, breach: DataBreach) -> String {
        let id = breach.id.clone();
        let mut breaches = self.breaches.write().unwrap();
        breaches.push(breach);
        id
    }

    pub fn get_unreported_breaches(&self) -> Vec<DataBreach> {
        let breaches = self.breaches.read().unwrap();
        breaches
            .iter()
            .filter(|b| b.requires_notification && b.reported_to_authority_at.is_none())
            .cloned()
            .collect()
    }

    // Processing Records (Art. 30)

    pub fn add_processing_record(&self, record: ProcessingRecord) {
        let mut records = self.processing_records.write().unwrap();
        records.push(record);
    }

    pub fn get_processing_records(&self) -> Vec<ProcessingRecord> {
        self.processing_records.read().unwrap().clone()
    }

    // DPIAs

    pub fn add_dpia(&self, dpia: PrivacyImpactAssessment) {
        let mut dpias = self.dpias.write().unwrap();
        dpias.push(dpia);
    }

    // Compliance Dashboard

    pub fn compliance_summary(&self) -> ComplianceSummary {
        let requests = self.requests.read().unwrap();
        let breaches = self.breaches.read().unwrap();
        let consents = self.consents.read().unwrap();

        let pending_requests = requests
            .iter()
            .filter(|r| r.status != RequestStatus::Completed)
            .count();

        let overdue_requests = requests.iter().filter(|r| r.is_overdue()).count();

        let unreported_breaches = breaches
            .iter()
            .filter(|b| b.requires_notification && b.reported_to_authority_at.is_none())
            .count();

        let total_data_subjects = consents.len();

        let active_consents: usize = consents
            .values()
            .map(|records| records.iter().filter(|r| r.is_valid()).count())
            .sum();

        ComplianceSummary {
            pending_requests,
            overdue_requests,
            unreported_breaches,
            total_data_subjects,
            active_consents,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ComplianceSummary {
    pub pending_requests: usize,
    pub overdue_requests: usize,
    pub unreported_breaches: usize,
    pub total_data_subjects: usize,
    pub active_consents: usize,
}

/// Data export for portability (Art. 20)
#[derive(Debug, Clone)]
pub struct DataExport {
    pub data_subject_id: String,
    pub exported_at: SystemTime,
    pub format: ExportFormat,
    pub data: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
    Xml,
}

impl DataExport {
    pub fn new(data_subject_id: &str, format: ExportFormat) -> Self {
        Self {
            data_subject_id: data_subject_id.into(),
            exported_at: SystemTime::now(),
            format,
            data: HashMap::new(),
        }
    }

    pub fn add_data(&mut self, category: &str, value: serde_json::Value) {
        self.data.insert(category.into(), value);
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.data).unwrap_or_default()
    }
}

/// Audit log entry for GDPR compliance
#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub timestamp: SystemTime,
    pub actor: String,
    pub action: AuditAction,
    pub data_subject_id: Option<String>,
    pub details: String,
    pub ip_address: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    ConsentGiven,
    ConsentWithdrawn,
    DataAccessed,
    DataModified,
    DataDeleted,
    DataExported,
    RequestSubmitted,
    RequestCompleted,
    BreachDetected,
    BreachReported,
}

// Simple JSON value for demonstration
mod serde_json {
    #[derive(Debug, Clone)]
    pub enum Value {
        String(String),
        Number(f64),
        Bool(bool),
        Array(Vec<Value>),
        Object(std::collections::HashMap<String, Value>),
        Null,
    }

    pub fn to_string_pretty(data: &std::collections::HashMap<String, Value>) -> Result<String, ()> {
        Ok(format!("{:?}", data))
    }
}

fn main() {
    println!("GDPR Compliance Framework\n");

    let manager = GdprComplianceManager::new();

    // Record consent
    println!("=== Consent Management ===\n");

    let consent = ConsentRecord {
        id: "CONSENT-001".into(),
        data_subject_id: "user-123".into(),
        purpose: "Marketing emails".into(),
        legal_basis: LegalBasis::Consent,
        data_categories: vec![DataCategory::Personal],
        given_at: SystemTime::now(),
        expires_at: Some(SystemTime::now() + Duration::from_secs(365 * 24 * 60 * 60)),
        withdrawn_at: None,
        version: 1,
        proof: ConsentProof {
            method: ConsentMethod::DoubleOptIn,
            ip_address: Some("192.168.1.1".into()),
            user_agent: Some("Mozilla/5.0".into()),
            consent_text_hash: "sha256:abc123...".into(),
            signature: None,
        },
    };

    manager.record_consent(consent);
    println!("Consent recorded for user-123");
    println!(
        "Has marketing consent: {}",
        manager.has_valid_consent("user-123", "Marketing emails")
    );

    // Data Subject Request
    println!("\n=== Data Subject Requests ===\n");

    let mut request = DataSubjectRequest::new("user-123", DataSubjectRight::Access);
    request.acknowledge();
    println!("Request ID: {}", request.id);
    println!("Status: {:?}", request.status);
    println!("Days remaining: {}", request.days_remaining());

    manager.submit_request(request);

    // Data Breach
    println!("\n=== Data Breach Handling ===\n");

    let breach = DataBreach::new("Unauthorized access to user database", 1500);
    println!("Breach ID: {}", breach.id);
    println!("Severity: {:?}", breach.severity);
    println!(
        "Hours until notification deadline: {}",
        breach.hours_until_deadline()
    );
    println!("Notification overdue: {}", breach.is_notification_overdue());

    manager.report_breach(breach);

    // Retention Policy
    println!("\n=== Retention Policies ===\n");

    let policy = RetentionPolicy {
        data_category: DataCategory::Personal,
        retention_period: Duration::from_secs(365 * 24 * 60 * 60 * 3), // 3 years
        legal_basis: LegalBasis::Contract,
        deletion_method: DeletionMethod::Anonymize,
        exceptions: vec![RetentionException {
            reason: "Tax records".into(),
            legal_reference: "Tax Code Section 123".into(),
            extended_period: Some(Duration::from_secs(365 * 24 * 60 * 60 * 7)), // 7 years
        }],
    };

    manager.set_retention_policy(policy.clone());
    println!(
        "Retention policy for {:?}: {} days",
        policy.data_category,
        policy.retention_period.as_secs() / (24 * 60 * 60)
    );

    // Privacy Impact Assessment
    println!("\n=== Privacy Impact Assessment ===\n");

    let risk = PrivacyRisk {
        description: "Unauthorized access to sensitive data".into(),
        likelihood: RiskLevel::Medium,
        impact: RiskLevel::High,
        overall_risk: PrivacyRisk::calculate_overall_risk(RiskLevel::Medium, RiskLevel::High),
        mitigation: Some("Implement encryption at rest".into()),
        residual_risk: Some(RiskLevel::Low),
    };

    println!("Risk: {}", risk.description);
    println!("Overall risk level: {:?}", risk.overall_risk);

    // Compliance Summary
    println!("\n=== Compliance Summary ===\n");

    let summary = manager.compliance_summary();
    println!("Pending requests: {}", summary.pending_requests);
    println!("Overdue requests: {}", summary.overdue_requests);
    println!("Unreported breaches: {}", summary.unreported_breaches);
    println!("Total data subjects: {}", summary.total_data_subjects);
    println!("Active consents: {}", summary.active_consents);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legal_basis_display() {
        assert!(LegalBasis::Consent.to_string().contains("Art. 6(1)(a)"));
        assert!(LegalBasis::Contract.to_string().contains("Art. 6(1)(b)"));
    }

    #[test]
    fn test_data_category_special() {
        assert!(DataCategory::Health.is_special_category());
        assert!(DataCategory::Biometric.is_special_category());
        assert!(!DataCategory::Personal.is_special_category());
    }

    #[test]
    fn test_data_category_explicit_consent() {
        assert!(DataCategory::Sensitive.requires_explicit_consent());
        assert!(!DataCategory::Financial.requires_explicit_consent());
    }

    #[test]
    fn test_consent_validity() {
        let consent = ConsentRecord {
            id: "test".into(),
            data_subject_id: "user".into(),
            purpose: "test".into(),
            legal_basis: LegalBasis::Consent,
            data_categories: vec![],
            given_at: SystemTime::now(),
            expires_at: Some(SystemTime::now() + Duration::from_secs(3600)),
            withdrawn_at: None,
            version: 1,
            proof: ConsentProof {
                method: ConsentMethod::WebForm,
                ip_address: None,
                user_agent: None,
                consent_text_hash: "hash".into(),
                signature: None,
            },
        };

        assert!(consent.is_valid());
    }

    #[test]
    fn test_consent_withdrawn() {
        let mut consent = ConsentRecord {
            id: "test".into(),
            data_subject_id: "user".into(),
            purpose: "test".into(),
            legal_basis: LegalBasis::Consent,
            data_categories: vec![],
            given_at: SystemTime::now(),
            expires_at: None,
            withdrawn_at: None,
            version: 1,
            proof: ConsentProof {
                method: ConsentMethod::WebForm,
                ip_address: None,
                user_agent: None,
                consent_text_hash: "hash".into(),
                signature: None,
            },
        };

        consent.withdraw();
        assert!(!consent.is_valid());
    }

    #[test]
    fn test_dsr_creation() {
        let request = DataSubjectRequest::new("user-123", DataSubjectRight::Access);
        assert_eq!(request.status, RequestStatus::Pending);
        assert!(!request.identity_verified);
        assert!(request.days_remaining() > 25); // Should be around 30 days
    }

    #[test]
    fn test_dsr_acknowledge() {
        let mut request = DataSubjectRequest::new("user-123", DataSubjectRight::Erasure);
        request.acknowledge();
        assert_eq!(request.status, RequestStatus::InProgress);
        assert!(request.acknowledged_at.is_some());
    }

    #[test]
    fn test_dsr_extend() {
        let mut request = DataSubjectRequest::new("user-123", DataSubjectRight::Portability);
        let original_days = request.days_remaining();
        request.extend_deadline(30);
        assert!(request.days_remaining() > original_days);
        assert_eq!(request.status, RequestStatus::Extended);
    }

    #[test]
    fn test_breach_notification_deadline() {
        let breach = DataBreach::new("Test breach", 100);
        let deadline_hours = breach.hours_until_deadline();
        assert!(deadline_hours > 70 && deadline_hours <= 72);
    }

    #[test]
    fn test_privacy_risk_calculation() {
        assert_eq!(
            PrivacyRisk::calculate_overall_risk(RiskLevel::High, RiskLevel::High),
            RiskLevel::VeryHigh
        );
        assert_eq!(
            PrivacyRisk::calculate_overall_risk(RiskLevel::Low, RiskLevel::Low),
            RiskLevel::Low
        );
        assert_eq!(
            PrivacyRisk::calculate_overall_risk(RiskLevel::Medium, RiskLevel::High),
            RiskLevel::High
        );
    }

    #[test]
    fn test_compliance_manager_consent() {
        let manager = GdprComplianceManager::new();

        let consent = ConsentRecord {
            id: "test".into(),
            data_subject_id: "user".into(),
            purpose: "marketing".into(),
            legal_basis: LegalBasis::Consent,
            data_categories: vec![],
            given_at: SystemTime::now(),
            expires_at: None,
            withdrawn_at: None,
            version: 1,
            proof: ConsentProof {
                method: ConsentMethod::WebForm,
                ip_address: None,
                user_agent: None,
                consent_text_hash: "hash".into(),
                signature: None,
            },
        };

        manager.record_consent(consent);
        assert!(manager.has_valid_consent("user", "marketing"));
        assert!(!manager.has_valid_consent("user", "analytics"));
    }

    #[test]
    fn test_compliance_manager_withdraw() {
        let manager = GdprComplianceManager::new();

        let consent = ConsentRecord {
            id: "test".into(),
            data_subject_id: "user".into(),
            purpose: "marketing".into(),
            legal_basis: LegalBasis::Consent,
            data_categories: vec![],
            given_at: SystemTime::now(),
            expires_at: None,
            withdrawn_at: None,
            version: 1,
            proof: ConsentProof {
                method: ConsentMethod::WebForm,
                ip_address: None,
                user_agent: None,
                consent_text_hash: "hash".into(),
                signature: None,
            },
        };

        manager.record_consent(consent);
        assert!(manager.withdraw_consent("user", "marketing"));
        assert!(!manager.has_valid_consent("user", "marketing"));
    }

    #[test]
    fn test_data_export() {
        let mut export = DataExport::new("user-123", ExportFormat::Json);
        export.add_data("profile", serde_json::Value::String("test".into()));
        assert!(!export.data.is_empty());
    }

    #[test]
    fn test_transfer_safeguards() {
        let transfer = ThirdCountryTransfer {
            country: "US".into(),
            recipient: "Cloud Provider".into(),
            safeguards: TransferSafeguard::StandardContractualClauses,
            derogation: None,
        };

        assert_eq!(
            transfer.safeguards,
            TransferSafeguard::StandardContractualClauses
        );
    }
}
