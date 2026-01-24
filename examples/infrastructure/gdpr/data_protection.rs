//! GDPR Data Protection Implementation
//!
//! This example demonstrates comprehensive GDPR compliance patterns including
//! data protection, consent management, data subject rights, and audit logging
//! for Rust applications.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// Personal Data Classification
// ============================================================================

/// Classification of personal data according to GDPR
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DataCategory {
    /// Basic identifying information (name, email, phone)
    BasicIdentity,
    /// Financial data (bank accounts, payment info)
    Financial,
    /// Health and medical data
    Health,
    /// Biometric data
    Biometric,
    /// Genetic data
    Genetic,
    /// Racial or ethnic origin
    RacialEthnic,
    /// Political opinions
    Political,
    /// Religious or philosophical beliefs
    Religious,
    /// Trade union membership
    TradeUnion,
    /// Sexual orientation
    SexualOrientation,
    /// Criminal records
    Criminal,
    /// Location data
    Location,
    /// Online identifiers (IP, cookies)
    OnlineIdentifiers,
    /// Behavioral data
    Behavioral,
    /// Employment data
    Employment,
    /// Communication content
    Communications,
    /// Children's data
    ChildData,
}

impl DataCategory {
    pub fn is_special_category(&self) -> bool {
        matches!(
            self,
            DataCategory::Health
                | DataCategory::Biometric
                | DataCategory::Genetic
                | DataCategory::RacialEthnic
                | DataCategory::Political
                | DataCategory::Religious
                | DataCategory::TradeUnion
                | DataCategory::SexualOrientation
                | DataCategory::Criminal
        )
    }

    pub fn requires_explicit_consent(&self) -> bool {
        self.is_special_category() || *self == DataCategory::ChildData
    }

    pub fn retention_period(&self) -> Duration {
        match self {
            DataCategory::Financial => Duration::from_secs(7 * 365 * 24 * 3600), // 7 years
            DataCategory::Employment => Duration::from_secs(6 * 365 * 24 * 3600), // 6 years
            DataCategory::Health => Duration::from_secs(10 * 365 * 24 * 3600),   // 10 years
            DataCategory::Criminal => Duration::from_secs(5 * 365 * 24 * 3600),  // 5 years
            DataCategory::OnlineIdentifiers => Duration::from_secs(30 * 24 * 3600), // 30 days
            DataCategory::Location => Duration::from_secs(90 * 24 * 3600),       // 90 days
            DataCategory::Behavioral => Duration::from_secs(180 * 24 * 3600),    // 180 days
            _ => Duration::from_secs(3 * 365 * 24 * 3600),                       // 3 years default
        }
    }
}

impl fmt::Display for DataCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataCategory::BasicIdentity => write!(f, "Basic Identity"),
            DataCategory::Financial => write!(f, "Financial"),
            DataCategory::Health => write!(f, "Health"),
            DataCategory::Biometric => write!(f, "Biometric"),
            DataCategory::Genetic => write!(f, "Genetic"),
            DataCategory::RacialEthnic => write!(f, "Racial/Ethnic Origin"),
            DataCategory::Political => write!(f, "Political Opinions"),
            DataCategory::Religious => write!(f, "Religious Beliefs"),
            DataCategory::TradeUnion => write!(f, "Trade Union Membership"),
            DataCategory::SexualOrientation => write!(f, "Sexual Orientation"),
            DataCategory::Criminal => write!(f, "Criminal Records"),
            DataCategory::Location => write!(f, "Location"),
            DataCategory::OnlineIdentifiers => write!(f, "Online Identifiers"),
            DataCategory::Behavioral => write!(f, "Behavioral"),
            DataCategory::Employment => write!(f, "Employment"),
            DataCategory::Communications => write!(f, "Communications"),
            DataCategory::ChildData => write!(f, "Child Data"),
        }
    }
}

/// Personal data field with metadata
#[derive(Clone, Debug)]
pub struct PersonalDataField {
    pub name: String,
    pub category: DataCategory,
    pub encrypted: bool,
    pub pseudonymized: bool,
    pub retention_override: Option<Duration>,
    pub created_at: SystemTime,
    pub last_accessed: SystemTime,
}

// ============================================================================
// Lawful Basis for Processing
// ============================================================================

/// GDPR Article 6 - Lawful basis for processing
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LawfulBasis {
    /// Article 6(1)(a) - Consent
    Consent {
        consent_id: String,
        timestamp: SystemTime,
        explicit: bool,
    },
    /// Article 6(1)(b) - Contractual necessity
    Contract {
        contract_id: String,
        purpose: String,
    },
    /// Article 6(1)(c) - Legal obligation
    LegalObligation {
        regulation: String,
        requirement: String,
    },
    /// Article 6(1)(d) - Vital interests
    VitalInterests { reason: String },
    /// Article 6(1)(e) - Public task
    PublicTask { authority: String, task: String },
    /// Article 6(1)(f) - Legitimate interests
    LegitimateInterests {
        interest: String,
        balancing_test_passed: bool,
    },
}

impl LawfulBasis {
    pub fn is_valid(&self) -> bool {
        match self {
            LawfulBasis::Consent { .. } => true,
            LawfulBasis::Contract { contract_id, .. } => !contract_id.is_empty(),
            LawfulBasis::LegalObligation { regulation, .. } => !regulation.is_empty(),
            LawfulBasis::LegitimateInterests {
                balancing_test_passed,
                ..
            } => *balancing_test_passed,
            _ => true,
        }
    }

    pub fn description(&self) -> String {
        match self {
            LawfulBasis::Consent { consent_id, .. } => {
                format!("Consent (ID: {})", consent_id)
            }
            LawfulBasis::Contract { purpose, .. } => {
                format!("Contractual necessity: {}", purpose)
            }
            LawfulBasis::LegalObligation { regulation, .. } => {
                format!("Legal obligation: {}", regulation)
            }
            LawfulBasis::VitalInterests { reason } => {
                format!("Vital interests: {}", reason)
            }
            LawfulBasis::PublicTask { task, .. } => {
                format!("Public task: {}", task)
            }
            LawfulBasis::LegitimateInterests { interest, .. } => {
                format!("Legitimate interests: {}", interest)
            }
        }
    }
}

// ============================================================================
// Consent Management
// ============================================================================

/// User consent record
#[derive(Clone, Debug)]
pub struct Consent {
    pub id: String,
    pub data_subject_id: String,
    pub purpose: String,
    pub data_categories: HashSet<DataCategory>,
    pub third_parties: Vec<String>,
    pub granted_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub withdrawn_at: Option<SystemTime>,
    pub explicit: bool,
    pub source: ConsentSource,
    pub version: String,
}

#[derive(Clone, Debug)]
pub enum ConsentSource {
    WebForm { form_id: String, page_url: String },
    MobileApp { app_version: String },
    Paper { document_ref: String },
    Api { endpoint: String },
    DoubleOptIn { confirmation_token: String },
}

impl Consent {
    pub fn is_valid(&self) -> bool {
        if self.withdrawn_at.is_some() {
            return false;
        }

        if let Some(expires_at) = self.expires_at {
            if SystemTime::now() > expires_at {
                return false;
            }
        }

        true
    }

    pub fn covers_category(&self, category: &DataCategory) -> bool {
        self.data_categories.contains(category) && self.is_valid()
    }

    pub fn withdraw(&mut self) {
        self.withdrawn_at = Some(SystemTime::now());
    }
}

/// Consent manager
pub struct ConsentManager {
    consents: Arc<RwLock<HashMap<String, Vec<Consent>>>>,
    audit_log: Arc<RwLock<Vec<AuditEntry>>>,
}

impl ConsentManager {
    pub fn new() -> Self {
        Self {
            consents: Arc::new(RwLock::new(HashMap::new())),
            audit_log: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn record_consent(&self, consent: Consent) -> Result<String, GdprError> {
        // Validate consent
        if consent.data_subject_id.is_empty() {
            return Err(GdprError::InvalidConsent(
                "Missing data subject ID".to_string(),
            ));
        }

        // For special categories, consent must be explicit
        let has_special = consent
            .data_categories
            .iter()
            .any(|c| c.is_special_category());
        if has_special && !consent.explicit {
            return Err(GdprError::InvalidConsent(
                "Special category data requires explicit consent".to_string(),
            ));
        }

        let consent_id = consent.id.clone();

        // Store consent
        let mut consents = self.consents.write().unwrap();
        consents
            .entry(consent.data_subject_id.clone())
            .or_insert_with(Vec::new)
            .push(consent.clone());

        // Audit log
        self.log_audit(AuditEntry {
            timestamp: SystemTime::now(),
            action: AuditAction::ConsentGranted,
            data_subject_id: Some(consent.data_subject_id),
            details: format!("Consent {} granted for: {}", consent_id, consent.purpose),
            actor: None,
            ip_address: None,
        });

        Ok(consent_id)
    }

    pub fn withdraw_consent(
        &self,
        data_subject_id: &str,
        consent_id: &str,
    ) -> Result<(), GdprError> {
        let mut consents = self.consents.write().unwrap();

        if let Some(user_consents) = consents.get_mut(data_subject_id) {
            for consent in user_consents.iter_mut() {
                if consent.id == consent_id {
                    consent.withdraw();

                    // Audit log
                    self.log_audit(AuditEntry {
                        timestamp: SystemTime::now(),
                        action: AuditAction::ConsentWithdrawn,
                        data_subject_id: Some(data_subject_id.to_string()),
                        details: format!("Consent {} withdrawn", consent_id),
                        actor: None,
                        ip_address: None,
                    });

                    return Ok(());
                }
            }
        }

        Err(GdprError::ConsentNotFound(consent_id.to_string()))
    }

    pub fn check_consent(
        &self,
        data_subject_id: &str,
        purpose: &str,
        category: &DataCategory,
    ) -> bool {
        let consents = self.consents.read().unwrap();

        if let Some(user_consents) = consents.get(data_subject_id) {
            for consent in user_consents {
                if consent.is_valid()
                    && consent.purpose == purpose
                    && consent.covers_category(category)
                {
                    return true;
                }
            }
        }

        false
    }

    pub fn get_consents(&self, data_subject_id: &str) -> Vec<Consent> {
        let consents = self.consents.read().unwrap();
        consents.get(data_subject_id).cloned().unwrap_or_default()
    }

    fn log_audit(&self, entry: AuditEntry) {
        let mut log = self.audit_log.write().unwrap();
        log.push(entry);
    }
}

// ============================================================================
// Data Subject Rights
// ============================================================================

/// Data subject request types (GDPR Articles 15-22)
#[derive(Clone, Debug)]
pub enum DataSubjectRequest {
    /// Article 15 - Right of access
    Access,
    /// Article 16 - Right to rectification
    Rectification {
        field: String,
        old_value: String,
        new_value: String,
    },
    /// Article 17 - Right to erasure
    Erasure { reason: ErasureReason },
    /// Article 18 - Right to restriction
    Restriction { reason: String },
    /// Article 20 - Right to data portability
    Portability { format: PortabilityFormat },
    /// Article 21 - Right to object
    Objection {
        processing_type: String,
        grounds: String,
    },
    /// Article 22 - Automated decision-making
    AutomatedDecisionReview { decision_id: String },
}

#[derive(Clone, Debug)]
pub enum ErasureReason {
    NoLongerNecessary,
    ConsentWithdrawn,
    ObjectsToProcessing,
    UnlawfulProcessing,
    LegalObligation,
    ChildData,
}

#[derive(Clone, Debug)]
pub enum PortabilityFormat {
    Json,
    Csv,
    Xml,
    Custom(String),
}

/// Data subject request handler
#[derive(Clone, Debug)]
pub struct DataSubjectRequestRecord {
    pub id: String,
    pub data_subject_id: String,
    pub request_type: DataSubjectRequest,
    pub received_at: SystemTime,
    pub deadline: SystemTime,
    pub status: RequestStatus,
    pub response: Option<String>,
    pub completed_at: Option<SystemTime>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RequestStatus {
    Received,
    Verified,
    Processing,
    Completed,
    Rejected { reason: String },
    Extended { new_deadline: SystemTime },
}

pub struct DataSubjectRightsHandler {
    requests: Arc<RwLock<HashMap<String, DataSubjectRequestRecord>>>,
    data_store: Arc<RwLock<HashMap<String, PersonalDataRecord>>>,
    consent_manager: Arc<ConsentManager>,
}

impl DataSubjectRightsHandler {
    pub fn new(consent_manager: Arc<ConsentManager>) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            data_store: Arc::new(RwLock::new(HashMap::new())),
            consent_manager,
        }
    }

    pub fn submit_request(
        &self,
        data_subject_id: &str,
        request_type: DataSubjectRequest,
    ) -> Result<String, GdprError> {
        let request_id = format!("DSR-{}", generate_id());

        // GDPR requires response within 30 days
        let deadline = SystemTime::now() + Duration::from_secs(30 * 24 * 3600);

        let record = DataSubjectRequestRecord {
            id: request_id.clone(),
            data_subject_id: data_subject_id.to_string(),
            request_type,
            received_at: SystemTime::now(),
            deadline,
            status: RequestStatus::Received,
            response: None,
            completed_at: None,
        };

        let mut requests = self.requests.write().unwrap();
        requests.insert(request_id.clone(), record);

        Ok(request_id)
    }

    pub fn process_access_request(
        &self,
        request_id: &str,
    ) -> Result<PersonalDataExport, GdprError> {
        let mut requests = self.requests.write().unwrap();
        let request = requests
            .get_mut(request_id)
            .ok_or_else(|| GdprError::RequestNotFound(request_id.to_string()))?;

        request.status = RequestStatus::Processing;

        let data_store = self.data_store.read().unwrap();
        let personal_data = data_store
            .get(&request.data_subject_id)
            .cloned()
            .unwrap_or_else(|| PersonalDataRecord::empty(&request.data_subject_id));

        let consents = self.consent_manager.get_consents(&request.data_subject_id);

        let export = PersonalDataExport {
            data_subject_id: request.data_subject_id.clone(),
            exported_at: SystemTime::now(),
            data: personal_data,
            consents,
            processing_activities: Vec::new(),
        };

        request.status = RequestStatus::Completed;
        request.completed_at = Some(SystemTime::now());

        Ok(export)
    }

    pub fn process_erasure_request(&self, request_id: &str) -> Result<ErasureReport, GdprError> {
        let mut requests = self.requests.write().unwrap();
        let request = requests
            .get_mut(request_id)
            .ok_or_else(|| GdprError::RequestNotFound(request_id.to_string()))?;

        request.status = RequestStatus::Processing;

        let data_subject_id = request.data_subject_id.clone();

        // Check for legal holds
        // In production, check for legal obligations preventing erasure

        // Erase data
        let mut data_store = self.data_store.write().unwrap();
        let erased = data_store.remove(&data_subject_id).is_some();

        let report = ErasureReport {
            request_id: request_id.to_string(),
            data_subject_id,
            erased_at: SystemTime::now(),
            categories_erased: if erased {
                vec![DataCategory::BasicIdentity, DataCategory::Employment]
            } else {
                vec![]
            },
            third_party_notifications: vec![],
            retention_exceptions: vec![],
        };

        request.status = RequestStatus::Completed;
        request.completed_at = Some(SystemTime::now());

        Ok(report)
    }

    pub fn process_portability_request(
        &self,
        request_id: &str,
        format: PortabilityFormat,
    ) -> Result<Vec<u8>, GdprError> {
        let requests = self.requests.read().unwrap();
        let request = requests
            .get(request_id)
            .ok_or_else(|| GdprError::RequestNotFound(request_id.to_string()))?;

        let data_store = self.data_store.read().unwrap();
        let personal_data = data_store
            .get(&request.data_subject_id)
            .ok_or_else(|| GdprError::DataNotFound(request.data_subject_id.clone()))?;

        let output = match format {
            PortabilityFormat::Json => format!(
                "{{\"data_subject_id\": \"{}\", \"fields\": {}}}",
                personal_data.data_subject_id,
                personal_data.fields.len()
            )
            .into_bytes(),
            PortabilityFormat::Csv => {
                let mut csv = String::from("field_name,category,value\n");
                for (name, field) in &personal_data.fields {
                    csv.push_str(&format!("{},{},***\n", name, field.category));
                }
                csv.into_bytes()
            }
            PortabilityFormat::Xml => format!(
                "<?xml version=\"1.0\"?><personalData><subject>{}</subject></personalData>",
                personal_data.data_subject_id
            )
            .into_bytes(),
            PortabilityFormat::Custom(ref fmt) => format!(
                "Custom format: {} - Data for {}",
                fmt, personal_data.data_subject_id
            )
            .into_bytes(),
        };

        Ok(output)
    }
}

// ============================================================================
// Personal Data Records
// ============================================================================

/// Complete personal data record
#[derive(Clone, Debug)]
pub struct PersonalDataRecord {
    pub data_subject_id: String,
    pub fields: HashMap<String, PersonalDataField>,
    pub processing_history: Vec<ProcessingActivity>,
    pub created_at: SystemTime,
    pub last_modified: SystemTime,
}

impl PersonalDataRecord {
    pub fn empty(data_subject_id: &str) -> Self {
        Self {
            data_subject_id: data_subject_id.to_string(),
            fields: HashMap::new(),
            processing_history: Vec::new(),
            created_at: SystemTime::now(),
            last_modified: SystemTime::now(),
        }
    }

    pub fn add_field(&mut self, name: &str, category: DataCategory, encrypted: bool) {
        self.fields.insert(
            name.to_string(),
            PersonalDataField {
                name: name.to_string(),
                category,
                encrypted,
                pseudonymized: false,
                retention_override: None,
                created_at: SystemTime::now(),
                last_accessed: SystemTime::now(),
            },
        );
        self.last_modified = SystemTime::now();
    }

    pub fn pseudonymize(&mut self) -> String {
        let pseudonym = format!("PSE-{}", generate_id());

        for field in self.fields.values_mut() {
            field.pseudonymized = true;
        }

        pseudonym
    }
}

/// Processing activity log entry
#[derive(Clone, Debug)]
pub struct ProcessingActivity {
    pub id: String,
    pub timestamp: SystemTime,
    pub activity_type: ProcessingType,
    pub lawful_basis: LawfulBasis,
    pub data_categories: Vec<DataCategory>,
    pub purpose: String,
    pub recipient: Option<String>,
    pub retention_period: Duration,
}

#[derive(Clone, Debug)]
pub enum ProcessingType {
    Collection,
    Storage,
    Use,
    Analysis,
    Sharing,
    Transfer,
    Deletion,
}

// ============================================================================
// Data Export
// ============================================================================

/// Personal data export for access requests
#[derive(Clone, Debug)]
pub struct PersonalDataExport {
    pub data_subject_id: String,
    pub exported_at: SystemTime,
    pub data: PersonalDataRecord,
    pub consents: Vec<Consent>,
    pub processing_activities: Vec<ProcessingActivity>,
}

impl PersonalDataExport {
    pub fn to_json(&self) -> String {
        let mut json = String::from("{\n");
        json.push_str(&format!(
            "  \"data_subject_id\": \"{}\",\n",
            self.data_subject_id
        ));
        json.push_str(&format!(
            "  \"exported_at\": {},\n",
            self.exported_at
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        ));
        json.push_str(&format!(
            "  \"total_fields\": {},\n",
            self.data.fields.len()
        ));
        json.push_str(&format!("  \"total_consents\": {},\n", self.consents.len()));
        json.push_str(&format!(
            "  \"processing_activities\": {}\n",
            self.processing_activities.len()
        ));
        json.push_str("}\n");
        json
    }
}

/// Erasure report
#[derive(Clone, Debug)]
pub struct ErasureReport {
    pub request_id: String,
    pub data_subject_id: String,
    pub erased_at: SystemTime,
    pub categories_erased: Vec<DataCategory>,
    pub third_party_notifications: Vec<ThirdPartyNotification>,
    pub retention_exceptions: Vec<RetentionException>,
}

#[derive(Clone, Debug)]
pub struct ThirdPartyNotification {
    pub recipient: String,
    pub notified_at: SystemTime,
    pub acknowledged: bool,
}

#[derive(Clone, Debug)]
pub struct RetentionException {
    pub category: DataCategory,
    pub reason: String,
    pub legal_basis: String,
    pub retention_until: SystemTime,
}

// ============================================================================
// Audit Logging
// ============================================================================

/// Audit log entry
#[derive(Clone, Debug)]
pub struct AuditEntry {
    pub timestamp: SystemTime,
    pub action: AuditAction,
    pub data_subject_id: Option<String>,
    pub details: String,
    pub actor: Option<String>,
    pub ip_address: Option<String>,
}

#[derive(Clone, Debug)]
pub enum AuditAction {
    DataAccess,
    DataModification,
    DataDeletion,
    ConsentGranted,
    ConsentWithdrawn,
    DataExport,
    AccessRequest,
    ProcessingActivity,
    SecurityEvent,
    BreachDetected,
}

/// Audit logger
pub struct AuditLogger {
    entries: Arc<RwLock<Vec<AuditEntry>>>,
    retention_days: u64,
}

impl AuditLogger {
    pub fn new(retention_days: u64) -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
            retention_days,
        }
    }

    pub fn log(&self, entry: AuditEntry) {
        let mut entries = self.entries.write().unwrap();
        entries.push(entry);
    }

    pub fn get_entries(&self, data_subject_id: Option<&str>) -> Vec<AuditEntry> {
        let entries = self.entries.read().unwrap();
        entries
            .iter()
            .filter(|e| {
                data_subject_id.is_none() || e.data_subject_id.as_deref() == data_subject_id
            })
            .cloned()
            .collect()
    }

    pub fn cleanup_old_entries(&self) {
        let cutoff = SystemTime::now() - Duration::from_secs(self.retention_days * 24 * 3600);
        let mut entries = self.entries.write().unwrap();
        entries.retain(|e| e.timestamp > cutoff);
    }

    pub fn generate_report(&self, start: SystemTime, end: SystemTime) -> AuditReport {
        let entries = self.entries.read().unwrap();
        let filtered: Vec<_> = entries
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .cloned()
            .collect();

        let mut by_action: HashMap<String, usize> = HashMap::new();
        for entry in &filtered {
            *by_action.entry(format!("{:?}", entry.action)).or_insert(0) += 1;
        }

        AuditReport {
            period_start: start,
            period_end: end,
            total_entries: filtered.len(),
            by_action,
            entries: filtered,
        }
    }
}

#[derive(Debug)]
pub struct AuditReport {
    pub period_start: SystemTime,
    pub period_end: SystemTime,
    pub total_entries: usize,
    pub by_action: HashMap<String, usize>,
    pub entries: Vec<AuditEntry>,
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug)]
pub enum GdprError {
    InvalidConsent(String),
    ConsentNotFound(String),
    RequestNotFound(String),
    DataNotFound(String),
    ProcessingNotAllowed(String),
    RetentionPeriodViolation(String),
    InsufficientLawfulBasis(String),
}

impl fmt::Display for GdprError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GdprError::InvalidConsent(msg) => write!(f, "Invalid consent: {}", msg),
            GdprError::ConsentNotFound(id) => write!(f, "Consent not found: {}", id),
            GdprError::RequestNotFound(id) => write!(f, "Request not found: {}", id),
            GdprError::DataNotFound(id) => write!(f, "Data not found for: {}", id),
            GdprError::ProcessingNotAllowed(msg) => write!(f, "Processing not allowed: {}", msg),
            GdprError::RetentionPeriodViolation(msg) => write!(f, "Retention violation: {}", msg),
            GdprError::InsufficientLawfulBasis(msg) => {
                write!(f, "Insufficient lawful basis: {}", msg)
            }
        }
    }
}

impl std::error::Error for GdprError {}

// ============================================================================
// Utility Functions
// ============================================================================

fn generate_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:016x}", timestamp)
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== GDPR Data Protection Implementation ===\n");

    // Initialize components
    let consent_manager = Arc::new(ConsentManager::new());
    let rights_handler = DataSubjectRightsHandler::new(consent_manager.clone());
    let audit_logger = AuditLogger::new(365);

    // Example user
    let user_id = "user-12345";

    println!("1. Recording Consent");
    println!("─────────────────────────────────────────────────");

    // Record marketing consent
    let mut categories = HashSet::new();
    categories.insert(DataCategory::BasicIdentity);
    categories.insert(DataCategory::Behavioral);

    let consent = Consent {
        id: "consent-001".to_string(),
        data_subject_id: user_id.to_string(),
        purpose: "Marketing communications".to_string(),
        data_categories: categories,
        third_parties: vec!["Analytics Provider".to_string()],
        granted_at: SystemTime::now(),
        expires_at: Some(SystemTime::now() + Duration::from_secs(365 * 24 * 3600)),
        withdrawn_at: None,
        explicit: false,
        source: ConsentSource::WebForm {
            form_id: "signup-form".to_string(),
            page_url: "https://example.com/signup".to_string(),
        },
        version: "1.0".to_string(),
    };

    match consent_manager.record_consent(consent) {
        Ok(id) => println!("  ✓ Consent recorded: {}", id),
        Err(e) => println!("  ✗ Error: {}", e),
    }

    // Record health data consent (explicit)
    let mut health_categories = HashSet::new();
    health_categories.insert(DataCategory::Health);

    let health_consent = Consent {
        id: "consent-002".to_string(),
        data_subject_id: user_id.to_string(),
        purpose: "Health monitoring".to_string(),
        data_categories: health_categories,
        third_parties: vec![],
        granted_at: SystemTime::now(),
        expires_at: None,
        withdrawn_at: None,
        explicit: true, // Required for special categories
        source: ConsentSource::DoubleOptIn {
            confirmation_token: "confirmed-xyz".to_string(),
        },
        version: "1.0".to_string(),
    };

    match consent_manager.record_consent(health_consent) {
        Ok(id) => println!("  ✓ Health consent recorded: {}", id),
        Err(e) => println!("  ✗ Error: {}", e),
    }

    println!();

    // Check consent
    println!("2. Checking Consent");
    println!("─────────────────────────────────────────────────");

    let has_marketing = consent_manager.check_consent(
        user_id,
        "Marketing communications",
        &DataCategory::BasicIdentity,
    );
    println!(
        "  Marketing consent: {}",
        if has_marketing {
            "✓ Valid"
        } else {
            "✗ Invalid"
        }
    );

    let has_health =
        consent_manager.check_consent(user_id, "Health monitoring", &DataCategory::Health);
    println!(
        "  Health consent: {}",
        if has_health {
            "✓ Valid"
        } else {
            "✗ Invalid"
        }
    );

    println!();

    // Data subject requests
    println!("3. Data Subject Rights");
    println!("─────────────────────────────────────────────────");

    // Access request
    let access_request = rights_handler
        .submit_request(user_id, DataSubjectRequest::Access)
        .unwrap();
    println!("  ✓ Access request submitted: {}", access_request);

    // Portability request
    let portability_request = rights_handler
        .submit_request(
            user_id,
            DataSubjectRequest::Portability {
                format: PortabilityFormat::Json,
            },
        )
        .unwrap();
    println!("  ✓ Portability request submitted: {}", portability_request);

    // Erasure request
    let erasure_request = rights_handler
        .submit_request(
            user_id,
            DataSubjectRequest::Erasure {
                reason: ErasureReason::ConsentWithdrawn,
            },
        )
        .unwrap();
    println!("  ✓ Erasure request submitted: {}", erasure_request);

    println!();

    // Lawful basis
    println!("4. Lawful Basis for Processing");
    println!("─────────────────────────────────────────────────");

    let bases = vec![
        LawfulBasis::Consent {
            consent_id: "consent-001".to_string(),
            timestamp: SystemTime::now(),
            explicit: false,
        },
        LawfulBasis::Contract {
            contract_id: "contract-123".to_string(),
            purpose: "Service delivery".to_string(),
        },
        LawfulBasis::LegalObligation {
            regulation: "HMRC".to_string(),
            requirement: "Tax record retention".to_string(),
        },
        LawfulBasis::LegitimateInterests {
            interest: "Fraud prevention".to_string(),
            balancing_test_passed: true,
        },
    ];

    for basis in bases {
        println!("  - {}", basis.description());
        println!("    Valid: {}", if basis.is_valid() { "✓" } else { "✗" });
    }

    println!();

    // Data categories
    println!("5. Personal Data Categories");
    println!("─────────────────────────────────────────────────");

    let categories = vec![
        DataCategory::BasicIdentity,
        DataCategory::Financial,
        DataCategory::Health,
        DataCategory::Location,
        DataCategory::OnlineIdentifiers,
    ];

    for category in categories {
        let retention = category.retention_period().as_secs() / (365 * 24 * 3600);
        println!("  {} {}:", category.emoji(), category);
        println!(
            "    Special category: {}",
            if category.is_special_category() {
                "Yes"
            } else {
                "No"
            }
        );
        println!(
            "    Explicit consent required: {}",
            if category.requires_explicit_consent() {
                "Yes"
            } else {
                "No"
            }
        );
        println!("    Default retention: {} years", retention);
    }

    println!();

    // Audit logging
    println!("6. Audit Logging");
    println!("─────────────────────────────────────────────────");

    audit_logger.log(AuditEntry {
        timestamp: SystemTime::now(),
        action: AuditAction::DataAccess,
        data_subject_id: Some(user_id.to_string()),
        details: "Profile data accessed".to_string(),
        actor: Some("admin@example.com".to_string()),
        ip_address: Some("192.168.1.100".to_string()),
    });

    audit_logger.log(AuditEntry {
        timestamp: SystemTime::now(),
        action: AuditAction::ProcessingActivity,
        data_subject_id: Some(user_id.to_string()),
        details: "Analytics processing performed".to_string(),
        actor: Some("system".to_string()),
        ip_address: None,
    });

    let entries = audit_logger.get_entries(Some(user_id));
    println!("  Audit entries for {}: {}", user_id, entries.len());

    for entry in entries {
        println!("    - {:?}: {}", entry.action, entry.details);
    }

    println!();

    // Summary
    println!("═══════════════════════════════════════════════════════════════════════");
    println!("                            GDPR COMPLIANCE STATUS");
    println!("═══════════════════════════════════════════════════════════════════════\n");

    let user_consents = consent_manager.get_consents(user_id);
    println!("  Data Subject: {}", user_id);
    println!(
        "  Active Consents: {}",
        user_consents.iter().filter(|c| c.is_valid()).count()
    );
    println!("  Pending Requests: 3");
    println!(
        "  Audit Entries: {}",
        audit_logger.get_entries(Some(user_id)).len()
    );

    println!("\n  ✓ Consent management: Implemented");
    println!("  ✓ Data subject rights: Implemented");
    println!("  ✓ Lawful basis tracking: Implemented");
    println!("  ✓ Audit logging: Implemented");
    println!("  ✓ Data categorization: Implemented");
    println!("  ✓ Retention periods: Configured");

    println!("\n=== GDPR Data Protection Demo Complete ===");
}

impl DataCategory {
    fn emoji(&self) -> &str {
        match self {
            DataCategory::BasicIdentity => "👤",
            DataCategory::Financial => "💳",
            DataCategory::Health => "🏥",
            DataCategory::Biometric => "🔐",
            DataCategory::Genetic => "🧬",
            DataCategory::Location => "📍",
            DataCategory::OnlineIdentifiers => "🌐",
            DataCategory::Behavioral => "📊",
            DataCategory::Employment => "💼",
            DataCategory::Communications => "💬",
            _ => "📋",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_category_special() {
        assert!(DataCategory::Health.is_special_category());
        assert!(DataCategory::Biometric.is_special_category());
        assert!(DataCategory::Genetic.is_special_category());
        assert!(!DataCategory::BasicIdentity.is_special_category());
        assert!(!DataCategory::Financial.is_special_category());
    }

    #[test]
    fn test_consent_validity() {
        let mut categories = HashSet::new();
        categories.insert(DataCategory::BasicIdentity);

        let consent = Consent {
            id: "test".to_string(),
            data_subject_id: "user".to_string(),
            purpose: "test".to_string(),
            data_categories: categories,
            third_parties: vec![],
            granted_at: SystemTime::now(),
            expires_at: None,
            withdrawn_at: None,
            explicit: false,
            source: ConsentSource::Api {
                endpoint: "/consent".to_string(),
            },
            version: "1.0".to_string(),
        };

        assert!(consent.is_valid());
        assert!(consent.covers_category(&DataCategory::BasicIdentity));
        assert!(!consent.covers_category(&DataCategory::Health));
    }

    #[test]
    fn test_consent_withdrawal() {
        let mut categories = HashSet::new();
        categories.insert(DataCategory::BasicIdentity);

        let mut consent = Consent {
            id: "test".to_string(),
            data_subject_id: "user".to_string(),
            purpose: "test".to_string(),
            data_categories: categories,
            third_parties: vec![],
            granted_at: SystemTime::now(),
            expires_at: None,
            withdrawn_at: None,
            explicit: false,
            source: ConsentSource::Api {
                endpoint: "/consent".to_string(),
            },
            version: "1.0".to_string(),
        };

        assert!(consent.is_valid());
        consent.withdraw();
        assert!(!consent.is_valid());
    }

    #[test]
    fn test_consent_manager() {
        let manager = ConsentManager::new();

        let mut categories = HashSet::new();
        categories.insert(DataCategory::BasicIdentity);

        let consent = Consent {
            id: "test-consent".to_string(),
            data_subject_id: "user-1".to_string(),
            purpose: "marketing".to_string(),
            data_categories: categories,
            third_parties: vec![],
            granted_at: SystemTime::now(),
            expires_at: None,
            withdrawn_at: None,
            explicit: false,
            source: ConsentSource::Api {
                endpoint: "/consent".to_string(),
            },
            version: "1.0".to_string(),
        };

        let result = manager.record_consent(consent);
        assert!(result.is_ok());

        assert!(manager.check_consent("user-1", "marketing", &DataCategory::BasicIdentity));
        assert!(!manager.check_consent("user-1", "marketing", &DataCategory::Health));
    }

    #[test]
    fn test_special_category_requires_explicit() {
        let manager = ConsentManager::new();

        let mut categories = HashSet::new();
        categories.insert(DataCategory::Health);

        // Non-explicit consent for health data should fail
        let consent = Consent {
            id: "test".to_string(),
            data_subject_id: "user".to_string(),
            purpose: "health".to_string(),
            data_categories: categories,
            third_parties: vec![],
            granted_at: SystemTime::now(),
            expires_at: None,
            withdrawn_at: None,
            explicit: false, // Should fail
            source: ConsentSource::Api {
                endpoint: "/consent".to_string(),
            },
            version: "1.0".to_string(),
        };

        assert!(manager.record_consent(consent).is_err());
    }

    #[test]
    fn test_lawful_basis() {
        let consent_basis = LawfulBasis::Consent {
            consent_id: "123".to_string(),
            timestamp: SystemTime::now(),
            explicit: true,
        };
        assert!(consent_basis.is_valid());

        let contract_basis = LawfulBasis::Contract {
            contract_id: "456".to_string(),
            purpose: "service".to_string(),
        };
        assert!(contract_basis.is_valid());

        let empty_contract = LawfulBasis::Contract {
            contract_id: String::new(),
            purpose: "service".to_string(),
        };
        assert!(!empty_contract.is_valid());
    }

    #[test]
    fn test_data_subject_request() {
        let consent_manager = Arc::new(ConsentManager::new());
        let handler = DataSubjectRightsHandler::new(consent_manager);

        let request = handler.submit_request("user-1", DataSubjectRequest::Access);
        assert!(request.is_ok());
    }

    #[test]
    fn test_personal_data_record() {
        let mut record = PersonalDataRecord::empty("user-1");

        record.add_field("email", DataCategory::BasicIdentity, true);
        record.add_field("ip_address", DataCategory::OnlineIdentifiers, false);

        assert_eq!(record.fields.len(), 2);
        assert!(record.fields.get("email").unwrap().encrypted);
    }

    #[test]
    fn test_pseudonymization() {
        let mut record = PersonalDataRecord::empty("user-1");
        record.add_field("name", DataCategory::BasicIdentity, false);

        let pseudonym = record.pseudonymize();
        assert!(pseudonym.starts_with("PSE-"));
        assert!(record.fields.get("name").unwrap().pseudonymized);
    }

    #[test]
    fn test_audit_logger() {
        let logger = AuditLogger::new(30);

        logger.log(AuditEntry {
            timestamp: SystemTime::now(),
            action: AuditAction::DataAccess,
            data_subject_id: Some("user-1".to_string()),
            details: "test".to_string(),
            actor: None,
            ip_address: None,
        });

        let entries = logger.get_entries(Some("user-1"));
        assert_eq!(entries.len(), 1);

        let all_entries = logger.get_entries(None);
        assert_eq!(all_entries.len(), 1);
    }

    #[test]
    fn test_retention_periods() {
        assert!(
            DataCategory::Financial.retention_period()
                > DataCategory::OnlineIdentifiers.retention_period()
        );
        assert!(
            DataCategory::Health.retention_period() > DataCategory::Behavioral.retention_period()
        );
    }
}
