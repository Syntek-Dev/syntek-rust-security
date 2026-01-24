//! GDPR Consent Manager
//!
//! Comprehensive consent management system for GDPR compliance.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::{Duration, SystemTime};

/// Consent purpose categories
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConsentPurpose {
    // Core purposes
    Essential,     // Strictly necessary cookies/processing
    Performance,   // Analytics and performance
    Functionality, // Enhanced functionality
    Marketing,     // Advertising and marketing

    // Specific purposes
    Analytics,
    Personalization,
    SocialMedia,
    ThirdPartyAds,
    Remarketing,
    EmailMarketing,
    PushNotifications,
    LocationTracking,
    BiometricData,
    HealthData,
    FinancialData,

    // Custom purpose
    Custom(String),
}

impl ConsentPurpose {
    pub fn requires_explicit_consent(&self) -> bool {
        matches!(
            self,
            Self::Marketing
                | Self::ThirdPartyAds
                | Self::Remarketing
                | Self::EmailMarketing
                | Self::BiometricData
                | Self::HealthData
                | Self::FinancialData
                | Self::LocationTracking
        )
    }

    pub fn is_essential(&self) -> bool {
        matches!(self, Self::Essential)
    }

    pub fn retention_period(&self) -> Duration {
        match self {
            Self::Essential => Duration::from_secs(365 * 24 * 60 * 60), // 1 year
            Self::Performance | Self::Analytics => Duration::from_secs(90 * 24 * 60 * 60), // 90 days
            Self::Marketing | Self::ThirdPartyAds => Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            Self::EmailMarketing => Duration::from_secs(365 * 24 * 60 * 60), // Until unsubscribe
            _ => Duration::from_secs(180 * 24 * 60 * 60),                    // 6 months default
        }
    }

    pub fn description(&self) -> &str {
        match self {
            Self::Essential => "Strictly necessary for the website to function",
            Self::Performance => "Help us understand how visitors interact with our website",
            Self::Functionality => "Enable enhanced functionality and personalization",
            Self::Marketing => "Used to deliver relevant advertisements",
            Self::Analytics => "Measure and analyze website traffic",
            Self::Personalization => "Customize content based on your preferences",
            Self::SocialMedia => "Enable social media features and sharing",
            Self::ThirdPartyAds => "Third-party advertising and tracking",
            Self::Remarketing => "Show relevant ads based on previous visits",
            Self::EmailMarketing => "Send promotional emails and newsletters",
            Self::PushNotifications => "Send browser push notifications",
            Self::LocationTracking => "Track your geographic location",
            Self::BiometricData => "Process biometric identification data",
            Self::HealthData => "Process health-related information",
            Self::FinancialData => "Process financial and payment information",
            Self::Custom(_) => "Custom processing purpose",
        }
    }
}

impl fmt::Display for ConsentPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Essential => write!(f, "Essential"),
            Self::Performance => write!(f, "Performance"),
            Self::Functionality => write!(f, "Functionality"),
            Self::Marketing => write!(f, "Marketing"),
            Self::Analytics => write!(f, "Analytics"),
            Self::Personalization => write!(f, "Personalization"),
            Self::SocialMedia => write!(f, "Social Media"),
            Self::ThirdPartyAds => write!(f, "Third-Party Ads"),
            Self::Remarketing => write!(f, "Remarketing"),
            Self::EmailMarketing => write!(f, "Email Marketing"),
            Self::PushNotifications => write!(f, "Push Notifications"),
            Self::LocationTracking => write!(f, "Location Tracking"),
            Self::BiometricData => write!(f, "Biometric Data"),
            Self::HealthData => write!(f, "Health Data"),
            Self::FinancialData => write!(f, "Financial Data"),
            Self::Custom(name) => write!(f, "{}", name),
        }
    }
}

/// Legal basis for processing
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegalBasis {
    Consent,
    Contract,
    LegalObligation,
    VitalInterests,
    PublicTask,
    LegitimateInterests,
}

impl LegalBasis {
    pub fn requires_consent(&self) -> bool {
        matches!(self, Self::Consent)
    }
}

impl fmt::Display for LegalBasis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consent => write!(f, "Consent (Art. 6(1)(a))"),
            Self::Contract => write!(f, "Contract (Art. 6(1)(b))"),
            Self::LegalObligation => write!(f, "Legal Obligation (Art. 6(1)(c))"),
            Self::VitalInterests => write!(f, "Vital Interests (Art. 6(1)(d))"),
            Self::PublicTask => write!(f, "Public Task (Art. 6(1)(e))"),
            Self::LegitimateInterests => write!(f, "Legitimate Interests (Art. 6(1)(f))"),
        }
    }
}

/// Individual consent record
#[derive(Debug, Clone)]
pub struct ConsentRecord {
    pub id: String,
    pub user_id: String,
    pub purpose: ConsentPurpose,
    pub granted: bool,
    pub legal_basis: LegalBasis,
    pub granted_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub withdrawn_at: Option<SystemTime>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub consent_version: String,
    pub proof_of_consent: String,
}

impl ConsentRecord {
    pub fn new(user_id: impl Into<String>, purpose: ConsentPurpose, granted: bool) -> Self {
        let now = SystemTime::now();
        let expires_at = now.checked_add(purpose.retention_period());

        Self {
            id: generate_consent_id(),
            user_id: user_id.into(),
            purpose,
            granted,
            legal_basis: LegalBasis::Consent,
            granted_at: now,
            expires_at,
            withdrawn_at: None,
            ip_address: None,
            user_agent: None,
            consent_version: "1.0".to_string(),
            proof_of_consent: String::new(),
        }
    }

    pub fn with_metadata(mut self, ip: impl Into<String>, user_agent: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self.user_agent = Some(user_agent.into());
        self
    }

    pub fn with_proof(mut self, proof: impl Into<String>) -> Self {
        self.proof_of_consent = proof.into();
        self
    }

    pub fn is_valid(&self) -> bool {
        if !self.granted {
            return false;
        }

        if self.withdrawn_at.is_some() {
            return false;
        }

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

/// Consent preferences for a user
#[derive(Debug, Clone)]
pub struct ConsentPreferences {
    pub user_id: String,
    pub consents: HashMap<ConsentPurpose, ConsentRecord>,
    pub last_updated: SystemTime,
    pub consent_version: String,
}

impl ConsentPreferences {
    pub fn new(user_id: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            consents: HashMap::new(),
            last_updated: SystemTime::now(),
            consent_version: "1.0".to_string(),
        }
    }

    pub fn set_consent(&mut self, purpose: ConsentPurpose, granted: bool) {
        let record = ConsentRecord::new(&self.user_id, purpose.clone(), granted);
        self.consents.insert(purpose, record);
        self.last_updated = SystemTime::now();
    }

    pub fn has_consent(&self, purpose: &ConsentPurpose) -> bool {
        // Essential purposes are always allowed
        if purpose.is_essential() {
            return true;
        }

        self.consents
            .get(purpose)
            .map(|r| r.is_valid())
            .unwrap_or(false)
    }

    pub fn withdraw_consent(&mut self, purpose: &ConsentPurpose) {
        if let Some(record) = self.consents.get_mut(purpose) {
            record.withdraw();
            self.last_updated = SystemTime::now();
        }
    }

    pub fn withdraw_all(&mut self) {
        for record in self.consents.values_mut() {
            record.withdraw();
        }
        self.last_updated = SystemTime::now();
    }

    pub fn get_granted_purposes(&self) -> Vec<&ConsentPurpose> {
        self.consents
            .iter()
            .filter(|(_, r)| r.is_valid())
            .map(|(p, _)| p)
            .collect()
    }
}

/// Consent banner configuration
#[derive(Debug, Clone)]
pub struct ConsentBannerConfig {
    pub title: String,
    pub description: String,
    pub accept_all_text: String,
    pub reject_all_text: String,
    pub customize_text: String,
    pub save_text: String,
    pub privacy_policy_url: String,
    pub cookie_policy_url: String,
    pub show_reject_all: bool,
    pub purposes: Vec<ConsentPurpose>,
    pub default_on_purposes: Vec<ConsentPurpose>,
}

impl Default for ConsentBannerConfig {
    fn default() -> Self {
        Self {
            title: "We value your privacy".to_string(),
            description: "We use cookies and similar technologies to enhance your experience, analyze traffic, and for ads personalization and measurement.".to_string(),
            accept_all_text: "Accept All".to_string(),
            reject_all_text: "Reject All".to_string(),
            customize_text: "Customize".to_string(),
            save_text: "Save Preferences".to_string(),
            privacy_policy_url: "/privacy".to_string(),
            cookie_policy_url: "/cookies".to_string(),
            show_reject_all: true,
            purposes: vec![
                ConsentPurpose::Essential,
                ConsentPurpose::Performance,
                ConsentPurpose::Functionality,
                ConsentPurpose::Marketing,
            ],
            default_on_purposes: vec![ConsentPurpose::Essential],
        }
    }
}

/// Consent manager
pub struct ConsentManager {
    config: ConsentBannerConfig,
    preferences: HashMap<String, ConsentPreferences>,
    audit_log: Vec<ConsentAuditEntry>,
}

impl ConsentManager {
    pub fn new(config: ConsentBannerConfig) -> Self {
        Self {
            config,
            preferences: HashMap::new(),
            audit_log: Vec::new(),
        }
    }

    pub fn get_or_create_preferences(&mut self, user_id: &str) -> &mut ConsentPreferences {
        if !self.preferences.contains_key(user_id) {
            let prefs = ConsentPreferences::new(user_id);
            self.preferences.insert(user_id.to_string(), prefs);
        }
        self.preferences.get_mut(user_id).unwrap()
    }

    pub fn record_consent(
        &mut self,
        user_id: &str,
        purpose: ConsentPurpose,
        granted: bool,
        metadata: Option<ConsentMetadata>,
    ) {
        let prefs = self.get_or_create_preferences(user_id);
        prefs.set_consent(purpose.clone(), granted);

        // Create audit entry
        let entry = ConsentAuditEntry {
            timestamp: SystemTime::now(),
            user_id: user_id.to_string(),
            action: if granted {
                ConsentAction::Granted
            } else {
                ConsentAction::Denied
            },
            purpose: purpose.clone(),
            metadata,
        };
        self.audit_log.push(entry);
    }

    pub fn record_bulk_consent(
        &mut self,
        user_id: &str,
        consents: HashMap<ConsentPurpose, bool>,
        metadata: Option<ConsentMetadata>,
    ) {
        for (purpose, granted) in consents {
            self.record_consent(user_id, purpose, granted, metadata.clone());
        }
    }

    pub fn accept_all(&mut self, user_id: &str, metadata: Option<ConsentMetadata>) {
        let purposes = self.config.purposes.clone();
        for purpose in purposes {
            self.record_consent(user_id, purpose, true, metadata.clone());
        }
    }

    pub fn reject_all(&mut self, user_id: &str, metadata: Option<ConsentMetadata>) {
        let purposes = self.config.purposes.clone();
        for purpose in purposes {
            let granted = purpose.is_essential();
            self.record_consent(user_id, purpose, granted, metadata.clone());
        }
    }

    pub fn withdraw_consent(&mut self, user_id: &str, purpose: &ConsentPurpose) {
        if let Some(prefs) = self.preferences.get_mut(user_id) {
            prefs.withdraw_consent(purpose);

            let entry = ConsentAuditEntry {
                timestamp: SystemTime::now(),
                user_id: user_id.to_string(),
                action: ConsentAction::Withdrawn,
                purpose: purpose.clone(),
                metadata: None,
            };
            self.audit_log.push(entry);
        }
    }

    pub fn check_consent(&self, user_id: &str, purpose: &ConsentPurpose) -> bool {
        // Essential purposes don't require consent
        if purpose.is_essential() {
            return true;
        }

        self.preferences
            .get(user_id)
            .map(|p| p.has_consent(purpose))
            .unwrap_or(false)
    }

    pub fn get_consent_status(&self, user_id: &str) -> ConsentStatus {
        let prefs = self.preferences.get(user_id);

        match prefs {
            None => ConsentStatus::NotCollected,
            Some(p) if p.consents.is_empty() => ConsentStatus::NotCollected,
            Some(p) => {
                let granted: Vec<_> = p.get_granted_purposes();
                if granted.is_empty() {
                    ConsentStatus::AllRejected
                } else if granted.len() == self.config.purposes.len() {
                    ConsentStatus::AllAccepted
                } else {
                    ConsentStatus::Partial
                }
            }
        }
    }

    pub fn get_audit_log(&self, user_id: &str) -> Vec<&ConsentAuditEntry> {
        self.audit_log
            .iter()
            .filter(|e| e.user_id == user_id)
            .collect()
    }

    pub fn export_consent_proof(&self, user_id: &str) -> ConsentProof {
        let prefs = self.preferences.get(user_id);
        let audit_entries: Vec<_> = self.get_audit_log(user_id).into_iter().cloned().collect();

        ConsentProof {
            user_id: user_id.to_string(),
            export_timestamp: SystemTime::now(),
            current_preferences: prefs.cloned(),
            audit_trail: audit_entries,
            consent_version: self.config.purposes.len().to_string(),
        }
    }

    pub fn generate_consent_banner_html(&self) -> String {
        let purposes_html: String = self
            .config
            .purposes
            .iter()
            .map(|p| {
                let checked = if self.config.default_on_purposes.contains(p) || p.is_essential() {
                    "checked"
                } else {
                    ""
                };
                let disabled = if p.is_essential() { "disabled" } else { "" };

                format!(
                    r#"<div class="consent-purpose">
                    <label>
                        <input type="checkbox" name="{}" {} {} />
                        <span class="purpose-name">{}</span>
                        <span class="purpose-desc">{}</span>
                    </label>
                </div>"#,
                    p,
                    checked,
                    disabled,
                    p,
                    p.description()
                )
            })
            .collect();

        format!(
            r#"<div id="consent-banner" class="consent-banner">
    <div class="consent-content">
        <h2>{}</h2>
        <p>{}</p>

        <div class="consent-purposes" style="display: none;">
            {}
        </div>

        <div class="consent-actions">
            <button onclick="acceptAll()" class="btn-primary">{}</button>
            {}
            <button onclick="customize()" class="btn-secondary">{}</button>
        </div>

        <div class="consent-links">
            <a href="{}" target="_blank">Privacy Policy</a>
            <a href="{}" target="_blank">Cookie Policy</a>
        </div>
    </div>
</div>"#,
            self.config.title,
            self.config.description,
            purposes_html,
            self.config.accept_all_text,
            if self.config.show_reject_all {
                format!(
                    r#"<button onclick="rejectAll()" class="btn-secondary">{}</button>"#,
                    self.config.reject_all_text
                )
            } else {
                String::new()
            },
            self.config.customize_text,
            self.config.privacy_policy_url,
            self.config.cookie_policy_url
        )
    }

    pub fn generate_consent_cookie(&self, user_id: &str) -> String {
        let prefs = self.preferences.get(user_id);

        match prefs {
            None => "consent=none".to_string(),
            Some(p) => {
                let granted: Vec<String> = p
                    .get_granted_purposes()
                    .iter()
                    .map(|p| format!("{}", p))
                    .collect();
                format!("consent={}", granted.join(","))
            }
        }
    }
}

/// Consent status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentStatus {
    NotCollected,
    AllAccepted,
    AllRejected,
    Partial,
}

/// Consent action for audit log
#[derive(Debug, Clone)]
pub enum ConsentAction {
    Granted,
    Denied,
    Withdrawn,
    Updated,
    Expired,
}

impl fmt::Display for ConsentAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Granted => write!(f, "GRANTED"),
            Self::Denied => write!(f, "DENIED"),
            Self::Withdrawn => write!(f, "WITHDRAWN"),
            Self::Updated => write!(f, "UPDATED"),
            Self::Expired => write!(f, "EXPIRED"),
        }
    }
}

/// Consent metadata
#[derive(Debug, Clone)]
pub struct ConsentMetadata {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub page_url: Option<String>,
    pub referrer: Option<String>,
}

/// Audit log entry
#[derive(Debug, Clone)]
pub struct ConsentAuditEntry {
    pub timestamp: SystemTime,
    pub user_id: String,
    pub action: ConsentAction,
    pub purpose: ConsentPurpose,
    pub metadata: Option<ConsentMetadata>,
}

/// Consent proof for compliance
#[derive(Debug, Clone)]
pub struct ConsentProof {
    pub user_id: String,
    pub export_timestamp: SystemTime,
    pub current_preferences: Option<ConsentPreferences>,
    pub audit_trail: Vec<ConsentAuditEntry>,
    pub consent_version: String,
}

impl ConsentProof {
    pub fn to_json(&self) -> String {
        let audit_entries: Vec<String> = self
            .audit_trail
            .iter()
            .map(|e| {
                format!(
                    r#"    {{
      "timestamp": "{:?}",
      "action": "{}",
      "purpose": "{}"
    }}"#,
                    e.timestamp, e.action, e.purpose
                )
            })
            .collect();

        format!(
            r#"{{
  "user_id": "{}",
  "export_timestamp": "{:?}",
  "consent_version": "{}",
  "audit_trail": [
{}
  ]
}}"#,
            self.user_id,
            self.export_timestamp,
            self.consent_version,
            audit_entries.join(",\n")
        )
    }
}

/// Generate unique consent ID
fn generate_consent_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    format!("consent_{}", timestamp)
}

/// TCF (Transparency & Consent Framework) v2 support
pub struct TcfV2Builder {
    vendor_consents: HashSet<u32>,
    purpose_consents: HashSet<u8>,
    special_feature_optins: HashSet<u8>,
    publisher_restrictions: Vec<(u8, u32, u8)>,
}

impl TcfV2Builder {
    pub fn new() -> Self {
        Self {
            vendor_consents: HashSet::new(),
            purpose_consents: HashSet::new(),
            special_feature_optins: HashSet::new(),
            publisher_restrictions: Vec::new(),
        }
    }

    pub fn add_vendor_consent(mut self, vendor_id: u32) -> Self {
        self.vendor_consents.insert(vendor_id);
        self
    }

    pub fn add_purpose_consent(mut self, purpose_id: u8) -> Self {
        self.purpose_consents.insert(purpose_id);
        self
    }

    pub fn add_special_feature_optin(mut self, feature_id: u8) -> Self {
        self.special_feature_optins.insert(feature_id);
        self
    }

    pub fn build_tc_string(&self) -> String {
        // Simplified TC string generation
        // Real implementation would follow IAB TCF v2 specification
        format!("CPXxRfAPXxRfAAfKABENB-CgAAAAAAAAAAYgAAAAAAAA.YAAAAAAAAAAA")
    }
}

impl Default for TcfV2Builder {
    fn default() -> Self {
        Self::new()
    }
}

fn main() {
    println!("=== GDPR Consent Manager Demo ===\n");

    // Create consent manager with custom config
    let config = ConsentBannerConfig {
        title: "Privacy Settings".to_string(),
        description: "We use cookies to improve your experience and analyze site usage."
            .to_string(),
        show_reject_all: true,
        purposes: vec![
            ConsentPurpose::Essential,
            ConsentPurpose::Analytics,
            ConsentPurpose::Marketing,
            ConsentPurpose::Personalization,
        ],
        ..Default::default()
    };

    let mut manager = ConsentManager::new(config);

    // Simulate user consent flow
    let user_id = "user_12345";

    // Check initial status
    println!(
        "Initial consent status: {:?}",
        manager.get_consent_status(user_id)
    );

    // User accepts all
    println!("\nUser accepts all cookies...");
    manager.accept_all(
        user_id,
        Some(ConsentMetadata {
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            page_url: Some("/".to_string()),
            referrer: None,
        }),
    );

    println!("Consent status: {:?}", manager.get_consent_status(user_id));

    // Check individual consents
    println!("\nConsent checks:");
    println!(
        "  Essential: {}",
        manager.check_consent(user_id, &ConsentPurpose::Essential)
    );
    println!(
        "  Analytics: {}",
        manager.check_consent(user_id, &ConsentPurpose::Analytics)
    );
    println!(
        "  Marketing: {}",
        manager.check_consent(user_id, &ConsentPurpose::Marketing)
    );

    // User withdraws marketing consent
    println!("\nUser withdraws marketing consent...");
    manager.withdraw_consent(user_id, &ConsentPurpose::Marketing);

    println!(
        "Marketing consent after withdrawal: {}",
        manager.check_consent(user_id, &ConsentPurpose::Marketing)
    );

    // Export consent proof
    println!("\n--- Consent Proof Export ---");
    let proof = manager.export_consent_proof(user_id);
    println!("{}", proof.to_json());

    // Generate consent banner HTML
    println!("\n--- Generated Consent Banner HTML ---");
    println!("{}", manager.generate_consent_banner_html());

    // Generate consent cookie
    println!("\n--- Consent Cookie ---");
    println!("{}", manager.generate_consent_cookie(user_id));

    // TCF v2 support
    println!("\n--- TCF v2 String ---");
    let tcf = TcfV2Builder::new()
        .add_vendor_consent(755) // Example vendor ID
        .add_purpose_consent(1)
        .add_purpose_consent(2)
        .build_tc_string();
    println!("TC String: {}", tcf);

    // Audit log
    println!("\n--- Audit Log ---");
    for entry in manager.get_audit_log(user_id) {
        println!(
            "  [{:?}] {} - {}",
            entry.timestamp, entry.action, entry.purpose
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consent_purpose_essential() {
        assert!(ConsentPurpose::Essential.is_essential());
        assert!(!ConsentPurpose::Marketing.is_essential());
    }

    #[test]
    fn test_consent_purpose_explicit_consent() {
        assert!(ConsentPurpose::Marketing.requires_explicit_consent());
        assert!(ConsentPurpose::BiometricData.requires_explicit_consent());
        assert!(!ConsentPurpose::Essential.requires_explicit_consent());
        assert!(!ConsentPurpose::Functionality.requires_explicit_consent());
    }

    #[test]
    fn test_consent_record_creation() {
        let record = ConsentRecord::new("user1", ConsentPurpose::Analytics, true);

        assert!(record.granted);
        assert!(record.is_valid());
        assert!(record.withdrawn_at.is_none());
    }

    #[test]
    fn test_consent_record_withdrawal() {
        let mut record = ConsentRecord::new("user1", ConsentPurpose::Marketing, true);
        assert!(record.is_valid());

        record.withdraw();

        assert!(!record.is_valid());
        assert!(record.withdrawn_at.is_some());
    }

    #[test]
    fn test_consent_preferences() {
        let mut prefs = ConsentPreferences::new("user1");

        prefs.set_consent(ConsentPurpose::Analytics, true);
        prefs.set_consent(ConsentPurpose::Marketing, false);

        assert!(prefs.has_consent(&ConsentPurpose::Analytics));
        assert!(!prefs.has_consent(&ConsentPurpose::Marketing));
        assert!(prefs.has_consent(&ConsentPurpose::Essential)); // Always allowed
    }

    #[test]
    fn test_consent_preferences_withdraw_all() {
        let mut prefs = ConsentPreferences::new("user1");

        prefs.set_consent(ConsentPurpose::Analytics, true);
        prefs.set_consent(ConsentPurpose::Marketing, true);

        prefs.withdraw_all();

        assert!(!prefs.has_consent(&ConsentPurpose::Analytics));
        assert!(!prefs.has_consent(&ConsentPurpose::Marketing));
    }

    #[test]
    fn test_consent_manager_creation() {
        let config = ConsentBannerConfig::default();
        let manager = ConsentManager::new(config);

        assert!(manager.preferences.is_empty());
        assert!(manager.audit_log.is_empty());
    }

    #[test]
    fn test_consent_manager_record() {
        let config = ConsentBannerConfig::default();
        let mut manager = ConsentManager::new(config);

        manager.record_consent("user1", ConsentPurpose::Analytics, true, None);

        assert!(manager.check_consent("user1", &ConsentPurpose::Analytics));
        assert_eq!(manager.audit_log.len(), 1);
    }

    #[test]
    fn test_consent_manager_accept_all() {
        let config = ConsentBannerConfig {
            purposes: vec![
                ConsentPurpose::Essential,
                ConsentPurpose::Analytics,
                ConsentPurpose::Marketing,
            ],
            ..Default::default()
        };
        let mut manager = ConsentManager::new(config);

        manager.accept_all("user1", None);

        assert!(manager.check_consent("user1", &ConsentPurpose::Analytics));
        assert!(manager.check_consent("user1", &ConsentPurpose::Marketing));
    }

    #[test]
    fn test_consent_manager_reject_all() {
        let config = ConsentBannerConfig {
            purposes: vec![
                ConsentPurpose::Essential,
                ConsentPurpose::Analytics,
                ConsentPurpose::Marketing,
            ],
            ..Default::default()
        };
        let mut manager = ConsentManager::new(config);

        manager.reject_all("user1", None);

        // Essential should still be allowed
        assert!(manager.check_consent("user1", &ConsentPurpose::Essential));
        // Others should be rejected
        assert!(!manager.check_consent("user1", &ConsentPurpose::Marketing));
    }

    #[test]
    fn test_consent_status() {
        let config = ConsentBannerConfig {
            purposes: vec![ConsentPurpose::Essential, ConsentPurpose::Analytics],
            ..Default::default()
        };
        let mut manager = ConsentManager::new(config);

        assert_eq!(
            manager.get_consent_status("user1"),
            ConsentStatus::NotCollected
        );

        manager.accept_all("user1", None);
        assert_eq!(
            manager.get_consent_status("user1"),
            ConsentStatus::AllAccepted
        );
    }

    #[test]
    fn test_consent_withdrawal() {
        let config = ConsentBannerConfig::default();
        let mut manager = ConsentManager::new(config);

        manager.record_consent("user1", ConsentPurpose::Marketing, true, None);
        assert!(manager.check_consent("user1", &ConsentPurpose::Marketing));

        manager.withdraw_consent("user1", &ConsentPurpose::Marketing);
        assert!(!manager.check_consent("user1", &ConsentPurpose::Marketing));
    }

    #[test]
    fn test_audit_log() {
        let config = ConsentBannerConfig::default();
        let mut manager = ConsentManager::new(config);

        manager.record_consent("user1", ConsentPurpose::Analytics, true, None);
        manager.record_consent("user1", ConsentPurpose::Marketing, false, None);
        manager.withdraw_consent("user1", &ConsentPurpose::Analytics);

        let log = manager.get_audit_log("user1");
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn test_consent_proof_export() {
        let config = ConsentBannerConfig::default();
        let mut manager = ConsentManager::new(config);

        manager.record_consent("user1", ConsentPurpose::Analytics, true, None);

        let proof = manager.export_consent_proof("user1");
        assert_eq!(proof.user_id, "user1");
        assert!(!proof.audit_trail.is_empty());
    }

    #[test]
    fn test_legal_basis() {
        assert!(LegalBasis::Consent.requires_consent());
        assert!(!LegalBasis::Contract.requires_consent());
        assert!(!LegalBasis::LegitimateInterests.requires_consent());
    }

    #[test]
    fn test_tcf_builder() {
        let tc_string = TcfV2Builder::new()
            .add_vendor_consent(1)
            .add_purpose_consent(1)
            .build_tc_string();

        assert!(!tc_string.is_empty());
    }

    #[test]
    fn test_consent_cookie_generation() {
        let config = ConsentBannerConfig {
            purposes: vec![ConsentPurpose::Essential, ConsentPurpose::Analytics],
            ..Default::default()
        };
        let mut manager = ConsentManager::new(config);

        manager.record_consent("user1", ConsentPurpose::Analytics, true, None);

        let cookie = manager.generate_consent_cookie("user1");
        assert!(cookie.contains("consent="));
    }
}
