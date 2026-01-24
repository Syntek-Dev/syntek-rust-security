//! STRIDE Threat Modelling Framework
//!
//! Implementation of the STRIDE threat modelling methodology for
//! systematically identifying security threats in software systems.

use std::collections::{HashMap, HashSet};
use std::fmt;

/// STRIDE threat categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StrideCategory {
    /// Pretending to be something or someone other than yourself
    Spoofing,
    /// Modifying data or code without authorization
    Tampering,
    /// Claiming you didn't do something or were not responsible
    Repudiation,
    /// Exposing information to unauthorized parties
    InformationDisclosure,
    /// Preventing legitimate users from accessing resources
    DenialOfService,
    /// Gaining unauthorized access or capabilities
    ElevationOfPrivilege,
}

impl StrideCategory {
    pub fn abbreviation(&self) -> char {
        match self {
            StrideCategory::Spoofing => 'S',
            StrideCategory::Tampering => 'T',
            StrideCategory::Repudiation => 'R',
            StrideCategory::InformationDisclosure => 'I',
            StrideCategory::DenialOfService => 'D',
            StrideCategory::ElevationOfPrivilege => 'E',
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            StrideCategory::Spoofing => "Impersonating something or someone else",
            StrideCategory::Tampering => "Modifying data or code",
            StrideCategory::Repudiation => "Denying having performed an action",
            StrideCategory::InformationDisclosure => "Exposing information to unauthorized parties",
            StrideCategory::DenialOfService => "Denying or degrading service to users",
            StrideCategory::ElevationOfPrivilege => "Gaining capabilities without authorization",
        }
    }

    pub fn security_property(&self) -> &'static str {
        match self {
            StrideCategory::Spoofing => "Authentication",
            StrideCategory::Tampering => "Integrity",
            StrideCategory::Repudiation => "Non-repudiation",
            StrideCategory::InformationDisclosure => "Confidentiality",
            StrideCategory::DenialOfService => "Availability",
            StrideCategory::ElevationOfPrivilege => "Authorization",
        }
    }

    pub fn all() -> Vec<StrideCategory> {
        vec![
            StrideCategory::Spoofing,
            StrideCategory::Tampering,
            StrideCategory::Repudiation,
            StrideCategory::InformationDisclosure,
            StrideCategory::DenialOfService,
            StrideCategory::ElevationOfPrivilege,
        ]
    }
}

impl fmt::Display for StrideCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Risk severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskSeverity {
    pub fn from_dread_score(score: f32) -> Self {
        match score {
            s if s >= 9.0 => RiskSeverity::Critical,
            s if s >= 7.0 => RiskSeverity::High,
            s if s >= 4.0 => RiskSeverity::Medium,
            _ => RiskSeverity::Low,
        }
    }
}

/// DREAD risk assessment model
#[derive(Debug, Clone)]
pub struct DreadScore {
    /// How bad would an attack be?
    pub damage_potential: u8,
    /// How easy is it to reproduce?
    pub reproducibility: u8,
    /// How easy is it to launch?
    pub exploitability: u8,
    /// How many users are affected?
    pub affected_users: u8,
    /// How easy is it to find the vulnerability?
    pub discoverability: u8,
}

impl DreadScore {
    pub fn new(damage: u8, repro: u8, exploit: u8, affected: u8, discover: u8) -> Self {
        Self {
            damage_potential: damage.min(10),
            reproducibility: repro.min(10),
            exploitability: exploit.min(10),
            affected_users: affected.min(10),
            discoverability: discover.min(10),
        }
    }

    pub fn total(&self) -> f32 {
        (self.damage_potential as f32
            + self.reproducibility as f32
            + self.exploitability as f32
            + self.affected_users as f32
            + self.discoverability as f32)
            / 5.0
    }

    pub fn severity(&self) -> RiskSeverity {
        RiskSeverity::from_dread_score(self.total())
    }
}

/// System component types for data flow diagrams
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComponentType {
    ExternalEntity,
    Process,
    DataStore,
    DataFlow,
    TrustBoundary,
}

impl ComponentType {
    pub fn applicable_threats(&self) -> Vec<StrideCategory> {
        match self {
            ComponentType::ExternalEntity => {
                vec![StrideCategory::Spoofing, StrideCategory::Repudiation]
            }
            ComponentType::Process => StrideCategory::all(),
            ComponentType::DataStore => vec![
                StrideCategory::Tampering,
                StrideCategory::Repudiation,
                StrideCategory::InformationDisclosure,
                StrideCategory::DenialOfService,
            ],
            ComponentType::DataFlow => vec![
                StrideCategory::Tampering,
                StrideCategory::InformationDisclosure,
                StrideCategory::DenialOfService,
            ],
            ComponentType::TrustBoundary => vec![
                StrideCategory::Spoofing,
                StrideCategory::ElevationOfPrivilege,
            ],
        }
    }
}

/// A component in the system model
#[derive(Debug, Clone)]
pub struct Component {
    pub id: String,
    pub name: String,
    pub component_type: ComponentType,
    pub description: String,
    pub technologies: Vec<String>,
    pub trust_level: TrustLevel,
    pub data_classification: DataClassification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    Untrusted,
    PartiallyTrusted,
    Trusted,
    HighlyTrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl Component {
    pub fn new(id: &str, name: &str, component_type: ComponentType) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            component_type,
            description: String::new(),
            technologies: vec![],
            trust_level: TrustLevel::Untrusted,
            data_classification: DataClassification::Internal,
        }
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_technology(mut self, tech: &str) -> Self {
        self.technologies.push(tech.into());
        self
    }

    pub fn with_trust_level(mut self, level: TrustLevel) -> Self {
        self.trust_level = level;
        self
    }

    pub fn with_data_classification(mut self, classification: DataClassification) -> Self {
        self.data_classification = classification;
        self
    }
}

/// A data flow between components
#[derive(Debug, Clone)]
pub struct DataFlow {
    pub id: String,
    pub name: String,
    pub source: String,
    pub destination: String,
    pub data_type: String,
    pub protocol: Option<String>,
    pub encrypted: bool,
    pub authenticated: bool,
}

impl DataFlow {
    pub fn new(id: &str, name: &str, source: &str, destination: &str) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            source: source.into(),
            destination: destination.into(),
            data_type: "Unknown".into(),
            protocol: None,
            encrypted: false,
            authenticated: false,
        }
    }

    pub fn with_data_type(mut self, data_type: &str) -> Self {
        self.data_type = data_type.into();
        self
    }

    pub fn with_protocol(mut self, protocol: &str) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    pub fn encrypted(mut self) -> Self {
        self.encrypted = true;
        self
    }

    pub fn authenticated(mut self) -> Self {
        self.authenticated = true;
        self
    }
}

/// An identified threat
#[derive(Debug, Clone)]
pub struct Threat {
    pub id: String,
    pub title: String,
    pub category: StrideCategory,
    pub description: String,
    pub affected_components: Vec<String>,
    pub attack_scenario: String,
    pub dread_score: Option<DreadScore>,
    pub mitigations: Vec<Mitigation>,
    pub status: ThreatStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatStatus {
    Identified,
    UnderReview,
    Mitigated,
    Accepted,
    Transferred,
    NotApplicable,
}

impl Threat {
    pub fn new(id: &str, title: &str, category: StrideCategory) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            category,
            description: String::new(),
            affected_components: vec![],
            attack_scenario: String::new(),
            dread_score: None,
            mitigations: vec![],
            status: ThreatStatus::Identified,
        }
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_component(mut self, component_id: &str) -> Self {
        self.affected_components.push(component_id.into());
        self
    }

    pub fn with_attack_scenario(mut self, scenario: &str) -> Self {
        self.attack_scenario = scenario.into();
        self
    }

    pub fn with_dread(mut self, score: DreadScore) -> Self {
        self.dread_score = Some(score);
        self
    }

    pub fn add_mitigation(&mut self, mitigation: Mitigation) {
        self.mitigations.push(mitigation);
    }

    pub fn severity(&self) -> RiskSeverity {
        self.dread_score
            .as_ref()
            .map(|d| d.severity())
            .unwrap_or(RiskSeverity::Medium)
    }
}

/// A mitigation for a threat
#[derive(Debug, Clone)]
pub struct Mitigation {
    pub id: String,
    pub title: String,
    pub description: String,
    pub implementation_status: ImplementationStatus,
    pub effectiveness: MitigationEffectiveness,
    pub cost: MitigationCost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImplementationStatus {
    NotStarted,
    InProgress,
    Implemented,
    Verified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitigationEffectiveness {
    Partial,
    Significant,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitigationCost {
    Low,
    Medium,
    High,
}

impl Mitigation {
    pub fn new(id: &str, title: &str, description: &str) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            description: description.into(),
            implementation_status: ImplementationStatus::NotStarted,
            effectiveness: MitigationEffectiveness::Partial,
            cost: MitigationCost::Medium,
        }
    }

    pub fn with_status(mut self, status: ImplementationStatus) -> Self {
        self.implementation_status = status;
        self
    }

    pub fn with_effectiveness(mut self, effectiveness: MitigationEffectiveness) -> Self {
        self.effectiveness = effectiveness;
        self
    }

    pub fn with_cost(mut self, cost: MitigationCost) -> Self {
        self.cost = cost;
        self
    }
}

/// Threat model for a system
#[derive(Debug)]
pub struct ThreatModel {
    pub name: String,
    pub version: String,
    pub description: String,
    pub components: HashMap<String, Component>,
    pub data_flows: Vec<DataFlow>,
    pub trust_boundaries: Vec<TrustBoundary>,
    pub threats: Vec<Threat>,
    pub assumptions: Vec<String>,
    pub external_dependencies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TrustBoundary {
    pub id: String,
    pub name: String,
    pub components_inside: Vec<String>,
}

impl ThreatModel {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            version: "1.0".into(),
            description: String::new(),
            components: HashMap::new(),
            data_flows: vec![],
            trust_boundaries: vec![],
            threats: vec![],
            assumptions: vec![],
            external_dependencies: vec![],
        }
    }

    pub fn add_component(&mut self, component: Component) {
        self.components.insert(component.id.clone(), component);
    }

    pub fn add_data_flow(&mut self, flow: DataFlow) {
        self.data_flows.push(flow);
    }

    pub fn add_trust_boundary(&mut self, boundary: TrustBoundary) {
        self.trust_boundaries.push(boundary);
    }

    pub fn add_threat(&mut self, threat: Threat) {
        self.threats.push(threat);
    }

    pub fn add_assumption(&mut self, assumption: &str) {
        self.assumptions.push(assumption.into());
    }

    /// Automatically identify potential threats based on components
    pub fn identify_threats(&mut self) {
        let mut threat_counter = 1;

        // Analyze each component
        for component in self.components.values() {
            for category in component.component_type.applicable_threats() {
                let threat =
                    self.generate_threat_for_component(&mut threat_counter, component, category);
                self.threats.push(threat);
            }
        }

        // Analyze data flows
        for flow in &self.data_flows {
            if !flow.encrypted {
                let threat = Threat::new(
                    &format!("T{:03}", threat_counter),
                    &format!("Unencrypted data flow: {}", flow.name),
                    StrideCategory::InformationDisclosure,
                )
                .with_description(&format!(
                    "Data flowing from {} to {} is not encrypted, allowing eavesdropping",
                    flow.source, flow.destination
                ))
                .with_component(&flow.source)
                .with_component(&flow.destination);

                self.threats.push(threat);
                threat_counter += 1;
            }

            if !flow.authenticated {
                let threat = Threat::new(
                    &format!("T{:03}", threat_counter),
                    &format!("Unauthenticated data flow: {}", flow.name),
                    StrideCategory::Spoofing,
                )
                .with_description(&format!(
                    "Data flowing from {} to {} is not authenticated, allowing spoofing",
                    flow.source, flow.destination
                ))
                .with_component(&flow.source)
                .with_component(&flow.destination);

                self.threats.push(threat);
                threat_counter += 1;
            }
        }
    }

    fn generate_threat_for_component(
        &self,
        counter: &mut u32,
        component: &Component,
        category: StrideCategory,
    ) -> Threat {
        let id = format!("T{:03}", counter);
        *counter += 1;

        let title = match category {
            StrideCategory::Spoofing => format!("Spoofing {}", component.name),
            StrideCategory::Tampering => format!("Tampering with {}", component.name),
            StrideCategory::Repudiation => format!("Repudiation of {} actions", component.name),
            StrideCategory::InformationDisclosure => {
                format!("Information disclosure from {}", component.name)
            }
            StrideCategory::DenialOfService => format!("Denial of service on {}", component.name),
            StrideCategory::ElevationOfPrivilege => {
                format!("Elevation of privilege via {}", component.name)
            }
        };

        Threat::new(&id, &title, category)
            .with_component(&component.id)
            .with_description(&format!(
                "An attacker could {} the {} component ({})",
                category.description().to_lowercase(),
                component.name,
                component
                    .component_type
                    .applicable_threats()
                    .iter()
                    .map(|t| t.abbreviation())
                    .collect::<String>()
            ))
    }

    /// Get threats by severity
    pub fn threats_by_severity(&self) -> HashMap<RiskSeverity, Vec<&Threat>> {
        let mut by_severity: HashMap<RiskSeverity, Vec<&Threat>> = HashMap::new();

        for threat in &self.threats {
            by_severity
                .entry(threat.severity())
                .or_default()
                .push(threat);
        }

        by_severity
    }

    /// Get threats by category
    pub fn threats_by_category(&self) -> HashMap<StrideCategory, Vec<&Threat>> {
        let mut by_category: HashMap<StrideCategory, Vec<&Threat>> = HashMap::new();

        for threat in &self.threats {
            by_category.entry(threat.category).or_default().push(threat);
        }

        by_category
    }

    /// Get unmitigated threats
    pub fn unmitigated_threats(&self) -> Vec<&Threat> {
        self.threats
            .iter()
            .filter(|t| {
                t.status == ThreatStatus::Identified || t.status == ThreatStatus::UnderReview
            })
            .collect()
    }

    /// Generate summary report
    pub fn summary(&self) -> ThreatModelSummary {
        let by_severity = self.threats_by_severity();
        let by_category = self.threats_by_category();

        ThreatModelSummary {
            total_threats: self.threats.len(),
            critical: by_severity
                .get(&RiskSeverity::Critical)
                .map(|v| v.len())
                .unwrap_or(0),
            high: by_severity
                .get(&RiskSeverity::High)
                .map(|v| v.len())
                .unwrap_or(0),
            medium: by_severity
                .get(&RiskSeverity::Medium)
                .map(|v| v.len())
                .unwrap_or(0),
            low: by_severity
                .get(&RiskSeverity::Low)
                .map(|v| v.len())
                .unwrap_or(0),
            mitigated: self
                .threats
                .iter()
                .filter(|t| t.status == ThreatStatus::Mitigated)
                .count(),
            by_category: by_category.into_iter().map(|(k, v)| (k, v.len())).collect(),
        }
    }

    /// Export to markdown
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str(&format!("# Threat Model: {}\n\n", self.name));
        md.push_str(&format!("**Version:** {}\n\n", self.version));
        md.push_str(&format!("{}\n\n", self.description));

        // Components
        md.push_str("## System Components\n\n");
        md.push_str("| ID | Name | Type | Trust Level |\n");
        md.push_str("|---|---|---|---|\n");
        for component in self.components.values() {
            md.push_str(&format!(
                "| {} | {} | {:?} | {:?} |\n",
                component.id, component.name, component.component_type, component.trust_level
            ));
        }
        md.push_str("\n");

        // Data Flows
        md.push_str("## Data Flows\n\n");
        md.push_str("| Name | Source | Destination | Encrypted | Authenticated |\n");
        md.push_str("|---|---|---|---|---|\n");
        for flow in &self.data_flows {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                flow.name,
                flow.source,
                flow.destination,
                if flow.encrypted { "Yes" } else { "No" },
                if flow.authenticated { "Yes" } else { "No" }
            ));
        }
        md.push_str("\n");

        // Threats
        md.push_str("## Identified Threats\n\n");
        for threat in &self.threats {
            md.push_str(&format!("### {} - {}\n\n", threat.id, threat.title));
            md.push_str(&format!(
                "**Category:** {} ({})\n\n",
                threat.category,
                threat.category.security_property()
            ));
            md.push_str(&format!("**Severity:** {:?}\n\n", threat.severity()));
            md.push_str(&format!("**Status:** {:?}\n\n", threat.status));
            md.push_str(&format!("{}\n\n", threat.description));

            if !threat.mitigations.is_empty() {
                md.push_str("**Mitigations:**\n\n");
                for mitigation in &threat.mitigations {
                    md.push_str(&format!(
                        "- {} ({:?}): {}\n",
                        mitigation.title, mitigation.implementation_status, mitigation.description
                    ));
                }
                md.push_str("\n");
            }
        }

        // Summary
        let summary = self.summary();
        md.push_str("## Summary\n\n");
        md.push_str(&format!("- **Total Threats:** {}\n", summary.total_threats));
        md.push_str(&format!("- **Critical:** {}\n", summary.critical));
        md.push_str(&format!("- **High:** {}\n", summary.high));
        md.push_str(&format!("- **Medium:** {}\n", summary.medium));
        md.push_str(&format!("- **Low:** {}\n", summary.low));
        md.push_str(&format!("- **Mitigated:** {}\n", summary.mitigated));

        md
    }
}

#[derive(Debug, Clone)]
pub struct ThreatModelSummary {
    pub total_threats: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub mitigated: usize,
    pub by_category: HashMap<StrideCategory, usize>,
}

fn main() {
    println!("STRIDE Threat Modelling Framework\n");

    // Create a threat model for a web application
    let mut model = ThreatModel::new("E-Commerce Web Application");
    model.description = "Threat model for customer-facing e-commerce platform".into();

    // Add components
    model.add_component(
        Component::new("WEB", "Web Browser", ComponentType::ExternalEntity)
            .with_description("Customer's web browser")
            .with_trust_level(TrustLevel::Untrusted),
    );

    model.add_component(
        Component::new("LB", "Load Balancer", ComponentType::Process)
            .with_description("Nginx load balancer")
            .with_technology("Nginx")
            .with_trust_level(TrustLevel::Trusted),
    );

    model.add_component(
        Component::new("API", "API Server", ComponentType::Process)
            .with_description("REST API backend")
            .with_technology("Rust/Actix")
            .with_trust_level(TrustLevel::Trusted),
    );

    model.add_component(
        Component::new("DB", "Database", ComponentType::DataStore)
            .with_description("PostgreSQL database")
            .with_technology("PostgreSQL")
            .with_trust_level(TrustLevel::HighlyTrusted)
            .with_data_classification(DataClassification::Confidential),
    );

    model.add_component(
        Component::new("CACHE", "Redis Cache", ComponentType::DataStore)
            .with_description("Redis session cache")
            .with_technology("Redis")
            .with_trust_level(TrustLevel::Trusted),
    );

    // Add data flows
    model.add_data_flow(
        DataFlow::new("DF1", "User Requests", "WEB", "LB")
            .with_protocol("HTTPS")
            .with_data_type("HTTP Request")
            .encrypted(),
    );

    model.add_data_flow(
        DataFlow::new("DF2", "API Requests", "LB", "API")
            .with_protocol("HTTP")
            .with_data_type("HTTP Request"),
    );

    model.add_data_flow(
        DataFlow::new("DF3", "Database Queries", "API", "DB")
            .with_protocol("PostgreSQL")
            .with_data_type("SQL Queries")
            .encrypted()
            .authenticated(),
    );

    model.add_data_flow(
        DataFlow::new("DF4", "Session Data", "API", "CACHE")
            .with_protocol("Redis")
            .with_data_type("Session tokens"),
    );

    // Add trust boundary
    model.add_trust_boundary(TrustBoundary {
        id: "TB1".into(),
        name: "DMZ Boundary".into(),
        components_inside: vec!["LB".into()],
    });

    model.add_trust_boundary(TrustBoundary {
        id: "TB2".into(),
        name: "Internal Network".into(),
        components_inside: vec!["API".into(), "DB".into(), "CACHE".into()],
    });

    // Add assumptions
    model.add_assumption("TLS 1.3 is used for all external communications");
    model.add_assumption("Database credentials are stored in HashiCorp Vault");
    model.add_assumption("Infrastructure is hosted in a SOC 2 compliant cloud provider");

    // Auto-identify threats
    model.identify_threats();

    // Add specific threat with DREAD score
    let mut sql_injection = Threat::new(
        "T-CUSTOM-001",
        "SQL Injection in Search API",
        StrideCategory::Tampering,
    )
    .with_description("Attacker could inject malicious SQL through the product search endpoint")
    .with_component("API")
    .with_component("DB")
    .with_attack_scenario("1. Attacker crafts malicious search query\n2. Query is not properly sanitized\n3. Malicious SQL is executed on database")
    .with_dread(DreadScore::new(9, 8, 7, 10, 6));

    sql_injection.add_mitigation(
        Mitigation::new(
            "M001",
            "Use Parameterized Queries",
            "All database queries must use parameterized queries or prepared statements",
        )
        .with_status(ImplementationStatus::Implemented)
        .with_effectiveness(MitigationEffectiveness::Full)
        .with_cost(MitigationCost::Low),
    );

    sql_injection.add_mitigation(
        Mitigation::new(
            "M002",
            "Input Validation",
            "Implement strict input validation on all API endpoints",
        )
        .with_status(ImplementationStatus::InProgress)
        .with_effectiveness(MitigationEffectiveness::Significant)
        .with_cost(MitigationCost::Medium),
    );

    sql_injection.status = ThreatStatus::Mitigated;
    model.add_threat(sql_injection);

    // Generate report
    println!("=== Threat Model Summary ===\n");
    let summary = model.summary();
    println!("Total threats identified: {}", summary.total_threats);
    println!("  Critical: {}", summary.critical);
    println!("  High: {}", summary.high);
    println!("  Medium: {}", summary.medium);
    println!("  Low: {}", summary.low);
    println!("  Mitigated: {}", summary.mitigated);

    println!("\nBy STRIDE Category:");
    for category in StrideCategory::all() {
        let count = summary.by_category.get(&category).unwrap_or(&0);
        println!("  {} ({}): {}", category, category.abbreviation(), count);
    }

    println!("\n=== Unmitigated Threats ===\n");
    for threat in model.unmitigated_threats().iter().take(5) {
        println!("{}: {} [{:?}]", threat.id, threat.title, threat.severity());
    }
    if model.unmitigated_threats().len() > 5 {
        println!("... and {} more", model.unmitigated_threats().len() - 5);
    }

    // Export partial markdown
    println!("\n=== Markdown Export (truncated) ===\n");
    let markdown = model.to_markdown();
    for line in markdown.lines().take(40) {
        println!("{}", line);
    }
    println!("...");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stride_categories() {
        assert_eq!(StrideCategory::Spoofing.abbreviation(), 'S');
        assert_eq!(StrideCategory::Tampering.abbreviation(), 'T');
        assert_eq!(StrideCategory::all().len(), 6);
    }

    #[test]
    fn test_stride_security_property() {
        assert_eq!(
            StrideCategory::Spoofing.security_property(),
            "Authentication"
        );
        assert_eq!(
            StrideCategory::InformationDisclosure.security_property(),
            "Confidentiality"
        );
    }

    #[test]
    fn test_dread_score() {
        let score = DreadScore::new(8, 7, 9, 10, 6);
        assert!((score.total() - 8.0).abs() < 0.01);
        assert_eq!(score.severity(), RiskSeverity::High);
    }

    #[test]
    fn test_dread_score_max() {
        let score = DreadScore::new(15, 15, 15, 15, 15); // Should be capped at 10
        assert_eq!(score.damage_potential, 10);
        assert_eq!(score.total(), 10.0);
    }

    #[test]
    fn test_component_applicable_threats() {
        let external = ComponentType::ExternalEntity;
        let threats = external.applicable_threats();
        assert!(threats.contains(&StrideCategory::Spoofing));
        assert!(!threats.contains(&StrideCategory::Tampering));

        let process = ComponentType::Process;
        assert_eq!(process.applicable_threats().len(), 6);
    }

    #[test]
    fn test_component_creation() {
        let component = Component::new("C1", "Test", ComponentType::Process)
            .with_description("Test component")
            .with_trust_level(TrustLevel::Trusted);

        assert_eq!(component.id, "C1");
        assert_eq!(component.trust_level, TrustLevel::Trusted);
    }

    #[test]
    fn test_data_flow_creation() {
        let flow = DataFlow::new("DF1", "Test Flow", "A", "B")
            .encrypted()
            .authenticated();

        assert!(flow.encrypted);
        assert!(flow.authenticated);
    }

    #[test]
    fn test_threat_creation() {
        let threat = Threat::new("T001", "Test Threat", StrideCategory::Spoofing)
            .with_description("Test description")
            .with_component("C1");

        assert_eq!(threat.category, StrideCategory::Spoofing);
        assert!(threat.affected_components.contains(&"C1".to_string()));
    }

    #[test]
    fn test_threat_severity() {
        let threat = Threat::new("T001", "Test", StrideCategory::Spoofing)
            .with_dread(DreadScore::new(9, 9, 9, 9, 9));

        assert_eq!(threat.severity(), RiskSeverity::Critical);
    }

    #[test]
    fn test_mitigation_creation() {
        let mitigation = Mitigation::new("M001", "Test", "Description")
            .with_status(ImplementationStatus::Implemented)
            .with_effectiveness(MitigationEffectiveness::Full);

        assert_eq!(
            mitigation.implementation_status,
            ImplementationStatus::Implemented
        );
        assert_eq!(mitigation.effectiveness, MitigationEffectiveness::Full);
    }

    #[test]
    fn test_threat_model_creation() {
        let model = ThreatModel::new("Test Model");
        assert_eq!(model.name, "Test Model");
        assert!(model.components.is_empty());
    }

    #[test]
    fn test_threat_model_add_component() {
        let mut model = ThreatModel::new("Test");
        model.add_component(Component::new("C1", "Test", ComponentType::Process));
        assert_eq!(model.components.len(), 1);
    }

    #[test]
    fn test_threat_identification() {
        let mut model = ThreatModel::new("Test");
        model.add_component(Component::new("C1", "Test", ComponentType::Process));
        model.identify_threats();
        assert!(!model.threats.is_empty());
    }

    #[test]
    fn test_unmitigated_threats() {
        let mut model = ThreatModel::new("Test");
        model.add_threat(Threat::new("T1", "Test", StrideCategory::Spoofing));

        let unmitigated = model.unmitigated_threats();
        assert_eq!(unmitigated.len(), 1);
    }

    #[test]
    fn test_summary() {
        let mut model = ThreatModel::new("Test");
        model.add_threat(
            Threat::new("T1", "Test", StrideCategory::Spoofing)
                .with_dread(DreadScore::new(9, 9, 9, 9, 9)),
        );

        let summary = model.summary();
        assert_eq!(summary.total_threats, 1);
        assert_eq!(summary.critical, 1);
    }

    #[test]
    fn test_risk_severity_from_dread() {
        assert_eq!(RiskSeverity::from_dread_score(9.5), RiskSeverity::Critical);
        assert_eq!(RiskSeverity::from_dread_score(7.5), RiskSeverity::High);
        assert_eq!(RiskSeverity::from_dread_score(5.0), RiskSeverity::Medium);
        assert_eq!(RiskSeverity::from_dread_score(2.0), RiskSeverity::Low);
    }
}
