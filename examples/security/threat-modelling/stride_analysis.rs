//! STRIDE Threat Modelling Example
//!
//! Demonstrates systematic threat analysis using the STRIDE methodology.

use std::collections::HashMap;

/// STRIDE threat categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StrideCategory {
    Spoofing,
    Tampering,
    Repudiation,
    InformationDisclosure,
    DenialOfService,
    ElevationOfPrivilege,
}

impl StrideCategory {
    pub fn description(&self) -> &'static str {
        match self {
            Self::Spoofing => "Impersonating something or someone else",
            Self::Tampering => "Modifying data or code",
            Self::Repudiation => "Claiming to have not performed an action",
            Self::InformationDisclosure => "Exposing information to unauthorized parties",
            Self::DenialOfService => "Denying or degrading service to users",
            Self::ElevationOfPrivilege => "Gaining capabilities without proper authorization",
        }
    }

    pub fn mitigations(&self) -> Vec<&'static str> {
        match self {
            Self::Spoofing => vec![
                "Strong authentication (MFA)",
                "Digital signatures",
                "Certificate validation",
            ],
            Self::Tampering => vec![
                "Input validation",
                "Integrity checks (HMAC, signatures)",
                "Access control lists",
            ],
            Self::Repudiation => vec![
                "Audit logging",
                "Digital signatures",
                "Timestamps with trusted time source",
            ],
            Self::InformationDisclosure => vec![
                "Encryption at rest and in transit",
                "Access control",
                "Data classification",
            ],
            Self::DenialOfService => vec![
                "Rate limiting",
                "Resource quotas",
                "Redundancy and failover",
            ],
            Self::ElevationOfPrivilege => vec![
                "Principle of least privilege",
                "Role-based access control",
                "Input validation",
            ],
        }
    }
}

/// A threat identified in the system
#[derive(Debug, Clone)]
pub struct Threat {
    pub id: String,
    pub category: StrideCategory,
    pub component: String,
    pub description: String,
    pub severity: ThreatSeverity,
    pub mitigations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// System component for analysis
#[derive(Debug, Clone)]
pub struct Component {
    pub name: String,
    pub component_type: ComponentType,
    pub trust_boundary: Option<String>,
    pub data_flows: Vec<DataFlow>,
}

#[derive(Debug, Clone, Copy)]
pub enum ComponentType {
    Process,
    DataStore,
    ExternalEntity,
    DataFlow,
}

#[derive(Debug, Clone)]
pub struct DataFlow {
    pub source: String,
    pub destination: String,
    pub data_type: String,
    pub encrypted: bool,
}

/// STRIDE threat model analyzer
pub struct ThreatModelAnalyzer {
    components: Vec<Component>,
    threats: Vec<Threat>,
}

impl ThreatModelAnalyzer {
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
            threats: Vec::new(),
        }
    }

    pub fn add_component(&mut self, component: Component) {
        self.components.push(component);
    }

    /// Analyze all components for STRIDE threats
    pub fn analyze(&mut self) {
        for component in &self.components {
            self.analyze_component(component.clone());
        }
    }

    fn analyze_component(&mut self, component: Component) {
        match component.component_type {
            ComponentType::Process => {
                // Processes are subject to all STRIDE categories
                self.check_spoofing(&component);
                self.check_tampering(&component);
                self.check_repudiation(&component);
                self.check_information_disclosure(&component);
                self.check_dos(&component);
                self.check_elevation(&component);
            }
            ComponentType::DataStore => {
                // Data stores: Tampering, Information Disclosure, DoS
                self.check_tampering(&component);
                self.check_information_disclosure(&component);
                self.check_dos(&component);
            }
            ComponentType::ExternalEntity => {
                // External entities: Spoofing, Repudiation
                self.check_spoofing(&component);
                self.check_repudiation(&component);
            }
            ComponentType::DataFlow => {
                // Data flows: Tampering, Information Disclosure, DoS
                for flow in &component.data_flows {
                    if !flow.encrypted {
                        self.threats.push(Threat {
                            id: format!("T-{}-DISC", self.threats.len() + 1),
                            category: StrideCategory::InformationDisclosure,
                            component: component.name.clone(),
                            description: format!(
                                "Unencrypted data flow '{}' from {} to {}",
                                flow.data_type, flow.source, flow.destination
                            ),
                            severity: ThreatSeverity::High,
                            mitigations: vec!["Enable TLS encryption".to_string()],
                        });
                    }
                }
            }
        }
    }

    fn check_spoofing(&mut self, component: &Component) {
        self.threats.push(Threat {
            id: format!("T-{}-SPOOF", self.threats.len() + 1),
            category: StrideCategory::Spoofing,
            component: component.name.clone(),
            description: format!(
                "An attacker could impersonate {} to gain unauthorized access",
                component.name
            ),
            severity: ThreatSeverity::High,
            mitigations: StrideCategory::Spoofing.mitigations()
                .iter().map(|s| s.to_string()).collect(),
        });
    }

    fn check_tampering(&mut self, component: &Component) {
        self.threats.push(Threat {
            id: format!("T-{}-TAMP", self.threats.len() + 1),
            category: StrideCategory::Tampering,
            component: component.name.clone(),
            description: format!(
                "An attacker could modify data processed by {}",
                component.name
            ),
            severity: ThreatSeverity::Medium,
            mitigations: StrideCategory::Tampering.mitigations()
                .iter().map(|s| s.to_string()).collect(),
        });
    }

    fn check_repudiation(&mut self, component: &Component) {
        self.threats.push(Threat {
            id: format!("T-{}-REP", self.threats.len() + 1),
            category: StrideCategory::Repudiation,
            component: component.name.clone(),
            description: format!(
                "Actions performed by {} may not be properly logged",
                component.name
            ),
            severity: ThreatSeverity::Medium,
            mitigations: StrideCategory::Repudiation.mitigations()
                .iter().map(|s| s.to_string()).collect(),
        });
    }

    fn check_information_disclosure(&mut self, component: &Component) {
        self.threats.push(Threat {
            id: format!("T-{}-INFO", self.threats.len() + 1),
            category: StrideCategory::InformationDisclosure,
            component: component.name.clone(),
            description: format!(
                "Sensitive data in {} could be exposed to unauthorized parties",
                component.name
            ),
            severity: ThreatSeverity::High,
            mitigations: StrideCategory::InformationDisclosure.mitigations()
                .iter().map(|s| s.to_string()).collect(),
        });
    }

    fn check_dos(&mut self, component: &Component) {
        self.threats.push(Threat {
            id: format!("T-{}-DOS", self.threats.len() + 1),
            category: StrideCategory::DenialOfService,
            component: component.name.clone(),
            description: format!(
                "{} could be overwhelmed by malicious requests",
                component.name
            ),
            severity: ThreatSeverity::Medium,
            mitigations: StrideCategory::DenialOfService.mitigations()
                .iter().map(|s| s.to_string()).collect(),
        });
    }

    fn check_elevation(&mut self, component: &Component) {
        self.threats.push(Threat {
            id: format!("T-{}-ELEV", self.threats.len() + 1),
            category: StrideCategory::ElevationOfPrivilege,
            component: component.name.clone(),
            description: format!(
                "An attacker could gain elevated privileges through {}",
                component.name
            ),
            severity: ThreatSeverity::Critical,
            mitigations: StrideCategory::ElevationOfPrivilege.mitigations()
                .iter().map(|s| s.to_string()).collect(),
        });
    }

    /// Get all identified threats
    pub fn get_threats(&self) -> &[Threat] {
        &self.threats
    }

    /// Get threats by severity
    pub fn get_threats_by_severity(&self, severity: ThreatSeverity) -> Vec<&Threat> {
        self.threats.iter().filter(|t| t.severity == severity).collect()
    }

    /// Generate threat report
    pub fn generate_report(&self) -> String {
        let mut report = String::new();
        report.push_str("# STRIDE Threat Model Report\n\n");

        let mut by_category: HashMap<StrideCategory, Vec<&Threat>> = HashMap::new();
        for threat in &self.threats {
            by_category.entry(threat.category).or_default().push(threat);
        }

        for (category, threats) in &by_category {
            report.push_str(&format!("## {:?}\n", category));
            report.push_str(&format!("_{}_\n\n", category.description()));

            for threat in threats {
                report.push_str(&format!("### {}\n", threat.id));
                report.push_str(&format!("- **Component**: {}\n", threat.component));
                report.push_str(&format!("- **Severity**: {:?}\n", threat.severity));
                report.push_str(&format!("- **Description**: {}\n", threat.description));
                report.push_str("- **Mitigations**:\n");
                for m in &threat.mitigations {
                    report.push_str(&format!("  - {}\n", m));
                }
                report.push('\n');
            }
        }

        report
    }
}

impl Default for ThreatModelAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

fn main() {
    let mut analyzer = ThreatModelAnalyzer::new();

    // Define system components
    analyzer.add_component(Component {
        name: "Web API".to_string(),
        component_type: ComponentType::Process,
        trust_boundary: Some("DMZ".to_string()),
        data_flows: vec![
            DataFlow {
                source: "Client".to_string(),
                destination: "Web API".to_string(),
                data_type: "HTTP Request".to_string(),
                encrypted: true,
            },
        ],
    });

    analyzer.add_component(Component {
        name: "Database".to_string(),
        component_type: ComponentType::DataStore,
        trust_boundary: Some("Internal".to_string()),
        data_flows: vec![],
    });

    analyzer.add_component(Component {
        name: "External User".to_string(),
        component_type: ComponentType::ExternalEntity,
        trust_boundary: None,
        data_flows: vec![],
    });

    // Run analysis
    analyzer.analyze();

    // Generate report
    let report = analyzer.generate_report();
    println!("{}", report);

    // Show critical threats
    let critical = analyzer.get_threats_by_severity(ThreatSeverity::Critical);
    println!("\n## Critical Threats: {}", critical.len());
    for threat in critical {
        println!("  - {}: {}", threat.id, threat.description);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stride_analysis() {
        let mut analyzer = ThreatModelAnalyzer::new();
        analyzer.add_component(Component {
            name: "TestProcess".to_string(),
            component_type: ComponentType::Process,
            trust_boundary: None,
            data_flows: vec![],
        });

        analyzer.analyze();

        // Process components should have 6 threat categories
        assert_eq!(analyzer.get_threats().len(), 6);
    }

    #[test]
    fn test_data_store_threats() {
        let mut analyzer = ThreatModelAnalyzer::new();
        analyzer.add_component(Component {
            name: "Database".to_string(),
            component_type: ComponentType::DataStore,
            trust_boundary: None,
            data_flows: vec![],
        });

        analyzer.analyze();

        // Data stores have 3 applicable threat categories
        assert_eq!(analyzer.get_threats().len(), 3);
    }
}
