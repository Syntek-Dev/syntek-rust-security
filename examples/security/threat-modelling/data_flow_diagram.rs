//! Data Flow Diagram (DFD) for Threat Modelling
//!
//! Demonstrates creating and analyzing DFDs for security assessment.

use std::collections::{HashMap, HashSet};

/// Element types in a Data Flow Diagram
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElementType {
    /// External entity (user, external system)
    ExternalEntity,
    /// Process that transforms data
    Process,
    /// Data store (database, file, cache)
    DataStore,
}

/// A trust boundary in the DFD
#[derive(Debug, Clone)]
pub struct TrustBoundary {
    pub id: String,
    pub name: String,
    pub trust_level: TrustLevel,
    pub elements: HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    Untrusted,
    PartiallyTrusted,
    Trusted,
    HighlyTrusted,
}

/// An element in the DFD
#[derive(Debug, Clone)]
pub struct DfdElement {
    pub id: String,
    pub name: String,
    pub element_type: ElementType,
    pub description: String,
    pub trust_boundary: Option<String>,
}

/// A data flow between elements
#[derive(Debug, Clone)]
pub struct DataFlow {
    pub id: String,
    pub source: String,
    pub destination: String,
    pub data_description: String,
    pub protocol: Option<String>,
    pub encrypted: bool,
    pub authenticated: bool,
    pub data_classification: DataClassification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

/// The complete Data Flow Diagram
pub struct DataFlowDiagram {
    pub name: String,
    elements: HashMap<String, DfdElement>,
    flows: Vec<DataFlow>,
    trust_boundaries: HashMap<String, TrustBoundary>,
}

impl DataFlowDiagram {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            elements: HashMap::new(),
            flows: Vec::new(),
            trust_boundaries: HashMap::new(),
        }
    }

    pub fn add_element(&mut self, element: DfdElement) {
        self.elements.insert(element.id.clone(), element);
    }

    pub fn add_flow(&mut self, flow: DataFlow) {
        self.flows.push(flow);
    }

    pub fn add_trust_boundary(&mut self, boundary: TrustBoundary) {
        self.trust_boundaries.insert(boundary.id.clone(), boundary);
    }

    /// Find flows that cross trust boundaries
    pub fn find_boundary_crossings(&self) -> Vec<BoundaryCrossing> {
        let mut crossings = Vec::new();

        for flow in &self.flows {
            let source_boundary = self.get_element_boundary(&flow.source);
            let dest_boundary = self.get_element_boundary(&flow.destination);

            if source_boundary != dest_boundary {
                let source_trust = source_boundary
                    .and_then(|b| self.trust_boundaries.get(b))
                    .map(|b| b.trust_level)
                    .unwrap_or(TrustLevel::Untrusted);

                let dest_trust = dest_boundary
                    .and_then(|b| self.trust_boundaries.get(b))
                    .map(|b| b.trust_level)
                    .unwrap_or(TrustLevel::Untrusted);

                crossings.push(BoundaryCrossing {
                    flow: flow.clone(),
                    source_boundary: source_boundary.map(String::from),
                    dest_boundary: dest_boundary.map(String::from),
                    trust_direction: if source_trust < dest_trust {
                        TrustDirection::IntoTrusted
                    } else if source_trust > dest_trust {
                        TrustDirection::IntoUntrusted
                    } else {
                        TrustDirection::SameLevel
                    },
                });
            }
        }

        crossings
    }

    fn get_element_boundary(&self, element_id: &str) -> Option<&str> {
        self.elements
            .get(element_id)
            .and_then(|e| e.trust_boundary.as_deref())
    }

    /// Find security issues in the DFD
    pub fn analyze_security(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        // Check for unencrypted sensitive data flows
        for flow in &self.flows {
            if !flow.encrypted && flow.data_classification >= DataClassification::Confidential {
                findings.push(SecurityFinding {
                    severity: FindingSeverity::High,
                    category: "Encryption".to_string(),
                    description: format!(
                        "Sensitive data ({:?}) flows unencrypted from {} to {}",
                        flow.data_classification, flow.source, flow.destination
                    ),
                    recommendation: "Enable TLS/encryption for this data flow".to_string(),
                    affected_flow: Some(flow.id.clone()),
                });
            }
        }

        // Check for unauthenticated flows across trust boundaries
        for crossing in self.find_boundary_crossings() {
            if !crossing.flow.authenticated {
                findings.push(SecurityFinding {
                    severity: FindingSeverity::Medium,
                    category: "Authentication".to_string(),
                    description: format!(
                        "Unauthenticated data flow '{}' crosses trust boundary",
                        crossing.flow.id
                    ),
                    recommendation: "Add authentication for cross-boundary flows".to_string(),
                    affected_flow: Some(crossing.flow.id.clone()),
                });
            }

            // High-risk: data flowing into trusted zone
            if crossing.trust_direction == TrustDirection::IntoTrusted {
                findings.push(SecurityFinding {
                    severity: FindingSeverity::Medium,
                    category: "Trust Boundary".to_string(),
                    description: format!(
                        "Data flows from untrusted to trusted zone: {} -> {}",
                        crossing.flow.source, crossing.flow.destination
                    ),
                    recommendation: "Validate and sanitize all input from untrusted sources"
                        .to_string(),
                    affected_flow: Some(crossing.flow.id.clone()),
                });
            }
        }

        // Check for direct external access to data stores
        for flow in &self.flows {
            let source = self.elements.get(&flow.source);
            let dest = self.elements.get(&flow.destination);

            if let (Some(src), Some(dst)) = (source, dest) {
                if src.element_type == ElementType::ExternalEntity
                    && dst.element_type == ElementType::DataStore
                {
                    findings.push(SecurityFinding {
                        severity: FindingSeverity::Critical,
                        category: "Access Control".to_string(),
                        description: format!(
                            "External entity '{}' has direct access to data store '{}'",
                            src.name, dst.name
                        ),
                        recommendation: "Route access through an intermediary process".to_string(),
                        affected_flow: Some(flow.id.clone()),
                    });
                }
            }
        }

        findings
    }

    /// Generate DFD visualization in DOT format
    pub fn to_dot(&self) -> String {
        let mut dot = String::new();
        dot.push_str(&format!("digraph \"{}\" {{\n", self.name));
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [fontname=\"Arial\"];\n\n");

        // Draw trust boundaries as subgraphs
        for (id, boundary) in &self.trust_boundaries {
            dot.push_str(&format!("  subgraph cluster_{} {{\n", id));
            dot.push_str(&format!(
                "    label=\"{} ({:?})\";\n",
                boundary.name, boundary.trust_level
            ));
            dot.push_str("    style=dashed;\n");

            for element_id in &boundary.elements {
                dot.push_str(&format!("    {};\n", element_id));
            }
            dot.push_str("  }\n\n");
        }

        // Draw elements
        for (id, element) in &self.elements {
            let shape = match element.element_type {
                ElementType::ExternalEntity => "box",
                ElementType::Process => "ellipse",
                ElementType::DataStore => "cylinder",
            };
            dot.push_str(&format!(
                "  {} [label=\"{}\" shape={}];\n",
                id, element.name, shape
            ));
        }

        dot.push_str("\n");

        // Draw flows
        for flow in &self.flows {
            let style = if flow.encrypted { "bold" } else { "dashed" };
            let color = match flow.data_classification {
                DataClassification::Restricted => "red",
                DataClassification::Confidential => "orange",
                DataClassification::Internal => "blue",
                DataClassification::Public => "black",
            };
            dot.push_str(&format!(
                "  {} -> {} [label=\"{}\" style={} color={}];\n",
                flow.source, flow.destination, flow.data_description, style, color
            ));
        }

        dot.push_str("}\n");
        dot
    }
}

#[derive(Debug, Clone)]
pub struct BoundaryCrossing {
    pub flow: DataFlow,
    pub source_boundary: Option<String>,
    pub dest_boundary: Option<String>,
    pub trust_direction: TrustDirection,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrustDirection {
    IntoTrusted,
    IntoUntrusted,
    SameLevel,
}

#[derive(Debug, Clone)]
pub struct SecurityFinding {
    pub severity: FindingSeverity,
    pub category: String,
    pub description: String,
    pub recommendation: String,
    pub affected_flow: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

fn main() {
    let mut dfd = DataFlowDiagram::new("Web Application DFD");

    // Add trust boundaries
    dfd.add_trust_boundary(TrustBoundary {
        id: "external".to_string(),
        name: "Internet".to_string(),
        trust_level: TrustLevel::Untrusted,
        elements: ["user", "attacker"].into_iter().map(String::from).collect(),
    });

    dfd.add_trust_boundary(TrustBoundary {
        id: "dmz".to_string(),
        name: "DMZ".to_string(),
        trust_level: TrustLevel::PartiallyTrusted,
        elements: ["web_server", "api_gateway"]
            .into_iter()
            .map(String::from)
            .collect(),
    });

    dfd.add_trust_boundary(TrustBoundary {
        id: "internal".to_string(),
        name: "Internal Network".to_string(),
        trust_level: TrustLevel::Trusted,
        elements: ["app_server", "database"]
            .into_iter()
            .map(String::from)
            .collect(),
    });

    // Add elements
    dfd.add_element(DfdElement {
        id: "user".to_string(),
        name: "User".to_string(),
        element_type: ElementType::ExternalEntity,
        description: "End user accessing the application".to_string(),
        trust_boundary: Some("external".to_string()),
    });

    dfd.add_element(DfdElement {
        id: "web_server".to_string(),
        name: "Web Server".to_string(),
        element_type: ElementType::Process,
        description: "Nginx reverse proxy".to_string(),
        trust_boundary: Some("dmz".to_string()),
    });

    dfd.add_element(DfdElement {
        id: "api_gateway".to_string(),
        name: "API Gateway".to_string(),
        element_type: ElementType::Process,
        description: "API authentication and routing".to_string(),
        trust_boundary: Some("dmz".to_string()),
    });

    dfd.add_element(DfdElement {
        id: "app_server".to_string(),
        name: "Application Server".to_string(),
        element_type: ElementType::Process,
        description: "Business logic processing".to_string(),
        trust_boundary: Some("internal".to_string()),
    });

    dfd.add_element(DfdElement {
        id: "database".to_string(),
        name: "PostgreSQL".to_string(),
        element_type: ElementType::DataStore,
        description: "Primary database".to_string(),
        trust_boundary: Some("internal".to_string()),
    });

    // Add data flows
    dfd.add_flow(DataFlow {
        id: "F1".to_string(),
        source: "user".to_string(),
        destination: "web_server".to_string(),
        data_description: "HTTPS Request".to_string(),
        protocol: Some("HTTPS".to_string()),
        encrypted: true,
        authenticated: false,
        data_classification: DataClassification::Internal,
    });

    dfd.add_flow(DataFlow {
        id: "F2".to_string(),
        source: "web_server".to_string(),
        destination: "api_gateway".to_string(),
        data_description: "API Request".to_string(),
        protocol: Some("HTTP".to_string()),
        encrypted: false, // Internal traffic not encrypted
        authenticated: true,
        data_classification: DataClassification::Internal,
    });

    dfd.add_flow(DataFlow {
        id: "F3".to_string(),
        source: "api_gateway".to_string(),
        destination: "app_server".to_string(),
        data_description: "Authenticated Request".to_string(),
        protocol: Some("gRPC".to_string()),
        encrypted: true,
        authenticated: true,
        data_classification: DataClassification::Confidential,
    });

    dfd.add_flow(DataFlow {
        id: "F4".to_string(),
        source: "app_server".to_string(),
        destination: "database".to_string(),
        data_description: "SQL Queries".to_string(),
        protocol: Some("PostgreSQL".to_string()),
        encrypted: false, // Often unencrypted in internal network
        authenticated: true,
        data_classification: DataClassification::Restricted,
    });

    // Analyze
    println!("=== Data Flow Diagram: {} ===\n", dfd.name);

    println!("Trust Boundary Crossings:");
    for crossing in dfd.find_boundary_crossings() {
        println!(
            "  {} -> {} ({:?})",
            crossing.flow.source, crossing.flow.destination, crossing.trust_direction
        );
    }

    println!("\n=== Security Findings ===\n");
    let findings = dfd.analyze_security();
    for finding in &findings {
        println!("[{:?}] {}", finding.severity, finding.category);
        println!("  Description: {}", finding.description);
        println!("  Recommendation: {}", finding.recommendation);
        println!();
    }

    println!("\n=== DOT Output (for Graphviz) ===\n");
    println!("{}", dfd.to_dot());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boundary_crossing_detection() {
        let mut dfd = DataFlowDiagram::new("Test");

        dfd.add_trust_boundary(TrustBoundary {
            id: "external".to_string(),
            name: "External".to_string(),
            trust_level: TrustLevel::Untrusted,
            elements: ["A"].into_iter().map(String::from).collect(),
        });

        dfd.add_trust_boundary(TrustBoundary {
            id: "internal".to_string(),
            name: "Internal".to_string(),
            trust_level: TrustLevel::Trusted,
            elements: ["B"].into_iter().map(String::from).collect(),
        });

        dfd.add_element(DfdElement {
            id: "A".to_string(),
            name: "A".to_string(),
            element_type: ElementType::ExternalEntity,
            description: String::new(),
            trust_boundary: Some("external".to_string()),
        });

        dfd.add_element(DfdElement {
            id: "B".to_string(),
            name: "B".to_string(),
            element_type: ElementType::Process,
            description: String::new(),
            trust_boundary: Some("internal".to_string()),
        });

        dfd.add_flow(DataFlow {
            id: "F1".to_string(),
            source: "A".to_string(),
            destination: "B".to_string(),
            data_description: "Data".to_string(),
            protocol: None,
            encrypted: false,
            authenticated: false,
            data_classification: DataClassification::Internal,
        });

        let crossings = dfd.find_boundary_crossings();
        assert_eq!(crossings.len(), 1);
        assert_eq!(crossings[0].trust_direction, TrustDirection::IntoTrusted);
    }

    #[test]
    fn test_unencrypted_sensitive_data_finding() {
        let mut dfd = DataFlowDiagram::new("Test");

        dfd.add_element(DfdElement {
            id: "A".to_string(),
            name: "A".to_string(),
            element_type: ElementType::Process,
            description: String::new(),
            trust_boundary: None,
        });

        dfd.add_element(DfdElement {
            id: "B".to_string(),
            name: "B".to_string(),
            element_type: ElementType::Process,
            description: String::new(),
            trust_boundary: None,
        });

        dfd.add_flow(DataFlow {
            id: "F1".to_string(),
            source: "A".to_string(),
            destination: "B".to_string(),
            data_description: "Passwords".to_string(),
            protocol: None,
            encrypted: false,
            authenticated: true,
            data_classification: DataClassification::Restricted,
        });

        let findings = dfd.analyze_security();
        assert!(findings.iter().any(|f| f.category == "Encryption"));
    }
}
