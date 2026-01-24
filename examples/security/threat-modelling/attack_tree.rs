//! Attack Tree Analysis Example
//!
//! Demonstrates building and analyzing attack trees for security assessment.

use std::fmt;

/// Node in an attack tree
#[derive(Debug, Clone)]
pub struct AttackNode {
    pub id: String,
    pub name: String,
    pub description: String,
    pub node_type: NodeType,
    pub children: Vec<AttackNode>,
    pub attributes: AttackAttributes,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NodeType {
    /// Root goal of the attack
    Goal,
    /// Sub-goal that contributes to parent
    SubGoal,
    /// Concrete attack action
    Attack,
    /// AND node - all children must succeed
    And,
    /// OR node - any child can succeed
    Or,
}

#[derive(Debug, Clone, Default)]
pub struct AttackAttributes {
    /// Cost to execute the attack (1-10)
    pub cost: u8,
    /// Technical difficulty (1-10)
    pub difficulty: u8,
    /// Likelihood of detection (1-10)
    pub detection_risk: u8,
    /// Potential impact if successful (1-10)
    pub impact: u8,
    /// Whether a mitigation exists
    pub mitigated: bool,
    /// Associated CVE if applicable
    pub cve: Option<String>,
}

impl AttackNode {
    pub fn new_goal(id: &str, name: &str, description: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            node_type: NodeType::Goal,
            children: Vec::new(),
            attributes: AttackAttributes::default(),
        }
    }

    pub fn new_attack(id: &str, name: &str, attrs: AttackAttributes) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: String::new(),
            node_type: NodeType::Attack,
            children: Vec::new(),
            attributes: attrs,
        }
    }

    pub fn new_and(id: &str, name: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: String::new(),
            node_type: NodeType::And,
            children: Vec::new(),
            attributes: AttackAttributes::default(),
        }
    }

    pub fn new_or(id: &str, name: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: String::new(),
            node_type: NodeType::Or,
            children: Vec::new(),
            attributes: AttackAttributes::default(),
        }
    }

    pub fn add_child(&mut self, child: AttackNode) {
        self.children.push(child);
    }

    /// Calculate the minimum cost path to achieve this node
    pub fn min_cost(&self) -> u8 {
        if self.children.is_empty() {
            return self.attributes.cost;
        }

        match self.node_type {
            NodeType::And => {
                // AND: sum of all children costs
                self.children.iter().map(|c| c.min_cost()).sum()
            }
            NodeType::Or | NodeType::Goal | NodeType::SubGoal | NodeType::Attack => {
                // OR: minimum of children costs
                self.children
                    .iter()
                    .map(|c| c.min_cost())
                    .min()
                    .unwrap_or(0)
            }
        }
    }

    /// Calculate attack feasibility score (lower is more feasible)
    pub fn feasibility_score(&self) -> f32 {
        let attrs = &self.attributes;
        (attrs.cost as f32 + attrs.difficulty as f32 + attrs.detection_risk as f32) / 3.0
    }

    /// Calculate risk score (higher is more dangerous)
    pub fn risk_score(&self) -> f32 {
        let feasibility = 10.0 - self.feasibility_score();
        let impact = self.attributes.impact as f32;
        (feasibility * impact) / 10.0
    }

    /// Check if the attack path is mitigated
    pub fn is_mitigated(&self) -> bool {
        if self.attributes.mitigated {
            return true;
        }

        match self.node_type {
            NodeType::And => {
                // AND: any child mitigated blocks the path
                self.children.iter().any(|c| c.is_mitigated())
            }
            NodeType::Or => {
                // OR: all children must be mitigated
                !self.children.is_empty() && self.children.iter().all(|c| c.is_mitigated())
            }
            _ => self.children.iter().all(|c| c.is_mitigated()),
        }
    }

    /// Find all unmitigated leaf attacks
    pub fn find_unmitigated_attacks(&self) -> Vec<&AttackNode> {
        let mut attacks = Vec::new();
        self.collect_unmitigated(&mut attacks);
        attacks
    }

    fn collect_unmitigated<'a>(&'a self, attacks: &mut Vec<&'a AttackNode>) {
        if self.node_type == NodeType::Attack && !self.attributes.mitigated {
            attacks.push(self);
        }
        for child in &self.children {
            child.collect_unmitigated(attacks);
        }
    }

    /// Generate a text representation of the tree
    pub fn to_text(&self, indent: usize) -> String {
        let mut output = String::new();
        let prefix = "  ".repeat(indent);
        let node_marker = match self.node_type {
            NodeType::Goal => "[GOAL]",
            NodeType::SubGoal => "[SUB]",
            NodeType::Attack => "[ATK]",
            NodeType::And => "[AND]",
            NodeType::Or => "[OR]",
        };

        let status = if self.attributes.mitigated {
            " (MITIGATED)"
        } else {
            ""
        };
        output.push_str(&format!(
            "{}{} {}{}\n",
            prefix, node_marker, self.name, status
        ));

        if self.node_type == NodeType::Attack {
            output.push_str(&format!(
                "{}  Cost:{} Diff:{} Detect:{} Impact:{}\n",
                prefix,
                self.attributes.cost,
                self.attributes.difficulty,
                self.attributes.detection_risk,
                self.attributes.impact
            ));
        }

        for child in &self.children {
            output.push_str(&child.to_text(indent + 1));
        }

        output
    }
}

impl fmt::Display for AttackNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_text(0))
    }
}

/// Attack tree analyzer
pub struct AttackTreeAnalyzer {
    root: AttackNode,
}

impl AttackTreeAnalyzer {
    pub fn new(root: AttackNode) -> Self {
        Self { root }
    }

    /// Get the root node
    pub fn root(&self) -> &AttackNode {
        &self.root
    }

    /// Get mutable root node
    pub fn root_mut(&mut self) -> &mut AttackNode {
        &mut self.root
    }

    /// Find highest risk attack paths
    pub fn highest_risk_attacks(&self) -> Vec<(&AttackNode, f32)> {
        let attacks = self.root.find_unmitigated_attacks();
        let mut scored: Vec<_> = attacks.iter().map(|a| (*a, a.risk_score())).collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        scored
    }

    /// Find cheapest attack paths
    pub fn cheapest_attacks(&self) -> Vec<(&AttackNode, u8)> {
        let attacks = self.root.find_unmitigated_attacks();
        let mut scored: Vec<_> = attacks.iter().map(|a| (*a, a.attributes.cost)).collect();
        scored.sort_by_key(|a| a.1);
        scored
    }

    /// Generate security recommendations
    pub fn generate_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();

        let high_risk = self.highest_risk_attacks();
        for (attack, score) in high_risk.iter().take(5) {
            if *score > 5.0 {
                recommendations.push(format!(
                    "HIGH PRIORITY: Mitigate '{}' (risk score: {:.1})",
                    attack.name, score
                ));
            }
        }

        let cheap_attacks = self.cheapest_attacks();
        for (attack, cost) in cheap_attacks.iter().take(3) {
            if *cost <= 3 {
                recommendations.push(format!(
                    "LOW-COST THREAT: '{}' can be executed with cost {} - prioritize mitigation",
                    attack.name, cost
                ));
            }
        }

        recommendations
    }

    /// Check if the goal is achievable
    pub fn is_goal_achievable(&self) -> bool {
        !self.root.is_mitigated()
    }
}

fn main() {
    // Build an attack tree for "Steal User Credentials"
    let mut root = AttackNode::new_goal(
        "G1",
        "Steal User Credentials",
        "Attacker obtains valid user credentials",
    );

    // OR: Multiple ways to steal credentials
    let mut credential_theft = AttackNode::new_or("O1", "Credential Theft Methods");

    // Method 1: Phishing
    credential_theft.add_child(AttackNode::new_attack(
        "A1",
        "Phishing Attack",
        AttackAttributes {
            cost: 2,
            difficulty: 3,
            detection_risk: 4,
            impact: 8,
            mitigated: false,
            cve: None,
        },
    ));

    // Method 2: SQL Injection
    let mut sqli = AttackNode::new_attack(
        "A2",
        "SQL Injection",
        AttackAttributes {
            cost: 3,
            difficulty: 5,
            detection_risk: 6,
            impact: 9,
            mitigated: true, // Parameterized queries in place
            cve: Some("CWE-89".to_string()),
        },
    );
    credential_theft.add_child(sqli);

    // Method 3: Brute Force (AND - requires multiple steps)
    let mut brute_force = AttackNode::new_and("AND1", "Brute Force Attack");
    brute_force.add_child(AttackNode::new_attack(
        "A3a",
        "Enumerate Usernames",
        AttackAttributes {
            cost: 2,
            difficulty: 2,
            detection_risk: 5,
            impact: 3,
            mitigated: false,
            cve: None,
        },
    ));
    brute_force.add_child(AttackNode::new_attack(
        "A3b",
        "Password Spray",
        AttackAttributes {
            cost: 3,
            difficulty: 3,
            detection_risk: 7,
            impact: 8,
            mitigated: false,
            cve: None,
        },
    ));
    credential_theft.add_child(brute_force);

    // Method 4: Session Hijacking
    credential_theft.add_child(AttackNode::new_attack(
        "A4",
        "Session Hijacking",
        AttackAttributes {
            cost: 4,
            difficulty: 6,
            detection_risk: 5,
            impact: 8,
            mitigated: true, // Secure cookies enabled
            cve: None,
        },
    ));

    root.add_child(credential_theft);

    // Analyze the tree
    let analyzer = AttackTreeAnalyzer::new(root);

    println!("=== Attack Tree ===\n");
    println!("{}", analyzer.root());

    println!("\n=== Analysis ===\n");
    println!("Goal achievable: {}", analyzer.is_goal_achievable());
    println!(
        "Minimum cost to achieve goal: {}",
        analyzer.root().min_cost()
    );

    println!("\n=== Highest Risk Attacks ===");
    for (attack, score) in analyzer.highest_risk_attacks().iter().take(3) {
        println!("  - {} (risk: {:.1})", attack.name, score);
    }

    println!("\n=== Recommendations ===");
    for rec in analyzer.generate_recommendations() {
        println!("  - {}", rec);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_and_node_cost() {
        let mut and_node = AttackNode::new_and("AND", "Test AND");
        and_node.add_child(AttackNode::new_attack(
            "A1",
            "Attack 1",
            AttackAttributes {
                cost: 5,
                ..Default::default()
            },
        ));
        and_node.add_child(AttackNode::new_attack(
            "A2",
            "Attack 2",
            AttackAttributes {
                cost: 3,
                ..Default::default()
            },
        ));

        // AND node cost is sum of children
        assert_eq!(and_node.min_cost(), 8);
    }

    #[test]
    fn test_or_node_cost() {
        let mut or_node = AttackNode::new_or("OR", "Test OR");
        or_node.add_child(AttackNode::new_attack(
            "A1",
            "Attack 1",
            AttackAttributes {
                cost: 5,
                ..Default::default()
            },
        ));
        or_node.add_child(AttackNode::new_attack(
            "A2",
            "Attack 2",
            AttackAttributes {
                cost: 3,
                ..Default::default()
            },
        ));

        // OR node cost is minimum of children
        assert_eq!(or_node.min_cost(), 3);
    }

    #[test]
    fn test_mitigation() {
        let mut or_node = AttackNode::new_or("OR", "Test");
        or_node.add_child(AttackNode::new_attack(
            "A1",
            "Mitigated",
            AttackAttributes {
                mitigated: true,
                ..Default::default()
            },
        ));
        or_node.add_child(AttackNode::new_attack(
            "A2",
            "Not Mitigated",
            AttackAttributes {
                mitigated: false,
                ..Default::default()
            },
        ));

        // OR node with one unmitigated child is not fully mitigated
        assert!(!or_node.is_mitigated());
    }
}
