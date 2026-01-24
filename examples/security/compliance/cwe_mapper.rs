//! CWE (Common Weakness Enumeration) Mapper Example
//!
//! Demonstrates mapping security findings to CWE identifiers
//! for standardized vulnerability classification.

use std::collections::HashMap;

/// CWE entry with full details
#[derive(Debug, Clone)]
pub struct CweEntry {
    pub id: u32,
    pub name: String,
    pub description: String,
    pub extended_description: Option<String>,
    pub likelihood_of_exploit: Likelihood,
    pub typical_severity: Severity,
    pub related_cwes: Vec<u32>,
    pub related_attacks: Vec<String>,
    pub mitigations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Likelihood {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// CWE database for Rust-relevant weaknesses
pub struct CweDatabase {
    entries: HashMap<u32, CweEntry>,
}

impl Default for CweDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl CweDatabase {
    pub fn new() -> Self {
        let mut entries = HashMap::new();

        // Memory safety weaknesses
        entries.insert(119, CweEntry {
            id: 119,
            name: "Improper Restriction of Operations within the Bounds of a Memory Buffer".to_string(),
            description: "The software performs operations on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer.".to_string(),
            extended_description: Some("Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.".to_string()),
            likelihood_of_exploit: Likelihood::High,
            typical_severity: Severity::Critical,
            related_cwes: vec![120, 125, 787],
            related_attacks: vec!["Buffer Overflow".to_string()],
            mitigations: vec![
                "Use safe Rust code without unsafe blocks".to_string(),
                "When using unsafe, carefully validate all bounds".to_string(),
                "Use slice methods that perform bounds checking".to_string(),
            ],
        });

        entries.insert(125, CweEntry {
            id: 125,
            name: "Out-of-bounds Read".to_string(),
            description: "The software reads data past the end, or before the beginning, of the intended buffer.".to_string(),
            extended_description: None,
            likelihood_of_exploit: Likelihood::High,
            typical_severity: Severity::High,
            related_cwes: vec![119, 126, 127],
            related_attacks: vec!["Information Disclosure".to_string()],
            mitigations: vec![
                "Use .get() instead of direct indexing".to_string(),
                "Validate indices before use".to_string(),
            ],
        });

        entries.insert(416, CweEntry {
            id: 416,
            name: "Use After Free".to_string(),
            description: "Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code.".to_string(),
            extended_description: Some("The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code.".to_string()),
            likelihood_of_exploit: Likelihood::High,
            typical_severity: Severity::Critical,
            related_cwes: vec![119, 825],
            related_attacks: vec!["Arbitrary Code Execution".to_string()],
            mitigations: vec![
                "Rust's ownership system prevents this in safe code".to_string(),
                "Audit all unsafe code for manual memory management".to_string(),
                "Use smart pointers (Box, Rc, Arc)".to_string(),
            ],
        });

        // Injection weaknesses
        entries.insert(89, CweEntry {
            id: 89,
            name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')".to_string(),
            description: "The software constructs all or part of an SQL command using externally-influenced input from an upstream component.".to_string(),
            extended_description: None,
            likelihood_of_exploit: Likelihood::High,
            typical_severity: Severity::Critical,
            related_cwes: vec![20, 74, 707],
            related_attacks: vec!["SQL Injection".to_string()],
            mitigations: vec![
                "Use parameterized queries with sqlx or diesel".to_string(),
                "Never concatenate user input into SQL strings".to_string(),
                "Use prepared statements".to_string(),
            ],
        });

        entries.insert(78, CweEntry {
            id: 78,
            name: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')".to_string(),
            description: "The software constructs all or part of an OS command using externally-influenced input.".to_string(),
            extended_description: None,
            likelihood_of_exploit: Likelihood::High,
            typical_severity: Severity::Critical,
            related_cwes: vec![77, 88],
            related_attacks: vec!["Command Injection".to_string()],
            mitigations: vec![
                "Avoid shell=true or shell invocation".to_string(),
                "Use Command::new() with explicit arguments".to_string(),
                "Validate and sanitize all input".to_string(),
            ],
        });

        // Cryptographic weaknesses
        entries.insert(327, CweEntry {
            id: 327,
            name: "Use of a Broken or Risky Cryptographic Algorithm".to_string(),
            description: "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.".to_string(),
            extended_description: None,
            likelihood_of_exploit: Likelihood::Medium,
            typical_severity: Severity::High,
            related_cwes: vec![326, 328],
            related_attacks: vec!["Cryptanalysis".to_string()],
            mitigations: vec![
                "Use AES-GCM or ChaCha20-Poly1305 for encryption".to_string(),
                "Use SHA-256 or better for hashing".to_string(),
                "Use Argon2id for password hashing".to_string(),
            ],
        });

        entries.insert(321, CweEntry {
            id: 321,
            name: "Use of Hard-coded Cryptographic Key".to_string(),
            description: "The use of a hard-coded cryptographic key significantly increases the possibility that encrypted data may be recovered.".to_string(),
            extended_description: None,
            likelihood_of_exploit: Likelihood::High,
            typical_severity: Severity::Critical,
            related_cwes: vec![259, 798],
            related_attacks: vec!["Key Recovery".to_string()],
            mitigations: vec![
                "Store keys in secure key management systems".to_string(),
                "Use environment variables or secret managers".to_string(),
                "Derive keys from secure sources".to_string(),
            ],
        });

        // Authentication weaknesses
        entries.insert(287, CweEntry {
            id: 287,
            name: "Improper Authentication".to_string(),
            description: "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.".to_string(),
            extended_description: None,
            likelihood_of_exploit: Likelihood::High,
            typical_severity: Severity::Critical,
            related_cwes: vec![284, 306],
            related_attacks: vec!["Authentication Bypass".to_string()],
            mitigations: vec![
                "Implement proper authentication mechanisms".to_string(),
                "Use established authentication libraries".to_string(),
                "Implement MFA where appropriate".to_string(),
            ],
        });

        // SSRF weakness
        entries.insert(918, CweEntry {
            id: 918,
            name: "Server-Side Request Forgery (SSRF)".to_string(),
            description: "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.".to_string(),
            extended_description: None,
            likelihood_of_exploit: Likelihood::Medium,
            typical_severity: Severity::High,
            related_cwes: vec![441, 610],
            related_attacks: vec!["SSRF".to_string()],
            mitigations: vec![
                "Validate URLs against an allowlist".to_string(),
                "Block requests to internal IP ranges".to_string(),
                "Use DNS resolution controls".to_string(),
            ],
        });

        Self { entries }
    }

    pub fn get(&self, id: u32) -> Option<&CweEntry> {
        self.entries.get(&id)
    }

    pub fn search(&self, keyword: &str) -> Vec<&CweEntry> {
        let keyword_lower = keyword.to_lowercase();
        self.entries
            .values()
            .filter(|e| {
                e.name.to_lowercase().contains(&keyword_lower)
                    || e.description.to_lowercase().contains(&keyword_lower)
            })
            .collect()
    }

    pub fn by_severity(&self, min_severity: Severity) -> Vec<&CweEntry> {
        self.entries
            .values()
            .filter(|e| e.typical_severity >= min_severity)
            .collect()
    }

    pub fn get_related(&self, id: u32) -> Vec<&CweEntry> {
        if let Some(entry) = self.entries.get(&id) {
            entry
                .related_cwes
                .iter()
                .filter_map(|related_id| self.entries.get(related_id))
                .collect()
        } else {
            Vec::new()
        }
    }
}

/// Mapping from security finding patterns to CWEs
pub struct CweMapper {
    patterns: Vec<(String, Vec<u32>)>,
}

impl Default for CweMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl CweMapper {
    pub fn new() -> Self {
        let patterns = vec![
            // Memory safety
            ("buffer overflow".to_string(), vec![119, 120, 787]),
            ("out of bounds".to_string(), vec![119, 125, 787]),
            ("use after free".to_string(), vec![416]),
            ("double free".to_string(), vec![415]),
            ("null pointer".to_string(), vec![476]),
            ("uninitialized".to_string(), vec![457, 908]),
            ("integer overflow".to_string(), vec![190, 191]),
            // Injection
            ("sql injection".to_string(), vec![89]),
            ("command injection".to_string(), vec![78]),
            ("code injection".to_string(), vec![94]),
            ("xpath injection".to_string(), vec![643]),
            ("ldap injection".to_string(), vec![90]),
            // Cryptography
            ("weak crypto".to_string(), vec![327, 328]),
            ("hardcoded key".to_string(), vec![321]),
            ("hardcoded password".to_string(), vec![259, 798]),
            ("insecure random".to_string(), vec![330, 338]),
            ("md5".to_string(), vec![327, 328]),
            ("sha1".to_string(), vec![327, 328]),
            // Authentication/Authorization
            ("authentication bypass".to_string(), vec![287]),
            ("missing auth".to_string(), vec![306]),
            ("broken access control".to_string(), vec![284, 285]),
            ("privilege escalation".to_string(), vec![269]),
            // Other
            ("ssrf".to_string(), vec![918]),
            ("path traversal".to_string(), vec![22]),
            ("xss".to_string(), vec![79]),
            ("open redirect".to_string(), vec![601]),
            ("information disclosure".to_string(), vec![200]),
            ("race condition".to_string(), vec![362]),
        ];

        Self { patterns }
    }

    /// Map a finding description to relevant CWE IDs
    pub fn map(&self, description: &str) -> Vec<u32> {
        let desc_lower = description.to_lowercase();
        let mut cwes = Vec::new();

        for (pattern, ids) in &self.patterns {
            if desc_lower.contains(pattern) {
                cwes.extend(ids.iter().copied());
            }
        }

        // Deduplicate
        cwes.sort();
        cwes.dedup();
        cwes
    }

    /// Get full CWE details for mapped findings
    pub fn map_with_details<'a>(
        &self,
        description: &str,
        db: &'a CweDatabase,
    ) -> Vec<&'a CweEntry> {
        self.map(description)
            .iter()
            .filter_map(|id| db.get(*id))
            .collect()
    }
}

/// Generate a CWE-focused vulnerability report
pub fn generate_cwe_report(findings: &[(String, Vec<u32>)], db: &CweDatabase) -> String {
    let mut report = String::new();

    report.push_str("# CWE Vulnerability Report\n\n");

    // Collect all unique CWEs
    let mut all_cwes: Vec<u32> = findings
        .iter()
        .flat_map(|(_, cwes)| cwes.iter().copied())
        .collect();
    all_cwes.sort();
    all_cwes.dedup();

    report.push_str(&format!("Total unique CWEs: {}\n\n", all_cwes.len()));

    // Group findings by CWE
    let mut by_cwe: HashMap<u32, Vec<&str>> = HashMap::new();
    for (desc, cwes) in findings {
        for cwe in cwes {
            by_cwe.entry(*cwe).or_default().push(desc.as_str());
        }
    }

    for cwe_id in all_cwes {
        if let Some(entry) = db.get(cwe_id) {
            report.push_str(&format!("## CWE-{}: {}\n\n", entry.id, entry.name));
            report.push_str(&format!("**Severity**: {:?}\n", entry.typical_severity));
            report.push_str(&format!(
                "**Likelihood**: {:?}\n\n",
                entry.likelihood_of_exploit
            ));
            report.push_str(&format!("{}\n\n", entry.description));

            if let Some(findings) = by_cwe.get(&cwe_id) {
                report.push_str("**Related Findings:**\n");
                for finding in findings {
                    report.push_str(&format!("- {}\n", finding));
                }
                report.push('\n');
            }

            report.push_str("**Mitigations:**\n");
            for mitigation in &entry.mitigations {
                report.push_str(&format!("- {}\n", mitigation));
            }
            report.push_str("\n---\n\n");
        }
    }

    report
}

fn main() {
    println!("CWE Mapper Example");
    println!("==================\n");

    let db = CweDatabase::new();
    let mapper = CweMapper::new();

    // Example findings to map
    let findings = vec![
        "Potential SQL injection in user query",
        "Use of MD5 hash for password storage",
        "Buffer overflow in unsafe block",
        "Hardcoded API key detected",
        "SSRF vulnerability in URL fetch",
    ];

    println!("Mapping findings to CWEs:\n");

    let mut mapped_findings = Vec::new();

    for finding in &findings {
        let cwes = mapper.map(finding);
        println!("Finding: {}", finding);
        println!("  Mapped CWEs: {:?}", cwes);

        for cwe_id in &cwes {
            if let Some(entry) = db.get(*cwe_id) {
                println!("    CWE-{}: {}", entry.id, entry.name);
            }
        }
        println!();

        mapped_findings.push((finding.to_string(), cwes));
    }

    // Generate report
    println!("\n{}", "=".repeat(60));
    println!("\nGenerated CWE Report:");
    println!("{}", generate_cwe_report(&mapped_findings, &db));

    // Search demonstration
    println!("\nSearching for 'injection' related CWEs:");
    for entry in db.search("injection") {
        println!("  CWE-{}: {}", entry.id, entry.name);
    }

    // Severity filter demonstration
    println!("\nCritical severity CWEs:");
    for entry in db.by_severity(Severity::Critical) {
        println!("  CWE-{}: {}", entry.id, entry.name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cwe_database() {
        let db = CweDatabase::new();

        let entry = db.get(89).unwrap();
        assert_eq!(
            entry.name,
            "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
        );
    }

    #[test]
    fn test_cwe_search() {
        let db = CweDatabase::new();
        let results = db.search("injection");

        assert!(!results.is_empty());
        assert!(results.iter().any(|e| e.id == 89));
    }

    #[test]
    fn test_cwe_by_severity() {
        let db = CweDatabase::new();
        let critical = db.by_severity(Severity::Critical);

        assert!(!critical.is_empty());
        assert!(critical
            .iter()
            .all(|e| e.typical_severity >= Severity::Critical));
    }

    #[test]
    fn test_cwe_mapper() {
        let mapper = CweMapper::new();

        let cwes = mapper.map("sql injection vulnerability");
        assert!(cwes.contains(&89));

        let cwes = mapper.map("buffer overflow in parser");
        assert!(cwes.contains(&119));
    }

    #[test]
    fn test_mapper_deduplication() {
        let mapper = CweMapper::new();
        let cwes = mapper.map("sql injection and more sql injection");

        let mut sorted = cwes.clone();
        sorted.sort();
        sorted.dedup();

        assert_eq!(cwes, sorted);
    }

    #[test]
    fn test_map_with_details() {
        let db = CweDatabase::new();
        let mapper = CweMapper::new();

        let entries = mapper.map_with_details("hardcoded password found", &db);
        assert!(!entries.is_empty());
    }

    #[test]
    fn test_related_cwes() {
        let db = CweDatabase::new();
        let related = db.get_related(89);

        assert!(!related.is_empty());
    }

    #[test]
    fn test_report_generation() {
        let db = CweDatabase::new();
        let findings = vec![
            ("SQL injection".to_string(), vec![89]),
            ("Buffer overflow".to_string(), vec![119]),
        ];

        let report = generate_cwe_report(&findings, &db);

        assert!(report.contains("CWE-89"));
        assert!(report.contains("CWE-119"));
        assert!(report.contains("Mitigations"));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }
}
