//! Software Bill of Materials (SBOM) Generator Example
//!
//! Demonstrates generating SBOM in CycloneDX and SPDX formats for Rust projects.
//! SBOMs are critical for supply chain transparency and vulnerability tracking.

use std::collections::HashMap;

/// Package information for SBOM
#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub license: Option<String>,
    pub description: Option<String>,
    pub authors: Vec<String>,
    pub repository: Option<String>,
    pub checksum: Option<PackageChecksum>,
    pub dependencies: Vec<String>,
    pub purl: String,
}

#[derive(Debug, Clone)]
pub struct PackageChecksum {
    pub algorithm: String,
    pub value: String,
}

impl Package {
    pub fn new(name: &str, version: &str) -> Self {
        let purl = format!("pkg:cargo/{}@{}", name, version);
        Self {
            name: name.to_string(),
            version: version.to_string(),
            license: None,
            description: None,
            authors: Vec::new(),
            repository: None,
            checksum: None,
            dependencies: Vec::new(),
            purl,
        }
    }

    pub fn with_license(mut self, license: &str) -> Self {
        self.license = Some(license.to_string());
        self
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }

    pub fn with_repository(mut self, repo: &str) -> Self {
        self.repository = Some(repo.to_string());
        self
    }

    pub fn with_checksum(mut self, algorithm: &str, value: &str) -> Self {
        self.checksum = Some(PackageChecksum {
            algorithm: algorithm.to_string(),
            value: value.to_string(),
        });
        self
    }

    pub fn add_dependency(&mut self, dep: &str) {
        self.dependencies.push(dep.to_string());
    }
}

/// SBOM metadata
#[derive(Debug, Clone)]
pub struct SbomMetadata {
    pub name: String,
    pub version: String,
    pub timestamp: String,
    pub tool_name: String,
    pub tool_version: String,
    pub authors: Vec<String>,
}

impl Default for SbomMetadata {
    fn default() -> Self {
        Self {
            name: "Unknown".to_string(),
            version: "0.0.0".to_string(),
            timestamp: chrono_now(),
            tool_name: "syntek-rust-security".to_string(),
            tool_version: "0.1.0".to_string(),
            authors: Vec::new(),
        }
    }
}

fn chrono_now() -> String {
    // Simplified timestamp - would use chrono crate in production
    "2025-01-01T00:00:00Z".to_string()
}

/// SBOM generator supporting multiple formats
pub struct SbomGenerator {
    pub metadata: SbomMetadata,
    pub packages: Vec<Package>,
}

impl SbomGenerator {
    pub fn new(metadata: SbomMetadata) -> Self {
        Self {
            metadata,
            packages: Vec::new(),
        }
    }

    pub fn add_package(&mut self, package: Package) {
        self.packages.push(package);
    }

    /// Generate CycloneDX 1.5 JSON format
    pub fn to_cyclonedx_json(&self) -> String {
        let mut json = String::new();
        json.push_str("{\n");
        json.push_str("  \"bomFormat\": \"CycloneDX\",\n");
        json.push_str("  \"specVersion\": \"1.5\",\n");
        json.push_str(&format!(
            "  \"serialNumber\": \"urn:uuid:{}\",\n",
            generate_uuid()
        ));
        json.push_str("  \"version\": 1,\n");

        // Metadata
        json.push_str("  \"metadata\": {\n");
        json.push_str(&format!(
            "    \"timestamp\": \"{}\",\n",
            self.metadata.timestamp
        ));
        json.push_str("    \"tools\": [{\n");
        json.push_str(&format!(
            "      \"name\": \"{}\",\n",
            self.metadata.tool_name
        ));
        json.push_str(&format!(
            "      \"version\": \"{}\"\n",
            self.metadata.tool_version
        ));
        json.push_str("    }],\n");
        json.push_str("    \"component\": {\n");
        json.push_str("      \"type\": \"application\",\n");
        json.push_str(&format!("      \"name\": \"{}\",\n", self.metadata.name));
        json.push_str(&format!(
            "      \"version\": \"{}\"\n",
            self.metadata.version
        ));
        json.push_str("    }\n");
        json.push_str("  },\n");

        // Components
        json.push_str("  \"components\": [\n");
        for (i, pkg) in self.packages.iter().enumerate() {
            json.push_str("    {\n");
            json.push_str("      \"type\": \"library\",\n");
            json.push_str(&format!("      \"name\": \"{}\",\n", pkg.name));
            json.push_str(&format!("      \"version\": \"{}\",\n", pkg.version));
            json.push_str(&format!("      \"purl\": \"{}\",\n", pkg.purl));

            if let Some(ref license) = pkg.license {
                json.push_str(&format!(
                    "      \"licenses\": [{{\"license\": {{\"id\": \"{}\"}}}}],\n",
                    license
                ));
            }

            if let Some(ref checksum) = pkg.checksum {
                json.push_str(&format!(
                    "      \"hashes\": [{{\"alg\": \"{}\", \"content\": \"{}\"}}]\n",
                    checksum.algorithm, checksum.value
                ));
            } else {
                // Remove trailing comma from purl line
                json = json.trim_end_matches(",\n").to_string();
                json.push('\n');
            }

            if i < self.packages.len() - 1 {
                json.push_str("    },\n");
            } else {
                json.push_str("    }\n");
            }
        }
        json.push_str("  ],\n");

        // Dependencies
        json.push_str("  \"dependencies\": [\n");
        for (i, pkg) in self.packages.iter().enumerate() {
            json.push_str("    {\n");
            json.push_str(&format!("      \"ref\": \"{}\",\n", pkg.purl));
            json.push_str("      \"dependsOn\": [");
            if !pkg.dependencies.is_empty() {
                json.push('\n');
                for (j, dep) in pkg.dependencies.iter().enumerate() {
                    json.push_str(&format!("        \"{}\"", dep));
                    if j < pkg.dependencies.len() - 1 {
                        json.push(',');
                    }
                    json.push('\n');
                }
                json.push_str("      ");
            }
            json.push_str("]\n");

            if i < self.packages.len() - 1 {
                json.push_str("    },\n");
            } else {
                json.push_str("    }\n");
            }
        }
        json.push_str("  ]\n");

        json.push_str("}\n");
        json
    }

    /// Generate SPDX 2.3 JSON format
    pub fn to_spdx_json(&self) -> String {
        let mut json = String::new();
        json.push_str("{\n");
        json.push_str("  \"spdxVersion\": \"SPDX-2.3\",\n");
        json.push_str("  \"dataLicense\": \"CC0-1.0\",\n");
        json.push_str(&format!("  \"SPDXID\": \"SPDXRef-DOCUMENT\",\n"));
        json.push_str(&format!("  \"name\": \"{}\",\n", self.metadata.name));
        json.push_str(&format!(
            "  \"documentNamespace\": \"https://example.com/sbom/{}-{}\",\n",
            self.metadata.name,
            generate_uuid()
        ));

        // Creation info
        json.push_str("  \"creationInfo\": {\n");
        json.push_str(&format!(
            "    \"created\": \"{}\",\n",
            self.metadata.timestamp
        ));
        json.push_str(&format!(
            "    \"creators\": [\"Tool: {}-{}\"]\n",
            self.metadata.tool_name, self.metadata.tool_version
        ));
        json.push_str("  },\n");

        // Packages
        json.push_str("  \"packages\": [\n");
        for (i, pkg) in self.packages.iter().enumerate() {
            let spdx_id = format!("SPDXRef-Package-{}", pkg.name.replace('-', ""));

            json.push_str("    {\n");
            json.push_str(&format!("      \"SPDXID\": \"{}\",\n", spdx_id));
            json.push_str(&format!("      \"name\": \"{}\",\n", pkg.name));
            json.push_str(&format!("      \"versionInfo\": \"{}\",\n", pkg.version));
            json.push_str("      \"downloadLocation\": \"NOASSERTION\",\n");
            json.push_str("      \"filesAnalyzed\": false,\n");

            if let Some(ref license) = pkg.license {
                json.push_str(&format!("      \"licenseConcluded\": \"{}\",\n", license));
                json.push_str(&format!("      \"licenseDeclared\": \"{}\",\n", license));
            } else {
                json.push_str("      \"licenseConcluded\": \"NOASSERTION\",\n");
                json.push_str("      \"licenseDeclared\": \"NOASSERTION\",\n");
            }

            json.push_str("      \"copyrightText\": \"NOASSERTION\",\n");
            json.push_str(&format!(
                "      \"externalRefs\": [{{\n        \"referenceCategory\": \"PACKAGE-MANAGER\",\n        \"referenceType\": \"purl\",\n        \"referenceLocator\": \"{}\"\n      }}]\n",
                pkg.purl
            ));

            if i < self.packages.len() - 1 {
                json.push_str("    },\n");
            } else {
                json.push_str("    }\n");
            }
        }
        json.push_str("  ],\n");

        // Relationships
        json.push_str("  \"relationships\": [\n");
        json.push_str("    {\n");
        json.push_str("      \"spdxElementId\": \"SPDXRef-DOCUMENT\",\n");
        json.push_str("      \"relationshipType\": \"DESCRIBES\",\n");
        json.push_str(&format!(
            "      \"relatedSpdxElement\": \"SPDXRef-Package-{}\"\n",
            self.metadata.name.replace('-', "")
        ));
        json.push_str("    }\n");
        json.push_str("  ]\n");

        json.push_str("}\n");
        json
    }

    /// Generate simple text format for humans
    pub fn to_text(&self) -> String {
        let mut text = String::new();

        text.push_str(&format!(
            "Software Bill of Materials: {}\n",
            self.metadata.name
        ));
        text.push_str(&format!("Version: {}\n", self.metadata.version));
        text.push_str(&format!("Generated: {}\n", self.metadata.timestamp));
        text.push_str(&format!(
            "Tool: {} {}\n",
            self.metadata.tool_name, self.metadata.tool_version
        ));
        text.push_str(&format!("\nTotal packages: {}\n\n", self.packages.len()));
        text.push_str("=".repeat(60).as_str());
        text.push_str("\n\n");

        for pkg in &self.packages {
            text.push_str(&format!("{} @ {}\n", pkg.name, pkg.version));
            text.push_str(&format!("  PURL: {}\n", pkg.purl));

            if let Some(ref license) = pkg.license {
                text.push_str(&format!("  License: {}\n", license));
            }

            if let Some(ref desc) = pkg.description {
                text.push_str(&format!("  Description: {}\n", desc));
            }

            if let Some(ref repo) = pkg.repository {
                text.push_str(&format!("  Repository: {}\n", repo));
            }

            if let Some(ref checksum) = pkg.checksum {
                text.push_str(&format!(
                    "  Checksum ({}): {}\n",
                    checksum.algorithm, checksum.value
                ));
            }

            if !pkg.dependencies.is_empty() {
                text.push_str("  Dependencies:\n");
                for dep in &pkg.dependencies {
                    text.push_str(&format!("    - {}\n", dep));
                }
            }

            text.push('\n');
        }

        text
    }
}

fn generate_uuid() -> String {
    // Simplified UUID generation - would use uuid crate in production
    "00000000-0000-0000-0000-000000000000".to_string()
}

/// Parse Cargo.lock to extract dependencies
pub fn parse_cargo_lock(_content: &str) -> Vec<Package> {
    // Simplified - would parse actual Cargo.lock format
    Vec::new()
}

fn main() {
    println!("SBOM Generator Example");
    println!("======================\n");

    // Create metadata
    let metadata = SbomMetadata {
        name: "my-secure-app".to_string(),
        version: "1.0.0".to_string(),
        timestamp: "2025-01-01T12:00:00Z".to_string(),
        tool_name: "syntek-rust-security".to_string(),
        tool_version: "0.1.0".to_string(),
        authors: vec!["Security Team".to_string()],
    };

    // Create generator
    let mut generator = SbomGenerator::new(metadata);

    // Add packages
    let mut tokio = Package::new("tokio", "1.35.0")
        .with_license("MIT")
        .with_description("An event-driven, non-blocking I/O platform")
        .with_repository("https://github.com/tokio-rs/tokio")
        .with_checksum("SHA256", "abc123def456...");
    tokio.add_dependency("pkg:cargo/mio@0.8.10");
    tokio.add_dependency("pkg:cargo/bytes@1.5.0");
    generator.add_package(tokio);

    generator.add_package(
        Package::new("serde", "1.0.195")
            .with_license("MIT OR Apache-2.0")
            .with_description("A serialization framework"),
    );

    generator.add_package(
        Package::new("ring", "0.17.7")
            .with_license("ISC AND MIT AND OpenSSL")
            .with_description("Safe, fast cryptography"),
    );

    // Generate outputs
    println!("Text Format:");
    println!("============");
    println!("{}", generator.to_text());

    println!("\nCycloneDX JSON (truncated):");
    println!("============================");
    let cyclonedx = generator.to_cyclonedx_json();
    for line in cyclonedx.lines().take(30) {
        println!("{}", line);
    }
    println!("...\n");

    println!("SPDX JSON (truncated):");
    println!("======================");
    let spdx = generator.to_spdx_json();
    for line in spdx.lines().take(30) {
        println!("{}", line);
    }
    println!("...");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_creation() {
        let pkg = Package::new("test-crate", "1.0.0");

        assert_eq!(pkg.name, "test-crate");
        assert_eq!(pkg.version, "1.0.0");
        assert_eq!(pkg.purl, "pkg:cargo/test-crate@1.0.0");
    }

    #[test]
    fn test_package_builder() {
        let pkg = Package::new("test", "1.0.0")
            .with_license("MIT")
            .with_description("Test package")
            .with_repository("https://github.com/test/test")
            .with_checksum("SHA256", "abc123");

        assert_eq!(pkg.license, Some("MIT".to_string()));
        assert_eq!(pkg.description, Some("Test package".to_string()));
        assert!(pkg.checksum.is_some());
    }

    #[test]
    fn test_package_dependencies() {
        let mut pkg = Package::new("main", "1.0.0");
        pkg.add_dependency("pkg:cargo/dep1@1.0.0");
        pkg.add_dependency("pkg:cargo/dep2@2.0.0");

        assert_eq!(pkg.dependencies.len(), 2);
    }

    #[test]
    fn test_sbom_generator() {
        let metadata = SbomMetadata::default();
        let mut generator = SbomGenerator::new(metadata);

        generator.add_package(Package::new("test", "1.0.0"));
        assert_eq!(generator.packages.len(), 1);
    }

    #[test]
    fn test_cyclonedx_output() {
        let metadata = SbomMetadata {
            name: "test-app".to_string(),
            version: "1.0.0".to_string(),
            ..Default::default()
        };

        let mut generator = SbomGenerator::new(metadata);
        generator.add_package(Package::new("dep", "1.0.0").with_license("MIT"));

        let json = generator.to_cyclonedx_json();

        assert!(json.contains("\"bomFormat\": \"CycloneDX\""));
        assert!(json.contains("\"specVersion\": \"1.5\""));
        assert!(json.contains("\"name\": \"dep\""));
    }

    #[test]
    fn test_spdx_output() {
        let metadata = SbomMetadata {
            name: "test-app".to_string(),
            version: "1.0.0".to_string(),
            ..Default::default()
        };

        let mut generator = SbomGenerator::new(metadata);
        generator.add_package(Package::new("dep", "1.0.0"));

        let json = generator.to_spdx_json();

        assert!(json.contains("\"spdxVersion\": \"SPDX-2.3\""));
        assert!(json.contains("\"dataLicense\": \"CC0-1.0\""));
        assert!(json.contains("\"name\": \"dep\""));
    }

    #[test]
    fn test_text_output() {
        let metadata = SbomMetadata {
            name: "test-app".to_string(),
            version: "1.0.0".to_string(),
            ..Default::default()
        };

        let mut generator = SbomGenerator::new(metadata);
        generator.add_package(
            Package::new("test-dep", "2.0.0")
                .with_license("Apache-2.0")
                .with_description("A test dependency"),
        );

        let text = generator.to_text();

        assert!(text.contains("test-app"));
        assert!(text.contains("test-dep @ 2.0.0"));
        assert!(text.contains("Apache-2.0"));
        assert!(text.contains("A test dependency"));
    }
}
