# Rust Threat Detection Skills

This skill provides patterns for building threat detection systems in Rust,
including malware signature matching, YARA rule processing, entropy analysis,
and heuristic detection.

## Overview

Threat detection encompasses:

- **Signature Matching**: Known malware patterns
- **YARA Rules**: Flexible pattern matching language
- **Entropy Analysis**: Detect packed/encrypted content
- **Heuristic Detection**: Behavioral analysis
- **IOC Matching**: Indicators of compromise

## /malware-scanner-setup

Initialize a malware scanning engine.

### Usage

```bash
/malware-scanner-setup
```

### What It Does

1. Creates scanner project structure
2. Implements YARA rule loading
3. Sets up signature database
4. Configures entropy analysis
5. Implements quarantine system

---

## YARA Rule Integration

### YARA Rule Compiler

```rust
use std::path::Path;
use std::collections::HashMap;

pub struct YaraEngine {
    compiler: yara::Compiler,
    rules: Option<yara::Rules>,
}

impl YaraEngine {
    pub fn new() -> Result<Self, Error> {
        let compiler = yara::Compiler::new()?;
        Ok(Self {
            compiler,
            rules: None,
        })
    }

    pub fn add_rules_from_file(&mut self, path: &Path) -> Result<(), Error> {
        let content = std::fs::read_to_string(path)?;
        self.compiler.add_rules_str(&content)?;
        Ok(())
    }

    pub fn add_rules_from_string(&mut self, rules: &str) -> Result<(), Error> {
        self.compiler.add_rules_str(rules)?;
        Ok(())
    }

    pub fn compile(&mut self) -> Result<(), Error> {
        let rules = std::mem::replace(&mut self.compiler, yara::Compiler::new()?)
            .compile_rules()?;
        self.rules = Some(rules);
        Ok(())
    }

    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>, Error> {
        let rules = self.rules.as_ref()
            .ok_or(Error::RulesNotCompiled)?;

        let matches = rules.scan_mem(data, 30)?;  // 30 second timeout

        Ok(matches
            .iter()
            .map(|m| YaraMatch {
                rule: m.identifier.to_string(),
                namespace: m.namespace.to_string(),
                tags: m.tags.iter().map(|t| t.to_string()).collect(),
                strings: m.strings
                    .iter()
                    .map(|s| MatchedString {
                        identifier: s.identifier.to_string(),
                        offset: s.matches.first().map(|m| m.offset).unwrap_or(0),
                        data: s.matches.first().map(|m| m.data.clone()).unwrap_or_default(),
                    })
                    .collect(),
            })
            .collect())
    }

    pub fn scan_file(&self, path: &Path) -> Result<Vec<YaraMatch>, Error> {
        let rules = self.rules.as_ref()
            .ok_or(Error::RulesNotCompiled)?;

        let matches = rules.scan_file(path, 60)?;  // 60 second timeout

        Ok(matches
            .iter()
            .map(|m| YaraMatch {
                rule: m.identifier.to_string(),
                namespace: m.namespace.to_string(),
                tags: m.tags.iter().map(|t| t.to_string()).collect(),
                strings: m.strings
                    .iter()
                    .map(|s| MatchedString {
                        identifier: s.identifier.to_string(),
                        offset: s.matches.first().map(|m| m.offset).unwrap_or(0),
                        data: s.matches.first().map(|m| m.data.clone()).unwrap_or_default(),
                    })
                    .collect(),
            })
            .collect())
    }
}

#[derive(Debug, Clone)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub strings: Vec<MatchedString>,
}

#[derive(Debug, Clone)]
pub struct MatchedString {
    pub identifier: String,
    pub offset: usize,
    pub data: Vec<u8>,
}
```

### Common YARA Rules

```rust
pub const SUSPICIOUS_STRINGS_RULE: &str = r#"
rule SuspiciousStrings
{
    meta:
        description = "Detects suspicious strings commonly found in malware"
        severity = "medium"

    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "/bin/sh" nocase
        $cmd3 = "/bin/bash" nocase
        $ps1 = "powershell" nocase
        $wget = "wget " nocase
        $curl = "curl " nocase
        $nc = "netcat" nocase
        $reverse = "reverse shell" nocase

    condition:
        2 of them
}

rule Base64Encoded
{
    meta:
        description = "Detects base64 encoded content"
        severity = "low"

    strings:
        $b64 = /[A-Za-z0-9+\/]{50,}={0,2}/

    condition:
        $b64
}

rule PackedExecutable
{
    meta:
        description = "Detects potentially packed executables"
        severity = "medium"

    condition:
        uint16(0) == 0x5A4D and
        (
            for any i in (0..pe.number_of_sections - 1):
            (
                pe.sections[i].raw_data_size == 0 and
                pe.sections[i].virtual_size > 0
            )
        )
}
"#;

pub const RANSOMWARE_INDICATORS_RULE: &str = r#"
rule RansomwareIndicators
{
    meta:
        description = "Detects common ransomware indicators"
        severity = "critical"

    strings:
        $ransom1 = "your files have been encrypted" nocase
        $ransom2 = "bitcoin" nocase
        $ransom3 = "decrypt" nocase
        $ransom4 = "pay" nocase
        $ransom5 = ".locked" nocase
        $ransom6 = ".encrypted" nocase
        $ransom7 = "README_FOR_DECRYPT" nocase

        $crypto1 = "CryptoLocker" nocase
        $crypto2 = "WannaCry" nocase
        $crypto3 = "Locky" nocase

    condition:
        3 of ($ransom*) or any of ($crypto*)
}
"#;
```

---

## Entropy Analysis

```rust
pub struct EntropyAnalyzer {
    block_size: usize,
    high_entropy_threshold: f64,
}

impl EntropyAnalyzer {
    pub fn new() -> Self {
        Self {
            block_size: 256,
            high_entropy_threshold: 7.0,  // Out of 8.0 max
        }
    }

    pub fn with_block_size(mut self, size: usize) -> Self {
        self.block_size = size;
        self
    }

    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.high_entropy_threshold = threshold;
        self
    }

    /// Calculate Shannon entropy of data (0-8 for bytes)
    pub fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequency = [0u64; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &frequency {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Analyze file for high-entropy regions
    pub fn analyze_file(&self, path: &std::path::Path) -> Result<EntropyReport, Error> {
        let data = std::fs::read(path)?;
        self.analyze_bytes(&data)
    }

    /// Analyze bytes for high-entropy regions
    pub fn analyze_bytes(&self, data: &[u8]) -> Result<EntropyReport, Error> {
        let overall_entropy = self.calculate_entropy(data);
        let mut high_entropy_regions = Vec::new();
        let mut block_entropies = Vec::new();

        for (i, chunk) in data.chunks(self.block_size).enumerate() {
            let entropy = self.calculate_entropy(chunk);
            block_entropies.push(entropy);

            if entropy >= self.high_entropy_threshold {
                high_entropy_regions.push(HighEntropyRegion {
                    offset: i * self.block_size,
                    size: chunk.len(),
                    entropy,
                });
            }
        }

        // Calculate high entropy ratio
        let high_entropy_blocks = block_entropies
            .iter()
            .filter(|&&e| e >= self.high_entropy_threshold)
            .count();
        let high_entropy_ratio = high_entropy_blocks as f64 / block_entropies.len() as f64;

        Ok(EntropyReport {
            overall_entropy,
            high_entropy_regions,
            high_entropy_ratio,
            is_likely_packed: overall_entropy > 7.5,
            is_likely_encrypted: high_entropy_ratio > 0.8,
        })
    }
}

#[derive(Debug)]
pub struct EntropyReport {
    pub overall_entropy: f64,
    pub high_entropy_regions: Vec<HighEntropyRegion>,
    pub high_entropy_ratio: f64,
    pub is_likely_packed: bool,
    pub is_likely_encrypted: bool,
}

#[derive(Debug)]
pub struct HighEntropyRegion {
    pub offset: usize,
    pub size: usize,
    pub entropy: f64,
}
```

---

## Signature Database

```rust
use std::collections::HashMap;

pub struct SignatureDatabase {
    md5_signatures: HashMap<String, MalwareSignature>,
    sha256_signatures: HashMap<String, MalwareSignature>,
    byte_patterns: Vec<BytePatternSignature>,
}

#[derive(Debug, Clone)]
pub struct MalwareSignature {
    pub name: String,
    pub family: String,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct BytePatternSignature {
    pub name: String,
    pub pattern: Vec<u8>,
    pub mask: Option<Vec<u8>>,  // None = exact match, Some = wildcard mask
    pub offset: Option<usize>,   // None = anywhere, Some = specific offset
    pub severity: Severity,
}

impl SignatureDatabase {
    pub fn new() -> Self {
        Self {
            md5_signatures: HashMap::new(),
            sha256_signatures: HashMap::new(),
            byte_patterns: Vec::new(),
        }
    }

    pub fn add_md5_signature(&mut self, hash: &str, signature: MalwareSignature) {
        self.md5_signatures.insert(hash.to_lowercase(), signature);
    }

    pub fn add_sha256_signature(&mut self, hash: &str, signature: MalwareSignature) {
        self.sha256_signatures.insert(hash.to_lowercase(), signature);
    }

    pub fn add_byte_pattern(&mut self, pattern: BytePatternSignature) {
        self.byte_patterns.push(pattern);
    }

    pub fn check_md5(&self, hash: &str) -> Option<&MalwareSignature> {
        self.md5_signatures.get(&hash.to_lowercase())
    }

    pub fn check_sha256(&self, hash: &str) -> Option<&MalwareSignature> {
        self.sha256_signatures.get(&hash.to_lowercase())
    }

    pub fn scan_bytes(&self, data: &[u8]) -> Vec<&BytePatternSignature> {
        let mut matches = Vec::new();

        for sig in &self.byte_patterns {
            if self.pattern_matches(data, sig) {
                matches.push(sig);
            }
        }

        matches
    }

    fn pattern_matches(&self, data: &[u8], sig: &BytePatternSignature) -> bool {
        if let Some(offset) = sig.offset {
            // Check at specific offset
            if offset + sig.pattern.len() > data.len() {
                return false;
            }
            return self.compare_with_mask(&data[offset..], &sig.pattern, sig.mask.as_deref());
        }

        // Search anywhere in data
        for window in data.windows(sig.pattern.len()) {
            if self.compare_with_mask(window, &sig.pattern, sig.mask.as_deref()) {
                return true;
            }
        }

        false
    }

    fn compare_with_mask(&self, data: &[u8], pattern: &[u8], mask: Option<&[u8]>) -> bool {
        if data.len() < pattern.len() {
            return false;
        }

        for i in 0..pattern.len() {
            let mask_byte = mask.map(|m| m.get(i).copied().unwrap_or(0xFF)).unwrap_or(0xFF);
            if (data[i] & mask_byte) != (pattern[i] & mask_byte) {
                return false;
            }
        }

        true
    }

    pub fn load_from_file(&mut self, path: &std::path::Path) -> Result<(), Error> {
        let content = std::fs::read_to_string(path)?;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Format: TYPE:HASH:NAME:FAMILY:SEVERITY:DESCRIPTION
            let parts: Vec<&str> = line.splitn(6, ':').collect();
            if parts.len() < 6 {
                continue;
            }

            let severity = match parts[4].to_lowercase().as_str() {
                "low" => Severity::Low,
                "medium" => Severity::Medium,
                "high" => Severity::High,
                "critical" => Severity::Critical,
                _ => Severity::Medium,
            };

            let signature = MalwareSignature {
                name: parts[2].to_string(),
                family: parts[3].to_string(),
                severity,
                description: parts[5].to_string(),
            };

            match parts[0].to_lowercase().as_str() {
                "md5" => self.add_md5_signature(parts[1], signature),
                "sha256" => self.add_sha256_signature(parts[1], signature),
                _ => {}
            }
        }

        Ok(())
    }
}
```

---

## Heuristic Detection

```rust
pub struct HeuristicAnalyzer {
    rules: Vec<HeuristicRule>,
}

#[derive(Clone)]
pub struct HeuristicRule {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub check: fn(&[u8], &FileMetadata) -> bool,
}

pub struct FileMetadata {
    pub path: std::path::PathBuf,
    pub size: u64,
    pub extension: Option<String>,
    pub is_executable: bool,
}

impl HeuristicAnalyzer {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn with_default_rules() -> Self {
        let mut analyzer = Self::new();

        // Double extension detection
        analyzer.add_rule(HeuristicRule {
            name: "DoubleExtension".to_string(),
            description: "File has double extension (e.g., .pdf.exe)".to_string(),
            severity: Severity::Medium,
            check: |_, meta| {
                if let Some(name) = meta.path.file_name() {
                    let name = name.to_string_lossy();
                    let parts: Vec<&str> = name.split('.').collect();
                    if parts.len() >= 3 {
                        let suspicious_exts = ["exe", "scr", "bat", "cmd", "com", "pif", "js", "vbs"];
                        return suspicious_exts.contains(&parts.last().unwrap().to_lowercase().as_str());
                    }
                }
                false
            },
        });

        // Suspicious file in temp directory
        analyzer.add_rule(HeuristicRule {
            name: "TempExecutable".to_string(),
            description: "Executable in temporary directory".to_string(),
            severity: Severity::Medium,
            check: |_, meta| {
                let path_str = meta.path.to_string_lossy().to_lowercase();
                meta.is_executable && (path_str.contains("/tmp/") || path_str.contains("\\temp\\"))
            },
        });

        // Large entropy executable
        analyzer.add_rule(HeuristicRule {
            name: "PackedExecutable".to_string(),
            description: "Executable with high entropy (possibly packed)".to_string(),
            severity: Severity::Medium,
            check: |data, meta| {
                if !meta.is_executable || data.len() < 1000 {
                    return false;
                }
                let entropy = EntropyAnalyzer::new().calculate_entropy(data);
                entropy > 7.2
            },
        });

        // Hidden executable
        analyzer.add_rule(HeuristicRule {
            name: "HiddenExecutable".to_string(),
            description: "Hidden executable file".to_string(),
            severity: Severity::High,
            check: |_, meta| {
                if let Some(name) = meta.path.file_name() {
                    let name = name.to_string_lossy();
                    return meta.is_executable && name.starts_with('.');
                }
                false
            },
        });

        analyzer
    }

    pub fn add_rule(&mut self, rule: HeuristicRule) {
        self.rules.push(rule);
    }

    pub fn analyze(&self, data: &[u8], metadata: &FileMetadata) -> Vec<HeuristicMatch> {
        let mut matches = Vec::new();

        for rule in &self.rules {
            if (rule.check)(data, metadata) {
                matches.push(HeuristicMatch {
                    rule_name: rule.name.clone(),
                    description: rule.description.clone(),
                    severity: rule.severity,
                });
            }
        }

        matches
    }
}

#[derive(Debug)]
pub struct HeuristicMatch {
    pub rule_name: String,
    pub description: String,
    pub severity: Severity,
}
```

---

## Combined Threat Scanner

```rust
pub struct ThreatScanner {
    yara_engine: YaraEngine,
    signature_db: SignatureDatabase,
    entropy_analyzer: EntropyAnalyzer,
    heuristic_analyzer: HeuristicAnalyzer,
}

impl ThreatScanner {
    pub fn new() -> Result<Self, Error> {
        let mut yara_engine = YaraEngine::new()?;
        yara_engine.add_rules_from_string(SUSPICIOUS_STRINGS_RULE)?;
        yara_engine.add_rules_from_string(RANSOMWARE_INDICATORS_RULE)?;
        yara_engine.compile()?;

        Ok(Self {
            yara_engine,
            signature_db: SignatureDatabase::new(),
            entropy_analyzer: EntropyAnalyzer::new(),
            heuristic_analyzer: HeuristicAnalyzer::with_default_rules(),
        })
    }

    pub fn scan_file(&self, path: &std::path::Path) -> Result<ScanResult, Error> {
        let data = std::fs::read(path)?;
        let metadata = std::fs::metadata(path)?;

        // Calculate hashes
        let md5_hash = format!("{:x}", md5::compute(&data));
        let sha256_hash = hex::encode(ring::digest::digest(&ring::digest::SHA256, &data));

        // Check signature database
        let md5_match = self.signature_db.check_md5(&md5_hash).cloned();
        let sha256_match = self.signature_db.check_sha256(&sha256_hash).cloned();

        // YARA scan
        let yara_matches = self.yara_engine.scan_bytes(&data)?;

        // Entropy analysis
        let entropy_report = self.entropy_analyzer.analyze_bytes(&data)?;

        // Byte pattern matches
        let pattern_matches: Vec<_> = self.signature_db.scan_bytes(&data)
            .into_iter()
            .cloned()
            .collect();

        // Heuristic analysis
        let file_metadata = FileMetadata {
            path: path.to_path_buf(),
            size: metadata.len(),
            extension: path.extension().map(|e| e.to_string_lossy().to_string()),
            is_executable: is_executable(&data),
        };
        let heuristic_matches = self.heuristic_analyzer.analyze(&data, &file_metadata);

        // Determine overall threat level
        let threat_level = self.calculate_threat_level(
            &md5_match,
            &sha256_match,
            &yara_matches,
            &entropy_report,
            &pattern_matches,
            &heuristic_matches,
        );

        Ok(ScanResult {
            path: path.to_path_buf(),
            size: metadata.len(),
            md5_hash,
            sha256_hash,
            md5_match,
            sha256_match,
            yara_matches,
            entropy_report,
            pattern_matches,
            heuristic_matches,
            threat_level,
        })
    }

    fn calculate_threat_level(
        &self,
        md5_match: &Option<MalwareSignature>,
        sha256_match: &Option<MalwareSignature>,
        yara_matches: &[YaraMatch],
        entropy_report: &EntropyReport,
        pattern_matches: &[BytePatternSignature],
        heuristic_matches: &[HeuristicMatch],
    ) -> ThreatLevel {
        // Known malware hash = Critical
        if md5_match.as_ref().map(|m| m.severity == Severity::Critical).unwrap_or(false) ||
           sha256_match.as_ref().map(|m| m.severity == Severity::Critical).unwrap_or(false) {
            return ThreatLevel::Critical;
        }

        // Check for critical YARA rules
        for yara_match in yara_matches {
            if yara_match.tags.iter().any(|t| t == "critical") {
                return ThreatLevel::Critical;
            }
        }

        // Count severity indicators
        let high_count = pattern_matches.iter().filter(|p| p.severity == Severity::High).count()
            + heuristic_matches.iter().filter(|h| h.severity == Severity::High).count();

        let medium_count = yara_matches.len()
            + pattern_matches.iter().filter(|p| p.severity == Severity::Medium).count()
            + heuristic_matches.iter().filter(|h| h.severity == Severity::Medium).count();

        if high_count >= 2 || (entropy_report.is_likely_packed && medium_count >= 2) {
            return ThreatLevel::High;
        }

        if medium_count >= 2 || entropy_report.is_likely_encrypted {
            return ThreatLevel::Medium;
        }

        if medium_count >= 1 || !heuristic_matches.is_empty() {
            return ThreatLevel::Low;
        }

        ThreatLevel::Clean
    }
}

#[derive(Debug)]
pub struct ScanResult {
    pub path: std::path::PathBuf,
    pub size: u64,
    pub md5_hash: String,
    pub sha256_hash: String,
    pub md5_match: Option<MalwareSignature>,
    pub sha256_match: Option<MalwareSignature>,
    pub yara_matches: Vec<YaraMatch>,
    pub entropy_report: EntropyReport,
    pub pattern_matches: Vec<BytePatternSignature>,
    pub heuristic_matches: Vec<HeuristicMatch>,
    pub threat_level: ThreatLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatLevel {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

fn is_executable(data: &[u8]) -> bool {
    // Check for common executable magic bytes
    if data.len() < 4 {
        return false;
    }

    // PE (Windows)
    if data.starts_with(&[0x4D, 0x5A]) {
        return true;
    }

    // ELF (Linux)
    if data.starts_with(&[0x7F, 0x45, 0x4C, 0x46]) {
        return true;
    }

    // Mach-O (macOS)
    if data.starts_with(&[0xFE, 0xED, 0xFA, 0xCE]) ||
       data.starts_with(&[0xFE, 0xED, 0xFA, 0xCF]) ||
       data.starts_with(&[0xCE, 0xFA, 0xED, 0xFE]) ||
       data.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) {
        return true;
    }

    // Shebang
    if data.starts_with(&[0x23, 0x21]) {  // #!
        return true;
    }

    false
}
```

---

## Security Checklist

- [ ] YARA rules from trusted sources
- [ ] Signature database regularly updated
- [ ] Entropy thresholds tuned for environment
- [ ] Heuristic rules tested for false positives
- [ ] Quarantine system configured
- [ ] Scan results logged securely

## Recommended Crates

- **yara**: YARA rule engine
- **md5/sha2**: Hash calculation
- **ring**: Cryptographic operations
- **regex**: Pattern matching

## Integration Points

This skill works well with:

- `/quarantine-setup` - Isolate detected threats
- `/threat-feeds-setup` - Update signatures
