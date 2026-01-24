# Rust NAS Security Template

## Overview

NAS security wrapper with file scanning, quarantine, integrity monitoring, and
ransomware detection.

## Project Structure

```
my-nas-security/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── scanner/
│   │   ├── mod.rs
│   │   ├── clamav.rs
│   │   └── yara.rs
│   ├── monitor/
│   │   ├── mod.rs
│   │   └── integrity.rs
│   ├── quarantine/
│   │   └── mod.rs
│   └── ransomware/
│       └── mod.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-nas-security"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1.40", features = ["full"] }
notify = "6.1"
sha2 = "0.10"
serde = { version = "1.0", features = ["derive"] }
tracing = "0.1"
walkdir = "2.5"
```

## Core Implementation

### src/monitor/integrity.rs

```rust
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;

pub struct IntegrityMonitor {
    baselines: HashMap<PathBuf, String>,
}

impl IntegrityMonitor {
    pub fn new() -> Self {
        Self { baselines: HashMap::new() }
    }

    pub async fn baseline_file(&mut self, path: &Path) -> std::io::Result<()> {
        let hash = self.hash_file(path).await?;
        self.baselines.insert(path.to_path_buf(), hash);
        Ok(())
    }

    pub async fn check_file(&self, path: &Path) -> std::io::Result<bool> {
        let current_hash = self.hash_file(path).await?;
        Ok(self.baselines.get(path) == Some(&current_hash))
    }

    async fn hash_file(&self, path: &Path) -> std::io::Result<String> {
        let content = fs::read(path).await?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(hex::encode(hasher.finalize()))
    }
}
```

### src/ransomware/mod.rs

```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct RansomwareDetector {
    file_changes: HashMap<String, Vec<Instant>>,
    threshold: usize,
    window: Duration,
}

impl RansomwareDetector {
    pub fn new(threshold: usize, window_secs: u64) -> Self {
        Self {
            file_changes: HashMap::new(),
            threshold,
            window: Duration::from_secs(window_secs),
        }
    }

    pub fn record_change(&mut self, dir: &str) -> bool {
        let now = Instant::now();
        let changes = self.file_changes.entry(dir.to_string()).or_default();

        // Remove old entries
        changes.retain(|t| now.duration_since(*t) < self.window);
        changes.push(now);

        // Check threshold
        changes.len() >= self.threshold
    }

    pub fn calculate_entropy(&self, data: &[u8]) -> f64 {
        let mut freq = [0u64; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let len = data.len() as f64;
        freq.iter()
            .filter(|&&f| f > 0)
            .map(|&f| {
                let p = f as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    pub fn is_high_entropy(&self, data: &[u8]) -> bool {
        self.calculate_entropy(data) > 7.5 // Encrypted files typically have entropy > 7.5
    }
}
```

### src/quarantine/mod.rs

```rust
use std::path::{Path, PathBuf};
use tokio::fs;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
    pub hash: String,
}

pub struct QuarantineManager {
    quarantine_dir: PathBuf,
    entries: Vec<QuarantineEntry>,
}

impl QuarantineManager {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            quarantine_dir: dir,
            entries: Vec::new(),
        }
    }

    pub async fn quarantine(&mut self, path: &Path, reason: &str) -> std::io::Result<()> {
        let filename = format!("{}-{}",
            Utc::now().timestamp(),
            path.file_name().unwrap().to_string_lossy()
        );
        let quarantine_path = self.quarantine_dir.join(&filename);

        fs::rename(path, &quarantine_path).await?;

        self.entries.push(QuarantineEntry {
            original_path: path.to_path_buf(),
            quarantine_path,
            reason: reason.to_string(),
            timestamp: Utc::now(),
            hash: String::new(),
        });

        Ok(())
    }

    pub async fn restore(&mut self, index: usize) -> std::io::Result<()> {
        if let Some(entry) = self.entries.get(index) {
            fs::rename(&entry.quarantine_path, &entry.original_path).await?;
            self.entries.remove(index);
        }
        Ok(())
    }
}
```

## Security Checklist

- [ ] Real-time scanning enabled
- [ ] Integrity baselines created
- [ ] Quarantine configured
- [ ] Ransomware detection active
- [ ] Audit logging enabled
