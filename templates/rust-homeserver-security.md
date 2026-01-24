# Rust Homeserver Security Template

## Overview

Homeserver protection with process monitoring, application firewall, rootkit
detection, and privilege escalation monitoring.

## Project Structure

```
my-homeserver-security/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── process/
│   │   ├── mod.rs
│   │   └── monitor.rs
│   ├── firewall/
│   │   └── mod.rs
│   ├── rootkit/
│   │   └── mod.rs
│   └── privilege/
│       └── mod.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-homeserver-security"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1.40", features = ["full"] }
sysinfo = "0.31"
serde = { version = "1.0", features = ["derive"] }
tracing = "0.1"
```

## Core Implementation

### src/process/monitor.rs

```rust
use sysinfo::{System, Process, Pid};
use std::collections::{HashMap, HashSet};
use tracing::{info, warn};

pub struct ProcessMonitor {
    system: System,
    allowed_processes: HashSet<String>,
    baseline: HashMap<String, ProcessInfo>,
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub name: String,
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub user: Option<String>,
    pub memory: u64,
    pub cpu: f32,
}

impl ProcessMonitor {
    pub fn new() -> Self {
        Self {
            system: System::new_all(),
            allowed_processes: HashSet::new(),
            baseline: HashMap::new(),
        }
    }

    pub fn allow_process(&mut self, name: &str) {
        self.allowed_processes.insert(name.to_string());
    }

    pub fn refresh(&mut self) {
        self.system.refresh_all();
    }

    pub fn get_suspicious_processes(&self) -> Vec<ProcessInfo> {
        self.system.processes()
            .values()
            .filter(|p| !self.allowed_processes.contains(p.name().to_str().unwrap_or("")))
            .map(|p| ProcessInfo {
                name: p.name().to_string_lossy().to_string(),
                pid: p.pid().as_u32(),
                parent_pid: p.parent().map(|p| p.as_u32()),
                user: p.user_id().map(|u| u.to_string()),
                memory: p.memory(),
                cpu: p.cpu_usage(),
            })
            .collect()
    }

    pub fn detect_anomalies(&self) -> Vec<String> {
        let mut anomalies = Vec::new();

        for proc in self.system.processes().values() {
            // High CPU usage
            if proc.cpu_usage() > 90.0 {
                anomalies.push(format!("High CPU: {} ({}%)", proc.name().to_string_lossy(), proc.cpu_usage()));
            }

            // Suspicious parent (init spawning shells)
            if proc.parent() == Some(Pid::from(1)) {
                let name = proc.name().to_string_lossy();
                if name.contains("sh") || name.contains("bash") {
                    anomalies.push(format!("Shell spawned from init: {}", name));
                }
            }
        }

        anomalies
    }
}
```

### src/privilege/mod.rs

```rust
use std::collections::HashMap;
use std::fs;
use tracing::warn;

pub struct PrivilegeMonitor {
    suid_baseline: HashMap<String, u32>,
}

impl PrivilegeMonitor {
    pub fn new() -> Self {
        Self {
            suid_baseline: HashMap::new(),
        }
    }

    pub fn scan_suid_files(&self, paths: &[&str]) -> Vec<String> {
        let mut suid_files = Vec::new();

        for path in paths {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    if let Ok(metadata) = entry.metadata() {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::MetadataExt;
                            let mode = metadata.mode();
                            if mode & 0o4000 != 0 || mode & 0o2000 != 0 {
                                suid_files.push(entry.path().to_string_lossy().to_string());
                            }
                        }
                    }
                }
            }
        }

        suid_files
    }

    pub fn check_passwd_changes(&self) -> bool {
        // Check for unauthorized changes to /etc/passwd, /etc/shadow
        let passwd_hash = self.hash_file("/etc/passwd");
        let shadow_hash = self.hash_file("/etc/shadow");

        // Compare with baseline
        true // Simplified - would compare with stored hashes
    }

    fn hash_file(&self, path: &str) -> Option<String> {
        use sha2::{Sha256, Digest};
        let content = fs::read(path).ok()?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Some(hex::encode(hasher.finalize()))
    }
}
```

## Security Checklist

- [ ] Process whitelist configured
- [ ] SUID scanning enabled
- [ ] Privilege escalation monitoring
- [ ] Anomaly detection active
- [ ] Audit logging enabled
