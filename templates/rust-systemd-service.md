# Rust Systemd Service Template

## Overview

Hardened systemd service file generator with sandboxing, capabilities, and
security restrictions.

## Project Structure

```
my-systemd-service/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   └── service.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-systemd-service"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
```

## Core Implementation

### src/service.rs

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdService {
    pub name: String,
    pub description: String,
    pub exec_start: String,
    pub user: String,
    pub group: String,
    pub working_directory: Option<String>,
    pub environment: Vec<(String, String)>,
    pub hardening: HardeningConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningConfig {
    pub no_new_privileges: bool,
    pub private_tmp: bool,
    pub private_devices: bool,
    pub protect_system: String,
    pub protect_home: String,
    pub read_only_paths: Vec<String>,
    pub inaccessible_paths: Vec<String>,
    pub capabilities: Vec<String>,
    pub system_call_filter: Vec<String>,
    pub memory_deny_write_execute: bool,
    pub restrict_namespaces: bool,
    pub restrict_realtime: bool,
    pub restrict_suid_sgid: bool,
}

impl SystemdService {
    pub fn generate(&self) -> String {
        let mut unit = String::new();

        // [Unit] section
        unit.push_str("[Unit]\n");
        unit.push_str(&format!("Description={}\n", self.description));
        unit.push_str("After=network.target\n\n");

        // [Service] section
        unit.push_str("[Service]\n");
        unit.push_str("Type=simple\n");
        unit.push_str(&format!("User={}\n", self.user));
        unit.push_str(&format!("Group={}\n", self.group));
        unit.push_str(&format!("ExecStart={}\n", self.exec_start));

        if let Some(wd) = &self.working_directory {
            unit.push_str(&format!("WorkingDirectory={}\n", wd));
        }

        for (key, value) in &self.environment {
            unit.push_str(&format!("Environment=\"{}={}\"\n", key, value));
        }

        unit.push_str("Restart=on-failure\n");
        unit.push_str("RestartSec=5\n\n");

        // Security hardening
        unit.push_str("# Security hardening\n");
        unit.push_str(&format!("NoNewPrivileges={}\n",
            if self.hardening.no_new_privileges { "yes" } else { "no" }));
        unit.push_str(&format!("PrivateTmp={}\n",
            if self.hardening.private_tmp { "yes" } else { "no" }));
        unit.push_str(&format!("PrivateDevices={}\n",
            if self.hardening.private_devices { "yes" } else { "no" }));
        unit.push_str(&format!("ProtectSystem={}\n", self.hardening.protect_system));
        unit.push_str(&format!("ProtectHome={}\n", self.hardening.protect_home));

        if !self.hardening.read_only_paths.is_empty() {
            unit.push_str(&format!("ReadOnlyPaths={}\n",
                self.hardening.read_only_paths.join(" ")));
        }

        if !self.hardening.inaccessible_paths.is_empty() {
            unit.push_str(&format!("InaccessiblePaths={}\n",
                self.hardening.inaccessible_paths.join(" ")));
        }

        if !self.hardening.capabilities.is_empty() {
            unit.push_str("CapabilityBoundingSet=\n");
            for cap in &self.hardening.capabilities {
                unit.push_str(&format!("AmbientCapabilities={}\n", cap));
            }
        } else {
            unit.push_str("CapabilityBoundingSet=\n");
        }

        if !self.hardening.system_call_filter.is_empty() {
            unit.push_str(&format!("SystemCallFilter={}\n",
                self.hardening.system_call_filter.join(" ")));
        }

        unit.push_str(&format!("MemoryDenyWriteExecute={}\n",
            if self.hardening.memory_deny_write_execute { "yes" } else { "no" }));
        unit.push_str(&format!("RestrictNamespaces={}\n",
            if self.hardening.restrict_namespaces { "yes" } else { "no" }));
        unit.push_str(&format!("RestrictRealtime={}\n",
            if self.hardening.restrict_realtime { "yes" } else { "no" }));
        unit.push_str(&format!("RestrictSUIDSGID={}\n",
            if self.hardening.restrict_suid_sgid { "yes" } else { "no" }));

        unit.push_str("\n[Install]\n");
        unit.push_str("WantedBy=multi-user.target\n");

        unit
    }
}

impl Default for HardeningConfig {
    fn default() -> Self {
        Self {
            no_new_privileges: true,
            private_tmp: true,
            private_devices: true,
            protect_system: "strict".to_string(),
            protect_home: "yes".to_string(),
            read_only_paths: vec![],
            inaccessible_paths: vec!["/root".to_string(), "/home".to_string()],
            capabilities: vec![],
            system_call_filter: vec!["@system-service".to_string()],
            memory_deny_write_execute: true,
            restrict_namespaces: true,
            restrict_realtime: true,
            restrict_suid_sgid: true,
        }
    }
}
```

## Security Checklist

- [ ] NoNewPrivileges enabled
- [ ] PrivateTmp enabled
- [ ] ProtectSystem=strict
- [ ] Minimal capabilities
- [ ] SystemCallFilter configured
- [ ] Namespace restrictions
