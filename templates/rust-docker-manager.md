# Rust Docker Manager Template

## Overview

This template provides a Docker security management CLI with container
hardening, image scanning, and security policy enforcement using the Docker API.

**Target Use Cases:**

- Container security hardening
- Image vulnerability scanning
- Security policy enforcement
- Container runtime monitoring
- Registry authentication

## Project Structure

```
my-docker-manager/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── client.rs
│   ├── container/
│   │   ├── mod.rs
│   │   ├── hardening.rs
│   │   └── monitor.rs
│   ├── image/
│   │   ├── mod.rs
│   │   └── scanner.rs
│   ├── policy/
│   │   ├── mod.rs
│   │   └── enforcer.rs
│   └── error.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-docker-manager"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"

[dependencies]
tokio = { version = "1.40", features = ["full"] }
bollard = "0.17"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
clap = { version = "4.5", features = ["derive"] }
thiserror = "2.0"
tracing = "0.1"
tracing-subscriber = "0.3"
```

## Core Implementation

### src/container/hardening.rs

```rust
use bollard::Docker;
use bollard::container::{Config, CreateContainerOptions, HostConfig};
use bollard::models::{HostConfigLogConfig, DeviceMapping};
use std::collections::HashMap;
use crate::error::DockerError;

#[derive(Debug, Clone)]
pub struct HardeningPolicy {
    pub read_only_root: bool,
    pub no_new_privileges: bool,
    pub drop_capabilities: Vec<String>,
    pub add_capabilities: Vec<String>,
    pub memory_limit: Option<i64>,
    pub cpu_limit: Option<f64>,
    pub pids_limit: Option<i64>,
    pub seccomp_profile: Option<String>,
    pub apparmor_profile: Option<String>,
}

impl Default for HardeningPolicy {
    fn default() -> Self {
        Self {
            read_only_root: true,
            no_new_privileges: true,
            drop_capabilities: vec![
                "ALL".to_string(),
            ],
            add_capabilities: vec![],
            memory_limit: Some(512 * 1024 * 1024), // 512MB
            cpu_limit: Some(1.0),
            pids_limit: Some(100),
            seccomp_profile: None,
            apparmor_profile: None,
        }
    }
}

pub struct ContainerHardener {
    docker: Docker,
}

impl ContainerHardener {
    pub fn new(docker: Docker) -> Self {
        Self { docker }
    }

    pub fn apply_policy(&self, config: &mut Config<String>, policy: &HardeningPolicy) {
        let host_config = config.host_config.get_or_insert_with(HostConfig::default);

        // Read-only root filesystem
        host_config.read_only_rootfs = Some(policy.read_only_root);

        // No new privileges
        host_config.security_opt = Some(vec![
            if policy.no_new_privileges {
                "no-new-privileges:true".to_string()
            } else {
                "no-new-privileges:false".to_string()
            }
        ]);

        // Capabilities
        host_config.cap_drop = Some(policy.drop_capabilities.clone());
        if !policy.add_capabilities.is_empty() {
            host_config.cap_add = Some(policy.add_capabilities.clone());
        }

        // Resource limits
        if let Some(mem) = policy.memory_limit {
            host_config.memory = Some(mem);
        }
        if let Some(pids) = policy.pids_limit {
            host_config.pids_limit = Some(pids);
        }

        // Seccomp profile
        if let Some(profile) = &policy.seccomp_profile {
            if let Some(sec_opts) = &mut host_config.security_opt {
                sec_opts.push(format!("seccomp={}", profile));
            }
        }
    }

    pub async fn create_hardened_container(
        &self,
        name: &str,
        image: &str,
        policy: &HardeningPolicy,
    ) -> Result<String, DockerError> {
        let mut config = Config {
            image: Some(image.to_string()),
            ..Default::default()
        };

        self.apply_policy(&mut config, policy);

        let options = CreateContainerOptions { name, platform: None };
        let response = self.docker
            .create_container(Some(options), config)
            .await
            .map_err(|e| DockerError::ApiError(e.to_string()))?;

        Ok(response.id)
    }
}
```

### src/image/scanner.rs

```rust
use bollard::Docker;
use bollard::image::InspectImageOptions;
use serde::{Deserialize, Serialize};
use crate::error::DockerError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub image: String,
    pub vulnerabilities: Vec<Vulnerability>,
    pub risk_score: u32,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub severity: Severity,
    pub package: String,
    pub version: String,
    pub fixed_version: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

pub struct ImageScanner {
    docker: Docker,
    max_severity: Severity,
}

impl ImageScanner {
    pub fn new(docker: Docker, max_severity: Severity) -> Self {
        Self { docker, max_severity }
    }

    pub async fn scan(&self, image: &str) -> Result<ScanResult, DockerError> {
        // Inspect image
        let inspect = self.docker
            .inspect_image(image)
            .await
            .map_err(|e| DockerError::ApiError(e.to_string()))?;

        // In production, integrate with Trivy, Grype, or similar
        let vulnerabilities = self.run_vulnerability_scan(image).await?;

        let risk_score = self.calculate_risk_score(&vulnerabilities);
        let passed = !vulnerabilities.iter().any(|v| v.severity <= self.max_severity);

        Ok(ScanResult {
            image: image.to_string(),
            vulnerabilities,
            risk_score,
            passed,
        })
    }

    async fn run_vulnerability_scan(&self, image: &str) -> Result<Vec<Vulnerability>, DockerError> {
        // Integration point for Trivy/Grype
        // For now, return empty - implement actual scanner integration
        Ok(vec![])
    }

    fn calculate_risk_score(&self, vulns: &[Vulnerability]) -> u32 {
        vulns.iter().map(|v| match v.severity {
            Severity::Critical => 40,
            Severity::High => 20,
            Severity::Medium => 10,
            Severity::Low => 5,
            Severity::Unknown => 1,
        }).sum()
    }
}
```

### src/policy/enforcer.rs

```rust
use bollard::Docker;
use bollard::container::ListContainersOptions;
use std::collections::HashMap;
use tracing::{info, warn};
use crate::container::hardening::HardeningPolicy;
use crate::error::DockerError;

#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    pub allowed_images: Vec<String>,
    pub required_labels: HashMap<String, String>,
    pub hardening: HardeningPolicy,
    pub max_containers: Option<usize>,
}

pub struct PolicyEnforcer {
    docker: Docker,
    policy: SecurityPolicy,
}

impl PolicyEnforcer {
    pub fn new(docker: Docker, policy: SecurityPolicy) -> Self {
        Self { docker, policy }
    }

    pub async fn audit_containers(&self) -> Result<Vec<PolicyViolation>, DockerError> {
        let mut violations = Vec::new();

        let options = ListContainersOptions::<String> {
            all: true,
            ..Default::default()
        };

        let containers = self.docker
            .list_containers(Some(options))
            .await
            .map_err(|e| DockerError::ApiError(e.to_string()))?;

        // Check container count
        if let Some(max) = self.policy.max_containers {
            if containers.len() > max {
                violations.push(PolicyViolation {
                    container_id: None,
                    rule: "max_containers".to_string(),
                    message: format!("Container count {} exceeds limit {}", containers.len(), max),
                });
            }
        }

        for container in containers {
            let id = container.id.clone().unwrap_or_default();
            let image = container.image.clone().unwrap_or_default();

            // Check allowed images
            if !self.policy.allowed_images.is_empty() {
                let allowed = self.policy.allowed_images.iter()
                    .any(|pattern| image.starts_with(pattern));
                if !allowed {
                    violations.push(PolicyViolation {
                        container_id: Some(id.clone()),
                        rule: "allowed_images".to_string(),
                        message: format!("Image {} not in allowed list", image),
                    });
                }
            }

            // Check required labels
            let labels = container.labels.unwrap_or_default();
            for (key, value) in &self.policy.required_labels {
                match labels.get(key) {
                    None => {
                        violations.push(PolicyViolation {
                            container_id: Some(id.clone()),
                            rule: "required_labels".to_string(),
                            message: format!("Missing required label: {}", key),
                        });
                    }
                    Some(v) if v != value => {
                        violations.push(PolicyViolation {
                            container_id: Some(id.clone()),
                            rule: "required_labels".to_string(),
                            message: format!("Label {} has wrong value: {} != {}", key, v, value),
                        });
                    }
                    _ => {}
                }
            }
        }

        Ok(violations)
    }
}

#[derive(Debug, Clone)]
pub struct PolicyViolation {
    pub container_id: Option<String>,
    pub rule: String,
    pub message: String,
}
```

## Security Checklist

- [ ] Docker socket access restricted
- [ ] Images scanned before deployment
- [ ] Containers run as non-root
- [ ] Read-only root filesystem enabled
- [ ] Resource limits configured
- [ ] Network policies applied
- [ ] Seccomp profiles enabled
- [ ] Capabilities dropped
