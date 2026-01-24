# Rust Docker Security Skills

This skill provides patterns for Docker container management, security
hardening, and container runtime security in Rust.

## Overview

Docker security encompasses:

- **Container Hardening**: Secure container configuration
- **Image Security**: Scanning and vulnerability management
- **Runtime Security**: Process isolation and monitoring
- **Registry Security**: Secure image distribution
- **Orchestration**: Secure Docker Compose and Swarm patterns

## /docker-harden

Generate Docker security hardening recommendations and configurations.

### Usage

```bash
/docker-harden
```

### What It Does

1. Analyzes Dockerfile and docker-compose.yml
2. Identifies security misconfigurations
3. Generates hardened configurations
4. Creates security scanning scripts
5. Sets up runtime monitoring

---

## Docker API Client

### Basic Client Setup

```rust
use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, StartContainerOptions,
    StopContainerOptions, RemoveContainerOptions,
};

pub struct DockerManager {
    client: Docker,
}

impl DockerManager {
    pub fn new() -> Result<Self, Error> {
        let client = Docker::connect_with_socket_defaults()
            .map_err(Error::DockerConnect)?;
        Ok(Self { client })
    }

    pub fn with_socket(socket_path: &str) -> Result<Self, Error> {
        let client = Docker::connect_with_socket(socket_path, 120, bollard::API_DEFAULT_VERSION)
            .map_err(Error::DockerConnect)?;
        Ok(Self { client })
    }

    pub async fn ping(&self) -> Result<(), Error> {
        self.client.ping().await.map_err(Error::DockerPing)?;
        Ok(())
    }
}
```

### Secure Container Creation

```rust
use bollard::container::{Config, HostConfig};
use bollard::models::{HostConfigLogConfig, Mount, MountTypeEnum};
use std::collections::HashMap;

impl DockerManager {
    pub async fn create_secure_container(
        &self,
        name: &str,
        image: &str,
        config: SecureContainerConfig,
    ) -> Result<String, Error> {
        let mut env = config.env.clone();

        // Security labels
        let mut labels = HashMap::new();
        labels.insert("security.hardened".to_string(), "true".to_string());

        // Host configuration with security settings
        let host_config = HostConfig {
            // Resource limits
            memory: config.memory_limit,
            memory_swap: config.memory_limit,  // Same as memory to prevent swap
            cpu_period: Some(100000),
            cpu_quota: config.cpu_limit.map(|c| (c * 100000.0) as i64),
            pids_limit: config.pids_limit,

            // Security options
            cap_drop: Some(vec!["ALL".to_string()]),  // Drop all capabilities
            cap_add: config.capabilities.clone(),      // Add only needed ones
            security_opt: Some(vec![
                "no-new-privileges:true".to_string(),
                format!("seccomp={}", config.seccomp_profile.as_deref().unwrap_or("default")),
            ]),
            read_only_rootfs: Some(config.read_only_root),
            privileged: Some(false),

            // Network
            network_mode: config.network_mode.clone(),
            publish_all_ports: Some(false),

            // Filesystem
            mounts: config.mounts.clone(),
            tmpfs: config.tmpfs.clone(),

            // User namespace
            userns_mode: config.userns_mode.clone(),

            // Logging
            log_config: Some(HostConfigLogConfig {
                r#type: Some("json-file".to_string()),
                config: Some({
                    let mut log_opts = HashMap::new();
                    log_opts.insert("max-size".to_string(), "10m".to_string());
                    log_opts.insert("max-file".to_string(), "3".to_string());
                    log_opts
                }),
            }),

            ..Default::default()
        };

        let container_config = Config {
            image: Some(image.to_string()),
            env: Some(env),
            labels: Some(labels),
            host_config: Some(host_config),
            user: config.user.clone(),
            working_dir: config.working_dir.clone(),
            cmd: config.cmd.clone(),
            entrypoint: config.entrypoint.clone(),
            healthcheck: config.healthcheck.clone(),
            ..Default::default()
        };

        let options = CreateContainerOptions { name, platform: None };

        let response = self.client
            .create_container(Some(options), container_config)
            .await
            .map_err(Error::ContainerCreate)?;

        Ok(response.id)
    }
}

#[derive(Debug, Clone)]
pub struct SecureContainerConfig {
    pub env: Vec<String>,
    pub memory_limit: Option<i64>,           // Bytes
    pub cpu_limit: Option<f64>,              // Number of CPUs
    pub pids_limit: Option<i64>,
    pub capabilities: Option<Vec<String>>,   // Capabilities to add
    pub read_only_root: bool,
    pub network_mode: Option<String>,
    pub mounts: Option<Vec<Mount>>,
    pub tmpfs: Option<HashMap<String, String>>,
    pub user: Option<String>,
    pub userns_mode: Option<String>,
    pub working_dir: Option<String>,
    pub cmd: Option<Vec<String>>,
    pub entrypoint: Option<Vec<String>>,
    pub healthcheck: Option<bollard::models::HealthConfig>,
    pub seccomp_profile: Option<String>,
}

impl Default for SecureContainerConfig {
    fn default() -> Self {
        Self {
            env: Vec::new(),
            memory_limit: Some(512 * 1024 * 1024),  // 512MB
            cpu_limit: Some(1.0),
            pids_limit: Some(100),
            capabilities: None,  // No additional capabilities
            read_only_root: true,
            network_mode: Some("bridge".to_string()),
            mounts: None,
            tmpfs: Some({
                let mut tmpfs = HashMap::new();
                tmpfs.insert("/tmp".to_string(), "size=64M,noexec,nodev,nosuid".to_string());
                tmpfs
            }),
            user: Some("1000:1000".to_string()),  // Non-root user
            userns_mode: None,
            working_dir: Some("/app".to_string()),
            cmd: None,
            entrypoint: None,
            healthcheck: None,
            seccomp_profile: None,
        }
    }
}
```

---

## Image Security

### Image Scanning

```rust
use bollard::image::{ListImagesOptions, InspectImageOptions};

impl DockerManager {
    pub async fn inspect_image(&self, image: &str) -> Result<ImageSecurityInfo, Error> {
        let inspection = self.client
            .inspect_image(image)
            .await
            .map_err(Error::ImageInspect)?;

        let mut warnings = Vec::new();

        // Check for root user
        if let Some(config) = &inspection.config {
            if config.user.as_deref().unwrap_or("root") == "root" ||
               config.user.as_deref().unwrap_or("") == "" {
                warnings.push(SecurityWarning::RunningAsRoot);
            }
        }

        // Check for exposed ports
        if let Some(config) = &inspection.config {
            if let Some(ports) = &config.exposed_ports {
                for port in ports.keys() {
                    if port.contains("22") {
                        warnings.push(SecurityWarning::SshExposed);
                    }
                }
            }
        }

        // Check image age
        if let Some(created) = &inspection.created {
            if let Ok(created_time) = chrono::DateTime::parse_from_rfc3339(created) {
                let age = chrono::Utc::now().signed_duration_since(created_time);
                if age.num_days() > 90 {
                    warnings.push(SecurityWarning::ImageTooOld(age.num_days()));
                }
            }
        }

        Ok(ImageSecurityInfo {
            id: inspection.id.unwrap_or_default(),
            repo_tags: inspection.repo_tags.unwrap_or_default(),
            created: inspection.created,
            size: inspection.size,
            warnings,
        })
    }

    pub async fn pull_image_with_verification(
        &self,
        image: &str,
        expected_digest: Option<&str>,
    ) -> Result<(), Error> {
        use bollard::image::CreateImageOptions;
        use futures::StreamExt;

        let options = CreateImageOptions {
            from_image: image,
            ..Default::default()
        };

        let mut stream = self.client.create_image(Some(options), None, None);

        while let Some(result) = stream.next().await {
            match result {
                Ok(info) => {
                    if let Some(status) = info.status {
                        tracing::debug!("Pull: {}", status);
                    }
                }
                Err(e) => return Err(Error::ImagePull(e.to_string())),
            }
        }

        // Verify digest if provided
        if let Some(digest) = expected_digest {
            let inspection = self.client
                .inspect_image(image)
                .await
                .map_err(Error::ImageInspect)?;

            let actual_digests = inspection.repo_digests.unwrap_or_default();
            if !actual_digests.iter().any(|d| d.contains(digest)) {
                return Err(Error::DigestMismatch {
                    expected: digest.to_string(),
                    actual: actual_digests,
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct ImageSecurityInfo {
    pub id: String,
    pub repo_tags: Vec<String>,
    pub created: Option<String>,
    pub size: Option<i64>,
    pub warnings: Vec<SecurityWarning>,
}

#[derive(Debug)]
pub enum SecurityWarning {
    RunningAsRoot,
    SshExposed,
    ImageTooOld(i64),
    NoHealthcheck,
    PrivilegedMode,
    HostNetworkMode,
}
```

### Trivy Integration for Vulnerability Scanning

```rust
use std::process::Command;

pub struct TrivyScanner;

impl TrivyScanner {
    pub fn scan_image(image: &str) -> Result<VulnerabilityReport, Error> {
        let output = Command::new("trivy")
            .args([
                "image",
                "--format", "json",
                "--severity", "CRITICAL,HIGH,MEDIUM",
                image,
            ])
            .output()
            .map_err(Error::TrivyExec)?;

        if !output.status.success() {
            return Err(Error::TrivyScan(
                String::from_utf8_lossy(&output.stderr).to_string()
            ));
        }

        let report: TrivyReport = serde_json::from_slice(&output.stdout)
            .map_err(Error::TrivyParse)?;

        Ok(VulnerabilityReport::from(report))
    }
}

#[derive(Debug, serde::Deserialize)]
struct TrivyReport {
    #[serde(rename = "Results")]
    results: Option<Vec<TrivyResult>>,
}

#[derive(Debug, serde::Deserialize)]
struct TrivyResult {
    #[serde(rename = "Target")]
    target: String,
    #[serde(rename = "Vulnerabilities")]
    vulnerabilities: Option<Vec<TrivyVulnerability>>,
}

#[derive(Debug, serde::Deserialize)]
struct TrivyVulnerability {
    #[serde(rename = "VulnerabilityID")]
    id: String,
    #[serde(rename = "PkgName")]
    package: String,
    #[serde(rename = "Severity")]
    severity: String,
    #[serde(rename = "Title")]
    title: Option<String>,
    #[serde(rename = "FixedVersion")]
    fixed_version: Option<String>,
}

#[derive(Debug)]
pub struct VulnerabilityReport {
    pub critical: Vec<Vulnerability>,
    pub high: Vec<Vulnerability>,
    pub medium: Vec<Vulnerability>,
}

#[derive(Debug)]
pub struct Vulnerability {
    pub id: String,
    pub package: String,
    pub title: String,
    pub fixed_version: Option<String>,
}
```

---

## Container Runtime Security

### Runtime Monitoring

```rust
use bollard::container::StatsOptions;
use futures::StreamExt;

impl DockerManager {
    pub async fn monitor_container(
        &self,
        container_id: &str,
        anomaly_detector: &AnomalyDetector,
    ) -> Result<(), Error> {
        let options = StatsOptions { stream: true, one_shot: false };

        let mut stats_stream = self.client.stats(container_id, Some(options));

        while let Some(result) = stats_stream.next().await {
            match result {
                Ok(stats) => {
                    let metrics = ContainerMetrics::from(stats);

                    if let Some(anomaly) = anomaly_detector.check(&metrics) {
                        tracing::warn!(
                            container = container_id,
                            anomaly = ?anomaly,
                            "Container anomaly detected"
                        );

                        // Take action based on anomaly type
                        match anomaly {
                            Anomaly::HighCpu | Anomaly::HighMemory => {
                                // Log but continue
                            }
                            Anomaly::SuspiciousNetwork | Anomaly::ProcessSpike => {
                                // Consider stopping container
                                self.stop_container(container_id).await?;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Stats error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    pub async fn stop_container(&self, container_id: &str) -> Result<(), Error> {
        self.client
            .stop_container(container_id, Some(StopContainerOptions { t: 10 }))
            .await
            .map_err(Error::ContainerStop)
    }
}

#[derive(Debug)]
pub struct ContainerMetrics {
    pub cpu_percent: f64,
    pub memory_usage: u64,
    pub memory_limit: u64,
    pub memory_percent: f64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub pids: u64,
}

#[derive(Debug)]
pub enum Anomaly {
    HighCpu,
    HighMemory,
    SuspiciousNetwork,
    ProcessSpike,
}

pub struct AnomalyDetector {
    cpu_threshold: f64,
    memory_threshold: f64,
    network_threshold: u64,
    pids_threshold: u64,
}

impl AnomalyDetector {
    pub fn check(&self, metrics: &ContainerMetrics) -> Option<Anomaly> {
        if metrics.cpu_percent > self.cpu_threshold {
            return Some(Anomaly::HighCpu);
        }
        if metrics.memory_percent > self.memory_threshold {
            return Some(Anomaly::HighMemory);
        }
        if metrics.network_rx_bytes > self.network_threshold ||
           metrics.network_tx_bytes > self.network_threshold {
            return Some(Anomaly::SuspiciousNetwork);
        }
        if metrics.pids > self.pids_threshold {
            return Some(Anomaly::ProcessSpike);
        }
        None
    }
}
```

---

## Registry Security

### Private Registry Authentication

```rust
use bollard::auth::DockerCredentials;

impl DockerManager {
    pub async fn login_registry(
        &self,
        server: &str,
        username: &str,
        password: &str,
    ) -> Result<(), Error> {
        let credentials = DockerCredentials {
            username: Some(username.to_string()),
            password: Some(password.to_string()),
            serveraddress: Some(server.to_string()),
            ..Default::default()
        };

        self.client
            .check_auth(credentials)
            .await
            .map_err(Error::RegistryAuth)?;

        Ok(())
    }

    pub async fn push_image(
        &self,
        image: &str,
        credentials: &DockerCredentials,
    ) -> Result<(), Error> {
        use bollard::image::PushImageOptions;

        let options = PushImageOptions { tag: "latest" };

        let mut stream = self.client.push_image(image, Some(options), Some(credentials.clone()));

        while let Some(result) = stream.next().await {
            match result {
                Ok(info) => {
                    if let Some(error) = info.error {
                        return Err(Error::ImagePush(error));
                    }
                }
                Err(e) => return Err(Error::ImagePush(e.to_string())),
            }
        }

        Ok(())
    }
}
```

### Vault-Based Registry Credentials

```rust
use vaultrs::kv2;

pub struct VaultRegistryManager {
    vault_client: vaultrs::client::VaultClient,
    vault_mount: String,
}

impl VaultRegistryManager {
    pub async fn get_credentials(&self, registry: &str) -> Result<DockerCredentials, Error> {
        let path = format!("docker-registries/{}", registry.replace('.', "-"));

        #[derive(serde::Deserialize)]
        struct RegistrySecret {
            username: String,
            password: String,
        }

        let secret: RegistrySecret = kv2::read(&self.vault_client, &self.vault_mount, &path)
            .await
            .map_err(Error::VaultRead)?;

        Ok(DockerCredentials {
            username: Some(secret.username),
            password: Some(secret.password),
            serveraddress: Some(registry.to_string()),
            ..Default::default()
        })
    }
}
```

---

## Dockerfile Hardening

### Secure Dockerfile Template

```dockerfile
# Use specific version tag, not 'latest'
FROM rust:1.92-slim-bookworm AS builder

# Create non-root user
RUN groupadd -r app && useradd -r -g app app

# Set working directory
WORKDIR /app

# Copy only what's needed for build
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build with release optimizations
RUN cargo build --release --locked

# Runtime stage - minimal image
FROM gcr.io/distroless/cc-debian12

# Copy binary from builder
COPY --from=builder /app/target/release/myapp /app/myapp

# Use non-root user (distroless default is nonroot)
USER nonroot:nonroot

# No shell, no package manager - minimal attack surface
ENTRYPOINT ["/app/myapp"]
```

### Dockerfile Security Analyzer

```rust
pub struct DockerfileAnalyzer;

impl DockerfileAnalyzer {
    pub fn analyze(dockerfile_content: &str) -> Vec<DockerfileWarning> {
        let mut warnings = Vec::new();

        for (line_num, line) in dockerfile_content.lines().enumerate() {
            let line = line.trim();

            // Check for root user
            if line.starts_with("USER") && line.contains("root") {
                warnings.push(DockerfileWarning {
                    line: line_num + 1,
                    severity: Severity::High,
                    message: "Container runs as root user".to_string(),
                    suggestion: "Use a non-root user: USER 1000:1000".to_string(),
                });
            }

            // Check for latest tag
            if line.starts_with("FROM") && (line.contains(":latest") || !line.contains(':')) {
                warnings.push(DockerfileWarning {
                    line: line_num + 1,
                    severity: Severity::Medium,
                    message: "Using 'latest' tag or no tag specified".to_string(),
                    suggestion: "Use specific version tag for reproducibility".to_string(),
                });
            }

            // Check for ADD instead of COPY
            if line.starts_with("ADD") && !line.contains("http") {
                warnings.push(DockerfileWarning {
                    line: line_num + 1,
                    severity: Severity::Low,
                    message: "ADD used for local files".to_string(),
                    suggestion: "Use COPY for local files, ADD only for URLs/archives".to_string(),
                });
            }

            // Check for secrets in ENV
            let lower_line = line.to_lowercase();
            if line.starts_with("ENV") &&
               (lower_line.contains("password") ||
                lower_line.contains("secret") ||
                lower_line.contains("api_key")) {
                warnings.push(DockerfileWarning {
                    line: line_num + 1,
                    severity: Severity::Critical,
                    message: "Potential secret in ENV instruction".to_string(),
                    suggestion: "Use Docker secrets or runtime environment variables".to_string(),
                });
            }

            // Check for sudo/apt-get without cleanup
            if line.contains("apt-get install") && !dockerfile_content.contains("apt-get clean") {
                warnings.push(DockerfileWarning {
                    line: line_num + 1,
                    severity: Severity::Low,
                    message: "apt-get without cleanup".to_string(),
                    suggestion: "Add 'apt-get clean && rm -rf /var/lib/apt/lists/*'".to_string(),
                });
            }
        }

        warnings
    }
}

#[derive(Debug)]
pub struct DockerfileWarning {
    pub line: usize,
    pub severity: Severity,
    pub message: String,
    pub suggestion: String,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}
```

---

## Docker Compose Security

### Secure docker-compose.yml Template

```yaml
version: '3.8'

services:
  app:
    image: myregistry.com/myapp:1.0.0@sha256:abc123...
    user: '1000:1000'
    read_only: true
    security_opt:
      - no-new-privileges:true
      - seccomp:./seccomp-profile.json
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE # Only if needed
    tmpfs:
      - /tmp:size=64M,noexec,nodev,nosuid
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 512M
          pids: 100
    healthcheck:
      test: ['CMD', '/app/healthcheck']
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - internal
    logging:
      driver: json-file
      options:
        max-size: '10m'
        max-file: '3'

networks:
  internal:
    internal: true
```

---

## Security Checklist

### Container Configuration

- [ ] Run as non-root user
- [ ] Drop all capabilities
- [ ] Read-only root filesystem
- [ ] No privileged mode
- [ ] Resource limits set
- [ ] PID limit configured
- [ ] no-new-privileges enabled

### Image Security

- [ ] Use minimal base image (distroless, Alpine)
- [ ] Multi-stage builds
- [ ] Specific version tags
- [ ] Image signing and verification
- [ ] Regular vulnerability scanning
- [ ] No secrets in images

### Network Security

- [ ] Minimal port exposure
- [ ] Internal networks for inter-service communication
- [ ] No host networking
- [ ] Network policies in orchestration

### Runtime Security

- [ ] Seccomp profiles
- [ ] AppArmor/SELinux
- [ ] Health checks
- [ ] Centralized logging
- [ ] Runtime monitoring

## Recommended Crates

- **bollard**: Docker API client
- **tokio**: Async runtime
- **futures**: Stream handling
- **serde**: JSON parsing
- **tracing**: Logging

## Integration Points

This skill works well with:

- `/server-harden` - Host security
- `/vault-setup` - Secret management for registry credentials
