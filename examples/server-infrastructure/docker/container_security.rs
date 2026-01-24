//! Docker Container Security
//!
//! Comprehensive Docker security management with:
//! - Secure container configuration
//! - Image scanning
//! - Runtime security policies
//! - Network isolation
//! - Secret management

use std::collections::HashMap;
use std::fmt;

/// Docker client
pub struct DockerClient {
    socket_path: String,
}

/// Container configuration
#[derive(Clone, Debug)]
pub struct ContainerConfig {
    pub image: String,
    pub name: Option<String>,
    pub command: Vec<String>,
    pub environment: HashMap<String, String>,
    pub labels: HashMap<String, String>,
    pub security: SecurityConfig,
    pub resources: ResourceConfig,
    pub network: NetworkConfig,
    pub volumes: Vec<VolumeMount>,
    pub health_check: Option<HealthCheck>,
}

/// Security configuration
#[derive(Clone, Debug, Default)]
pub struct SecurityConfig {
    /// Run as non-root user
    pub user: Option<String>,
    /// Drop all capabilities
    pub drop_capabilities: Vec<String>,
    /// Add specific capabilities
    pub add_capabilities: Vec<String>,
    /// Read-only root filesystem
    pub read_only_root: bool,
    /// No new privileges
    pub no_new_privileges: bool,
    /// Seccomp profile
    pub seccomp_profile: Option<String>,
    /// AppArmor profile
    pub apparmor_profile: Option<String>,
    /// SELinux options
    pub selinux_options: Option<SeLinuxOptions>,
    /// Privileged mode (avoid!)
    pub privileged: bool,
    /// PID namespace
    pub pid_mode: Option<String>,
    /// IPC mode
    pub ipc_mode: Option<String>,
    /// Sysctls
    pub sysctls: HashMap<String, String>,
}

/// SELinux options
#[derive(Clone, Debug)]
pub struct SeLinuxOptions {
    pub user: Option<String>,
    pub role: Option<String>,
    pub level: Option<String>,
    pub label_type: Option<String>,
}

/// Resource configuration
#[derive(Clone, Debug, Default)]
pub struct ResourceConfig {
    /// Memory limit (bytes)
    pub memory_limit: Option<u64>,
    /// Memory reservation
    pub memory_reservation: Option<u64>,
    /// CPU quota (microseconds per period)
    pub cpu_quota: Option<i64>,
    /// CPU period (microseconds)
    pub cpu_period: Option<u64>,
    /// CPU shares
    pub cpu_shares: Option<u64>,
    /// Number of CPUs
    pub cpus: Option<f64>,
    /// PIDs limit
    pub pids_limit: Option<i64>,
    /// IO weight
    pub blkio_weight: Option<u16>,
}

/// Network configuration
#[derive(Clone, Debug, Default)]
pub struct NetworkConfig {
    /// Network mode
    pub mode: NetworkMode,
    /// Published ports
    pub ports: Vec<PortBinding>,
    /// DNS servers
    pub dns: Vec<String>,
    /// Extra hosts
    pub extra_hosts: Vec<String>,
    /// Network aliases
    pub aliases: Vec<String>,
}

/// Network mode
#[derive(Clone, Debug, Default)]
pub enum NetworkMode {
    #[default]
    Bridge,
    Host,
    None,
    Container(String),
    Custom(String),
}

/// Port binding
#[derive(Clone, Debug)]
pub struct PortBinding {
    pub container_port: u16,
    pub host_port: Option<u16>,
    pub host_ip: Option<String>,
    pub protocol: Protocol,
}

/// Protocol
#[derive(Clone, Copy, Debug, Default)]
pub enum Protocol {
    #[default]
    Tcp,
    Udp,
}

/// Volume mount
#[derive(Clone, Debug)]
pub struct VolumeMount {
    pub source: String,
    pub target: String,
    pub read_only: bool,
    pub mount_type: MountType,
}

/// Mount type
#[derive(Clone, Debug, Default)]
pub enum MountType {
    #[default]
    Bind,
    Volume,
    Tmpfs,
}

/// Health check configuration
#[derive(Clone, Debug)]
pub struct HealthCheck {
    pub test: Vec<String>,
    pub interval: u64,
    pub timeout: u64,
    pub retries: u32,
    pub start_period: u64,
}

/// Image scan result
#[derive(Clone, Debug)]
pub struct ScanResult {
    pub image: String,
    pub vulnerabilities: Vec<Vulnerability>,
    pub summary: ScanSummary,
    pub compliant: bool,
}

/// Vulnerability
#[derive(Clone, Debug)]
pub struct Vulnerability {
    pub id: String,
    pub package: String,
    pub version: String,
    pub fixed_version: Option<String>,
    pub severity: Severity,
    pub description: String,
    pub cvss_score: Option<f32>,
}

/// Severity level
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

/// Scan summary
#[derive(Clone, Debug, Default)]
pub struct ScanSummary {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub unknown: u32,
}

/// Container info
#[derive(Clone, Debug)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: ContainerStatus,
    pub created: String,
}

/// Container status
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerStatus {
    Created,
    Running,
    Paused,
    Restarting,
    Removing,
    Exited,
    Dead,
}

/// Docker error
#[derive(Debug)]
pub enum DockerError {
    ConnectionFailed(String),
    ImageNotFound(String),
    ContainerNotFound(String),
    PermissionDenied(String),
    ResourceExhausted(String),
    InvalidConfig(String),
}

impl fmt::Display for DockerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DockerError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            DockerError::ImageNotFound(img) => write!(f, "Image not found: {}", img),
            DockerError::ContainerNotFound(id) => write!(f, "Container not found: {}", id),
            DockerError::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            DockerError::ResourceExhausted(msg) => write!(f, "Resource exhausted: {}", msg),
            DockerError::InvalidConfig(msg) => write!(f, "Invalid config: {}", msg),
        }
    }
}

impl std::error::Error for DockerError {}

impl DockerClient {
    /// Create new Docker client
    pub fn new() -> Self {
        Self {
            socket_path: "/var/run/docker.sock".to_string(),
        }
    }

    /// Create client with custom socket
    pub fn with_socket(path: impl Into<String>) -> Self {
        Self {
            socket_path: path.into(),
        }
    }

    /// Create container with security hardening
    pub fn create_container(&self, config: ContainerConfig) -> Result<String, DockerError> {
        // Validate security config
        self.validate_security(&config)?;

        // Simulated container creation
        let container_id = format!("container_{}", generate_id());
        println!("Created container: {}", container_id);
        Ok(container_id)
    }

    /// Start container
    pub fn start_container(&self, container_id: &str) -> Result<(), DockerError> {
        println!("Started container: {}", container_id);
        Ok(())
    }

    /// Stop container
    pub fn stop_container(&self, container_id: &str, timeout: u32) -> Result<(), DockerError> {
        println!(
            "Stopped container: {} (timeout: {}s)",
            container_id, timeout
        );
        Ok(())
    }

    /// Remove container
    pub fn remove_container(&self, container_id: &str, force: bool) -> Result<(), DockerError> {
        println!("Removed container: {} (force: {})", container_id, force);
        Ok(())
    }

    /// List containers
    pub fn list_containers(&self, all: bool) -> Result<Vec<ContainerInfo>, DockerError> {
        Ok(vec![ContainerInfo {
            id: "abc123".to_string(),
            name: "my-app".to_string(),
            image: "my-app:latest".to_string(),
            status: ContainerStatus::Running,
            created: "2025-01-23T10:00:00Z".to_string(),
        }])
    }

    /// Scan image for vulnerabilities
    pub fn scan_image(&self, image: &str) -> Result<ScanResult, DockerError> {
        // Simulated scan results
        let vulnerabilities = vec![
            Vulnerability {
                id: "CVE-2024-1234".to_string(),
                package: "openssl".to_string(),
                version: "1.1.1k".to_string(),
                fixed_version: Some("1.1.1l".to_string()),
                severity: Severity::High,
                description: "Buffer overflow in SSL handling".to_string(),
                cvss_score: Some(7.5),
            },
            Vulnerability {
                id: "CVE-2024-5678".to_string(),
                package: "libc".to_string(),
                version: "2.31".to_string(),
                fixed_version: Some("2.32".to_string()),
                severity: Severity::Medium,
                description: "Memory corruption vulnerability".to_string(),
                cvss_score: Some(5.5),
            },
        ];

        let summary = ScanSummary {
            critical: 0,
            high: 1,
            medium: 1,
            low: 0,
            unknown: 0,
        };

        Ok(ScanResult {
            image: image.to_string(),
            vulnerabilities,
            summary,
            compliant: false,
        })
    }

    /// Pull image
    pub fn pull_image(&self, image: &str) -> Result<(), DockerError> {
        println!("Pulled image: {}", image);
        Ok(())
    }

    /// Build image
    pub fn build_image(
        &self,
        dockerfile: &str,
        tag: &str,
        context: &str,
    ) -> Result<String, DockerError> {
        let image_id = format!("sha256:{}", generate_id());
        println!("Built image: {} -> {}", tag, image_id);
        Ok(image_id)
    }

    /// Create network
    pub fn create_network(&self, name: &str, driver: &str) -> Result<String, DockerError> {
        let network_id = format!("network_{}", generate_id());
        println!("Created network: {} ({})", name, driver);
        Ok(network_id)
    }

    /// Get container logs
    pub fn get_logs(&self, container_id: &str, tail: u32) -> Result<String, DockerError> {
        Ok(format!("Logs for {} (last {} lines)", container_id, tail))
    }

    /// Execute command in container
    pub fn exec(&self, container_id: &str, command: &[&str]) -> Result<String, DockerError> {
        Ok(format!("Executed: {:?}", command))
    }

    fn validate_security(&self, config: &ContainerConfig) -> Result<(), DockerError> {
        // Check for privileged mode
        if config.security.privileged {
            println!("WARNING: Privileged mode enabled - this is a security risk!");
        }

        // Validate user is set (non-root)
        if config.security.user.is_none() && !config.security.privileged {
            println!("RECOMMENDATION: Set a non-root user for better security");
        }

        // Check for dangerous capabilities
        let dangerous_caps = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"];
        for cap in &config.security.add_capabilities {
            if dangerous_caps.contains(&cap.as_str()) {
                println!("WARNING: Adding dangerous capability: {}", cap);
            }
        }

        // Validate read-only root
        if !config.security.read_only_root {
            println!("RECOMMENDATION: Use read-only root filesystem");
        }

        Ok(())
    }
}

impl Default for DockerClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Security presets for common use cases
pub struct SecurityPresets;

impl SecurityPresets {
    /// Minimal security (for development)
    pub fn minimal() -> SecurityConfig {
        SecurityConfig::default()
    }

    /// Standard hardened configuration
    pub fn hardened() -> SecurityConfig {
        SecurityConfig {
            user: Some("1000:1000".to_string()),
            drop_capabilities: vec!["ALL".to_string()],
            add_capabilities: vec![],
            read_only_root: true,
            no_new_privileges: true,
            seccomp_profile: Some("runtime/default".to_string()),
            apparmor_profile: Some("runtime/default".to_string()),
            privileged: false,
            ..Default::default()
        }
    }

    /// Web server configuration
    pub fn web_server() -> SecurityConfig {
        SecurityConfig {
            user: Some("www-data:www-data".to_string()),
            drop_capabilities: vec!["ALL".to_string()],
            add_capabilities: vec!["NET_BIND_SERVICE".to_string()],
            read_only_root: true,
            no_new_privileges: true,
            privileged: false,
            ..Default::default()
        }
    }

    /// Database configuration
    pub fn database() -> SecurityConfig {
        SecurityConfig {
            user: Some("999:999".to_string()),
            drop_capabilities: vec!["ALL".to_string()],
            add_capabilities: vec![
                "CHOWN".to_string(),
                "SETGID".to_string(),
                "SETUID".to_string(),
            ],
            read_only_root: false, // DB needs to write
            no_new_privileges: true,
            privileged: false,
            ..Default::default()
        }
    }
}

/// Resource presets
pub struct ResourcePresets;

impl ResourcePresets {
    /// Small container
    pub fn small() -> ResourceConfig {
        ResourceConfig {
            memory_limit: Some(256 * 1024 * 1024), // 256 MB
            cpus: Some(0.5),
            pids_limit: Some(100),
            ..Default::default()
        }
    }

    /// Medium container
    pub fn medium() -> ResourceConfig {
        ResourceConfig {
            memory_limit: Some(512 * 1024 * 1024), // 512 MB
            cpus: Some(1.0),
            pids_limit: Some(200),
            ..Default::default()
        }
    }

    /// Large container
    pub fn large() -> ResourceConfig {
        ResourceConfig {
            memory_limit: Some(2 * 1024 * 1024 * 1024), // 2 GB
            cpus: Some(2.0),
            pids_limit: Some(500),
            ..Default::default()
        }
    }
}

fn generate_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:016x}", now)
}

fn main() {
    println!("=== Docker Container Security Demo ===\n");

    let client = DockerClient::new();

    // Create hardened container
    println!("=== Creating Hardened Container ===\n");

    let config = ContainerConfig {
        image: "nginx:alpine".to_string(),
        name: Some("secure-nginx".to_string()),
        command: vec![],
        environment: {
            let mut env = HashMap::new();
            env.insert("NGINX_WORKER_PROCESSES".to_string(), "auto".to_string());
            env
        },
        labels: {
            let mut labels = HashMap::new();
            labels.insert("app".to_string(), "web".to_string());
            labels.insert("security".to_string(), "hardened".to_string());
            labels
        },
        security: SecurityPresets::web_server(),
        resources: ResourcePresets::medium(),
        network: NetworkConfig {
            mode: NetworkMode::Bridge,
            ports: vec![PortBinding {
                container_port: 80,
                host_port: Some(8080),
                host_ip: Some("127.0.0.1".to_string()),
                protocol: Protocol::Tcp,
            }],
            ..Default::default()
        },
        volumes: vec![
            VolumeMount {
                source: "/var/www/html".to_string(),
                target: "/usr/share/nginx/html".to_string(),
                read_only: true,
                mount_type: MountType::Bind,
            },
            VolumeMount {
                source: "nginx-cache".to_string(),
                target: "/var/cache/nginx".to_string(),
                read_only: false,
                mount_type: MountType::Volume,
            },
        ],
        health_check: Some(HealthCheck {
            test: vec![
                "CMD".to_string(),
                "wget",
                "-q",
                "--spider",
                "http://localhost/health".to_string(),
            ],
            interval: 30,
            timeout: 10,
            retries: 3,
            start_period: 10,
        }),
    };

    let container_id = client.create_container(config).unwrap();
    println!("Container ID: {}", container_id);

    client.start_container(&container_id).unwrap();

    // Scan image for vulnerabilities
    println!("\n=== Image Vulnerability Scan ===\n");

    let scan_result = client.scan_image("nginx:alpine").unwrap();
    println!("Image: {}", scan_result.image);
    println!("Compliant: {}", scan_result.compliant);
    println!("Summary:");
    println!("  Critical: {}", scan_result.summary.critical);
    println!("  High: {}", scan_result.summary.high);
    println!("  Medium: {}", scan_result.summary.medium);
    println!("  Low: {}", scan_result.summary.low);

    println!("\nVulnerabilities:");
    for vuln in &scan_result.vulnerabilities {
        println!(
            "  - {} ({:?}): {} {}",
            vuln.id, vuln.severity, vuln.package, vuln.version
        );
        if let Some(fixed) = &vuln.fixed_version {
            println!("    Fixed in: {}", fixed);
        }
    }

    // Create isolated network
    println!("\n=== Creating Isolated Network ===\n");

    let network_id = client.create_network("app-internal", "bridge").unwrap();
    println!("Network ID: {}", network_id);

    // List containers
    println!("\n=== Container List ===\n");

    let containers = client.list_containers(true).unwrap();
    for container in containers {
        println!(
            "{} ({}) - {:?}",
            container.name, container.id, container.status
        );
    }

    // Security presets
    println!("\n=== Security Presets ===\n");

    let hardened = SecurityPresets::hardened();
    println!("Hardened preset:");
    println!("  User: {:?}", hardened.user);
    println!("  Read-only root: {}", hardened.read_only_root);
    println!("  No new privileges: {}", hardened.no_new_privileges);
    println!("  Drop capabilities: {:?}", hardened.drop_capabilities);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = DockerClient::new();
        assert_eq!(client.socket_path, "/var/run/docker.sock");
    }

    #[test]
    fn test_custom_socket() {
        let client = DockerClient::with_socket("/custom/socket.sock");
        assert_eq!(client.socket_path, "/custom/socket.sock");
    }

    #[test]
    fn test_create_container() {
        let client = DockerClient::new();
        let config = ContainerConfig {
            image: "alpine:latest".to_string(),
            name: Some("test".to_string()),
            command: vec![],
            environment: HashMap::new(),
            labels: HashMap::new(),
            security: SecurityConfig::default(),
            resources: ResourceConfig::default(),
            network: NetworkConfig::default(),
            volumes: vec![],
            health_check: None,
        };

        let result = client.create_container(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_security_presets() {
        let minimal = SecurityPresets::minimal();
        assert!(!minimal.read_only_root);

        let hardened = SecurityPresets::hardened();
        assert!(hardened.read_only_root);
        assert!(hardened.no_new_privileges);
        assert!(hardened.user.is_some());
    }

    #[test]
    fn test_resource_presets() {
        let small = ResourcePresets::small();
        assert!(small.memory_limit.is_some());
        assert!(small.memory_limit.unwrap() < 512 * 1024 * 1024);

        let large = ResourcePresets::large();
        assert!(large.memory_limit.unwrap() > 1024 * 1024 * 1024);
    }

    #[test]
    fn test_scan_image() {
        let client = DockerClient::new();
        let result = client.scan_image("nginx:alpine").unwrap();

        assert_eq!(result.image, "nginx:alpine");
        assert!(!result.vulnerabilities.is_empty());
    }

    #[test]
    fn test_list_containers() {
        let client = DockerClient::new();
        let containers = client.list_containers(true).unwrap();
        assert!(!containers.is_empty());
    }

    #[test]
    fn test_container_lifecycle() {
        let client = DockerClient::new();

        let config = ContainerConfig {
            image: "alpine:latest".to_string(),
            name: None,
            command: vec![],
            environment: HashMap::new(),
            labels: HashMap::new(),
            security: SecurityConfig::default(),
            resources: ResourceConfig::default(),
            network: NetworkConfig::default(),
            volumes: vec![],
            health_check: None,
        };

        let id = client.create_container(config).unwrap();
        assert!(client.start_container(&id).is_ok());
        assert!(client.stop_container(&id, 10).is_ok());
        assert!(client.remove_container(&id, false).is_ok());
    }

    #[test]
    fn test_network_modes() {
        let bridge = NetworkMode::Bridge;
        let custom = NetworkMode::Custom("my-network".to_string());

        assert!(matches!(bridge, NetworkMode::Bridge));
        if let NetworkMode::Custom(name) = custom {
            assert_eq!(name, "my-network");
        }
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }
}
