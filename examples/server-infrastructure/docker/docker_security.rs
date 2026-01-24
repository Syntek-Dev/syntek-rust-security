//! Docker Security Manager Implementation
//!
//! Comprehensive Docker container security management with image scanning,
//! runtime security policies, and compliance checking.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Container state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerState {
    Created,
    Running,
    Paused,
    Restarting,
    Removing,
    Exited,
    Dead,
}

impl ContainerState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContainerState::Created => "created",
            ContainerState::Running => "running",
            ContainerState::Paused => "paused",
            ContainerState::Restarting => "restarting",
            ContainerState::Removing => "removing",
            ContainerState::Exited => "exited",
            ContainerState::Dead => "dead",
        }
    }
}

/// Vulnerability severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Unknown,
    Negligible,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Unknown => "UNKNOWN",
            Severity::Negligible => "NEGLIGIBLE",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    pub fn from_cvss(score: f32) -> Self {
        match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            s if s >= 0.1 => Severity::Low,
            _ => Severity::Unknown,
        }
    }
}

/// Image vulnerability
#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub id: String,
    pub package: String,
    pub version: String,
    pub fixed_version: Option<String>,
    pub severity: Severity,
    pub cvss_score: Option<f32>,
    pub description: String,
    pub references: Vec<String>,
}

/// Image scan result
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub image: String,
    pub digest: String,
    pub scanned_at: u64,
    pub vulnerabilities: Vec<Vulnerability>,
    pub os: String,
    pub os_version: String,
    pub layers: u32,
    pub size_bytes: u64,
}

impl ScanResult {
    pub fn critical_count(&self) -> usize {
        self.vulnerabilities
            .iter()
            .filter(|v| v.severity == Severity::Critical)
            .count()
    }

    pub fn high_count(&self) -> usize {
        self.vulnerabilities
            .iter()
            .filter(|v| v.severity == Severity::High)
            .count()
    }

    pub fn has_fixable(&self) -> bool {
        self.vulnerabilities
            .iter()
            .any(|v| v.fixed_version.is_some())
    }

    pub fn summary(&self) -> HashMap<Severity, usize> {
        let mut summary = HashMap::new();
        for vuln in &self.vulnerabilities {
            *summary.entry(vuln.severity).or_insert(0) += 1;
        }
        summary
    }
}

/// Security capability
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    ChOwn,
    DacOverride,
    Fsetid,
    FOwner,
    Mknod,
    NetRaw,
    Setgid,
    Setuid,
    Setfcap,
    Setpcap,
    NetBindService,
    SysChroot,
    Kill,
    AuditWrite,
    NetAdmin,
    SysAdmin,
    SysPtrace,
    SysRawio,
    SysBoot,
    SysNice,
    SysResource,
    SysTime,
    SysTtyConfig,
    Lease,
    AuditControl,
    MacAdmin,
    MacOverride,
    Syslog,
    WakeAlarm,
    BlockSuspend,
    AuditRead,
}

impl Capability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::ChOwn => "CHOWN",
            Capability::DacOverride => "DAC_OVERRIDE",
            Capability::Fsetid => "FSETID",
            Capability::FOwner => "FOWNER",
            Capability::Mknod => "MKNOD",
            Capability::NetRaw => "NET_RAW",
            Capability::Setgid => "SETGID",
            Capability::Setuid => "SETUID",
            Capability::Setfcap => "SETFCAP",
            Capability::Setpcap => "SETPCAP",
            Capability::NetBindService => "NET_BIND_SERVICE",
            Capability::SysChroot => "SYS_CHROOT",
            Capability::Kill => "KILL",
            Capability::AuditWrite => "AUDIT_WRITE",
            Capability::NetAdmin => "NET_ADMIN",
            Capability::SysAdmin => "SYS_ADMIN",
            Capability::SysPtrace => "SYS_PTRACE",
            Capability::SysRawio => "SYS_RAWIO",
            Capability::SysBoot => "SYS_BOOT",
            Capability::SysNice => "SYS_NICE",
            Capability::SysResource => "SYS_RESOURCE",
            Capability::SysTime => "SYS_TIME",
            Capability::SysTtyConfig => "SYS_TTY_CONFIG",
            Capability::Lease => "LEASE",
            Capability::AuditControl => "AUDIT_CONTROL",
            Capability::MacAdmin => "MAC_ADMIN",
            Capability::MacOverride => "MAC_OVERRIDE",
            Capability::Syslog => "SYSLOG",
            Capability::WakeAlarm => "WAKE_ALARM",
            Capability::BlockSuspend => "BLOCK_SUSPEND",
            Capability::AuditRead => "AUDIT_READ",
        }
    }

    /// Capabilities considered dangerous
    pub fn is_dangerous(&self) -> bool {
        matches!(
            self,
            Capability::SysAdmin
                | Capability::NetAdmin
                | Capability::SysPtrace
                | Capability::SysRawio
                | Capability::SysBoot
                | Capability::MacAdmin
                | Capability::MacOverride
        )
    }
}

/// Default capabilities granted to containers
pub fn default_capabilities() -> HashSet<Capability> {
    [
        Capability::ChOwn,
        Capability::DacOverride,
        Capability::Fsetid,
        Capability::FOwner,
        Capability::Mknod,
        Capability::NetRaw,
        Capability::Setgid,
        Capability::Setuid,
        Capability::Setfcap,
        Capability::Setpcap,
        Capability::NetBindService,
        Capability::SysChroot,
        Capability::Kill,
        Capability::AuditWrite,
    ]
    .into_iter()
    .collect()
}

/// Security profile for containers
#[derive(Debug, Clone)]
pub struct SecurityProfile {
    pub name: String,
    pub privileged: bool,
    pub user: Option<String>,
    pub read_only_root: bool,
    pub no_new_privileges: bool,
    pub cap_add: HashSet<Capability>,
    pub cap_drop: HashSet<Capability>,
    pub seccomp_profile: Option<String>,
    pub apparmor_profile: Option<String>,
    pub selinux_options: Option<SeLinuxOptions>,
    pub pid_limit: Option<i64>,
    pub memory_limit: Option<u64>,
    pub cpu_limit: Option<f64>,
    pub ulimits: HashMap<String, Ulimit>,
    pub allowed_syscalls: Option<Vec<String>>,
    pub blocked_syscalls: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct SeLinuxOptions {
    pub user: Option<String>,
    pub role: Option<String>,
    pub level: Option<String>,
    pub label_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Ulimit {
    pub name: String,
    pub soft: i64,
    pub hard: i64,
}

impl SecurityProfile {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            privileged: false,
            user: None,
            read_only_root: false,
            no_new_privileges: false,
            cap_add: HashSet::new(),
            cap_drop: HashSet::new(),
            seccomp_profile: None,
            apparmor_profile: None,
            selinux_options: None,
            pid_limit: None,
            memory_limit: None,
            cpu_limit: None,
            ulimits: HashMap::new(),
            allowed_syscalls: None,
            blocked_syscalls: None,
        }
    }

    pub fn hardened(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            privileged: false,
            user: Some("1000:1000".to_string()),
            read_only_root: true,
            no_new_privileges: true,
            cap_add: HashSet::new(),
            cap_drop: default_capabilities(), // Drop all default caps
            seccomp_profile: Some("runtime/default".to_string()),
            apparmor_profile: Some("runtime/default".to_string()),
            selinux_options: None,
            pid_limit: Some(100),
            memory_limit: Some(512 * 1024 * 1024), // 512MB
            cpu_limit: Some(1.0),
            ulimits: HashMap::new(),
            allowed_syscalls: None,
            blocked_syscalls: None,
        }
    }

    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    pub fn read_only_root(mut self, enable: bool) -> Self {
        self.read_only_root = enable;
        self
    }

    pub fn no_new_privileges(mut self, enable: bool) -> Self {
        self.no_new_privileges = enable;
        self
    }

    pub fn add_cap(mut self, cap: Capability) -> Self {
        self.cap_add.insert(cap);
        self
    }

    pub fn drop_cap(mut self, cap: Capability) -> Self {
        self.cap_drop.insert(cap);
        self
    }

    pub fn drop_all_caps(mut self) -> Self {
        self.cap_drop = default_capabilities();
        self
    }

    pub fn memory_limit(mut self, bytes: u64) -> Self {
        self.memory_limit = Some(bytes);
        self
    }

    pub fn cpu_limit(mut self, cpus: f64) -> Self {
        self.cpu_limit = Some(cpus);
        self
    }

    pub fn pid_limit(mut self, limit: i64) -> Self {
        self.pid_limit = Some(limit);
        self
    }

    pub fn seccomp(mut self, profile: impl Into<String>) -> Self {
        self.seccomp_profile = Some(profile.into());
        self
    }

    pub fn apparmor(mut self, profile: impl Into<String>) -> Self {
        self.apparmor_profile = Some(profile.into());
        self
    }
}

/// Container configuration
#[derive(Debug, Clone)]
pub struct ContainerConfig {
    pub name: String,
    pub image: String,
    pub command: Option<Vec<String>>,
    pub environment: HashMap<String, String>,
    pub volumes: Vec<VolumeMount>,
    pub ports: Vec<PortMapping>,
    pub network: Option<String>,
    pub security_profile: SecurityProfile,
    pub labels: HashMap<String, String>,
    pub health_check: Option<HealthCheck>,
    pub restart_policy: RestartPolicy,
}

#[derive(Debug, Clone)]
pub struct VolumeMount {
    pub source: String,
    pub target: String,
    pub read_only: bool,
    pub volume_type: VolumeType,
}

#[derive(Debug, Clone, Copy)]
pub enum VolumeType {
    Bind,
    Volume,
    Tmpfs,
}

#[derive(Debug, Clone)]
pub struct PortMapping {
    pub container_port: u16,
    pub host_port: Option<u16>,
    pub protocol: String,
    pub host_ip: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HealthCheck {
    pub command: Vec<String>,
    pub interval: Duration,
    pub timeout: Duration,
    pub retries: u32,
    pub start_period: Duration,
}

#[derive(Debug, Clone, Copy)]
pub enum RestartPolicy {
    No,
    Always,
    OnFailure(u32),
    UnlessStopped,
}

impl ContainerConfig {
    pub fn new(name: impl Into<String>, image: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            image: image.into(),
            command: None,
            environment: HashMap::new(),
            volumes: Vec::new(),
            ports: Vec::new(),
            network: None,
            security_profile: SecurityProfile::new("default"),
            labels: HashMap::new(),
            health_check: None,
            restart_policy: RestartPolicy::No,
        }
    }

    pub fn command(mut self, cmd: Vec<String>) -> Self {
        self.command = Some(cmd);
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }

    pub fn volume(mut self, source: impl Into<String>, target: impl Into<String>) -> Self {
        self.volumes.push(VolumeMount {
            source: source.into(),
            target: target.into(),
            read_only: false,
            volume_type: VolumeType::Bind,
        });
        self
    }

    pub fn volume_readonly(mut self, source: impl Into<String>, target: impl Into<String>) -> Self {
        self.volumes.push(VolumeMount {
            source: source.into(),
            target: target.into(),
            read_only: true,
            volume_type: VolumeType::Bind,
        });
        self
    }

    pub fn port(mut self, container: u16, host: u16) -> Self {
        self.ports.push(PortMapping {
            container_port: container,
            host_port: Some(host),
            protocol: "tcp".to_string(),
            host_ip: None,
        });
        self
    }

    pub fn network(mut self, network: impl Into<String>) -> Self {
        self.network = Some(network.into());
        self
    }

    pub fn security_profile(mut self, profile: SecurityProfile) -> Self {
        self.security_profile = profile;
        self
    }

    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    pub fn restart(mut self, policy: RestartPolicy) -> Self {
        self.restart_policy = policy;
        self
    }
}

/// Compliance check result
#[derive(Debug, Clone)]
pub struct ComplianceResult {
    pub passed: bool,
    pub checks: Vec<ComplianceCheck>,
    pub score: f32,
}

#[derive(Debug, Clone)]
pub struct ComplianceCheck {
    pub id: String,
    pub description: String,
    pub passed: bool,
    pub severity: Severity,
    pub remediation: Option<String>,
}

/// Docker security policy
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    pub name: String,
    pub allowed_registries: HashSet<String>,
    pub blocked_images: HashSet<String>,
    pub max_vulnerability_severity: Severity,
    pub require_image_signing: bool,
    pub require_non_root: bool,
    pub require_read_only_root: bool,
    pub require_resource_limits: bool,
    pub blocked_capabilities: HashSet<Capability>,
    pub max_port_number: u16,
    pub allowed_volume_paths: HashSet<String>,
    pub blocked_volume_paths: HashSet<String>,
}

impl SecurityPolicy {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            allowed_registries: HashSet::new(),
            blocked_images: HashSet::new(),
            max_vulnerability_severity: Severity::High,
            require_image_signing: false,
            require_non_root: false,
            require_read_only_root: false,
            require_resource_limits: false,
            blocked_capabilities: HashSet::new(),
            max_port_number: 65535,
            allowed_volume_paths: HashSet::new(),
            blocked_volume_paths: HashSet::new(),
        }
    }

    pub fn strict() -> Self {
        let mut policy = Self::new("strict");
        policy.require_non_root = true;
        policy.require_read_only_root = true;
        policy.require_resource_limits = true;
        policy.max_vulnerability_severity = Severity::Medium;
        policy.blocked_capabilities = [
            Capability::SysAdmin,
            Capability::NetAdmin,
            Capability::SysPtrace,
            Capability::NetRaw,
        ]
        .into_iter()
        .collect();
        policy.blocked_volume_paths = ["/", "/etc", "/var", "/root", "/home"]
            .into_iter()
            .map(String::from)
            .collect();
        policy
    }

    pub fn allow_registry(mut self, registry: impl Into<String>) -> Self {
        self.allowed_registries.insert(registry.into());
        self
    }

    pub fn block_image(mut self, image: impl Into<String>) -> Self {
        self.blocked_images.insert(image.into());
        self
    }

    pub fn block_capability(mut self, cap: Capability) -> Self {
        self.blocked_capabilities.insert(cap);
        self
    }

    pub fn block_volume_path(mut self, path: impl Into<String>) -> Self {
        self.blocked_volume_paths.insert(path.into());
        self
    }
}

/// Docker security manager
pub struct DockerSecurityManager {
    policies: Arc<RwLock<HashMap<String, SecurityPolicy>>>,
    scan_results: Arc<RwLock<HashMap<String, ScanResult>>>,
    default_policy: Option<String>,
}

impl DockerSecurityManager {
    pub fn new() -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            scan_results: Arc::new(RwLock::new(HashMap::new())),
            default_policy: None,
        }
    }

    pub fn add_policy(&mut self, policy: SecurityPolicy) {
        let name = policy.name.clone();
        let mut policies = self.policies.write().unwrap();
        policies.insert(name, policy);
    }

    pub fn set_default_policy(&mut self, name: impl Into<String>) {
        self.default_policy = Some(name.into());
    }

    /// Scan an image for vulnerabilities (mock implementation)
    pub fn scan_image(&self, image: &str) -> Result<ScanResult, DockerError> {
        // Mock scan result
        let result = ScanResult {
            image: image.to_string(),
            digest: format!("sha256:{:064x}", image.len()),
            scanned_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            vulnerabilities: vec![
                Vulnerability {
                    id: "CVE-2024-1234".to_string(),
                    package: "openssl".to_string(),
                    version: "1.1.1k".to_string(),
                    fixed_version: Some("1.1.1l".to_string()),
                    severity: Severity::High,
                    cvss_score: Some(7.5),
                    description: "Buffer overflow in SSL handling".to_string(),
                    references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-1234".to_string()],
                },
                Vulnerability {
                    id: "CVE-2024-5678".to_string(),
                    package: "curl".to_string(),
                    version: "7.68.0".to_string(),
                    fixed_version: Some("7.69.0".to_string()),
                    severity: Severity::Medium,
                    cvss_score: Some(5.3),
                    description: "URL parsing vulnerability".to_string(),
                    references: vec![],
                },
            ],
            os: "debian".to_string(),
            os_version: "11".to_string(),
            layers: 5,
            size_bytes: 150_000_000,
        };

        // Cache result
        let mut results = self.scan_results.write().unwrap();
        results.insert(image.to_string(), result.clone());

        Ok(result)
    }

    /// Validate container configuration against policy
    pub fn validate_config(
        &self,
        config: &ContainerConfig,
        policy_name: Option<&str>,
    ) -> Result<ComplianceResult, DockerError> {
        let policies = self.policies.read().unwrap();

        let policy_name = policy_name
            .map(String::from)
            .or(self.default_policy.clone())
            .ok_or(DockerError::NoPolicySet)?;

        let policy = policies
            .get(&policy_name)
            .ok_or_else(|| DockerError::PolicyNotFound(policy_name.clone()))?;

        let mut checks = Vec::new();

        // Check registry allowlist
        if !policy.allowed_registries.is_empty() {
            let registry = config.image.split('/').next().unwrap_or("");
            let passed = policy
                .allowed_registries
                .iter()
                .any(|r| registry.contains(r));
            checks.push(ComplianceCheck {
                id: "registry-allowlist".to_string(),
                description: "Image from allowed registry".to_string(),
                passed,
                severity: Severity::High,
                remediation: Some("Use an image from an allowed registry".to_string()),
            });
        }

        // Check blocked images
        let image_blocked = policy.blocked_images.contains(&config.image);
        checks.push(ComplianceCheck {
            id: "image-blocklist".to_string(),
            description: "Image not in blocklist".to_string(),
            passed: !image_blocked,
            severity: Severity::Critical,
            remediation: Some("Use a different image".to_string()),
        });

        // Check non-root requirement
        if policy.require_non_root {
            let has_user = config.security_profile.user.is_some();
            let is_root = config
                .security_profile
                .user
                .as_ref()
                .map(|u| u == "root" || u == "0")
                .unwrap_or(true);

            checks.push(ComplianceCheck {
                id: "non-root-user".to_string(),
                description: "Container runs as non-root".to_string(),
                passed: has_user && !is_root,
                severity: Severity::High,
                remediation: Some("Set a non-root user in security profile".to_string()),
            });
        }

        // Check read-only root filesystem
        if policy.require_read_only_root {
            checks.push(ComplianceCheck {
                id: "readonly-root".to_string(),
                description: "Root filesystem is read-only".to_string(),
                passed: config.security_profile.read_only_root,
                severity: Severity::Medium,
                remediation: Some("Enable read-only root filesystem".to_string()),
            });
        }

        // Check resource limits
        if policy.require_resource_limits {
            let has_limits = config.security_profile.memory_limit.is_some()
                || config.security_profile.cpu_limit.is_some();
            checks.push(ComplianceCheck {
                id: "resource-limits".to_string(),
                description: "Resource limits are set".to_string(),
                passed: has_limits,
                severity: Severity::Medium,
                remediation: Some("Set memory and CPU limits".to_string()),
            });
        }

        // Check blocked capabilities
        for cap in &config.security_profile.cap_add {
            if policy.blocked_capabilities.contains(cap) {
                checks.push(ComplianceCheck {
                    id: format!("blocked-cap-{}", cap.as_str().to_lowercase()),
                    description: format!("Capability {} is blocked", cap.as_str()),
                    passed: false,
                    severity: Severity::High,
                    remediation: Some(format!("Remove {} capability", cap.as_str())),
                });
            }
        }

        // Check privileged mode
        if config.security_profile.privileged {
            checks.push(ComplianceCheck {
                id: "privileged-mode".to_string(),
                description: "Container not running in privileged mode".to_string(),
                passed: false,
                severity: Severity::Critical,
                remediation: Some("Disable privileged mode".to_string()),
            });
        }

        // Check volume paths
        for volume in &config.volumes {
            if policy.blocked_volume_paths.contains(&volume.source) {
                checks.push(ComplianceCheck {
                    id: format!("blocked-volume-{}", volume.target.replace('/', "-")),
                    description: format!("Volume path {} is blocked", volume.source),
                    passed: false,
                    severity: Severity::High,
                    remediation: Some("Use a different volume path".to_string()),
                });
            }
        }

        let passed_count = checks.iter().filter(|c| c.passed).count();
        let total = checks.len();
        let score = if total > 0 {
            (passed_count as f32 / total as f32) * 100.0
        } else {
            100.0
        };

        Ok(ComplianceResult {
            passed: checks.iter().all(|c| c.passed),
            checks,
            score,
        })
    }

    /// Generate secure container run command
    pub fn generate_run_command(&self, config: &ContainerConfig) -> String {
        let mut cmd = vec!["docker".to_string(), "run".to_string()];

        // Name
        cmd.push("--name".to_string());
        cmd.push(config.name.clone());

        // Security options
        if config.security_profile.read_only_root {
            cmd.push("--read-only".to_string());
        }

        if config.security_profile.no_new_privileges {
            cmd.push("--security-opt".to_string());
            cmd.push("no-new-privileges:true".to_string());
        }

        if let Some(ref user) = config.security_profile.user {
            cmd.push("--user".to_string());
            cmd.push(user.clone());
        }

        // Capabilities
        if !config.security_profile.cap_drop.is_empty() {
            for cap in &config.security_profile.cap_drop {
                cmd.push("--cap-drop".to_string());
                cmd.push(cap.as_str().to_string());
            }
        }

        for cap in &config.security_profile.cap_add {
            cmd.push("--cap-add".to_string());
            cmd.push(cap.as_str().to_string());
        }

        // Resource limits
        if let Some(mem) = config.security_profile.memory_limit {
            cmd.push("--memory".to_string());
            cmd.push(format!("{}b", mem));
        }

        if let Some(cpu) = config.security_profile.cpu_limit {
            cmd.push("--cpus".to_string());
            cmd.push(format!("{}", cpu));
        }

        if let Some(pids) = config.security_profile.pid_limit {
            cmd.push("--pids-limit".to_string());
            cmd.push(pids.to_string());
        }

        // Seccomp
        if let Some(ref profile) = config.security_profile.seccomp_profile {
            cmd.push("--security-opt".to_string());
            cmd.push(format!("seccomp={}", profile));
        }

        // AppArmor
        if let Some(ref profile) = config.security_profile.apparmor_profile {
            cmd.push("--security-opt".to_string());
            cmd.push(format!("apparmor={}", profile));
        }

        // Environment
        for (key, value) in &config.environment {
            cmd.push("-e".to_string());
            cmd.push(format!("{}={}", key, value));
        }

        // Volumes
        for vol in &config.volumes {
            cmd.push("-v".to_string());
            let mount = if vol.read_only {
                format!("{}:{}:ro", vol.source, vol.target)
            } else {
                format!("{}:{}", vol.source, vol.target)
            };
            cmd.push(mount);
        }

        // Ports
        for port in &config.ports {
            cmd.push("-p".to_string());
            let mapping = if let Some(host) = port.host_port {
                format!("{}:{}", host, port.container_port)
            } else {
                port.container_port.to_string()
            };
            cmd.push(mapping);
        }

        // Network
        if let Some(ref network) = config.network {
            cmd.push("--network".to_string());
            cmd.push(network.clone());
        }

        // Labels
        for (key, value) in &config.labels {
            cmd.push("--label".to_string());
            cmd.push(format!("{}={}", key, value));
        }

        // Image
        cmd.push(config.image.clone());

        // Command
        if let Some(ref command) = config.command {
            cmd.extend(command.clone());
        }

        cmd.join(" ")
    }
}

impl Default for DockerSecurityManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Docker error types
#[derive(Debug)]
pub enum DockerError {
    ScanFailed(String),
    PolicyNotFound(String),
    NoPolicySet,
    ValidationFailed(String),
    ImageNotFound(String),
}

impl std::fmt::Display for DockerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DockerError::ScanFailed(msg) => write!(f, "Scan failed: {}", msg),
            DockerError::PolicyNotFound(name) => write!(f, "Policy not found: {}", name),
            DockerError::NoPolicySet => write!(f, "No policy set"),
            DockerError::ValidationFailed(msg) => write!(f, "Validation failed: {}", msg),
            DockerError::ImageNotFound(name) => write!(f, "Image not found: {}", name),
        }
    }
}

impl std::error::Error for DockerError {}

fn main() {
    println!("=== Docker Security Manager Demo ===\n");

    let mut manager = DockerSecurityManager::new();

    // Add security policies
    println!("1. Setting up security policies:");
    let strict_policy = SecurityPolicy::strict();
    println!("   Added strict policy with:");
    println!("   - Require non-root: {}", strict_policy.require_non_root);
    println!(
        "   - Require read-only root: {}",
        strict_policy.require_read_only_root
    );
    println!(
        "   - Blocked capabilities: {}",
        strict_policy.blocked_capabilities.len()
    );
    manager.add_policy(strict_policy);
    manager.set_default_policy("strict");

    // Scan an image
    println!("\n2. Scanning image for vulnerabilities:");
    match manager.scan_image("nginx:latest") {
        Ok(result) => {
            println!("   Image: {}", result.image);
            println!("   OS: {} {}", result.os, result.os_version);
            println!("   Vulnerabilities found: {}", result.vulnerabilities.len());
            println!("   - Critical: {}", result.critical_count());
            println!("   - High: {}", result.high_count());
            println!("   Has fixable: {}", result.has_fixable());
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Create a secure container config
    println!("\n3. Creating secure container configuration:");
    let secure_profile = SecurityProfile::hardened("secure-app")
        .add_cap(Capability::NetBindService)
        .memory_limit(256 * 1024 * 1024)
        .cpu_limit(0.5)
        .pid_limit(50);

    let config = ContainerConfig::new("my-secure-app", "myapp:v1.0")
        .env("APP_ENV", "production")
        .volume_readonly("/etc/app/config", "/config")
        .port(8080, 8080)
        .network("app-network")
        .security_profile(secure_profile)
        .label("team", "security")
        .restart(RestartPolicy::OnFailure(3));

    println!("   Container: {}", config.name);
    println!("   Image: {}", config.image);
    println!(
        "   Read-only root: {}",
        config.security_profile.read_only_root
    );
    println!("   Non-root user: {:?}", config.security_profile.user);

    // Validate configuration
    println!("\n4. Validating against strict policy:");
    match manager.validate_config(&config, None) {
        Ok(result) => {
            println!("   Compliance score: {:.1}%", result.score);
            println!("   Overall passed: {}", result.passed);
            println!("   Checks:");
            for check in &result.checks {
                let status = if check.passed { "PASS" } else { "FAIL" };
                println!(
                    "   - [{}] {} ({})",
                    status,
                    check.description,
                    check.severity.as_str()
                );
            }
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Generate run command
    println!("\n5. Generated docker run command:");
    let cmd = manager.generate_run_command(&config);
    println!("   {}", cmd);

    // Demonstrate insecure config
    println!("\n6. Testing insecure configuration:");
    let insecure_profile = SecurityProfile::new("insecure")
        .add_cap(Capability::SysAdmin)
        .add_cap(Capability::NetAdmin);

    let insecure_config = ContainerConfig::new("insecure-app", "someimage:latest")
        .security_profile(insecure_profile)
        .volume("/", "/host");

    match manager.validate_config(&insecure_config, None) {
        Ok(result) => {
            println!("   Compliance score: {:.1}%", result.score);
            println!("   Failed checks:");
            for check in result.checks.iter().filter(|c| !c.passed) {
                println!("   - {} ({})", check.description, check.severity.as_str());
                if let Some(ref remediation) = check.remediation {
                    println!("     Fix: {}", remediation);
                }
            }
        }
        Err(e) => println!("   Error: {}", e),
    }

    // Show capability info
    println!("\n7. Dangerous capabilities:");
    for cap in default_capabilities() {
        if cap.is_dangerous() {
            println!("   - {} (DANGEROUS)", cap.as_str());
        }
    }

    // Severity from CVSS
    println!("\n8. CVSS to Severity mapping:");
    for score in [9.5, 7.5, 5.0, 2.5, 0.0] {
        println!(
            "   CVSS {:.1} -> {}",
            score,
            Severity::from_cvss(score).as_str()
        );
    }

    println!("\n=== Demo Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }

    #[test]
    fn test_severity_from_cvss() {
        assert_eq!(Severity::from_cvss(9.5), Severity::Critical);
        assert_eq!(Severity::from_cvss(7.5), Severity::High);
        assert_eq!(Severity::from_cvss(5.0), Severity::Medium);
        assert_eq!(Severity::from_cvss(2.0), Severity::Low);
    }

    #[test]
    fn test_scan_result_counts() {
        let result = ScanResult {
            image: "test".to_string(),
            digest: "sha256:abc".to_string(),
            scanned_at: 0,
            vulnerabilities: vec![
                Vulnerability {
                    id: "CVE-1".to_string(),
                    package: "pkg".to_string(),
                    version: "1.0".to_string(),
                    fixed_version: Some("1.1".to_string()),
                    severity: Severity::Critical,
                    cvss_score: Some(9.8),
                    description: "desc".to_string(),
                    references: vec![],
                },
                Vulnerability {
                    id: "CVE-2".to_string(),
                    package: "pkg2".to_string(),
                    version: "2.0".to_string(),
                    fixed_version: None,
                    severity: Severity::High,
                    cvss_score: Some(7.5),
                    description: "desc".to_string(),
                    references: vec![],
                },
            ],
            os: "debian".to_string(),
            os_version: "11".to_string(),
            layers: 3,
            size_bytes: 100,
        };

        assert_eq!(result.critical_count(), 1);
        assert_eq!(result.high_count(), 1);
        assert!(result.has_fixable());
    }

    #[test]
    fn test_capability_dangerous() {
        assert!(Capability::SysAdmin.is_dangerous());
        assert!(Capability::NetAdmin.is_dangerous());
        assert!(!Capability::ChOwn.is_dangerous());
    }

    #[test]
    fn test_default_capabilities() {
        let caps = default_capabilities();
        assert!(caps.contains(&Capability::ChOwn));
        assert!(caps.contains(&Capability::NetRaw));
        assert!(!caps.contains(&Capability::SysAdmin));
    }

    #[test]
    fn test_security_profile_builder() {
        let profile = SecurityProfile::new("test")
            .user("1000:1000")
            .read_only_root(true)
            .no_new_privileges(true)
            .drop_cap(Capability::NetRaw)
            .add_cap(Capability::NetBindService)
            .memory_limit(512 * 1024 * 1024)
            .cpu_limit(1.0);

        assert_eq!(profile.user, Some("1000:1000".to_string()));
        assert!(profile.read_only_root);
        assert!(profile.cap_drop.contains(&Capability::NetRaw));
        assert!(profile.cap_add.contains(&Capability::NetBindService));
    }

    #[test]
    fn test_hardened_profile() {
        let profile = SecurityProfile::hardened("secure");

        assert!(profile.read_only_root);
        assert!(profile.no_new_privileges);
        assert!(profile.user.is_some());
        assert!(profile.seccomp_profile.is_some());
    }

    #[test]
    fn test_container_config_builder() {
        let config = ContainerConfig::new("test", "nginx:latest")
            .env("KEY", "value")
            .port(80, 8080)
            .volume("/data", "/app/data")
            .network("mynet")
            .label("env", "prod");

        assert_eq!(config.name, "test");
        assert_eq!(config.image, "nginx:latest");
        assert_eq!(config.environment.get("KEY"), Some(&"value".to_string()));
        assert_eq!(config.ports.len(), 1);
        assert_eq!(config.volumes.len(), 1);
    }

    #[test]
    fn test_security_policy_strict() {
        let policy = SecurityPolicy::strict();

        assert!(policy.require_non_root);
        assert!(policy.require_read_only_root);
        assert!(policy.blocked_capabilities.contains(&Capability::SysAdmin));
    }

    #[test]
    fn test_policy_builder() {
        let policy = SecurityPolicy::new("custom")
            .allow_registry("docker.io")
            .block_image("malicious:latest")
            .block_capability(Capability::SysPtrace)
            .block_volume_path("/etc");

        assert!(policy.allowed_registries.contains("docker.io"));
        assert!(policy.blocked_images.contains("malicious:latest"));
        assert!(policy.blocked_capabilities.contains(&Capability::SysPtrace));
        assert!(policy.blocked_volume_paths.contains("/etc"));
    }

    #[test]
    fn test_manager_scan() {
        let manager = DockerSecurityManager::new();
        let result = manager.scan_image("test:latest").unwrap();

        assert_eq!(result.image, "test:latest");
        assert!(!result.vulnerabilities.is_empty());
    }

    #[test]
    fn test_manager_validation() {
        let mut manager = DockerSecurityManager::new();
        manager.add_policy(SecurityPolicy::strict());
        manager.set_default_policy("strict");

        let config = ContainerConfig::new("test", "nginx:latest")
            .security_profile(SecurityProfile::hardened("test"));

        let result = manager.validate_config(&config, None).unwrap();
        assert!(!result.checks.is_empty());
    }

    #[test]
    fn test_generate_run_command() {
        let manager = DockerSecurityManager::new();

        let profile = SecurityProfile::new("test")
            .user("1000:1000")
            .read_only_root(true)
            .memory_limit(512 * 1024 * 1024);

        let config = ContainerConfig::new("myapp", "nginx:latest")
            .security_profile(profile)
            .port(80, 8080)
            .env("ENV", "prod");

        let cmd = manager.generate_run_command(&config);

        assert!(cmd.contains("docker run"));
        assert!(cmd.contains("--name myapp"));
        assert!(cmd.contains("--read-only"));
        assert!(cmd.contains("--user 1000:1000"));
        assert!(cmd.contains("-p 8080:80"));
    }

    #[test]
    fn test_no_policy_error() {
        let manager = DockerSecurityManager::new();
        let config = ContainerConfig::new("test", "nginx:latest");

        let result = manager.validate_config(&config, None);
        assert!(matches!(result, Err(DockerError::NoPolicySet)));
    }

    #[test]
    fn test_volume_mount_types() {
        let mount = VolumeMount {
            source: "/data".to_string(),
            target: "/app/data".to_string(),
            read_only: true,
            volume_type: VolumeType::Bind,
        };

        assert!(mount.read_only);
    }

    #[test]
    fn test_restart_policies() {
        let config =
            ContainerConfig::new("test", "nginx:latest").restart(RestartPolicy::OnFailure(3));

        assert!(matches!(config.restart_policy, RestartPolicy::OnFailure(3)));
    }

    #[test]
    fn test_container_state() {
        assert_eq!(ContainerState::Running.as_str(), "running");
        assert_eq!(ContainerState::Exited.as_str(), "exited");
    }

    #[test]
    fn test_compliance_score() {
        let result = ComplianceResult {
            passed: false,
            checks: vec![
                ComplianceCheck {
                    id: "1".to_string(),
                    description: "Test".to_string(),
                    passed: true,
                    severity: Severity::High,
                    remediation: None,
                },
                ComplianceCheck {
                    id: "2".to_string(),
                    description: "Test2".to_string(),
                    passed: false,
                    severity: Severity::Medium,
                    remediation: None,
                },
            ],
            score: 50.0,
        };

        assert_eq!(result.score, 50.0);
        assert!(!result.passed);
    }
}
