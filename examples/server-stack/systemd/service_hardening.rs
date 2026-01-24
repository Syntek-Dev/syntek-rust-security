//! Systemd Service Hardening
//!
//! Generate security-hardened systemd service files with:
//! - Sandboxing and isolation
//! - Resource limits
//! - Capability dropping
//! - Namespace isolation
//! - Filesystem restrictions

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

/// Service type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceType {
    Simple,
    Exec,
    Forking,
    OneShot,
    Notify,
    Idle,
}

/// Restart policy
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartPolicy {
    No,
    OnSuccess,
    OnFailure,
    OnAbnormal,
    OnWatchdog,
    OnAbort,
    Always,
}

/// Protect system mode
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectSystem {
    No,
    Yes,
    Full,
    Strict,
}

/// Protect home mode
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectHome {
    No,
    Yes,
    ReadOnly,
    Tmpfs,
}

/// Linux capability
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Capability {
    // Network capabilities
    NetBindService,
    NetAdmin,
    NetRaw,
    // File capabilities
    Chown,
    DacOverride,
    Fowner,
    Fsetid,
    // Process capabilities
    Kill,
    Setgid,
    Setuid,
    SetPcap,
    // System capabilities
    SysAdmin,
    SysPtrace,
    SysChroot,
    SysResource,
    // Other
    Audit,
    Mknod,
    Lease,
    Syslog,
}

/// Systemd service configuration
#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub name: String,
    pub description: String,
    pub service_type: ServiceType,
    pub exec_start: String,
    pub exec_stop: Option<String>,
    pub working_directory: Option<PathBuf>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub restart: RestartPolicy,
    pub restart_sec: u32,
    pub timeout_start_sec: u32,
    pub timeout_stop_sec: u32,
    pub environment: HashMap<String, String>,
    pub environment_file: Option<PathBuf>,
    pub security: SecurityConfig,
    pub resources: ResourceConfig,
    pub dependencies: DependencyConfig,
}

/// Security hardening configuration
#[derive(Clone, Debug, Default)]
pub struct SecurityConfig {
    // Sandboxing
    pub protect_system: ProtectSystem,
    pub protect_home: ProtectHome,
    pub private_tmp: bool,
    pub private_devices: bool,
    pub private_network: bool,
    pub private_users: bool,
    pub protect_kernel_tunables: bool,
    pub protect_kernel_modules: bool,
    pub protect_kernel_logs: bool,
    pub protect_control_groups: bool,
    pub protect_clock: bool,
    pub protect_hostname: bool,

    // Capabilities
    pub no_new_privileges: bool,
    pub capability_bounding_set: Vec<Capability>,
    pub ambient_capabilities: Vec<Capability>,

    // Namespaces
    pub private_mounts: bool,
    pub mount_flags: Vec<String>,
    pub bind_paths: Vec<PathBuf>,
    pub bind_read_only_paths: Vec<PathBuf>,
    pub inaccessible_paths: Vec<PathBuf>,
    pub temporary_filesystem: Vec<PathBuf>,

    // System call filtering
    pub system_call_filter: Vec<String>,
    pub system_call_error_number: Option<String>,
    pub system_call_architectures: Vec<String>,

    // Misc
    pub lock_personality: bool,
    pub memory_deny_write_execute: bool,
    pub restrict_address_families: Vec<String>,
    pub restrict_namespaces: bool,
    pub restrict_realtime: bool,
    pub restrict_suid_sgid: bool,
    pub remove_ipc: bool,
    pub umask: Option<String>,

    // Seccomp
    pub seccomp_filter: Option<String>,
}

/// Resource limits configuration
#[derive(Clone, Debug, Default)]
pub struct ResourceConfig {
    pub limit_nofile: Option<u64>,
    pub limit_nproc: Option<u64>,
    pub limit_memlock: Option<String>,
    pub limit_core: Option<u64>,
    pub limit_as: Option<String>,
    pub memory_max: Option<String>,
    pub memory_high: Option<String>,
    pub cpu_quota: Option<String>,
    pub tasks_max: Option<u64>,
    pub io_weight: Option<u32>,
    pub nice: Option<i32>,
    pub oom_score_adjust: Option<i32>,
}

/// Service dependencies
#[derive(Clone, Debug, Default)]
pub struct DependencyConfig {
    pub after: Vec<String>,
    pub before: Vec<String>,
    pub requires: Vec<String>,
    pub wants: Vec<String>,
    pub conflicts: Vec<String>,
    pub wanted_by: Vec<String>,
}

/// Systemd service generator
pub struct ServiceGenerator {
    config: ServiceConfig,
}

impl ServiceGenerator {
    /// Create new generator with config
    pub fn new(config: ServiceConfig) -> Self {
        Self { config }
    }

    /// Generate the service file content
    pub fn generate(&self) -> String {
        let mut output = String::new();

        // [Unit] section
        output.push_str("[Unit]\n");
        output.push_str(&format!("Description={}\n", self.config.description));

        for dep in &self.config.dependencies.after {
            output.push_str(&format!("After={}\n", dep));
        }
        for dep in &self.config.dependencies.before {
            output.push_str(&format!("Before={}\n", dep));
        }
        for dep in &self.config.dependencies.requires {
            output.push_str(&format!("Requires={}\n", dep));
        }
        for dep in &self.config.dependencies.wants {
            output.push_str(&format!("Wants={}\n", dep));
        }
        for dep in &self.config.dependencies.conflicts {
            output.push_str(&format!("Conflicts={}\n", dep));
        }

        output.push('\n');

        // [Service] section
        output.push_str("[Service]\n");
        output.push_str(&format!(
            "Type={}\n",
            service_type_str(self.config.service_type)
        ));
        output.push_str(&format!("ExecStart={}\n", self.config.exec_start));

        if let Some(exec_stop) = &self.config.exec_stop {
            output.push_str(&format!("ExecStop={}\n", exec_stop));
        }

        if let Some(dir) = &self.config.working_directory {
            output.push_str(&format!("WorkingDirectory={}\n", dir.display()));
        }

        if let Some(user) = &self.config.user {
            output.push_str(&format!("User={}\n", user));
        }

        if let Some(group) = &self.config.group {
            output.push_str(&format!("Group={}\n", group));
        }

        output.push_str(&format!(
            "Restart={}\n",
            restart_policy_str(self.config.restart)
        ));
        output.push_str(&format!("RestartSec={}\n", self.config.restart_sec));
        output.push_str(&format!(
            "TimeoutStartSec={}\n",
            self.config.timeout_start_sec
        ));
        output.push_str(&format!(
            "TimeoutStopSec={}\n",
            self.config.timeout_stop_sec
        ));

        // Environment
        for (key, value) in &self.config.environment {
            output.push_str(&format!("Environment=\"{}={}\"\n", key, value));
        }

        if let Some(env_file) = &self.config.environment_file {
            output.push_str(&format!("EnvironmentFile={}\n", env_file.display()));
        }

        output.push('\n');

        // Security hardening
        output.push_str("# Security Hardening\n");
        self.generate_security_config(&mut output);

        output.push('\n');

        // Resource limits
        output.push_str("# Resource Limits\n");
        self.generate_resource_config(&mut output);

        output.push('\n');

        // [Install] section
        output.push_str("[Install]\n");
        for target in &self.config.dependencies.wanted_by {
            output.push_str(&format!("WantedBy={}\n", target));
        }

        output
    }

    fn generate_security_config(&self, output: &mut String) {
        let sec = &self.config.security;

        // Sandboxing
        output.push_str(&format!(
            "ProtectSystem={}\n",
            protect_system_str(sec.protect_system)
        ));
        output.push_str(&format!(
            "ProtectHome={}\n",
            protect_home_str(sec.protect_home)
        ));

        if sec.private_tmp {
            output.push_str("PrivateTmp=yes\n");
        }
        if sec.private_devices {
            output.push_str("PrivateDevices=yes\n");
        }
        if sec.private_network {
            output.push_str("PrivateNetwork=yes\n");
        }
        if sec.private_users {
            output.push_str("PrivateUsers=yes\n");
        }
        if sec.protect_kernel_tunables {
            output.push_str("ProtectKernelTunables=yes\n");
        }
        if sec.protect_kernel_modules {
            output.push_str("ProtectKernelModules=yes\n");
        }
        if sec.protect_kernel_logs {
            output.push_str("ProtectKernelLogs=yes\n");
        }
        if sec.protect_control_groups {
            output.push_str("ProtectControlGroups=yes\n");
        }
        if sec.protect_clock {
            output.push_str("ProtectClock=yes\n");
        }
        if sec.protect_hostname {
            output.push_str("ProtectHostname=yes\n");
        }

        // Capabilities
        if sec.no_new_privileges {
            output.push_str("NoNewPrivileges=yes\n");
        }

        if !sec.capability_bounding_set.is_empty() {
            let caps: Vec<String> = sec
                .capability_bounding_set
                .iter()
                .map(|c| capability_str(*c))
                .collect();
            output.push_str(&format!("CapabilityBoundingSet={}\n", caps.join(" ")));
        } else {
            output.push_str("CapabilityBoundingSet=\n");
        }

        if !sec.ambient_capabilities.is_empty() {
            let caps: Vec<String> = sec
                .ambient_capabilities
                .iter()
                .map(|c| capability_str(*c))
                .collect();
            output.push_str(&format!("AmbientCapabilities={}\n", caps.join(" ")));
        }

        // Namespaces and paths
        if sec.private_mounts {
            output.push_str("PrivateMounts=yes\n");
        }

        for path in &sec.bind_paths {
            output.push_str(&format!("BindPaths={}\n", path.display()));
        }

        for path in &sec.bind_read_only_paths {
            output.push_str(&format!("BindReadOnlyPaths={}\n", path.display()));
        }

        for path in &sec.inaccessible_paths {
            output.push_str(&format!("InaccessiblePaths={}\n", path.display()));
        }

        for path in &sec.temporary_filesystem {
            output.push_str(&format!("TemporaryFileSystem={}\n", path.display()));
        }

        // System call filtering
        if !sec.system_call_filter.is_empty() {
            output.push_str(&format!(
                "SystemCallFilter={}\n",
                sec.system_call_filter.join(" ")
            ));
        }

        if let Some(errno) = &sec.system_call_error_number {
            output.push_str(&format!("SystemCallErrorNumber={}\n", errno));
        }

        if !sec.system_call_architectures.is_empty() {
            output.push_str(&format!(
                "SystemCallArchitectures={}\n",
                sec.system_call_architectures.join(" ")
            ));
        }

        // Misc security
        if sec.lock_personality {
            output.push_str("LockPersonality=yes\n");
        }
        if sec.memory_deny_write_execute {
            output.push_str("MemoryDenyWriteExecute=yes\n");
        }
        if !sec.restrict_address_families.is_empty() {
            output.push_str(&format!(
                "RestrictAddressFamilies={}\n",
                sec.restrict_address_families.join(" ")
            ));
        }
        if sec.restrict_namespaces {
            output.push_str("RestrictNamespaces=yes\n");
        }
        if sec.restrict_realtime {
            output.push_str("RestrictRealtime=yes\n");
        }
        if sec.restrict_suid_sgid {
            output.push_str("RestrictSUIDSGID=yes\n");
        }
        if sec.remove_ipc {
            output.push_str("RemoveIPC=yes\n");
        }
        if let Some(umask) = &sec.umask {
            output.push_str(&format!("UMask={}\n", umask));
        }
    }

    fn generate_resource_config(&self, output: &mut String) {
        let res = &self.config.resources;

        if let Some(v) = res.limit_nofile {
            output.push_str(&format!("LimitNOFILE={}\n", v));
        }
        if let Some(v) = res.limit_nproc {
            output.push_str(&format!("LimitNPROC={}\n", v));
        }
        if let Some(v) = &res.limit_memlock {
            output.push_str(&format!("LimitMEMLOCK={}\n", v));
        }
        if let Some(v) = res.limit_core {
            output.push_str(&format!("LimitCORE={}\n", v));
        }
        if let Some(v) = &res.limit_as {
            output.push_str(&format!("LimitAS={}\n", v));
        }
        if let Some(v) = &res.memory_max {
            output.push_str(&format!("MemoryMax={}\n", v));
        }
        if let Some(v) = &res.memory_high {
            output.push_str(&format!("MemoryHigh={}\n", v));
        }
        if let Some(v) = &res.cpu_quota {
            output.push_str(&format!("CPUQuota={}\n", v));
        }
        if let Some(v) = res.tasks_max {
            output.push_str(&format!("TasksMax={}\n", v));
        }
        if let Some(v) = res.io_weight {
            output.push_str(&format!("IOWeight={}\n", v));
        }
        if let Some(v) = res.nice {
            output.push_str(&format!("Nice={}\n", v));
        }
        if let Some(v) = res.oom_score_adjust {
            output.push_str(&format!("OOMScoreAdjust={}\n", v));
        }
    }
}

/// Security presets for common service types
pub struct SecurityPresets;

impl SecurityPresets {
    /// Maximum security for network services
    pub fn network_service() -> SecurityConfig {
        SecurityConfig {
            protect_system: ProtectSystem::Strict,
            protect_home: ProtectHome::Yes,
            private_tmp: true,
            private_devices: true,
            private_network: false,
            private_users: true,
            protect_kernel_tunables: true,
            protect_kernel_modules: true,
            protect_kernel_logs: true,
            protect_control_groups: true,
            protect_clock: true,
            protect_hostname: true,
            no_new_privileges: true,
            capability_bounding_set: vec![Capability::NetBindService],
            ambient_capabilities: vec![],
            private_mounts: true,
            lock_personality: true,
            memory_deny_write_execute: true,
            restrict_address_families: vec![
                "AF_INET".to_string(),
                "AF_INET6".to_string(),
                "AF_UNIX".to_string(),
            ],
            restrict_namespaces: true,
            restrict_realtime: true,
            restrict_suid_sgid: true,
            remove_ipc: true,
            umask: Some("0077".to_string()),
            system_call_filter: vec![
                "@system-service".to_string(),
                "~@privileged".to_string(),
                "~@resources".to_string(),
            ],
            system_call_architectures: vec!["native".to_string()],
            ..Default::default()
        }
    }

    /// Security for web servers
    pub fn web_server() -> SecurityConfig {
        let mut config = Self::network_service();
        config.bind_read_only_paths = vec![PathBuf::from("/var/www")];
        config.capability_bounding_set = vec![
            Capability::NetBindService,
            Capability::Chown,
            Capability::Setgid,
            Capability::Setuid,
        ];
        config
    }

    /// Security for database services
    pub fn database() -> SecurityConfig {
        SecurityConfig {
            protect_system: ProtectSystem::Full,
            protect_home: ProtectHome::Yes,
            private_tmp: true,
            private_devices: true,
            private_network: false,
            private_users: false, // DB needs to manage its own users
            protect_kernel_tunables: true,
            protect_kernel_modules: true,
            protect_kernel_logs: true,
            protect_control_groups: true,
            protect_clock: true,
            no_new_privileges: true,
            capability_bounding_set: vec![
                Capability::NetBindService,
                Capability::Chown,
                Capability::Setgid,
                Capability::Setuid,
                Capability::Fowner,
            ],
            lock_personality: true,
            restrict_realtime: true,
            remove_ipc: false, // DB may use shared memory
            ..Default::default()
        }
    }

    /// Security for worker/batch processes
    pub fn worker() -> SecurityConfig {
        SecurityConfig {
            protect_system: ProtectSystem::Strict,
            protect_home: ProtectHome::Yes,
            private_tmp: true,
            private_devices: true,
            private_network: true,
            private_users: true,
            protect_kernel_tunables: true,
            protect_kernel_modules: true,
            protect_kernel_logs: true,
            protect_control_groups: true,
            protect_clock: true,
            protect_hostname: true,
            no_new_privileges: true,
            capability_bounding_set: vec![],
            private_mounts: true,
            lock_personality: true,
            memory_deny_write_execute: true,
            restrict_namespaces: true,
            restrict_realtime: true,
            restrict_suid_sgid: true,
            remove_ipc: true,
            umask: Some("0077".to_string()),
            ..Default::default()
        }
    }
}

// Helper functions

fn service_type_str(t: ServiceType) -> &'static str {
    match t {
        ServiceType::Simple => "simple",
        ServiceType::Exec => "exec",
        ServiceType::Forking => "forking",
        ServiceType::OneShot => "oneshot",
        ServiceType::Notify => "notify",
        ServiceType::Idle => "idle",
    }
}

fn restart_policy_str(p: RestartPolicy) -> &'static str {
    match p {
        RestartPolicy::No => "no",
        RestartPolicy::OnSuccess => "on-success",
        RestartPolicy::OnFailure => "on-failure",
        RestartPolicy::OnAbnormal => "on-abnormal",
        RestartPolicy::OnWatchdog => "on-watchdog",
        RestartPolicy::OnAbort => "on-abort",
        RestartPolicy::Always => "always",
    }
}

fn protect_system_str(p: ProtectSystem) -> &'static str {
    match p {
        ProtectSystem::No => "no",
        ProtectSystem::Yes => "yes",
        ProtectSystem::Full => "full",
        ProtectSystem::Strict => "strict",
    }
}

fn protect_home_str(p: ProtectHome) -> &'static str {
    match p {
        ProtectHome::No => "no",
        ProtectHome::Yes => "yes",
        ProtectHome::ReadOnly => "read-only",
        ProtectHome::Tmpfs => "tmpfs",
    }
}

fn capability_str(c: Capability) -> String {
    match c {
        Capability::NetBindService => "CAP_NET_BIND_SERVICE",
        Capability::NetAdmin => "CAP_NET_ADMIN",
        Capability::NetRaw => "CAP_NET_RAW",
        Capability::Chown => "CAP_CHOWN",
        Capability::DacOverride => "CAP_DAC_OVERRIDE",
        Capability::Fowner => "CAP_FOWNER",
        Capability::Fsetid => "CAP_FSETID",
        Capability::Kill => "CAP_KILL",
        Capability::Setgid => "CAP_SETGID",
        Capability::Setuid => "CAP_SETUID",
        Capability::SetPcap => "CAP_SETPCAP",
        Capability::SysAdmin => "CAP_SYS_ADMIN",
        Capability::SysPtrace => "CAP_SYS_PTRACE",
        Capability::SysChroot => "CAP_SYS_CHROOT",
        Capability::SysResource => "CAP_SYS_RESOURCE",
        Capability::Audit => "CAP_AUDIT_WRITE",
        Capability::Mknod => "CAP_MKNOD",
        Capability::Lease => "CAP_LEASE",
        Capability::Syslog => "CAP_SYSLOG",
    }
    .to_string()
}

fn main() {
    println!("=== Systemd Service Hardening Demo ===\n");

    // Create a hardened web service
    let web_config = ServiceConfig {
        name: "my-web-app".to_string(),
        description: "My Secure Web Application".to_string(),
        service_type: ServiceType::Notify,
        exec_start: "/usr/local/bin/my-web-app --config /etc/my-web-app/config.toml".to_string(),
        exec_stop: None,
        working_directory: Some(PathBuf::from("/var/lib/my-web-app")),
        user: Some("www-data".to_string()),
        group: Some("www-data".to_string()),
        restart: RestartPolicy::OnFailure,
        restart_sec: 5,
        timeout_start_sec: 30,
        timeout_stop_sec: 30,
        environment: {
            let mut env = HashMap::new();
            env.insert("RUST_LOG".to_string(), "info".to_string());
            env.insert("RUST_BACKTRACE".to_string(), "1".to_string());
            env
        },
        environment_file: Some(PathBuf::from("/etc/my-web-app/environment")),
        security: SecurityPresets::web_server(),
        resources: ResourceConfig {
            limit_nofile: Some(65536),
            memory_max: Some("1G".to_string()),
            tasks_max: Some(100),
            oom_score_adjust: Some(-100),
            ..Default::default()
        },
        dependencies: DependencyConfig {
            after: vec![
                "network.target".to_string(),
                "postgresql.service".to_string(),
            ],
            wants: vec!["network-online.target".to_string()],
            wanted_by: vec!["multi-user.target".to_string()],
            ..Default::default()
        },
    };

    let generator = ServiceGenerator::new(web_config);
    let service_file = generator.generate();

    println!("=== Generated: my-web-app.service ===\n");
    println!("{}", service_file);

    // Create a hardened worker service
    println!("\n=== Generated: background-worker.service ===\n");

    let worker_config = ServiceConfig {
        name: "background-worker".to_string(),
        description: "Background Job Processor".to_string(),
        service_type: ServiceType::Simple,
        exec_start: "/usr/local/bin/worker --queue default".to_string(),
        exec_stop: None,
        working_directory: Some(PathBuf::from("/var/lib/worker")),
        user: Some("worker".to_string()),
        group: Some("worker".to_string()),
        restart: RestartPolicy::Always,
        restart_sec: 10,
        timeout_start_sec: 60,
        timeout_stop_sec: 60,
        environment: HashMap::new(),
        environment_file: None,
        security: SecurityPresets::worker(),
        resources: ResourceConfig {
            limit_nofile: Some(1024),
            memory_max: Some("512M".to_string()),
            cpu_quota: Some("50%".to_string()),
            tasks_max: Some(50),
            nice: Some(10),
            ..Default::default()
        },
        dependencies: DependencyConfig {
            after: vec!["network.target".to_string()],
            wanted_by: vec!["multi-user.target".to_string()],
            ..Default::default()
        },
    };

    let generator = ServiceGenerator::new(worker_config);
    println!("{}", generator.generate());

    // Show security presets
    println!("\n=== Security Presets ===\n");

    println!("Network Service preset:");
    let preset = SecurityPresets::network_service();
    println!("  ProtectSystem: {:?}", preset.protect_system);
    println!("  NoNewPrivileges: {}", preset.no_new_privileges);
    println!("  Capabilities: {:?}", preset.capability_bounding_set);

    println!("\nDatabase preset:");
    let preset = SecurityPresets::database();
    println!("  ProtectSystem: {:?}", preset.protect_system);
    println!("  PrivateUsers: {}", preset.private_users);
    println!("  RemoveIPC: {}", preset.remove_ipc);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config() -> ServiceConfig {
        ServiceConfig {
            name: "test".to_string(),
            description: "Test Service".to_string(),
            service_type: ServiceType::Simple,
            exec_start: "/usr/bin/test".to_string(),
            exec_stop: None,
            working_directory: None,
            user: None,
            group: None,
            restart: RestartPolicy::No,
            restart_sec: 5,
            timeout_start_sec: 90,
            timeout_stop_sec: 90,
            environment: HashMap::new(),
            environment_file: None,
            security: SecurityConfig::default(),
            resources: ResourceConfig::default(),
            dependencies: DependencyConfig::default(),
        }
    }

    #[test]
    fn test_basic_generation() {
        let config = minimal_config();
        let generator = ServiceGenerator::new(config);
        let output = generator.generate();

        assert!(output.contains("[Unit]"));
        assert!(output.contains("[Service]"));
        assert!(output.contains("[Install]"));
        assert!(output.contains("Description=Test Service"));
        assert!(output.contains("ExecStart=/usr/bin/test"));
    }

    #[test]
    fn test_security_config() {
        let mut config = minimal_config();
        config.security = SecurityPresets::network_service();

        let generator = ServiceGenerator::new(config);
        let output = generator.generate();

        assert!(output.contains("ProtectSystem=strict"));
        assert!(output.contains("NoNewPrivileges=yes"));
        assert!(output.contains("PrivateTmp=yes"));
    }

    #[test]
    fn test_resource_limits() {
        let mut config = minimal_config();
        config.resources.limit_nofile = Some(65536);
        config.resources.memory_max = Some("1G".to_string());

        let generator = ServiceGenerator::new(config);
        let output = generator.generate();

        assert!(output.contains("LimitNOFILE=65536"));
        assert!(output.contains("MemoryMax=1G"));
    }

    #[test]
    fn test_dependencies() {
        let mut config = minimal_config();
        config.dependencies.after = vec!["network.target".to_string()];
        config.dependencies.wanted_by = vec!["multi-user.target".to_string()];

        let generator = ServiceGenerator::new(config);
        let output = generator.generate();

        assert!(output.contains("After=network.target"));
        assert!(output.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn test_environment() {
        let mut config = minimal_config();
        config
            .environment
            .insert("FOO".to_string(), "bar".to_string());
        config.environment_file = Some(PathBuf::from("/etc/env"));

        let generator = ServiceGenerator::new(config);
        let output = generator.generate();

        assert!(output.contains("Environment=\"FOO=bar\""));
        assert!(output.contains("EnvironmentFile=/etc/env"));
    }

    #[test]
    fn test_capabilities() {
        let mut config = minimal_config();
        config.security.capability_bounding_set =
            vec![Capability::NetBindService, Capability::Chown];

        let generator = ServiceGenerator::new(config);
        let output = generator.generate();

        assert!(output.contains("CAP_NET_BIND_SERVICE"));
        assert!(output.contains("CAP_CHOWN"));
    }

    #[test]
    fn test_system_call_filter() {
        let mut config = minimal_config();
        config.security.system_call_filter =
            vec!["@system-service".to_string(), "~@privileged".to_string()];

        let generator = ServiceGenerator::new(config);
        let output = generator.generate();

        assert!(output.contains("SystemCallFilter=@system-service ~@privileged"));
    }

    #[test]
    fn test_web_server_preset() {
        let preset = SecurityPresets::web_server();

        assert_eq!(preset.protect_system, ProtectSystem::Strict);
        assert!(preset.no_new_privileges);
        assert!(preset.private_tmp);
        assert!(preset
            .capability_bounding_set
            .contains(&Capability::NetBindService));
    }

    #[test]
    fn test_database_preset() {
        let preset = SecurityPresets::database();

        assert_eq!(preset.protect_system, ProtectSystem::Full);
        assert!(!preset.private_users); // DB needs user management
        assert!(!preset.remove_ipc); // DB may use shared memory
    }

    #[test]
    fn test_worker_preset() {
        let preset = SecurityPresets::worker();

        assert_eq!(preset.protect_system, ProtectSystem::Strict);
        assert!(preset.private_network);
        assert!(preset.capability_bounding_set.is_empty());
    }

    #[test]
    fn test_service_types() {
        for service_type in [
            ServiceType::Simple,
            ServiceType::Exec,
            ServiceType::Notify,
            ServiceType::OneShot,
        ] {
            let mut config = minimal_config();
            config.service_type = service_type;

            let generator = ServiceGenerator::new(config);
            let output = generator.generate();

            assert!(output.contains(&format!("Type={}", service_type_str(service_type))));
        }
    }
}
