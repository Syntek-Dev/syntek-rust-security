//! Systemd Service Hardening Generator
//!
//! Generates security-hardened systemd service files with:
//! - Capability restrictions
//! - Filesystem isolation
//! - Network restrictions
//! - System call filtering
//! - Resource limits

use std::collections::{HashMap, HashSet};

// ============================================================================
// Security Directives
// ============================================================================

/// Linux capability
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Network operations
    NetBindService,
    NetAdmin,
    NetRaw,
    /// File operations
    Chown,
    DacOverride,
    Fowner,
    Fsetid,
    /// Process operations
    Kill,
    Setuid,
    Setgid,
    SetPcap,
    /// System operations
    SysAdmin,
    SysPtrace,
    SysChroot,
    SysResource,
    SysTime,
    SysNice,
    /// Audit
    AuditWrite,
    AuditControl,
    /// Other
    Mknod,
    Lease,
    IpcLock,
    IpcOwner,
}

impl Capability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NetBindService => "CAP_NET_BIND_SERVICE",
            Self::NetAdmin => "CAP_NET_ADMIN",
            Self::NetRaw => "CAP_NET_RAW",
            Self::Chown => "CAP_CHOWN",
            Self::DacOverride => "CAP_DAC_OVERRIDE",
            Self::Fowner => "CAP_FOWNER",
            Self::Fsetid => "CAP_FSETID",
            Self::Kill => "CAP_KILL",
            Self::Setuid => "CAP_SETUID",
            Self::Setgid => "CAP_SETGID",
            Self::SetPcap => "CAP_SETPCAP",
            Self::SysAdmin => "CAP_SYS_ADMIN",
            Self::SysPtrace => "CAP_SYS_PTRACE",
            Self::SysChroot => "CAP_SYS_CHROOT",
            Self::SysResource => "CAP_SYS_RESOURCE",
            Self::SysTime => "CAP_SYS_TIME",
            Self::SysNice => "CAP_SYS_NICE",
            Self::AuditWrite => "CAP_AUDIT_WRITE",
            Self::AuditControl => "CAP_AUDIT_CONTROL",
            Self::Mknod => "CAP_MKNOD",
            Self::Lease => "CAP_LEASE",
            Self::IpcLock => "CAP_IPC_LOCK",
            Self::IpcOwner => "CAP_IPC_OWNER",
        }
    }
}

/// System call filter group
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyscallGroup {
    /// Default set for system services
    SystemService,
    /// Basic I/O operations
    BasicIo,
    /// Network operations
    Network,
    /// File operations
    FileSystem,
    /// Process operations
    Process,
    /// Timer operations
    Timer,
    /// Signal operations
    Signal,
    /// Memory operations
    Memory,
    /// IPC operations
    Ipc,
    /// Privileged operations
    Privileged,
    /// Obsolete syscalls
    Obsolete,
    /// Raw I/O
    RawIo,
    /// Reboot operations
    Reboot,
    /// Swap operations
    Swap,
    /// Module operations
    Module,
    /// Debug operations
    Debug,
    /// CPU emulation
    CpuEmulation,
}

impl SyscallGroup {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SystemService => "@system-service",
            Self::BasicIo => "@basic-io",
            Self::Network => "@network-io",
            Self::FileSystem => "@file-system",
            Self::Process => "@process",
            Self::Timer => "@timer",
            Self::Signal => "@signal",
            Self::Memory => "@memory-allocate",
            Self::Ipc => "@ipc",
            Self::Privileged => "@privileged",
            Self::Obsolete => "@obsolete",
            Self::RawIo => "@raw-io",
            Self::Reboot => "@reboot",
            Self::Swap => "@swap",
            Self::Module => "@module",
            Self::Debug => "@debug",
            Self::CpuEmulation => "@cpu-emulation",
        }
    }
}

/// Address family restrictions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    Inet,    // IPv4
    Inet6,   // IPv6
    Unix,    // Unix sockets
    Netlink, // Kernel netlink
    Packet,  // Raw packets
}

impl AddressFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Inet => "AF_INET",
            Self::Inet6 => "AF_INET6",
            Self::Unix => "AF_UNIX",
            Self::Netlink => "AF_NETLINK",
            Self::Packet => "AF_PACKET",
        }
    }
}

/// Protect system paths setting
#[derive(Debug, Clone, Copy)]
pub enum ProtectSystem {
    No,
    Yes,
    Full,
    Strict,
}

impl ProtectSystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::No => "no",
            Self::Yes => "yes",
            Self::Full => "full",
            Self::Strict => "strict",
        }
    }
}

/// Protect home setting
#[derive(Debug, Clone, Copy)]
pub enum ProtectHome {
    No,
    Yes,
    ReadOnly,
    Tmpfs,
}

impl ProtectHome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::No => "no",
            Self::Yes => "yes",
            Self::ReadOnly => "read-only",
            Self::Tmpfs => "tmpfs",
        }
    }
}

// ============================================================================
// Service Configuration
// ============================================================================

/// Service type
#[derive(Debug, Clone, Copy)]
pub enum ServiceType {
    Simple,
    Forking,
    Oneshot,
    Notify,
    Dbus,
    Idle,
}

impl ServiceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Simple => "simple",
            Self::Forking => "forking",
            Self::Oneshot => "oneshot",
            Self::Notify => "notify",
            Self::Dbus => "dbus",
            Self::Idle => "idle",
        }
    }
}

/// Restart policy
#[derive(Debug, Clone, Copy)]
pub enum RestartPolicy {
    No,
    Always,
    OnSuccess,
    OnFailure,
    OnAbnormal,
    OnAbort,
    OnWatchdog,
}

impl RestartPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::No => "no",
            Self::Always => "always",
            Self::OnSuccess => "on-success",
            Self::OnFailure => "on-failure",
            Self::OnAbnormal => "on-abnormal",
            Self::OnAbort => "on-abort",
            Self::OnWatchdog => "on-watchdog",
        }
    }
}

/// Resource limits
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub nofile: Option<u64>,
    pub nproc: Option<u64>,
    pub memlock: Option<String>,
    pub as_limit: Option<String>,
    pub fsize: Option<String>,
    pub cpu: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            nofile: Some(65536),
            nproc: Some(4096),
            memlock: None,
            as_limit: None,
            fsize: None,
            cpu: None,
        }
    }
}

/// Security hardening profile
#[derive(Debug, Clone)]
pub struct SecurityProfile {
    /// Drop all capabilities
    pub no_new_privileges: bool,
    /// Capability bounding set
    pub capability_bounding_set: HashSet<Capability>,
    /// Ambient capabilities
    pub ambient_capabilities: HashSet<Capability>,
    /// System call filter
    pub syscall_filter: Vec<SyscallGroup>,
    /// Syscall architecture
    pub syscall_architectures: Option<String>,
    /// Address families
    pub address_families: HashSet<AddressFamily>,
    /// Protect system
    pub protect_system: ProtectSystem,
    /// Protect home
    pub protect_home: ProtectHome,
    /// Private tmp
    pub private_tmp: bool,
    /// Private devices
    pub private_devices: bool,
    /// Private network
    pub private_network: bool,
    /// Private users
    pub private_users: bool,
    /// Protect kernel tunables
    pub protect_kernel_tunables: bool,
    /// Protect kernel modules
    pub protect_kernel_modules: bool,
    /// Protect kernel logs
    pub protect_kernel_logs: bool,
    /// Protect control groups
    pub protect_control_groups: bool,
    /// Protect clock
    pub protect_clock: bool,
    /// Protect hostname
    pub protect_hostname: bool,
    /// Lock personality
    pub lock_personality: bool,
    /// Restrict SUID/SGID
    pub restrict_suid_sgid: bool,
    /// Restrict namespaces
    pub restrict_namespaces: bool,
    /// Restrict realtime
    pub restrict_realtime: bool,
    /// Memory deny write execute
    pub memory_deny_write_execute: bool,
    /// Remove IPC
    pub remove_ipc: bool,
    /// Umask
    pub umask: Option<u32>,
}

impl SecurityProfile {
    /// Create a minimal security profile (least restrictive)
    pub fn minimal() -> Self {
        Self {
            no_new_privileges: true,
            capability_bounding_set: HashSet::new(),
            ambient_capabilities: HashSet::new(),
            syscall_filter: vec![],
            syscall_architectures: None,
            address_families: HashSet::new(),
            protect_system: ProtectSystem::No,
            protect_home: ProtectHome::No,
            private_tmp: false,
            private_devices: false,
            private_network: false,
            private_users: false,
            protect_kernel_tunables: false,
            protect_kernel_modules: false,
            protect_kernel_logs: false,
            protect_control_groups: false,
            protect_clock: false,
            protect_hostname: false,
            lock_personality: false,
            restrict_suid_sgid: false,
            restrict_namespaces: false,
            restrict_realtime: false,
            memory_deny_write_execute: false,
            remove_ipc: false,
            umask: None,
        }
    }

    /// Create a standard security profile
    pub fn standard() -> Self {
        let mut families = HashSet::new();
        families.insert(AddressFamily::Inet);
        families.insert(AddressFamily::Inet6);
        families.insert(AddressFamily::Unix);

        Self {
            no_new_privileges: true,
            capability_bounding_set: HashSet::new(),
            ambient_capabilities: HashSet::new(),
            syscall_filter: vec![SyscallGroup::SystemService],
            syscall_architectures: Some("native".to_string()),
            address_families: families,
            protect_system: ProtectSystem::Strict,
            protect_home: ProtectHome::Yes,
            private_tmp: true,
            private_devices: true,
            private_network: false,
            private_users: false,
            protect_kernel_tunables: true,
            protect_kernel_modules: true,
            protect_kernel_logs: true,
            protect_control_groups: true,
            protect_clock: true,
            protect_hostname: true,
            lock_personality: true,
            restrict_suid_sgid: true,
            restrict_namespaces: true,
            restrict_realtime: true,
            memory_deny_write_execute: true,
            remove_ipc: true,
            umask: Some(0o027),
        }
    }

    /// Create a strict security profile (most restrictive)
    pub fn strict() -> Self {
        let mut profile = Self::standard();
        profile.private_network = false; // Most services need network
        profile.private_users = true;
        profile
    }

    /// Create profile for a web server
    pub fn web_server() -> Self {
        let mut profile = Self::standard();
        profile
            .capability_bounding_set
            .insert(Capability::NetBindService);
        profile
            .ambient_capabilities
            .insert(Capability::NetBindService);
        profile
    }

    /// Create profile for a database
    pub fn database() -> Self {
        let mut profile = Self::standard();
        profile.memory_deny_write_execute = false; // Databases may need JIT
        profile.protect_home = ProtectHome::Yes;
        profile
    }
}

/// Complete systemd service configuration
#[derive(Debug, Clone)]
pub struct SystemdService {
    pub name: String,
    pub description: String,
    pub after: Vec<String>,
    pub wants: Vec<String>,
    pub requires: Vec<String>,
    pub service_type: ServiceType,
    pub user: Option<String>,
    pub group: Option<String>,
    pub working_directory: Option<String>,
    pub exec_start: String,
    pub exec_stop: Option<String>,
    pub exec_reload: Option<String>,
    pub pid_file: Option<String>,
    pub restart: RestartPolicy,
    pub restart_sec: u32,
    pub timeout_start_sec: u32,
    pub timeout_stop_sec: u32,
    pub watchdog_sec: Option<u32>,
    pub environment: HashMap<String, String>,
    pub environment_file: Option<String>,
    pub security: SecurityProfile,
    pub limits: ResourceLimits,
    pub read_write_paths: Vec<String>,
    pub read_only_paths: Vec<String>,
    pub inaccessible_paths: Vec<String>,
    pub runtime_directory: Option<String>,
    pub state_directory: Option<String>,
    pub cache_directory: Option<String>,
    pub logs_directory: Option<String>,
    pub wanted_by: Vec<String>,
}

impl SystemdService {
    pub fn new(name: &str, exec_start: &str) -> Self {
        Self {
            name: name.to_string(),
            description: format!("{} Service", name),
            after: vec!["network.target".to_string()],
            wants: vec![],
            requires: vec![],
            service_type: ServiceType::Simple,
            user: None,
            group: None,
            working_directory: None,
            exec_start: exec_start.to_string(),
            exec_stop: None,
            exec_reload: None,
            pid_file: None,
            restart: RestartPolicy::OnFailure,
            restart_sec: 5,
            timeout_start_sec: 90,
            timeout_stop_sec: 90,
            watchdog_sec: None,
            environment: HashMap::new(),
            environment_file: None,
            security: SecurityProfile::standard(),
            limits: ResourceLimits::default(),
            read_write_paths: vec![],
            read_only_paths: vec![],
            inaccessible_paths: vec![],
            runtime_directory: None,
            state_directory: None,
            cache_directory: None,
            logs_directory: None,
            wanted_by: vec!["multi-user.target".to_string()],
        }
    }

    pub fn with_user(mut self, user: &str) -> Self {
        self.user = Some(user.to_string());
        self
    }

    pub fn with_group(mut self, group: &str) -> Self {
        self.group = Some(group.to_string());
        self
    }

    pub fn with_security(mut self, security: SecurityProfile) -> Self {
        self.security = security;
        self
    }

    pub fn with_working_directory(mut self, dir: &str) -> Self {
        self.working_directory = Some(dir.to_string());
        self
    }

    /// Generate the systemd unit file
    pub fn to_unit_file(&self) -> String {
        let mut unit = String::new();

        // [Unit] section
        unit.push_str("[Unit]\n");
        unit.push_str(&format!("Description={}\n", self.description));

        if !self.after.is_empty() {
            unit.push_str(&format!("After={}\n", self.after.join(" ")));
        }
        if !self.wants.is_empty() {
            unit.push_str(&format!("Wants={}\n", self.wants.join(" ")));
        }
        if !self.requires.is_empty() {
            unit.push_str(&format!("Requires={}\n", self.requires.join(" ")));
        }

        // [Service] section
        unit.push_str("\n[Service]\n");
        unit.push_str(&format!("Type={}\n", self.service_type.as_str()));

        if let Some(ref user) = self.user {
            unit.push_str(&format!("User={}\n", user));
        }
        if let Some(ref group) = self.group {
            unit.push_str(&format!("Group={}\n", group));
        }
        if let Some(ref dir) = self.working_directory {
            unit.push_str(&format!("WorkingDirectory={}\n", dir));
        }

        unit.push_str(&format!("ExecStart={}\n", self.exec_start));

        if let Some(ref stop) = self.exec_stop {
            unit.push_str(&format!("ExecStop={}\n", stop));
        }
        if let Some(ref reload) = self.exec_reload {
            unit.push_str(&format!("ExecReload={}\n", reload));
        }
        if let Some(ref pid) = self.pid_file {
            unit.push_str(&format!("PIDFile={}\n", pid));
        }

        unit.push_str(&format!("Restart={}\n", self.restart.as_str()));
        unit.push_str(&format!("RestartSec={}s\n", self.restart_sec));
        unit.push_str(&format!("TimeoutStartSec={}s\n", self.timeout_start_sec));
        unit.push_str(&format!("TimeoutStopSec={}s\n", self.timeout_stop_sec));

        if let Some(watchdog) = self.watchdog_sec {
            unit.push_str(&format!("WatchdogSec={}s\n", watchdog));
        }

        // Environment
        for (key, value) in &self.environment {
            unit.push_str(&format!("Environment=\"{}={}\"\n", key, value));
        }
        if let Some(ref env_file) = self.environment_file {
            unit.push_str(&format!("EnvironmentFile={}\n", env_file));
        }

        // Directories
        if let Some(ref dir) = self.runtime_directory {
            unit.push_str(&format!("RuntimeDirectory={}\n", dir));
        }
        if let Some(ref dir) = self.state_directory {
            unit.push_str(&format!("StateDirectory={}\n", dir));
        }
        if let Some(ref dir) = self.cache_directory {
            unit.push_str(&format!("CacheDirectory={}\n", dir));
        }
        if let Some(ref dir) = self.logs_directory {
            unit.push_str(&format!("LogsDirectory={}\n", dir));
        }

        // Security hardening
        unit.push_str("\n# Security Hardening\n");

        if self.security.no_new_privileges {
            unit.push_str("NoNewPrivileges=yes\n");
        }

        if !self.security.capability_bounding_set.is_empty() {
            let caps: Vec<&str> = self
                .security
                .capability_bounding_set
                .iter()
                .map(|c| c.as_str())
                .collect();
            unit.push_str(&format!("CapabilityBoundingSet={}\n", caps.join(" ")));
        } else {
            unit.push_str("CapabilityBoundingSet=\n");
        }

        if !self.security.ambient_capabilities.is_empty() {
            let caps: Vec<&str> = self
                .security
                .ambient_capabilities
                .iter()
                .map(|c| c.as_str())
                .collect();
            unit.push_str(&format!("AmbientCapabilities={}\n", caps.join(" ")));
        }

        unit.push_str(&format!(
            "ProtectSystem={}\n",
            self.security.protect_system.as_str()
        ));
        unit.push_str(&format!(
            "ProtectHome={}\n",
            self.security.protect_home.as_str()
        ));

        if self.security.private_tmp {
            unit.push_str("PrivateTmp=yes\n");
        }
        if self.security.private_devices {
            unit.push_str("PrivateDevices=yes\n");
        }
        if self.security.private_network {
            unit.push_str("PrivateNetwork=yes\n");
        }
        if self.security.private_users {
            unit.push_str("PrivateUsers=yes\n");
        }
        if self.security.protect_kernel_tunables {
            unit.push_str("ProtectKernelTunables=yes\n");
        }
        if self.security.protect_kernel_modules {
            unit.push_str("ProtectKernelModules=yes\n");
        }
        if self.security.protect_kernel_logs {
            unit.push_str("ProtectKernelLogs=yes\n");
        }
        if self.security.protect_control_groups {
            unit.push_str("ProtectControlGroups=yes\n");
        }
        if self.security.protect_clock {
            unit.push_str("ProtectClock=yes\n");
        }
        if self.security.protect_hostname {
            unit.push_str("ProtectHostname=yes\n");
        }
        if self.security.lock_personality {
            unit.push_str("LockPersonality=yes\n");
        }
        if self.security.restrict_suid_sgid {
            unit.push_str("RestrictSUIDSGID=yes\n");
        }
        if self.security.restrict_namespaces {
            unit.push_str("RestrictNamespaces=yes\n");
        }
        if self.security.restrict_realtime {
            unit.push_str("RestrictRealtime=yes\n");
        }
        if self.security.memory_deny_write_execute {
            unit.push_str("MemoryDenyWriteExecute=yes\n");
        }
        if self.security.remove_ipc {
            unit.push_str("RemoveIPC=yes\n");
        }

        if let Some(umask) = self.security.umask {
            unit.push_str(&format!("UMask={:04o}\n", umask));
        }

        // Address families
        if !self.security.address_families.is_empty() {
            let families: Vec<&str> = self
                .security
                .address_families
                .iter()
                .map(|f| f.as_str())
                .collect();
            unit.push_str(&format!("RestrictAddressFamilies={}\n", families.join(" ")));
        }

        // System call filter
        if !self.security.syscall_filter.is_empty() {
            let groups: Vec<&str> = self
                .security
                .syscall_filter
                .iter()
                .map(|g| g.as_str())
                .collect();
            unit.push_str(&format!("SystemCallFilter={}\n", groups.join(" ")));
        }

        if let Some(ref arch) = self.security.syscall_architectures {
            unit.push_str(&format!("SystemCallArchitectures={}\n", arch));
        }

        // Path restrictions
        if !self.read_write_paths.is_empty() {
            unit.push_str(&format!(
                "ReadWritePaths={}\n",
                self.read_write_paths.join(" ")
            ));
        }
        if !self.read_only_paths.is_empty() {
            unit.push_str(&format!(
                "ReadOnlyPaths={}\n",
                self.read_only_paths.join(" ")
            ));
        }
        if !self.inaccessible_paths.is_empty() {
            unit.push_str(&format!(
                "InaccessiblePaths={}\n",
                self.inaccessible_paths.join(" ")
            ));
        }

        // Resource limits
        unit.push_str("\n# Resource Limits\n");
        if let Some(nofile) = self.limits.nofile {
            unit.push_str(&format!("LimitNOFILE={}\n", nofile));
        }
        if let Some(nproc) = self.limits.nproc {
            unit.push_str(&format!("LimitNPROC={}\n", nproc));
        }
        if let Some(ref memlock) = self.limits.memlock {
            unit.push_str(&format!("LimitMEMLOCK={}\n", memlock));
        }

        // [Install] section
        unit.push_str("\n[Install]\n");
        if !self.wanted_by.is_empty() {
            unit.push_str(&format!("WantedBy={}\n", self.wanted_by.join(" ")));
        }

        unit
    }
}

// ============================================================================
// Preset Services
// ============================================================================

/// Generate preset service configurations
pub struct ServicePresets;

impl ServicePresets {
    /// Web server (nginx, apache)
    pub fn web_server(name: &str, exec: &str) -> SystemdService {
        SystemdService::new(name, exec)
            .with_user("www-data")
            .with_group("www-data")
            .with_security(SecurityProfile::web_server())
    }

    /// Application server (gunicorn, uvicorn)
    pub fn app_server(name: &str, exec: &str, working_dir: &str) -> SystemdService {
        let mut service = SystemdService::new(name, exec)
            .with_user("www-data")
            .with_group("www-data")
            .with_working_directory(working_dir)
            .with_security(SecurityProfile::standard());

        service.service_type = ServiceType::Notify;
        service.runtime_directory = Some(name.to_string());
        service
    }

    /// Database (postgresql, mysql)
    pub fn database(name: &str, exec: &str, data_dir: &str) -> SystemdService {
        let mut service = SystemdService::new(name, exec)
            .with_user(name)
            .with_group(name)
            .with_security(SecurityProfile::database());

        service.service_type = ServiceType::Notify;
        service.state_directory = Some(name.to_string());
        service.read_write_paths.push(data_dir.to_string());
        service
    }

    /// Background worker
    pub fn worker(name: &str, exec: &str, user: &str) -> SystemdService {
        let mut service = SystemdService::new(name, exec)
            .with_user(user)
            .with_security(SecurityProfile::strict());

        service.restart = RestartPolicy::Always;
        service.restart_sec = 10;
        service
    }

    /// Cron-like scheduled task
    pub fn scheduled_task(name: &str, exec: &str) -> SystemdService {
        let mut service = SystemdService::new(name, exec).with_security(SecurityProfile::strict());

        service.service_type = ServiceType::Oneshot;
        service.restart = RestartPolicy::No;
        service
    }
}

// ============================================================================
// Main and Tests
// ============================================================================

fn main() {
    println!("Systemd Service Hardening Generator\n");

    // Web Server
    println!("=== Web Server Service ===\n");
    let nginx = ServicePresets::web_server("nginx", "/usr/sbin/nginx -g 'daemon off;'");
    println!("{}", nginx.to_unit_file());

    // Application Server
    println!("\n=== Application Server Service ===\n");
    let mut gunicorn = ServicePresets::app_server(
        "myapp",
        "/usr/bin/gunicorn --config /etc/gunicorn/myapp.py myapp.wsgi:application",
        "/var/www/myapp",
    );
    gunicorn.environment.insert(
        "DJANGO_SETTINGS_MODULE".to_string(),
        "myapp.settings".to_string(),
    );
    gunicorn.read_write_paths.push("/var/log/myapp".to_string());
    println!("{}", gunicorn.to_unit_file());

    // Database
    println!("\n=== Database Service ===\n");
    let postgres = ServicePresets::database(
        "postgresql",
        "/usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main",
        "/var/lib/postgresql",
    );
    println!("{}", postgres.to_unit_file());

    // Background Worker
    println!("\n=== Background Worker Service ===\n");
    let worker = ServicePresets::worker(
        "celery-worker",
        "/usr/bin/celery -A myapp worker --loglevel=info",
        "celery",
    );
    println!("{}", worker.to_unit_file());

    // Security Profiles
    println!("\n=== Available Security Profiles ===\n");
    for (name, profile) in [
        ("minimal", SecurityProfile::minimal()),
        ("standard", SecurityProfile::standard()),
        ("strict", SecurityProfile::strict()),
        ("web_server", SecurityProfile::web_server()),
        ("database", SecurityProfile::database()),
    ] {
        println!(
            "{}: NoNewPrivileges={}, ProtectSystem={:?}, PrivateTmp={}",
            name,
            profile.no_new_privileges,
            profile.protect_system.as_str(),
            profile.private_tmp,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_str() {
        assert_eq!(Capability::NetBindService.as_str(), "CAP_NET_BIND_SERVICE");
        assert_eq!(Capability::SysAdmin.as_str(), "CAP_SYS_ADMIN");
    }

    #[test]
    fn test_syscall_group_str() {
        assert_eq!(SyscallGroup::SystemService.as_str(), "@system-service");
        assert_eq!(SyscallGroup::Network.as_str(), "@network-io");
    }

    #[test]
    fn test_service_creation() {
        let service = SystemdService::new("test", "/usr/bin/test");
        assert_eq!(service.name, "test");
        assert_eq!(service.exec_start, "/usr/bin/test");
    }

    #[test]
    fn test_service_builder() {
        let service = SystemdService::new("test", "/usr/bin/test")
            .with_user("testuser")
            .with_group("testgroup");

        assert_eq!(service.user, Some("testuser".to_string()));
        assert_eq!(service.group, Some("testgroup".to_string()));
    }

    #[test]
    fn test_unit_file_generation() {
        let service = SystemdService::new("test", "/usr/bin/test").with_user("testuser");

        let unit = service.to_unit_file();
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("[Install]"));
        assert!(unit.contains("User=testuser"));
        assert!(unit.contains("ExecStart=/usr/bin/test"));
    }

    #[test]
    fn test_security_profile_standard() {
        let profile = SecurityProfile::standard();
        assert!(profile.no_new_privileges);
        assert!(profile.private_tmp);
        assert!(profile.protect_kernel_tunables);
    }

    #[test]
    fn test_security_profile_web_server() {
        let profile = SecurityProfile::web_server();
        assert!(profile
            .capability_bounding_set
            .contains(&Capability::NetBindService));
        assert!(profile
            .ambient_capabilities
            .contains(&Capability::NetBindService));
    }

    #[test]
    fn test_preset_web_server() {
        let service = ServicePresets::web_server("nginx", "/usr/sbin/nginx");
        assert_eq!(service.user, Some("www-data".to_string()));
    }

    #[test]
    fn test_preset_database() {
        let service =
            ServicePresets::database("postgres", "/usr/bin/postgres", "/var/lib/postgres");
        assert!(!service.security.memory_deny_write_execute);
    }

    #[test]
    fn test_resource_limits() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.nofile, Some(65536));
        assert_eq!(limits.nproc, Some(4096));
    }

    #[test]
    fn test_protect_system_str() {
        assert_eq!(ProtectSystem::Strict.as_str(), "strict");
        assert_eq!(ProtectSystem::Full.as_str(), "full");
    }
}
