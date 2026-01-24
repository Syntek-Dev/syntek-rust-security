//! Systemd Service Hardening Configuration Generator
//!
//! Generates security-hardened systemd service unit files with sandboxing,
//! capability restrictions, and resource controls.

use std::collections::{HashMap, HashSet};
use std::fmt::Write;

/// Linux capability
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    ChOwn,
    DacOverride,
    DacReadSearch,
    FOwner,
    Fsetid,
    Kill,
    Setgid,
    Setuid,
    Setpcap,
    LinuxImmutable,
    NetBindService,
    NetBroadcast,
    NetAdmin,
    NetRaw,
    IpcLock,
    IpcOwner,
    SysModule,
    SysRawio,
    SysChroot,
    SysPtrace,
    SysPacct,
    SysAdmin,
    SysBoot,
    SysNice,
    SysResource,
    SysTime,
    SysTtyConfig,
    Mknod,
    Lease,
    AuditWrite,
    AuditControl,
    Setfcap,
    MacOverride,
    MacAdmin,
    Syslog,
    WakeAlarm,
    BlockSuspend,
    AuditRead,
    Perfmon,
    Bpf,
    CheckpointRestore,
}

impl Capability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::ChOwn => "CAP_CHOWN",
            Capability::DacOverride => "CAP_DAC_OVERRIDE",
            Capability::DacReadSearch => "CAP_DAC_READ_SEARCH",
            Capability::FOwner => "CAP_FOWNER",
            Capability::Fsetid => "CAP_FSETID",
            Capability::Kill => "CAP_KILL",
            Capability::Setgid => "CAP_SETGID",
            Capability::Setuid => "CAP_SETUID",
            Capability::Setpcap => "CAP_SETPCAP",
            Capability::LinuxImmutable => "CAP_LINUX_IMMUTABLE",
            Capability::NetBindService => "CAP_NET_BIND_SERVICE",
            Capability::NetBroadcast => "CAP_NET_BROADCAST",
            Capability::NetAdmin => "CAP_NET_ADMIN",
            Capability::NetRaw => "CAP_NET_RAW",
            Capability::IpcLock => "CAP_IPC_LOCK",
            Capability::IpcOwner => "CAP_IPC_OWNER",
            Capability::SysModule => "CAP_SYS_MODULE",
            Capability::SysRawio => "CAP_SYS_RAWIO",
            Capability::SysChroot => "CAP_SYS_CHROOT",
            Capability::SysPtrace => "CAP_SYS_PTRACE",
            Capability::SysPacct => "CAP_SYS_PACCT",
            Capability::SysAdmin => "CAP_SYS_ADMIN",
            Capability::SysBoot => "CAP_SYS_BOOT",
            Capability::SysNice => "CAP_SYS_NICE",
            Capability::SysResource => "CAP_SYS_RESOURCE",
            Capability::SysTime => "CAP_SYS_TIME",
            Capability::SysTtyConfig => "CAP_SYS_TTY_CONFIG",
            Capability::Mknod => "CAP_MKNOD",
            Capability::Lease => "CAP_LEASE",
            Capability::AuditWrite => "CAP_AUDIT_WRITE",
            Capability::AuditControl => "CAP_AUDIT_CONTROL",
            Capability::Setfcap => "CAP_SETFCAP",
            Capability::MacOverride => "CAP_MAC_OVERRIDE",
            Capability::MacAdmin => "CAP_MAC_ADMIN",
            Capability::Syslog => "CAP_SYSLOG",
            Capability::WakeAlarm => "CAP_WAKE_ALARM",
            Capability::BlockSuspend => "CAP_BLOCK_SUSPEND",
            Capability::AuditRead => "CAP_AUDIT_READ",
            Capability::Perfmon => "CAP_PERFMON",
            Capability::Bpf => "CAP_BPF",
            Capability::CheckpointRestore => "CAP_CHECKPOINT_RESTORE",
        }
    }
}

/// Protect system options
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
            ProtectSystem::No => "no",
            ProtectSystem::Yes => "yes",
            ProtectSystem::Full => "full",
            ProtectSystem::Strict => "strict",
        }
    }
}

/// Protect home options
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
            ProtectHome::No => "no",
            ProtectHome::Yes => "yes",
            ProtectHome::ReadOnly => "read-only",
            ProtectHome::Tmpfs => "tmpfs",
        }
    }
}

/// Service type
#[derive(Debug, Clone, Copy)]
pub enum ServiceType {
    Simple,
    Exec,
    Forking,
    Oneshot,
    Notify,
    Idle,
}

impl ServiceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceType::Simple => "simple",
            ServiceType::Exec => "exec",
            ServiceType::Forking => "forking",
            ServiceType::Oneshot => "oneshot",
            ServiceType::Notify => "notify",
            ServiceType::Idle => "idle",
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
            RestartPolicy::No => "no",
            RestartPolicy::Always => "always",
            RestartPolicy::OnSuccess => "on-success",
            RestartPolicy::OnFailure => "on-failure",
            RestartPolicy::OnAbnormal => "on-abnormal",
            RestartPolicy::OnAbort => "on-abort",
            RestartPolicy::OnWatchdog => "on-watchdog",
        }
    }
}

/// Namespace isolation type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrivateNamespace {
    Network,
    Users,
    Ipc,
    Uts,
    Mounts,
    Pid,
    Cgroup,
}

/// System call filter action
#[derive(Debug, Clone, Copy)]
pub enum SystemCallFilterAction {
    Allow,
    Deny,
    Log,
    Kill,
}

/// Resource limit
#[derive(Debug, Clone)]
pub struct ResourceLimit {
    pub soft: Option<String>,
    pub hard: Option<String>,
}

impl ResourceLimit {
    pub fn new(soft: impl Into<String>, hard: impl Into<String>) -> Self {
        Self {
            soft: Some(soft.into()),
            hard: Some(hard.into()),
        }
    }

    pub fn unlimited() -> Self {
        Self {
            soft: Some("infinity".to_string()),
            hard: Some("infinity".to_string()),
        }
    }

    pub fn both(value: impl Into<String>) -> Self {
        let v = value.into();
        Self {
            soft: Some(v.clone()),
            hard: Some(v),
        }
    }
}

/// Unit section configuration
#[derive(Debug, Clone, Default)]
pub struct UnitSection {
    pub description: Option<String>,
    pub documentation: Vec<String>,
    pub wants: Vec<String>,
    pub requires: Vec<String>,
    pub after: Vec<String>,
    pub before: Vec<String>,
    pub conflicts: Vec<String>,
    pub condition_path_exists: Vec<String>,
    pub condition_path_is_directory: Vec<String>,
}

impl UnitSection {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn documentation(mut self, doc: impl Into<String>) -> Self {
        self.documentation.push(doc.into());
        self
    }

    pub fn wants(mut self, unit: impl Into<String>) -> Self {
        self.wants.push(unit.into());
        self
    }

    pub fn requires(mut self, unit: impl Into<String>) -> Self {
        self.requires.push(unit.into());
        self
    }

    pub fn after(mut self, unit: impl Into<String>) -> Self {
        self.after.push(unit.into());
        self
    }

    pub fn before(mut self, unit: impl Into<String>) -> Self {
        self.before.push(unit.into());
        self
    }

    pub fn conflicts(mut self, unit: impl Into<String>) -> Self {
        self.conflicts.push(unit.into());
        self
    }

    pub fn condition_path_exists(mut self, path: impl Into<String>) -> Self {
        self.condition_path_exists.push(path.into());
        self
    }

    pub fn generate(&self) -> Vec<String> {
        let mut lines = Vec::new();

        if let Some(ref desc) = self.description {
            lines.push(format!("Description={}", desc));
        }

        for doc in &self.documentation {
            lines.push(format!("Documentation={}", doc));
        }

        for unit in &self.wants {
            lines.push(format!("Wants={}", unit));
        }

        for unit in &self.requires {
            lines.push(format!("Requires={}", unit));
        }

        for unit in &self.after {
            lines.push(format!("After={}", unit));
        }

        for unit in &self.before {
            lines.push(format!("Before={}", unit));
        }

        for unit in &self.conflicts {
            lines.push(format!("Conflicts={}", unit));
        }

        for path in &self.condition_path_exists {
            lines.push(format!("ConditionPathExists={}", path));
        }

        for path in &self.condition_path_is_directory {
            lines.push(format!("ConditionPathIsDirectory={}", path));
        }

        lines
    }
}

/// Install section configuration
#[derive(Debug, Clone, Default)]
pub struct InstallSection {
    pub wanted_by: Vec<String>,
    pub required_by: Vec<String>,
    pub also: Vec<String>,
    pub alias: Vec<String>,
}

impl InstallSection {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn wanted_by(mut self, target: impl Into<String>) -> Self {
        self.wanted_by.push(target.into());
        self
    }

    pub fn required_by(mut self, target: impl Into<String>) -> Self {
        self.required_by.push(target.into());
        self
    }

    pub fn also(mut self, unit: impl Into<String>) -> Self {
        self.also.push(unit.into());
        self
    }

    pub fn alias(mut self, name: impl Into<String>) -> Self {
        self.alias.push(name.into());
        self
    }

    pub fn generate(&self) -> Vec<String> {
        let mut lines = Vec::new();

        for target in &self.wanted_by {
            lines.push(format!("WantedBy={}", target));
        }

        for target in &self.required_by {
            lines.push(format!("RequiredBy={}", target));
        }

        for unit in &self.also {
            lines.push(format!("Also={}", unit));
        }

        for name in &self.alias {
            lines.push(format!("Alias={}", name));
        }

        lines
    }
}

/// Security hardening configuration
#[derive(Debug, Clone)]
pub struct SecurityHardening {
    // Sandboxing
    pub protect_system: ProtectSystem,
    pub protect_home: ProtectHome,
    pub private_tmp: bool,
    pub private_devices: bool,
    pub private_network: bool,
    pub private_users: bool,
    pub private_ipc: bool,
    pub protect_hostname: bool,
    pub protect_clock: bool,
    pub protect_kernel_tunables: bool,
    pub protect_kernel_modules: bool,
    pub protect_kernel_logs: bool,
    pub protect_control_groups: bool,
    pub protect_proc: Option<String>,
    pub proc_subset: Option<String>,

    // Capabilities
    pub capability_bounding_set: Option<HashSet<Capability>>,
    pub ambient_capabilities: HashSet<Capability>,
    pub no_new_privileges: bool,

    // System calls
    pub system_call_filter: Vec<String>,
    pub system_call_filter_action: SystemCallFilterAction,
    pub system_call_architectures: Vec<String>,
    pub system_call_error_number: Option<String>,

    // Filesystem
    pub read_only_paths: Vec<String>,
    pub read_write_paths: Vec<String>,
    pub inaccessible_paths: Vec<String>,
    pub temporary_filesystem: Vec<(String, String)>,
    pub bind_paths: Vec<(String, String)>,
    pub bind_read_only_paths: Vec<(String, String)>,

    // Misc security
    pub restrict_address_families: Vec<String>,
    pub restrict_namespaces: Option<bool>,
    pub restrict_realtime: bool,
    pub restrict_suid_sgid: bool,
    pub lock_personality: bool,
    pub memory_deny_write_execute: bool,
    pub remove_ipc: bool,
    pub umask: Option<String>,
    pub keyring_mode: Option<String>,
}

impl Default for SecurityHardening {
    fn default() -> Self {
        Self {
            protect_system: ProtectSystem::No,
            protect_home: ProtectHome::No,
            private_tmp: false,
            private_devices: false,
            private_network: false,
            private_users: false,
            private_ipc: false,
            protect_hostname: false,
            protect_clock: false,
            protect_kernel_tunables: false,
            protect_kernel_modules: false,
            protect_kernel_logs: false,
            protect_control_groups: false,
            protect_proc: None,
            proc_subset: None,
            capability_bounding_set: None,
            ambient_capabilities: HashSet::new(),
            no_new_privileges: false,
            system_call_filter: Vec::new(),
            system_call_filter_action: SystemCallFilterAction::Allow,
            system_call_architectures: Vec::new(),
            system_call_error_number: None,
            read_only_paths: Vec::new(),
            read_write_paths: Vec::new(),
            inaccessible_paths: Vec::new(),
            temporary_filesystem: Vec::new(),
            bind_paths: Vec::new(),
            bind_read_only_paths: Vec::new(),
            restrict_address_families: Vec::new(),
            restrict_namespaces: None,
            restrict_realtime: false,
            restrict_suid_sgid: false,
            lock_personality: false,
            memory_deny_write_execute: false,
            remove_ipc: false,
            umask: None,
            keyring_mode: None,
        }
    }
}

impl SecurityHardening {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a minimal hardening profile for basic services
    pub fn minimal() -> Self {
        Self {
            protect_system: ProtectSystem::Yes,
            protect_home: ProtectHome::Yes,
            private_tmp: true,
            no_new_privileges: true,
            ..Default::default()
        }
    }

    /// Create a strict hardening profile
    pub fn strict() -> Self {
        Self {
            protect_system: ProtectSystem::Strict,
            protect_home: ProtectHome::Yes,
            private_tmp: true,
            private_devices: true,
            private_users: true,
            protect_hostname: true,
            protect_clock: true,
            protect_kernel_tunables: true,
            protect_kernel_modules: true,
            protect_kernel_logs: true,
            protect_control_groups: true,
            protect_proc: Some("invisible".to_string()),
            proc_subset: Some("pid".to_string()),
            capability_bounding_set: Some(HashSet::new()),
            no_new_privileges: true,
            system_call_architectures: vec!["native".to_string()],
            restrict_address_families: vec![
                "AF_UNIX".to_string(),
                "AF_INET".to_string(),
                "AF_INET6".to_string(),
            ],
            restrict_namespaces: Some(true),
            restrict_realtime: true,
            restrict_suid_sgid: true,
            lock_personality: true,
            memory_deny_write_execute: true,
            remove_ipc: true,
            umask: Some("0077".to_string()),
            keyring_mode: Some("private".to_string()),
            ..Default::default()
        }
    }

    pub fn protect_system(mut self, protection: ProtectSystem) -> Self {
        self.protect_system = protection;
        self
    }

    pub fn protect_home(mut self, protection: ProtectHome) -> Self {
        self.protect_home = protection;
        self
    }

    pub fn private_tmp(mut self, enable: bool) -> Self {
        self.private_tmp = enable;
        self
    }

    pub fn private_devices(mut self, enable: bool) -> Self {
        self.private_devices = enable;
        self
    }

    pub fn private_network(mut self, enable: bool) -> Self {
        self.private_network = enable;
        self
    }

    pub fn no_new_privileges(mut self, enable: bool) -> Self {
        self.no_new_privileges = enable;
        self
    }

    pub fn drop_all_capabilities(mut self) -> Self {
        self.capability_bounding_set = Some(HashSet::new());
        self
    }

    pub fn add_capability(mut self, cap: Capability) -> Self {
        if self.capability_bounding_set.is_none() {
            self.capability_bounding_set = Some(HashSet::new());
        }
        self.capability_bounding_set.as_mut().unwrap().insert(cap);
        self
    }

    pub fn add_ambient_capability(mut self, cap: Capability) -> Self {
        self.ambient_capabilities.insert(cap);
        self
    }

    pub fn syscall_filter(mut self, filter: impl Into<String>) -> Self {
        self.system_call_filter.push(filter.into());
        self
    }

    pub fn read_only_path(mut self, path: impl Into<String>) -> Self {
        self.read_only_paths.push(path.into());
        self
    }

    pub fn read_write_path(mut self, path: impl Into<String>) -> Self {
        self.read_write_paths.push(path.into());
        self
    }

    pub fn inaccessible_path(mut self, path: impl Into<String>) -> Self {
        self.inaccessible_paths.push(path.into());
        self
    }

    pub fn restrict_address_family(mut self, family: impl Into<String>) -> Self {
        self.restrict_address_families.push(family.into());
        self
    }

    pub fn generate(&self) -> Vec<String> {
        let mut lines = Vec::new();

        // Sandboxing
        lines.push(format!("ProtectSystem={}", self.protect_system.as_str()));
        lines.push(format!("ProtectHome={}", self.protect_home.as_str()));

        if self.private_tmp {
            lines.push("PrivateTmp=yes".to_string());
        }
        if self.private_devices {
            lines.push("PrivateDevices=yes".to_string());
        }
        if self.private_network {
            lines.push("PrivateNetwork=yes".to_string());
        }
        if self.private_users {
            lines.push("PrivateUsers=yes".to_string());
        }
        if self.private_ipc {
            lines.push("PrivateIPC=yes".to_string());
        }
        if self.protect_hostname {
            lines.push("ProtectHostname=yes".to_string());
        }
        if self.protect_clock {
            lines.push("ProtectClock=yes".to_string());
        }
        if self.protect_kernel_tunables {
            lines.push("ProtectKernelTunables=yes".to_string());
        }
        if self.protect_kernel_modules {
            lines.push("ProtectKernelModules=yes".to_string());
        }
        if self.protect_kernel_logs {
            lines.push("ProtectKernelLogs=yes".to_string());
        }
        if self.protect_control_groups {
            lines.push("ProtectControlGroups=yes".to_string());
        }

        if let Some(ref proc) = self.protect_proc {
            lines.push(format!("ProtectProc={}", proc));
        }
        if let Some(ref subset) = self.proc_subset {
            lines.push(format!("ProcSubset={}", subset));
        }

        // Capabilities
        if let Some(ref caps) = self.capability_bounding_set {
            if caps.is_empty() {
                lines.push("CapabilityBoundingSet=".to_string());
            } else {
                let caps_str: Vec<&str> = caps.iter().map(|c| c.as_str()).collect();
                lines.push(format!("CapabilityBoundingSet={}", caps_str.join(" ")));
            }
        }

        if !self.ambient_capabilities.is_empty() {
            let caps_str: Vec<&str> = self
                .ambient_capabilities
                .iter()
                .map(|c| c.as_str())
                .collect();
            lines.push(format!("AmbientCapabilities={}", caps_str.join(" ")));
        }

        if self.no_new_privileges {
            lines.push("NoNewPrivileges=yes".to_string());
        }

        // System calls
        if !self.system_call_filter.is_empty() {
            for filter in &self.system_call_filter {
                lines.push(format!("SystemCallFilter={}", filter));
            }
        }

        if !self.system_call_architectures.is_empty() {
            lines.push(format!(
                "SystemCallArchitectures={}",
                self.system_call_architectures.join(" ")
            ));
        }

        if let Some(ref errno) = self.system_call_error_number {
            lines.push(format!("SystemCallErrorNumber={}", errno));
        }

        // Filesystem
        for path in &self.read_only_paths {
            lines.push(format!("ReadOnlyPaths={}", path));
        }
        for path in &self.read_write_paths {
            lines.push(format!("ReadWritePaths={}", path));
        }
        for path in &self.inaccessible_paths {
            lines.push(format!("InaccessiblePaths={}", path));
        }
        for (path, options) in &self.temporary_filesystem {
            lines.push(format!("TemporaryFileSystem={}:{}", path, options));
        }
        for (src, dst) in &self.bind_paths {
            lines.push(format!("BindPaths={}:{}", src, dst));
        }
        for (src, dst) in &self.bind_read_only_paths {
            lines.push(format!("BindReadOnlyPaths={}:{}", src, dst));
        }

        // Misc security
        if !self.restrict_address_families.is_empty() {
            lines.push(format!(
                "RestrictAddressFamilies={}",
                self.restrict_address_families.join(" ")
            ));
        }

        if let Some(restrict) = self.restrict_namespaces {
            lines.push(format!(
                "RestrictNamespaces={}",
                if restrict { "yes" } else { "no" }
            ));
        }

        if self.restrict_realtime {
            lines.push("RestrictRealtime=yes".to_string());
        }
        if self.restrict_suid_sgid {
            lines.push("RestrictSUIDSGID=yes".to_string());
        }
        if self.lock_personality {
            lines.push("LockPersonality=yes".to_string());
        }
        if self.memory_deny_write_execute {
            lines.push("MemoryDenyWriteExecute=yes".to_string());
        }
        if self.remove_ipc {
            lines.push("RemoveIPC=yes".to_string());
        }

        if let Some(ref umask) = self.umask {
            lines.push(format!("UMask={}", umask));
        }
        if let Some(ref mode) = self.keyring_mode {
            lines.push(format!("KeyringMode={}", mode));
        }

        lines
    }
}

/// Service section configuration
#[derive(Debug, Clone)]
pub struct ServiceSection {
    pub service_type: ServiceType,
    pub exec_start: String,
    pub exec_start_pre: Vec<String>,
    pub exec_start_post: Vec<String>,
    pub exec_stop: Option<String>,
    pub exec_stop_post: Vec<String>,
    pub exec_reload: Option<String>,
    pub restart: RestartPolicy,
    pub restart_sec: Option<u32>,
    pub timeout_start_sec: Option<u32>,
    pub timeout_stop_sec: Option<u32>,
    pub watchdog_sec: Option<u32>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub dynamic_user: bool,
    pub working_directory: Option<String>,
    pub root_directory: Option<String>,
    pub state_directory: Vec<String>,
    pub cache_directory: Vec<String>,
    pub logs_directory: Vec<String>,
    pub runtime_directory: Vec<String>,
    pub configuration_directory: Vec<String>,
    pub environment: HashMap<String, String>,
    pub environment_file: Vec<String>,
    pub pid_file: Option<String>,
    pub nice: Option<i32>,
    pub io_scheduling_class: Option<String>,
    pub io_scheduling_priority: Option<u32>,
    pub cpu_scheduling_policy: Option<String>,
    pub cpu_affinity: Option<String>,
    pub memory_limit: Option<String>,
    pub memory_high: Option<String>,
    pub memory_max: Option<String>,
    pub tasks_max: Option<u32>,
    pub cpu_quota: Option<String>,
    pub resource_limits: HashMap<String, ResourceLimit>,
    pub security: SecurityHardening,
}

impl ServiceSection {
    pub fn new(exec_start: impl Into<String>) -> Self {
        Self {
            service_type: ServiceType::Simple,
            exec_start: exec_start.into(),
            exec_start_pre: Vec::new(),
            exec_start_post: Vec::new(),
            exec_stop: None,
            exec_stop_post: Vec::new(),
            exec_reload: None,
            restart: RestartPolicy::No,
            restart_sec: None,
            timeout_start_sec: None,
            timeout_stop_sec: None,
            watchdog_sec: None,
            user: None,
            group: None,
            dynamic_user: false,
            working_directory: None,
            root_directory: None,
            state_directory: Vec::new(),
            cache_directory: Vec::new(),
            logs_directory: Vec::new(),
            runtime_directory: Vec::new(),
            configuration_directory: Vec::new(),
            environment: HashMap::new(),
            environment_file: Vec::new(),
            pid_file: None,
            nice: None,
            io_scheduling_class: None,
            io_scheduling_priority: None,
            cpu_scheduling_policy: None,
            cpu_affinity: None,
            memory_limit: None,
            memory_high: None,
            memory_max: None,
            tasks_max: None,
            cpu_quota: None,
            resource_limits: HashMap::new(),
            security: SecurityHardening::default(),
        }
    }

    pub fn service_type(mut self, t: ServiceType) -> Self {
        self.service_type = t;
        self
    }

    pub fn exec_start_pre(mut self, cmd: impl Into<String>) -> Self {
        self.exec_start_pre.push(cmd.into());
        self
    }

    pub fn exec_stop(mut self, cmd: impl Into<String>) -> Self {
        self.exec_stop = Some(cmd.into());
        self
    }

    pub fn exec_reload(mut self, cmd: impl Into<String>) -> Self {
        self.exec_reload = Some(cmd.into());
        self
    }

    pub fn restart(mut self, policy: RestartPolicy) -> Self {
        self.restart = policy;
        self
    }

    pub fn restart_sec(mut self, seconds: u32) -> Self {
        self.restart_sec = Some(seconds);
        self
    }

    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    pub fn group(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
        self
    }

    pub fn dynamic_user(mut self, enable: bool) -> Self {
        self.dynamic_user = enable;
        self
    }

    pub fn working_directory(mut self, dir: impl Into<String>) -> Self {
        self.working_directory = Some(dir.into());
        self
    }

    pub fn state_directory(mut self, dir: impl Into<String>) -> Self {
        self.state_directory.push(dir.into());
        self
    }

    pub fn cache_directory(mut self, dir: impl Into<String>) -> Self {
        self.cache_directory.push(dir.into());
        self
    }

    pub fn logs_directory(mut self, dir: impl Into<String>) -> Self {
        self.logs_directory.push(dir.into());
        self
    }

    pub fn runtime_directory(mut self, dir: impl Into<String>) -> Self {
        self.runtime_directory.push(dir.into());
        self
    }

    pub fn environment(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }

    pub fn environment_file(mut self, path: impl Into<String>) -> Self {
        self.environment_file.push(path.into());
        self
    }

    pub fn memory_max(mut self, limit: impl Into<String>) -> Self {
        self.memory_max = Some(limit.into());
        self
    }

    pub fn tasks_max(mut self, max: u32) -> Self {
        self.tasks_max = Some(max);
        self
    }

    pub fn cpu_quota(mut self, quota: impl Into<String>) -> Self {
        self.cpu_quota = Some(quota.into());
        self
    }

    pub fn limit(mut self, name: impl Into<String>, limit: ResourceLimit) -> Self {
        self.resource_limits.insert(name.into(), limit);
        self
    }

    pub fn security(mut self, security: SecurityHardening) -> Self {
        self.security = security;
        self
    }

    pub fn generate(&self) -> Vec<String> {
        let mut lines = Vec::new();

        lines.push(format!("Type={}", self.service_type.as_str()));

        for cmd in &self.exec_start_pre {
            lines.push(format!("ExecStartPre={}", cmd));
        }
        lines.push(format!("ExecStart={}", self.exec_start));
        for cmd in &self.exec_start_post {
            lines.push(format!("ExecStartPost={}", cmd));
        }

        if let Some(ref cmd) = self.exec_stop {
            lines.push(format!("ExecStop={}", cmd));
        }
        for cmd in &self.exec_stop_post {
            lines.push(format!("ExecStopPost={}", cmd));
        }

        if let Some(ref cmd) = self.exec_reload {
            lines.push(format!("ExecReload={}", cmd));
        }

        lines.push(format!("Restart={}", self.restart.as_str()));
        if let Some(sec) = self.restart_sec {
            lines.push(format!("RestartSec={}", sec));
        }

        if let Some(sec) = self.timeout_start_sec {
            lines.push(format!("TimeoutStartSec={}", sec));
        }
        if let Some(sec) = self.timeout_stop_sec {
            lines.push(format!("TimeoutStopSec={}", sec));
        }
        if let Some(sec) = self.watchdog_sec {
            lines.push(format!("WatchdogSec={}", sec));
        }

        if let Some(ref user) = self.user {
            lines.push(format!("User={}", user));
        }
        if let Some(ref group) = self.group {
            lines.push(format!("Group={}", group));
        }
        if self.dynamic_user {
            lines.push("DynamicUser=yes".to_string());
        }

        if let Some(ref dir) = self.working_directory {
            lines.push(format!("WorkingDirectory={}", dir));
        }
        if let Some(ref dir) = self.root_directory {
            lines.push(format!("RootDirectory={}", dir));
        }

        for dir in &self.state_directory {
            lines.push(format!("StateDirectory={}", dir));
        }
        for dir in &self.cache_directory {
            lines.push(format!("CacheDirectory={}", dir));
        }
        for dir in &self.logs_directory {
            lines.push(format!("LogsDirectory={}", dir));
        }
        for dir in &self.runtime_directory {
            lines.push(format!("RuntimeDirectory={}", dir));
        }

        for (key, value) in &self.environment {
            lines.push(format!("Environment=\"{}={}\"", key, value));
        }
        for file in &self.environment_file {
            lines.push(format!("EnvironmentFile={}", file));
        }

        if let Some(ref pid) = self.pid_file {
            lines.push(format!("PIDFile={}", pid));
        }

        if let Some(nice) = self.nice {
            lines.push(format!("Nice={}", nice));
        }

        if let Some(ref limit) = self.memory_max {
            lines.push(format!("MemoryMax={}", limit));
        }
        if let Some(max) = self.tasks_max {
            lines.push(format!("TasksMax={}", max));
        }
        if let Some(ref quota) = self.cpu_quota {
            lines.push(format!("CPUQuota={}", quota));
        }

        for (name, limit) in &self.resource_limits {
            if let Some(ref soft) = limit.soft {
                if let Some(ref hard) = limit.hard {
                    lines.push(format!("Limit{}={}:{}", name.to_uppercase(), soft, hard));
                } else {
                    lines.push(format!("Limit{}={}", name.to_uppercase(), soft));
                }
            }
        }

        // Security hardening
        lines.extend(self.security.generate());

        lines
    }
}

/// Systemd unit file generator
pub struct SystemdUnitGenerator {
    pub name: String,
    pub unit: UnitSection,
    pub service: ServiceSection,
    pub install: InstallSection,
}

impl SystemdUnitGenerator {
    pub fn new(name: impl Into<String>, exec_start: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            unit: UnitSection::new(),
            service: ServiceSection::new(exec_start),
            install: InstallSection::new(),
        }
    }

    pub fn unit(mut self, unit: UnitSection) -> Self {
        self.unit = unit;
        self
    }

    pub fn service(mut self, service: ServiceSection) -> Self {
        self.service = service;
        self
    }

    pub fn install(mut self, install: InstallSection) -> Self {
        self.install = install;
        self
    }

    pub fn generate(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("# {}.service\n", self.name));
        output.push_str("# Generated by Rust Systemd Unit Generator\n\n");

        output.push_str("[Unit]\n");
        for line in self.unit.generate() {
            output.push_str(&format!("{}\n", line));
        }

        output.push_str("\n[Service]\n");
        for line in self.service.generate() {
            output.push_str(&format!("{}\n", line));
        }

        output.push_str("\n[Install]\n");
        for line in self.install.generate() {
            output.push_str(&format!("{}\n", line));
        }

        output
    }
}

fn main() {
    println!("=== Systemd Service Hardening Demo ===\n");

    // Create a hardened web application service
    let unit = UnitSection::new()
        .description("My Secure Web Application")
        .documentation("https://example.com/docs")
        .after("network.target")
        .after("postgresql.service")
        .wants("postgresql.service");

    let security = SecurityHardening::strict()
        .add_capability(Capability::NetBindService)
        .restrict_address_family("AF_UNIX")
        .restrict_address_family("AF_INET")
        .restrict_address_family("AF_INET6")
        .read_write_path("/var/lib/myapp")
        .syscall_filter("@system-service")
        .syscall_filter("~@privileged")
        .syscall_filter("~@resources");

    let service = ServiceSection::new("/usr/bin/myapp --config /etc/myapp/config.toml")
        .service_type(ServiceType::Notify)
        .user("myapp")
        .group("myapp")
        .working_directory("/var/lib/myapp")
        .state_directory("myapp")
        .cache_directory("myapp")
        .logs_directory("myapp")
        .runtime_directory("myapp")
        .environment("NODE_ENV", "production")
        .environment("PORT", "8080")
        .environment_file("/etc/myapp/env")
        .restart(RestartPolicy::OnFailure)
        .restart_sec(5)
        .memory_max("512M")
        .tasks_max(100)
        .cpu_quota("50%")
        .limit("NOFILE", ResourceLimit::both("65535"))
        .limit("NPROC", ResourceLimit::both("512"))
        .security(security);

    let install = InstallSection::new().wanted_by("multi-user.target");

    let generator = SystemdUnitGenerator::new("myapp", "/usr/bin/myapp")
        .unit(unit)
        .service(service)
        .install(install);

    println!("Generated Systemd Unit File:");
    println!("{}", "=".repeat(60));
    println!("{}", generator.generate());
    println!("{}", "=".repeat(60));

    // Show security hardening levels
    println!("\nSecurity Hardening Profiles:");
    println!("\n1. Minimal (basic protection):");
    for line in SecurityHardening::minimal().generate().iter().take(5) {
        println!("   {}", line);
    }
    println!("   ...");

    println!("\n2. Strict (maximum protection):");
    for line in SecurityHardening::strict().generate().iter().take(10) {
        println!("   {}", line);
    }
    println!("   ...");

    // Simple service example
    println!("\n3. Simple timer service:");
    let simple = SystemdUnitGenerator::new("backup", "/usr/local/bin/backup.sh")
        .unit(UnitSection::new().description("Backup Service"))
        .service(
            ServiceSection::new("/usr/local/bin/backup.sh")
                .service_type(ServiceType::Oneshot)
                .user("backup")
                .security(
                    SecurityHardening::minimal()
                        .private_network(true)
                        .read_only_path("/")
                        .read_write_path("/backup"),
                ),
        )
        .install(InstallSection::new().wanted_by("multi-user.target"));

    println!("{}", simple.generate());

    println!("\n=== Demo Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_strings() {
        assert_eq!(Capability::NetBindService.as_str(), "CAP_NET_BIND_SERVICE");
        assert_eq!(Capability::SysAdmin.as_str(), "CAP_SYS_ADMIN");
    }

    #[test]
    fn test_protect_system_values() {
        assert_eq!(ProtectSystem::Strict.as_str(), "strict");
        assert_eq!(ProtectSystem::Full.as_str(), "full");
    }

    #[test]
    fn test_service_type_values() {
        assert_eq!(ServiceType::Simple.as_str(), "simple");
        assert_eq!(ServiceType::Notify.as_str(), "notify");
    }

    #[test]
    fn test_unit_section() {
        let unit = UnitSection::new()
            .description("Test Service")
            .after("network.target")
            .wants("redis.service");

        let lines = unit.generate();
        assert!(lines.iter().any(|l| l.contains("Description=Test Service")));
        assert!(lines.iter().any(|l| l.contains("After=network.target")));
    }

    #[test]
    fn test_install_section() {
        let install = InstallSection::new()
            .wanted_by("multi-user.target")
            .also("myapp.socket");

        let lines = install.generate();
        assert!(lines
            .iter()
            .any(|l| l.contains("WantedBy=multi-user.target")));
    }

    #[test]
    fn test_security_hardening_minimal() {
        let security = SecurityHardening::minimal();
        let lines = security.generate();

        assert!(lines.iter().any(|l| l.contains("ProtectSystem=yes")));
        assert!(lines.iter().any(|l| l.contains("PrivateTmp=yes")));
    }

    #[test]
    fn test_security_hardening_strict() {
        let security = SecurityHardening::strict();
        let lines = security.generate();

        assert!(lines.iter().any(|l| l.contains("ProtectSystem=strict")));
        assert!(lines.iter().any(|l| l.contains("NoNewPrivileges=yes")));
        assert!(lines
            .iter()
            .any(|l| l.contains("MemoryDenyWriteExecute=yes")));
    }

    #[test]
    fn test_capability_bounding_set() {
        let security = SecurityHardening::new()
            .drop_all_capabilities()
            .add_capability(Capability::NetBindService);

        let lines = security.generate();
        assert!(lines
            .iter()
            .any(|l| l.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE")));
    }

    #[test]
    fn test_service_section() {
        let service = ServiceSection::new("/usr/bin/test")
            .service_type(ServiceType::Notify)
            .user("testuser")
            .restart(RestartPolicy::OnFailure);

        let lines = service.generate();
        assert!(lines.iter().any(|l| l.contains("Type=notify")));
        assert!(lines.iter().any(|l| l.contains("User=testuser")));
        assert!(lines.iter().any(|l| l.contains("Restart=on-failure")));
    }

    #[test]
    fn test_environment_variables() {
        let service = ServiceSection::new("/usr/bin/test")
            .environment("KEY", "value")
            .environment_file("/etc/env");

        let lines = service.generate();
        assert!(lines
            .iter()
            .any(|l| l.contains("Environment=\"KEY=value\"")));
        assert!(lines.iter().any(|l| l.contains("EnvironmentFile=/etc/env")));
    }

    #[test]
    fn test_resource_limits() {
        let service = ServiceSection::new("/usr/bin/test")
            .memory_max("1G")
            .tasks_max(50)
            .cpu_quota("25%")
            .limit("NOFILE", ResourceLimit::both("4096"));

        let lines = service.generate();
        assert!(lines.iter().any(|l| l.contains("MemoryMax=1G")));
        assert!(lines.iter().any(|l| l.contains("TasksMax=50")));
        assert!(lines.iter().any(|l| l.contains("CPUQuota=25%")));
        assert!(lines.iter().any(|l| l.contains("LimitNOFILE=4096:4096")));
    }

    #[test]
    fn test_filesystem_paths() {
        let security = SecurityHardening::new()
            .read_only_path("/etc")
            .read_write_path("/var/lib/app")
            .inaccessible_path("/home");

        let lines = security.generate();
        assert!(lines.iter().any(|l| l.contains("ReadOnlyPaths=/etc")));
        assert!(lines
            .iter()
            .any(|l| l.contains("ReadWritePaths=/var/lib/app")));
        assert!(lines.iter().any(|l| l.contains("InaccessiblePaths=/home")));
    }

    #[test]
    fn test_full_unit_generation() {
        let generator = SystemdUnitGenerator::new("test", "/usr/bin/test")
            .unit(UnitSection::new().description("Test"))
            .service(ServiceSection::new("/usr/bin/test").user("nobody"))
            .install(InstallSection::new().wanted_by("multi-user.target"));

        let output = generator.generate();
        assert!(output.contains("[Unit]"));
        assert!(output.contains("[Service]"));
        assert!(output.contains("[Install]"));
        assert!(output.contains("Description=Test"));
    }

    #[test]
    fn test_dynamic_user() {
        let service = ServiceSection::new("/usr/bin/test").dynamic_user(true);

        let lines = service.generate();
        assert!(lines.iter().any(|l| l.contains("DynamicUser=yes")));
    }

    #[test]
    fn test_directories() {
        let service = ServiceSection::new("/usr/bin/test")
            .state_directory("myapp")
            .cache_directory("myapp")
            .logs_directory("myapp")
            .runtime_directory("myapp");

        let lines = service.generate();
        assert!(lines.iter().any(|l| l.contains("StateDirectory=myapp")));
        assert!(lines.iter().any(|l| l.contains("CacheDirectory=myapp")));
        assert!(lines.iter().any(|l| l.contains("LogsDirectory=myapp")));
        assert!(lines.iter().any(|l| l.contains("RuntimeDirectory=myapp")));
    }

    #[test]
    fn test_syscall_filter() {
        let security = SecurityHardening::new()
            .syscall_filter("@system-service")
            .syscall_filter("~@privileged");

        let lines = security.generate();
        assert!(lines
            .iter()
            .any(|l| l.contains("SystemCallFilter=@system-service")));
        assert!(lines
            .iter()
            .any(|l| l.contains("SystemCallFilter=~@privileged")));
    }

    #[test]
    fn test_restart_policy() {
        assert_eq!(RestartPolicy::OnFailure.as_str(), "on-failure");
        assert_eq!(RestartPolicy::Always.as_str(), "always");
        assert_eq!(RestartPolicy::OnAbnormal.as_str(), "on-abnormal");
    }

    #[test]
    fn test_resource_limit_unlimited() {
        let limit = ResourceLimit::unlimited();
        assert_eq!(limit.soft, Some("infinity".to_string()));
        assert_eq!(limit.hard, Some("infinity".to_string()));
    }
}
