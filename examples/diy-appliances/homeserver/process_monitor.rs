//! Process Monitor for Homeserver Security
//!
//! This example demonstrates a security-focused process monitoring system
//! that detects anomalous behavior, unauthorized processes, privilege
//! escalation attempts, and resource abuse on homeservers.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// Process Information
// ============================================================================

/// Process information
#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe_path: String,
    pub cmdline: Vec<String>,
    pub user: UserInfo,
    pub state: ProcessState,
    pub cpu_usage: f64,
    pub memory_usage: u64,
    pub memory_percent: f64,
    pub threads: u32,
    pub open_files: u32,
    pub network_connections: u32,
    pub start_time: SystemTime,
    pub cwd: String,
    pub env: HashMap<String, String>,
    pub capabilities: Vec<Capability>,
    pub seccomp_mode: SeccompMode,
    pub namespace_ids: NamespaceIds,
}

#[derive(Clone, Debug)]
pub struct UserInfo {
    pub uid: u32,
    pub gid: u32,
    pub username: String,
    pub groups: Vec<u32>,
    pub is_root: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProcessState {
    Running,
    Sleeping,
    Waiting,
    Zombie,
    Stopped,
    Dead,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Capability {
    CapChown,
    CapDacOverride,
    CapDacReadSearch,
    CapFowner,
    CapFsetid,
    CapKill,
    CapSetgid,
    CapSetuid,
    CapSetpcap,
    CapNetBindService,
    CapNetRaw,
    CapSysChroot,
    CapSysPtrace,
    CapSysAdmin,
    CapSysBoot,
    CapSysResource,
    CapSysTime,
    CapAuditWrite,
    CapMknod,
    Unknown(String),
}

impl Capability {
    pub fn is_dangerous(&self) -> bool {
        matches!(
            self,
            Capability::CapSysAdmin
                | Capability::CapSysPtrace
                | Capability::CapDacOverride
                | Capability::CapSetuid
                | Capability::CapSetgid
                | Capability::CapSysBoot
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SeccompMode {
    Disabled,
    Strict,
    Filter,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct NamespaceIds {
    pub mnt: u64,
    pub pid: u64,
    pub net: u64,
    pub user: u64,
    pub uts: u64,
    pub ipc: u64,
    pub cgroup: u64,
}

impl Default for NamespaceIds {
    fn default() -> Self {
        Self {
            mnt: 0,
            pid: 0,
            net: 0,
            user: 0,
            uts: 0,
            ipc: 0,
            cgroup: 0,
        }
    }
}

// ============================================================================
// Security Policies
// ============================================================================

/// Process security policy
#[derive(Clone, Debug)]
pub struct SecurityPolicy {
    pub allowed_processes: HashSet<String>,
    pub blocked_processes: HashSet<String>,
    pub allowed_network_ports: HashSet<u16>,
    pub max_cpu_percent: f64,
    pub max_memory_percent: f64,
    pub max_open_files: u32,
    pub max_connections: u32,
    pub allow_root_processes: bool,
    pub require_seccomp: bool,
    pub blocked_capabilities: HashSet<Capability>,
    pub allowed_paths: Vec<String>,
    pub blocked_paths: Vec<String>,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        let mut blocked_caps = HashSet::new();
        blocked_caps.insert(Capability::CapSysAdmin);
        blocked_caps.insert(Capability::CapSysPtrace);
        blocked_caps.insert(Capability::CapSysBoot);

        let mut blocked_processes = HashSet::new();
        blocked_processes.insert("nc".to_string());
        blocked_processes.insert("netcat".to_string());
        blocked_processes.insert("ncat".to_string());
        blocked_processes.insert("socat".to_string());
        blocked_processes.insert("cryptominer".to_string());
        blocked_processes.insert("xmrig".to_string());

        Self {
            allowed_processes: HashSet::new(),
            blocked_processes,
            allowed_network_ports: HashSet::new(),
            max_cpu_percent: 95.0,
            max_memory_percent: 90.0,
            max_open_files: 10000,
            max_connections: 1000,
            allow_root_processes: false,
            require_seccomp: false,
            blocked_capabilities: blocked_caps,
            allowed_paths: vec![
                "/usr/".to_string(),
                "/bin/".to_string(),
                "/sbin/".to_string(),
                "/opt/".to_string(),
            ],
            blocked_paths: vec!["/tmp/".to_string(), "/dev/shm/".to_string()],
        }
    }
}

impl SecurityPolicy {
    pub fn strict() -> Self {
        let mut policy = Self::default();
        policy.allow_root_processes = false;
        policy.require_seccomp = true;
        policy.max_cpu_percent = 80.0;
        policy.max_memory_percent = 70.0;
        policy
    }
}

// ============================================================================
// Security Alerts
// ============================================================================

/// Security alert
#[derive(Clone, Debug)]
pub struct SecurityAlert {
    pub id: u64,
    pub timestamp: SystemTime,
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub process: ProcessInfo,
    pub description: String,
    pub details: HashMap<String, String>,
    pub recommended_action: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AlertType {
    UnauthorizedProcess,
    PrivilegeEscalation,
    SuspiciousCapability,
    ResourceAbuse,
    NetworkAnomaly,
    FileSystemAnomaly,
    RootkitIndicator,
    CryptoMining,
    ReverseShell,
    DataExfiltration,
    ProcessInjection,
    MemoryAnomaly,
    NamespaceEscape,
    SeccompBypass,
    PtraceMisuse,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlertSeverity::Info => write!(f, "INFO"),
            AlertSeverity::Low => write!(f, "LOW"),
            AlertSeverity::Medium => write!(f, "MEDIUM"),
            AlertSeverity::High => write!(f, "HIGH"),
            AlertSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl AlertType {
    pub fn default_severity(&self) -> AlertSeverity {
        match self {
            AlertType::RootkitIndicator
            | AlertType::NamespaceEscape
            | AlertType::PrivilegeEscalation
            | AlertType::ReverseShell => AlertSeverity::Critical,

            AlertType::SuspiciousCapability
            | AlertType::ProcessInjection
            | AlertType::DataExfiltration
            | AlertType::SeccompBypass
            | AlertType::PtraceMisuse => AlertSeverity::High,

            AlertType::UnauthorizedProcess
            | AlertType::CryptoMining
            | AlertType::NetworkAnomaly
            | AlertType::MemoryAnomaly => AlertSeverity::Medium,

            AlertType::ResourceAbuse | AlertType::FileSystemAnomaly => AlertSeverity::Low,
        }
    }
}

// ============================================================================
// Process Monitor
// ============================================================================

/// Process monitor configuration
#[derive(Clone, Debug)]
pub struct MonitorConfig {
    pub scan_interval: Duration,
    pub history_size: usize,
    pub alert_retention: Duration,
    pub enable_behavioral_analysis: bool,
    pub enable_resource_monitoring: bool,
    pub enable_network_monitoring: bool,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            scan_interval: Duration::from_secs(5),
            history_size: 1000,
            alert_retention: Duration::from_secs(86400),
            enable_behavioral_analysis: true,
            enable_resource_monitoring: true,
            enable_network_monitoring: true,
        }
    }
}

/// Process monitor
pub struct ProcessMonitor {
    config: MonitorConfig,
    policy: SecurityPolicy,
    processes: Arc<RwLock<HashMap<u32, ProcessInfo>>>,
    process_history: Arc<RwLock<HashMap<u32, VecDeque<ProcessSnapshot>>>>,
    alerts: Arc<RwLock<Vec<SecurityAlert>>>,
    baselines: Arc<RwLock<HashMap<String, ProcessBaseline>>>,
    stats: MonitorStats,
    next_alert_id: AtomicU64,
}

#[derive(Clone, Debug)]
pub struct ProcessSnapshot {
    pub timestamp: SystemTime,
    pub cpu_usage: f64,
    pub memory_usage: u64,
    pub threads: u32,
    pub open_files: u32,
    pub connections: u32,
}

#[derive(Clone, Debug)]
pub struct ProcessBaseline {
    pub process_name: String,
    pub avg_cpu: f64,
    pub avg_memory: u64,
    pub avg_threads: u32,
    pub avg_files: u32,
    pub avg_connections: u32,
    pub sample_count: u64,
    pub normal_parents: HashSet<String>,
    pub normal_children: HashSet<String>,
}

#[derive(Default)]
pub struct MonitorStats {
    pub scans_completed: AtomicU64,
    pub processes_monitored: AtomicU64,
    pub alerts_generated: AtomicU64,
    pub blocked_attempts: AtomicU64,
}

impl ProcessMonitor {
    pub fn new(config: MonitorConfig, policy: SecurityPolicy) -> Self {
        Self {
            config,
            policy,
            processes: Arc::new(RwLock::new(HashMap::new())),
            process_history: Arc::new(RwLock::new(HashMap::new())),
            alerts: Arc::new(RwLock::new(Vec::new())),
            baselines: Arc::new(RwLock::new(HashMap::new())),
            stats: MonitorStats::default(),
            next_alert_id: AtomicU64::new(1),
        }
    }

    /// Analyze a process for security issues
    pub fn analyze_process(&self, process: &ProcessInfo) -> Vec<SecurityAlert> {
        let mut alerts = Vec::new();

        // Check blocked processes
        if self.policy.blocked_processes.contains(&process.name) {
            alerts.push(self.create_alert(
                AlertType::UnauthorizedProcess,
                process,
                format!("Blocked process '{}' detected", process.name),
                "Terminate the process and investigate".to_string(),
            ));
        }

        // Check for root processes
        if process.user.is_root && !self.policy.allow_root_processes {
            if !self.is_system_process(&process.name) {
                alerts.push(self.create_alert(
                    AlertType::PrivilegeEscalation,
                    process,
                    format!("Unexpected root process: {}", process.name),
                    "Verify if root privileges are required".to_string(),
                ));
            }
        }

        // Check dangerous capabilities
        for cap in &process.capabilities {
            if cap.is_dangerous() && self.policy.blocked_capabilities.contains(cap) {
                alerts.push(self.create_alert(
                    AlertType::SuspiciousCapability,
                    process,
                    format!("Process has dangerous capability: {:?}", cap),
                    "Review if this capability is necessary".to_string(),
                ));
            }
        }

        // Check resource abuse
        if process.cpu_usage > self.policy.max_cpu_percent {
            alerts.push(self.create_alert(
                AlertType::ResourceAbuse,
                process,
                format!("High CPU usage: {:.1}%", process.cpu_usage),
                "Monitor process or apply resource limits".to_string(),
            ));
        }

        if process.memory_percent > self.policy.max_memory_percent {
            alerts.push(self.create_alert(
                AlertType::ResourceAbuse,
                process,
                format!("High memory usage: {:.1}%", process.memory_percent),
                "Monitor process or apply memory limits".to_string(),
            ));
        }

        // Check seccomp
        if self.policy.require_seccomp && process.seccomp_mode == SeccompMode::Disabled {
            alerts.push(self.create_alert(
                AlertType::SeccompBypass,
                process,
                "Process running without seccomp protection".to_string(),
                "Enable seccomp for this process".to_string(),
            ));
        }

        // Check for execution from blocked paths
        for blocked_path in &self.policy.blocked_paths {
            if process.exe_path.starts_with(blocked_path) {
                alerts.push(self.create_alert(
                    AlertType::UnauthorizedProcess,
                    process,
                    format!("Process executing from blocked path: {}", process.exe_path),
                    "Investigate and terminate suspicious process".to_string(),
                ));
            }
        }

        // Check for crypto mining indicators
        if self.detect_cryptomining(process) {
            alerts.push(self.create_alert(
                AlertType::CryptoMining,
                process,
                "Potential cryptocurrency mining detected".to_string(),
                "Terminate process and investigate compromise".to_string(),
            ));
        }

        // Check for reverse shell indicators
        if self.detect_reverse_shell(process) {
            alerts.push(self.create_alert(
                AlertType::ReverseShell,
                process,
                "Potential reverse shell detected".to_string(),
                "Isolate system immediately and investigate".to_string(),
            ));
        }

        // Behavioral analysis
        if self.config.enable_behavioral_analysis {
            if let Some(anomaly) = self.detect_behavioral_anomaly(process) {
                alerts.push(anomaly);
            }
        }

        // Store alerts
        if !alerts.is_empty() {
            let mut alert_store = self.alerts.write().unwrap();
            alert_store.extend(alerts.clone());
            self.stats
                .alerts_generated
                .fetch_add(alerts.len() as u64, Ordering::Relaxed);
        }

        alerts
    }

    fn create_alert(
        &self,
        alert_type: AlertType,
        process: &ProcessInfo,
        description: String,
        recommended_action: String,
    ) -> SecurityAlert {
        let mut details = HashMap::new();
        details.insert("exe_path".to_string(), process.exe_path.clone());
        details.insert("user".to_string(), process.user.username.clone());
        details.insert("pid".to_string(), process.pid.to_string());
        details.insert("ppid".to_string(), process.ppid.to_string());

        SecurityAlert {
            id: self.next_alert_id.fetch_add(1, Ordering::Relaxed),
            timestamp: SystemTime::now(),
            alert_type: alert_type.clone(),
            severity: alert_type.default_severity(),
            process: process.clone(),
            description,
            details,
            recommended_action,
        }
    }

    fn is_system_process(&self, name: &str) -> bool {
        let system_processes = [
            "init",
            "systemd",
            "kthreadd",
            "ksoftirqd",
            "kworker",
            "migration",
            "watchdog",
            "rcu",
            "netns",
            "sshd",
            "cron",
            "rsyslogd",
            "dbus-daemon",
            "polkitd",
        ];

        system_processes.iter().any(|p| name.starts_with(p))
    }

    fn detect_cryptomining(&self, process: &ProcessInfo) -> bool {
        let mining_indicators = [
            "xmrig", "minerd", "cgminer", "bfgminer", "ethminer", "cpuminer", "nicehash",
            "stratum", "mining",
        ];

        let name_lower = process.name.to_lowercase();
        let cmdline_lower = process.cmdline.join(" ").to_lowercase();

        // Check name
        if mining_indicators.iter().any(|i| name_lower.contains(i)) {
            return true;
        }

        // Check command line
        if mining_indicators.iter().any(|i| cmdline_lower.contains(i)) {
            return true;
        }

        // Check for stratum protocol indicators
        if cmdline_lower.contains("stratum+tcp://") || cmdline_lower.contains("stratum+ssl://") {
            return true;
        }

        // High CPU with specific patterns
        if process.cpu_usage > 90.0 && process.threads > 4 {
            // Additional heuristics could be added here
        }

        false
    }

    fn detect_reverse_shell(&self, process: &ProcessInfo) -> bool {
        let cmdline = process.cmdline.join(" ");

        let shell_indicators = [
            "bash -i",
            "/dev/tcp/",
            "/dev/udp/",
            "nc -e",
            "nc -c",
            "ncat -e",
            "python -c \"import socket",
            "perl -e",
            "ruby -rsocket",
            "php -r",
            "exec 5<>/dev/tcp",
            "mkfifo /tmp",
        ];

        shell_indicators.iter().any(|i| cmdline.contains(i))
    }

    fn detect_behavioral_anomaly(&self, process: &ProcessInfo) -> Option<SecurityAlert> {
        let baselines = self.baselines.read().unwrap();

        if let Some(baseline) = baselines.get(&process.name) {
            // Check for significant deviations
            let cpu_deviation = (process.cpu_usage - baseline.avg_cpu).abs();
            let memory_deviation = (process.memory_usage as f64 - baseline.avg_memory as f64).abs();

            // CPU deviation threshold (2x normal)
            if process.cpu_usage > baseline.avg_cpu * 2.0 && cpu_deviation > 20.0 {
                return Some(self.create_alert(
                    AlertType::MemoryAnomaly,
                    process,
                    format!(
                        "Unusual CPU usage for {}: {:.1}% (baseline: {:.1}%)",
                        process.name, process.cpu_usage, baseline.avg_cpu
                    ),
                    "Investigate process behavior".to_string(),
                ));
            }

            // Memory deviation threshold
            if process.memory_usage > baseline.avg_memory * 2 {
                return Some(self.create_alert(
                    AlertType::MemoryAnomaly,
                    process,
                    format!(
                        "Unusual memory usage for {}: {} bytes (baseline: {} bytes)",
                        process.name, process.memory_usage, baseline.avg_memory
                    ),
                    "Investigate memory consumption".to_string(),
                ));
            }
        }

        None
    }

    /// Update process baseline
    pub fn update_baseline(&self, process: &ProcessInfo) {
        let mut baselines = self.baselines.write().unwrap();

        let baseline = baselines
            .entry(process.name.clone())
            .or_insert_with(|| ProcessBaseline {
                process_name: process.name.clone(),
                avg_cpu: 0.0,
                avg_memory: 0,
                avg_threads: 0,
                avg_files: 0,
                avg_connections: 0,
                sample_count: 0,
                normal_parents: HashSet::new(),
                normal_children: HashSet::new(),
            });

        // Update running averages
        let n = baseline.sample_count as f64;
        baseline.avg_cpu = (baseline.avg_cpu * n + process.cpu_usage) / (n + 1.0);
        baseline.avg_memory =
            ((baseline.avg_memory as f64 * n + process.memory_usage as f64) / (n + 1.0)) as u64;
        baseline.avg_threads =
            ((baseline.avg_threads as f64 * n + process.threads as f64) / (n + 1.0)) as u32;
        baseline.avg_files =
            ((baseline.avg_files as f64 * n + process.open_files as f64) / (n + 1.0)) as u32;
        baseline.avg_connections = ((baseline.avg_connections as f64 * n
            + process.network_connections as f64)
            / (n + 1.0)) as u32;
        baseline.sample_count += 1;
    }

    /// Get recent alerts
    pub fn get_alerts(&self, severity_filter: Option<AlertSeverity>) -> Vec<SecurityAlert> {
        let alerts = self.alerts.read().unwrap();

        alerts
            .iter()
            .filter(|a| severity_filter.as_ref().map_or(true, |s| a.severity >= *s))
            .cloned()
            .collect()
    }

    /// Get monitoring statistics
    pub fn get_stats(&self) -> MonitorStatsSummary {
        let alerts = self.alerts.read().unwrap();
        let baselines = self.baselines.read().unwrap();

        let mut alerts_by_type: HashMap<AlertType, usize> = HashMap::new();
        let mut alerts_by_severity: HashMap<AlertSeverity, usize> = HashMap::new();

        for alert in alerts.iter() {
            *alerts_by_type.entry(alert.alert_type.clone()).or_insert(0) += 1;
            *alerts_by_severity
                .entry(alert.severity.clone())
                .or_insert(0) += 1;
        }

        MonitorStatsSummary {
            scans_completed: self.stats.scans_completed.load(Ordering::Relaxed),
            processes_monitored: self.stats.processes_monitored.load(Ordering::Relaxed),
            total_alerts: self.stats.alerts_generated.load(Ordering::Relaxed),
            blocked_attempts: self.stats.blocked_attempts.load(Ordering::Relaxed),
            alerts_by_type,
            alerts_by_severity,
            baselines_count: baselines.len(),
        }
    }
}

#[derive(Debug)]
pub struct MonitorStatsSummary {
    pub scans_completed: u64,
    pub processes_monitored: u64,
    pub total_alerts: u64,
    pub blocked_attempts: u64,
    pub alerts_by_type: HashMap<AlertType, usize>,
    pub alerts_by_severity: HashMap<AlertSeverity, usize>,
    pub baselines_count: usize,
}

// ============================================================================
// Process Tree Analysis
// ============================================================================

/// Process tree node
#[derive(Clone, Debug)]
pub struct ProcessTreeNode {
    pub process: ProcessInfo,
    pub children: Vec<ProcessTreeNode>,
    pub depth: usize,
}

/// Process tree analyzer
pub struct ProcessTreeAnalyzer;

impl ProcessTreeAnalyzer {
    /// Build process tree from flat list
    pub fn build_tree(processes: &[ProcessInfo]) -> Vec<ProcessTreeNode> {
        let mut tree: Vec<ProcessTreeNode> = Vec::new();
        let process_map: HashMap<u32, &ProcessInfo> =
            processes.iter().map(|p| (p.pid, p)).collect();

        // Find root processes (ppid = 0 or 1, or parent not in list)
        let roots: Vec<&ProcessInfo> = processes
            .iter()
            .filter(|p| p.ppid == 0 || p.ppid == 1 || !process_map.contains_key(&p.ppid))
            .collect();

        for root in roots {
            let node = Self::build_subtree(root, processes, 0);
            tree.push(node);
        }

        tree
    }

    fn build_subtree(process: &ProcessInfo, all: &[ProcessInfo], depth: usize) -> ProcessTreeNode {
        let children: Vec<ProcessTreeNode> = all
            .iter()
            .filter(|p| p.ppid == process.pid && p.pid != process.pid)
            .map(|p| Self::build_subtree(p, all, depth + 1))
            .collect();

        ProcessTreeNode {
            process: process.clone(),
            children,
            depth,
        }
    }

    /// Detect suspicious process relationships
    pub fn detect_suspicious_relationships(tree: &[ProcessTreeNode]) -> Vec<String> {
        let mut findings = Vec::new();

        for node in tree {
            Self::check_node(&node, &mut findings);
        }

        findings
    }

    fn check_node(node: &ProcessTreeNode, findings: &mut Vec<String>) {
        let process = &node.process;

        // Shell spawning other shells
        if Self::is_shell(&process.name) {
            for child in &node.children {
                if Self::is_shell(&child.process.name) {
                    findings.push(format!(
                        "Shell {} (pid {}) spawned another shell {} (pid {})",
                        process.name, process.pid, child.process.name, child.process.pid
                    ));
                }
            }
        }

        // Web server spawning shells
        if Self::is_web_server(&process.name) {
            for child in &node.children {
                if Self::is_shell(&child.process.name) {
                    findings.push(format!(
                        "Web server {} spawned shell {} (potential webshell)",
                        process.name, child.process.name
                    ));
                }
            }
        }

        // Deep nesting (potential process hiding)
        if node.depth > 10 {
            findings.push(format!(
                "Deep process nesting detected: {} at depth {}",
                process.name, node.depth
            ));
        }

        // Recurse into children
        for child in &node.children {
            Self::check_node(child, findings);
        }
    }

    fn is_shell(name: &str) -> bool {
        let shells = ["bash", "sh", "zsh", "ksh", "csh", "tcsh", "fish", "dash"];
        shells.iter().any(|s| name == *s || name.ends_with(s))
    }

    fn is_web_server(name: &str) -> bool {
        let servers = [
            "nginx", "apache", "httpd", "lighttpd", "caddy", "node", "python", "php-fpm",
        ];
        servers.iter().any(|s| name.contains(s))
    }
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== Process Monitor for Homeserver Security ===\n");

    // Create monitor with strict policy
    let config = MonitorConfig::default();
    let policy = SecurityPolicy::strict();
    let monitor = ProcessMonitor::new(config, policy);

    // Sample processes for demonstration
    let processes = vec![
        ProcessInfo {
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            exe_path: "/usr/lib/systemd/systemd".to_string(),
            cmdline: vec!["systemd".to_string()],
            user: UserInfo {
                uid: 0,
                gid: 0,
                username: "root".to_string(),
                groups: vec![0],
                is_root: true,
            },
            state: ProcessState::Running,
            cpu_usage: 0.1,
            memory_usage: 10_000_000,
            memory_percent: 0.5,
            threads: 1,
            open_files: 50,
            network_connections: 0,
            start_time: SystemTime::now() - Duration::from_secs(86400),
            cwd: "/".to_string(),
            env: HashMap::new(),
            capabilities: vec![],
            seccomp_mode: SeccompMode::Disabled,
            namespace_ids: NamespaceIds::default(),
        },
        ProcessInfo {
            pid: 1234,
            ppid: 1,
            name: "nginx".to_string(),
            exe_path: "/usr/sbin/nginx".to_string(),
            cmdline: vec![
                "nginx".to_string(),
                "-g".to_string(),
                "daemon off;".to_string(),
            ],
            user: UserInfo {
                uid: 33,
                gid: 33,
                username: "www-data".to_string(),
                groups: vec![33],
                is_root: false,
            },
            state: ProcessState::Running,
            cpu_usage: 2.5,
            memory_usage: 50_000_000,
            memory_percent: 2.5,
            threads: 4,
            open_files: 100,
            network_connections: 50,
            start_time: SystemTime::now() - Duration::from_secs(3600),
            cwd: "/var/www".to_string(),
            env: HashMap::new(),
            capabilities: vec![Capability::CapNetBindService],
            seccomp_mode: SeccompMode::Filter,
            namespace_ids: NamespaceIds::default(),
        },
        ProcessInfo {
            pid: 5678,
            ppid: 1234,
            name: "xmrig".to_string(),
            exe_path: "/tmp/xmrig".to_string(),
            cmdline: vec![
                "xmrig".to_string(),
                "-o".to_string(),
                "stratum+tcp://pool.example.com:3333".to_string(),
            ],
            user: UserInfo {
                uid: 33,
                gid: 33,
                username: "www-data".to_string(),
                groups: vec![33],
                is_root: false,
            },
            state: ProcessState::Running,
            cpu_usage: 95.0,
            memory_usage: 200_000_000,
            memory_percent: 10.0,
            threads: 8,
            open_files: 20,
            network_connections: 5,
            start_time: SystemTime::now() - Duration::from_secs(300),
            cwd: "/tmp".to_string(),
            env: HashMap::new(),
            capabilities: vec![],
            seccomp_mode: SeccompMode::Disabled,
            namespace_ids: NamespaceIds::default(),
        },
        ProcessInfo {
            pid: 9999,
            ppid: 1,
            name: "suspicious".to_string(),
            exe_path: "/dev/shm/suspicious".to_string(),
            cmdline: vec!["bash".to_string(), "-i".to_string()],
            user: UserInfo {
                uid: 0,
                gid: 0,
                username: "root".to_string(),
                groups: vec![0],
                is_root: true,
            },
            state: ProcessState::Running,
            cpu_usage: 1.0,
            memory_usage: 5_000_000,
            memory_percent: 0.25,
            threads: 1,
            open_files: 10,
            network_connections: 1,
            start_time: SystemTime::now() - Duration::from_secs(60),
            cwd: "/tmp".to_string(),
            env: HashMap::new(),
            capabilities: vec![Capability::CapSysAdmin, Capability::CapSysPtrace],
            seccomp_mode: SeccompMode::Disabled,
            namespace_ids: NamespaceIds::default(),
        },
    ];

    // Analyze each process
    println!("1. Process Analysis");
    println!("─────────────────────────────────────────────────────────────────────────");

    for process in &processes {
        println!("\n  Analyzing: {} (PID: {})", process.name, process.pid);
        println!("    Path: {}", process.exe_path);
        println!(
            "    User: {} (UID: {})",
            process.user.username, process.user.uid
        );
        println!(
            "    CPU: {:.1}%, Memory: {:.1}%",
            process.cpu_usage, process.memory_percent
        );

        let alerts = monitor.analyze_process(process);

        if alerts.is_empty() {
            println!("    Status: ✓ OK");
        } else {
            println!("    Status: ⚠️  {} alert(s)", alerts.len());
            for alert in &alerts {
                println!(
                    "      [{:?}] {} - {}",
                    alert.severity,
                    alert.alert_type.default_severity(),
                    alert.description
                );
            }
        }

        // Update baseline
        monitor.update_baseline(process);
    }
    println!();

    // Process tree analysis
    println!("2. Process Tree Analysis");
    println!("─────────────────────────────────────────────────────────────────────────");

    let tree = ProcessTreeAnalyzer::build_tree(&processes);
    let findings = ProcessTreeAnalyzer::detect_suspicious_relationships(&tree);

    if findings.is_empty() {
        println!("  ✓ No suspicious process relationships detected");
    } else {
        println!("  ⚠️  Suspicious relationships found:");
        for finding in &findings {
            println!("    - {}", finding);
        }
    }
    println!();

    // Alert summary
    println!("3. Security Alerts Summary");
    println!("─────────────────────────────────────────────────────────────────────────");

    let all_alerts = monitor.get_alerts(None);

    if all_alerts.is_empty() {
        println!("  ✓ No security alerts");
    } else {
        println!("  Total alerts: {}\n", all_alerts.len());

        for alert in &all_alerts {
            let icon = match alert.severity {
                AlertSeverity::Critical => "🔴",
                AlertSeverity::High => "🟠",
                AlertSeverity::Medium => "🟡",
                AlertSeverity::Low => "🔵",
                AlertSeverity::Info => "⚪",
            };

            println!("  {} [{:8}] {:?}", icon, alert.severity, alert.alert_type);
            println!("      PID: {} - {}", alert.process.pid, alert.process.name);
            println!("      {}", alert.description);
            println!("      Action: {}", alert.recommended_action);
            println!();
        }
    }

    // Statistics
    println!("4. Monitoring Statistics");
    println!("─────────────────────────────────────────────────────────────────────────");

    let stats = monitor.get_stats();

    println!("  Processes monitored: {}", processes.len());
    println!("  Total alerts: {}", stats.total_alerts);
    println!("  Baselines collected: {}", stats.baselines_count);
    println!();

    println!("  Alerts by severity:");
    for severity in [
        AlertSeverity::Critical,
        AlertSeverity::High,
        AlertSeverity::Medium,
        AlertSeverity::Low,
        AlertSeverity::Info,
    ] {
        if let Some(&count) = stats.alerts_by_severity.get(&severity) {
            println!("    {}: {}", severity, count);
        }
    }

    println!("\n=== Process Monitor Demo Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_process(name: &str, pid: u32, is_root: bool) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: 1,
            name: name.to_string(),
            exe_path: format!("/usr/bin/{}", name),
            cmdline: vec![name.to_string()],
            user: UserInfo {
                uid: if is_root { 0 } else { 1000 },
                gid: if is_root { 0 } else { 1000 },
                username: if is_root {
                    "root".to_string()
                } else {
                    "user".to_string()
                },
                groups: vec![if is_root { 0 } else { 1000 }],
                is_root,
            },
            state: ProcessState::Running,
            cpu_usage: 1.0,
            memory_usage: 10_000_000,
            memory_percent: 0.5,
            threads: 1,
            open_files: 10,
            network_connections: 0,
            start_time: SystemTime::now(),
            cwd: "/".to_string(),
            env: HashMap::new(),
            capabilities: vec![],
            seccomp_mode: SeccompMode::Filter,
            namespace_ids: NamespaceIds::default(),
        }
    }

    #[test]
    fn test_blocked_process_detection() {
        let monitor = ProcessMonitor::new(MonitorConfig::default(), SecurityPolicy::default());

        let process = create_test_process("xmrig", 1234, false);
        let alerts = monitor.analyze_process(&process);

        assert!(alerts
            .iter()
            .any(|a| matches!(a.alert_type, AlertType::UnauthorizedProcess)));
    }

    #[test]
    fn test_root_process_detection() {
        let mut policy = SecurityPolicy::default();
        policy.allow_root_processes = false;
        let monitor = ProcessMonitor::new(MonitorConfig::default(), policy);

        let process = create_test_process("suspicious", 1234, true);
        let alerts = monitor.analyze_process(&process);

        assert!(alerts
            .iter()
            .any(|a| matches!(a.alert_type, AlertType::PrivilegeEscalation)));
    }

    #[test]
    fn test_dangerous_capability_detection() {
        let monitor = ProcessMonitor::new(MonitorConfig::default(), SecurityPolicy::default());

        let mut process = create_test_process("test", 1234, false);
        process.capabilities = vec![Capability::CapSysAdmin];

        let alerts = monitor.analyze_process(&process);

        assert!(alerts
            .iter()
            .any(|a| matches!(a.alert_type, AlertType::SuspiciousCapability)));
    }

    #[test]
    fn test_resource_abuse_detection() {
        let monitor = ProcessMonitor::new(MonitorConfig::default(), SecurityPolicy::default());

        let mut process = create_test_process("test", 1234, false);
        process.cpu_usage = 99.0;

        let alerts = monitor.analyze_process(&process);

        assert!(alerts
            .iter()
            .any(|a| matches!(a.alert_type, AlertType::ResourceAbuse)));
    }

    #[test]
    fn test_cryptomining_detection() {
        let monitor = ProcessMonitor::new(MonitorConfig::default(), SecurityPolicy::default());

        let mut process = create_test_process("miner", 1234, false);
        process.cmdline = vec![
            "miner".to_string(),
            "-o".to_string(),
            "stratum+tcp://pool.com:3333".to_string(),
        ];

        assert!(monitor.detect_cryptomining(&process));
    }

    #[test]
    fn test_reverse_shell_detection() {
        let monitor = ProcessMonitor::new(MonitorConfig::default(), SecurityPolicy::default());

        let mut process = create_test_process("bash", 1234, false);
        process.cmdline = vec!["bash".to_string(), "-i".to_string()];

        assert!(monitor.detect_reverse_shell(&process));
    }

    #[test]
    fn test_process_tree_building() {
        let processes = vec![
            create_test_process("init", 1, true),
            {
                let mut p = create_test_process("nginx", 100, false);
                p.ppid = 1;
                p
            },
            {
                let mut p = create_test_process("worker", 101, false);
                p.ppid = 100;
                p
            },
        ];

        let tree = ProcessTreeAnalyzer::build_tree(&processes);
        assert!(!tree.is_empty());
    }

    #[test]
    fn test_capability_is_dangerous() {
        assert!(Capability::CapSysAdmin.is_dangerous());
        assert!(Capability::CapSysPtrace.is_dangerous());
        assert!(!Capability::CapNetBindService.is_dangerous());
    }

    #[test]
    fn test_alert_severity_ordering() {
        assert!(AlertSeverity::Critical > AlertSeverity::High);
        assert!(AlertSeverity::High > AlertSeverity::Medium);
        assert!(AlertSeverity::Medium > AlertSeverity::Low);
        assert!(AlertSeverity::Low > AlertSeverity::Info);
    }

    #[test]
    fn test_baseline_update() {
        let monitor = ProcessMonitor::new(MonitorConfig::default(), SecurityPolicy::default());
        let process = create_test_process("test", 1234, false);

        monitor.update_baseline(&process);
        monitor.update_baseline(&process);

        let baselines = monitor.baselines.read().unwrap();
        let baseline = baselines.get("test").unwrap();
        assert_eq!(baseline.sample_count, 2);
    }
}
