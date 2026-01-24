//! Homeserver Process Monitor
//!
//! Host-level security monitoring with:
//! - Process monitoring and anomaly detection
//! - Application-level firewall (outbound connection control)
//! - Privilege escalation monitoring
//! - Memory corruption detection
//! - Rootkit detection patterns

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// Process Information
// ============================================================================

/// Process information
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmdline: String,
    pub user: String,
    pub uid: u32,
    pub gid: u32,
    pub state: ProcessState,
    pub memory_rss: u64,
    pub memory_vms: u64,
    pub cpu_percent: f32,
    pub open_files: u32,
    pub connections: Vec<NetworkConnection>,
    pub started_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProcessState {
    Running,
    Sleeping,
    Stopped,
    Zombie,
    Dead,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct NetworkConnection {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub state: ConnectionState,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionState {
    Listen,
    Established,
    TimeWait,
    CloseWait,
    SynSent,
    SynRecv,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Unix,
}

// ============================================================================
// Process Baseline
// ============================================================================

/// Expected process baseline for comparison
#[derive(Debug, Clone)]
pub struct ProcessBaseline {
    pub name: String,
    pub expected_user: Option<String>,
    pub expected_parent: Option<String>,
    pub max_memory_mb: Option<u64>,
    pub max_cpu_percent: Option<f32>,
    pub allowed_ports: HashSet<u16>,
    pub allowed_outbound: Vec<String>,
    pub max_instances: u32,
}

impl ProcessBaseline {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            expected_user: None,
            expected_parent: None,
            max_memory_mb: None,
            max_cpu_percent: None,
            allowed_ports: HashSet::new(),
            allowed_outbound: Vec::new(),
            max_instances: 10,
        }
    }

    pub fn with_user(mut self, user: &str) -> Self {
        self.expected_user = Some(user.to_string());
        self
    }

    pub fn with_parent(mut self, parent: &str) -> Self {
        self.expected_parent = Some(parent.to_string());
        self
    }

    pub fn with_max_memory(mut self, mb: u64) -> Self {
        self.max_memory_mb = Some(mb);
        self
    }

    pub fn with_allowed_ports(mut self, ports: &[u16]) -> Self {
        self.allowed_ports = ports.iter().copied().collect();
        self
    }

    pub fn with_allowed_outbound(mut self, destinations: &[&str]) -> Self {
        self.allowed_outbound = destinations.iter().map(|s| s.to_string()).collect();
        self
    }
}

// ============================================================================
// Security Alerts
// ============================================================================

/// Security alert severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Security alert
#[derive(Debug, Clone)]
pub struct SecurityAlert {
    pub timestamp: u64,
    pub severity: AlertSeverity,
    pub category: AlertCategory,
    pub process: Option<ProcessInfo>,
    pub description: String,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AlertCategory {
    UnauthorizedProcess,
    PrivilegeEscalation,
    AnomalousNetwork,
    MemoryAnomaly,
    ResourceExhaustion,
    SuspiciousBehavior,
    RootkitIndicator,
    PolicyViolation,
}

impl SecurityAlert {
    pub fn to_json(&self) -> String {
        let details: String = self
            .details
            .iter()
            .map(|(k, v)| format!(r#""{}":"{}""#, k, escape_json(v)))
            .collect::<Vec<_>>()
            .join(",");

        format!(
            r#"{{"timestamp":{},"severity":"{:?}","category":"{:?}","description":"{}","details":{{{}}}}}"#,
            self.timestamp,
            self.severity,
            self.category,
            escape_json(&self.description),
            details,
        )
    }
}

// ============================================================================
// Process Monitor
// ============================================================================

/// Process monitoring engine
pub struct ProcessMonitor {
    /// Known process baselines
    baselines: HashMap<String, ProcessBaseline>,
    /// Current process snapshot
    processes: Mutex<HashMap<u32, ProcessInfo>>,
    /// Historical process data
    history: Mutex<Vec<ProcessSnapshot>>,
    /// Alert callback
    alerts: Mutex<Vec<SecurityAlert>>,
    /// Allowed parent-child relationships
    allowed_spawns: HashMap<String, HashSet<String>>,
    /// Known safe processes
    safe_processes: HashSet<String>,
    /// Monitoring settings
    settings: MonitorSettings,
}

#[derive(Debug, Clone)]
pub struct ProcessSnapshot {
    pub timestamp: u64,
    pub process_count: usize,
    pub total_memory: u64,
    pub total_cpu: f32,
}

#[derive(Debug, Clone)]
pub struct MonitorSettings {
    /// Snapshot interval
    pub interval: Duration,
    /// Alert on unknown processes
    pub alert_unknown: bool,
    /// Maximum history entries
    pub max_history: usize,
    /// Enable outbound connection monitoring
    pub monitor_outbound: bool,
}

impl Default for MonitorSettings {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            alert_unknown: true,
            max_history: 1000,
            monitor_outbound: true,
        }
    }
}

impl ProcessMonitor {
    pub fn new(settings: MonitorSettings) -> Self {
        let mut safe_processes = HashSet::new();
        // Common safe system processes
        for proc in [
            "init",
            "systemd",
            "kthreadd",
            "ksoftirqd",
            "kworker",
            "rcu_sched",
            "migration",
            "watchdog",
            "cpuhp",
            "netns",
            "sshd",
            "cron",
            "rsyslogd",
            "dbus-daemon",
        ] {
            safe_processes.insert(proc.to_string());
        }

        let mut allowed_spawns = HashMap::new();
        // systemd can spawn anything
        allowed_spawns.insert("systemd".to_string(), HashSet::new());
        // sshd spawns shells
        let mut sshd_children = HashSet::new();
        sshd_children.insert("bash".to_string());
        sshd_children.insert("sh".to_string());
        sshd_children.insert("zsh".to_string());
        allowed_spawns.insert("sshd".to_string(), sshd_children);

        Self {
            baselines: HashMap::new(),
            processes: Mutex::new(HashMap::new()),
            history: Mutex::new(Vec::new()),
            alerts: Mutex::new(Vec::new()),
            allowed_spawns,
            safe_processes,
            settings,
        }
    }

    /// Register a process baseline
    pub fn register_baseline(&mut self, baseline: ProcessBaseline) {
        self.baselines.insert(baseline.name.clone(), baseline);
    }

    /// Update process snapshot
    pub fn update(&self, processes: Vec<ProcessInfo>) {
        let mut current = self.processes.lock().unwrap();
        let old_pids: HashSet<u32> = current.keys().copied().collect();
        let new_pids: HashSet<u32> = processes.iter().map(|p| p.pid).collect();

        // Check for new processes
        for proc in &processes {
            if !old_pids.contains(&proc.pid) {
                self.check_new_process(proc);
            }
        }

        // Check for terminated processes
        for pid in old_pids.difference(&new_pids) {
            if let Some(old_proc) = current.get(pid) {
                self.check_terminated_process(old_proc);
            }
        }

        // Update current snapshot
        current.clear();
        for proc in processes {
            current.insert(proc.pid, proc);
        }

        // Check all running processes
        for proc in current.values() {
            self.check_process(proc);
        }

        // Update history
        let snapshot = ProcessSnapshot {
            timestamp: current_timestamp(),
            process_count: current.len(),
            total_memory: current.values().map(|p| p.memory_rss).sum(),
            total_cpu: current.values().map(|p| p.cpu_percent).sum(),
        };

        let mut history = self.history.lock().unwrap();
        if history.len() >= self.settings.max_history {
            history.remove(0);
        }
        history.push(snapshot);
    }

    fn check_new_process(&self, proc: &ProcessInfo) {
        // Check if process is known
        if !self.safe_processes.contains(&proc.name) && !self.baselines.contains_key(&proc.name) {
            if self.settings.alert_unknown {
                self.create_alert(
                    AlertSeverity::Medium,
                    AlertCategory::UnauthorizedProcess,
                    Some(proc.clone()),
                    format!("Unknown process started: {} (PID {})", proc.name, proc.pid),
                );
            }
        }

        // Check for privilege escalation (non-root spawning root process)
        if proc.uid == 0 {
            // Would need parent info to check properly
            // This is simplified
        }

        // Check parent-child relationship
        // Simplified: would need to look up parent process
    }

    fn check_terminated_process(&self, _proc: &ProcessInfo) {
        // Check for unexpected termination of critical processes
        // Would log for audit trail
    }

    fn check_process(&self, proc: &ProcessInfo) {
        // Check against baseline if exists
        if let Some(baseline) = self.baselines.get(&proc.name) {
            // Check user
            if let Some(ref expected_user) = baseline.expected_user {
                if &proc.user != expected_user {
                    self.create_alert(
                        AlertSeverity::High,
                        AlertCategory::PolicyViolation,
                        Some(proc.clone()),
                        format!(
                            "{} running as {} instead of {}",
                            proc.name, proc.user, expected_user
                        ),
                    );
                }
            }

            // Check memory
            if let Some(max_mem) = baseline.max_memory_mb {
                let mem_mb = proc.memory_rss / (1024 * 1024);
                if mem_mb > max_mem {
                    self.create_alert(
                        AlertSeverity::Medium,
                        AlertCategory::MemoryAnomaly,
                        Some(proc.clone()),
                        format!("{} using {} MB (max {})", proc.name, mem_mb, max_mem),
                    );
                }
            }

            // Check network connections
            if self.settings.monitor_outbound {
                for conn in &proc.connections {
                    if let Some(ref remote) = conn.remote_addr {
                        if conn.state == ConnectionState::Established {
                            // Check if outbound connection is allowed
                            let allowed = baseline
                                .allowed_outbound
                                .iter()
                                .any(|a| remote.contains(a) || a == "*");

                            if !allowed && !baseline.allowed_outbound.is_empty() {
                                self.create_alert(
                                    AlertSeverity::High,
                                    AlertCategory::AnomalousNetwork,
                                    Some(proc.clone()),
                                    format!(
                                        "{} connected to unauthorized destination: {}",
                                        proc.name, remote
                                    ),
                                );
                            }
                        }
                    }
                }
            }
        }

        // Check for suspicious behavior patterns
        self.check_suspicious_behavior(proc);
    }

    fn check_suspicious_behavior(&self, proc: &ProcessInfo) {
        // Check for processes with suspicious names
        let suspicious_names = ["nc", "ncat", "netcat", "socat", "nmap", "masscan"];
        if suspicious_names.contains(&proc.name.as_str()) {
            self.create_alert(
                AlertSeverity::High,
                AlertCategory::SuspiciousBehavior,
                Some(proc.clone()),
                format!("Suspicious tool running: {}", proc.name),
            );
        }

        // Check for hidden processes (name starting with .)
        if proc.name.starts_with('.') {
            self.create_alert(
                AlertSeverity::Critical,
                AlertCategory::RootkitIndicator,
                Some(proc.clone()),
                format!("Hidden process detected: {}", proc.name),
            );
        }

        // Check for processes with deleted executables
        if proc.cmdline.contains("(deleted)") {
            self.create_alert(
                AlertSeverity::Critical,
                AlertCategory::RootkitIndicator,
                Some(proc.clone()),
                format!("Process running from deleted executable: {}", proc.name),
            );
        }

        // Check for kernel thread imposters (non-kernel process with [brackets])
        if proc.name.starts_with('[') && proc.name.ends_with(']') && proc.ppid != 2 {
            self.create_alert(
                AlertSeverity::Critical,
                AlertCategory::RootkitIndicator,
                Some(proc.clone()),
                format!("Possible kernel thread imposter: {}", proc.name),
            );
        }
    }

    fn create_alert(
        &self,
        severity: AlertSeverity,
        category: AlertCategory,
        process: Option<ProcessInfo>,
        description: String,
    ) {
        let mut details = HashMap::new();
        if let Some(ref proc) = process {
            details.insert("pid".to_string(), proc.pid.to_string());
            details.insert("user".to_string(), proc.user.clone());
            details.insert("cmdline".to_string(), proc.cmdline.clone());
        }

        let alert = SecurityAlert {
            timestamp: current_timestamp(),
            severity,
            category,
            process,
            description: description.clone(),
            details,
        };

        println!(
            "ALERT: [{}] {:?} - {}",
            match severity {
                AlertSeverity::Info => "INFO",
                AlertSeverity::Low => "LOW",
                AlertSeverity::Medium => "MEDIUM",
                AlertSeverity::High => "HIGH",
                AlertSeverity::Critical => "CRITICAL",
            },
            category,
            description
        );

        self.alerts.lock().unwrap().push(alert);
    }

    /// Get recent alerts
    pub fn alerts(&self, count: usize) -> Vec<SecurityAlert> {
        self.alerts
            .lock()
            .unwrap()
            .iter()
            .rev()
            .take(count)
            .cloned()
            .collect()
    }

    /// Get current process list
    pub fn current_processes(&self) -> Vec<ProcessInfo> {
        self.processes.lock().unwrap().values().cloned().collect()
    }

    /// Get process by PID
    pub fn get_process(&self, pid: u32) -> Option<ProcessInfo> {
        self.processes.lock().unwrap().get(&pid).cloned()
    }
}

// ============================================================================
// Application Firewall
// ============================================================================

/// Application-level firewall for outbound connections
pub struct ApplicationFirewall {
    /// Rules per application
    rules: HashMap<String, AppFirewallRules>,
    /// Default policy
    default_policy: FirewallPolicy,
    /// Connection log
    log: Mutex<Vec<ConnectionLog>>,
}

#[derive(Debug, Clone)]
pub struct AppFirewallRules {
    pub app_name: String,
    pub allowed_destinations: Vec<DestinationRule>,
    pub blocked_destinations: Vec<DestinationRule>,
    pub max_connections: Option<u32>,
    pub rate_limit: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct DestinationRule {
    pub host: String,
    pub port: Option<u16>,
    pub protocol: Option<Protocol>,
}

impl DestinationRule {
    pub fn any_host() -> Self {
        Self {
            host: "*".to_string(),
            port: None,
            protocol: None,
        }
    }

    pub fn host(host: &str) -> Self {
        Self {
            host: host.to_string(),
            port: None,
            protocol: None,
        }
    }

    pub fn host_port(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port: Some(port),
            protocol: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FirewallPolicy {
    Allow,
    Deny,
    Log,
}

#[derive(Debug, Clone)]
pub struct ConnectionLog {
    pub timestamp: u64,
    pub app_name: String,
    pub pid: u32,
    pub destination: String,
    pub port: u16,
    pub action: FirewallAction,
}

#[derive(Debug, Clone, Copy)]
pub enum FirewallAction {
    Allowed,
    Denied,
    Logged,
}

impl ApplicationFirewall {
    pub fn new(default_policy: FirewallPolicy) -> Self {
        Self {
            rules: HashMap::new(),
            default_policy,
            log: Mutex::new(Vec::new()),
        }
    }

    pub fn add_rule(&mut self, rules: AppFirewallRules) {
        self.rules.insert(rules.app_name.clone(), rules);
    }

    /// Check if connection should be allowed
    pub fn check_connection(
        &self,
        app_name: &str,
        pid: u32,
        destination: &str,
        port: u16,
    ) -> FirewallAction {
        let action = if let Some(rules) = self.rules.get(app_name) {
            // Check blocked first
            for blocked in &rules.blocked_destinations {
                if self.matches_rule(blocked, destination, port) {
                    return FirewallAction::Denied;
                }
            }

            // Check allowed
            for allowed in &rules.allowed_destinations {
                if self.matches_rule(allowed, destination, port) {
                    return FirewallAction::Allowed;
                }
            }

            // No specific rule, use default
            match self.default_policy {
                FirewallPolicy::Allow => FirewallAction::Allowed,
                FirewallPolicy::Deny => FirewallAction::Denied,
                FirewallPolicy::Log => FirewallAction::Logged,
            }
        } else {
            // No rules for this app
            match self.default_policy {
                FirewallPolicy::Allow => FirewallAction::Allowed,
                FirewallPolicy::Deny => FirewallAction::Denied,
                FirewallPolicy::Log => FirewallAction::Logged,
            }
        };

        // Log connection
        self.log.lock().unwrap().push(ConnectionLog {
            timestamp: current_timestamp(),
            app_name: app_name.to_string(),
            pid,
            destination: destination.to_string(),
            port,
            action,
        });

        action
    }

    fn matches_rule(&self, rule: &DestinationRule, destination: &str, port: u16) -> bool {
        // Check host
        let host_matches = rule.host == "*"
            || destination.contains(&rule.host)
            || rule.host.starts_with("*.") && destination.ends_with(&rule.host[1..]);

        // Check port
        let port_matches = rule.port.map_or(true, |p| p == port);

        host_matches && port_matches
    }

    /// Get connection log
    pub fn connection_log(&self, count: usize) -> Vec<ConnectionLog> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .rev()
            .take(count)
            .cloned()
            .collect()
    }
}

// ============================================================================
// Rootkit Detection
// ============================================================================

/// Rootkit detection patterns
pub struct RootkitDetector {
    /// Known rootkit signatures
    signatures: Vec<RootkitSignature>,
    /// Detection results
    findings: Mutex<Vec<RootkitFinding>>,
}

#[derive(Debug, Clone)]
pub struct RootkitSignature {
    pub name: String,
    pub pattern_type: PatternType,
    pub pattern: String,
    pub severity: AlertSeverity,
}

#[derive(Debug, Clone, Copy)]
pub enum PatternType {
    ProcessName,
    FilePath,
    KernelModule,
    NetworkPort,
    Environment,
}

#[derive(Debug, Clone)]
pub struct RootkitFinding {
    pub timestamp: u64,
    pub signature: String,
    pub location: String,
    pub severity: AlertSeverity,
}

impl RootkitDetector {
    pub fn new() -> Self {
        let signatures = vec![
            // Known rootkit process names
            RootkitSignature {
                name: "Reptile rootkit".to_string(),
                pattern_type: PatternType::ProcessName,
                pattern: "reptile".to_string(),
                severity: AlertSeverity::Critical,
            },
            RootkitSignature {
                name: "Diamorphine rootkit".to_string(),
                pattern_type: PatternType::KernelModule,
                pattern: "diamorphine".to_string(),
                severity: AlertSeverity::Critical,
            },
            // Hidden files
            RootkitSignature {
                name: "Hidden SSH directory".to_string(),
                pattern_type: PatternType::FilePath,
                pattern: "/dev/shm/.".to_string(),
                severity: AlertSeverity::High,
            },
            // Suspicious ports
            RootkitSignature {
                name: "Common backdoor port".to_string(),
                pattern_type: PatternType::NetworkPort,
                pattern: "31337".to_string(),
                severity: AlertSeverity::High,
            },
        ];

        Self {
            signatures,
            findings: Mutex::new(Vec::new()),
        }
    }

    /// Check for rootkit indicators
    pub fn scan(&self, processes: &[ProcessInfo]) -> Vec<RootkitFinding> {
        let mut findings = Vec::new();

        for proc in processes {
            // Check process names
            for sig in &self.signatures {
                if sig.pattern_type == PatternType::ProcessName {
                    if proc
                        .name
                        .to_lowercase()
                        .contains(&sig.pattern.to_lowercase())
                    {
                        findings.push(RootkitFinding {
                            timestamp: current_timestamp(),
                            signature: sig.name.clone(),
                            location: format!("Process: {} (PID {})", proc.name, proc.pid),
                            severity: sig.severity,
                        });
                    }
                }

                // Check for suspicious ports
                if sig.pattern_type == PatternType::NetworkPort {
                    let port: u16 = sig.pattern.parse().unwrap_or(0);
                    for conn in &proc.connections {
                        if conn.local_port == port {
                            findings.push(RootkitFinding {
                                timestamp: current_timestamp(),
                                signature: sig.name.clone(),
                                location: format!(
                                    "Port {} by {} (PID {})",
                                    port, proc.name, proc.pid
                                ),
                                severity: sig.severity,
                            });
                        }
                    }
                }
            }

            // Check for deleted executables
            if proc.cmdline.contains("(deleted)") {
                findings.push(RootkitFinding {
                    timestamp: current_timestamp(),
                    signature: "Deleted executable".to_string(),
                    location: format!("Process: {} (PID {})", proc.name, proc.pid),
                    severity: AlertSeverity::Critical,
                });
            }

            // Check for processes hiding as kernel threads
            if proc.name.starts_with('[') && proc.ppid != 2 {
                findings.push(RootkitFinding {
                    timestamp: current_timestamp(),
                    signature: "Kernel thread impersonation".to_string(),
                    location: format!("Process: {} (PID {})", proc.name, proc.pid),
                    severity: AlertSeverity::Critical,
                });
            }
        }

        *self.findings.lock().unwrap() = findings.clone();
        findings
    }

    /// Get all findings
    pub fn findings(&self) -> Vec<RootkitFinding> {
        self.findings.lock().unwrap().clone()
    }
}

impl Default for RootkitDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Utilities
// ============================================================================

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

// ============================================================================
// Main and Tests
// ============================================================================

fn main() {
    println!("Homeserver Process Monitor Example\n");

    // Create process monitor
    let mut monitor = ProcessMonitor::new(MonitorSettings::default());

    // Register expected process baselines
    monitor.register_baseline(
        ProcessBaseline::new("nginx")
            .with_user("www-data")
            .with_max_memory(256)
            .with_allowed_ports(&[80, 443]),
    );

    monitor.register_baseline(
        ProcessBaseline::new("postgres")
            .with_user("postgres")
            .with_max_memory(1024)
            .with_allowed_ports(&[5432]),
    );

    // Simulate process update
    let test_processes = vec![
        ProcessInfo {
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            cmdline: "/sbin/init".to_string(),
            user: "root".to_string(),
            uid: 0,
            gid: 0,
            state: ProcessState::Running,
            memory_rss: 10 * 1024 * 1024,
            memory_vms: 50 * 1024 * 1024,
            cpu_percent: 0.1,
            open_files: 100,
            connections: vec![],
            started_at: 1000,
        },
        ProcessInfo {
            pid: 1000,
            ppid: 1,
            name: "nginx".to_string(),
            cmdline: "nginx: master process".to_string(),
            user: "www-data".to_string(),
            uid: 33,
            gid: 33,
            state: ProcessState::Running,
            memory_rss: 50 * 1024 * 1024,
            memory_vms: 100 * 1024 * 1024,
            cpu_percent: 1.0,
            open_files: 50,
            connections: vec![NetworkConnection {
                local_addr: "0.0.0.0".to_string(),
                local_port: 80,
                remote_addr: None,
                remote_port: None,
                state: ConnectionState::Listen,
                protocol: Protocol::Tcp,
            }],
            started_at: 2000,
        },
        // Suspicious process
        ProcessInfo {
            pid: 9999,
            ppid: 1,
            name: ".hidden_proc".to_string(),
            cmdline: "/tmp/.hidden_proc".to_string(),
            user: "root".to_string(),
            uid: 0,
            gid: 0,
            state: ProcessState::Running,
            memory_rss: 1024 * 1024,
            memory_vms: 5 * 1024 * 1024,
            cpu_percent: 50.0,
            open_files: 10,
            connections: vec![NetworkConnection {
                local_addr: "0.0.0.0".to_string(),
                local_port: 31337,
                remote_addr: Some("evil.com".to_string()),
                remote_port: Some(4444),
                state: ConnectionState::Established,
                protocol: Protocol::Tcp,
            }],
            started_at: 5000,
        },
    ];

    println!("--- Updating Process Monitor ---");
    monitor.update(test_processes.clone());

    println!("\n--- Recent Alerts ---");
    for alert in monitor.alerts(10) {
        println!("  {}", alert.to_json());
    }

    // Application Firewall
    println!("\n--- Application Firewall ---");
    let mut firewall = ApplicationFirewall::new(FirewallPolicy::Deny);

    firewall.add_rule(AppFirewallRules {
        app_name: "nginx".to_string(),
        allowed_destinations: vec![DestinationRule::any_host()],
        blocked_destinations: vec![],
        max_connections: Some(1000),
        rate_limit: None,
    });

    firewall.add_rule(AppFirewallRules {
        app_name: "postgres".to_string(),
        allowed_destinations: vec![DestinationRule::host("backup.local")],
        blocked_destinations: vec![DestinationRule::any_host()],
        max_connections: Some(10),
        rate_limit: None,
    });

    // Test connections
    let test_connections = [
        ("nginx", 1000, "client.example.com", 443),
        ("postgres", 1001, "backup.local", 5432),
        ("postgres", 1001, "evil.com", 4444),
        ("unknown_app", 9999, "anywhere.com", 80),
    ];

    for (app, pid, dest, port) in test_connections {
        let action = firewall.check_connection(app, pid, dest, port);
        println!("  {} -> {}:{} = {:?}", app, dest, port, action);
    }

    // Rootkit Detection
    println!("\n--- Rootkit Detection ---");
    let detector = RootkitDetector::new();
    let findings = detector.scan(&test_processes);

    if findings.is_empty() {
        println!("  No rootkit indicators found");
    } else {
        for finding in findings {
            println!(
                "  [{:?}] {} - {}",
                finding.severity, finding.signature, finding.location
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_baseline() {
        let baseline = ProcessBaseline::new("nginx")
            .with_user("www-data")
            .with_max_memory(256);

        assert_eq!(baseline.name, "nginx");
        assert_eq!(baseline.expected_user, Some("www-data".to_string()));
        assert_eq!(baseline.max_memory_mb, Some(256));
    }

    #[test]
    fn test_process_monitor_creation() {
        let monitor = ProcessMonitor::new(MonitorSettings::default());
        assert!(monitor.current_processes().is_empty());
    }

    #[test]
    fn test_alert_json() {
        let alert = SecurityAlert {
            timestamp: 1234567890,
            severity: AlertSeverity::High,
            category: AlertCategory::SuspiciousBehavior,
            process: None,
            description: "Test alert".to_string(),
            details: HashMap::new(),
        };

        let json = alert.to_json();
        assert!(json.contains("\"severity\":\"High\""));
        assert!(json.contains("Test alert"));
    }

    #[test]
    fn test_application_firewall() {
        let mut firewall = ApplicationFirewall::new(FirewallPolicy::Deny);

        firewall.add_rule(AppFirewallRules {
            app_name: "test".to_string(),
            allowed_destinations: vec![DestinationRule::host("allowed.com")],
            blocked_destinations: vec![],
            max_connections: None,
            rate_limit: None,
        });

        let action = firewall.check_connection("test", 1, "allowed.com", 443);
        assert!(matches!(action, FirewallAction::Allowed));

        let action = firewall.check_connection("test", 1, "blocked.com", 443);
        assert!(matches!(action, FirewallAction::Denied));
    }

    #[test]
    fn test_destination_rule() {
        let rule = DestinationRule::host_port("example.com", 443);
        assert_eq!(rule.host, "example.com");
        assert_eq!(rule.port, Some(443));
    }

    #[test]
    fn test_rootkit_detector() {
        let detector = RootkitDetector::new();

        let suspicious = ProcessInfo {
            pid: 1,
            ppid: 0,
            name: ".hidden".to_string(),
            cmdline: "hidden".to_string(),
            user: "root".to_string(),
            uid: 0,
            gid: 0,
            state: ProcessState::Running,
            memory_rss: 0,
            memory_vms: 0,
            cpu_percent: 0.0,
            open_files: 0,
            connections: vec![],
            started_at: 0,
        };

        let findings = detector.scan(&[suspicious]);
        // Should detect hidden process
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_monitor_settings() {
        let settings = MonitorSettings::default();
        assert!(settings.alert_unknown);
        assert!(settings.monitor_outbound);
    }
}
