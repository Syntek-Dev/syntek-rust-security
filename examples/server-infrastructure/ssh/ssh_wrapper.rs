//! SSH Wrapper - Secure Access Management and Logging
//!
//! This example demonstrates building a comprehensive SSH wrapper for
//! access management, command filtering, and detailed audit logging.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// SSH session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Connecting,
    Authenticating,
    Authenticated,
    Active,
    Terminated,
}

/// Authentication method
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    Password,
    PublicKey { fingerprint: String },
    Certificate { serial: String },
    Keyboard,
    MultiFactor { methods: Vec<String> },
}

/// SSH session information
#[derive(Debug, Clone)]
pub struct SshSession {
    pub id: String,
    pub user: String,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub auth_method: Option<AuthMethod>,
    pub state: SessionState,
    pub started_at: u64,
    pub last_activity: u64,
    pub commands_executed: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub terminal_type: Option<String>,
}

impl SshSession {
    pub fn new(user: String, remote_ip: IpAddr, remote_port: u16) -> Self {
        let now = current_timestamp();
        Self {
            id: generate_session_id(),
            user,
            remote_ip,
            remote_port,
            auth_method: None,
            state: SessionState::Connecting,
            started_at: now,
            last_activity: now,
            commands_executed: 0,
            bytes_sent: 0,
            bytes_received: 0,
            terminal_type: None,
        }
    }

    pub fn duration(&self) -> Duration {
        Duration::from_secs(current_timestamp() - self.started_at)
    }
}

/// Command filter rule
#[derive(Debug, Clone)]
pub struct CommandRule {
    pub pattern: String,
    pub action: RuleAction,
    pub log_level: LogLevel,
    pub notify: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Deny,
    RequireConfirmation,
    Log,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Critical,
}

/// Access control policy
#[derive(Debug, Clone)]
pub struct AccessPolicy {
    pub allowed_users: HashSet<String>,
    pub allowed_ips: Vec<IpRange>,
    pub allowed_commands: Vec<CommandRule>,
    pub denied_commands: Vec<CommandRule>,
    pub max_session_duration: Duration,
    pub idle_timeout: Duration,
    pub require_mfa: bool,
    pub allowed_auth_methods: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct IpRange {
    pub network: IpAddr,
    pub prefix_len: u8,
}

impl IpRange {
    pub fn contains(&self, ip: &IpAddr) -> bool {
        // Simplified - in production use proper CIDR matching
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(target)) => {
                let net_bits = u32::from(net);
                let target_bits = u32::from(*target);
                let mask = !((1u32 << (32 - self.prefix_len)) - 1);
                (net_bits & mask) == (target_bits & mask)
            }
            _ => false,
        }
    }
}

impl Default for AccessPolicy {
    fn default() -> Self {
        Self {
            allowed_users: HashSet::new(),
            allowed_ips: Vec::new(),
            allowed_commands: Vec::new(),
            denied_commands: vec![
                CommandRule {
                    pattern: "rm -rf /".to_string(),
                    action: RuleAction::Deny,
                    log_level: LogLevel::Critical,
                    notify: true,
                },
                CommandRule {
                    pattern: ":(){ :|:& };:".to_string(), // Fork bomb
                    action: RuleAction::Deny,
                    log_level: LogLevel::Critical,
                    notify: true,
                },
                CommandRule {
                    pattern: "chmod 777".to_string(),
                    action: RuleAction::RequireConfirmation,
                    log_level: LogLevel::Warning,
                    notify: false,
                },
            ],
            max_session_duration: Duration::from_secs(8 * 3600), // 8 hours
            idle_timeout: Duration::from_secs(30 * 60),          // 30 minutes
            require_mfa: false,
            allowed_auth_methods: vec!["publickey".to_string(), "certificate".to_string()],
        }
    }
}

/// Audit log entry
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub session_id: String,
    pub user: String,
    pub remote_ip: IpAddr,
    pub event_type: AuditEventType,
    pub details: String,
    pub level: LogLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEventType {
    ConnectionAttempt,
    AuthSuccess,
    AuthFailure,
    SessionStart,
    SessionEnd,
    CommandExecuted,
    CommandBlocked,
    FileAccess,
    PortForward,
    SftpOperation,
    PolicyViolation,
    Timeout,
}

/// Audit logger trait
pub trait AuditLogger: Send + Sync {
    fn log(&self, entry: AuditEntry);
    fn query(&self, filter: &AuditFilter) -> Vec<AuditEntry>;
}

#[derive(Debug, Default)]
pub struct AuditFilter {
    pub user: Option<String>,
    pub session_id: Option<String>,
    pub event_type: Option<AuditEventType>,
    pub level: Option<LogLevel>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub limit: Option<usize>,
}

/// In-memory audit logger (for demo - use persistent storage in production)
pub struct MemoryAuditLogger {
    entries: RwLock<Vec<AuditEntry>>,
    max_entries: usize,
}

impl MemoryAuditLogger {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            max_entries,
        }
    }
}

impl AuditLogger for MemoryAuditLogger {
    fn log(&self, entry: AuditEntry) {
        let mut entries = self.entries.write().unwrap();
        entries.push(entry);
        if entries.len() > self.max_entries {
            entries.remove(0);
        }
    }

    fn query(&self, filter: &AuditFilter) -> Vec<AuditEntry> {
        let entries = self.entries.read().unwrap();
        entries
            .iter()
            .filter(|e| {
                if let Some(ref user) = filter.user {
                    if &e.user != user {
                        return false;
                    }
                }
                if let Some(ref sid) = filter.session_id {
                    if &e.session_id != sid {
                        return false;
                    }
                }
                if let Some(ref etype) = filter.event_type {
                    if &e.event_type != etype {
                        return false;
                    }
                }
                if let Some(since) = filter.since {
                    if e.timestamp < since {
                        return false;
                    }
                }
                if let Some(until) = filter.until {
                    if e.timestamp > until {
                        return false;
                    }
                }
                true
            })
            .take(filter.limit.unwrap_or(1000))
            .cloned()
            .collect()
    }
}

/// Command execution result
#[derive(Debug, Clone)]
pub struct CommandResult {
    pub command: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub allowed: bool,
    pub reason: Option<String>,
}

/// SSH wrapper error
#[derive(Debug, Clone)]
pub enum SshWrapperError {
    AccessDenied { reason: String },
    CommandBlocked { command: String, reason: String },
    SessionExpired,
    IdleTimeout,
    AuthenticationFailed { method: String },
    PolicyViolation { policy: String },
    InvalidCommand { reason: String },
}

impl std::fmt::Display for SshWrapperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessDenied { reason } => write!(f, "Access denied: {}", reason),
            Self::CommandBlocked { command, reason } => {
                write!(f, "Command '{}' blocked: {}", command, reason)
            }
            Self::SessionExpired => write!(f, "Session expired"),
            Self::IdleTimeout => write!(f, "Idle timeout"),
            Self::AuthenticationFailed { method } => {
                write!(f, "Authentication failed: {}", method)
            }
            Self::PolicyViolation { policy } => write!(f, "Policy violation: {}", policy),
            Self::InvalidCommand { reason } => write!(f, "Invalid command: {}", reason),
        }
    }
}

impl std::error::Error for SshWrapperError {}

/// Main SSH wrapper
pub struct SshWrapper {
    policy: AccessPolicy,
    logger: Arc<dyn AuditLogger>,
    sessions: RwLock<HashMap<String, SshSession>>,
    blocked_ips: RwLock<HashMap<IpAddr, (u64, u32)>>, // IP -> (block_until, attempts)
    max_auth_failures: u32,
    block_duration: Duration,
}

impl SshWrapper {
    pub fn new(policy: AccessPolicy, logger: Arc<dyn AuditLogger>) -> Self {
        Self {
            policy,
            logger,
            sessions: RwLock::new(HashMap::new()),
            blocked_ips: RwLock::new(HashMap::new()),
            max_auth_failures: 5,
            block_duration: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Check if connection is allowed
    pub fn check_connection(&self, user: &str, remote_ip: IpAddr) -> Result<(), SshWrapperError> {
        // Check IP blocklist
        {
            let blocked = self.blocked_ips.read().unwrap();
            if let Some((until, _)) = blocked.get(&remote_ip) {
                if *until > current_timestamp() {
                    return Err(SshWrapperError::AccessDenied {
                        reason: "IP temporarily blocked".to_string(),
                    });
                }
            }
        }

        // Check allowed users
        if !self.policy.allowed_users.is_empty() && !self.policy.allowed_users.contains(user) {
            return Err(SshWrapperError::AccessDenied {
                reason: format!("User '{}' not in allowed list", user),
            });
        }

        // Check allowed IPs
        if !self.policy.allowed_ips.is_empty() {
            let allowed = self
                .policy
                .allowed_ips
                .iter()
                .any(|r| r.contains(&remote_ip));
            if !allowed {
                return Err(SshWrapperError::AccessDenied {
                    reason: format!("IP {} not in allowed range", remote_ip),
                });
            }
        }

        Ok(())
    }

    /// Start a new session
    pub fn start_session(
        &self,
        user: String,
        remote_ip: IpAddr,
        remote_port: u16,
    ) -> Result<SshSession, SshWrapperError> {
        self.check_connection(&user, remote_ip)?;

        let session = SshSession::new(user.clone(), remote_ip, remote_port);
        let session_id = session.id.clone();

        self.logger.log(AuditEntry {
            timestamp: current_timestamp(),
            session_id: session_id.clone(),
            user: user.clone(),
            remote_ip,
            event_type: AuditEventType::ConnectionAttempt,
            details: format!("Connection from {}:{}", remote_ip, remote_port),
            level: LogLevel::Info,
        });

        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(session_id.clone(), session.clone());

        Ok(session)
    }

    /// Authenticate session
    pub fn authenticate(
        &self,
        session_id: &str,
        method: AuthMethod,
    ) -> Result<(), SshWrapperError> {
        let mut sessions = self.sessions.write().unwrap();
        let session = sessions
            .get_mut(session_id)
            .ok_or(SshWrapperError::AccessDenied {
                reason: "Session not found".to_string(),
            })?;

        // Check allowed auth methods
        let method_name = match &method {
            AuthMethod::Password => "password",
            AuthMethod::PublicKey { .. } => "publickey",
            AuthMethod::Certificate { .. } => "certificate",
            AuthMethod::Keyboard => "keyboard-interactive",
            AuthMethod::MultiFactor { .. } => "mfa",
        };

        if !self.policy.allowed_auth_methods.is_empty()
            && !self
                .policy
                .allowed_auth_methods
                .contains(&method_name.to_string())
        {
            self.record_auth_failure(session.remote_ip);
            self.logger.log(AuditEntry {
                timestamp: current_timestamp(),
                session_id: session_id.to_string(),
                user: session.user.clone(),
                remote_ip: session.remote_ip,
                event_type: AuditEventType::AuthFailure,
                details: format!("Auth method '{}' not allowed", method_name),
                level: LogLevel::Warning,
            });
            return Err(SshWrapperError::AuthenticationFailed {
                method: method_name.to_string(),
            });
        }

        // Check MFA requirement
        if self.policy.require_mfa && !matches!(method, AuthMethod::MultiFactor { .. }) {
            return Err(SshWrapperError::PolicyViolation {
                policy: "MFA required".to_string(),
            });
        }

        session.auth_method = Some(method);
        session.state = SessionState::Authenticated;

        self.logger.log(AuditEntry {
            timestamp: current_timestamp(),
            session_id: session_id.to_string(),
            user: session.user.clone(),
            remote_ip: session.remote_ip,
            event_type: AuditEventType::AuthSuccess,
            details: format!("Authenticated via {}", method_name),
            level: LogLevel::Info,
        });

        Ok(())
    }

    /// Execute a command
    pub fn execute_command(
        &self,
        session_id: &str,
        command: &str,
    ) -> Result<CommandResult, SshWrapperError> {
        // Validate session
        {
            let mut sessions = self.sessions.write().unwrap();
            let session = sessions
                .get_mut(session_id)
                .ok_or(SshWrapperError::AccessDenied {
                    reason: "Session not found".to_string(),
                })?;

            // Check session timeouts
            let now = current_timestamp();
            if Duration::from_secs(now - session.started_at) > self.policy.max_session_duration {
                return Err(SshWrapperError::SessionExpired);
            }
            if Duration::from_secs(now - session.last_activity) > self.policy.idle_timeout {
                return Err(SshWrapperError::IdleTimeout);
            }

            session.last_activity = now;
        }

        // Check command against rules
        let (allowed, reason) = self.check_command(command);

        let session = self.sessions.read().unwrap();
        let session = session.get(session_id).unwrap();

        if !allowed {
            self.logger.log(AuditEntry {
                timestamp: current_timestamp(),
                session_id: session_id.to_string(),
                user: session.user.clone(),
                remote_ip: session.remote_ip,
                event_type: AuditEventType::CommandBlocked,
                details: format!(
                    "Blocked: {} - {}",
                    command,
                    reason.as_deref().unwrap_or("policy")
                ),
                level: LogLevel::Warning,
            });

            return Err(SshWrapperError::CommandBlocked {
                command: command.to_string(),
                reason: reason.unwrap_or_else(|| "Denied by policy".to_string()),
            });
        }

        // Log command execution
        self.logger.log(AuditEntry {
            timestamp: current_timestamp(),
            session_id: session_id.to_string(),
            user: session.user.clone(),
            remote_ip: session.remote_ip,
            event_type: AuditEventType::CommandExecuted,
            details: command.to_string(),
            level: LogLevel::Info,
        });

        // Update session stats
        drop(session);
        {
            let mut sessions = self.sessions.write().unwrap();
            if let Some(s) = sessions.get_mut(session_id) {
                s.commands_executed += 1;
            }
        }

        // Simulate command execution
        Ok(CommandResult {
            command: command.to_string(),
            exit_code: 0,
            stdout: format!("Executed: {}", command),
            stderr: String::new(),
            duration_ms: 100,
            allowed: true,
            reason: None,
        })
    }

    /// Check command against rules
    fn check_command(&self, command: &str) -> (bool, Option<String>) {
        // Check denied commands first
        for rule in &self.policy.denied_commands {
            if command.contains(&rule.pattern) {
                return (
                    false,
                    Some(format!("Matches denied pattern: {}", rule.pattern)),
                );
            }
        }

        // Check allowed commands if specified
        if !self.policy.allowed_commands.is_empty() {
            let allowed = self
                .policy
                .allowed_commands
                .iter()
                .any(|r| command.contains(&r.pattern) && r.action == RuleAction::Allow);
            if !allowed {
                return (false, Some("Command not in allowed list".to_string()));
            }
        }

        (true, None)
    }

    /// Record authentication failure
    fn record_auth_failure(&self, ip: IpAddr) {
        let mut blocked = self.blocked_ips.write().unwrap();
        let entry = blocked.entry(ip).or_insert((0, 0));
        entry.1 += 1;

        if entry.1 >= self.max_auth_failures {
            entry.0 = current_timestamp() + self.block_duration.as_secs();
        }
    }

    /// End a session
    pub fn end_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write().unwrap();
        if let Some(session) = sessions.remove(session_id) {
            self.logger.log(AuditEntry {
                timestamp: current_timestamp(),
                session_id: session_id.to_string(),
                user: session.user,
                remote_ip: session.remote_ip,
                event_type: AuditEventType::SessionEnd,
                details: format!(
                    "Session ended after {:?}, {} commands executed",
                    session.duration(),
                    session.commands_executed
                ),
                level: LogLevel::Info,
            });
        }
    }

    /// Get active sessions
    pub fn active_sessions(&self) -> Vec<SshSession> {
        self.sessions.read().unwrap().values().cloned().collect()
    }

    /// Query audit log
    pub fn query_audit(&self, filter: &AuditFilter) -> Vec<AuditEntry> {
        self.logger.query(filter)
    }

    /// Generate session report
    pub fn session_report(&self, session_id: &str) -> Option<SessionReport> {
        let sessions = self.sessions.read().unwrap();
        let session = sessions.get(session_id)?;

        let entries = self.logger.query(&AuditFilter {
            session_id: Some(session_id.to_string()),
            ..Default::default()
        });

        Some(SessionReport {
            session: session.clone(),
            commands: entries
                .iter()
                .filter(|e| e.event_type == AuditEventType::CommandExecuted)
                .map(|e| e.details.clone())
                .collect(),
            blocked_commands: entries
                .iter()
                .filter(|e| e.event_type == AuditEventType::CommandBlocked)
                .map(|e| e.details.clone())
                .collect(),
            total_events: entries.len(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SessionReport {
    pub session: SshSession,
    pub commands: Vec<String>,
    pub blocked_commands: Vec<String>,
    pub total_events: usize,
}

// Helper functions

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn generate_session_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("ssh-{}-{}", current_timestamp(), count)
}

fn main() {
    println!("=== SSH Wrapper - Secure Access Management ===\n");

    // Create policy
    let mut policy = AccessPolicy::default();
    policy.allowed_users.insert("admin".to_string());
    policy.allowed_users.insert("developer".to_string());
    policy.allowed_auth_methods = vec!["publickey".to_string(), "mfa".to_string()];

    // Add custom command rules
    policy.denied_commands.push(CommandRule {
        pattern: "sudo su".to_string(),
        action: RuleAction::Deny,
        log_level: LogLevel::Critical,
        notify: true,
    });

    // Create audit logger
    let logger: Arc<dyn AuditLogger> = Arc::new(MemoryAuditLogger::new(10000));

    // Create SSH wrapper
    let wrapper = SshWrapper::new(policy, logger);

    // Simulate session
    println!("--- Starting SSH Session ---");
    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    let session = wrapper.start_session("admin".to_string(), ip, 22).unwrap();
    println!("Session started: {}", session.id);

    // Authenticate
    println!("\n--- Authentication ---");
    wrapper
        .authenticate(
            &session.id,
            AuthMethod::PublicKey {
                fingerprint: "SHA256:abc123...".to_string(),
            },
        )
        .unwrap();
    println!("Authentication successful");

    // Execute commands
    println!("\n--- Command Execution ---");
    let commands = vec![
        "ls -la",
        "whoami",
        "cat /etc/passwd",
        "rm -rf /", // This should be blocked
    ];

    for cmd in commands {
        match wrapper.execute_command(&session.id, cmd) {
            Ok(result) => {
                println!(
                    "✓ Executed: {} (exit: {})",
                    result.command, result.exit_code
                );
            }
            Err(e) => {
                println!("✗ Blocked: {} - {}", cmd, e);
            }
        }
    }

    // Session report
    println!("\n--- Session Report ---");
    if let Some(report) = wrapper.session_report(&session.id) {
        println!("Session ID: {}", report.session.id);
        println!("User: {}", report.session.user);
        println!("Commands executed: {}", report.commands.len());
        println!("Commands blocked: {}", report.blocked_commands.len());
        println!("Total events: {}", report.total_events);
    }

    // Query audit log
    println!("\n--- Audit Log Query ---");
    let entries = wrapper.query_audit(&AuditFilter {
        user: Some("admin".to_string()),
        limit: Some(10),
        ..Default::default()
    });
    println!("Recent entries for admin:");
    for entry in entries {
        println!(
            "  [{:?}] {:?}: {}",
            entry.level, entry.event_type, entry.details
        );
    }

    // Active sessions
    println!("\n--- Active Sessions ---");
    let active = wrapper.active_sessions();
    println!("Active sessions: {}", active.len());
    for s in &active {
        println!("  {} - {} from {}", s.id, s.user, s.remote_ip);
    }

    // End session
    println!("\n--- Ending Session ---");
    wrapper.end_session(&session.id);
    println!("Session ended");

    println!("\n=== SSH Wrapper Demo Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_wrapper() -> SshWrapper {
        let mut policy = AccessPolicy::default();
        policy.allowed_users.insert("testuser".to_string());
        policy.allowed_auth_methods = vec!["publickey".to_string()];

        let logger: Arc<dyn AuditLogger> = Arc::new(MemoryAuditLogger::new(1000));
        SshWrapper::new(policy, logger)
    }

    #[test]
    fn test_session_start() {
        let wrapper = test_wrapper();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let session = wrapper
            .start_session("testuser".to_string(), ip, 22)
            .unwrap();
        assert_eq!(session.user, "testuser");
        assert_eq!(session.state, SessionState::Connecting);
    }

    #[test]
    fn test_access_denied_unknown_user() {
        let wrapper = test_wrapper();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let result = wrapper.start_session("unknown".to_string(), ip, 22);
        assert!(matches!(result, Err(SshWrapperError::AccessDenied { .. })));
    }

    #[test]
    fn test_authentication() {
        let wrapper = test_wrapper();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let session = wrapper
            .start_session("testuser".to_string(), ip, 22)
            .unwrap();

        wrapper
            .authenticate(
                &session.id,
                AuthMethod::PublicKey {
                    fingerprint: "test".to_string(),
                },
            )
            .unwrap();

        let sessions = wrapper.sessions.read().unwrap();
        assert_eq!(sessions[&session.id].state, SessionState::Authenticated);
    }

    #[test]
    fn test_auth_method_not_allowed() {
        let wrapper = test_wrapper();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let session = wrapper
            .start_session("testuser".to_string(), ip, 22)
            .unwrap();

        let result = wrapper.authenticate(&session.id, AuthMethod::Password);
        assert!(matches!(
            result,
            Err(SshWrapperError::AuthenticationFailed { .. })
        ));
    }

    #[test]
    fn test_command_execution() {
        let wrapper = test_wrapper();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let session = wrapper
            .start_session("testuser".to_string(), ip, 22)
            .unwrap();
        wrapper
            .authenticate(
                &session.id,
                AuthMethod::PublicKey {
                    fingerprint: "test".to_string(),
                },
            )
            .unwrap();

        let result = wrapper.execute_command(&session.id, "ls -la").unwrap();
        assert!(result.allowed);
    }

    #[test]
    fn test_command_blocked() {
        let wrapper = test_wrapper();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let session = wrapper
            .start_session("testuser".to_string(), ip, 22)
            .unwrap();
        wrapper
            .authenticate(
                &session.id,
                AuthMethod::PublicKey {
                    fingerprint: "test".to_string(),
                },
            )
            .unwrap();

        let result = wrapper.execute_command(&session.id, "rm -rf /");
        assert!(matches!(
            result,
            Err(SshWrapperError::CommandBlocked { .. })
        ));
    }

    #[test]
    fn test_audit_logging() {
        let wrapper = test_wrapper();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let session = wrapper
            .start_session("testuser".to_string(), ip, 22)
            .unwrap();

        let entries = wrapper.query_audit(&AuditFilter {
            session_id: Some(session.id.clone()),
            ..Default::default()
        });
        assert!(!entries.is_empty());
    }

    #[test]
    fn test_session_end() {
        let wrapper = test_wrapper();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let session = wrapper
            .start_session("testuser".to_string(), ip, 22)
            .unwrap();

        wrapper.end_session(&session.id);

        let active = wrapper.active_sessions();
        assert!(active.is_empty());
    }

    #[test]
    fn test_ip_range_matching() {
        let range = IpRange {
            network: "192.168.1.0".parse().unwrap(),
            prefix_len: 24,
        };

        assert!(range.contains(&"192.168.1.100".parse().unwrap()));
        assert!(!range.contains(&"192.168.2.100".parse().unwrap()));
    }

    #[test]
    fn test_session_report() {
        let wrapper = test_wrapper();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let session = wrapper
            .start_session("testuser".to_string(), ip, 22)
            .unwrap();
        wrapper
            .authenticate(
                &session.id,
                AuthMethod::PublicKey {
                    fingerprint: "test".to_string(),
                },
            )
            .unwrap();
        wrapper.execute_command(&session.id, "ls").unwrap();

        let report = wrapper.session_report(&session.id).unwrap();
        assert_eq!(report.session.user, "testuser");
        assert!(!report.commands.is_empty());
    }
}
