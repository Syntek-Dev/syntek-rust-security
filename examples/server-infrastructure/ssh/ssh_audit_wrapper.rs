//! SSH Audit Wrapper Implementation
//!
//! Comprehensive SSH wrapper with audit logging, command filtering,
//! session recording, and security controls.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// SSH session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Connecting,
    Authenticating,
    Authenticated,
    Active,
    Idle,
    Terminating,
    Terminated,
}

/// Authentication method
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    Password,
    PublicKey { fingerprint: String },
    Certificate { serial: String },
    Keyboard,
    GssApi,
    None,
}

impl AuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthMethod::Password => "password",
            AuthMethod::PublicKey { .. } => "publickey",
            AuthMethod::Certificate { .. } => "certificate",
            AuthMethod::Keyboard => "keyboard-interactive",
            AuthMethod::GssApi => "gssapi-with-mic",
            AuthMethod::None => "none",
        }
    }
}

/// SSH session information
#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub user: String,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub auth_method: AuthMethod,
    pub state: SessionState,
    pub started_at: u64,
    pub last_activity: u64,
    pub commands_executed: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub pty_requested: bool,
    pub forwarding_requested: bool,
}

impl Session {
    pub fn new(id: String, user: String, source_ip: IpAddr, source_port: u16) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            id,
            user,
            source_ip,
            source_port,
            auth_method: AuthMethod::None,
            state: SessionState::Connecting,
            started_at: now,
            last_activity: now,
            commands_executed: 0,
            bytes_sent: 0,
            bytes_received: 0,
            pty_requested: false,
            forwarding_requested: false,
        }
    }

    pub fn duration(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Duration::from_secs(now - self.started_at)
    }

    pub fn idle_time(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Duration::from_secs(now - self.last_activity)
    }
}

/// Audit log event type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    SessionStart,
    SessionEnd,
    AuthSuccess,
    AuthFailure {
        reason: String,
    },
    CommandExecuted {
        command: String,
    },
    CommandBlocked {
        command: String,
        reason: String,
    },
    FileTransfer {
        operation: String,
        path: String,
    },
    PortForward {
        direction: String,
        host: String,
        port: u16,
    },
    PolicyViolation {
        rule: String,
        details: String,
    },
    Alert {
        severity: AlertSeverity,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// Audit log entry
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub session_id: String,
    pub user: String,
    pub source_ip: IpAddr,
    pub event: AuditEvent,
    pub metadata: HashMap<String, String>,
}

impl AuditEntry {
    pub fn new(session: &Session, event: AuditEvent) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            session_id: session.id.clone(),
            user: session.user.clone(),
            source_ip: session.source_ip,
            event,
            metadata: HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn to_json(&self) -> String {
        let event_type = match &self.event {
            AuditEvent::SessionStart => "session_start",
            AuditEvent::SessionEnd => "session_end",
            AuditEvent::AuthSuccess => "auth_success",
            AuditEvent::AuthFailure { .. } => "auth_failure",
            AuditEvent::CommandExecuted { .. } => "command_executed",
            AuditEvent::CommandBlocked { .. } => "command_blocked",
            AuditEvent::FileTransfer { .. } => "file_transfer",
            AuditEvent::PortForward { .. } => "port_forward",
            AuditEvent::PolicyViolation { .. } => "policy_violation",
            AuditEvent::Alert { .. } => "alert",
        };

        format!(
            r#"{{"timestamp":{},"session_id":"{}","user":"{}","source_ip":"{}","event_type":"{}"}}"#,
            self.timestamp, self.session_id, self.user, self.source_ip, event_type
        )
    }
}

/// Command filter rule
#[derive(Debug, Clone)]
pub struct CommandRule {
    pub pattern: String,
    pub action: RuleAction,
    pub reason: String,
    pub log_level: LogLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Deny,
    Audit,
    RequireApproval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

impl CommandRule {
    pub fn deny(pattern: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            action: RuleAction::Deny,
            reason: reason.into(),
            log_level: LogLevel::Warning,
        }
    }

    pub fn allow(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            action: RuleAction::Allow,
            reason: String::new(),
            log_level: LogLevel::Debug,
        }
    }

    pub fn audit(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            action: RuleAction::Audit,
            reason: "Command requires audit".to_string(),
            log_level: LogLevel::Info,
        }
    }

    pub fn matches(&self, command: &str) -> bool {
        // Simple pattern matching (production would use regex)
        if self.pattern == "*" {
            return true;
        }
        if self.pattern.ends_with('*') {
            let prefix = &self.pattern[..self.pattern.len() - 1];
            return command.starts_with(prefix);
        }
        if self.pattern.starts_with('*') {
            let suffix = &self.pattern[1..];
            return command.ends_with(suffix);
        }
        command == self.pattern || command.contains(&self.pattern)
    }
}

/// Access control policy
#[derive(Debug, Clone)]
pub struct AccessPolicy {
    pub name: String,
    pub users: HashSet<String>,
    pub allowed_commands: Vec<CommandRule>,
    pub blocked_commands: Vec<CommandRule>,
    pub allowed_hosts: HashSet<IpAddr>,
    pub blocked_hosts: HashSet<IpAddr>,
    pub max_session_duration: Option<Duration>,
    pub max_idle_time: Option<Duration>,
    pub allow_pty: bool,
    pub allow_forwarding: bool,
    pub allow_sftp: bool,
    pub allow_scp: bool,
}

impl AccessPolicy {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            users: HashSet::new(),
            allowed_commands: Vec::new(),
            blocked_commands: Vec::new(),
            allowed_hosts: HashSet::new(),
            blocked_hosts: HashSet::new(),
            max_session_duration: None,
            max_idle_time: None,
            allow_pty: true,
            allow_forwarding: false,
            allow_sftp: true,
            allow_scp: true,
        }
    }

    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.users.insert(user.into());
        self
    }

    pub fn users(mut self, users: Vec<String>) -> Self {
        self.users.extend(users);
        self
    }

    pub fn allow_command(mut self, rule: CommandRule) -> Self {
        self.allowed_commands.push(rule);
        self
    }

    pub fn block_command(mut self, rule: CommandRule) -> Self {
        self.blocked_commands.push(rule);
        self
    }

    pub fn allow_host(mut self, ip: IpAddr) -> Self {
        self.allowed_hosts.insert(ip);
        self
    }

    pub fn block_host(mut self, ip: IpAddr) -> Self {
        self.blocked_hosts.insert(ip);
        self
    }

    pub fn max_session(mut self, duration: Duration) -> Self {
        self.max_session_duration = Some(duration);
        self
    }

    pub fn max_idle(mut self, duration: Duration) -> Self {
        self.max_idle_time = Some(duration);
        self
    }

    pub fn no_forwarding(mut self) -> Self {
        self.allow_forwarding = false;
        self
    }

    pub fn no_sftp(mut self) -> Self {
        self.allow_sftp = false;
        self
    }
}

/// Command evaluation result
#[derive(Debug, Clone)]
pub enum CommandResult {
    Allowed,
    Denied { reason: String },
    RequiresApproval { reason: String },
    Audited,
}

/// Session recording configuration
#[derive(Debug, Clone)]
pub struct RecordingConfig {
    pub enabled: bool,
    pub record_input: bool,
    pub record_output: bool,
    pub max_size_bytes: u64,
    pub storage_path: String,
    pub compress: bool,
    pub encrypt: bool,
}

impl Default for RecordingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            record_input: true,
            record_output: true,
            max_size_bytes: 100 * 1024 * 1024, // 100 MB
            storage_path: "/var/log/ssh-recordings".to_string(),
            compress: true,
            encrypt: true,
        }
    }
}

/// Session recording
pub struct SessionRecorder {
    session_id: String,
    config: RecordingConfig,
    buffer: Vec<RecordingEvent>,
    total_size: u64,
}

#[derive(Debug, Clone)]
pub struct RecordingEvent {
    pub timestamp: u64,
    pub event_type: RecordingEventType,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub enum RecordingEventType {
    Input,
    Output,
    WindowResize,
    Signal,
}

impl SessionRecorder {
    pub fn new(session_id: impl Into<String>, config: RecordingConfig) -> Self {
        Self {
            session_id: session_id.into(),
            config,
            buffer: Vec::new(),
            total_size: 0,
        }
    }

    pub fn record_input(&mut self, data: &[u8]) {
        if !self.config.enabled || !self.config.record_input {
            return;
        }
        self.add_event(RecordingEventType::Input, data);
    }

    pub fn record_output(&mut self, data: &[u8]) {
        if !self.config.enabled || !self.config.record_output {
            return;
        }
        self.add_event(RecordingEventType::Output, data);
    }

    fn add_event(&mut self, event_type: RecordingEventType, data: &[u8]) {
        if self.total_size >= self.config.max_size_bytes {
            return; // Recording size limit reached
        }

        let event = RecordingEvent {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            event_type,
            data: data.to_vec(),
        };

        self.total_size += data.len() as u64;
        self.buffer.push(event);
    }

    pub fn events(&self) -> &[RecordingEvent] {
        &self.buffer
    }

    pub fn total_size(&self) -> u64 {
        self.total_size
    }
}

/// Audit log storage
pub trait AuditStorage: Send + Sync {
    fn write(&self, entry: &AuditEntry) -> Result<(), AuditError>;
    fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>, AuditError>;
}

#[derive(Debug, Default)]
pub struct AuditFilter {
    pub session_id: Option<String>,
    pub user: Option<String>,
    pub source_ip: Option<IpAddr>,
    pub start_time: Option<u64>,
    pub end_time: Option<u64>,
    pub event_types: Option<Vec<String>>,
    pub limit: Option<usize>,
}

/// In-memory audit storage for demonstration
pub struct MemoryAuditStorage {
    entries: RwLock<Vec<AuditEntry>>,
    max_entries: usize,
}

impl MemoryAuditStorage {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            max_entries,
        }
    }
}

impl AuditStorage for MemoryAuditStorage {
    fn write(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        let mut entries = self.entries.write().unwrap();
        if entries.len() >= self.max_entries {
            entries.remove(0);
        }
        entries.push(entry.clone());
        Ok(())
    }

    fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>, AuditError> {
        let entries = self.entries.read().unwrap();
        let mut results: Vec<_> = entries
            .iter()
            .filter(|e| {
                if let Some(ref user) = filter.user {
                    if &e.user != user {
                        return false;
                    }
                }
                if let Some(ref session) = filter.session_id {
                    if &e.session_id != session {
                        return false;
                    }
                }
                if let Some(start) = filter.start_time {
                    if e.timestamp < start {
                        return false;
                    }
                }
                if let Some(end) = filter.end_time {
                    if e.timestamp > end {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }

        Ok(results)
    }
}

#[derive(Debug)]
pub enum AuditError {
    StorageError(String),
    QueryError(String),
}

/// SSH audit wrapper
pub struct SshAuditWrapper {
    policies: HashMap<String, AccessPolicy>,
    default_policy: Option<String>,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    audit_storage: Arc<dyn AuditStorage>,
    recording_config: RecordingConfig,
    stats: WrapperStats,
}

pub struct WrapperStats {
    total_sessions: AtomicU64,
    active_sessions: AtomicU64,
    blocked_commands: AtomicU64,
    auth_failures: AtomicU64,
}

impl WrapperStats {
    pub fn new() -> Self {
        Self {
            total_sessions: AtomicU64::new(0),
            active_sessions: AtomicU64::new(0),
            blocked_commands: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
        }
    }
}

impl Default for WrapperStats {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAuditWrapper {
    pub fn new(audit_storage: Arc<dyn AuditStorage>) -> Self {
        Self {
            policies: HashMap::new(),
            default_policy: None,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            audit_storage,
            recording_config: RecordingConfig::default(),
            stats: WrapperStats::new(),
        }
    }

    pub fn add_policy(&mut self, policy: AccessPolicy) {
        let name = policy.name.clone();
        self.policies.insert(name, policy);
    }

    pub fn set_default_policy(&mut self, name: impl Into<String>) {
        self.default_policy = Some(name.into());
    }

    pub fn set_recording_config(&mut self, config: RecordingConfig) {
        self.recording_config = config;
    }

    /// Start a new SSH session
    pub fn start_session(
        &self,
        user: &str,
        source_ip: IpAddr,
        source_port: u16,
    ) -> Result<String, SshError> {
        // Check if source IP is blocked by any policy
        for policy in self.policies.values() {
            if policy.blocked_hosts.contains(&source_ip) {
                return Err(SshError::Blocked(format!(
                    "Source IP {} is blocked",
                    source_ip
                )));
            }
        }

        let session_id = generate_session_id();
        let session = Session::new(session_id.clone(), user.to_string(), source_ip, source_port);

        // Log session start
        let entry = AuditEntry::new(&session, AuditEvent::SessionStart)
            .with_metadata("source_port", source_port.to_string());
        let _ = self.audit_storage.write(&entry);

        // Store session
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(session_id.clone(), session);

        self.stats.total_sessions.fetch_add(1, Ordering::SeqCst);
        self.stats.active_sessions.fetch_add(1, Ordering::SeqCst);

        Ok(session_id)
    }

    /// Record successful authentication
    pub fn auth_success(&self, session_id: &str, method: AuthMethod) -> Result<(), SshError> {
        let mut sessions = self.sessions.write().unwrap();
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| SshError::SessionNotFound(session_id.to_string()))?;

        session.auth_method = method;
        session.state = SessionState::Authenticated;

        let entry = AuditEntry::new(session, AuditEvent::AuthSuccess)
            .with_metadata("method", session.auth_method.as_str());
        let _ = self.audit_storage.write(&entry);

        Ok(())
    }

    /// Record failed authentication
    pub fn auth_failure(&self, session_id: &str, reason: &str) -> Result<(), SshError> {
        let sessions = self.sessions.read().unwrap();
        let session = sessions
            .get(session_id)
            .ok_or_else(|| SshError::SessionNotFound(session_id.to_string()))?;

        let entry = AuditEntry::new(
            session,
            AuditEvent::AuthFailure {
                reason: reason.to_string(),
            },
        );
        let _ = self.audit_storage.write(&entry);

        self.stats.auth_failures.fetch_add(1, Ordering::SeqCst);

        Ok(())
    }

    /// Evaluate a command against policies
    pub fn evaluate_command(
        &self,
        session_id: &str,
        command: &str,
    ) -> Result<CommandResult, SshError> {
        let sessions = self.sessions.read().unwrap();
        let session = sessions
            .get(session_id)
            .ok_or_else(|| SshError::SessionNotFound(session_id.to_string()))?;

        // Find applicable policy
        let policy = self.find_policy(&session.user);

        if let Some(policy) = policy {
            // Check blocked commands first
            for rule in &policy.blocked_commands {
                if rule.matches(command) {
                    let entry = AuditEntry::new(
                        session,
                        AuditEvent::CommandBlocked {
                            command: command.to_string(),
                            reason: rule.reason.clone(),
                        },
                    );
                    let _ = self.audit_storage.write(&entry);

                    self.stats.blocked_commands.fetch_add(1, Ordering::SeqCst);

                    return Ok(CommandResult::Denied {
                        reason: rule.reason.clone(),
                    });
                }
            }

            // Check allowed commands
            for rule in &policy.allowed_commands {
                if rule.matches(command) {
                    match rule.action {
                        RuleAction::Allow => {
                            return Ok(CommandResult::Allowed);
                        }
                        RuleAction::Audit => {
                            let entry = AuditEntry::new(
                                session,
                                AuditEvent::CommandExecuted {
                                    command: command.to_string(),
                                },
                            )
                            .with_metadata("audited", "true");
                            let _ = self.audit_storage.write(&entry);
                            return Ok(CommandResult::Audited);
                        }
                        RuleAction::RequireApproval => {
                            return Ok(CommandResult::RequiresApproval {
                                reason: rule.reason.clone(),
                            });
                        }
                        RuleAction::Deny => {
                            return Ok(CommandResult::Denied {
                                reason: rule.reason.clone(),
                            });
                        }
                    }
                }
            }
        }

        // Default: allow and log
        let entry = AuditEntry::new(
            session,
            AuditEvent::CommandExecuted {
                command: command.to_string(),
            },
        );
        let _ = self.audit_storage.write(&entry);

        Ok(CommandResult::Allowed)
    }

    /// Record command execution
    pub fn record_command(&self, session_id: &str, command: &str) -> Result<(), SshError> {
        let mut sessions = self.sessions.write().unwrap();
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| SshError::SessionNotFound(session_id.to_string()))?;

        session.commands_executed += 1;
        session.last_activity = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(())
    }

    /// End a session
    pub fn end_session(&self, session_id: &str) -> Result<Session, SshError> {
        let mut sessions = self.sessions.write().unwrap();
        let mut session = sessions
            .remove(session_id)
            .ok_or_else(|| SshError::SessionNotFound(session_id.to_string()))?;

        session.state = SessionState::Terminated;

        let entry = AuditEntry::new(&session, AuditEvent::SessionEnd)
            .with_metadata("duration_secs", session.duration().as_secs().to_string())
            .with_metadata("commands", session.commands_executed.to_string());
        let _ = self.audit_storage.write(&entry);

        self.stats.active_sessions.fetch_sub(1, Ordering::SeqCst);

        Ok(session)
    }

    /// Get active sessions
    pub fn active_sessions(&self) -> Vec<Session> {
        let sessions = self.sessions.read().unwrap();
        sessions.values().cloned().collect()
    }

    /// Get session by ID
    pub fn get_session(&self, session_id: &str) -> Option<Session> {
        let sessions = self.sessions.read().unwrap();
        sessions.get(session_id).cloned()
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64, u64, u64) {
        (
            self.stats.total_sessions.load(Ordering::SeqCst),
            self.stats.active_sessions.load(Ordering::SeqCst),
            self.stats.blocked_commands.load(Ordering::SeqCst),
            self.stats.auth_failures.load(Ordering::SeqCst),
        )
    }

    fn find_policy(&self, user: &str) -> Option<&AccessPolicy> {
        // Check user-specific policies first
        for policy in self.policies.values() {
            if policy.users.contains(user) {
                return Some(policy);
            }
        }

        // Fall back to default policy
        if let Some(ref default) = self.default_policy {
            return self.policies.get(default);
        }

        None
    }
}

/// SSH error types
#[derive(Debug)]
pub enum SshError {
    SessionNotFound(String),
    Blocked(String),
    PolicyViolation(String),
    AuthenticationFailed(String),
}

impl std::fmt::Display for SshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshError::SessionNotFound(id) => write!(f, "Session not found: {}", id),
            SshError::Blocked(reason) => write!(f, "Blocked: {}", reason),
            SshError::PolicyViolation(msg) => write!(f, "Policy violation: {}", msg),
            SshError::AuthenticationFailed(msg) => write!(f, "Auth failed: {}", msg),
        }
    }
}

impl std::error::Error for SshError {}

/// Generate a unique session ID
fn generate_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("ssh-{:016x}", nanos)
}

fn main() {
    println!("=== SSH Audit Wrapper Demo ===\n");

    // Create audit storage
    let storage = Arc::new(MemoryAuditStorage::new(1000));

    // Create wrapper
    let mut wrapper = SshAuditWrapper::new(storage.clone());

    // Define policies
    let admin_policy = AccessPolicy::new("admin")
        .user("admin")
        .user("root")
        .allow_command(CommandRule::allow("*"))
        .max_session(Duration::from_secs(3600 * 8))
        .max_idle(Duration::from_secs(1800));

    let developer_policy = AccessPolicy::new("developer")
        .users(vec!["dev1".to_string(), "dev2".to_string()])
        .allow_command(CommandRule::allow("git *"))
        .allow_command(CommandRule::allow("vim *"))
        .allow_command(CommandRule::allow("cat *"))
        .allow_command(CommandRule::allow("ls *"))
        .block_command(CommandRule::deny("rm -rf *", "Dangerous command blocked"))
        .block_command(CommandRule::deny(
            "sudo *",
            "Sudo not allowed for developers",
        ))
        .block_command(CommandRule::deny("passwd", "Password changes not allowed"))
        .no_forwarding()
        .max_session(Duration::from_secs(3600 * 4))
        .max_idle(Duration::from_secs(600));

    let restricted_policy = AccessPolicy::new("restricted")
        .user("guest")
        .allow_command(CommandRule::allow("ls"))
        .allow_command(CommandRule::allow("cat"))
        .allow_command(CommandRule::audit("*"))
        .no_forwarding()
        .no_sftp()
        .max_session(Duration::from_secs(1800))
        .max_idle(Duration::from_secs(300));

    wrapper.add_policy(admin_policy);
    wrapper.add_policy(developer_policy);
    wrapper.add_policy(restricted_policy);
    wrapper.set_default_policy("restricted");

    // Simulate SSH sessions
    println!("1. Starting SSH sessions:");

    // Admin session
    let admin_session = wrapper
        .start_session("admin", "192.168.1.100".parse().unwrap(), 54321)
        .unwrap();
    println!("   Admin session started: {}", admin_session);

    wrapper
        .auth_success(
            &admin_session,
            AuthMethod::PublicKey {
                fingerprint: "SHA256:abc123...".to_string(),
            },
        )
        .unwrap();
    println!("   Admin authenticated with public key");

    // Developer session
    let dev_session = wrapper
        .start_session("dev1", "192.168.1.101".parse().unwrap(), 54322)
        .unwrap();
    println!("   Developer session started: {}", dev_session);

    wrapper
        .auth_success(&dev_session, AuthMethod::Password)
        .unwrap();
    println!("   Developer authenticated with password");

    // Guest session
    let guest_session = wrapper
        .start_session("guest", "10.0.0.50".parse().unwrap(), 54323)
        .unwrap();
    println!("   Guest session started: {}", guest_session);

    wrapper
        .auth_success(&guest_session, AuthMethod::Keyboard)
        .unwrap();
    println!("   Guest authenticated with keyboard-interactive");

    // Command evaluation
    println!("\n2. Command evaluation:");

    // Admin can do anything
    let result = wrapper
        .evaluate_command(&admin_session, "rm -rf /tmp/test")
        .unwrap();
    println!("   Admin 'rm -rf /tmp/test': {:?}", result);

    // Developer commands
    let result = wrapper
        .evaluate_command(&dev_session, "git pull origin main")
        .unwrap();
    println!("   Dev 'git pull': {:?}", result);

    let result = wrapper
        .evaluate_command(&dev_session, "sudo systemctl restart nginx")
        .unwrap();
    println!("   Dev 'sudo systemctl': {:?}", result);

    let result = wrapper
        .evaluate_command(&dev_session, "rm -rf /important")
        .unwrap();
    println!("   Dev 'rm -rf': {:?}", result);

    // Guest commands
    let result = wrapper.evaluate_command(&guest_session, "ls -la").unwrap();
    println!("   Guest 'ls -la': {:?}", result);

    let result = wrapper
        .evaluate_command(&guest_session, "cat /etc/passwd")
        .unwrap();
    println!("   Guest 'cat /etc/passwd': {:?}", result);

    // Record some commands
    wrapper.record_command(&admin_session, "ls -la").unwrap();
    wrapper.record_command(&dev_session, "git status").unwrap();

    // Session recording
    println!("\n3. Session recording:");
    let mut recorder = SessionRecorder::new(&admin_session, RecordingConfig::default());
    recorder.record_input(b"ls -la\n");
    recorder.record_output(b"total 123\ndrwxr-xr-x 2 user group 4096 ...\n");
    println!(
        "   Recorded {} events, {} bytes",
        recorder.events().len(),
        recorder.total_size()
    );

    // Active sessions
    println!("\n4. Active sessions:");
    for session in wrapper.active_sessions() {
        println!(
            "   - {} ({}@{}) - {:?} - {} commands",
            session.id, session.user, session.source_ip, session.state, session.commands_executed
        );
    }

    // Statistics
    println!("\n5. Statistics:");
    let (total, active, blocked, auth_fails) = wrapper.stats();
    println!("   Total sessions: {}", total);
    println!("   Active sessions: {}", active);
    println!("   Blocked commands: {}", blocked);
    println!("   Auth failures: {}", auth_fails);

    // End sessions
    println!("\n6. Ending sessions:");
    let ended = wrapper.end_session(&guest_session).unwrap();
    println!(
        "   Guest session ended - duration: {:?}, commands: {}",
        ended.duration(),
        ended.commands_executed
    );

    let ended = wrapper.end_session(&dev_session).unwrap();
    println!("   Dev session ended - duration: {:?}", ended.duration());

    // Query audit logs
    println!("\n7. Audit log query:");
    let filter = AuditFilter {
        limit: Some(5),
        ..Default::default()
    };
    match storage.query(&filter) {
        Ok(entries) => {
            println!("   Found {} audit entries:", entries.len());
            for entry in entries {
                println!("   - {}", entry.to_json());
            }
        }
        Err(e) => println!("   Query error: {:?}", e),
    }

    // Final stats
    println!("\n8. Final statistics:");
    let (total, active, blocked, auth_fails) = wrapper.stats();
    println!("   Total sessions: {}", total);
    println!("   Active sessions: {}", active);
    println!("   Blocked commands: {}", blocked);
    println!("   Auth failures: {}", auth_fails);

    println!("\n=== Demo Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_wrapper() -> SshAuditWrapper {
        let storage = Arc::new(MemoryAuditStorage::new(100));
        SshAuditWrapper::new(storage)
    }

    #[test]
    fn test_session_creation() {
        let wrapper = create_test_wrapper();
        let session_id = wrapper
            .start_session("testuser", "127.0.0.1".parse().unwrap(), 22)
            .unwrap();

        assert!(!session_id.is_empty());
        assert!(session_id.starts_with("ssh-"));
    }

    #[test]
    fn test_session_retrieval() {
        let wrapper = create_test_wrapper();
        let session_id = wrapper
            .start_session("testuser", "127.0.0.1".parse().unwrap(), 22)
            .unwrap();

        let session = wrapper.get_session(&session_id).unwrap();
        assert_eq!(session.user, "testuser");
        assert_eq!(session.state, SessionState::Connecting);
    }

    #[test]
    fn test_authentication() {
        let wrapper = create_test_wrapper();
        let session_id = wrapper
            .start_session("testuser", "127.0.0.1".parse().unwrap(), 22)
            .unwrap();

        wrapper
            .auth_success(&session_id, AuthMethod::Password)
            .unwrap();

        let session = wrapper.get_session(&session_id).unwrap();
        assert_eq!(session.state, SessionState::Authenticated);
        assert_eq!(session.auth_method, AuthMethod::Password);
    }

    #[test]
    fn test_command_rule_matching() {
        let rule = CommandRule::deny("rm -rf *", "Dangerous");
        assert!(rule.matches("rm -rf /"));
        assert!(rule.matches("rm -rf /tmp"));
        assert!(!rule.matches("rm file.txt"));
    }

    #[test]
    fn test_wildcard_prefix_rule() {
        let rule = CommandRule::allow("git *");
        assert!(rule.matches("git status"));
        assert!(rule.matches("git pull origin main"));
        assert!(!rule.matches("vim file.txt"));
    }

    #[test]
    fn test_policy_command_blocking() {
        let mut wrapper = create_test_wrapper();

        let policy = AccessPolicy::new("test")
            .user("testuser")
            .block_command(CommandRule::deny("sudo *", "No sudo"));

        wrapper.add_policy(policy);

        let session_id = wrapper
            .start_session("testuser", "127.0.0.1".parse().unwrap(), 22)
            .unwrap();

        let result = wrapper
            .evaluate_command(&session_id, "sudo rm -rf /")
            .unwrap();
        assert!(matches!(result, CommandResult::Denied { .. }));
    }

    #[test]
    fn test_policy_command_allowing() {
        let mut wrapper = create_test_wrapper();

        let policy = AccessPolicy::new("test")
            .user("testuser")
            .allow_command(CommandRule::allow("ls *"));

        wrapper.add_policy(policy);

        let session_id = wrapper
            .start_session("testuser", "127.0.0.1".parse().unwrap(), 22)
            .unwrap();

        let result = wrapper.evaluate_command(&session_id, "ls -la").unwrap();
        assert!(matches!(result, CommandResult::Allowed));
    }

    #[test]
    fn test_session_ending() {
        let wrapper = create_test_wrapper();
        let session_id = wrapper
            .start_session("testuser", "127.0.0.1".parse().unwrap(), 22)
            .unwrap();

        let session = wrapper.end_session(&session_id).unwrap();
        assert_eq!(session.state, SessionState::Terminated);
        assert!(wrapper.get_session(&session_id).is_none());
    }

    #[test]
    fn test_statistics() {
        let wrapper = create_test_wrapper();

        let _ = wrapper
            .start_session("user1", "127.0.0.1".parse().unwrap(), 22)
            .unwrap();
        let _ = wrapper
            .start_session("user2", "127.0.0.2".parse().unwrap(), 22)
            .unwrap();

        let (total, active, _, _) = wrapper.stats();
        assert_eq!(total, 2);
        assert_eq!(active, 2);
    }

    #[test]
    fn test_active_sessions() {
        let wrapper = create_test_wrapper();

        let _ = wrapper
            .start_session("user1", "127.0.0.1".parse().unwrap(), 22)
            .unwrap();
        let _ = wrapper
            .start_session("user2", "127.0.0.2".parse().unwrap(), 22)
            .unwrap();

        let sessions = wrapper.active_sessions();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn test_auth_method_strings() {
        assert_eq!(AuthMethod::Password.as_str(), "password");
        assert_eq!(
            AuthMethod::PublicKey {
                fingerprint: "test".to_string()
            }
            .as_str(),
            "publickey"
        );
        assert_eq!(
            AuthMethod::Certificate {
                serial: "123".to_string()
            }
            .as_str(),
            "certificate"
        );
    }

    #[test]
    fn test_audit_entry_json() {
        let session = Session::new(
            "test-id".to_string(),
            "user".to_string(),
            "127.0.0.1".parse().unwrap(),
            22,
        );
        let entry = AuditEntry::new(&session, AuditEvent::SessionStart);
        let json = entry.to_json();

        assert!(json.contains("session_start"));
        assert!(json.contains("test-id"));
    }

    #[test]
    fn test_session_recorder() {
        let config = RecordingConfig::default();
        let mut recorder = SessionRecorder::new("test-session", config);

        recorder.record_input(b"test input");
        recorder.record_output(b"test output");

        assert_eq!(recorder.events().len(), 2);
        assert!(recorder.total_size() > 0);
    }

    #[test]
    fn test_recording_size_limit() {
        let config = RecordingConfig {
            max_size_bytes: 10,
            ..Default::default()
        };
        let mut recorder = SessionRecorder::new("test", config);

        recorder.record_input(b"0123456789"); // 10 bytes
        recorder.record_input(b"more data"); // Should be ignored

        assert_eq!(recorder.events().len(), 1);
    }

    #[test]
    fn test_memory_audit_storage() {
        let storage = MemoryAuditStorage::new(5);

        let session = Session::new(
            "test".to_string(),
            "user".to_string(),
            "127.0.0.1".parse().unwrap(),
            22,
        );

        for _ in 0..10 {
            let entry = AuditEntry::new(&session, AuditEvent::SessionStart);
            storage.write(&entry).unwrap();
        }

        let filter = AuditFilter::default();
        let entries = storage.query(&filter).unwrap();
        assert_eq!(entries.len(), 5); // Max entries
    }

    #[test]
    fn test_audit_filter() {
        let storage = MemoryAuditStorage::new(100);

        let session1 = Session::new(
            "session1".to_string(),
            "user1".to_string(),
            "127.0.0.1".parse().unwrap(),
            22,
        );
        let session2 = Session::new(
            "session2".to_string(),
            "user2".to_string(),
            "127.0.0.2".parse().unwrap(),
            22,
        );

        storage
            .write(&AuditEntry::new(&session1, AuditEvent::SessionStart))
            .unwrap();
        storage
            .write(&AuditEntry::new(&session2, AuditEvent::SessionStart))
            .unwrap();

        let filter = AuditFilter {
            user: Some("user1".to_string()),
            ..Default::default()
        };
        let entries = storage.query(&filter).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].user, "user1");
    }

    #[test]
    fn test_session_duration() {
        let session = Session::new(
            "test".to_string(),
            "user".to_string(),
            "127.0.0.1".parse().unwrap(),
            22,
        );

        // Duration should be very small (just created)
        assert!(session.duration().as_secs() < 2);
    }

    #[test]
    fn test_policy_builder() {
        let policy = AccessPolicy::new("test")
            .user("user1")
            .users(vec!["user2".to_string(), "user3".to_string()])
            .allow_command(CommandRule::allow("ls"))
            .block_command(CommandRule::deny("rm", "No remove"))
            .max_session(Duration::from_secs(3600))
            .max_idle(Duration::from_secs(600))
            .no_forwarding()
            .no_sftp();

        assert_eq!(policy.users.len(), 3);
        assert_eq!(policy.allowed_commands.len(), 1);
        assert_eq!(policy.blocked_commands.len(), 1);
        assert!(!policy.allow_forwarding);
        assert!(!policy.allow_sftp);
    }

    #[test]
    fn test_default_policy() {
        let mut wrapper = create_test_wrapper();

        let default = AccessPolicy::new("default").allow_command(CommandRule::audit("*"));

        wrapper.add_policy(default);
        wrapper.set_default_policy("default");

        let session_id = wrapper
            .start_session("unknown_user", "127.0.0.1".parse().unwrap(), 22)
            .unwrap();

        let result = wrapper
            .evaluate_command(&session_id, "any command")
            .unwrap();
        assert!(matches!(result, CommandResult::Audited));
    }

    #[test]
    fn test_command_recording() {
        let wrapper = create_test_wrapper();
        let session_id = wrapper
            .start_session("user", "127.0.0.1".parse().unwrap(), 22)
            .unwrap();

        wrapper.record_command(&session_id, "ls").unwrap();
        wrapper.record_command(&session_id, "pwd").unwrap();

        let session = wrapper.get_session(&session_id).unwrap();
        assert_eq!(session.commands_executed, 2);
    }

    #[test]
    fn test_auth_failure_tracking() {
        let wrapper = create_test_wrapper();
        let session_id = wrapper
            .start_session("user", "127.0.0.1".parse().unwrap(), 22)
            .unwrap();

        wrapper
            .auth_failure(&session_id, "Invalid password")
            .unwrap();

        let (_, _, _, auth_fails) = wrapper.stats();
        assert_eq!(auth_fails, 1);
    }
}
