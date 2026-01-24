//! SSH Session Manager
//!
//! Secure SSH session management with logging and access control.

use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// SSH session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshSession {
    pub id: Uuid,
    pub user: String,
    pub host: String,
    pub port: u16,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub status: SessionStatus,
    pub commands: Vec<CommandLog>,
    pub source_ip: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SessionStatus {
    Active,
    Completed,
    Failed,
    Terminated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandLog {
    pub timestamp: DateTime<Utc>,
    pub command: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
}

/// Access control rules
#[derive(Debug, Clone)]
pub struct AccessPolicy {
    pub allowed_users: Vec<String>,
    pub allowed_hosts: Vec<String>,
    pub denied_commands: Vec<String>,
    pub require_mfa: bool,
    pub max_session_duration: std::time::Duration,
}

impl Default for AccessPolicy {
    fn default() -> Self {
        Self {
            allowed_users: vec!["*".to_string()],
            allowed_hosts: vec![],
            denied_commands: vec![
                "rm -rf /".to_string(),
                "mkfs".to_string(),
                "dd if=/dev".to_string(),
            ],
            require_mfa: false,
            max_session_duration: std::time::Duration::from_secs(3600 * 8), // 8 hours
        }
    }
}

/// SSH session manager with access control and logging
pub struct SshSessionManager {
    sessions: Arc<RwLock<HashMap<Uuid, SshSession>>>,
    policy: AccessPolicy,
    audit_log: Arc<RwLock<Vec<AuditEvent>>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub session_id: Option<Uuid>,
    pub user: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize)]
pub enum AuditEventType {
    SessionStart,
    SessionEnd,
    CommandExecuted,
    AccessDenied,
    PolicyViolation,
}

impl SshSessionManager {
    pub fn new(policy: AccessPolicy) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            policy,
            audit_log: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Check if access is allowed
    pub async fn check_access(&self, user: &str, host: &str) -> Result<(), AccessError> {
        // Check user allowlist
        if !self.policy.allowed_users.contains(&"*".to_string())
            && !self.policy.allowed_users.contains(&user.to_string()) {
            self.log_audit(AuditEvent {
                timestamp: Utc::now(),
                event_type: AuditEventType::AccessDenied,
                session_id: None,
                user: user.to_string(),
                details: format!("User not in allowlist"),
            }).await;
            return Err(AccessError::UserNotAllowed);
        }

        // Check host allowlist
        if !self.policy.allowed_hosts.is_empty()
            && !self.policy.allowed_hosts.contains(&host.to_string()) {
            self.log_audit(AuditEvent {
                timestamp: Utc::now(),
                event_type: AuditEventType::AccessDenied,
                session_id: None,
                user: user.to_string(),
                details: format!("Host {} not in allowlist", host),
            }).await;
            return Err(AccessError::HostNotAllowed);
        }

        Ok(())
    }

    /// Start a new SSH session
    pub async fn start_session(
        &self,
        user: &str,
        host: &str,
        port: u16,
        source_ip: Option<&str>,
    ) -> Result<Uuid, AccessError> {
        self.check_access(user, host).await?;

        let session = SshSession {
            id: Uuid::new_v4(),
            user: user.to_string(),
            host: host.to_string(),
            port,
            started_at: Utc::now(),
            ended_at: None,
            status: SessionStatus::Active,
            commands: Vec::new(),
            source_ip: source_ip.map(String::from),
        };

        let session_id = session.id;

        self.log_audit(AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::SessionStart,
            session_id: Some(session_id),
            user: user.to_string(),
            details: format!("Session started to {}:{}", host, port),
        }).await;

        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id, session);

        Ok(session_id)
    }

    /// Execute a command in a session
    pub async fn execute_command(
        &self,
        session_id: Uuid,
        command: &str,
    ) -> Result<CommandResult, AccessError> {
        // Check for denied commands
        for denied in &self.policy.denied_commands {
            if command.contains(denied) {
                self.log_audit(AuditEvent {
                    timestamp: Utc::now(),
                    event_type: AuditEventType::PolicyViolation,
                    session_id: Some(session_id),
                    user: self.get_session_user(session_id).await.unwrap_or_default(),
                    details: format!("Blocked command: {}", command),
                }).await;
                return Err(AccessError::CommandDenied);
            }
        }

        let start = std::time::Instant::now();

        // In a real implementation, this would execute via SSH
        // For demo, we simulate the execution
        let result = CommandResult {
            stdout: format!("Executed: {}", command),
            stderr: String::new(),
            exit_code: 0,
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        // Log the command
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&session_id) {
            session.commands.push(CommandLog {
                timestamp: Utc::now(),
                command: command.to_string(),
                exit_code: Some(result.exit_code),
                duration_ms,
            });
        }

        self.log_audit(AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::CommandExecuted,
            session_id: Some(session_id),
            user: self.get_session_user(session_id).await.unwrap_or_default(),
            details: format!("Command: {} (exit: {})", command, result.exit_code),
        }).await;

        Ok(result)
    }

    /// End a session
    pub async fn end_session(&self, session_id: Uuid, status: SessionStatus) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&session_id) {
            session.ended_at = Some(Utc::now());
            session.status = status;

            self.log_audit(AuditEvent {
                timestamp: Utc::now(),
                event_type: AuditEventType::SessionEnd,
                session_id: Some(session_id),
                user: session.user.clone(),
                details: format!("Session ended with status {:?}", status),
            }).await;
        }
    }

    /// Get session info
    pub async fn get_session(&self, session_id: Uuid) -> Option<SshSession> {
        let sessions = self.sessions.read().await;
        sessions.get(&session_id).cloned()
    }

    /// Get all active sessions
    pub async fn get_active_sessions(&self) -> Vec<SshSession> {
        let sessions = self.sessions.read().await;
        sessions.values()
            .filter(|s| s.status == SessionStatus::Active)
            .cloned()
            .collect()
    }

    /// Get audit log
    pub async fn get_audit_log(&self) -> Vec<AuditEvent> {
        let log = self.audit_log.read().await;
        log.clone()
    }

    async fn get_session_user(&self, session_id: Uuid) -> Option<String> {
        let sessions = self.sessions.read().await;
        sessions.get(&session_id).map(|s| s.user.clone())
    }

    async fn log_audit(&self, event: AuditEvent) {
        let mut log = self.audit_log.write().await;
        log.push(event);
    }
}

#[derive(Debug)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    #[error("User not allowed")]
    UserNotAllowed,
    #[error("Host not allowed")]
    HostNotAllowed,
    #[error("Command denied by policy")]
    CommandDenied,
    #[error("Session not found")]
    SessionNotFound,
    #[error("SSH error: {0}")]
    SshError(String),
}

/// SSH key management
pub struct SshKeyManager {
    keys_dir: std::path::PathBuf,
}

impl SshKeyManager {
    pub fn new(keys_dir: &std::path::Path) -> Self {
        Self {
            keys_dir: keys_dir.to_path_buf(),
        }
    }

    /// Generate a new SSH key pair
    pub fn generate_key(&self, name: &str, key_type: &str) -> Result<(), std::io::Error> {
        let private_key = self.keys_dir.join(name);
        let public_key = self.keys_dir.join(format!("{}.pub", name));

        Command::new("ssh-keygen")
            .args([
                "-t", key_type,
                "-f", private_key.to_str().unwrap(),
                "-N", "", // No passphrase for automated use
                "-C", &format!("managed-key-{}", name),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;

        // Set proper permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// List managed keys
    pub fn list_keys(&self) -> Result<Vec<String>, std::io::Error> {
        let mut keys = Vec::new();
        for entry in std::fs::read_dir(&self.keys_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".pub") && entry.file_type()?.is_file() {
                keys.push(name);
            }
        }
        Ok(keys)
    }
}

#[tokio::main]
async fn main() {
    println!("=== SSH Session Manager ===\n");

    let policy = AccessPolicy {
        allowed_users: vec!["admin".to_string(), "developer".to_string()],
        allowed_hosts: vec!["server1.example.com".to_string(), "server2.example.com".to_string()],
        denied_commands: vec!["rm -rf".to_string(), "shutdown".to_string()],
        require_mfa: false,
        max_session_duration: std::time::Duration::from_secs(3600),
    };

    let manager = SshSessionManager::new(policy);

    // Start a session
    println!("Starting session...");
    let session_id = manager.start_session(
        "admin",
        "server1.example.com",
        22,
        Some("192.168.1.100"),
    ).await.expect("Failed to start session");
    println!("Session ID: {}", session_id);

    // Execute commands
    println!("\nExecuting commands...");

    match manager.execute_command(session_id, "ls -la").await {
        Ok(result) => println!("Command succeeded: {}", result.stdout),
        Err(e) => println!("Command failed: {}", e),
    }

    match manager.execute_command(session_id, "cat /etc/passwd").await {
        Ok(result) => println!("Command succeeded: {}", result.stdout),
        Err(e) => println!("Command failed: {}", e),
    }

    // Try a denied command
    println!("\nTrying denied command...");
    match manager.execute_command(session_id, "rm -rf /tmp/test").await {
        Ok(_) => println!("ERROR: Should have been denied!"),
        Err(e) => println!("Correctly denied: {}", e),
    }

    // End session
    println!("\nEnding session...");
    manager.end_session(session_id, SessionStatus::Completed).await;

    // Show session info
    if let Some(session) = manager.get_session(session_id).await {
        println!("\nSession Summary:");
        println!("  User: {}", session.user);
        println!("  Host: {}", session.host);
        println!("  Commands executed: {}", session.commands.len());
        println!("  Status: {:?}", session.status);
    }

    // Show audit log
    println!("\nAudit Log:");
    for event in manager.get_audit_log().await {
        println!("  [{:?}] {} - {}", event.event_type, event.user, event.details);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_lifecycle() {
        let manager = SshSessionManager::new(AccessPolicy::default());

        let session_id = manager.start_session("user", "host", 22, None).await.unwrap();

        let session = manager.get_session(session_id).await.unwrap();
        assert_eq!(session.status, SessionStatus::Active);

        manager.end_session(session_id, SessionStatus::Completed).await;

        let session = manager.get_session(session_id).await.unwrap();
        assert_eq!(session.status, SessionStatus::Completed);
    }

    #[tokio::test]
    async fn test_access_denied() {
        let policy = AccessPolicy {
            allowed_users: vec!["admin".to_string()],
            ..Default::default()
        };
        let manager = SshSessionManager::new(policy);

        let result = manager.start_session("hacker", "host", 22, None).await;
        assert!(matches!(result, Err(AccessError::UserNotAllowed)));
    }

    #[tokio::test]
    async fn test_command_denied() {
        let manager = SshSessionManager::new(AccessPolicy::default());
        let session_id = manager.start_session("user", "host", 22, None).await.unwrap();

        let result = manager.execute_command(session_id, "rm -rf /").await;
        assert!(matches!(result, Err(AccessError::CommandDenied)));
    }
}
