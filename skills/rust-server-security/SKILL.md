# Rust Server Security Skills

This skill provides patterns for server hardening, SSH wrapper implementations,
and infrastructure security in Rust.

## Overview

Server security encompasses:

- **SSH Wrappers**: Access control and comprehensive logging
- **Firewall Integration**: iptables/nftables bindings
- **Process Isolation**: Seccomp, namespaces, cgroups
- **Audit Logging**: Tamper-evident logging systems
- **Privilege Management**: Capability-based security

## /server-harden

Generate a server hardening checklist and implementation plan.

### Usage

```bash
/server-harden
```

### What It Does

1. Analyzes current server configuration
2. Identifies security gaps
3. Generates hardening recommendations
4. Creates implementation scripts
5. Sets up monitoring and alerting

## /ssh-wrapper

Generate an SSH wrapper with comprehensive logging.

### Usage

```bash
/ssh-wrapper
```

### What It Does

1. Creates SSH command wrapper
2. Implements session logging
3. Adds command filtering
4. Sets up access control
5. Configures audit trail

---

## SSH Wrapper Implementation

### Basic SSH Wrapper

```rust
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader, Write};
use chrono::Utc;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct SshSession {
    pub session_id: String,
    pub user: String,
    pub source_ip: String,
    pub target_host: String,
    pub start_time: chrono::DateTime<Utc>,
    pub end_time: Option<chrono::DateTime<Utc>>,
    pub commands: Vec<CommandLog>,
}

#[derive(Debug, Serialize)]
pub struct CommandLog {
    pub timestamp: chrono::DateTime<Utc>,
    pub command: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
}

pub struct SshWrapper {
    config: SshWrapperConfig,
    logger: Box<dyn SessionLogger + Send + Sync>,
}

pub struct SshWrapperConfig {
    pub allowed_commands: Option<Vec<String>>,
    pub denied_commands: Vec<String>,
    pub max_session_duration: std::time::Duration,
    pub idle_timeout: std::time::Duration,
    pub log_output: bool,
}

impl SshWrapper {
    pub fn new(config: SshWrapperConfig, logger: Box<dyn SessionLogger + Send + Sync>) -> Self {
        Self { config, logger }
    }

    pub async fn execute_session(
        &self,
        user: &str,
        source_ip: &str,
        target: &str,
    ) -> Result<i32, Error> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let start_time = Utc::now();

        let mut session = SshSession {
            session_id: session_id.clone(),
            user: user.to_string(),
            source_ip: source_ip.to_string(),
            target_host: target.to_string(),
            start_time,
            end_time: None,
            commands: Vec::new(),
        };

        self.logger.log_session_start(&session).await?;

        // Execute SSH with PTY allocation
        let result = self.run_ssh_session(&mut session, target).await;

        session.end_time = Some(Utc::now());
        self.logger.log_session_end(&session).await?;

        result
    }

    async fn run_ssh_session(
        &self,
        session: &mut SshSession,
        target: &str,
    ) -> Result<i32, Error> {
        let mut child = Command::new("ssh")
            .args(["-t", target])  // Force PTY allocation
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(Error::ProcessSpawn)?;

        // Set up I/O handling with logging
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        // Stream output while logging
        let stdout_handle = tokio::spawn(async move {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(line) = line {
                    println!("{}", line);
                    // Log output if configured
                }
            }
        });

        let stderr_handle = tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    eprintln!("{}", line);
                }
            }
        });

        let status = child.wait().map_err(Error::ProcessWait)?;

        stdout_handle.await.ok();
        stderr_handle.await.ok();

        Ok(status.code().unwrap_or(-1))
    }

    fn is_command_allowed(&self, command: &str) -> bool {
        // Check denied list first
        for denied in &self.config.denied_commands {
            if command.contains(denied) {
                return false;
            }
        }

        // If allowed list is set, command must be in it
        if let Some(allowed) = &self.config.allowed_commands {
            return allowed.iter().any(|a| command.starts_with(a));
        }

        true
    }
}
```

### Session Logger Trait

```rust
use async_trait::async_trait;

#[async_trait]
pub trait SessionLogger {
    async fn log_session_start(&self, session: &SshSession) -> Result<(), Error>;
    async fn log_session_end(&self, session: &SshSession) -> Result<(), Error>;
    async fn log_command(&self, session_id: &str, command: &CommandLog) -> Result<(), Error>;
    async fn log_output(&self, session_id: &str, output: &str, is_stderr: bool) -> Result<(), Error>;
}

// File-based logger with tamper-evident hashing
pub struct FileSessionLogger {
    log_dir: std::path::PathBuf,
    hasher: ring::hmac::Key,
}

impl FileSessionLogger {
    pub fn new(log_dir: impl Into<std::path::PathBuf>, hmac_key: &[u8]) -> Self {
        Self {
            log_dir: log_dir.into(),
            hasher: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, hmac_key),
        }
    }

    fn compute_hash(&self, data: &[u8]) -> String {
        let tag = ring::hmac::sign(&self.hasher, data);
        hex::encode(tag.as_ref())
    }
}

#[async_trait]
impl SessionLogger for FileSessionLogger {
    async fn log_session_start(&self, session: &SshSession) -> Result<(), Error> {
        let log_entry = serde_json::to_string(session)?;
        let hash = self.compute_hash(log_entry.as_bytes());

        let log_line = format!("{}|{}\n", log_entry, hash);
        let log_path = self.log_dir.join(format!("{}.log", session.session_id));

        tokio::fs::write(&log_path, &log_line).await?;
        Ok(())
    }

    async fn log_session_end(&self, session: &SshSession) -> Result<(), Error> {
        let log_entry = serde_json::to_string(session)?;
        let hash = self.compute_hash(log_entry.as_bytes());

        let log_line = format!("{}|{}\n", log_entry, hash);
        let log_path = self.log_dir.join(format!("{}.log", session.session_id));

        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .await?;

        tokio::io::AsyncWriteExt::write_all(&mut file, log_line.as_bytes()).await?;
        Ok(())
    }

    async fn log_command(&self, session_id: &str, command: &CommandLog) -> Result<(), Error> {
        let log_entry = serde_json::to_string(command)?;
        let hash = self.compute_hash(log_entry.as_bytes());

        let log_line = format!("CMD|{}|{}\n", log_entry, hash);
        let log_path = self.log_dir.join(format!("{}.log", session_id));

        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .await?;

        tokio::io::AsyncWriteExt::write_all(&mut file, log_line.as_bytes()).await?;
        Ok(())
    }

    async fn log_output(&self, session_id: &str, output: &str, is_stderr: bool) -> Result<(), Error> {
        let stream = if is_stderr { "STDERR" } else { "STDOUT" };
        let hash = self.compute_hash(output.as_bytes());

        let log_line = format!("{}|{}|{}\n", stream, output, hash);
        let log_path = self.log_dir.join(format!("{}.log", session_id));

        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .await?;

        tokio::io::AsyncWriteExt::write_all(&mut file, log_line.as_bytes()).await?;
        Ok(())
    }
}
```

---

## Firewall Integration

### iptables Wrapper

```rust
use std::process::Command;

pub struct IptablesManager {
    table: String,
    chain: String,
}

#[derive(Debug, Clone)]
pub struct FirewallRule {
    pub action: RuleAction,
    pub protocol: Option<Protocol>,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub port: Option<u16>,
    pub interface: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum RuleAction {
    Accept,
    Drop,
    Reject,
    Log,
}

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    All,
}

impl IptablesManager {
    pub fn new(table: &str, chain: &str) -> Self {
        Self {
            table: table.to_string(),
            chain: chain.to_string(),
        }
    }

    pub fn add_rule(&self, rule: &FirewallRule) -> Result<(), Error> {
        let mut args = vec![
            "-t".to_string(),
            self.table.clone(),
            "-A".to_string(),
            self.chain.clone(),
        ];

        if let Some(protocol) = &rule.protocol {
            args.push("-p".to_string());
            args.push(protocol.to_string());
        }

        if let Some(source) = &rule.source {
            args.push("-s".to_string());
            args.push(source.clone());
        }

        if let Some(destination) = &rule.destination {
            args.push("-d".to_string());
            args.push(destination.clone());
        }

        if let Some(port) = rule.port {
            args.push("--dport".to_string());
            args.push(port.to_string());
        }

        if let Some(interface) = &rule.interface {
            args.push("-i".to_string());
            args.push(interface.clone());
        }

        args.push("-j".to_string());
        args.push(rule.action.to_string());

        let output = Command::new("iptables")
            .args(&args)
            .output()
            .map_err(Error::IptablesExec)?;

        if !output.status.success() {
            return Err(Error::IptablesError(
                String::from_utf8_lossy(&output.stderr).to_string()
            ));
        }

        Ok(())
    }

    pub fn delete_rule(&self, rule: &FirewallRule) -> Result<(), Error> {
        // Similar to add_rule but with -D instead of -A
        todo!()
    }

    pub fn list_rules(&self) -> Result<Vec<String>, Error> {
        let output = Command::new("iptables")
            .args(["-t", &self.table, "-L", &self.chain, "-n", "--line-numbers"])
            .output()
            .map_err(Error::IptablesExec)?;

        if !output.status.success() {
            return Err(Error::IptablesError(
                String::from_utf8_lossy(&output.stderr).to_string()
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.lines().skip(2).map(String::from).collect())
    }

    pub fn flush(&self) -> Result<(), Error> {
        let output = Command::new("iptables")
            .args(["-t", &self.table, "-F", &self.chain])
            .output()
            .map_err(Error::IptablesExec)?;

        if !output.status.success() {
            return Err(Error::IptablesError(
                String::from_utf8_lossy(&output.stderr).to_string()
            ));
        }

        Ok(())
    }
}

impl std::fmt::Display for RuleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleAction::Accept => write!(f, "ACCEPT"),
            RuleAction::Drop => write!(f, "DROP"),
            RuleAction::Reject => write!(f, "REJECT"),
            RuleAction::Log => write!(f, "LOG"),
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::All => write!(f, "all"),
        }
    }
}
```

### nftables Wrapper

```rust
pub struct NftablesManager {
    table_family: String,
    table_name: String,
}

impl NftablesManager {
    pub fn new(family: &str, table: &str) -> Self {
        Self {
            table_family: family.to_string(),
            table_name: table.to_string(),
        }
    }

    pub fn create_table(&self) -> Result<(), Error> {
        let cmd = format!(
            "add table {} {}",
            self.table_family,
            self.table_name
        );
        self.execute_nft(&cmd)
    }

    pub fn create_chain(&self, chain: &str, chain_type: &str, hook: &str, priority: i32) -> Result<(), Error> {
        let cmd = format!(
            "add chain {} {} {} {{ type {} hook {} priority {}; }}",
            self.table_family,
            self.table_name,
            chain,
            chain_type,
            hook,
            priority
        );
        self.execute_nft(&cmd)
    }

    pub fn add_rule(&self, chain: &str, rule: &str) -> Result<(), Error> {
        let cmd = format!(
            "add rule {} {} {} {}",
            self.table_family,
            self.table_name,
            chain,
            rule
        );
        self.execute_nft(&cmd)
    }

    fn execute_nft(&self, command: &str) -> Result<(), Error> {
        let output = Command::new("nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(stdin) = child.stdin.as_mut() {
                    stdin.write_all(command.as_bytes())?;
                }
                child.wait_with_output()
            })
            .map_err(Error::NftablesExec)?;

        if !output.status.success() {
            return Err(Error::NftablesError(
                String::from_utf8_lossy(&output.stderr).to_string()
            ));
        }

        Ok(())
    }
}
```

---

## Process Isolation with Seccomp

```rust
use seccompiler::{BpfMap, SeccompAction, SeccompFilter, SeccompRule};
use std::collections::BTreeMap;

pub fn create_strict_seccomp_filter() -> Result<BpfMap, Error> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Allow basic syscalls
    let allowed_syscalls = [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_futex,
        libc::SYS_clock_gettime,
        libc::SYS_getrandom,
    ];

    for syscall in allowed_syscalls {
        rules.insert(syscall, vec![SeccompRule::new(vec![]).unwrap()]);
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),  // Default: deny with EPERM
        SeccompAction::Allow,  // For allowed syscalls
        std::env::consts::ARCH.parse().unwrap(),
    )?;

    let mut bpf_map = BpfMap::new();
    bpf_map.insert("main".to_string(), filter.try_into()?);

    Ok(bpf_map)
}

pub fn apply_seccomp_filter(filter: &BpfMap) -> Result<(), Error> {
    if let Some(program) = filter.get("main") {
        seccompiler::apply_filter(program)?;
    }
    Ok(())
}
```

---

## Privilege Dropping

```rust
use nix::unistd::{setuid, setgid, Uid, Gid, User, Group};
use caps::{CapSet, Capability, CapsHashSet};

pub struct PrivilegeManager;

impl PrivilegeManager {
    /// Drop root privileges to specified user
    pub fn drop_privileges(username: &str) -> Result<(), Error> {
        let user = User::from_name(username)?
            .ok_or(Error::UserNotFound(username.to_string()))?;

        let group = Group::from_gid(user.gid)?
            .ok_or(Error::GroupNotFound(user.gid.as_raw()))?;

        // Set supplementary groups
        nix::unistd::setgroups(&[user.gid])?;

        // Set GID first (must be done before UID)
        setgid(user.gid)?;

        // Set UID
        setuid(user.uid)?;

        // Verify we can't get root back
        if nix::unistd::setuid(Uid::from_raw(0)).is_ok() {
            return Err(Error::PrivilegeDropFailed);
        }

        Ok(())
    }

    /// Set specific capabilities
    pub fn set_capabilities(caps: &[Capability]) -> Result<(), Error> {
        let mut permitted = CapsHashSet::new();
        let mut effective = CapsHashSet::new();

        for cap in caps {
            permitted.insert(*cap);
            effective.insert(*cap);
        }

        caps::set(None, CapSet::Permitted, &permitted)?;
        caps::set(None, CapSet::Effective, &effective)?;
        caps::set(None, CapSet::Inheritable, &CapsHashSet::new())?;

        Ok(())
    }

    /// Drop all capabilities
    pub fn drop_all_capabilities() -> Result<(), Error> {
        caps::clear(None, CapSet::Permitted)?;
        caps::clear(None, CapSet::Effective)?;
        caps::clear(None, CapSet::Inheritable)?;
        Ok(())
    }
}
```

---

## Audit Logging

```rust
use ring::hmac;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub actor: String,
    pub resource: String,
    pub action: String,
    pub outcome: AuditOutcome,
    pub details: serde_json::Value,
    #[serde(skip_serializing)]
    pub previous_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    Authentication,
    Authorization,
    FileAccess,
    NetworkConnection,
    ProcessExecution,
    ConfigurationChange,
    SecurityAlert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditOutcome {
    Success,
    Failure,
    Blocked,
}

pub struct AuditLogger {
    log_path: std::path::PathBuf,
    hmac_key: hmac::Key,
    last_hash: parking_lot::Mutex<String>,
}

impl AuditLogger {
    pub fn new(log_path: impl Into<std::path::PathBuf>, secret: &[u8]) -> Self {
        Self {
            log_path: log_path.into(),
            hmac_key: hmac::Key::new(hmac::HMAC_SHA256, secret),
            last_hash: parking_lot::Mutex::new(String::new()),
        }
    }

    pub fn log(&self, mut event: AuditEvent) -> Result<(), Error> {
        // Chain with previous hash for tamper detection
        {
            let last_hash = self.last_hash.lock();
            event.previous_hash = last_hash.clone();
        }

        // Serialize and compute hash
        let event_json = serde_json::to_string(&event)?;
        let tag = hmac::sign(&self.hmac_key, event_json.as_bytes());
        let current_hash = hex::encode(tag.as_ref());

        // Update last hash
        {
            let mut last_hash = self.last_hash.lock();
            *last_hash = current_hash.clone();
        }

        // Write to log file
        let log_line = format!("{}|{}\n", event_json, current_hash);

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;

        std::io::Write::write_all(&mut file, log_line.as_bytes())?;

        Ok(())
    }

    pub fn verify_integrity(&self) -> Result<bool, Error> {
        let content = std::fs::read_to_string(&self.log_path)?;
        let mut expected_prev_hash = String::new();

        for line in content.lines() {
            let parts: Vec<&str> = line.rsplitn(2, '|').collect();
            if parts.len() != 2 {
                return Ok(false);
            }

            let (hash, event_json) = (parts[0], parts[1]);

            // Verify HMAC
            let computed = hmac::sign(&self.hmac_key, event_json.as_bytes());
            if hex::encode(computed.as_ref()) != hash {
                return Ok(false);
            }

            // Verify chain
            let event: AuditEvent = serde_json::from_str(event_json)?;
            if event.previous_hash != expected_prev_hash {
                return Ok(false);
            }

            expected_prev_hash = hash.to_string();
        }

        Ok(true)
    }
}
```

---

## Server Hardening Checklist

### Network Security

- [ ] Firewall enabled with default deny
- [ ] SSH on non-standard port
- [ ] SSH key authentication only
- [ ] Fail2ban or similar configured
- [ ] Unnecessary ports closed

### Access Control

- [ ] Root login disabled
- [ ] sudo configured with audit
- [ ] User accounts with least privilege
- [ ] Strong password policy
- [ ] MFA enabled where possible

### File System

- [ ] Separate partitions for /tmp, /var
- [ ] noexec on /tmp
- [ ] File integrity monitoring (AIDE)
- [ ] Secure permissions on sensitive files

### Services

- [ ] Unnecessary services disabled
- [ ] Services running as non-root
- [ ] Seccomp/AppArmor/SELinux enabled
- [ ] Automatic security updates

### Logging

- [ ] Centralized logging
- [ ] Log rotation configured
- [ ] Tamper-evident audit logs
- [ ] Log monitoring and alerting

### Kernel

- [ ] Kernel hardening (sysctl)
- [ ] Address space randomization (ASLR)
- [ ] Stack protector enabled
- [ ] Kernel module loading restricted

## Recommended Crates

- **nix**: Unix system calls
- **caps**: Linux capabilities
- **seccompiler**: Seccomp filters
- **ring**: Cryptographic operations
- **chrono**: Date/time handling
- **tracing**: Structured logging

## Best Practices

1. **Principle of least privilege** - Run services with minimal permissions
2. **Defense in depth** - Multiple layers of security
3. **Audit everything** - Comprehensive logging
4. **Automate hardening** - Reproducible security configuration
5. **Regular updates** - Patch management
6. **Incident response** - Plan and practice
7. **Backup and recovery** - Tested restore procedures

## Integration Points

This skill works well with:

- `/ssh-wrapper` - SSH access control
- `/firewall-setup` - Firewall configuration
- `/systemd-harden` - Service hardening
