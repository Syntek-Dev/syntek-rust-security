//! Redis/Valkey Secure Connection Patterns
//!
//! Demonstrates secure Redis connection handling with:
//! - TLS/SSL connections
//! - Authentication with ACL users
//! - Connection pooling with health checks
//! - Command filtering and auditing
//! - Secure key prefix namespacing

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ============================================================================
// Connection Configuration
// ============================================================================

/// TLS configuration for Redis connection
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Path to CA certificate
    pub ca_cert_path: Option<String>,
    /// Path to client certificate
    pub client_cert_path: Option<String>,
    /// Path to client key
    pub client_key_path: Option<String>,
    /// Verify server certificate
    pub verify_peer: bool,
    /// Server name for SNI
    pub server_name: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            verify_peer: true,
            server_name: None,
        }
    }
}

/// Redis connection configuration
#[derive(Debug, Clone)]
pub struct RedisConfig {
    /// Host address
    pub host: String,
    /// Port number
    pub port: u16,
    /// ACL username (Redis 6.0+)
    pub username: Option<String>,
    /// Password or ACL password
    pub password: Option<String>,
    /// Database number (0-15)
    pub database: u8,
    /// TLS configuration
    pub tls: Option<TlsConfig>,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Read timeout
    pub read_timeout: Duration,
    /// Write timeout
    pub write_timeout: Duration,
    /// Key prefix for namespacing
    pub key_prefix: Option<String>,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 6379,
            username: None,
            password: None,
            database: 0,
            tls: None,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(3),
            write_timeout: Duration::from_secs(3),
            key_prefix: None,
        }
    }
}

impl RedisConfig {
    /// Create config for local development
    pub fn local() -> Self {
        Self::default()
    }

    /// Create config for production with TLS
    pub fn production(host: &str, port: u16, password: &str) -> Self {
        Self {
            host: host.to_string(),
            port,
            password: Some(password.to_string()),
            tls: Some(TlsConfig::default()),
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            ..Default::default()
        }
    }

    /// Build connection URL (for logging - masks password)
    pub fn connection_url_safe(&self) -> String {
        let auth = match (&self.username, &self.password) {
            (Some(user), Some(_)) => format!("{}:***@", user),
            (None, Some(_)) => ":***@".to_string(),
            _ => String::new(),
        };
        let scheme = if self.tls.is_some() {
            "rediss"
        } else {
            "redis"
        };
        format!(
            "{}://{}{}:{}/{}",
            scheme, auth, self.host, self.port, self.database
        )
    }
}

// ============================================================================
// Command Filter (Security Policy)
// ============================================================================

/// Dangerous commands that should be filtered
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DangerLevel {
    Safe,
    Moderate,
    Dangerous,
    Administrative,
}

/// Command security policy
pub struct CommandFilter {
    /// Commands explicitly allowed
    allowed_commands: HashSet<String>,
    /// Commands explicitly denied
    denied_commands: HashSet<String>,
    /// Whether to use allowlist (true) or denylist (false) mode
    allowlist_mode: bool,
    /// Maximum key pattern complexity (for KEYS, SCAN)
    max_pattern_length: usize,
}

impl CommandFilter {
    /// Create a restrictive filter (allowlist mode)
    pub fn restrictive() -> Self {
        let mut allowed = HashSet::new();
        // Safe read commands
        for cmd in [
            "GET",
            "MGET",
            "HGET",
            "HGETALL",
            "HMGET",
            "LRANGE",
            "SMEMBERS",
            "SISMEMBER",
            "ZRANGE",
            "ZRANGEBYSCORE",
            "EXISTS",
            "TYPE",
            "TTL",
            "PTTL",
        ] {
            allowed.insert(cmd.to_string());
        }
        // Safe write commands
        for cmd in [
            "SET", "SETEX", "PSETEX", "SETNX", "MSET", "HSET", "HMSET", "LPUSH", "RPUSH", "SADD",
            "ZADD", "INCR", "INCRBY", "DECR", "EXPIRE", "EXPIREAT", "PEXPIRE", "DEL",
        ] {
            allowed.insert(cmd.to_string());
        }

        Self {
            allowed_commands: allowed,
            denied_commands: HashSet::new(),
            allowlist_mode: true,
            max_pattern_length: 50,
        }
    }

    /// Create a permissive filter (denylist mode)
    pub fn permissive() -> Self {
        let mut denied = HashSet::new();
        // Dangerous administrative commands
        for cmd in [
            "FLUSHDB",
            "FLUSHALL",
            "DEBUG",
            "SHUTDOWN",
            "CONFIG",
            "SLAVEOF",
            "REPLICAOF",
            "MIGRATE",
            "RESTORE",
            "DUMP",
            "CLUSTER",
            "SLOWLOG",
            "BGSAVE",
            "BGREWRITEAOF",
            "SAVE",
            "ACL",
            "MODULE",
            "SCRIPT KILL",
            "CLIENT KILL",
        ] {
            denied.insert(cmd.to_string());
        }

        Self {
            allowed_commands: HashSet::new(),
            denied_commands: denied,
            allowlist_mode: false,
            max_pattern_length: 100,
        }
    }

    /// Check if a command is allowed
    pub fn check(&self, command: &str, args: &[&str]) -> Result<(), FilterError> {
        let cmd_upper = command.to_uppercase();

        // Check command allowlist/denylist
        if self.allowlist_mode {
            if !self.allowed_commands.contains(&cmd_upper) {
                return Err(FilterError::CommandNotAllowed(cmd_upper));
            }
        } else if self.denied_commands.contains(&cmd_upper) {
            return Err(FilterError::CommandDenied(cmd_upper));
        }

        // Check pattern commands
        if matches!(cmd_upper.as_str(), "KEYS" | "SCAN") {
            if let Some(pattern) = args.first() {
                if pattern.len() > self.max_pattern_length {
                    return Err(FilterError::PatternTooComplex(pattern.to_string()));
                }
                // Deny broad patterns
                if *pattern == "*" || pattern.starts_with("*") {
                    return Err(FilterError::PatternTooComplex(pattern.to_string()));
                }
            }
        }

        Ok(())
    }

    /// Get danger level for a command
    pub fn danger_level(command: &str) -> DangerLevel {
        match command.to_uppercase().as_str() {
            // Safe reads
            "GET" | "MGET" | "HGET" | "EXISTS" | "TYPE" | "TTL" => DangerLevel::Safe,
            // Safe writes
            "SET" | "SETEX" | "HSET" | "LPUSH" | "SADD" | "ZADD" => DangerLevel::Safe,
            // Moderate risk
            "DEL" | "KEYS" | "SCAN" | "EVAL" | "EVALSHA" => DangerLevel::Moderate,
            // Dangerous
            "FLUSHDB" | "RENAME" | "MIGRATE" => DangerLevel::Dangerous,
            // Administrative
            "FLUSHALL" | "CONFIG" | "DEBUG" | "SHUTDOWN" | "ACL" => DangerLevel::Administrative,
            _ => DangerLevel::Moderate,
        }
    }
}

#[derive(Debug)]
pub enum FilterError {
    CommandNotAllowed(String),
    CommandDenied(String),
    PatternTooComplex(String),
}

impl std::fmt::Display for FilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommandNotAllowed(cmd) => write!(f, "Command not in allowlist: {}", cmd),
            Self::CommandDenied(cmd) => write!(f, "Command denied: {}", cmd),
            Self::PatternTooComplex(pattern) => write!(f, "Pattern too complex: {}", pattern),
        }
    }
}

// ============================================================================
// Command Auditing
// ============================================================================

/// Audit log entry
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: Instant,
    pub command: String,
    pub args: Vec<String>,
    pub duration_us: u64,
    pub success: bool,
    pub error: Option<String>,
    pub client_id: String,
}

/// Command auditor
pub struct CommandAuditor {
    entries: Mutex<Vec<AuditEntry>>,
    max_entries: usize,
    audit_reads: bool,
    redact_values: bool,
}

impl CommandAuditor {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(Vec::with_capacity(max_entries)),
            max_entries,
            audit_reads: false,
            redact_values: true,
        }
    }

    /// Enable/disable read command auditing
    pub fn set_audit_reads(&mut self, audit: bool) {
        self.audit_reads = audit;
    }

    /// Record a command execution
    pub fn record(
        &self,
        command: &str,
        args: &[&str],
        duration: Duration,
        result: Result<(), &str>,
        client_id: &str,
    ) {
        // Skip reads if not auditing
        if !self.audit_reads
            && matches!(
                command.to_uppercase().as_str(),
                "GET" | "MGET" | "HGET" | "HGETALL" | "EXISTS" | "TYPE" | "TTL" | "SCAN"
            )
        {
            return;
        }

        let mut entries = self.entries.lock().unwrap();

        // Rotate if full
        if entries.len() >= self.max_entries {
            entries.remove(0);
        }

        let args_logged: Vec<String> = if self.redact_values {
            args.iter()
                .enumerate()
                .map(|(i, arg)| {
                    // Redact values (keep keys visible)
                    if i == 0 {
                        arg.to_string() // First arg is usually key
                    } else if arg.len() > 20 {
                        format!("[{} bytes]", arg.len())
                    } else {
                        "[redacted]".to_string()
                    }
                })
                .collect()
        } else {
            args.iter().map(|s| s.to_string()).collect()
        };

        entries.push(AuditEntry {
            timestamp: Instant::now(),
            command: command.to_uppercase(),
            args: args_logged,
            duration_us: duration.as_micros() as u64,
            success: result.is_ok(),
            error: result.err().map(|s| s.to_string()),
            client_id: client_id.to_string(),
        });
    }

    /// Get recent audit entries
    pub fn recent(&self, count: usize) -> Vec<AuditEntry> {
        let entries = self.entries.lock().unwrap();
        entries.iter().rev().take(count).cloned().collect()
    }

    /// Get slow queries (above threshold)
    pub fn slow_queries(&self, threshold_us: u64) -> Vec<AuditEntry> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .filter(|e| e.duration_us > threshold_us)
            .cloned()
            .collect()
    }
}

// ============================================================================
// Connection Pool
// ============================================================================

/// Connection pool configuration
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Minimum connections to maintain
    pub min_connections: usize,
    /// Maximum connections allowed
    pub max_connections: usize,
    /// Connection idle timeout
    pub idle_timeout: Duration,
    /// Health check interval
    pub health_check_interval: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_connections: 2,
            max_connections: 10,
            idle_timeout: Duration::from_secs(300),
            health_check_interval: Duration::from_secs(30),
        }
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionState {
    Available,
    InUse,
    Failed,
    Closed,
}

/// A pooled Redis connection (simulated)
pub struct PooledConnection {
    id: u64,
    state: ConnectionState,
    created_at: Instant,
    last_used: Instant,
    commands_executed: u64,
}

impl PooledConnection {
    fn new(id: u64) -> Self {
        let now = Instant::now();
        Self {
            id,
            state: ConnectionState::Available,
            created_at: now,
            last_used: now,
            commands_executed: 0,
        }
    }

    /// Simulate executing a command
    pub fn execute(&mut self, _command: &str, _args: &[&str]) -> Result<String, ConnectionError> {
        if self.state == ConnectionState::Failed {
            return Err(ConnectionError::ConnectionFailed(
                "Connection is in failed state".into(),
            ));
        }
        self.last_used = Instant::now();
        self.commands_executed += 1;
        Ok("OK".to_string())
    }

    /// Health check
    pub fn ping(&mut self) -> bool {
        // Simulate PING command
        self.last_used = Instant::now();
        self.state != ConnectionState::Failed
    }
}

/// Secure connection pool
pub struct SecureConnectionPool {
    config: RedisConfig,
    pool_config: PoolConfig,
    connections: Mutex<Vec<PooledConnection>>,
    next_id: AtomicU64,
    command_filter: CommandFilter,
    auditor: Arc<CommandAuditor>,
    is_shutdown: AtomicBool,
}

impl SecureConnectionPool {
    pub fn new(
        config: RedisConfig,
        pool_config: PoolConfig,
        command_filter: CommandFilter,
    ) -> Self {
        let pool = Self {
            config,
            pool_config: pool_config.clone(),
            connections: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
            command_filter,
            auditor: Arc::new(CommandAuditor::new(1000)),
            is_shutdown: AtomicBool::new(false),
        };

        // Create initial connections
        {
            let mut conns = pool.connections.lock().unwrap();
            for _ in 0..pool_config.min_connections {
                let id = pool.next_id.fetch_add(1, Ordering::Relaxed);
                conns.push(PooledConnection::new(id));
            }
        }

        pool
    }

    /// Execute a command with full security checks
    pub fn execute(&self, command: &str, args: &[&str]) -> Result<String, PoolError> {
        if self.is_shutdown.load(Ordering::Relaxed) {
            return Err(PoolError::PoolShutdown);
        }

        // Security filter check
        self.command_filter
            .check(command, args)
            .map_err(|e| PoolError::SecurityViolation(e.to_string()))?;

        // Apply key prefix
        let prefixed_args: Vec<String> = if let Some(prefix) = &self.config.key_prefix {
            args.iter()
                .enumerate()
                .map(|(i, arg)| {
                    // First arg is typically the key
                    if i == 0 && is_key_command(command) {
                        format!("{}:{}", prefix, arg)
                    } else {
                        arg.to_string()
                    }
                })
                .collect()
        } else {
            args.iter().map(|s| s.to_string()).collect()
        };

        let args_refs: Vec<&str> = prefixed_args.iter().map(|s| s.as_str()).collect();

        // Get connection from pool
        let start = Instant::now();
        let result = {
            let mut conns = self.connections.lock().unwrap();

            // Find available connection
            let conn = conns
                .iter_mut()
                .find(|c| c.state == ConnectionState::Available);

            match conn {
                Some(c) => {
                    c.state = ConnectionState::InUse;
                    let result = c.execute(command, &args_refs);
                    c.state = ConnectionState::Available;
                    result.map_err(|e| PoolError::ConnectionError(e.to_string()))
                }
                None => {
                    // Try to create new connection if under limit
                    if conns.len() < self.pool_config.max_connections {
                        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
                        let mut new_conn = PooledConnection::new(id);
                        let result = new_conn.execute(command, &args_refs);
                        conns.push(new_conn);
                        result.map_err(|e| PoolError::ConnectionError(e.to_string()))
                    } else {
                        Err(PoolError::PoolExhausted)
                    }
                }
            }
        };

        // Audit the command
        let duration = start.elapsed();
        self.auditor.record(
            command,
            &args_refs,
            duration,
            result
                .as_ref()
                .map(|_| ())
                .map_err(|e| e.to_string().as_str()),
            "client-1",
        );

        result
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        let conns = self.connections.lock().unwrap();
        PoolStats {
            total_connections: conns.len(),
            available: conns
                .iter()
                .filter(|c| c.state == ConnectionState::Available)
                .count(),
            in_use: conns
                .iter()
                .filter(|c| c.state == ConnectionState::InUse)
                .count(),
            failed: conns
                .iter()
                .filter(|c| c.state == ConnectionState::Failed)
                .count(),
            total_commands: conns.iter().map(|c| c.commands_executed).sum(),
        }
    }

    /// Health check all connections
    pub fn health_check(&self) -> usize {
        let mut conns = self.connections.lock().unwrap();
        let mut healthy = 0;

        for conn in conns.iter_mut() {
            if conn.ping() {
                healthy += 1;
            } else {
                conn.state = ConnectionState::Failed;
            }
        }

        healthy
    }

    /// Shutdown the pool
    pub fn shutdown(&self) {
        self.is_shutdown.store(true, Ordering::Relaxed);
        let mut conns = self.connections.lock().unwrap();
        for conn in conns.iter_mut() {
            conn.state = ConnectionState::Closed;
        }
        conns.clear();
    }

    /// Get the auditor
    pub fn auditor(&self) -> Arc<CommandAuditor> {
        Arc::clone(&self.auditor)
    }
}

fn is_key_command(command: &str) -> bool {
    matches!(
        command.to_uppercase().as_str(),
        "GET"
            | "SET"
            | "SETEX"
            | "DEL"
            | "EXISTS"
            | "EXPIRE"
            | "TTL"
            | "HGET"
            | "HSET"
            | "HGETALL"
            | "HDEL"
            | "LPUSH"
            | "RPUSH"
            | "LRANGE"
            | "LPOP"
            | "RPOP"
            | "SADD"
            | "SREM"
            | "SMEMBERS"
            | "SISMEMBER"
            | "ZADD"
            | "ZREM"
            | "ZRANGE"
            | "ZSCORE"
            | "INCR"
            | "INCRBY"
            | "DECR"
            | "DECRBY"
    )
}

#[derive(Debug)]
pub struct PoolStats {
    pub total_connections: usize,
    pub available: usize,
    pub in_use: usize,
    pub failed: usize,
    pub total_commands: u64,
}

#[derive(Debug)]
pub enum ConnectionError {
    ConnectionFailed(String),
    AuthenticationFailed(String),
    Timeout,
}

#[derive(Debug)]
pub enum PoolError {
    ConnectionError(String),
    PoolExhausted,
    PoolShutdown,
    SecurityViolation(String),
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionError(e) => write!(f, "Connection error: {}", e),
            Self::PoolExhausted => write!(f, "Connection pool exhausted"),
            Self::PoolShutdown => write!(f, "Connection pool is shutdown"),
            Self::SecurityViolation(e) => write!(f, "Security violation: {}", e),
        }
    }
}

// ============================================================================
// Secure Key Builder
// ============================================================================

/// Builder for type-safe Redis keys
pub struct KeyBuilder {
    prefix: String,
    parts: Vec<String>,
}

impl KeyBuilder {
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
            parts: vec![],
        }
    }

    pub fn add(mut self, part: &str) -> Self {
        // Validate part - no colons or special characters
        let sanitized: String = part
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
            .collect();
        self.parts.push(sanitized);
        self
    }

    pub fn add_id(self, id: impl std::fmt::Display) -> Self {
        self.add(&id.to_string())
    }

    pub fn build(&self) -> String {
        let mut key = self.prefix.clone();
        for part in &self.parts {
            key.push(':');
            key.push_str(part);
        }
        key
    }
}

/// Common key patterns
pub struct Keys;

impl Keys {
    pub fn user(user_id: &str) -> String {
        KeyBuilder::new("user").add(user_id).build()
    }

    pub fn user_session(user_id: &str, session_id: &str) -> String {
        KeyBuilder::new("session")
            .add(user_id)
            .add(session_id)
            .build()
    }

    pub fn cache(resource: &str, id: &str) -> String {
        KeyBuilder::new("cache").add(resource).add(id).build()
    }

    pub fn rate_limit(client_id: &str, resource: &str) -> String {
        KeyBuilder::new("ratelimit")
            .add(client_id)
            .add(resource)
            .build()
    }

    pub fn lock(resource: &str) -> String {
        KeyBuilder::new("lock").add(resource).build()
    }
}

// ============================================================================
// Main and Tests
// ============================================================================

fn main() {
    println!("Redis/Valkey Secure Connection Example\n");

    // Create secure configuration
    let config = RedisConfig {
        host: "localhost".to_string(),
        port: 6379,
        username: Some("app_user".to_string()),
        password: Some("secure_password".to_string()),
        database: 1,
        key_prefix: Some("myapp".to_string()),
        tls: Some(TlsConfig {
            verify_peer: true,
            ca_cert_path: Some("/etc/ssl/certs/ca-certificates.crt".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    println!("Connection URL (safe): {}", config.connection_url_safe());

    // Create connection pool with restrictive filter
    let pool =
        SecureConnectionPool::new(config, PoolConfig::default(), CommandFilter::restrictive());

    println!("\nPool Stats: {:?}", pool.stats());

    // Execute allowed commands
    println!("\n--- Executing Allowed Commands ---");

    match pool.execute("SET", &["user:123", "John Doe"]) {
        Ok(result) => println!("SET user:123: {}", result),
        Err(e) => println!("SET failed: {}", e),
    }

    match pool.execute("GET", &["user:123"]) {
        Ok(result) => println!("GET user:123: {}", result),
        Err(e) => println!("GET failed: {}", e),
    }

    // Try blocked commands
    println!("\n--- Attempting Blocked Commands ---");

    match pool.execute("FLUSHALL", &[]) {
        Ok(_) => println!("FLUSHALL: Unexpectedly succeeded"),
        Err(e) => println!("FLUSHALL: Blocked - {}", e),
    }

    match pool.execute("CONFIG", &["GET", "requirepass"]) {
        Ok(_) => println!("CONFIG: Unexpectedly succeeded"),
        Err(e) => println!("CONFIG: Blocked - {}", e),
    }

    match pool.execute("KEYS", &["*"]) {
        Ok(_) => println!("KEYS *: Unexpectedly succeeded"),
        Err(e) => println!("KEYS *: Blocked - {}", e),
    }

    // Show pool stats
    println!("\n--- Pool Statistics ---");
    let stats = pool.stats();
    println!("Total connections: {}", stats.total_connections);
    println!("Available: {}", stats.available);
    println!("In use: {}", stats.in_use);
    println!("Total commands: {}", stats.total_commands);

    // Show audit log
    println!("\n--- Recent Audit Entries ---");
    for entry in pool.auditor().recent(5) {
        println!(
            "  {} {:?} - {} ({} us)",
            entry.command,
            entry.args,
            if entry.success { "OK" } else { "FAILED" },
            entry.duration_us
        );
    }

    // Demonstrate key builder
    println!("\n--- Type-Safe Key Building ---");
    println!("User key: {}", Keys::user("123"));
    println!("Session key: {}", Keys::user_session("123", "abc"));
    println!("Cache key: {}", Keys::cache("products", "456"));
    println!("Rate limit key: {}", Keys::rate_limit("192.168.1.1", "api"));
    println!("Lock key: {}", Keys::lock("inventory-update"));

    // Custom key builder
    let custom_key = KeyBuilder::new("analytics")
        .add("events")
        .add("2024")
        .add_id(12)
        .build();
    println!("Custom key: {}", custom_key);

    // Shutdown
    pool.shutdown();
    println!("\nPool shutdown complete");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_url_masks_password() {
        let config = RedisConfig {
            host: "redis.example.com".to_string(),
            port: 6380,
            username: Some("user".to_string()),
            password: Some("secret123".to_string()),
            tls: Some(TlsConfig::default()),
            ..Default::default()
        };

        let url = config.connection_url_safe();
        assert!(url.contains("user:***@"));
        assert!(!url.contains("secret123"));
        assert!(url.starts_with("rediss://"));
    }

    #[test]
    fn test_command_filter_restrictive() {
        let filter = CommandFilter::restrictive();

        // Allowed commands
        assert!(filter.check("GET", &["key"]).is_ok());
        assert!(filter.check("SET", &["key", "value"]).is_ok());
        assert!(filter.check("HGET", &["hash", "field"]).is_ok());

        // Denied commands
        assert!(filter.check("FLUSHALL", &[]).is_err());
        assert!(filter.check("CONFIG", &["GET", "*"]).is_err());
        assert!(filter.check("DEBUG", &["SEGFAULT"]).is_err());
    }

    #[test]
    fn test_command_filter_blocks_broad_patterns() {
        let filter = CommandFilter::restrictive();

        // KEYS with wildcard should be blocked
        assert!(filter.check("KEYS", &["*"]).is_err());
        assert!(filter.check("KEYS", &["*pattern*"]).is_err());
    }

    #[test]
    fn test_danger_levels() {
        assert_eq!(CommandFilter::danger_level("GET"), DangerLevel::Safe);
        assert_eq!(CommandFilter::danger_level("DEL"), DangerLevel::Moderate);
        assert_eq!(
            CommandFilter::danger_level("FLUSHDB"),
            DangerLevel::Dangerous
        );
        assert_eq!(
            CommandFilter::danger_level("CONFIG"),
            DangerLevel::Administrative
        );
    }

    #[test]
    fn test_connection_pool() {
        let pool = SecureConnectionPool::new(
            RedisConfig::default(),
            PoolConfig {
                min_connections: 2,
                max_connections: 5,
                ..Default::default()
            },
            CommandFilter::restrictive(),
        );

        let stats = pool.stats();
        assert_eq!(stats.total_connections, 2);
        assert_eq!(stats.available, 2);

        // Execute a command
        let result = pool.execute("SET", &["test", "value"]);
        assert!(result.is_ok());

        let stats = pool.stats();
        assert!(stats.total_commands > 0);
    }

    #[test]
    fn test_pool_security_violation() {
        let pool = SecureConnectionPool::new(
            RedisConfig::default(),
            PoolConfig::default(),
            CommandFilter::restrictive(),
        );

        let result = pool.execute("FLUSHALL", &[]);
        assert!(matches!(result, Err(PoolError::SecurityViolation(_))));
    }

    #[test]
    fn test_key_builder() {
        let key = KeyBuilder::new("app").add("users").add_id(123).build();
        assert_eq!(key, "app:users:123");
    }

    #[test]
    fn test_key_builder_sanitizes() {
        let key = KeyBuilder::new("app").add("user:malicious").build();
        // Colons should be stripped
        assert_eq!(key, "app:usermalicious");
    }

    #[test]
    fn test_keys_patterns() {
        assert_eq!(Keys::user("123"), "user:123");
        assert_eq!(Keys::user_session("123", "abc"), "session:123:abc");
        assert_eq!(Keys::cache("products", "456"), "cache:products:456");
    }

    #[test]
    fn test_auditor() {
        let auditor = CommandAuditor::new(100);

        auditor.record(
            "SET",
            &["key", "value"],
            Duration::from_micros(50),
            Ok(()),
            "client-1",
        );
        auditor.record(
            "DEL",
            &["key"],
            Duration::from_micros(30),
            Ok(()),
            "client-1",
        );

        let recent = auditor.recent(10);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].command, "DEL");
        assert_eq!(recent[1].command, "SET");
    }

    #[test]
    fn test_pool_shutdown() {
        let pool = SecureConnectionPool::new(
            RedisConfig::default(),
            PoolConfig::default(),
            CommandFilter::restrictive(),
        );

        pool.shutdown();

        let result = pool.execute("GET", &["key"]);
        assert!(matches!(result, Err(PoolError::PoolShutdown)));
    }
}
