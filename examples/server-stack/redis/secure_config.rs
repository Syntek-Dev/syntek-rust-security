//! Redis/Valkey Secure Configuration Generator
//!
//! Generates security-hardened configurations for:
//! - Authentication (ACL users)
//! - TLS encryption
//! - Network security
//! - Memory and resource limits
//! - Persistence security

use std::collections::{HashMap, HashSet};

// ============================================================================
// Configuration Types
// ============================================================================

/// Redis deployment mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DeploymentMode {
    /// Single instance
    Standalone,
    /// Master-replica replication
    Replication,
    /// Redis Sentinel for HA
    Sentinel,
    /// Redis Cluster
    Cluster,
}

/// TLS configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_file: String,
    pub key_file: String,
    pub ca_cert_file: Option<String>,
    pub dh_params_file: Option<String>,
    pub protocols: Vec<String>,
    pub ciphers: Option<String>,
    pub prefer_server_ciphers: bool,
    pub client_auth: TlsClientAuth,
}

#[derive(Debug, Clone, Copy)]
pub enum TlsClientAuth {
    No,
    Optional,
    Required,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_file: "/etc/redis/tls/redis.crt".to_string(),
            key_file: "/etc/redis/tls/redis.key".to_string(),
            ca_cert_file: Some("/etc/redis/tls/ca.crt".to_string()),
            dh_params_file: None,
            protocols: vec!["TLSv1.2".to_string(), "TLSv1.3".to_string()],
            ciphers: None,
            prefer_server_ciphers: true,
            client_auth: TlsClientAuth::Optional,
        }
    }
}

/// ACL user definition
#[derive(Debug, Clone)]
pub struct AclUser {
    pub username: String,
    pub password_hash: Option<String>,
    pub enabled: bool,
    pub commands: AclCommands,
    pub keys: AclKeys,
    pub channels: AclChannels,
}

#[derive(Debug, Clone)]
pub enum AclCommands {
    /// All commands allowed
    All,
    /// No commands allowed
    None,
    /// Specific commands allowed
    Allow(HashSet<String>),
    /// All except these commands
    AllExcept(HashSet<String>),
    /// Category-based permissions
    Categories(Vec<String>),
}

#[derive(Debug, Clone)]
pub enum AclKeys {
    /// All keys accessible
    All,
    /// No keys accessible
    None,
    /// Specific key patterns
    Patterns(Vec<String>),
}

#[derive(Debug, Clone)]
pub enum AclChannels {
    /// All channels accessible
    All,
    /// No channels accessible
    None,
    /// Specific channel patterns
    Patterns(Vec<String>),
}

impl AclUser {
    /// Create an admin user with full access
    pub fn admin(username: &str, password_hash: &str) -> Self {
        Self {
            username: username.to_string(),
            password_hash: Some(password_hash.to_string()),
            enabled: true,
            commands: AclCommands::All,
            keys: AclKeys::All,
            channels: AclChannels::All,
        }
    }

    /// Create a read-only user
    pub fn readonly(username: &str, password_hash: &str, key_pattern: &str) -> Self {
        let mut allowed = HashSet::new();
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
            "EXISTS",
            "TYPE",
            "TTL",
            "PTTL",
            "SCAN",
            "HSCAN",
            "SSCAN",
            "ZSCAN",
            "KEYS",
        ] {
            allowed.insert(cmd.to_string());
        }

        Self {
            username: username.to_string(),
            password_hash: Some(password_hash.to_string()),
            enabled: true,
            commands: AclCommands::Allow(allowed),
            keys: AclKeys::Patterns(vec![key_pattern.to_string()]),
            channels: AclChannels::None,
        }
    }

    /// Create an application user with limited access
    pub fn application(username: &str, password_hash: &str, key_prefix: &str) -> Self {
        let mut blocked = HashSet::new();
        // Block dangerous commands
        for cmd in [
            "FLUSHDB",
            "FLUSHALL",
            "DEBUG",
            "CONFIG",
            "SHUTDOWN",
            "SLAVEOF",
            "REPLICAOF",
            "ACL",
            "MODULE",
            "BGSAVE",
            "BGREWRITEAOF",
            "SAVE",
            "CLUSTER",
            "MIGRATE",
        ] {
            blocked.insert(cmd.to_string());
        }

        Self {
            username: username.to_string(),
            password_hash: Some(password_hash.to_string()),
            enabled: true,
            commands: AclCommands::AllExcept(blocked),
            keys: AclKeys::Patterns(vec![format!("{}:*", key_prefix)]),
            channels: AclChannels::Patterns(vec![format!("{}:*", key_prefix)]),
        }
    }

    /// Generate ACL rule string
    pub fn to_acl_rule(&self) -> String {
        let mut parts = Vec::new();

        // Username
        parts.push(format!("user {}", self.username));

        // Enabled/disabled
        if self.enabled {
            parts.push("on".to_string());
        } else {
            parts.push("off".to_string());
        }

        // Password
        if let Some(ref hash) = self.password_hash {
            parts.push(format!("#{}", hash));
        } else {
            parts.push("nopass".to_string());
        }

        // Commands
        match &self.commands {
            AclCommands::All => parts.push("+@all".to_string()),
            AclCommands::None => parts.push("-@all".to_string()),
            AclCommands::Allow(cmds) => {
                parts.push("-@all".to_string());
                for cmd in cmds {
                    parts.push(format!("+{}", cmd.to_lowercase()));
                }
            }
            AclCommands::AllExcept(cmds) => {
                parts.push("+@all".to_string());
                for cmd in cmds {
                    parts.push(format!("-{}", cmd.to_lowercase()));
                }
            }
            AclCommands::Categories(cats) => {
                parts.push("-@all".to_string());
                for cat in cats {
                    parts.push(format!("+@{}", cat));
                }
            }
        }

        // Keys
        match &self.keys {
            AclKeys::All => parts.push("~*".to_string()),
            AclKeys::None => {} // No key access
            AclKeys::Patterns(patterns) => {
                for pattern in patterns {
                    parts.push(format!("~{}", pattern));
                }
            }
        }

        // Channels
        match &self.channels {
            AclChannels::All => parts.push("&*".to_string()),
            AclChannels::None => {} // No channel access
            AclChannels::Patterns(patterns) => {
                for pattern in patterns {
                    parts.push(format!("&{}", pattern));
                }
            }
        }

        parts.join(" ")
    }
}

/// Memory configuration
#[derive(Debug, Clone)]
pub struct MemoryConfig {
    /// Maximum memory in bytes (0 = unlimited)
    pub maxmemory: u64,
    /// Eviction policy
    pub maxmemory_policy: EvictionPolicy,
    /// Eviction samples
    pub maxmemory_samples: u32,
    /// Active defragmentation
    pub active_defrag: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum EvictionPolicy {
    NoEviction,
    AllKeysLru,
    AllKeysLfu,
    AllKeysRandom,
    VolatileLru,
    VolatileLfu,
    VolatileRandom,
    VolatileTtl,
}

impl EvictionPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoEviction => "noeviction",
            Self::AllKeysLru => "allkeys-lru",
            Self::AllKeysLfu => "allkeys-lfu",
            Self::AllKeysRandom => "allkeys-random",
            Self::VolatileLru => "volatile-lru",
            Self::VolatileLfu => "volatile-lfu",
            Self::VolatileRandom => "volatile-random",
            Self::VolatileTtl => "volatile-ttl",
        }
    }
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            maxmemory: 0,
            maxmemory_policy: EvictionPolicy::NoEviction,
            maxmemory_samples: 5,
            active_defrag: false,
        }
    }
}

/// Persistence configuration
#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    /// RDB snapshots enabled
    pub rdb_enabled: bool,
    /// RDB save rules (seconds, changes)
    pub rdb_save_rules: Vec<(u64, u64)>,
    /// RDB filename
    pub rdb_filename: String,
    /// RDB compression
    pub rdb_compression: bool,
    /// RDB checksum
    pub rdb_checksum: bool,
    /// AOF enabled
    pub aof_enabled: bool,
    /// AOF filename
    pub aof_filename: String,
    /// AOF fsync policy
    pub aof_fsync: AofFsync,
    /// AOF rewrite settings
    pub aof_rewrite_percentage: u32,
    pub aof_rewrite_min_size: String,
}

#[derive(Debug, Clone, Copy)]
pub enum AofFsync {
    Always,
    Everysec,
    No,
}

impl AofFsync {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Everysec => "everysec",
            Self::No => "no",
        }
    }
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            rdb_enabled: true,
            rdb_save_rules: vec![
                (900, 1),    // 15 minutes if at least 1 change
                (300, 10),   // 5 minutes if at least 10 changes
                (60, 10000), // 1 minute if at least 10000 changes
            ],
            rdb_filename: "dump.rdb".to_string(),
            rdb_compression: true,
            rdb_checksum: true,
            aof_enabled: true,
            aof_filename: "appendonly.aof".to_string(),
            aof_fsync: AofFsync::Everysec,
            aof_rewrite_percentage: 100,
            aof_rewrite_min_size: "64mb".to_string(),
        }
    }
}

/// Network security configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Bind addresses
    pub bind: Vec<String>,
    /// Port (0 to disable TCP)
    pub port: u16,
    /// Unix socket path
    pub unix_socket: Option<String>,
    /// Unix socket permissions
    pub unix_socket_perm: u32,
    /// Protected mode
    pub protected_mode: bool,
    /// TCP backlog
    pub tcp_backlog: u32,
    /// Timeout for idle connections
    pub timeout: u32,
    /// TCP keepalive
    pub tcp_keepalive: u32,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bind: vec!["127.0.0.1".to_string()],
            port: 6379,
            unix_socket: None,
            unix_socket_perm: 0o700,
            protected_mode: true,
            tcp_backlog: 511,
            timeout: 0,
            tcp_keepalive: 300,
        }
    }
}

// ============================================================================
// Main Configuration
// ============================================================================

/// Complete Redis configuration
#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub mode: DeploymentMode,
    pub network: NetworkConfig,
    pub tls: TlsConfig,
    pub users: Vec<AclUser>,
    pub memory: MemoryConfig,
    pub persistence: PersistenceConfig,
    /// Data directory
    pub dir: String,
    /// Log file
    pub logfile: String,
    /// Log level
    pub loglevel: LogLevel,
    /// Daemonize
    pub daemonize: bool,
    /// PID file
    pub pidfile: String,
    /// Client output buffer limits
    pub client_output_buffer_limits: HashMap<String, (String, String, u32)>,
    /// Dangerous commands renamed
    pub rename_commands: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Debug,
    Verbose,
    Notice,
    Warning,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Verbose => "verbose",
            Self::Notice => "notice",
            Self::Warning => "warning",
        }
    }
}

impl Default for RedisConfig {
    fn default() -> Self {
        let mut rename_commands = HashMap::new();
        // Rename dangerous commands
        rename_commands.insert("FLUSHALL".to_string(), "".to_string()); // Disable
        rename_commands.insert("FLUSHDB".to_string(), "".to_string()); // Disable
        rename_commands.insert("DEBUG".to_string(), "".to_string()); // Disable
        rename_commands.insert(
            "CONFIG".to_string(),
            format!("CONFIG_{}", generate_random_suffix()),
        );
        rename_commands.insert(
            "SHUTDOWN".to_string(),
            format!("SHUTDOWN_{}", generate_random_suffix()),
        );

        let mut buffer_limits = HashMap::new();
        buffer_limits.insert("normal".to_string(), ("0".to_string(), "0".to_string(), 0));
        buffer_limits.insert(
            "replica".to_string(),
            ("256mb".to_string(), "64mb".to_string(), 60),
        );
        buffer_limits.insert(
            "pubsub".to_string(),
            ("32mb".to_string(), "8mb".to_string(), 60),
        );

        Self {
            mode: DeploymentMode::Standalone,
            network: NetworkConfig::default(),
            tls: TlsConfig::default(),
            users: vec![],
            memory: MemoryConfig::default(),
            persistence: PersistenceConfig::default(),
            dir: "/var/lib/redis".to_string(),
            logfile: "/var/log/redis/redis-server.log".to_string(),
            loglevel: LogLevel::Notice,
            daemonize: false,
            pidfile: "/var/run/redis/redis-server.pid".to_string(),
            client_output_buffer_limits: buffer_limits,
            rename_commands,
        }
    }
}

impl RedisConfig {
    /// Create a secure production configuration
    pub fn production() -> Self {
        let mut config = Self::default();

        // Enable TLS
        config.tls.enabled = true;

        // Add default admin user
        config
            .users
            .push(AclUser::admin("admin", "replace_with_sha256_hash"));

        // Disable default user
        config.users.push(AclUser {
            username: "default".to_string(),
            password_hash: None,
            enabled: false,
            commands: AclCommands::None,
            keys: AclKeys::None,
            channels: AclChannels::None,
        });

        // Set memory limits
        config.memory.maxmemory = 2 * 1024 * 1024 * 1024; // 2GB
        config.memory.maxmemory_policy = EvictionPolicy::AllKeysLru;

        config
    }

    /// Create a development configuration
    pub fn development() -> Self {
        let mut config = Self::default();
        config.network.protected_mode = false;
        config.loglevel = LogLevel::Debug;
        config
    }

    /// Add an ACL user
    pub fn add_user(&mut self, user: AclUser) {
        self.users.push(user);
    }

    /// Enable TLS with certificates
    pub fn enable_tls(&mut self, cert: &str, key: &str, ca: Option<&str>) {
        self.tls.enabled = true;
        self.tls.cert_file = cert.to_string();
        self.tls.key_file = key.to_string();
        self.tls.ca_cert_file = ca.map(|s| s.to_string());
    }

    /// Generate configuration file content
    pub fn to_config_file(&self) -> String {
        let mut config = String::new();

        // Header
        config.push_str("# Redis Security Configuration\n");
        config.push_str("# Generated by syntek-rust-security\n\n");

        // Network
        config.push_str("# Network\n");
        config.push_str(&format!("bind {}\n", self.network.bind.join(" ")));
        config.push_str(&format!("port {}\n", self.network.port));
        config.push_str(&format!(
            "protected-mode {}\n",
            if self.network.protected_mode {
                "yes"
            } else {
                "no"
            }
        ));
        config.push_str(&format!("tcp-backlog {}\n", self.network.tcp_backlog));
        config.push_str(&format!("timeout {}\n", self.network.timeout));
        config.push_str(&format!("tcp-keepalive {}\n", self.network.tcp_keepalive));

        if let Some(ref socket) = self.network.unix_socket {
            config.push_str(&format!("unixsocket {}\n", socket));
            config.push_str(&format!(
                "unixsocketperm {:03o}\n",
                self.network.unix_socket_perm
            ));
        }

        // TLS
        if self.tls.enabled {
            config.push_str("\n# TLS\n");
            config.push_str(&format!("tls-port {}\n", self.network.port));
            config.push_str("port 0\n"); // Disable non-TLS
            config.push_str(&format!("tls-cert-file {}\n", self.tls.cert_file));
            config.push_str(&format!("tls-key-file {}\n", self.tls.key_file));
            if let Some(ref ca) = self.tls.ca_cert_file {
                config.push_str(&format!("tls-ca-cert-file {}\n", ca));
            }
            config.push_str(&format!(
                "tls-auth-clients {}\n",
                match self.tls.client_auth {
                    TlsClientAuth::No => "no",
                    TlsClientAuth::Optional => "optional",
                    TlsClientAuth::Required => "yes",
                }
            ));
            config.push_str(&format!(
                "tls-protocols \"{}\"\n",
                self.tls.protocols.join(" ")
            ));
            config.push_str(&format!(
                "tls-prefer-server-ciphers {}\n",
                if self.tls.prefer_server_ciphers {
                    "yes"
                } else {
                    "no"
                }
            ));
        }

        // General
        config.push_str("\n# General\n");
        config.push_str(&format!(
            "daemonize {}\n",
            if self.daemonize { "yes" } else { "no" }
        ));
        config.push_str(&format!("pidfile {}\n", self.pidfile));
        config.push_str(&format!("loglevel {}\n", self.loglevel.as_str()));
        config.push_str(&format!("logfile {}\n", self.logfile));
        config.push_str(&format!("dir {}\n", self.dir));

        // Memory
        config.push_str("\n# Memory\n");
        if self.memory.maxmemory > 0 {
            config.push_str(&format!("maxmemory {}\n", self.memory.maxmemory));
        }
        config.push_str(&format!(
            "maxmemory-policy {}\n",
            self.memory.maxmemory_policy.as_str()
        ));
        config.push_str(&format!(
            "maxmemory-samples {}\n",
            self.memory.maxmemory_samples
        ));
        config.push_str(&format!(
            "activedefrag {}\n",
            if self.memory.active_defrag {
                "yes"
            } else {
                "no"
            }
        ));

        // Persistence
        config.push_str("\n# Persistence\n");
        if self.persistence.rdb_enabled {
            for (seconds, changes) in &self.persistence.rdb_save_rules {
                config.push_str(&format!("save {} {}\n", seconds, changes));
            }
            config.push_str(&format!("dbfilename {}\n", self.persistence.rdb_filename));
            config.push_str(&format!(
                "rdbcompression {}\n",
                if self.persistence.rdb_compression {
                    "yes"
                } else {
                    "no"
                }
            ));
            config.push_str(&format!(
                "rdbchecksum {}\n",
                if self.persistence.rdb_checksum {
                    "yes"
                } else {
                    "no"
                }
            ));
        } else {
            config.push_str("save \"\"\n");
        }

        if self.persistence.aof_enabled {
            config.push_str("appendonly yes\n");
            config.push_str(&format!(
                "appendfilename \"{}\"\n",
                self.persistence.aof_filename
            ));
            config.push_str(&format!(
                "appendfsync {}\n",
                self.persistence.aof_fsync.as_str()
            ));
            config.push_str(&format!(
                "auto-aof-rewrite-percentage {}\n",
                self.persistence.aof_rewrite_percentage
            ));
            config.push_str(&format!(
                "auto-aof-rewrite-min-size {}\n",
                self.persistence.aof_rewrite_min_size
            ));
        }

        // Client output buffer limits
        config.push_str("\n# Client Output Buffer Limits\n");
        for (class, (hard, soft, seconds)) in &self.client_output_buffer_limits {
            config.push_str(&format!(
                "client-output-buffer-limit {} {} {} {}\n",
                class, hard, soft, seconds
            ));
        }

        // Renamed commands
        config.push_str("\n# Security: Renamed Commands\n");
        for (from, to) in &self.rename_commands {
            config.push_str(&format!("rename-command {} \"{}\"\n", from, to));
        }

        // ACL users
        if !self.users.is_empty() {
            config.push_str("\n# ACL Users\n");
            config.push_str("aclfile /etc/redis/users.acl\n");
        }

        config
    }

    /// Generate ACL file content
    pub fn to_acl_file(&self) -> String {
        let mut acl = String::new();
        acl.push_str("# Redis ACL Configuration\n");
        acl.push_str("# Generated by syntek-rust-security\n\n");

        for user in &self.users {
            acl.push_str(&user.to_acl_rule());
            acl.push('\n');
        }

        acl
    }

    /// Generate systemd service file
    pub fn to_systemd_service(&self) -> String {
        format!(
            r#"[Unit]
Description=Redis In-Memory Data Store
After=network.target

[Service]
Type=notify
User=redis
Group=redis
ExecStart=/usr/bin/redis-server /etc/redis/redis.conf
ExecStop=/usr/bin/redis-cli shutdown
Restart=always
RestartSec=3
LimitNOFILE=65535

# Security Hardening
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths={dir}
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
SystemCallArchitectures=native
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
"#,
            dir = self.dir
        )
    }
}

// ============================================================================
// Utilities
// ============================================================================

fn generate_random_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:08x}", (seed & 0xFFFFFFFF) as u32)
}

// ============================================================================
// Main and Tests
// ============================================================================

fn main() {
    println!("Redis/Valkey Secure Configuration Generator\n");

    // Create production configuration
    let mut config = RedisConfig::production();

    // Add application users
    config.add_user(AclUser::application(
        "webapp",
        "sha256_hash_of_password",
        "webapp",
    ));

    config.add_user(AclUser::readonly(
        "monitoring",
        "sha256_hash_of_password",
        "*",
    ));

    // Enable TLS
    config.enable_tls(
        "/etc/redis/tls/redis.crt",
        "/etc/redis/tls/redis.key",
        Some("/etc/redis/tls/ca.crt"),
    );

    // Set memory limit
    config.memory.maxmemory = 4 * 1024 * 1024 * 1024; // 4GB
    config.memory.maxmemory_policy = EvictionPolicy::AllKeysLfu;

    // Print configuration
    println!("=== redis.conf ===\n");
    println!("{}", config.to_config_file());

    println!("\n=== users.acl ===\n");
    println!("{}", config.to_acl_file());

    println!("\n=== redis.service (systemd) ===\n");
    println!("{}", config.to_systemd_service());

    // Development configuration
    println!("\n=== Development Configuration ===\n");
    let dev_config = RedisConfig::development();
    println!("Protected mode: {}", dev_config.network.protected_mode);
    println!("Log level: {}", dev_config.loglevel.as_str());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acl_user_admin() {
        let user = AclUser::admin("admin", "hash123");
        let rule = user.to_acl_rule();

        assert!(rule.contains("user admin"));
        assert!(rule.contains("on"));
        assert!(rule.contains("+@all"));
        assert!(rule.contains("~*"));
    }

    #[test]
    fn test_acl_user_readonly() {
        let user = AclUser::readonly("reader", "hash", "cache:*");
        let rule = user.to_acl_rule();

        assert!(rule.contains("user reader"));
        assert!(rule.contains("-@all"));
        assert!(rule.contains("+get"));
        assert!(rule.contains("~cache:*"));
    }

    #[test]
    fn test_acl_user_application() {
        let user = AclUser::application("app", "hash", "myapp");
        let rule = user.to_acl_rule();

        assert!(rule.contains("user app"));
        assert!(rule.contains("+@all"));
        assert!(rule.contains("-flushall"));
        assert!(rule.contains("~myapp:*"));
    }

    #[test]
    fn test_config_generation() {
        let config = RedisConfig::default();
        let output = config.to_config_file();

        assert!(output.contains("bind 127.0.0.1"));
        assert!(output.contains("port 6379"));
        assert!(output.contains("protected-mode yes"));
    }

    #[test]
    fn test_tls_config() {
        let mut config = RedisConfig::default();
        config.enable_tls("/cert.pem", "/key.pem", Some("/ca.pem"));

        let output = config.to_config_file();
        assert!(output.contains("tls-port"));
        assert!(output.contains("tls-cert-file /cert.pem"));
    }

    #[test]
    fn test_production_config() {
        let config = RedisConfig::production();

        assert!(config.tls.enabled);
        assert!(config.memory.maxmemory > 0);
        assert!(!config.users.is_empty());
    }

    #[test]
    fn test_eviction_policy() {
        assert_eq!(EvictionPolicy::AllKeysLru.as_str(), "allkeys-lru");
        assert_eq!(EvictionPolicy::VolatileTtl.as_str(), "volatile-ttl");
    }

    #[test]
    fn test_systemd_service() {
        let config = RedisConfig::default();
        let service = config.to_systemd_service();

        assert!(service.contains("[Unit]"));
        assert!(service.contains("[Service]"));
        assert!(service.contains("NoNewPrivileges=yes"));
    }

    #[test]
    fn test_rename_commands() {
        let config = RedisConfig::default();

        assert!(config.rename_commands.contains_key("FLUSHALL"));
        assert_eq!(
            config.rename_commands.get("FLUSHALL"),
            Some(&"".to_string())
        );
    }
}
