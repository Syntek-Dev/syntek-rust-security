//! Redis/Valkey Secure Configuration Generator
//!
//! Generates security-hardened Redis/Valkey configurations with TLS,
//! authentication, ACLs, and memory protection settings.

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Redis deployment mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentMode {
    Standalone,
    Sentinel,
    Cluster,
}

/// Memory eviction policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            EvictionPolicy::NoEviction => "noeviction",
            EvictionPolicy::AllKeysLru => "allkeys-lru",
            EvictionPolicy::AllKeysLfu => "allkeys-lfu",
            EvictionPolicy::AllKeysRandom => "allkeys-random",
            EvictionPolicy::VolatileLru => "volatile-lru",
            EvictionPolicy::VolatileLfu => "volatile-lfu",
            EvictionPolicy::VolatileRandom => "volatile-random",
            EvictionPolicy::VolatileTtl => "volatile-ttl",
        }
    }
}

/// Append-only file sync strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendFsync {
    Always,
    EverySec,
    No,
}

impl AppendFsync {
    pub fn as_str(&self) -> &'static str {
        match self {
            AppendFsync::Always => "always",
            AppendFsync::EverySec => "everysec",
            AppendFsync::No => "no",
        }
    }
}

/// TLS/SSL configuration
#[derive(Debug, Clone)]
pub struct RedisTlsConfig {
    pub port: u16,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub key_file_pass: Option<String>,
    pub ca_cert_file: Option<PathBuf>,
    pub ca_cert_dir: Option<PathBuf>,
    pub dh_params_file: Option<PathBuf>,
    pub auth_clients: bool,
    pub protocols: Option<String>,
    pub ciphers: Option<String>,
    pub ciphersuites: Option<String>,
    pub prefer_server_ciphers: bool,
    pub session_caching: bool,
    pub session_cache_size: u32,
    pub session_cache_timeout: u32,
}

impl Default for RedisTlsConfig {
    fn default() -> Self {
        Self {
            port: 6379,
            cert_file: PathBuf::from("/etc/redis/tls/redis.crt"),
            key_file: PathBuf::from("/etc/redis/tls/redis.key"),
            key_file_pass: None,
            ca_cert_file: Some(PathBuf::from("/etc/redis/tls/ca.crt")),
            ca_cert_dir: None,
            dh_params_file: None,
            auth_clients: true,
            protocols: Some("TLSv1.2 TLSv1.3".into()),
            ciphers: None,
            ciphersuites: None,
            prefer_server_ciphers: true,
            session_caching: true,
            session_cache_size: 20480,
            session_cache_timeout: 300,
        }
    }
}

/// ACL user definition
#[derive(Debug, Clone)]
pub struct AclUser {
    pub username: String,
    pub enabled: bool,
    pub nopass: bool,
    pub passwords: Vec<String>, // Hashed passwords (SHA256)
    pub commands: Vec<String>,  // +command or -command
    pub keys: Vec<String>,      // ~pattern or %R~pattern or %W~pattern
    pub channels: Vec<String>,  // &pattern
    pub selectors: Vec<String>, // Additional selectors
}

impl AclUser {
    pub fn new(username: &str) -> Self {
        Self {
            username: username.into(),
            enabled: true,
            nopass: false,
            passwords: vec![],
            commands: vec![],
            keys: vec![],
            channels: vec![],
            selectors: vec![],
        }
    }

    /// Create a read-only user for a specific key pattern
    pub fn read_only(username: &str, password_hash: &str, key_pattern: &str) -> Self {
        Self {
            username: username.into(),
            enabled: true,
            nopass: false,
            passwords: vec![password_hash.into()],
            commands: vec![
                "+get".into(),
                "+mget".into(),
                "+hget".into(),
                "+hgetall".into(),
                "+hmget".into(),
                "+lrange".into(),
                "+smembers".into(),
                "+zrange".into(),
                "+scan".into(),
                "+keys".into(),
                "+exists".into(),
                "+type".into(),
                "+ttl".into(),
                "-@all".into(), // Deny all first
            ],
            keys: vec![format!("~{}", key_pattern)],
            channels: vec![],
            selectors: vec![],
        }
    }

    /// Create a user for a specific application
    pub fn application(username: &str, password_hash: &str, key_prefix: &str) -> Self {
        Self {
            username: username.into(),
            enabled: true,
            nopass: false,
            passwords: vec![password_hash.into()],
            commands: vec![
                "-@all".into(),
                "+@read".into(),
                "+@write".into(),
                "+@keyspace".into(),
                "-@dangerous".into(),
                "-@admin".into(),
                "-config".into(),
                "-debug".into(),
                "-shutdown".into(),
                "-bgsave".into(),
                "-bgrewriteaof".into(),
            ],
            keys: vec![format!("~{}:*", key_prefix)],
            channels: vec![format!("&{}:*", key_prefix)],
            selectors: vec![],
        }
    }

    /// Generate ACL line for redis.conf
    pub fn to_acl_line(&self) -> String {
        let mut parts = vec![format!("user {}", self.username)];

        if self.enabled {
            parts.push("on".into());
        } else {
            parts.push("off".into());
        }

        if self.nopass {
            parts.push("nopass".into());
        } else {
            for pwd in &self.passwords {
                parts.push(format!("#{}", pwd));
            }
        }

        // Commands (deny all first, then allow specific)
        for cmd in &self.commands {
            parts.push(cmd.clone());
        }

        // Keys
        for key in &self.keys {
            parts.push(key.clone());
        }

        // Channels
        for channel in &self.channels {
            parts.push(channel.clone());
        }

        // Selectors
        for selector in &self.selectors {
            parts.push(format!("({})", selector));
        }

        parts.join(" ")
    }
}

/// Network configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub bind: Vec<String>,
    pub port: u16,
    pub tcp_backlog: u32,
    pub unix_socket: Option<PathBuf>,
    pub unix_socket_perm: u32,
    pub timeout: u32,
    pub tcp_keepalive: u32,
    pub protected_mode: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bind: vec!["127.0.0.1".into(), "::1".into()],
            port: 6379,
            tcp_backlog: 511,
            unix_socket: None,
            unix_socket_perm: 700,
            timeout: 0,
            tcp_keepalive: 300,
            protected_mode: true,
        }
    }
}

/// Memory configuration
#[derive(Debug, Clone)]
pub struct MemoryConfig {
    pub maxmemory: Option<String>,
    pub maxmemory_policy: EvictionPolicy,
    pub maxmemory_samples: u32,
    pub maxmemory_eviction_tenacity: u32,
    pub replica_ignore_maxmemory: bool,
    pub active_expire_effort: u32,
    pub lazyfree_lazy_eviction: bool,
    pub lazyfree_lazy_expire: bool,
    pub lazyfree_lazy_server_del: bool,
    pub replica_lazy_flush: bool,
    pub lazyfree_lazy_user_del: bool,
    pub lazyfree_lazy_user_flush: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            maxmemory: Some("256mb".into()),
            maxmemory_policy: EvictionPolicy::AllKeysLru,
            maxmemory_samples: 5,
            maxmemory_eviction_tenacity: 10,
            replica_ignore_maxmemory: true,
            active_expire_effort: 1,
            lazyfree_lazy_eviction: true,
            lazyfree_lazy_expire: true,
            lazyfree_lazy_server_del: true,
            replica_lazy_flush: true,
            lazyfree_lazy_user_del: true,
            lazyfree_lazy_user_flush: true,
        }
    }
}

/// Persistence configuration
#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    pub rdb_enabled: bool,
    pub save_points: Vec<(u32, u32)>, // (seconds, changes)
    pub stop_writes_on_bgsave_error: bool,
    pub rdb_compression: bool,
    pub rdb_checksum: bool,
    pub rdb_filename: String,
    pub rdb_del_sync_files: bool,
    pub dir: PathBuf,
    pub aof_enabled: bool,
    pub aof_filename: String,
    pub aof_fsync: AppendFsync,
    pub aof_no_fsync_on_rewrite: bool,
    pub aof_auto_rewrite_percentage: u32,
    pub aof_auto_rewrite_min_size: String,
    pub aof_load_truncated: bool,
    pub aof_use_rdb_preamble: bool,
    pub aof_timestamp_enabled: bool,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            rdb_enabled: true,
            save_points: vec![
                (3600, 1),   // After 3600 sec (1 hour) if at least 1 change
                (300, 100),  // After 300 sec (5 min) if at least 100 changes
                (60, 10000), // After 60 sec if at least 10000 changes
            ],
            stop_writes_on_bgsave_error: true,
            rdb_compression: true,
            rdb_checksum: true,
            rdb_filename: "dump.rdb".into(),
            rdb_del_sync_files: false,
            dir: PathBuf::from("/var/lib/redis"),
            aof_enabled: true,
            aof_filename: "appendonly.aof".into(),
            aof_fsync: AppendFsync::EverySec,
            aof_no_fsync_on_rewrite: false,
            aof_auto_rewrite_percentage: 100,
            aof_auto_rewrite_min_size: "64mb".into(),
            aof_load_truncated: true,
            aof_use_rdb_preamble: true,
            aof_timestamp_enabled: false,
        }
    }
}

/// Security configuration
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub requirepass: Option<String>,
    pub acl_file: Option<PathBuf>,
    pub acl_users: Vec<AclUser>,
    pub rename_commands: HashMap<String, String>,
    pub enable_debug_command: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        let mut rename_commands = HashMap::new();
        // Disable dangerous commands by renaming to empty string
        rename_commands.insert("FLUSHDB".into(), "".into());
        rename_commands.insert("FLUSHALL".into(), "".into());
        rename_commands.insert("DEBUG".into(), "".into());
        rename_commands.insert("CONFIG".into(), "".into());
        rename_commands.insert("SHUTDOWN".into(), "".into());

        Self {
            requirepass: None,
            acl_file: None,
            acl_users: vec![],
            rename_commands,
            enable_debug_command: false,
        }
    }
}

/// Client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub maxclients: u32,
    pub client_output_buffer_limit_normal: String,
    pub client_output_buffer_limit_replica: String,
    pub client_output_buffer_limit_pubsub: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            maxclients: 10000,
            client_output_buffer_limit_normal: "0 0 0".into(),
            client_output_buffer_limit_replica: "256mb 64mb 60".into(),
            client_output_buffer_limit_pubsub: "32mb 8mb 60".into(),
        }
    }
}

/// Main Redis configuration generator
#[derive(Debug, Clone)]
pub struct RedisConfigGenerator {
    pub deployment_mode: DeploymentMode,
    pub network: NetworkConfig,
    pub tls: Option<RedisTlsConfig>,
    pub memory: MemoryConfig,
    pub persistence: PersistenceConfig,
    pub security: SecurityConfig,
    pub client: ClientConfig,
    pub daemonize: bool,
    pub supervised: String,
    pub pidfile: PathBuf,
    pub loglevel: String,
    pub logfile: PathBuf,
    pub databases: u32,
    pub always_show_logo: bool,
    pub io_threads: u32,
    pub io_threads_do_reads: bool,
    pub slowlog_log_slower_than: i64,
    pub slowlog_max_len: u32,
    pub latency_monitor_threshold: u32,
    pub custom_directives: Vec<String>,
}

impl Default for RedisConfigGenerator {
    fn default() -> Self {
        Self {
            deployment_mode: DeploymentMode::Standalone,
            network: NetworkConfig::default(),
            tls: None,
            memory: MemoryConfig::default(),
            persistence: PersistenceConfig::default(),
            security: SecurityConfig::default(),
            client: ClientConfig::default(),
            daemonize: true,
            supervised: "systemd".into(),
            pidfile: PathBuf::from("/var/run/redis/redis-server.pid"),
            loglevel: "notice".into(),
            logfile: PathBuf::from("/var/log/redis/redis-server.log"),
            databases: 16,
            always_show_logo: false,
            io_threads: 4,
            io_threads_do_reads: false,
            slowlog_log_slower_than: 10000,
            slowlog_max_len: 128,
            latency_monitor_threshold: 0,
            custom_directives: vec![],
        }
    }
}

impl RedisConfigGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create production-ready configuration
    pub fn production() -> Self {
        let mut config = Self::default();
        config.memory.maxmemory = Some("2gb".into());
        config.io_threads = 4;
        config.persistence.aof_enabled = true;
        config.persistence.aof_fsync = AppendFsync::EverySec;
        config.latency_monitor_threshold = 100;
        config
    }

    /// Create configuration with TLS enabled
    pub fn with_tls(mut self, tls: RedisTlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Set password authentication
    pub fn with_password(mut self, password: &str) -> Self {
        self.security.requirepass = Some(password.into());
        self
    }

    /// Add ACL user
    pub fn with_acl_user(mut self, user: AclUser) -> Self {
        self.security.acl_users.push(user);
        self
    }

    /// Set max memory
    pub fn with_max_memory(mut self, memory: &str) -> Self {
        self.memory.maxmemory = Some(memory.into());
        self
    }

    /// Generate complete redis.conf content
    pub fn generate(&self) -> String {
        let mut config = String::new();

        writeln!(config, "# Redis Configuration File").unwrap();
        writeln!(config, "# Generated by Syntek Rust Security Plugin").unwrap();
        writeln!(config, "# Security-hardened configuration\n").unwrap();

        // Include sections
        self.generate_general_section(&mut config);
        self.generate_network_section(&mut config);
        if self.tls.is_some() {
            self.generate_tls_section(&mut config);
        }
        self.generate_security_section(&mut config);
        self.generate_memory_section(&mut config);
        self.generate_persistence_section(&mut config);
        self.generate_client_section(&mut config);
        self.generate_slow_log_section(&mut config);

        // Custom directives
        if !self.custom_directives.is_empty() {
            writeln!(
                config,
                "\n################################ CUSTOM ################################"
            )
            .unwrap();
            for directive in &self.custom_directives {
                writeln!(config, "{}", directive).unwrap();
            }
        }

        config
    }

    fn generate_general_section(&self, config: &mut String) {
        writeln!(
            config,
            "################################ GENERAL ################################\n"
        )
        .unwrap();

        if self.daemonize {
            writeln!(config, "daemonize yes").unwrap();
        } else {
            writeln!(config, "daemonize no").unwrap();
        }

        writeln!(config, "supervised {}", self.supervised).unwrap();
        writeln!(config, "pidfile {}", self.pidfile.display()).unwrap();
        writeln!(config, "loglevel {}", self.loglevel).unwrap();
        writeln!(config, "logfile \"{}\"", self.logfile.display()).unwrap();
        writeln!(config, "databases {}", self.databases).unwrap();
        writeln!(
            config,
            "always-show-logo {}",
            if self.always_show_logo { "yes" } else { "no" }
        )
        .unwrap();
        writeln!(config, "io-threads {}", self.io_threads).unwrap();
        writeln!(
            config,
            "io-threads-do-reads {}",
            if self.io_threads_do_reads {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(config).unwrap();
    }

    fn generate_network_section(&self, config: &mut String) {
        writeln!(
            config,
            "################################ NETWORK ################################\n"
        )
        .unwrap();

        for bind in &self.network.bind {
            writeln!(config, "bind {}", bind).unwrap();
        }

        writeln!(config, "port {}", self.network.port).unwrap();
        writeln!(config, "tcp-backlog {}", self.network.tcp_backlog).unwrap();

        if let Some(unix_socket) = &self.network.unix_socket {
            writeln!(config, "unixsocket {}", unix_socket.display()).unwrap();
            writeln!(config, "unixsocketperm {:o}", self.network.unix_socket_perm).unwrap();
        }

        writeln!(config, "timeout {}", self.network.timeout).unwrap();
        writeln!(config, "tcp-keepalive {}", self.network.tcp_keepalive).unwrap();
        writeln!(
            config,
            "protected-mode {}",
            if self.network.protected_mode {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(config).unwrap();
    }

    fn generate_tls_section(&self, config: &mut String) {
        let tls = self.tls.as_ref().unwrap();

        writeln!(
            config,
            "################################## TLS ##################################\n"
        )
        .unwrap();

        writeln!(config, "tls-port {}", tls.port).unwrap();
        writeln!(config, "tls-cert-file {}", tls.cert_file.display()).unwrap();
        writeln!(config, "tls-key-file {}", tls.key_file.display()).unwrap();

        if let Some(key_pass) = &tls.key_file_pass {
            writeln!(config, "tls-key-file-pass {}", key_pass).unwrap();
        }

        if let Some(ca_file) = &tls.ca_cert_file {
            writeln!(config, "tls-ca-cert-file {}", ca_file.display()).unwrap();
        }

        if let Some(ca_dir) = &tls.ca_cert_dir {
            writeln!(config, "tls-ca-cert-dir {}", ca_dir.display()).unwrap();
        }

        if let Some(dh_params) = &tls.dh_params_file {
            writeln!(config, "tls-dh-params-file {}", dh_params.display()).unwrap();
        }

        writeln!(
            config,
            "tls-auth-clients {}",
            if tls.auth_clients { "yes" } else { "no" }
        )
        .unwrap();

        if let Some(protocols) = &tls.protocols {
            writeln!(config, "tls-protocols \"{}\"", protocols).unwrap();
        }

        if let Some(ciphers) = &tls.ciphers {
            writeln!(config, "tls-ciphers {}", ciphers).unwrap();
        }

        if let Some(ciphersuites) = &tls.ciphersuites {
            writeln!(config, "tls-ciphersuites {}", ciphersuites).unwrap();
        }

        writeln!(
            config,
            "tls-prefer-server-ciphers {}",
            if tls.prefer_server_ciphers {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(
            config,
            "tls-session-caching {}",
            if tls.session_caching { "yes" } else { "no" }
        )
        .unwrap();
        writeln!(config, "tls-session-cache-size {}", tls.session_cache_size).unwrap();
        writeln!(
            config,
            "tls-session-cache-timeout {}",
            tls.session_cache_timeout
        )
        .unwrap();
        writeln!(config).unwrap();
    }

    fn generate_security_section(&self, config: &mut String) {
        writeln!(
            config,
            "################################ SECURITY ###############################\n"
        )
        .unwrap();

        if let Some(requirepass) = &self.security.requirepass {
            writeln!(config, "requirepass {}", requirepass).unwrap();
        }

        // ACL configuration
        if let Some(acl_file) = &self.security.acl_file {
            writeln!(config, "aclfile {}", acl_file.display()).unwrap();
        }

        // Inline ACL users
        for user in &self.security.acl_users {
            writeln!(config, "{}", user.to_acl_line()).unwrap();
        }

        // Renamed commands
        for (cmd, new_name) in &self.security.rename_commands {
            if new_name.is_empty() {
                writeln!(config, "rename-command {} \"\"", cmd).unwrap();
            } else {
                writeln!(config, "rename-command {} {}", cmd, new_name).unwrap();
            }
        }

        writeln!(
            config,
            "enable-debug-command {}",
            if self.security.enable_debug_command {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(config).unwrap();
    }

    fn generate_memory_section(&self, config: &mut String) {
        writeln!(
            config,
            "################################ MEMORY #################################\n"
        )
        .unwrap();

        if let Some(maxmemory) = &self.memory.maxmemory {
            writeln!(config, "maxmemory {}", maxmemory).unwrap();
        }

        writeln!(
            config,
            "maxmemory-policy {}",
            self.memory.maxmemory_policy.as_str()
        )
        .unwrap();
        writeln!(
            config,
            "maxmemory-samples {}",
            self.memory.maxmemory_samples
        )
        .unwrap();
        writeln!(
            config,
            "maxmemory-eviction-tenacity {}",
            self.memory.maxmemory_eviction_tenacity
        )
        .unwrap();
        writeln!(
            config,
            "replica-ignore-maxmemory {}",
            if self.memory.replica_ignore_maxmemory {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(
            config,
            "active-expire-effort {}",
            self.memory.active_expire_effort
        )
        .unwrap();

        // Lazy free options
        writeln!(
            config,
            "lazyfree-lazy-eviction {}",
            if self.memory.lazyfree_lazy_eviction {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(
            config,
            "lazyfree-lazy-expire {}",
            if self.memory.lazyfree_lazy_expire {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(
            config,
            "lazyfree-lazy-server-del {}",
            if self.memory.lazyfree_lazy_server_del {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(
            config,
            "replica-lazy-flush {}",
            if self.memory.replica_lazy_flush {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(
            config,
            "lazyfree-lazy-user-del {}",
            if self.memory.lazyfree_lazy_user_del {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(
            config,
            "lazyfree-lazy-user-flush {}",
            if self.memory.lazyfree_lazy_user_flush {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(config).unwrap();
    }

    fn generate_persistence_section(&self, config: &mut String) {
        writeln!(
            config,
            "############################## PERSISTENCE #############################\n"
        )
        .unwrap();

        // RDB snapshots
        if self.persistence.rdb_enabled {
            for (seconds, changes) in &self.persistence.save_points {
                writeln!(config, "save {} {}", seconds, changes).unwrap();
            }
        } else {
            writeln!(config, "save \"\"").unwrap();
        }

        writeln!(
            config,
            "stop-writes-on-bgsave-error {}",
            if self.persistence.stop_writes_on_bgsave_error {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(
            config,
            "rdbcompression {}",
            if self.persistence.rdb_compression {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(
            config,
            "rdbchecksum {}",
            if self.persistence.rdb_checksum {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(config, "dbfilename {}", self.persistence.rdb_filename).unwrap();
        writeln!(
            config,
            "rdb-del-sync-files {}",
            if self.persistence.rdb_del_sync_files {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(config, "dir {}", self.persistence.dir.display()).unwrap();

        // AOF
        writeln!(config).unwrap();
        writeln!(
            config,
            "appendonly {}",
            if self.persistence.aof_enabled {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(
            config,
            "appendfilename \"{}\"",
            self.persistence.aof_filename
        )
        .unwrap();
        writeln!(
            config,
            "appendfsync {}",
            self.persistence.aof_fsync.as_str()
        )
        .unwrap();
        writeln!(
            config,
            "no-appendfsync-on-rewrite {}",
            if self.persistence.aof_no_fsync_on_rewrite {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(
            config,
            "auto-aof-rewrite-percentage {}",
            self.persistence.aof_auto_rewrite_percentage
        )
        .unwrap();
        writeln!(
            config,
            "auto-aof-rewrite-min-size {}",
            self.persistence.aof_auto_rewrite_min_size
        )
        .unwrap();
        writeln!(
            config,
            "aof-load-truncated {}",
            if self.persistence.aof_load_truncated {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(
            config,
            "aof-use-rdb-preamble {}",
            if self.persistence.aof_use_rdb_preamble {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(
            config,
            "aof-timestamp-enabled {}",
            if self.persistence.aof_timestamp_enabled {
                "yes"
            } else {
                "no"
            }
        )
        .unwrap();
        writeln!(config).unwrap();
    }

    fn generate_client_section(&self, config: &mut String) {
        writeln!(
            config,
            "################################ CLIENTS ################################\n"
        )
        .unwrap();

        writeln!(config, "maxclients {}", self.client.maxclients).unwrap();
        writeln!(
            config,
            "client-output-buffer-limit normal {}",
            self.client.client_output_buffer_limit_normal
        )
        .unwrap();
        writeln!(
            config,
            "client-output-buffer-limit replica {}",
            self.client.client_output_buffer_limit_replica
        )
        .unwrap();
        writeln!(
            config,
            "client-output-buffer-limit pubsub {}",
            self.client.client_output_buffer_limit_pubsub
        )
        .unwrap();
        writeln!(config).unwrap();
    }

    fn generate_slow_log_section(&self, config: &mut String) {
        writeln!(
            config,
            "############################### SLOW LOG ################################\n"
        )
        .unwrap();

        writeln!(
            config,
            "slowlog-log-slower-than {}",
            self.slowlog_log_slower_than
        )
        .unwrap();
        writeln!(config, "slowlog-max-len {}", self.slowlog_max_len).unwrap();
        writeln!(
            config,
            "latency-monitor-threshold {}",
            self.latency_monitor_threshold
        )
        .unwrap();
        writeln!(config).unwrap();
    }

    /// Write configuration to file
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let config = self.generate();
        let mut file = fs::File::create(path)?;
        file.write_all(config.as_bytes())?;
        Ok(())
    }

    /// Generate systemd service file
    pub fn generate_systemd_service(&self) -> String {
        let mut service = String::new();

        service.push_str("# Redis Server Systemd Service\n");
        service.push_str("# Generated by Syntek Rust Security Plugin\n\n");

        service.push_str("[Unit]\n");
        service.push_str("Description=Redis In-Memory Data Store\n");
        service.push_str("After=network.target\n\n");

        service.push_str("[Service]\n");
        service.push_str("Type=notify\n");
        service.push_str(
            "ExecStart=/usr/bin/redis-server /etc/redis/redis.conf --supervised systemd\n",
        );
        service.push_str("ExecStop=/usr/bin/redis-cli shutdown\n");
        service.push_str("User=redis\n");
        service.push_str("Group=redis\n");
        service.push_str("RuntimeDirectory=redis\n");
        service.push_str("RuntimeDirectoryMode=0755\n");
        service.push_str("TimeoutStopSec=0\n");
        service.push_str("Restart=always\n");
        service.push_str("RestartSec=5\n\n");

        // Security hardening
        service.push_str("# Security Hardening\n");
        service.push_str("NoNewPrivileges=true\n");
        service.push_str("ProtectSystem=strict\n");
        service.push_str("ProtectHome=true\n");
        service.push_str("ProtectKernelTunables=true\n");
        service.push_str("ProtectKernelModules=true\n");
        service.push_str("ProtectControlGroups=true\n");
        service.push_str("RestrictSUIDSGID=true\n");
        service.push_str("PrivateTmp=true\n");
        service.push_str(&format!(
            "ReadWritePaths={}\n",
            self.persistence.dir.display()
        ));
        service.push_str(&format!(
            "ReadWritePaths={}\n",
            self.logfile.parent().unwrap().display()
        ));

        service.push_str("\n[Install]\n");
        service.push_str("WantedBy=multi-user.target\n");

        service
    }
}

fn main() {
    println!("Redis/Valkey Security Configuration Generator\n");

    // Create production configuration with TLS and ACLs
    let app_user = AclUser::application("myapp", "sha256_hash_here", "myapp");
    let readonly_user = AclUser::read_only("readonly", "sha256_hash_here", "cache:*");

    let config = RedisConfigGenerator::production()
        .with_tls(RedisTlsConfig::default())
        .with_password("secure_password_here")
        .with_acl_user(app_user)
        .with_acl_user(readonly_user)
        .with_max_memory("4gb");

    println!("Generated redis.conf:");
    println!("{}", "=".repeat(60));

    let redis_conf = config.generate();
    // Print first 100 lines
    for (i, line) in redis_conf.lines().enumerate() {
        if i >= 100 {
            println!("... ({} more lines)", redis_conf.lines().count() - 100);
            break;
        }
        println!("{}", line);
    }

    println!("\n{}", "=".repeat(60));
    println!("\nConfiguration Summary:");
    println!("  - Mode: {:?}", config.deployment_mode);
    println!("  - TLS enabled: {}", config.tls.is_some());
    println!("  - Max memory: {:?}", config.memory.maxmemory);
    println!(
        "  - Eviction policy: {}",
        config.memory.maxmemory_policy.as_str()
    );
    println!("  - ACL users: {}", config.security.acl_users.len());
    println!("  - RDB enabled: {}", config.persistence.rdb_enabled);
    println!("  - AOF enabled: {}", config.persistence.aof_enabled);
    println!("  - AOF fsync: {}", config.persistence.aof_fsync.as_str());

    // Generate systemd service
    println!("\n\nGenerated systemd service:");
    println!("{}", "=".repeat(60));
    println!("{}", config.generate_systemd_service());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eviction_policy() {
        assert_eq!(EvictionPolicy::AllKeysLru.as_str(), "allkeys-lru");
        assert_eq!(EvictionPolicy::NoEviction.as_str(), "noeviction");
    }

    #[test]
    fn test_append_fsync() {
        assert_eq!(AppendFsync::Always.as_str(), "always");
        assert_eq!(AppendFsync::EverySec.as_str(), "everysec");
    }

    #[test]
    fn test_acl_user_creation() {
        let user = AclUser::new("testuser");
        assert_eq!(user.username, "testuser");
        assert!(user.enabled);
        assert!(!user.nopass);
    }

    #[test]
    fn test_acl_application_user() {
        let user = AclUser::application("myapp", "hash123", "app");
        assert!(user.keys.contains(&"~app:*".to_string()));
        assert!(user.channels.contains(&"&app:*".to_string()));
    }

    #[test]
    fn test_acl_line_generation() {
        let user = AclUser {
            username: "test".into(),
            enabled: true,
            nopass: false,
            passwords: vec!["abc123".into()],
            commands: vec!["-@all".into(), "+get".into()],
            keys: vec!["~*".into()],
            channels: vec![],
            selectors: vec![],
        };

        let line = user.to_acl_line();
        assert!(line.contains("user test"));
        assert!(line.contains("on"));
        assert!(line.contains("#abc123"));
    }

    #[test]
    fn test_default_config() {
        let config = RedisConfigGenerator::default();
        assert_eq!(config.deployment_mode, DeploymentMode::Standalone);
        assert!(config.network.protected_mode);
        assert_eq!(config.databases, 16);
    }

    #[test]
    fn test_production_config() {
        let config = RedisConfigGenerator::production();
        assert!(config.persistence.aof_enabled);
        assert_eq!(config.io_threads, 4);
    }

    #[test]
    fn test_with_tls() {
        let config = RedisConfigGenerator::new().with_tls(RedisTlsConfig::default());
        assert!(config.tls.is_some());
    }

    #[test]
    fn test_with_password() {
        let config = RedisConfigGenerator::new().with_password("secret123");
        assert_eq!(config.security.requirepass, Some("secret123".into()));
    }

    #[test]
    fn test_config_generation() {
        let config = RedisConfigGenerator::default();
        let output = config.generate();

        assert!(output.contains("bind 127.0.0.1"));
        assert!(output.contains("port 6379"));
        assert!(output.contains("protected-mode yes"));
        assert!(output.contains("maxmemory"));
    }

    #[test]
    fn test_tls_config_generation() {
        let config = RedisConfigGenerator::new().with_tls(RedisTlsConfig::default());
        let output = config.generate();

        assert!(output.contains("tls-port"));
        assert!(output.contains("tls-cert-file"));
        assert!(output.contains("tls-key-file"));
    }

    #[test]
    fn test_security_defaults() {
        let security = SecurityConfig::default();
        assert!(security.rename_commands.contains_key("FLUSHDB"));
        assert!(security.rename_commands.contains_key("DEBUG"));
        assert!(!security.enable_debug_command);
    }

    #[test]
    fn test_systemd_service_generation() {
        let config = RedisConfigGenerator::default();
        let service = config.generate_systemd_service();

        assert!(service.contains("[Unit]"));
        assert!(service.contains("[Service]"));
        assert!(service.contains("NoNewPrivileges=true"));
        assert!(service.contains("ProtectSystem=strict"));
    }
}
