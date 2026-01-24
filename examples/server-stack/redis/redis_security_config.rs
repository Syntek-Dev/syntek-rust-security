//! Redis Security Configuration Generator
//!
//! Generates security-hardened Redis configuration with authentication,
//! TLS, ACLs, and network security settings.

use std::collections::{HashMap, HashSet};
use std::fmt::Write;

/// Redis ACL permission
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AclPermission {
    // Command categories
    AllCommands,
    Read,
    Write,
    Admin,
    Dangerous,
    Fast,
    Slow,
    PubSub,
    Transaction,
    Scripting,
    Connection,

    // Key patterns
    AllKeys,
    NoKeys,
}

impl AclPermission {
    pub fn as_acl_str(&self) -> &'static str {
        match self {
            AclPermission::AllCommands => "+@all",
            AclPermission::Read => "+@read",
            AclPermission::Write => "+@write",
            AclPermission::Admin => "+@admin",
            AclPermission::Dangerous => "+@dangerous",
            AclPermission::Fast => "+@fast",
            AclPermission::Slow => "+@slow",
            AclPermission::PubSub => "+@pubsub",
            AclPermission::Transaction => "+@transaction",
            AclPermission::Scripting => "+@scripting",
            AclPermission::Connection => "+@connection",
            AclPermission::AllKeys => "~*",
            AclPermission::NoKeys => "",
        }
    }

    pub fn deny_str(&self) -> &'static str {
        match self {
            AclPermission::AllCommands => "-@all",
            AclPermission::Read => "-@read",
            AclPermission::Write => "-@write",
            AclPermission::Admin => "-@admin",
            AclPermission::Dangerous => "-@dangerous",
            AclPermission::Fast => "-@fast",
            AclPermission::Slow => "-@slow",
            AclPermission::PubSub => "-@pubsub",
            AclPermission::Transaction => "-@transaction",
            AclPermission::Scripting => "-@scripting",
            AclPermission::Connection => "-@connection",
            _ => "",
        }
    }
}

/// Redis ACL user configuration
#[derive(Debug, Clone)]
pub struct AclUser {
    pub username: String,
    pub enabled: bool,
    pub passwords: Vec<String>,
    pub nopass: bool,
    pub allowed_commands: HashSet<String>,
    pub denied_commands: HashSet<String>,
    pub allowed_categories: HashSet<AclPermission>,
    pub denied_categories: HashSet<AclPermission>,
    pub allowed_keys: Vec<String>,
    pub allowed_channels: Vec<String>,
    pub reset_on_update: bool,
}

impl AclUser {
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            enabled: true,
            passwords: Vec::new(),
            nopass: false,
            allowed_commands: HashSet::new(),
            denied_commands: HashSet::new(),
            allowed_categories: HashSet::new(),
            denied_categories: HashSet::new(),
            allowed_keys: Vec::new(),
            allowed_channels: Vec::new(),
            reset_on_update: true,
        }
    }

    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.passwords.push(password.into());
        self
    }

    pub fn nopass(mut self) -> Self {
        self.nopass = true;
        self
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    pub fn allow_category(mut self, category: AclPermission) -> Self {
        self.allowed_categories.insert(category);
        self
    }

    pub fn deny_category(mut self, category: AclPermission) -> Self {
        self.denied_categories.insert(category);
        self
    }

    pub fn allow_command(mut self, command: impl Into<String>) -> Self {
        self.allowed_commands.insert(command.into());
        self
    }

    pub fn deny_command(mut self, command: impl Into<String>) -> Self {
        self.denied_commands.insert(command.into());
        self
    }

    pub fn key_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.allowed_keys.push(pattern.into());
        self
    }

    pub fn channel_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.allowed_channels.push(pattern.into());
        self
    }

    pub fn generate(&self) -> String {
        let mut acl = format!("user {}", self.username);

        if self.reset_on_update {
            acl.push_str(" reset");
        }

        if self.enabled {
            acl.push_str(" on");
        } else {
            acl.push_str(" off");
        }

        if self.nopass {
            acl.push_str(" nopass");
        } else {
            for password in &self.passwords {
                acl.push_str(&format!(" >{}", password));
            }
        }

        // Denied categories first
        for category in &self.denied_categories {
            acl.push_str(&format!(" {}", category.deny_str()));
        }

        // Allowed categories
        for category in &self.allowed_categories {
            acl.push_str(&format!(" {}", category.as_acl_str()));
        }

        // Denied commands
        for cmd in &self.denied_commands {
            acl.push_str(&format!(" -{}", cmd));
        }

        // Allowed commands
        for cmd in &self.allowed_commands {
            acl.push_str(&format!(" +{}", cmd));
        }

        // Key patterns
        if self.allowed_keys.is_empty() {
            acl.push_str(" ~*");
        } else {
            for pattern in &self.allowed_keys {
                acl.push_str(&format!(" ~{}", pattern));
            }
        }

        // Channel patterns
        for pattern in &self.allowed_channels {
            acl.push_str(&format!(" &{}", pattern));
        }

        acl
    }
}

/// TLS configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub enabled: bool,
    pub port: u16,
    pub cert_file: String,
    pub key_file: String,
    pub ca_cert_file: Option<String>,
    pub dh_params_file: Option<String>,
    pub protocols: Vec<String>,
    pub ciphers: Option<String>,
    pub ciphersuites: Option<String>,
    pub prefer_server_ciphers: bool,
    pub client_cert_required: bool,
    pub session_caching: bool,
    pub session_cache_size: u32,
    pub session_cache_timeout: u32,
}

impl TlsConfig {
    pub fn new(cert_file: impl Into<String>, key_file: impl Into<String>) -> Self {
        Self {
            enabled: true,
            port: 6379,
            cert_file: cert_file.into(),
            key_file: key_file.into(),
            ca_cert_file: None,
            dh_params_file: None,
            protocols: vec!["TLSv1.2".to_string(), "TLSv1.3".to_string()],
            ciphers: None,
            ciphersuites: None,
            prefer_server_ciphers: true,
            client_cert_required: false,
            session_caching: true,
            session_cache_size: 20480,
            session_cache_timeout: 300,
        }
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn ca_cert(mut self, path: impl Into<String>) -> Self {
        self.ca_cert_file = Some(path.into());
        self
    }

    pub fn dh_params(mut self, path: impl Into<String>) -> Self {
        self.dh_params_file = Some(path.into());
        self
    }

    pub fn protocols(mut self, protocols: Vec<String>) -> Self {
        self.protocols = protocols;
        self
    }

    pub fn ciphers(mut self, ciphers: impl Into<String>) -> Self {
        self.ciphers = Some(ciphers.into());
        self
    }

    pub fn require_client_cert(mut self) -> Self {
        self.client_cert_required = true;
        self
    }

    pub fn generate(&self) -> Vec<String> {
        let mut config = Vec::new();

        config.push(format!("tls-port {}", self.port));
        config.push(format!("tls-cert-file {}", self.cert_file));
        config.push(format!("tls-key-file {}", self.key_file));

        if let Some(ref ca) = self.ca_cert_file {
            config.push(format!("tls-ca-cert-file {}", ca));
        }

        if let Some(ref dh) = self.dh_params_file {
            config.push(format!("tls-dh-params-file {}", dh));
        }

        if !self.protocols.is_empty() {
            config.push(format!("tls-protocols \"{}\"", self.protocols.join(" ")));
        }

        if let Some(ref ciphers) = self.ciphers {
            config.push(format!("tls-ciphers {}", ciphers));
        }

        if let Some(ref ciphersuites) = self.ciphersuites {
            config.push(format!("tls-ciphersuites {}", ciphersuites));
        }

        config.push(format!(
            "tls-prefer-server-ciphers {}",
            if self.prefer_server_ciphers {
                "yes"
            } else {
                "no"
            }
        ));

        if self.client_cert_required {
            config.push("tls-auth-clients yes".to_string());
        } else {
            config.push("tls-auth-clients no".to_string());
        }

        config.push(format!(
            "tls-session-caching {}",
            if self.session_caching { "yes" } else { "no" }
        ));

        if self.session_caching {
            config.push(format!(
                "tls-session-cache-size {}",
                self.session_cache_size
            ));
            config.push(format!(
                "tls-session-cache-timeout {}",
                self.session_cache_timeout
            ));
        }

        config
    }
}

/// Memory policy
#[derive(Debug, Clone, Copy)]
pub enum MaxMemoryPolicy {
    NoEviction,
    AllKeysLru,
    AllKeysLfu,
    VolatileLru,
    VolatileLfu,
    AllKeysRandom,
    VolatileRandom,
    VolatileTtl,
}

impl MaxMemoryPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            MaxMemoryPolicy::NoEviction => "noeviction",
            MaxMemoryPolicy::AllKeysLru => "allkeys-lru",
            MaxMemoryPolicy::AllKeysLfu => "allkeys-lfu",
            MaxMemoryPolicy::VolatileLru => "volatile-lru",
            MaxMemoryPolicy::VolatileLfu => "volatile-lfu",
            MaxMemoryPolicy::AllKeysRandom => "allkeys-random",
            MaxMemoryPolicy::VolatileRandom => "volatile-random",
            MaxMemoryPolicy::VolatileTtl => "volatile-ttl",
        }
    }
}

/// Persistence configuration
#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    pub rdb_enabled: bool,
    pub rdb_filename: String,
    pub rdb_save_rules: Vec<(u32, u32)>,
    pub rdb_compression: bool,
    pub rdb_checksum: bool,
    pub aof_enabled: bool,
    pub aof_filename: String,
    pub aof_fsync: AofFsync,
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
            AofFsync::Always => "always",
            AofFsync::Everysec => "everysec",
            AofFsync::No => "no",
        }
    }
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            rdb_enabled: true,
            rdb_filename: "dump.rdb".to_string(),
            rdb_save_rules: vec![(900, 1), (300, 10), (60, 10000)],
            rdb_compression: true,
            rdb_checksum: true,
            aof_enabled: false,
            aof_filename: "appendonly.aof".to_string(),
            aof_fsync: AofFsync::Everysec,
            aof_rewrite_percentage: 100,
            aof_rewrite_min_size: "64mb".to_string(),
        }
    }
}

impl PersistenceConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enable_aof(mut self) -> Self {
        self.aof_enabled = true;
        self
    }

    pub fn disable_rdb(mut self) -> Self {
        self.rdb_enabled = false;
        self
    }

    pub fn aof_fsync(mut self, fsync: AofFsync) -> Self {
        self.aof_fsync = fsync;
        self
    }

    pub fn rdb_save_rule(mut self, seconds: u32, changes: u32) -> Self {
        self.rdb_save_rules.push((seconds, changes));
        self
    }

    pub fn generate(&self) -> Vec<String> {
        let mut config = Vec::new();

        // RDB
        if self.rdb_enabled {
            for (seconds, changes) in &self.rdb_save_rules {
                config.push(format!("save {} {}", seconds, changes));
            }
            config.push(format!("dbfilename {}", self.rdb_filename));
            config.push(format!(
                "rdbcompression {}",
                if self.rdb_compression { "yes" } else { "no" }
            ));
            config.push(format!(
                "rdbchecksum {}",
                if self.rdb_checksum { "yes" } else { "no" }
            ));
        } else {
            config.push("save \"\"".to_string());
        }

        // AOF
        config.push(format!(
            "appendonly {}",
            if self.aof_enabled { "yes" } else { "no" }
        ));

        if self.aof_enabled {
            config.push(format!("appendfilename \"{}\"", self.aof_filename));
            config.push(format!("appendfsync {}", self.aof_fsync.as_str()));
            config.push(format!(
                "auto-aof-rewrite-percentage {}",
                self.aof_rewrite_percentage
            ));
            config.push(format!(
                "auto-aof-rewrite-min-size {}",
                self.aof_rewrite_min_size
            ));
        }

        config
    }
}

/// Security configuration
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub protected_mode: bool,
    pub bind_addresses: Vec<String>,
    pub require_pass: Option<String>,
    pub acl_users: Vec<AclUser>,
    pub acl_file: Option<String>,
    pub rename_commands: HashMap<String, String>,
    pub disable_commands: HashSet<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            protected_mode: true,
            bind_addresses: vec!["127.0.0.1".to_string()],
            require_pass: None,
            acl_users: Vec::new(),
            acl_file: None,
            rename_commands: HashMap::new(),
            disable_commands: HashSet::new(),
        }
    }
}

impl SecurityConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind(mut self, address: impl Into<String>) -> Self {
        self.bind_addresses.push(address.into());
        self
    }

    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.require_pass = Some(password.into());
        self
    }

    pub fn acl_user(mut self, user: AclUser) -> Self {
        self.acl_users.push(user);
        self
    }

    pub fn acl_file(mut self, path: impl Into<String>) -> Self {
        self.acl_file = Some(path.into());
        self
    }

    pub fn rename_command(
        mut self,
        command: impl Into<String>,
        new_name: impl Into<String>,
    ) -> Self {
        self.rename_commands.insert(command.into(), new_name.into());
        self
    }

    pub fn disable_command(mut self, command: impl Into<String>) -> Self {
        self.disable_commands.insert(command.into());
        self
    }

    pub fn protected_mode(mut self, enabled: bool) -> Self {
        self.protected_mode = enabled;
        self
    }

    pub fn generate(&self) -> Vec<String> {
        let mut config = Vec::new();

        config.push(format!("bind {}", self.bind_addresses.join(" ")));
        config.push(format!(
            "protected-mode {}",
            if self.protected_mode { "yes" } else { "no" }
        ));

        if let Some(ref pass) = self.require_pass {
            config.push(format!("requirepass {}", pass));
        }

        if let Some(ref acl_file) = self.acl_file {
            config.push(format!("aclfile {}", acl_file));
        }

        for user in &self.acl_users {
            config.push(user.generate());
        }

        for (cmd, new_name) in &self.rename_commands {
            config.push(format!("rename-command {} {}", cmd, new_name));
        }

        for cmd in &self.disable_commands {
            config.push(format!("rename-command {} \"\"", cmd));
        }

        config
    }
}

/// Limits configuration
#[derive(Debug, Clone)]
pub struct LimitsConfig {
    pub maxclients: u32,
    pub maxmemory: Option<String>,
    pub maxmemory_policy: MaxMemoryPolicy,
    pub maxmemory_samples: u32,
    pub client_output_buffer_limit_normal: String,
    pub client_output_buffer_limit_replica: String,
    pub client_output_buffer_limit_pubsub: String,
    pub timeout: u32,
    pub tcp_keepalive: u32,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            maxclients: 10000,
            maxmemory: None,
            maxmemory_policy: MaxMemoryPolicy::NoEviction,
            maxmemory_samples: 5,
            client_output_buffer_limit_normal: "0 0 0".to_string(),
            client_output_buffer_limit_replica: "256mb 64mb 60".to_string(),
            client_output_buffer_limit_pubsub: "32mb 8mb 60".to_string(),
            timeout: 0,
            tcp_keepalive: 300,
        }
    }
}

impl LimitsConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn maxclients(mut self, clients: u32) -> Self {
        self.maxclients = clients;
        self
    }

    pub fn maxmemory(mut self, memory: impl Into<String>) -> Self {
        self.maxmemory = Some(memory.into());
        self
    }

    pub fn maxmemory_policy(mut self, policy: MaxMemoryPolicy) -> Self {
        self.maxmemory_policy = policy;
        self
    }

    pub fn timeout(mut self, seconds: u32) -> Self {
        self.timeout = seconds;
        self
    }

    pub fn tcp_keepalive(mut self, seconds: u32) -> Self {
        self.tcp_keepalive = seconds;
        self
    }

    pub fn generate(&self) -> Vec<String> {
        let mut config = Vec::new();

        config.push(format!("maxclients {}", self.maxclients));

        if let Some(ref mem) = self.maxmemory {
            config.push(format!("maxmemory {}", mem));
        }

        config.push(format!(
            "maxmemory-policy {}",
            self.maxmemory_policy.as_str()
        ));
        config.push(format!("maxmemory-samples {}", self.maxmemory_samples));

        config.push(format!(
            "client-output-buffer-limit normal {}",
            self.client_output_buffer_limit_normal
        ));
        config.push(format!(
            "client-output-buffer-limit replica {}",
            self.client_output_buffer_limit_replica
        ));
        config.push(format!(
            "client-output-buffer-limit pubsub {}",
            self.client_output_buffer_limit_pubsub
        ));

        config.push(format!("timeout {}", self.timeout));
        config.push(format!("tcp-keepalive {}", self.tcp_keepalive));

        config
    }
}

/// Replication configuration
#[derive(Debug, Clone)]
pub struct ReplicationConfig {
    pub replica_of: Option<(String, u16)>,
    pub masterauth: Option<String>,
    pub masteruser: Option<String>,
    pub replica_serve_stale_data: bool,
    pub replica_read_only: bool,
    pub repl_diskless_sync: bool,
    pub repl_diskless_sync_delay: u32,
    pub min_replicas_to_write: Option<u32>,
    pub min_replicas_max_lag: Option<u32>,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            replica_of: None,
            masterauth: None,
            masteruser: None,
            replica_serve_stale_data: true,
            replica_read_only: true,
            repl_diskless_sync: false,
            repl_diskless_sync_delay: 5,
            min_replicas_to_write: None,
            min_replicas_max_lag: None,
        }
    }
}

impl ReplicationConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn replica_of(mut self, host: impl Into<String>, port: u16) -> Self {
        self.replica_of = Some((host.into(), port));
        self
    }

    pub fn masterauth(mut self, password: impl Into<String>) -> Self {
        self.masterauth = Some(password.into());
        self
    }

    pub fn masteruser(mut self, user: impl Into<String>) -> Self {
        self.masteruser = Some(user.into());
        self
    }

    pub fn min_replicas(mut self, count: u32, max_lag: u32) -> Self {
        self.min_replicas_to_write = Some(count);
        self.min_replicas_max_lag = Some(max_lag);
        self
    }

    pub fn generate(&self) -> Vec<String> {
        let mut config = Vec::new();

        if let Some((ref host, port)) = self.replica_of {
            config.push(format!("replicaof {} {}", host, port));
        }

        if let Some(ref auth) = self.masterauth {
            config.push(format!("masterauth {}", auth));
        }

        if let Some(ref user) = self.masteruser {
            config.push(format!("masteruser {}", user));
        }

        config.push(format!(
            "replica-serve-stale-data {}",
            if self.replica_serve_stale_data {
                "yes"
            } else {
                "no"
            }
        ));
        config.push(format!(
            "replica-read-only {}",
            if self.replica_read_only { "yes" } else { "no" }
        ));
        config.push(format!(
            "repl-diskless-sync {}",
            if self.repl_diskless_sync { "yes" } else { "no" }
        ));
        config.push(format!(
            "repl-diskless-sync-delay {}",
            self.repl_diskless_sync_delay
        ));

        if let Some(count) = self.min_replicas_to_write {
            config.push(format!("min-replicas-to-write {}", count));
        }
        if let Some(lag) = self.min_replicas_max_lag {
            config.push(format!("min-replicas-max-lag {}", lag));
        }

        config
    }
}

/// Main Redis configuration generator
pub struct RedisConfigGenerator {
    pub port: u16,
    pub daemonize: bool,
    pub pidfile: String,
    pub loglevel: String,
    pub logfile: String,
    pub databases: u32,
    pub dir: String,
    pub security: SecurityConfig,
    pub tls: Option<TlsConfig>,
    pub persistence: PersistenceConfig,
    pub limits: LimitsConfig,
    pub replication: ReplicationConfig,
    pub slowlog_log_slower_than: u32,
    pub slowlog_max_len: u32,
    pub latency_monitor_threshold: u32,
    pub custom_config: Vec<String>,
}

impl Default for RedisConfigGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl RedisConfigGenerator {
    pub fn new() -> Self {
        Self {
            port: 6379,
            daemonize: false,
            pidfile: "/var/run/redis/redis-server.pid".to_string(),
            loglevel: "notice".to_string(),
            logfile: "/var/log/redis/redis-server.log".to_string(),
            databases: 16,
            dir: "/var/lib/redis".to_string(),
            security: SecurityConfig::default(),
            tls: None,
            persistence: PersistenceConfig::default(),
            limits: LimitsConfig::default(),
            replication: ReplicationConfig::default(),
            slowlog_log_slower_than: 10000,
            slowlog_max_len: 128,
            latency_monitor_threshold: 0,
            custom_config: Vec::new(),
        }
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn daemonize(mut self, daemon: bool) -> Self {
        self.daemonize = daemon;
        self
    }

    pub fn loglevel(mut self, level: impl Into<String>) -> Self {
        self.loglevel = level.into();
        self
    }

    pub fn logfile(mut self, path: impl Into<String>) -> Self {
        self.logfile = path.into();
        self
    }

    pub fn databases(mut self, count: u32) -> Self {
        self.databases = count;
        self
    }

    pub fn dir(mut self, path: impl Into<String>) -> Self {
        self.dir = path.into();
        self
    }

    pub fn security(mut self, config: SecurityConfig) -> Self {
        self.security = config;
        self
    }

    pub fn tls(mut self, config: TlsConfig) -> Self {
        self.tls = Some(config);
        self
    }

    pub fn persistence(mut self, config: PersistenceConfig) -> Self {
        self.persistence = config;
        self
    }

    pub fn limits(mut self, config: LimitsConfig) -> Self {
        self.limits = config;
        self
    }

    pub fn replication(mut self, config: ReplicationConfig) -> Self {
        self.replication = config;
        self
    }

    pub fn slowlog(mut self, threshold_us: u32, max_len: u32) -> Self {
        self.slowlog_log_slower_than = threshold_us;
        self.slowlog_max_len = max_len;
        self
    }

    pub fn latency_monitor(mut self, threshold_ms: u32) -> Self {
        self.latency_monitor_threshold = threshold_ms;
        self
    }

    pub fn custom(mut self, directive: impl Into<String>) -> Self {
        self.custom_config.push(directive.into());
        self
    }

    pub fn generate(&self) -> String {
        let mut config = String::new();

        config.push_str("# Redis Security Configuration\n");
        config.push_str("# Generated by Rust Redis Config Generator\n\n");

        // Basic settings
        config.push_str(
            "################################## NETWORK ##################################\n\n",
        );
        config.push_str(&format!("port {}\n", self.port));
        for line in self.security.generate() {
            if line.starts_with("bind") || line.starts_with("protected-mode") {
                config.push_str(&format!("{}\n", line));
            }
        }

        // TLS
        if let Some(ref tls) = self.tls {
            config.push_str(
                "\n################################### TLS ###################################\n\n",
            );
            for line in tls.generate() {
                config.push_str(&format!("{}\n", line));
            }
        }

        // General
        config.push_str(
            "\n################################## GENERAL ##################################\n\n",
        );
        config.push_str(&format!(
            "daemonize {}\n",
            if self.daemonize { "yes" } else { "no" }
        ));
        config.push_str(&format!("pidfile {}\n", self.pidfile));
        config.push_str(&format!("loglevel {}\n", self.loglevel));
        config.push_str(&format!("logfile \"{}\"\n", self.logfile));
        config.push_str(&format!("databases {}\n", self.databases));
        config.push_str(&format!("dir {}\n", self.dir));

        // Persistence
        config.push_str(
            "\n################################ SNAPSHOTTING ################################\n\n",
        );
        for line in self.persistence.generate() {
            config.push_str(&format!("{}\n", line));
        }

        // Replication
        config.push_str(
            "\n################################# REPLICATION #################################\n\n",
        );
        for line in self.replication.generate() {
            config.push_str(&format!("{}\n", line));
        }

        // Security
        config.push_str(
            "\n################################## SECURITY ##################################\n\n",
        );
        for line in self.security.generate() {
            if !line.starts_with("bind") && !line.starts_with("protected-mode") {
                config.push_str(&format!("{}\n", line));
            }
        }

        // Limits
        config.push_str(
            "\n################################### LIMITS ###################################\n\n",
        );
        for line in self.limits.generate() {
            config.push_str(&format!("{}\n", line));
        }

        // Slow log
        config.push_str(
            "\n################################## SLOW LOG ##################################\n\n",
        );
        config.push_str(&format!(
            "slowlog-log-slower-than {}\n",
            self.slowlog_log_slower_than
        ));
        config.push_str(&format!("slowlog-max-len {}\n", self.slowlog_max_len));

        // Latency monitor
        config.push_str(
            "\n############################ LATENCY MONITOR ################################\n\n",
        );
        config.push_str(&format!(
            "latency-monitor-threshold {}\n",
            self.latency_monitor_threshold
        ));

        // Custom
        if !self.custom_config.is_empty() {
            config.push_str("\n################################## CUSTOM ###################################\n\n");
            for line in &self.custom_config {
                config.push_str(&format!("{}\n", line));
            }
        }

        config
    }
}

fn main() {
    println!("=== Redis Security Configuration Generator Demo ===\n");

    // Create ACL users
    let admin_user = AclUser::new("admin")
        .password("super_secure_admin_password_2024!")
        .allow_category(AclPermission::AllCommands)
        .key_pattern("*");

    let app_user = AclUser::new("myapp")
        .password("app_password_secure_2024!")
        .allow_category(AclPermission::Read)
        .allow_category(AclPermission::Write)
        .deny_category(AclPermission::Admin)
        .deny_category(AclPermission::Dangerous)
        .key_pattern("app:*")
        .key_pattern("cache:*");

    let readonly_user = AclUser::new("readonly")
        .password("readonly_password_2024!")
        .allow_category(AclPermission::Read)
        .deny_command("DEBUG")
        .deny_command("CONFIG")
        .key_pattern("*");

    // Security configuration
    let security = SecurityConfig::new()
        .bind("127.0.0.1")
        .bind("::1")
        .protected_mode(true)
        .acl_user(admin_user)
        .acl_user(app_user)
        .acl_user(readonly_user)
        .disable_command("DEBUG")
        .disable_command("FLUSHALL")
        .disable_command("FLUSHDB")
        .rename_command("CONFIG", "CONFIG_a1b2c3d4");

    // TLS configuration
    let tls = TlsConfig::new("/etc/redis/tls/redis.crt", "/etc/redis/tls/redis.key")
        .port(6380)
        .ca_cert("/etc/redis/tls/ca.crt")
        .dh_params("/etc/redis/tls/dhparam.pem")
        .require_client_cert();

    // Persistence configuration
    let persistence = PersistenceConfig::new()
        .enable_aof()
        .aof_fsync(AofFsync::Everysec);

    // Limits configuration
    let limits = LimitsConfig::new()
        .maxclients(5000)
        .maxmemory("4gb")
        .maxmemory_policy(MaxMemoryPolicy::AllKeysLfu)
        .timeout(300)
        .tcp_keepalive(60);

    // Replication configuration
    let replication = ReplicationConfig::new().min_replicas(1, 10);

    // Generate full configuration
    let generator = RedisConfigGenerator::new()
        .port(6379)
        .loglevel("notice")
        .dir("/var/lib/redis")
        .security(security)
        .tls(tls)
        .persistence(persistence)
        .limits(limits)
        .replication(replication)
        .slowlog(10000, 256)
        .latency_monitor(100)
        .custom("# Application-specific settings")
        .custom("hash-max-ziplist-entries 512")
        .custom("hash-max-ziplist-value 64");

    println!("Generated Redis Configuration:");
    println!("{}", "=".repeat(70));
    println!("{}", generator.generate());
    println!("{}", "=".repeat(70));

    // Show individual ACL user
    println!("\nACL User Example (app user):");
    let example_user = AclUser::new("example")
        .password("secure123")
        .allow_category(AclPermission::Read)
        .allow_category(AclPermission::Write)
        .deny_category(AclPermission::Dangerous)
        .key_pattern("myapp:*");
    println!("  {}", example_user.generate());

    println!("\n=== Demo Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acl_permission_strings() {
        assert_eq!(AclPermission::Read.as_acl_str(), "+@read");
        assert_eq!(AclPermission::Write.as_acl_str(), "+@write");
        assert_eq!(AclPermission::AllCommands.deny_str(), "-@all");
    }

    #[test]
    fn test_acl_user_basic() {
        let user = AclUser::new("testuser")
            .password("testpass")
            .allow_category(AclPermission::Read);

        let acl = user.generate();
        assert!(acl.contains("user testuser"));
        assert!(acl.contains(">testpass"));
        assert!(acl.contains("+@read"));
    }

    #[test]
    fn test_acl_user_nopass() {
        let user = AclUser::new("nopassuser").nopass();
        let acl = user.generate();
        assert!(acl.contains("nopass"));
    }

    #[test]
    fn test_acl_user_disabled() {
        let user = AclUser::new("disableduser").disabled();
        let acl = user.generate();
        assert!(acl.contains("off"));
    }

    #[test]
    fn test_acl_user_key_pattern() {
        let user = AclUser::new("appuser")
            .password("pass")
            .key_pattern("app:*")
            .key_pattern("cache:*");

        let acl = user.generate();
        assert!(acl.contains("~app:*"));
        assert!(acl.contains("~cache:*"));
    }

    #[test]
    fn test_tls_config() {
        let tls = TlsConfig::new("/cert.pem", "/key.pem")
            .port(6380)
            .ca_cert("/ca.pem")
            .require_client_cert();

        let config = tls.generate();
        assert!(config.iter().any(|l| l.contains("tls-port 6380")));
        assert!(config.iter().any(|l| l.contains("tls-cert-file")));
        assert!(config.iter().any(|l| l.contains("tls-auth-clients yes")));
    }

    #[test]
    fn test_maxmemory_policy() {
        assert_eq!(MaxMemoryPolicy::AllKeysLru.as_str(), "allkeys-lru");
        assert_eq!(MaxMemoryPolicy::NoEviction.as_str(), "noeviction");
    }

    #[test]
    fn test_persistence_config() {
        let config = PersistenceConfig::new()
            .enable_aof()
            .aof_fsync(AofFsync::Always);

        let lines = config.generate();
        assert!(lines.iter().any(|l| l.contains("appendonly yes")));
        assert!(lines.iter().any(|l| l.contains("appendfsync always")));
    }

    #[test]
    fn test_persistence_rdb_disabled() {
        let config = PersistenceConfig::new().disable_rdb();
        let lines = config.generate();
        assert!(lines.iter().any(|l| l.contains("save \"\"")));
    }

    #[test]
    fn test_security_config() {
        let config = SecurityConfig::new()
            .bind("127.0.0.1")
            .bind("192.168.1.1")
            .password("secret")
            .disable_command("DEBUG");

        let lines = config.generate();
        assert!(lines
            .iter()
            .any(|l| l.contains("bind 127.0.0.1 192.168.1.1")));
        assert!(lines.iter().any(|l| l.contains("requirepass secret")));
        assert!(lines
            .iter()
            .any(|l| l.contains("rename-command DEBUG \"\"")));
    }

    #[test]
    fn test_limits_config() {
        let config = LimitsConfig::new()
            .maxclients(5000)
            .maxmemory("2gb")
            .maxmemory_policy(MaxMemoryPolicy::AllKeysLfu);

        let lines = config.generate();
        assert!(lines.iter().any(|l| l.contains("maxclients 5000")));
        assert!(lines.iter().any(|l| l.contains("maxmemory 2gb")));
        assert!(lines
            .iter()
            .any(|l| l.contains("maxmemory-policy allkeys-lfu")));
    }

    #[test]
    fn test_replication_config() {
        let config = ReplicationConfig::new()
            .replica_of("master.example.com", 6379)
            .masterauth("masterpassword")
            .min_replicas(2, 10);

        let lines = config.generate();
        assert!(lines
            .iter()
            .any(|l| l.contains("replicaof master.example.com 6379")));
        assert!(lines
            .iter()
            .any(|l| l.contains("masterauth masterpassword")));
        assert!(lines.iter().any(|l| l.contains("min-replicas-to-write 2")));
    }

    #[test]
    fn test_redis_config_generator() {
        let generator = RedisConfigGenerator::new()
            .port(6380)
            .databases(8)
            .loglevel("warning");

        let config = generator.generate();
        assert!(config.contains("port 6380"));
        assert!(config.contains("databases 8"));
        assert!(config.contains("loglevel warning"));
    }

    #[test]
    fn test_full_config_generation() {
        let security = SecurityConfig::new()
            .bind("127.0.0.1")
            .password("secret123");

        let generator = RedisConfigGenerator::new()
            .port(6379)
            .security(security)
            .slowlog(5000, 100);

        let config = generator.generate();
        assert!(config.contains("bind 127.0.0.1"));
        assert!(config.contains("requirepass secret123"));
        assert!(config.contains("slowlog-log-slower-than 5000"));
    }

    #[test]
    fn test_aof_fsync_options() {
        assert_eq!(AofFsync::Always.as_str(), "always");
        assert_eq!(AofFsync::Everysec.as_str(), "everysec");
        assert_eq!(AofFsync::No.as_str(), "no");
    }

    #[test]
    fn test_custom_config() {
        let generator = RedisConfigGenerator::new()
            .custom("notify-keyspace-events KEA")
            .custom("activerehashing yes");

        let config = generator.generate();
        assert!(config.contains("notify-keyspace-events KEA"));
        assert!(config.contains("activerehashing yes"));
    }

    #[test]
    fn test_command_rename() {
        let security = SecurityConfig::new().rename_command("CONFIG", "SECRET_CONFIG_123");

        let lines = security.generate();
        assert!(lines
            .iter()
            .any(|l| l.contains("rename-command CONFIG SECRET_CONFIG_123")));
    }

    #[test]
    fn test_acl_deny_category() {
        let user = AclUser::new("limited")
            .password("pass")
            .deny_category(AclPermission::Admin)
            .deny_category(AclPermission::Dangerous)
            .allow_category(AclPermission::Read);

        let acl = user.generate();
        assert!(acl.contains("-@admin"));
        assert!(acl.contains("-@dangerous"));
        assert!(acl.contains("+@read"));
    }
}
