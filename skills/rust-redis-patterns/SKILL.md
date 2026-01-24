# Rust Redis/Valkey Security Patterns Skills

This skill provides patterns for secure Redis and Valkey configuration from
Rust, including authentication, TLS, ACLs, and secure connection management.

## Overview

Redis/Valkey security covers:

- **Authentication**: Passwords and ACL users
- **TLS/SSL**: Encrypted connections
- **ACLs**: Fine-grained access control
- **Network Security**: Bind addresses and protected mode
- **Data Security**: Persistence and backup encryption

## /redis-config

Generate a security-hardened Redis/Valkey configuration.

### Usage

```bash
/redis-config
```

### What It Does

1. Generates secure redis.conf
2. Configures ACL users
3. Sets up TLS
4. Configures persistence security
5. Sets memory and connection limits

---

## Configuration Types

```rust
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct RedisConfig {
    pub network: NetworkConfig,
    pub security: SecurityConfig,
    pub tls: Option<TlsConfig>,
    pub persistence: PersistenceConfig,
    pub limits: LimitsConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub bind: Vec<String>,
    pub port: u16,
    pub tls_port: Option<u16>,
    pub unix_socket: Option<PathBuf>,
    pub unix_socket_perm: u32,
    pub tcp_backlog: u32,
    pub tcp_keepalive: u32,
    pub protected_mode: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub requirepass: Option<String>,
    pub acl_file: Option<PathBuf>,
    pub acl_users: Vec<AclUser>,
    pub rename_commands: Vec<(String, String)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AclUser {
    pub username: String,
    pub enabled: bool,
    pub passwords: Vec<AclPassword>,
    pub commands: AclCommands,
    pub keys: AclKeys,
    pub channels: AclChannels,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AclPassword {
    Plaintext(String),
    Sha256(String),
    NoPass,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AclCommands {
    pub allow_all: bool,
    pub allowed: Vec<String>,
    pub denied: Vec<String>,
    pub allowed_categories: Vec<String>,
    pub denied_categories: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AclKeys {
    pub all_keys: bool,
    pub patterns: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AclChannels {
    pub all_channels: bool,
    pub patterns: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub ca_cert_file: Option<PathBuf>,
    pub dh_params_file: Option<PathBuf>,
    pub protocols: Vec<String>,
    pub ciphers: Option<String>,
    pub ciphersuites: Option<String>,
    pub prefer_server_ciphers: bool,
    pub client_auth: ClientAuth,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ClientAuth {
    No,
    Optional,
    Required,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PersistenceConfig {
    pub rdb_enabled: bool,
    pub rdb_filename: String,
    pub rdb_save_rules: Vec<(u64, u64)>,  // (seconds, changes)
    pub aof_enabled: bool,
    pub aof_filename: String,
    pub aof_fsync: AofFsync,
    pub dir: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AofFsync {
    Always,
    Everysec,
    No,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LimitsConfig {
    pub maxclients: u32,
    pub maxmemory: String,
    pub maxmemory_policy: EvictionPolicy,
    pub timeout: u32,
    pub tcp_keepalive: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum EvictionPolicy {
    NoEviction,
    AllkeysLru,
    VolatileLru,
    AllkeysRandom,
    VolatileRandom,
    VolatileTtl,
    AllkeysLfu,
    VolatileLfu,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub loglevel: LogLevel,
    pub logfile: PathBuf,
    pub syslog_enabled: bool,
    pub syslog_ident: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum LogLevel {
    Debug,
    Verbose,
    Notice,
    Warning,
}
```

---

## Configuration Builder

```rust
impl RedisConfig {
    pub fn secure_default() -> Self {
        Self {
            network: NetworkConfig {
                bind: vec!["127.0.0.1".to_string()],
                port: 6379,
                tls_port: Some(6380),
                unix_socket: Some(PathBuf::from("/run/redis/redis.sock")),
                unix_socket_perm: 0o770,
                tcp_backlog: 511,
                tcp_keepalive: 300,
                protected_mode: true,
            },
            security: SecurityConfig {
                requirepass: None,  // Use ACL instead
                acl_file: Some(PathBuf::from("/etc/redis/users.acl")),
                acl_users: vec![
                    AclUser::admin("admin"),
                    AclUser::application("app"),
                    AclUser::readonly("reader"),
                ],
                rename_commands: vec![
                    ("FLUSHDB".to_string(), "".to_string()),     // Disable
                    ("FLUSHALL".to_string(), "".to_string()),    // Disable
                    ("DEBUG".to_string(), "".to_string()),       // Disable
                    ("CONFIG".to_string(), "".to_string()),      // Disable
                    ("SHUTDOWN".to_string(), "".to_string()),    // Disable
                ],
            },
            tls: None,
            persistence: PersistenceConfig {
                rdb_enabled: true,
                rdb_filename: "dump.rdb".to_string(),
                rdb_save_rules: vec![
                    (900, 1),      // After 900s if at least 1 key changed
                    (300, 10),     // After 300s if at least 10 keys changed
                    (60, 10000),   // After 60s if at least 10000 keys changed
                ],
                aof_enabled: true,
                aof_filename: "appendonly.aof".to_string(),
                aof_fsync: AofFsync::Everysec,
                dir: PathBuf::from("/var/lib/redis"),
            },
            limits: LimitsConfig {
                maxclients: 10000,
                maxmemory: "1gb".to_string(),
                maxmemory_policy: EvictionPolicy::AllkeysLru,
                timeout: 0,
                tcp_keepalive: 300,
            },
            logging: LoggingConfig {
                loglevel: LogLevel::Notice,
                logfile: PathBuf::from("/var/log/redis/redis.log"),
                syslog_enabled: false,
                syslog_ident: "redis".to_string(),
            },
        }
    }

    pub fn with_tls(mut self, cert: PathBuf, key: PathBuf, ca: Option<PathBuf>) -> Self {
        self.tls = Some(TlsConfig {
            cert_file: cert,
            key_file: key,
            ca_cert_file: ca,
            dh_params_file: None,
            protocols: vec!["TLSv1.2".to_string(), "TLSv1.3".to_string()],
            ciphers: None,
            ciphersuites: None,
            prefer_server_ciphers: true,
            client_auth: ClientAuth::Optional,
        });
        self
    }
}

impl AclUser {
    pub fn admin(username: &str) -> Self {
        Self {
            username: username.to_string(),
            enabled: true,
            passwords: vec![],  // Set during deployment
            commands: AclCommands {
                allow_all: true,
                allowed: vec![],
                denied: vec![],
                allowed_categories: vec![],
                denied_categories: vec![],
            },
            keys: AclKeys {
                all_keys: true,
                patterns: vec![],
            },
            channels: AclChannels {
                all_channels: true,
                patterns: vec![],
            },
        }
    }

    pub fn application(username: &str) -> Self {
        Self {
            username: username.to_string(),
            enabled: true,
            passwords: vec![],
            commands: AclCommands {
                allow_all: false,
                allowed: vec![],
                denied: vec![
                    "FLUSHDB".to_string(),
                    "FLUSHALL".to_string(),
                    "DEBUG".to_string(),
                    "CONFIG".to_string(),
                    "SHUTDOWN".to_string(),
                    "BGSAVE".to_string(),
                    "BGREWRITEAOF".to_string(),
                    "SLAVEOF".to_string(),
                    "REPLICAOF".to_string(),
                ],
                allowed_categories: vec![
                    "read".to_string(),
                    "write".to_string(),
                    "set".to_string(),
                    "list".to_string(),
                    "hash".to_string(),
                    "string".to_string(),
                    "transaction".to_string(),
                    "pubsub".to_string(),
                ],
                denied_categories: vec![
                    "admin".to_string(),
                    "dangerous".to_string(),
                ],
            },
            keys: AclKeys {
                all_keys: false,
                patterns: vec!["app:*".to_string()],  // Only app namespace
            },
            channels: AclChannels {
                all_channels: false,
                patterns: vec!["app:*".to_string()],
            },
        }
    }

    pub fn readonly(username: &str) -> Self {
        Self {
            username: username.to_string(),
            enabled: true,
            passwords: vec![],
            commands: AclCommands {
                allow_all: false,
                allowed: vec![],
                denied: vec![],
                allowed_categories: vec!["read".to_string()],
                denied_categories: vec![
                    "write".to_string(),
                    "admin".to_string(),
                    "dangerous".to_string(),
                ],
            },
            keys: AclKeys {
                all_keys: true,
                patterns: vec![],
            },
            channels: AclChannels {
                all_channels: false,
                patterns: vec![],
            },
        }
    }
}
```

---

## Configuration Renderer

```rust
pub struct RedisRenderer;

impl RedisRenderer {
    pub fn render(config: &RedisConfig) -> String {
        let mut output = String::new();

        output.push_str("# Redis Configuration\n");
        output.push_str("# Generated by syntek-rust-security\n\n");

        output.push_str(&Self::render_network(&config.network));
        output.push_str(&Self::render_security(&config.security));

        if let Some(tls) = &config.tls {
            output.push_str(&Self::render_tls(tls));
        }

        output.push_str(&Self::render_persistence(&config.persistence));
        output.push_str(&Self::render_limits(&config.limits));
        output.push_str(&Self::render_logging(&config.logging));

        output
    }

    fn render_network(network: &NetworkConfig) -> String {
        let mut output = String::new();

        output.push_str("################################# NETWORK #################################\n\n");

        output.push_str(&format!("bind {}\n", network.bind.join(" ")));
        output.push_str(&format!("port {}\n", network.port));

        if let Some(tls_port) = network.tls_port {
            output.push_str(&format!("tls-port {}\n", tls_port));
        }

        if let Some(socket) = &network.unix_socket {
            output.push_str(&format!("unixsocket {}\n", socket.display()));
            output.push_str(&format!("unixsocketperm {:03o}\n", network.unix_socket_perm));
        }

        output.push_str(&format!("tcp-backlog {}\n", network.tcp_backlog));
        output.push_str(&format!("tcp-keepalive {}\n", network.tcp_keepalive));
        output.push_str(&format!("protected-mode {}\n\n", if network.protected_mode { "yes" } else { "no" }));

        output
    }

    fn render_security(security: &SecurityConfig) -> String {
        let mut output = String::new();

        output.push_str("################################# SECURITY #################################\n\n");

        if let Some(pass) = &security.requirepass {
            output.push_str(&format!("requirepass {}\n", pass));
        }

        if let Some(acl_file) = &security.acl_file {
            output.push_str(&format!("aclfile {}\n", acl_file.display()));
        }

        for (cmd, rename_to) in &security.rename_commands {
            if rename_to.is_empty() {
                output.push_str(&format!("rename-command {} \"\"\n", cmd));
            } else {
                output.push_str(&format!("rename-command {} {}\n", cmd, rename_to));
            }
        }

        output.push_str("\n");
        output
    }

    fn render_tls(tls: &TlsConfig) -> String {
        let mut output = String::new();

        output.push_str("################################# TLS/SSL #################################\n\n");

        output.push_str(&format!("tls-cert-file {}\n", tls.cert_file.display()));
        output.push_str(&format!("tls-key-file {}\n", tls.key_file.display()));

        if let Some(ca) = &tls.ca_cert_file {
            output.push_str(&format!("tls-ca-cert-file {}\n", ca.display()));
        }

        if let Some(dh) = &tls.dh_params_file {
            output.push_str(&format!("tls-dh-params-file {}\n", dh.display()));
        }

        output.push_str(&format!("tls-protocols \"{}\"\n", tls.protocols.join(" ")));

        if let Some(ciphers) = &tls.ciphers {
            output.push_str(&format!("tls-ciphers {}\n", ciphers));
        }

        if let Some(ciphersuites) = &tls.ciphersuites {
            output.push_str(&format!("tls-ciphersuites {}\n", ciphersuites));
        }

        output.push_str(&format!("tls-prefer-server-ciphers {}\n", if tls.prefer_server_ciphers { "yes" } else { "no" }));

        let auth_clients = match tls.client_auth {
            ClientAuth::No => "no",
            ClientAuth::Optional => "optional",
            ClientAuth::Required => "yes",
        };
        output.push_str(&format!("tls-auth-clients {}\n\n", auth_clients));

        output
    }

    fn render_persistence(persistence: &PersistenceConfig) -> String {
        let mut output = String::new();

        output.push_str("################################# PERSISTENCE #################################\n\n");

        output.push_str(&format!("dir {}\n", persistence.dir.display()));

        // RDB
        if persistence.rdb_enabled {
            output.push_str(&format!("dbfilename {}\n", persistence.rdb_filename));
            for (seconds, changes) in &persistence.rdb_save_rules {
                output.push_str(&format!("save {} {}\n", seconds, changes));
            }
        } else {
            output.push_str("save \"\"\n");
        }

        // AOF
        output.push_str(&format!("appendonly {}\n", if persistence.aof_enabled { "yes" } else { "no" }));
        output.push_str(&format!("appendfilename \"{}\"\n", persistence.aof_filename));

        let fsync = match persistence.aof_fsync {
            AofFsync::Always => "always",
            AofFsync::Everysec => "everysec",
            AofFsync::No => "no",
        };
        output.push_str(&format!("appendfsync {}\n\n", fsync));

        output
    }

    fn render_limits(limits: &LimitsConfig) -> String {
        let mut output = String::new();

        output.push_str("################################# LIMITS #################################\n\n");

        output.push_str(&format!("maxclients {}\n", limits.maxclients));
        output.push_str(&format!("maxmemory {}\n", limits.maxmemory));

        let policy = match limits.maxmemory_policy {
            EvictionPolicy::NoEviction => "noeviction",
            EvictionPolicy::AllkeysLru => "allkeys-lru",
            EvictionPolicy::VolatileLru => "volatile-lru",
            EvictionPolicy::AllkeysRandom => "allkeys-random",
            EvictionPolicy::VolatileRandom => "volatile-random",
            EvictionPolicy::VolatileTtl => "volatile-ttl",
            EvictionPolicy::AllkeysLfu => "allkeys-lfu",
            EvictionPolicy::VolatileLfu => "volatile-lfu",
        };
        output.push_str(&format!("maxmemory-policy {}\n", policy));
        output.push_str(&format!("timeout {}\n\n", limits.timeout));

        output
    }

    fn render_logging(logging: &LoggingConfig) -> String {
        let mut output = String::new();

        output.push_str("################################# LOGGING #################################\n\n");

        let level = match logging.loglevel {
            LogLevel::Debug => "debug",
            LogLevel::Verbose => "verbose",
            LogLevel::Notice => "notice",
            LogLevel::Warning => "warning",
        };
        output.push_str(&format!("loglevel {}\n", level));
        output.push_str(&format!("logfile {}\n", logging.logfile.display()));

        if logging.syslog_enabled {
            output.push_str("syslog-enabled yes\n");
            output.push_str(&format!("syslog-ident {}\n", logging.syslog_ident));
        }

        output.push_str("\n");
        output
    }

    pub fn render_acl_file(users: &[AclUser]) -> String {
        let mut output = String::new();

        output.push_str("# Redis ACL File\n");
        output.push_str("# Generated by syntek-rust-security\n\n");

        for user in users {
            output.push_str(&Self::render_acl_user(user));
            output.push_str("\n");
        }

        output
    }

    fn render_acl_user(user: &AclUser) -> String {
        let mut parts = vec![format!("user {}", user.username)];

        // Enabled/disabled
        if user.enabled {
            parts.push("on".to_string());
        } else {
            parts.push("off".to_string());
        }

        // Passwords
        for password in &user.passwords {
            match password {
                AclPassword::Plaintext(p) => parts.push(format!(">{}", p)),
                AclPassword::Sha256(h) => parts.push(format!("#{}", h)),
                AclPassword::NoPass => parts.push("nopass".to_string()),
            }
        }

        // Commands
        if user.commands.allow_all {
            parts.push("+@all".to_string());
        } else {
            for cat in &user.commands.allowed_categories {
                parts.push(format!("+@{}", cat));
            }
            for cat in &user.commands.denied_categories {
                parts.push(format!("-@{}", cat));
            }
            for cmd in &user.commands.allowed {
                parts.push(format!("+{}", cmd));
            }
            for cmd in &user.commands.denied {
                parts.push(format!("-{}", cmd));
            }
        }

        // Keys
        if user.keys.all_keys {
            parts.push("~*".to_string());
        } else {
            for pattern in &user.keys.patterns {
                parts.push(format!("~{}", pattern));
            }
        }

        // Channels
        if user.channels.all_channels {
            parts.push("&*".to_string());
        } else {
            for pattern in &user.channels.patterns {
                parts.push(format!("&{}", pattern));
            }
        }

        parts.join(" ")
    }
}
```

---

## Rust Redis Client Integration

```rust
use redis::{Client, Connection, Commands, RedisResult};
use secrecy::{Secret, ExposeSecret};

pub struct SecureRedisClient {
    client: Client,
    password: Option<Secret<String>>,
}

impl SecureRedisClient {
    pub fn new(url: &str, password: Option<Secret<String>>) -> RedisResult<Self> {
        let client = Client::open(url)?;
        Ok(Self { client, password })
    }

    pub fn new_with_tls(
        host: &str,
        port: u16,
        password: Option<Secret<String>>,
        cert_path: &std::path::Path,
    ) -> RedisResult<Self> {
        let url = format!(
            "rediss://{}:{}/#insecure",  // Use proper TLS verification in production
            host, port
        );
        let client = Client::open(url)?;
        Ok(Self { client, password })
    }

    pub fn get_connection(&self) -> RedisResult<Connection> {
        let mut conn = self.client.get_connection()?;

        // Authenticate if password is set
        if let Some(password) = &self.password {
            redis::cmd("AUTH")
                .arg(password.expose_secret())
                .query::<()>(&mut conn)?;
        }

        Ok(conn)
    }

    pub fn get_connection_with_user(&self, username: &str, password: &Secret<String>) -> RedisResult<Connection> {
        let mut conn = self.client.get_connection()?;

        redis::cmd("AUTH")
            .arg(username)
            .arg(password.expose_secret())
            .query::<()>(&mut conn)?;

        Ok(conn)
    }
}
```

---

## Security Checklist

### Network

- [ ] Bind to localhost or Unix socket only
- [ ] protected-mode enabled
- [ ] TLS configured for remote access
- [ ] Firewall rules in place

### Authentication

- [ ] ACL users configured (not just requirepass)
- [ ] Strong passwords
- [ ] Different users for different access levels
- [ ] Default user disabled or restricted

### Commands

- [ ] Dangerous commands renamed or disabled
- [ ] DEBUG, CONFIG, SHUTDOWN disabled
- [ ] FLUSHDB, FLUSHALL disabled for app users

### Data

- [ ] Persistence enabled (RDB and/or AOF)
- [ ] Data directory secured
- [ ] Backup encryption considered

## Recommended Crates

- **redis**: Redis client
- **secrecy**: Secret wrapping

## Integration Points

This skill works well with:

- `/vault-setup` - Password management
- `/nginx-config` - Reverse proxy (for Redis Cluster)
