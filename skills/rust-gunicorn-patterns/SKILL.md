# Rust Gunicorn + Uvicorn Security Patterns Skills

This skill provides patterns for generating secure Gunicorn and Uvicorn
configurations from Rust for Django/FastAPI backends, including worker
management, SSL configuration, and integration with Rust security wrappers.

## Overview

Gunicorn/Uvicorn security covers:

- **Worker Configuration**: Process isolation and limits
- **SSL/TLS**: Secure connections
- **Timeouts**: DoS protection
- **Logging**: Security audit trails
- **Integration**: Rust wrapper communication

## /gunicorn-config

Generate a security-hardened Gunicorn configuration.

### Usage

```bash
/gunicorn-config [--django|--fastapi]
```

### What It Does

1. Generates secure gunicorn.conf.py
2. Creates uvicorn configuration
3. Sets up secure worker settings
4. Configures logging
5. Sets appropriate timeouts

---

## Configuration Types

```rust
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct GunicornConfig {
    pub bind: Vec<String>,
    pub workers: WorkerConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
    pub ssl: Option<SslConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerConfig {
    pub worker_class: WorkerClass,
    pub workers: WorkerCount,
    pub threads: u32,
    pub worker_connections: u32,
    pub max_requests: u32,
    pub max_requests_jitter: u32,
    pub timeout: u32,
    pub graceful_timeout: u32,
    pub keepalive: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerClass {
    Sync,
    Gevent,
    Eventlet,
    Tornado,
    Uvicorn,  // For ASGI (FastAPI)
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerCount {
    Auto,           // (2 * CPU cores) + 1
    Fixed(u32),
    CpuMultiplier(f32),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub user: Option<String>,
    pub group: Option<String>,
    pub umask: u32,
    pub limit_request_line: u32,
    pub limit_request_fields: u32,
    pub limit_request_field_size: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub access_log: PathBuf,
    pub error_log: PathBuf,
    pub log_level: LogLevel,
    pub access_log_format: String,
    pub capture_output: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SslConfig {
    pub keyfile: PathBuf,
    pub certfile: PathBuf,
    pub ssl_version: SslVersion,
    pub cert_reqs: CertRequirement,
    pub ca_certs: Option<PathBuf>,
    pub ciphers: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SslVersion {
    TLSv1_2,
    TLSv1_3,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CertRequirement {
    None,
    Optional,
    Required,
}
```

---

## Configuration Builder

```rust
impl GunicornConfig {
    pub fn secure_default() -> Self {
        Self {
            bind: vec!["unix:/run/gunicorn/gunicorn.sock".to_string()],
            workers: WorkerConfig {
                worker_class: WorkerClass::Uvicorn,
                workers: WorkerCount::Auto,
                threads: 1,
                worker_connections: 1000,
                max_requests: 10000,
                max_requests_jitter: 1000,
                timeout: 30,
                graceful_timeout: 30,
                keepalive: 5,
            },
            security: SecurityConfig {
                user: Some("www-data".to_string()),
                group: Some("www-data".to_string()),
                umask: 0o007,
                limit_request_line: 4094,
                limit_request_fields: 100,
                limit_request_field_size: 8190,
            },
            logging: LoggingConfig {
                access_log: PathBuf::from("/var/log/gunicorn/access.log"),
                error_log: PathBuf::from("/var/log/gunicorn/error.log"),
                log_level: LogLevel::Warning,
                access_log_format: r#"%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s"#.to_string(),
                capture_output: true,
            },
            ssl: None,
        }
    }

    pub fn for_django() -> Self {
        let mut config = Self::secure_default();
        config.workers.worker_class = WorkerClass::Sync;
        config.workers.threads = 4;
        config
    }

    pub fn for_fastapi() -> Self {
        let mut config = Self::secure_default();
        config.workers.worker_class = WorkerClass::Uvicorn;
        config.workers.worker_connections = 1000;
        config
    }

    pub fn with_ssl(mut self, cert: PathBuf, key: PathBuf) -> Self {
        self.ssl = Some(SslConfig {
            keyfile: key,
            certfile: cert,
            ssl_version: SslVersion::TLSv1_2,
            cert_reqs: CertRequirement::None,
            ca_certs: None,
            ciphers: Some("ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20:!aNULL:!MD5:!DSS".to_string()),
        });
        self
    }
}
```

---

## Configuration Renderer

```rust
pub struct GunicornRenderer;

impl GunicornRenderer {
    pub fn render_python(config: &GunicornConfig) -> String {
        let mut output = String::new();

        output.push_str("# Gunicorn Configuration\n");
        output.push_str("# Generated by syntek-rust-security\n\n");
        output.push_str("import multiprocessing\n\n");

        // Bind
        output.push_str(&format!(
            "bind = {}\n",
            Self::python_list(&config.bind)
        ));

        // Workers
        output.push_str(&Self::render_workers(&config.workers));

        // Security
        output.push_str(&Self::render_security(&config.security));

        // Logging
        output.push_str(&Self::render_logging(&config.logging));

        // SSL
        if let Some(ssl) = &config.ssl {
            output.push_str(&Self::render_ssl(ssl));
        }

        // Hooks for graceful handling
        output.push_str(&Self::render_hooks());

        output
    }

    fn render_workers(workers: &WorkerConfig) -> String {
        let mut output = String::new();

        output.push_str("\n# Worker Configuration\n");

        // Worker class
        let worker_class = match workers.worker_class {
            WorkerClass::Sync => "sync",
            WorkerClass::Gevent => "gevent",
            WorkerClass::Eventlet => "eventlet",
            WorkerClass::Tornado => "tornado",
            WorkerClass::Uvicorn => "uvicorn.workers.UvicornWorker",
        };
        output.push_str(&format!("worker_class = \"{}\"\n", worker_class));

        // Worker count
        let workers_expr = match workers.workers {
            WorkerCount::Auto => "multiprocessing.cpu_count() * 2 + 1".to_string(),
            WorkerCount::Fixed(n) => n.to_string(),
            WorkerCount::CpuMultiplier(m) => format!("int(multiprocessing.cpu_count() * {})", m),
        };
        output.push_str(&format!("workers = {}\n", workers_expr));

        output.push_str(&format!("threads = {}\n", workers.threads));
        output.push_str(&format!("worker_connections = {}\n", workers.worker_connections));
        output.push_str(&format!("max_requests = {}\n", workers.max_requests));
        output.push_str(&format!("max_requests_jitter = {}\n", workers.max_requests_jitter));
        output.push_str(&format!("timeout = {}\n", workers.timeout));
        output.push_str(&format!("graceful_timeout = {}\n", workers.graceful_timeout));
        output.push_str(&format!("keepalive = {}\n", workers.keepalive));

        output
    }

    fn render_security(security: &SecurityConfig) -> String {
        let mut output = String::new();

        output.push_str("\n# Security Configuration\n");

        if let Some(user) = &security.user {
            output.push_str(&format!("user = \"{}\"\n", user));
        }

        if let Some(group) = &security.group {
            output.push_str(&format!("group = \"{}\"\n", group));
        }

        output.push_str(&format!("umask = 0o{:03o}\n", security.umask));
        output.push_str(&format!("limit_request_line = {}\n", security.limit_request_line));
        output.push_str(&format!("limit_request_fields = {}\n", security.limit_request_fields));
        output.push_str(&format!("limit_request_field_size = {}\n", security.limit_request_field_size));

        output
    }

    fn render_logging(logging: &LoggingConfig) -> String {
        let mut output = String::new();

        output.push_str("\n# Logging Configuration\n");

        output.push_str(&format!("accesslog = \"{}\"\n", logging.access_log.display()));
        output.push_str(&format!("errorlog = \"{}\"\n", logging.error_log.display()));

        let level = match logging.log_level {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warning => "warning",
            LogLevel::Error => "error",
            LogLevel::Critical => "critical",
        };
        output.push_str(&format!("loglevel = \"{}\"\n", level));

        output.push_str(&format!("access_log_format = '{}'\n", logging.access_log_format));
        output.push_str(&format!("capture_output = {}\n", if logging.capture_output { "True" } else { "False" }));

        output
    }

    fn render_ssl(ssl: &SslConfig) -> String {
        let mut output = String::new();

        output.push_str("\n# SSL Configuration\n");

        output.push_str(&format!("keyfile = \"{}\"\n", ssl.keyfile.display()));
        output.push_str(&format!("certfile = \"{}\"\n", ssl.certfile.display()));

        let ssl_version = match ssl.ssl_version {
            SslVersion::TLSv1_2 => "TLSv1_2",
            SslVersion::TLSv1_3 => "TLSv1_3",
        };
        output.push_str(&format!("ssl_version = ssl.PROTOCOL_{}\n", ssl_version));

        let cert_reqs = match ssl.cert_reqs {
            CertRequirement::None => "ssl.CERT_NONE",
            CertRequirement::Optional => "ssl.CERT_OPTIONAL",
            CertRequirement::Required => "ssl.CERT_REQUIRED",
        };
        output.push_str(&format!("cert_reqs = {}\n", cert_reqs));

        if let Some(ca) = &ssl.ca_certs {
            output.push_str(&format!("ca_certs = \"{}\"\n", ca.display()));
        }

        if let Some(ciphers) = &ssl.ciphers {
            output.push_str(&format!("ciphers = \"{}\"\n", ciphers));
        }

        output
    }

    fn render_hooks() -> String {
        r#"
# Worker Hooks
def worker_int(worker):
    """Called when worker receives INT or QUIT signal."""
    import sys
    sys.exit(0)

def worker_abort(worker):
    """Called when worker receives SIGABRT signal."""
    import sys
    sys.exit(1)

def on_starting(server):
    """Called before master process is initialized."""
    pass

def on_exit(server):
    """Called just before exiting Gunicorn."""
    pass

def pre_fork(server, worker):
    """Called just before a worker is forked."""
    pass

def post_fork(server, worker):
    """Called just after a worker has been forked."""
    pass

def pre_exec(server):
    """Called just before a new master process is forked."""
    pass

def child_exit(server, worker):
    """Called when a worker has been exited, in the master process."""
    pass
"#.to_string()
    }

    fn python_list(items: &[String]) -> String {
        let quoted: Vec<String> = items.iter()
            .map(|s| format!("\"{}\"", s))
            .collect();
        format!("[{}]", quoted.join(", "))
    }
}
```

---

## Uvicorn Configuration

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct UvicornConfig {
    pub host: String,
    pub port: u16,
    pub uds: Option<PathBuf>,
    pub workers: u32,
    pub loop_type: LoopType,
    pub http: HttpImplementation,
    pub ws: WsImplementation,
    pub lifespan: LifespanMode,
    pub interface: InterfaceType,
    pub reload: bool,
    pub log_level: LogLevel,
    pub access_log: bool,
    pub ssl_keyfile: Option<PathBuf>,
    pub ssl_certfile: Option<PathBuf>,
    pub ssl_version: Option<SslVersion>,
    pub limit_concurrency: Option<u32>,
    pub limit_max_requests: Option<u32>,
    pub timeout_keep_alive: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum LoopType {
    Auto,
    Asyncio,
    Uvloop,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum HttpImplementation {
    Auto,
    H11,
    Httptools,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WsImplementation {
    Auto,
    Websockets,
    Wsproto,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum LifespanMode {
    Auto,
    On,
    Off,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum InterfaceType {
    Auto,
    Asgi3,
    Asgi2,
    Wsgi,
}

impl UvicornConfig {
    pub fn secure_default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8000,
            uds: Some(PathBuf::from("/run/uvicorn/uvicorn.sock")),
            workers: 1,  // Let Gunicorn manage workers
            loop_type: LoopType::Auto,
            http: HttpImplementation::Auto,
            ws: WsImplementation::Auto,
            lifespan: LifespanMode::On,
            interface: InterfaceType::Auto,
            reload: false,  // Never in production
            log_level: LogLevel::Warning,
            access_log: true,
            ssl_keyfile: None,
            ssl_certfile: None,
            ssl_version: None,
            limit_concurrency: Some(100),
            limit_max_requests: Some(10000),
            timeout_keep_alive: 5,
        }
    }

    pub fn for_development() -> Self {
        let mut config = Self::secure_default();
        config.reload = true;
        config.log_level = LogLevel::Debug;
        config.uds = None;  // Use TCP for development
        config
    }
}

pub struct UvicornRenderer;

impl UvicornRenderer {
    pub fn render_args(config: &UvicornConfig) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(uds) = &config.uds {
            args.push(format!("--uds={}", uds.display()));
        } else {
            args.push(format!("--host={}", config.host));
            args.push(format!("--port={}", config.port));
        }

        if config.workers > 1 {
            args.push(format!("--workers={}", config.workers));
        }

        let loop_type = match config.loop_type {
            LoopType::Auto => "auto",
            LoopType::Asyncio => "asyncio",
            LoopType::Uvloop => "uvloop",
        };
        args.push(format!("--loop={}", loop_type));

        let http = match config.http {
            HttpImplementation::Auto => "auto",
            HttpImplementation::H11 => "h11",
            HttpImplementation::Httptools => "httptools",
        };
        args.push(format!("--http={}", http));

        let lifespan = match config.lifespan {
            LifespanMode::Auto => "auto",
            LifespanMode::On => "on",
            LifespanMode::Off => "off",
        };
        args.push(format!("--lifespan={}", lifespan));

        if config.reload {
            args.push("--reload".to_string());
        }

        let log_level = match config.log_level {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warning => "warning",
            LogLevel::Error => "error",
            LogLevel::Critical => "critical",
        };
        args.push(format!("--log-level={}", log_level));

        if !config.access_log {
            args.push("--no-access-log".to_string());
        }

        if let Some(keyfile) = &config.ssl_keyfile {
            args.push(format!("--ssl-keyfile={}", keyfile.display()));
        }

        if let Some(certfile) = &config.ssl_certfile {
            args.push(format!("--ssl-certfile={}", certfile.display()));
        }

        if let Some(limit) = config.limit_concurrency {
            args.push(format!("--limit-concurrency={}", limit));
        }

        if let Some(limit) = config.limit_max_requests {
            args.push(format!("--limit-max-requests={}", limit));
        }

        args.push(format!("--timeout-keep-alive={}", config.timeout_keep_alive));

        args
    }
}
```

---

## Systemd Service Integration

```rust
pub struct SystemdServiceConfig {
    pub service_name: String,
    pub description: String,
    pub user: String,
    pub group: String,
    pub working_directory: PathBuf,
    pub environment_file: Option<PathBuf>,
    pub exec_start: String,
    pub restart_policy: RestartPolicy,
    pub security: SystemdSecurityOptions,
}

pub struct SystemdSecurityOptions {
    pub no_new_privileges: bool,
    pub protect_system: ProtectSystemMode,
    pub protect_home: bool,
    pub private_tmp: bool,
    pub private_devices: bool,
    pub protect_kernel_tunables: bool,
    pub protect_kernel_modules: bool,
    pub protect_control_groups: bool,
    pub restrict_address_families: Vec<String>,
    pub restrict_namespaces: bool,
    pub restrict_realtime: bool,
    pub restrict_suid_sgid: bool,
    pub memory_deny_write_execute: bool,
    pub lock_personality: bool,
}

pub enum ProtectSystemMode {
    False,
    True,
    Full,
    Strict,
}

pub enum RestartPolicy {
    No,
    OnSuccess,
    OnFailure,
    OnAbnormal,
    OnAbort,
    Always,
}

impl SystemdServiceConfig {
    pub fn for_gunicorn(app_module: &str, config_path: &PathBuf) -> Self {
        Self {
            service_name: "gunicorn".to_string(),
            description: "Gunicorn Application Server".to_string(),
            user: "www-data".to_string(),
            group: "www-data".to_string(),
            working_directory: PathBuf::from("/var/www/app"),
            environment_file: Some(PathBuf::from("/etc/app/env")),
            exec_start: format!(
                "/usr/bin/gunicorn {} -c {}",
                app_module,
                config_path.display()
            ),
            restart_policy: RestartPolicy::OnFailure,
            security: SystemdSecurityOptions::strict(),
        }
    }
}

impl SystemdSecurityOptions {
    pub fn strict() -> Self {
        Self {
            no_new_privileges: true,
            protect_system: ProtectSystemMode::Strict,
            protect_home: true,
            private_tmp: true,
            private_devices: true,
            protect_kernel_tunables: true,
            protect_kernel_modules: true,
            protect_control_groups: true,
            restrict_address_families: vec!["AF_INET".to_string(), "AF_INET6".to_string(), "AF_UNIX".to_string()],
            restrict_namespaces: true,
            restrict_realtime: true,
            restrict_suid_sgid: true,
            memory_deny_write_execute: true,
            lock_personality: true,
        }
    }
}
```

---

## Security Checklist

### Worker Configuration

- [ ] Worker count based on CPU cores
- [ ] max_requests set (prevent memory leaks)
- [ ] Appropriate timeouts configured
- [ ] Graceful shutdown configured

### Process Security

- [ ] Run as non-root user
- [ ] Restrictive umask
- [ ] Request size limits
- [ ] Header limits

### Network Security

- [ ] Bind to Unix socket (not TCP when behind nginx)
- [ ] SSL configured if direct exposure
- [ ] Keep-alive configured

### Systemd Hardening

- [ ] NoNewPrivileges=true
- [ ] ProtectSystem=strict
- [ ] PrivateTmp=true
- [ ] RestrictAddressFamilies

## Integration Points

This skill works well with:

- `/nginx-config` - Reverse proxy configuration
- `/systemd-harden` - Service hardening
