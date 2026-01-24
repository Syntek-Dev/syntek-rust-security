//! Gunicorn + Uvicorn Secure Configuration Generator
//!
//! Generates security-hardened configurations for:
//! - Gunicorn with Uvicorn workers (ASGI)
//! - Django/FastAPI deployments
//! - Worker process security
//! - Resource limits
//! - SSL/TLS configuration

use std::collections::HashMap;

// ============================================================================
// Configuration Types
// ============================================================================

/// Worker class types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WorkerClass {
    /// Synchronous workers (traditional Django)
    Sync,
    /// Async workers using gevent
    Gevent,
    /// Async workers using eventlet
    Eventlet,
    /// Uvicorn ASGI workers (recommended for FastAPI/async Django)
    Uvicorn,
    /// Uvicorn with HTTP tools (faster)
    UvicornH11,
}

impl WorkerClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::Gevent => "gevent",
            Self::Eventlet => "eventlet",
            Self::Uvicorn => "uvicorn.workers.UvicornWorker",
            Self::UvicornH11 => "uvicorn.workers.UvicornH11Worker",
        }
    }
}

/// SSL/TLS configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Certificate file path
    pub cert_file: String,
    /// Private key file path
    pub key_file: String,
    /// CA certificates file
    pub ca_certs: Option<String>,
    /// Minimum TLS version
    pub min_version: TlsVersion,
    /// Cipher suites
    pub ciphers: String,
    /// Require client certificates
    pub client_auth: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

impl TlsVersion {
    pub fn as_ssl_context(&self) -> &'static str {
        match self {
            Self::Tls12 => "ssl.TLSVersion.TLSv1_2",
            Self::Tls13 => "ssl.TLSVersion.TLSv1_3",
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_file: "/etc/ssl/certs/server.crt".to_string(),
            key_file: "/etc/ssl/private/server.key".to_string(),
            ca_certs: None,
            min_version: TlsVersion::Tls12,
            ciphers: "ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20".to_string(),
            client_auth: false,
        }
    }
}

/// Resource limits for workers
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum requests per worker before restart
    pub max_requests: u32,
    /// Jitter for max_requests to prevent thundering herd
    pub max_requests_jitter: u32,
    /// Worker timeout in seconds
    pub timeout: u32,
    /// Graceful timeout for shutdown
    pub graceful_timeout: u32,
    /// Keep-alive timeout
    pub keepalive: u32,
    /// Limit request line size
    pub limit_request_line: u32,
    /// Limit request fields
    pub limit_request_fields: u32,
    /// Limit request field size
    pub limit_request_field_size: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_requests: 10000,
            max_requests_jitter: 1000,
            timeout: 30,
            graceful_timeout: 30,
            keepalive: 5,
            limit_request_line: 4094,
            limit_request_fields: 100,
            limit_request_field_size: 8190,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Access log file
    pub access_log: String,
    /// Error log file
    pub error_log: String,
    /// Log level
    pub log_level: LogLevel,
    /// Access log format
    pub access_log_format: String,
    /// Capture stdout
    pub capture_output: bool,
    /// Enable request logging
    pub enable_stdio_inheritance: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            access_log: "/var/log/gunicorn/access.log".to_string(),
            error_log: "/var/log/gunicorn/error.log".to_string(),
            log_level: LogLevel::Info,
            access_log_format:
                r#"%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s"#.to_string(),
            capture_output: true,
            enable_stdio_inheritance: false,
        }
    }
}

/// Security settings
#[derive(Debug, Clone)]
pub struct SecuritySettings {
    /// User to run as
    pub user: Option<String>,
    /// Group to run as
    pub group: Option<String>,
    /// Umask for created files
    pub umask: u32,
    /// Temporary directory
    pub tmp_upload_dir: Option<String>,
    /// Secure scheme headers (for reverse proxy)
    pub secure_scheme_headers: HashMap<String, String>,
    /// Forwarded allow IPs
    pub forwarded_allow_ips: Vec<String>,
    /// Proxy allow from
    pub proxy_allow_from: Vec<String>,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        let mut secure_headers = HashMap::new();
        secure_headers.insert("X-FORWARDED-PROTOCOL".to_string(), "ssl".to_string());
        secure_headers.insert("X-FORWARDED-PROTO".to_string(), "https".to_string());
        secure_headers.insert("X-FORWARDED-SSL".to_string(), "on".to_string());

        Self {
            user: Some("www-data".to_string()),
            group: Some("www-data".to_string()),
            umask: 0o027,
            tmp_upload_dir: Some("/var/tmp/gunicorn".to_string()),
            secure_scheme_headers: secure_headers,
            forwarded_allow_ips: vec!["127.0.0.1".to_string()],
            proxy_allow_from: vec!["127.0.0.1".to_string()],
        }
    }
}

// ============================================================================
// Main Configuration
// ============================================================================

/// Complete Gunicorn configuration
#[derive(Debug, Clone)]
pub struct GunicornConfig {
    /// Application module path
    pub app_module: String,
    /// Bind address(es)
    pub bind: Vec<String>,
    /// Number of workers
    pub workers: u32,
    /// Threads per worker
    pub threads: u32,
    /// Worker class
    pub worker_class: WorkerClass,
    /// TLS configuration
    pub tls: Option<TlsConfig>,
    /// Resource limits
    pub limits: ResourceLimits,
    /// Logging configuration
    pub logging: LogConfig,
    /// Security settings
    pub security: SecuritySettings,
    /// Additional environment variables
    pub environment: HashMap<String, String>,
    /// Preload application
    pub preload_app: bool,
    /// Daemon mode
    pub daemon: bool,
    /// PID file
    pub pidfile: Option<String>,
}

impl GunicornConfig {
    /// Create config for Django WSGI
    pub fn django_wsgi(app_module: &str) -> Self {
        Self {
            app_module: app_module.to_string(),
            bind: vec!["127.0.0.1:8000".to_string()],
            workers: Self::recommended_workers(),
            threads: 1,
            worker_class: WorkerClass::Sync,
            tls: None,
            limits: ResourceLimits::default(),
            logging: LogConfig::default(),
            security: SecuritySettings::default(),
            environment: HashMap::new(),
            preload_app: true,
            daemon: false,
            pidfile: Some("/var/run/gunicorn/gunicorn.pid".to_string()),
        }
    }

    /// Create config for Django ASGI with Uvicorn
    pub fn django_asgi(app_module: &str) -> Self {
        Self {
            app_module: app_module.to_string(),
            bind: vec!["127.0.0.1:8000".to_string()],
            workers: Self::recommended_workers(),
            threads: 1,
            worker_class: WorkerClass::Uvicorn,
            tls: None,
            limits: ResourceLimits::default(),
            logging: LogConfig::default(),
            security: SecuritySettings::default(),
            environment: HashMap::new(),
            preload_app: false, // Don't preload for ASGI
            daemon: false,
            pidfile: Some("/var/run/gunicorn/gunicorn.pid".to_string()),
        }
    }

    /// Create config for FastAPI
    pub fn fastapi(app_module: &str) -> Self {
        Self {
            app_module: app_module.to_string(),
            bind: vec!["127.0.0.1:8000".to_string()],
            workers: Self::recommended_workers(),
            threads: 1,
            worker_class: WorkerClass::Uvicorn,
            tls: None,
            limits: ResourceLimits {
                timeout: 60, // Longer timeout for async
                ..Default::default()
            },
            logging: LogConfig::default(),
            security: SecuritySettings::default(),
            environment: HashMap::new(),
            preload_app: false,
            daemon: false,
            pidfile: Some("/var/run/gunicorn/gunicorn.pid".to_string()),
        }
    }

    /// Calculate recommended worker count
    pub fn recommended_workers() -> u32 {
        // Formula: (2 x CPU cores) + 1
        let cpus = std::thread::available_parallelism()
            .map(|p| p.get() as u32)
            .unwrap_or(2);
        (2 * cpus) + 1
    }

    /// Enable TLS
    pub fn with_tls(mut self, config: TlsConfig) -> Self {
        self.tls = Some(config);
        self
    }

    /// Set bind addresses
    pub fn with_bind(mut self, addresses: Vec<String>) -> Self {
        self.bind = addresses;
        self
    }

    /// Set worker count
    pub fn with_workers(mut self, workers: u32) -> Self {
        self.workers = workers;
        self
    }

    /// Generate Python configuration file
    pub fn to_python_config(&self) -> String {
        let mut config = String::new();

        // Header
        config.push_str("# Gunicorn configuration file\n");
        config.push_str("# Generated by syntek-rust-security\n");
        config.push_str("# Security-hardened configuration\n\n");

        config.push_str("import multiprocessing\n");
        if self.tls.is_some() {
            config.push_str("import ssl\n");
        }
        config.push_str("\n");

        // Bind
        let binds: Vec<String> = self.bind.iter().map(|b| format!("'{}'", b)).collect();
        config.push_str(&format!("bind = [{}]\n", binds.join(", ")));

        // Workers
        config.push_str(&format!("workers = {}\n", self.workers));
        config.push_str(&format!("threads = {}\n", self.threads));
        config.push_str(&format!(
            "worker_class = '{}'\n",
            self.worker_class.as_str()
        ));

        // Limits
        config.push_str(&format!("\n# Resource Limits\n"));
        config.push_str(&format!("max_requests = {}\n", self.limits.max_requests));
        config.push_str(&format!(
            "max_requests_jitter = {}\n",
            self.limits.max_requests_jitter
        ));
        config.push_str(&format!("timeout = {}\n", self.limits.timeout));
        config.push_str(&format!(
            "graceful_timeout = {}\n",
            self.limits.graceful_timeout
        ));
        config.push_str(&format!("keepalive = {}\n", self.limits.keepalive));
        config.push_str(&format!(
            "limit_request_line = {}\n",
            self.limits.limit_request_line
        ));
        config.push_str(&format!(
            "limit_request_fields = {}\n",
            self.limits.limit_request_fields
        ));
        config.push_str(&format!(
            "limit_request_field_size = {}\n",
            self.limits.limit_request_field_size
        ));

        // Logging
        config.push_str(&format!("\n# Logging\n"));
        config.push_str(&format!("accesslog = '{}'\n", self.logging.access_log));
        config.push_str(&format!("errorlog = '{}'\n", self.logging.error_log));
        config.push_str(&format!(
            "loglevel = '{}'\n",
            self.logging.log_level.as_str()
        ));
        config.push_str(&format!(
            "access_log_format = '{}'\n",
            self.logging.access_log_format
        ));
        config.push_str(&format!(
            "capture_output = {}\n",
            if self.logging.capture_output {
                "True"
            } else {
                "False"
            }
        ));

        // Security
        config.push_str(&format!("\n# Security\n"));
        if let Some(ref user) = self.security.user {
            config.push_str(&format!("user = '{}'\n", user));
        }
        if let Some(ref group) = self.security.group {
            config.push_str(&format!("group = '{}'\n", group));
        }
        config.push_str(&format!("umask = 0o{:03o}\n", self.security.umask));

        if let Some(ref tmp_dir) = self.security.tmp_upload_dir {
            config.push_str(&format!("tmp_upload_dir = '{}'\n", tmp_dir));
        }

        // Forwarded headers
        let forwarded_ips: Vec<String> = self
            .security
            .forwarded_allow_ips
            .iter()
            .map(|ip| format!("'{}'", ip))
            .collect();
        config.push_str(&format!(
            "forwarded_allow_ips = [{}]\n",
            forwarded_ips.join(", ")
        ));

        // Secure scheme headers
        config.push_str("\nsecure_scheme_headers = {\n");
        for (key, value) in &self.security.secure_scheme_headers {
            config.push_str(&format!("    '{}': '{}',\n", key, value));
        }
        config.push_str("}\n");

        // TLS
        if let Some(ref tls) = self.tls {
            config.push_str(&format!("\n# TLS Configuration\n"));
            config.push_str(&format!("certfile = '{}'\n", tls.cert_file));
            config.push_str(&format!("keyfile = '{}'\n", tls.key_file));
            if let Some(ref ca) = tls.ca_certs {
                config.push_str(&format!("ca_certs = '{}'\n", ca));
            }
            config.push_str(&format!(
                "ssl_version = {}\n",
                tls.min_version.as_ssl_context()
            ));
            config.push_str(&format!("ciphers = '{}'\n", tls.ciphers));
            if tls.client_auth {
                config.push_str("cert_reqs = ssl.CERT_REQUIRED\n");
            }
        }

        // Other settings
        config.push_str(&format!("\n# Other Settings\n"));
        config.push_str(&format!(
            "preload_app = {}\n",
            if self.preload_app { "True" } else { "False" }
        ));
        config.push_str(&format!(
            "daemon = {}\n",
            if self.daemon { "True" } else { "False" }
        ));
        if let Some(ref pidfile) = self.pidfile {
            config.push_str(&format!("pidfile = '{}'\n", pidfile));
        }

        // Environment
        if !self.environment.is_empty() {
            config.push_str("\n# Environment Variables\n");
            config.push_str("raw_env = [\n");
            for (key, value) in &self.environment {
                config.push_str(&format!("    '{}={}',\n", key, value));
            }
            config.push_str("]\n");
        }

        // Hooks for security logging
        config.push_str(
            r#"
# Security Hooks
def on_starting(server):
    """Log server startup."""
    server.log.info("Gunicorn starting with security configuration")

def worker_int(worker):
    """Log worker interruption."""
    worker.log.info(f"Worker {worker.pid} received INT signal")

def worker_abort(worker):
    """Log worker abort."""
    worker.log.warning(f"Worker {worker.pid} aborted")

def pre_request(worker, req):
    """Log incoming request headers for security audit."""
    worker.log.debug(f"Request: {req.method} {req.path}")
    # Add custom security checks here
    pass

def post_request(worker, req, environ, resp):
    """Log response for security audit."""
    worker.log.debug(f"Response: {resp.status}")
"#,
        );

        config
    }

    /// Generate systemd service file
    pub fn to_systemd_service(&self, service_name: &str) -> String {
        let user = self.security.user.as_deref().unwrap_or("www-data");
        let group = self.security.group.as_deref().unwrap_or("www-data");
        let pidfile = self
            .pidfile
            .as_deref()
            .unwrap_or("/var/run/gunicorn/gunicorn.pid");

        format!(
            r#"[Unit]
Description={service_name} Gunicorn Service
After=network.target

[Service]
Type=notify
User={user}
Group={group}
RuntimeDirectory=gunicorn
WorkingDirectory=/var/www/{service_name}
ExecStart=/usr/bin/gunicorn --config /etc/gunicorn/{service_name}.py {app_module}
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID
PIDFile={pidfile}
Restart=on-failure
RestartSec=5s

# Security Hardening
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/gunicorn /var/run/gunicorn /var/tmp/gunicorn
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Resource Limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
"#,
            service_name = service_name,
            user = user,
            group = group,
            app_module = self.app_module,
            pidfile = pidfile,
        )
    }
}

// ============================================================================
// Uvicorn Standalone Config
// ============================================================================

/// Uvicorn configuration for standalone deployment
#[derive(Debug, Clone)]
pub struct UvicornConfig {
    pub app: String,
    pub host: String,
    pub port: u16,
    pub workers: u32,
    pub log_level: LogLevel,
    pub access_log: bool,
    pub use_colors: bool,
    pub proxy_headers: bool,
    pub forwarded_allow_ips: Vec<String>,
    pub ssl_keyfile: Option<String>,
    pub ssl_certfile: Option<String>,
    pub ssl_ca_certs: Option<String>,
    pub limit_concurrency: Option<u32>,
    pub limit_max_requests: Option<u32>,
    pub timeout_keep_alive: u32,
    pub timeout_notify: u32,
}

impl UvicornConfig {
    pub fn new(app: &str) -> Self {
        Self {
            app: app.to_string(),
            host: "127.0.0.1".to_string(),
            port: 8000,
            workers: GunicornConfig::recommended_workers(),
            log_level: LogLevel::Info,
            access_log: true,
            use_colors: false,
            proxy_headers: true,
            forwarded_allow_ips: vec!["127.0.0.1".to_string()],
            ssl_keyfile: None,
            ssl_certfile: None,
            ssl_ca_certs: None,
            limit_concurrency: Some(1000),
            limit_max_requests: Some(10000),
            timeout_keep_alive: 5,
            timeout_notify: 30,
        }
    }

    /// Generate command line arguments
    pub fn to_args(&self) -> Vec<String> {
        let mut args = vec![
            format!("--host={}", self.host),
            format!("--port={}", self.port),
            format!("--workers={}", self.workers),
            format!("--log-level={}", self.log_level.as_str()),
        ];

        if !self.access_log {
            args.push("--no-access-log".to_string());
        }

        if !self.use_colors {
            args.push("--no-use-colors".to_string());
        }

        if self.proxy_headers {
            args.push("--proxy-headers".to_string());
            let ips = self.forwarded_allow_ips.join(",");
            args.push(format!("--forwarded-allow-ips={}", ips));
        }

        if let Some(ref keyfile) = self.ssl_keyfile {
            args.push(format!("--ssl-keyfile={}", keyfile));
        }
        if let Some(ref certfile) = self.ssl_certfile {
            args.push(format!("--ssl-certfile={}", certfile));
        }
        if let Some(ref ca_certs) = self.ssl_ca_certs {
            args.push(format!("--ssl-ca-certs={}", ca_certs));
        }

        if let Some(concurrency) = self.limit_concurrency {
            args.push(format!("--limit-concurrency={}", concurrency));
        }
        if let Some(max_requests) = self.limit_max_requests {
            args.push(format!("--limit-max-requests={}", max_requests));
        }

        args.push(format!("--timeout-keep-alive={}", self.timeout_keep_alive));
        args.push(format!("--timeout-notify={}", self.timeout_notify));

        args.push(self.app.clone());
        args
    }
}

// ============================================================================
// Main and Tests
// ============================================================================

fn main() {
    println!("Gunicorn + Uvicorn Secure Configuration Generator\n");

    // Django WSGI configuration
    println!("=== Django WSGI Configuration ===\n");
    let django_config = GunicornConfig::django_wsgi("myproject.wsgi:application").with_workers(4);

    println!("Python config file:\n");
    println!("{}", django_config.to_python_config());

    // FastAPI configuration with TLS
    println!("\n=== FastAPI with TLS Configuration ===\n");
    let fastapi_config = GunicornConfig::fastapi("main:app")
        .with_tls(TlsConfig {
            cert_file: "/etc/ssl/certs/api.crt".to_string(),
            key_file: "/etc/ssl/private/api.key".to_string(),
            min_version: TlsVersion::Tls13,
            ..Default::default()
        })
        .with_bind(vec!["0.0.0.0:443".to_string()]);

    println!("Python config file:\n");
    println!("{}", fastapi_config.to_python_config());

    // Systemd service
    println!("\n=== Systemd Service File ===\n");
    println!("{}", fastapi_config.to_systemd_service("myapi"));

    // Uvicorn standalone
    println!("\n=== Uvicorn Standalone Configuration ===\n");
    let uvicorn_config = UvicornConfig::new("main:app");
    println!("Command: uvicorn {}", uvicorn_config.to_args().join(" "));

    // Print recommendations
    println!("\n=== Security Recommendations ===");
    println!("1. Always run behind a reverse proxy (Nginx)");
    println!("2. Use Unix sockets instead of TCP when possible");
    println!("3. Enable TLS 1.3 for best security");
    println!("4. Set appropriate resource limits");
    println!("5. Run as non-root user (www-data)");
    println!("6. Use systemd hardening options");
    println!("7. Enable access logging for audit trail");
    println!("8. Set max_requests to prevent memory leaks");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_django_wsgi_config() {
        let config = GunicornConfig::django_wsgi("myproject.wsgi:application");
        assert_eq!(config.worker_class, WorkerClass::Sync);
        assert!(config.preload_app);
    }

    #[test]
    fn test_fastapi_config() {
        let config = GunicornConfig::fastapi("main:app");
        assert_eq!(config.worker_class, WorkerClass::Uvicorn);
        assert!(!config.preload_app);
    }

    #[test]
    fn test_recommended_workers() {
        let workers = GunicornConfig::recommended_workers();
        assert!(workers >= 3); // At least (2 * 1) + 1
    }

    #[test]
    fn test_tls_config() {
        let config = GunicornConfig::django_wsgi("app:application").with_tls(TlsConfig::default());
        assert!(config.tls.is_some());

        let python = config.to_python_config();
        assert!(python.contains("certfile"));
        assert!(python.contains("keyfile"));
    }

    #[test]
    fn test_python_config_generation() {
        let config = GunicornConfig::django_wsgi("app:application");
        let python = config.to_python_config();

        assert!(python.contains("bind"));
        assert!(python.contains("workers"));
        assert!(python.contains("timeout"));
        assert!(python.contains("accesslog"));
    }

    #[test]
    fn test_systemd_service_generation() {
        let config = GunicornConfig::django_wsgi("app:application");
        let service = config.to_systemd_service("myapp");

        assert!(service.contains("[Unit]"));
        assert!(service.contains("[Service]"));
        assert!(service.contains("[Install]"));
        assert!(service.contains("NoNewPrivileges=yes"));
        assert!(service.contains("PrivateTmp=yes"));
    }

    #[test]
    fn test_uvicorn_args() {
        let config = UvicornConfig::new("main:app");
        let args = config.to_args();

        assert!(args.iter().any(|a| a.starts_with("--host=")));
        assert!(args.iter().any(|a| a.starts_with("--port=")));
        assert!(args.iter().any(|a| a.starts_with("--workers=")));
        assert!(args.contains(&"main:app".to_string()));
    }

    #[test]
    fn test_resource_limits() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_requests, 10000);
        assert_eq!(limits.timeout, 30);
    }

    #[test]
    fn test_security_settings() {
        let security = SecuritySettings::default();
        assert_eq!(security.user, Some("www-data".to_string()));
        assert_eq!(security.umask, 0o027);
        assert!(!security.forwarded_allow_ips.is_empty());
    }

    #[test]
    fn test_worker_class_str() {
        assert_eq!(WorkerClass::Sync.as_str(), "sync");
        assert_eq!(
            WorkerClass::Uvicorn.as_str(),
            "uvicorn.workers.UvicornWorker"
        );
    }
}
