//! Gunicorn + Uvicorn Security Configuration Generator
//!
//! Generates secure configuration for Django/FastAPI deployments with
//! proper worker management, SSL/TLS settings, and security hardening.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Worker class types for Gunicorn
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerClass {
    Sync,
    Gevent,
    Eventlet,
    Tornado,
    Gthread,
    Uvicorn, // For ASGI applications
}

impl WorkerClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            WorkerClass::Sync => "sync",
            WorkerClass::Gevent => "gevent",
            WorkerClass::Eventlet => "eventlet",
            WorkerClass::Tornado => "tornado",
            WorkerClass::Gthread => "gthread",
            WorkerClass::Uvicorn => "uvicorn.workers.UvicornWorker",
        }
    }
}

/// SSL/TLS configuration for Gunicorn
#[derive(Debug, Clone)]
pub struct GunicornSslConfig {
    pub keyfile: PathBuf,
    pub certfile: PathBuf,
    pub ca_certs: Option<PathBuf>,
    pub ssl_version: String,
    pub cert_reqs: u8,
    pub ciphers: Option<String>,
    pub do_handshake_on_connect: bool,
    pub suppress_ragged_eofs: bool,
}

impl Default for GunicornSslConfig {
    fn default() -> Self {
        Self {
            keyfile: PathBuf::from("/etc/ssl/private/server.key"),
            certfile: PathBuf::from("/etc/ssl/certs/server.crt"),
            ca_certs: None,
            ssl_version: "TLSv1_2".into(),
            cert_reqs: 0, // ssl.CERT_NONE
            ciphers: Some("ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20".into()),
            do_handshake_on_connect: true,
            suppress_ragged_eofs: true,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    pub errorlog: PathBuf,
    pub accesslog: PathBuf,
    pub loglevel: String,
    pub access_log_format: String,
    pub capture_output: bool,
    pub enable_stdio_inheritance: bool,
    pub syslog: bool,
    pub syslog_addr: Option<String>,
    pub syslog_facility: Option<String>,
    pub syslog_prefix: Option<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            errorlog: PathBuf::from("/var/log/gunicorn/error.log"),
            accesslog: PathBuf::from("/var/log/gunicorn/access.log"),
            loglevel: "info".into(),
            access_log_format:
                "%(h)s %(l)s %(u)s %(t)s \"%(r)s\" %(s)s %(b)s \"%(f)s\" \"%(a)s\" %(D)s".into(),
            capture_output: true,
            enable_stdio_inheritance: false,
            syslog: false,
            syslog_addr: None,
            syslog_facility: None,
            syslog_prefix: None,
        }
    }
}

/// Security-related configuration options
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub limit_request_line: u32,
    pub limit_request_fields: u32,
    pub limit_request_field_size: u32,
    pub forwarded_allow_ips: Vec<String>,
    pub proxy_protocol: bool,
    pub proxy_allow_ips: Vec<String>,
    pub strip_header_spaces: bool,
    pub permit_unconventional_http_method: bool,
    pub permit_unconventional_http_version: bool,
    pub casefold_http_method: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            limit_request_line: 4094,
            limit_request_fields: 100,
            limit_request_field_size: 8190,
            forwarded_allow_ips: vec!["127.0.0.1".into()],
            proxy_protocol: false,
            proxy_allow_ips: vec!["127.0.0.1".into()],
            strip_header_spaces: false,
            permit_unconventional_http_method: false,
            permit_unconventional_http_version: false,
            casefold_http_method: false,
        }
    }
}

/// Process management configuration
#[derive(Debug, Clone)]
pub struct ProcessConfig {
    pub daemon: bool,
    pub pidfile: Option<PathBuf>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub umask: u32,
    pub initgroups: bool,
    pub tmp_upload_dir: Option<PathBuf>,
    pub secure_scheme_headers: HashMap<String, String>,
    pub chdir: Option<PathBuf>,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        let mut secure_headers = HashMap::new();
        secure_headers.insert("X-FORWARDED-PROTOCOL".into(), "ssl".into());
        secure_headers.insert("X-FORWARDED-PROTO".into(), "https".into());
        secure_headers.insert("X-FORWARDED-SSL".into(), "on".into());

        Self {
            daemon: false,
            pidfile: Some(PathBuf::from("/var/run/gunicorn.pid")),
            user: Some("www-data".into()),
            group: Some("www-data".into()),
            umask: 0o027,
            initgroups: false,
            tmp_upload_dir: None,
            secure_scheme_headers: secure_headers,
            chdir: None,
        }
    }
}

/// Main Gunicorn configuration generator
#[derive(Debug, Clone)]
pub struct GunicornConfigGenerator {
    pub bind: Vec<String>,
    pub workers: u32,
    pub worker_class: WorkerClass,
    pub threads: u32,
    pub worker_connections: u32,
    pub max_requests: u32,
    pub max_requests_jitter: u32,
    pub timeout: u32,
    pub graceful_timeout: u32,
    pub keepalive: u32,
    pub backlog: u32,
    pub preload_app: bool,
    pub reload: bool,
    pub reload_engine: String,
    pub ssl_config: Option<GunicornSslConfig>,
    pub logging: LoggingConfig,
    pub security: SecurityConfig,
    pub process: ProcessConfig,
    pub raw_env: Vec<String>,
    pub wsgi_app: String,
}

impl Default for GunicornConfigGenerator {
    fn default() -> Self {
        Self {
            bind: vec!["127.0.0.1:8000".into()],
            workers: 4,
            worker_class: WorkerClass::Sync,
            threads: 1,
            worker_connections: 1000,
            max_requests: 10000,
            max_requests_jitter: 1000,
            timeout: 30,
            graceful_timeout: 30,
            keepalive: 5,
            backlog: 2048,
            preload_app: true,
            reload: false,
            reload_engine: "auto".into(),
            ssl_config: None,
            logging: LoggingConfig::default(),
            security: SecurityConfig::default(),
            process: ProcessConfig::default(),
            raw_env: vec![],
            wsgi_app: "myapp.wsgi:application".into(),
        }
    }
}

impl GunicornConfigGenerator {
    pub fn new(wsgi_app: &str) -> Self {
        Self {
            wsgi_app: wsgi_app.into(),
            ..Default::default()
        }
    }

    /// Create configuration for Django application
    pub fn for_django(project_name: &str) -> Self {
        Self {
            wsgi_app: format!("{}.wsgi:application", project_name),
            workers: num_cpus_estimate() * 2 + 1,
            worker_class: WorkerClass::Sync,
            threads: 1,
            preload_app: true,
            ..Default::default()
        }
    }

    /// Create configuration for FastAPI/Starlette application
    pub fn for_fastapi(app_module: &str) -> Self {
        Self {
            wsgi_app: format!("{}:app", app_module),
            workers: num_cpus_estimate(),
            worker_class: WorkerClass::Uvicorn,
            threads: 1,
            preload_app: false, // ASGI apps often don't support preload
            ..Default::default()
        }
    }

    pub fn with_bind(mut self, address: &str) -> Self {
        self.bind = vec![address.into()];
        self
    }

    pub fn with_unix_socket(mut self, path: &str) -> Self {
        self.bind = vec![format!("unix:{}", path)];
        self
    }

    pub fn with_workers(mut self, workers: u32) -> Self {
        self.workers = workers;
        self
    }

    pub fn with_ssl(mut self, config: GunicornSslConfig) -> Self {
        self.ssl_config = Some(config);
        self
    }

    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.raw_env.push(format!("{}={}", key, value));
        self
    }

    /// Generate Python configuration file content
    pub fn generate_python(&self) -> String {
        let mut config = String::new();

        config.push_str("# Gunicorn Configuration File\n");
        config.push_str("# Generated by Syntek Rust Security Plugin\n");
        config.push_str("# Security-hardened configuration for production\n\n");

        config.push_str("import multiprocessing\n");
        config.push_str("import os\n\n");

        // Server socket
        config.push_str("# Server Socket\n");
        config.push_str(&format!("bind = {:?}\n", self.bind));
        config.push_str(&format!("backlog = {}\n\n", self.backlog));

        // Worker processes
        config.push_str("# Worker Processes\n");
        config.push_str(&format!("workers = {}\n", self.workers));
        config.push_str(&format!(
            "worker_class = '{}'\n",
            self.worker_class.as_str()
        ));
        config.push_str(&format!("threads = {}\n", self.threads));
        config.push_str(&format!(
            "worker_connections = {}\n",
            self.worker_connections
        ));
        config.push_str(&format!("max_requests = {}\n", self.max_requests));
        config.push_str(&format!(
            "max_requests_jitter = {}\n",
            self.max_requests_jitter
        ));
        config.push_str(&format!("timeout = {}\n", self.timeout));
        config.push_str(&format!("graceful_timeout = {}\n", self.graceful_timeout));
        config.push_str(&format!("keepalive = {}\n\n", self.keepalive));

        // Application preloading
        config.push_str("# Application\n");
        config.push_str(&format!(
            "preload_app = {}\n",
            if self.preload_app { "True" } else { "False" }
        ));
        config.push_str(&format!(
            "reload = {}\n\n",
            if self.reload { "True" } else { "False" }
        ));

        // SSL/TLS configuration
        if let Some(ssl) = &self.ssl_config {
            config.push_str("# SSL/TLS Configuration\n");
            config.push_str(&format!("keyfile = '{}'\n", ssl.keyfile.display()));
            config.push_str(&format!("certfile = '{}'\n", ssl.certfile.display()));
            if let Some(ca) = &ssl.ca_certs {
                config.push_str(&format!("ca_certs = '{}'\n", ca.display()));
            }
            config.push_str(&format!("ssl_version = '{}'\n", ssl.ssl_version));
            config.push_str(&format!("cert_reqs = {}\n", ssl.cert_reqs));
            if let Some(ciphers) = &ssl.ciphers {
                config.push_str(&format!("ciphers = '{}'\n", ciphers));
            }
            config.push_str(&format!(
                "do_handshake_on_connect = {}\n",
                if ssl.do_handshake_on_connect {
                    "True"
                } else {
                    "False"
                }
            ));
            config.push_str("\n");
        }

        // Logging
        config.push_str("# Logging\n");
        config.push_str(&format!(
            "errorlog = '{}'\n",
            self.logging.errorlog.display()
        ));
        config.push_str(&format!(
            "accesslog = '{}'\n",
            self.logging.accesslog.display()
        ));
        config.push_str(&format!("loglevel = '{}'\n", self.logging.loglevel));
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
        config.push_str("\n");

        // Security
        config.push_str("# Security Settings\n");
        config.push_str(&format!(
            "limit_request_line = {}\n",
            self.security.limit_request_line
        ));
        config.push_str(&format!(
            "limit_request_fields = {}\n",
            self.security.limit_request_fields
        ));
        config.push_str(&format!(
            "limit_request_field_size = {}\n",
            self.security.limit_request_field_size
        ));
        config.push_str(&format!(
            "forwarded_allow_ips = {:?}\n",
            self.security.forwarded_allow_ips.join(",")
        ));
        config.push_str(&format!(
            "strip_header_spaces = {}\n",
            if self.security.strip_header_spaces {
                "True"
            } else {
                "False"
            }
        ));
        config.push_str("\n");

        // Process management
        config.push_str("# Process Management\n");
        config.push_str(&format!(
            "daemon = {}\n",
            if self.process.daemon { "True" } else { "False" }
        ));
        if let Some(pidfile) = &self.process.pidfile {
            config.push_str(&format!("pidfile = '{}'\n", pidfile.display()));
        }
        if let Some(user) = &self.process.user {
            config.push_str(&format!("user = '{}'\n", user));
        }
        if let Some(group) = &self.process.group {
            config.push_str(&format!("group = '{}'\n", group));
        }
        config.push_str(&format!("umask = 0o{:03o}\n", self.process.umask));
        config.push_str("\n");

        // Secure scheme headers
        if !self.process.secure_scheme_headers.is_empty() {
            config.push_str("# Secure Scheme Headers (for proxy setups)\n");
            config.push_str("secure_scheme_headers = {\n");
            for (key, value) in &self.process.secure_scheme_headers {
                config.push_str(&format!("    '{}': '{}',\n", key, value));
            }
            config.push_str("}\n\n");
        }

        // Environment variables
        if !self.raw_env.is_empty() {
            config.push_str("# Environment Variables\n");
            config.push_str(&format!("raw_env = {:?}\n\n", self.raw_env));
        }

        // Hooks
        config.push_str("# Server Hooks\n");
        config.push_str(
            r#"
def on_starting(server):
    """Called just before the master process is initialized."""
    pass

def on_reload(server):
    """Called to recycle workers during a reload via SIGHUP."""
    pass

def when_ready(server):
    """Called just after the server is started."""
    pass

def pre_fork(server, worker):
    """Called just before a worker is forked."""
    pass

def post_fork(server, worker):
    """Called just after a worker has been forked."""
    pass

def post_worker_init(worker):
    """Called just after a worker has initialized the application."""
    pass

def worker_int(worker):
    """Called when a worker receives SIGINT or SIGQUIT."""
    pass

def worker_abort(worker):
    """Called when a worker receives SIGABRT."""
    pass

def pre_exec(server):
    """Called just before a new master process is forked."""
    pass

def pre_request(worker, req):
    """Called just before a worker processes the request."""
    worker.log.debug("%s %s", req.method, req.path)

def post_request(worker, req, environ, resp):
    """Called after a worker processes the request."""
    pass

def child_exit(server, worker):
    """Called in the master process after a worker exits."""
    pass

def worker_exit(server, worker):
    """Called in the worker process just after exiting."""
    pass

def nworkers_changed(server, new_value, old_value):
    """Called when the number of workers changes."""
    pass

def on_exit(server):
    """Called just before exiting Gunicorn."""
    pass
"#,
        );

        config
    }

    /// Generate systemd service file
    pub fn generate_systemd_service(&self, service_name: &str, working_dir: &str) -> String {
        let mut service = String::new();

        service.push_str(&format!("# Systemd service file for {}\n", service_name));
        service.push_str("# Generated by Syntek Rust Security Plugin\n\n");

        service.push_str("[Unit]\n");
        service.push_str(&format!(
            "Description=Gunicorn daemon for {}\n",
            service_name
        ));
        service.push_str("Requires=network.target\n");
        service.push_str("After=network.target\n\n");

        service.push_str("[Service]\n");
        service.push_str("Type=notify\n");
        service.push_str("RuntimeDirectory=gunicorn\n");
        service.push_str(&format!("WorkingDirectory={}\n", working_dir));

        if let Some(user) = &self.process.user {
            service.push_str(&format!("User={}\n", user));
        }
        if let Some(group) = &self.process.group {
            service.push_str(&format!("Group={}\n", group));
        }

        // Build ExecStart command
        let bind_arg = self
            .bind
            .iter()
            .map(|b| format!("-b {}", b))
            .collect::<Vec<_>>()
            .join(" ");

        service.push_str(&format!(
            "ExecStart=/usr/local/bin/gunicorn {} -w {} -k {} --timeout {} {}\n",
            bind_arg,
            self.workers,
            self.worker_class.as_str(),
            self.timeout,
            self.wsgi_app
        ));

        service.push_str("ExecReload=/bin/kill -s HUP $MAINPID\n");
        service.push_str("ExecStop=/bin/kill -s TERM $MAINPID\n");
        service.push_str("KillMode=mixed\n");
        service.push_str("TimeoutStopSec=5\n");
        service.push_str("PrivateTmp=true\n");
        service.push_str("Restart=on-failure\n");
        service.push_str("RestartSec=10\n\n");

        // Security hardening
        service.push_str("# Security Hardening\n");
        service.push_str("NoNewPrivileges=true\n");
        service.push_str("ProtectSystem=strict\n");
        service.push_str("ProtectHome=true\n");
        service.push_str("ProtectKernelTunables=true\n");
        service.push_str("ProtectKernelModules=true\n");
        service.push_str("ProtectControlGroups=true\n");
        service.push_str("RestrictSUIDSGID=true\n");
        service.push_str("RestrictNamespaces=true\n");
        service.push_str(&format!("ReadWritePaths={}\n", working_dir));
        service.push_str(&format!(
            "ReadWritePaths={}\n",
            self.logging.errorlog.parent().unwrap().display()
        ));

        service.push_str("\n[Install]\n");
        service.push_str("WantedBy=multi-user.target\n");

        service
    }

    /// Write Python config to file
    pub fn write_python_config<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let config = self.generate_python();
        let mut file = fs::File::create(path)?;
        file.write_all(config.as_bytes())?;
        Ok(())
    }

    /// Write systemd service file
    pub fn write_systemd_service<P: AsRef<Path>>(
        &self,
        path: P,
        service_name: &str,
        working_dir: &str,
    ) -> io::Result<()> {
        let service = self.generate_systemd_service(service_name, working_dir);
        let mut file = fs::File::create(path)?;
        file.write_all(service.as_bytes())?;
        Ok(())
    }
}

/// Uvicorn-specific configuration for ASGI apps
#[derive(Debug, Clone)]
pub struct UvicornConfig {
    pub host: String,
    pub port: u16,
    pub uds: Option<PathBuf>,
    pub workers: u32,
    pub loop_type: String,
    pub http: String,
    pub ws: String,
    pub interface: String,
    pub reload: bool,
    pub reload_dirs: Vec<PathBuf>,
    pub env_file: Option<PathBuf>,
    pub log_config: Option<PathBuf>,
    pub log_level: String,
    pub access_log: bool,
    pub use_colors: bool,
    pub proxy_headers: bool,
    pub forwarded_allow_ips: Vec<String>,
    pub root_path: String,
    pub limit_concurrency: Option<u32>,
    pub limit_max_requests: Option<u32>,
    pub backlog: u32,
    pub timeout_keep_alive: u32,
    pub timeout_notify: u32,
    pub ssl_keyfile: Option<PathBuf>,
    pub ssl_certfile: Option<PathBuf>,
    pub ssl_keyfile_password: Option<String>,
    pub ssl_version: Option<u32>,
    pub ssl_cert_reqs: Option<u32>,
    pub ssl_ca_certs: Option<PathBuf>,
    pub ssl_ciphers: String,
    pub headers: Vec<(String, String)>,
    pub app: String,
}

impl Default for UvicornConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 8000,
            uds: None,
            workers: 1,
            loop_type: "auto".into(),
            http: "auto".into(),
            ws: "auto".into(),
            interface: "auto".into(),
            reload: false,
            reload_dirs: vec![],
            env_file: None,
            log_config: None,
            log_level: "info".into(),
            access_log: true,
            use_colors: true,
            proxy_headers: true,
            forwarded_allow_ips: vec!["127.0.0.1".into()],
            root_path: String::new(),
            limit_concurrency: None,
            limit_max_requests: Some(10000),
            backlog: 2048,
            timeout_keep_alive: 5,
            timeout_notify: 30,
            ssl_keyfile: None,
            ssl_certfile: None,
            ssl_keyfile_password: None,
            ssl_version: None,
            ssl_cert_reqs: None,
            ssl_ca_certs: None,
            ssl_ciphers: "TLSv1".into(),
            headers: vec![],
            app: "main:app".into(),
        }
    }
}

impl UvicornConfig {
    pub fn new(app: &str) -> Self {
        Self {
            app: app.into(),
            ..Default::default()
        }
    }

    /// Generate command-line arguments for uvicorn
    pub fn generate_cli_args(&self) -> Vec<String> {
        let mut args = vec![];

        if let Some(uds) = &self.uds {
            args.push(format!("--uds={}", uds.display()));
        } else {
            args.push(format!("--host={}", self.host));
            args.push(format!("--port={}", self.port));
        }

        if self.workers > 1 {
            args.push(format!("--workers={}", self.workers));
        }

        args.push(format!("--loop={}", self.loop_type));
        args.push(format!("--http={}", self.http));
        args.push(format!("--ws={}", self.ws));
        args.push(format!("--interface={}", self.interface));

        if self.reload {
            args.push("--reload".into());
            for dir in &self.reload_dirs {
                args.push(format!("--reload-dir={}", dir.display()));
            }
        }

        args.push(format!("--log-level={}", self.log_level));

        if !self.access_log {
            args.push("--no-access-log".into());
        }

        if self.proxy_headers {
            args.push("--proxy-headers".into());
            args.push(format!(
                "--forwarded-allow-ips={}",
                self.forwarded_allow_ips.join(",")
            ));
        }

        if let Some(limit) = self.limit_concurrency {
            args.push(format!("--limit-concurrency={}", limit));
        }

        if let Some(limit) = self.limit_max_requests {
            args.push(format!("--limit-max-requests={}", limit));
        }

        args.push(format!("--backlog={}", self.backlog));
        args.push(format!("--timeout-keep-alive={}", self.timeout_keep_alive));

        // SSL options
        if let Some(keyfile) = &self.ssl_keyfile {
            args.push(format!("--ssl-keyfile={}", keyfile.display()));
        }
        if let Some(certfile) = &self.ssl_certfile {
            args.push(format!("--ssl-certfile={}", certfile.display()));
        }

        for (name, value) in &self.headers {
            args.push(format!("--header={}:{}", name, value));
        }

        args.push(self.app.clone());

        args
    }

    /// Generate configuration as dictionary (for programmatic use)
    pub fn as_dict(&self) -> HashMap<String, String> {
        let mut config = HashMap::new();

        config.insert("host".into(), self.host.clone());
        config.insert("port".into(), self.port.to_string());
        config.insert("workers".into(), self.workers.to_string());
        config.insert("loop".into(), self.loop_type.clone());
        config.insert("log_level".into(), self.log_level.clone());
        config.insert("backlog".into(), self.backlog.to_string());

        config
    }
}

/// Estimate number of CPUs for worker calculation
fn num_cpus_estimate() -> u32 {
    std::thread::available_parallelism()
        .map(|p| p.get() as u32)
        .unwrap_or(4)
}

fn main() {
    println!("Gunicorn/Uvicorn Security Configuration Generator\n");

    // Example 1: Django configuration
    println!("=== Django Configuration ===\n");
    let django_config = GunicornConfigGenerator::for_django("myproject")
        .with_bind("unix:/var/run/gunicorn/myproject.sock")
        .with_env("DJANGO_SETTINGS_MODULE", "myproject.settings.production");

    println!("Python config preview (first 50 lines):");
    let python_config = django_config.generate_python();
    for (i, line) in python_config.lines().enumerate() {
        if i >= 50 {
            break;
        }
        println!("{}", line);
    }
    println!("...\n");

    // Example 2: FastAPI configuration
    println!("=== FastAPI Configuration ===\n");
    let fastapi_config = GunicornConfigGenerator::for_fastapi("app.main")
        .with_workers(4)
        .with_ssl(GunicornSslConfig::default());

    println!("Worker class: {}", fastapi_config.worker_class.as_str());
    println!("Workers: {}", fastapi_config.workers);
    println!("SSL enabled: {}\n", fastapi_config.ssl_config.is_some());

    // Example 3: Systemd service
    println!("=== Systemd Service ===\n");
    let service = django_config.generate_systemd_service("myproject", "/var/www/myproject");
    println!("{}", service);

    // Example 4: Uvicorn standalone configuration
    println!("=== Uvicorn Configuration ===\n");
    let uvicorn = UvicornConfig::new("app.main:app");
    let cli_args = uvicorn.generate_cli_args();
    println!("CLI command: uvicorn {}", cli_args.join(" "));

    // Configuration summary
    println!("\n=== Configuration Summary ===");
    println!("Django workers: {}", django_config.workers);
    println!("FastAPI workers: {}", fastapi_config.workers);
    println!("Default timeout: {}s", django_config.timeout);
    println!("Max requests per worker: {}", django_config.max_requests);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_class_as_str() {
        assert_eq!(WorkerClass::Sync.as_str(), "sync");
        assert_eq!(
            WorkerClass::Uvicorn.as_str(),
            "uvicorn.workers.UvicornWorker"
        );
    }

    #[test]
    fn test_django_config() {
        let config = GunicornConfigGenerator::for_django("myapp");
        assert_eq!(config.wsgi_app, "myapp.wsgi:application");
        assert_eq!(config.worker_class, WorkerClass::Sync);
        assert!(config.preload_app);
    }

    #[test]
    fn test_fastapi_config() {
        let config = GunicornConfigGenerator::for_fastapi("main");
        assert_eq!(config.wsgi_app, "main:app");
        assert_eq!(config.worker_class, WorkerClass::Uvicorn);
        assert!(!config.preload_app);
    }

    #[test]
    fn test_with_bind() {
        let config = GunicornConfigGenerator::new("app:app").with_bind("0.0.0.0:8080");
        assert_eq!(config.bind, vec!["0.0.0.0:8080"]);
    }

    #[test]
    fn test_unix_socket_bind() {
        let config = GunicornConfigGenerator::new("app:app").with_unix_socket("/tmp/gunicorn.sock");
        assert_eq!(config.bind, vec!["unix:/tmp/gunicorn.sock"]);
    }

    #[test]
    fn test_generate_python() {
        let config = GunicornConfigGenerator::default();
        let output = config.generate_python();
        assert!(output.contains("workers ="));
        assert!(output.contains("timeout ="));
        assert!(output.contains("limit_request_line ="));
    }

    #[test]
    fn test_ssl_config() {
        let config = GunicornConfigGenerator::new("app:app").with_ssl(GunicornSslConfig::default());

        let output = config.generate_python();
        assert!(output.contains("keyfile ="));
        assert!(output.contains("certfile ="));
    }

    #[test]
    fn test_systemd_service() {
        let config = GunicornConfigGenerator::for_django("myapp");
        let service = config.generate_systemd_service("myapp", "/var/www/myapp");

        assert!(service.contains("[Unit]"));
        assert!(service.contains("[Service]"));
        assert!(service.contains("[Install]"));
        assert!(service.contains("NoNewPrivileges=true"));
    }

    #[test]
    fn test_uvicorn_config() {
        let config = UvicornConfig::new("main:app");
        let args = config.generate_cli_args();

        assert!(args.contains(&"main:app".to_string()));
        assert!(args.iter().any(|a| a.starts_with("--host=")));
        assert!(args.iter().any(|a| a.starts_with("--port=")));
    }

    #[test]
    fn test_uvicorn_with_workers() {
        let config = UvicornConfig {
            workers: 4,
            ..UvicornConfig::new("app:app")
        };
        let args = config.generate_cli_args();
        assert!(args.contains(&"--workers=4".to_string()));
    }

    #[test]
    fn test_security_defaults() {
        let security = SecurityConfig::default();
        assert_eq!(security.limit_request_line, 4094);
        assert_eq!(security.limit_request_fields, 100);
        assert!(!security.permit_unconventional_http_method);
    }

    #[test]
    fn test_logging_defaults() {
        let logging = LoggingConfig::default();
        assert_eq!(logging.loglevel, "info");
        assert!(logging.capture_output);
    }
}
