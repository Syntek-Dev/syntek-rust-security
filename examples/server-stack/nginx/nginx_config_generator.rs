//! Nginx Security Configuration Generator
//!
//! Generates security-hardened Nginx configurations with TLS best practices,
//! rate limiting, security headers, and WAF-like protection patterns.

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// TLS configuration versions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
    Tls12And13,
}

impl TlsVersion {
    pub fn as_nginx_directive(&self) -> &'static str {
        match self {
            TlsVersion::Tls12 => "TLSv1.2",
            TlsVersion::Tls13 => "TLSv1.3",
            TlsVersion::Tls12And13 => "TLSv1.2 TLSv1.3",
        }
    }
}

/// Security header configuration
#[derive(Debug, Clone)]
pub struct SecurityHeaders {
    pub strict_transport_security: Option<String>,
    pub content_security_policy: Option<String>,
    pub x_frame_options: Option<String>,
    pub x_content_type_options: bool,
    pub x_xss_protection: Option<String>,
    pub referrer_policy: Option<String>,
    pub permissions_policy: Option<String>,
    pub custom_headers: HashMap<String, String>,
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self {
            strict_transport_security: Some("max-age=31536000; includeSubDomains; preload".into()),
            content_security_policy: Some("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'".into()),
            x_frame_options: Some("DENY".into()),
            x_content_type_options: true,
            x_xss_protection: Some("1; mode=block".into()),
            referrer_policy: Some("strict-origin-when-cross-origin".into()),
            permissions_policy: Some("geolocation=(), microphone=(), camera=()".into()),
            custom_headers: HashMap::new(),
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub zone_name: String,
    pub zone_size: String,
    pub rate: String,
    pub burst: u32,
    pub nodelay: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            zone_name: "api_limit".into(),
            zone_size: "10m".into(),
            rate: "10r/s".into(),
            burst: 20,
            nodelay: true,
        }
    }
}

/// SSL/TLS configuration
#[derive(Debug, Clone)]
pub struct SslConfig {
    pub certificate_path: PathBuf,
    pub certificate_key_path: PathBuf,
    pub trusted_certificate_path: Option<PathBuf>,
    pub tls_version: TlsVersion,
    pub ciphers: Option<String>,
    pub prefer_server_ciphers: bool,
    pub session_timeout: String,
    pub session_cache: String,
    pub stapling: bool,
    pub stapling_verify: bool,
    pub dhparam_path: Option<PathBuf>,
}

impl Default for SslConfig {
    fn default() -> Self {
        Self {
            certificate_path: PathBuf::from("/etc/nginx/ssl/cert.pem"),
            certificate_key_path: PathBuf::from("/etc/nginx/ssl/key.pem"),
            trusted_certificate_path: None,
            tls_version: TlsVersion::Tls12And13,
            ciphers: Some("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384".into()),
            prefer_server_ciphers: true,
            session_timeout: "1d".into(),
            session_cache: "shared:SSL:10m".into(),
            stapling: true,
            stapling_verify: true,
            dhparam_path: Some(PathBuf::from("/etc/nginx/ssl/dhparam.pem")),
        }
    }
}

/// Upstream server configuration
#[derive(Debug, Clone)]
pub struct UpstreamServer {
    pub address: String,
    pub weight: u32,
    pub max_fails: u32,
    pub fail_timeout: String,
    pub backup: bool,
}

/// Upstream configuration for load balancing
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub name: String,
    pub servers: Vec<UpstreamServer>,
    pub keepalive: u32,
    pub keepalive_timeout: String,
}

/// Location block configuration
#[derive(Debug, Clone)]
pub struct LocationConfig {
    pub path: String,
    pub proxy_pass: Option<String>,
    pub root: Option<PathBuf>,
    pub index: Option<String>,
    pub try_files: Option<String>,
    pub rate_limit_zone: Option<String>,
    pub auth_basic: Option<String>,
    pub auth_basic_user_file: Option<PathBuf>,
    pub allow_methods: Vec<String>,
    pub deny_methods: Vec<String>,
    pub custom_directives: Vec<String>,
}

impl Default for LocationConfig {
    fn default() -> Self {
        Self {
            path: "/".into(),
            proxy_pass: None,
            root: None,
            index: None,
            try_files: None,
            rate_limit_zone: None,
            auth_basic: None,
            auth_basic_user_file: None,
            allow_methods: vec![],
            deny_methods: vec![],
            custom_directives: vec![],
        }
    }
}

/// Server block configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub server_name: Vec<String>,
    pub listen_port: u16,
    pub listen_ssl: bool,
    pub listen_http2: bool,
    pub ssl_config: Option<SslConfig>,
    pub root: Option<PathBuf>,
    pub access_log: Option<PathBuf>,
    pub error_log: Option<PathBuf>,
    pub security_headers: SecurityHeaders,
    pub locations: Vec<LocationConfig>,
    pub redirect_http_to_https: bool,
    pub custom_directives: Vec<String>,
}

/// WAF-like protection rules
#[derive(Debug, Clone)]
pub struct WafRules {
    pub block_sql_injection: bool,
    pub block_xss: bool,
    pub block_path_traversal: bool,
    pub block_rce: bool,
    pub block_file_inclusion: bool,
    pub blocked_user_agents: Vec<String>,
    pub blocked_referers: Vec<String>,
    pub custom_rules: Vec<String>,
}

impl Default for WafRules {
    fn default() -> Self {
        Self {
            block_sql_injection: true,
            block_xss: true,
            block_path_traversal: true,
            block_rce: true,
            block_file_inclusion: true,
            blocked_user_agents: vec![
                "sqlmap".into(),
                "nikto".into(),
                "nmap".into(),
                "masscan".into(),
            ],
            blocked_referers: vec![],
            custom_rules: vec![],
        }
    }
}

/// Main Nginx configuration generator
#[derive(Debug, Clone)]
pub struct NginxConfigGenerator {
    pub worker_processes: String,
    pub worker_connections: u32,
    pub multi_accept: bool,
    pub sendfile: bool,
    pub tcp_nopush: bool,
    pub tcp_nodelay: bool,
    pub keepalive_timeout: u32,
    pub types_hash_max_size: u32,
    pub server_tokens: bool,
    pub client_max_body_size: String,
    pub client_body_timeout: u32,
    pub client_header_timeout: u32,
    pub send_timeout: u32,
    pub rate_limits: Vec<RateLimitConfig>,
    pub upstreams: Vec<UpstreamConfig>,
    pub servers: Vec<ServerConfig>,
    pub waf_rules: Option<WafRules>,
    pub gzip_enabled: bool,
    pub gzip_types: Vec<String>,
}

impl Default for NginxConfigGenerator {
    fn default() -> Self {
        Self {
            worker_processes: "auto".into(),
            worker_connections: 1024,
            multi_accept: true,
            sendfile: true,
            tcp_nopush: true,
            tcp_nodelay: true,
            keepalive_timeout: 65,
            types_hash_max_size: 2048,
            server_tokens: false,
            client_max_body_size: "10m".into(),
            client_body_timeout: 12,
            client_header_timeout: 12,
            send_timeout: 10,
            rate_limits: vec![],
            upstreams: vec![],
            servers: vec![],
            waf_rules: None,
            gzip_enabled: true,
            gzip_types: vec![
                "text/plain".into(),
                "text/css".into(),
                "text/xml".into(),
                "application/json".into(),
                "application/javascript".into(),
                "application/xml".into(),
            ],
        }
    }
}

impl NginxConfigGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limits.push(config);
        self
    }

    pub fn with_upstream(mut self, config: UpstreamConfig) -> Self {
        self.upstreams.push(config);
        self
    }

    pub fn with_server(mut self, config: ServerConfig) -> Self {
        self.servers.push(config);
        self
    }

    pub fn with_waf(mut self, rules: WafRules) -> Self {
        self.waf_rules = Some(rules);
        self
    }

    /// Generate the complete nginx.conf
    pub fn generate(&self) -> String {
        let mut config = String::new();

        // Main context
        writeln!(config, "# Generated by Syntek Rust Security Plugin").unwrap();
        writeln!(config, "# Security-hardened Nginx configuration\n").unwrap();
        writeln!(config, "user nginx;").unwrap();
        writeln!(config, "worker_processes {};", self.worker_processes).unwrap();
        writeln!(config, "error_log /var/log/nginx/error.log warn;").unwrap();
        writeln!(config, "pid /var/run/nginx.pid;\n").unwrap();

        // Events context
        writeln!(config, "events {{").unwrap();
        writeln!(
            config,
            "    worker_connections {};",
            self.worker_connections
        )
        .unwrap();
        if self.multi_accept {
            writeln!(config, "    multi_accept on;").unwrap();
        }
        writeln!(config, "}}\n").unwrap();

        // HTTP context
        writeln!(config, "http {{").unwrap();
        self.generate_http_context(&mut config);
        writeln!(config, "}}").unwrap();

        config
    }

    fn generate_http_context(&self, config: &mut String) {
        // Basic settings
        writeln!(config, "    include /etc/nginx/mime.types;").unwrap();
        writeln!(config, "    default_type application/octet-stream;\n").unwrap();

        // Logging format
        writeln!(
            config,
            "    log_format main '$remote_addr - $remote_user [$time_local] \"$request\" '"
        )
        .unwrap();
        writeln!(
            config,
            "                    '$status $body_bytes_sent \"$http_referer\" '"
        )
        .unwrap();
        writeln!(
            config,
            "                    '\"$http_user_agent\" \"$http_x_forwarded_for\"';"
        )
        .unwrap();
        writeln!(config, "    access_log /var/log/nginx/access.log main;\n").unwrap();

        // Security settings
        if !self.server_tokens {
            writeln!(config, "    server_tokens off;").unwrap();
        }
        writeln!(
            config,
            "    client_max_body_size {};",
            self.client_max_body_size
        )
        .unwrap();
        writeln!(
            config,
            "    client_body_timeout {};",
            self.client_body_timeout
        )
        .unwrap();
        writeln!(
            config,
            "    client_header_timeout {};",
            self.client_header_timeout
        )
        .unwrap();
        writeln!(config, "    send_timeout {};\n", self.send_timeout).unwrap();

        // Performance settings
        if self.sendfile {
            writeln!(config, "    sendfile on;").unwrap();
        }
        if self.tcp_nopush {
            writeln!(config, "    tcp_nopush on;").unwrap();
        }
        if self.tcp_nodelay {
            writeln!(config, "    tcp_nodelay on;").unwrap();
        }
        writeln!(config, "    keepalive_timeout {};", self.keepalive_timeout).unwrap();
        writeln!(
            config,
            "    types_hash_max_size {};\n",
            self.types_hash_max_size
        )
        .unwrap();

        // Gzip compression
        if self.gzip_enabled {
            writeln!(config, "    gzip on;").unwrap();
            writeln!(config, "    gzip_vary on;").unwrap();
            writeln!(config, "    gzip_proxied any;").unwrap();
            writeln!(config, "    gzip_comp_level 6;").unwrap();
            writeln!(config, "    gzip_types {};", self.gzip_types.join(" ")).unwrap();
            writeln!(config).unwrap();
        }

        // Rate limiting zones
        for rate_limit in &self.rate_limits {
            writeln!(
                config,
                "    limit_req_zone $binary_remote_addr zone={}:{} rate={};",
                rate_limit.zone_name, rate_limit.zone_size, rate_limit.rate
            )
            .unwrap();
        }
        if !self.rate_limits.is_empty() {
            writeln!(config).unwrap();
        }

        // WAF rules
        if let Some(waf) = &self.waf_rules {
            self.generate_waf_rules(config, waf);
        }

        // Upstreams
        for upstream in &self.upstreams {
            self.generate_upstream(config, upstream);
        }

        // Servers
        for server in &self.servers {
            self.generate_server(config, server);
        }
    }

    fn generate_waf_rules(&self, config: &mut String, waf: &WafRules) {
        writeln!(config, "    # WAF-like protection rules").unwrap();

        // SQL injection patterns
        if waf.block_sql_injection {
            writeln!(config, "    map $request_uri $block_sql_injection {{").unwrap();
            writeln!(config, "        default 0;").unwrap();
            writeln!(config, "        ~*union.*select 1;").unwrap();
            writeln!(config, "        ~*select.*from 1;").unwrap();
            writeln!(config, "        ~*insert.*into 1;").unwrap();
            writeln!(config, "        ~*drop.*table 1;").unwrap();
            writeln!(config, "        ~*\\x27 1;").unwrap();
            writeln!(config, "        ~*\\x22 1;").unwrap();
            writeln!(config, "    }}\n").unwrap();
        }

        // XSS patterns
        if waf.block_xss {
            writeln!(config, "    map $request_uri $block_xss {{").unwrap();
            writeln!(config, "        default 0;").unwrap();
            writeln!(config, "        ~*<script 1;").unwrap();
            writeln!(config, "        ~*javascript: 1;").unwrap();
            writeln!(config, "        ~*vbscript: 1;").unwrap();
            writeln!(config, "        ~*onload= 1;").unwrap();
            writeln!(config, "        ~*onerror= 1;").unwrap();
            writeln!(config, "    }}\n").unwrap();
        }

        // Path traversal
        if waf.block_path_traversal {
            writeln!(config, "    map $request_uri $block_traversal {{").unwrap();
            writeln!(config, "        default 0;").unwrap();
            writeln!(config, "        ~*\\.\\./ 1;").unwrap();
            writeln!(config, "        ~*\\.\\.%2f 1;").unwrap();
            writeln!(config, "        ~*%2e%2e/ 1;").unwrap();
            writeln!(config, "    }}\n").unwrap();
        }

        // Blocked user agents
        if !waf.blocked_user_agents.is_empty() {
            writeln!(config, "    map $http_user_agent $block_user_agent {{").unwrap();
            writeln!(config, "        default 0;").unwrap();
            for agent in &waf.blocked_user_agents {
                writeln!(config, "        ~*{} 1;", agent).unwrap();
            }
            writeln!(config, "    }}\n").unwrap();
        }
    }

    fn generate_upstream(&self, config: &mut String, upstream: &UpstreamConfig) {
        writeln!(config, "    upstream {} {{", upstream.name).unwrap();
        for server in &upstream.servers {
            let mut directive = format!("        server {}", server.address);
            if server.weight != 1 {
                write!(directive, " weight={}", server.weight).unwrap();
            }
            write!(directive, " max_fails={}", server.max_fails).unwrap();
            write!(directive, " fail_timeout={}", server.fail_timeout).unwrap();
            if server.backup {
                write!(directive, " backup").unwrap();
            }
            writeln!(directive, ";").unwrap();
            config.push_str(&directive);
        }
        writeln!(config, "        keepalive {};", upstream.keepalive).unwrap();
        writeln!(config, "    }}\n").unwrap();
    }

    fn generate_server(&self, config: &mut String, server: &ServerConfig) {
        writeln!(config, "    server {{").unwrap();

        // Listen directive
        let mut listen = format!("        listen {}", server.listen_port);
        if server.listen_ssl {
            write!(listen, " ssl").unwrap();
        }
        if server.listen_http2 {
            write!(listen, " http2").unwrap();
        }
        writeln!(listen, ";").unwrap();
        config.push_str(&listen);

        // Server names
        if !server.server_name.is_empty() {
            writeln!(
                config,
                "        server_name {};",
                server.server_name.join(" ")
            )
            .unwrap();
        }

        // SSL configuration
        if let Some(ssl) = &server.ssl_config {
            writeln!(config).unwrap();
            self.generate_ssl_config(config, ssl);
        }

        // Root directory
        if let Some(root) = &server.root {
            writeln!(config, "        root {};", root.display()).unwrap();
        }

        // Access and error logs
        if let Some(access_log) = &server.access_log {
            writeln!(config, "        access_log {} main;", access_log.display()).unwrap();
        }
        if let Some(error_log) = &server.error_log {
            writeln!(config, "        error_log {};", error_log.display()).unwrap();
        }

        // Security headers
        writeln!(config).unwrap();
        self.generate_security_headers(config, &server.security_headers);

        // WAF enforcement
        if self.waf_rules.is_some() {
            writeln!(config).unwrap();
            writeln!(config, "        # WAF enforcement").unwrap();
            writeln!(
                config,
                "        if ($block_sql_injection) {{ return 403; }}"
            )
            .unwrap();
            writeln!(config, "        if ($block_xss) {{ return 403; }}").unwrap();
            writeln!(config, "        if ($block_traversal) {{ return 403; }}").unwrap();
            writeln!(config, "        if ($block_user_agent) {{ return 403; }}").unwrap();
        }

        // Locations
        for location in &server.locations {
            writeln!(config).unwrap();
            self.generate_location(config, location);
        }

        // Custom directives
        for directive in &server.custom_directives {
            writeln!(config, "        {}", directive).unwrap();
        }

        writeln!(config, "    }}\n").unwrap();

        // HTTP to HTTPS redirect server
        if server.redirect_http_to_https && server.listen_ssl {
            writeln!(config, "    server {{").unwrap();
            writeln!(config, "        listen 80;").unwrap();
            writeln!(
                config,
                "        server_name {};",
                server.server_name.join(" ")
            )
            .unwrap();
            writeln!(config, "        return 301 https://$host$request_uri;").unwrap();
            writeln!(config, "    }}\n").unwrap();
        }
    }

    fn generate_ssl_config(&self, config: &mut String, ssl: &SslConfig) {
        writeln!(config, "        # SSL/TLS configuration").unwrap();
        writeln!(
            config,
            "        ssl_certificate {};",
            ssl.certificate_path.display()
        )
        .unwrap();
        writeln!(
            config,
            "        ssl_certificate_key {};",
            ssl.certificate_key_path.display()
        )
        .unwrap();

        if let Some(trusted) = &ssl.trusted_certificate_path {
            writeln!(
                config,
                "        ssl_trusted_certificate {};",
                trusted.display()
            )
            .unwrap();
        }

        writeln!(
            config,
            "        ssl_protocols {};",
            ssl.tls_version.as_nginx_directive()
        )
        .unwrap();

        if let Some(ciphers) = &ssl.ciphers {
            writeln!(config, "        ssl_ciphers {};", ciphers).unwrap();
        }

        if ssl.prefer_server_ciphers {
            writeln!(config, "        ssl_prefer_server_ciphers on;").unwrap();
        }

        writeln!(
            config,
            "        ssl_session_timeout {};",
            ssl.session_timeout
        )
        .unwrap();
        writeln!(config, "        ssl_session_cache {};", ssl.session_cache).unwrap();
        writeln!(config, "        ssl_session_tickets off;").unwrap();

        if ssl.stapling {
            writeln!(config, "        ssl_stapling on;").unwrap();
        }
        if ssl.stapling_verify {
            writeln!(config, "        ssl_stapling_verify on;").unwrap();
        }

        if let Some(dhparam) = &ssl.dhparam_path {
            writeln!(config, "        ssl_dhparam {};", dhparam.display()).unwrap();
        }
    }

    fn generate_security_headers(&self, config: &mut String, headers: &SecurityHeaders) {
        writeln!(config, "        # Security headers").unwrap();

        if let Some(hsts) = &headers.strict_transport_security {
            writeln!(
                config,
                "        add_header Strict-Transport-Security \"{}\";",
                hsts
            )
            .unwrap();
        }
        if let Some(csp) = &headers.content_security_policy {
            writeln!(
                config,
                "        add_header Content-Security-Policy \"{}\";",
                csp
            )
            .unwrap();
        }
        if let Some(xfo) = &headers.x_frame_options {
            writeln!(config, "        add_header X-Frame-Options \"{}\";", xfo).unwrap();
        }
        if headers.x_content_type_options {
            writeln!(
                config,
                "        add_header X-Content-Type-Options \"nosniff\";"
            )
            .unwrap();
        }
        if let Some(xss) = &headers.x_xss_protection {
            writeln!(config, "        add_header X-XSS-Protection \"{}\";", xss).unwrap();
        }
        if let Some(referrer) = &headers.referrer_policy {
            writeln!(
                config,
                "        add_header Referrer-Policy \"{}\";",
                referrer
            )
            .unwrap();
        }
        if let Some(permissions) = &headers.permissions_policy {
            writeln!(
                config,
                "        add_header Permissions-Policy \"{}\";",
                permissions
            )
            .unwrap();
        }

        for (name, value) in &headers.custom_headers {
            writeln!(config, "        add_header {} \"{}\";", name, value).unwrap();
        }
    }

    fn generate_location(&self, config: &mut String, location: &LocationConfig) {
        writeln!(config, "        location {} {{", location.path).unwrap();

        if let Some(proxy_pass) = &location.proxy_pass {
            writeln!(config, "            proxy_pass {};", proxy_pass).unwrap();
            writeln!(config, "            proxy_http_version 1.1;").unwrap();
            writeln!(config, "            proxy_set_header Host $host;").unwrap();
            writeln!(
                config,
                "            proxy_set_header X-Real-IP $remote_addr;"
            )
            .unwrap();
            writeln!(
                config,
                "            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"
            )
            .unwrap();
            writeln!(
                config,
                "            proxy_set_header X-Forwarded-Proto $scheme;"
            )
            .unwrap();
        }

        if let Some(root) = &location.root {
            writeln!(config, "            root {};", root.display()).unwrap();
        }

        if let Some(index) = &location.index {
            writeln!(config, "            index {};", index).unwrap();
        }

        if let Some(try_files) = &location.try_files {
            writeln!(config, "            try_files {};", try_files).unwrap();
        }

        if let Some(zone) = &location.rate_limit_zone {
            let rate_limit = self.rate_limits.iter().find(|r| &r.zone_name == zone);
            if let Some(rl) = rate_limit {
                let nodelay = if rl.nodelay { " nodelay" } else { "" };
                writeln!(
                    config,
                    "            limit_req zone={} burst={}{};",
                    zone, rl.burst, nodelay
                )
                .unwrap();
            }
        }

        if let Some(auth) = &location.auth_basic {
            writeln!(config, "            auth_basic \"{}\";", auth).unwrap();
            if let Some(user_file) = &location.auth_basic_user_file {
                writeln!(
                    config,
                    "            auth_basic_user_file {};",
                    user_file.display()
                )
                .unwrap();
            }
        }

        if !location.allow_methods.is_empty() {
            writeln!(
                config,
                "            limit_except {} {{",
                location.allow_methods.join(" ")
            )
            .unwrap();
            writeln!(config, "                deny all;").unwrap();
            writeln!(config, "            }}").unwrap();
        }

        for directive in &location.custom_directives {
            writeln!(config, "            {}", directive).unwrap();
        }

        writeln!(config, "        }}").unwrap();
    }

    /// Write configuration to file
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let config = self.generate();
        let mut file = fs::File::create(path)?;
        file.write_all(config.as_bytes())?;
        Ok(())
    }
}

/// Builder for creating a complete server configuration
pub struct ServerConfigBuilder {
    config: ServerConfig,
}

impl ServerConfigBuilder {
    pub fn new(server_name: &str) -> Self {
        Self {
            config: ServerConfig {
                server_name: vec![server_name.into()],
                listen_port: 443,
                listen_ssl: true,
                listen_http2: true,
                ssl_config: Some(SslConfig::default()),
                root: None,
                access_log: None,
                error_log: None,
                security_headers: SecurityHeaders::default(),
                locations: vec![],
                redirect_http_to_https: true,
                custom_directives: vec![],
            },
        }
    }

    pub fn with_ssl_cert(mut self, cert: PathBuf, key: PathBuf) -> Self {
        if let Some(ssl) = &mut self.config.ssl_config {
            ssl.certificate_path = cert;
            ssl.certificate_key_path = key;
        }
        self
    }

    pub fn with_location(mut self, location: LocationConfig) -> Self {
        self.config.locations.push(location);
        self
    }

    pub fn with_proxy_location(mut self, path: &str, upstream: &str) -> Self {
        self.config.locations.push(LocationConfig {
            path: path.into(),
            proxy_pass: Some(format!("http://{}", upstream)),
            ..Default::default()
        });
        self
    }

    pub fn with_static_location(mut self, path: &str, root: PathBuf) -> Self {
        self.config.locations.push(LocationConfig {
            path: path.into(),
            root: Some(root),
            try_files: Some("$uri $uri/ =404".into()),
            ..Default::default()
        });
        self
    }

    pub fn build(self) -> ServerConfig {
        self.config
    }
}

fn main() {
    println!("Nginx Security Configuration Generator\n");

    // Create rate limiting configuration
    let api_rate_limit = RateLimitConfig {
        zone_name: "api_limit".into(),
        zone_size: "10m".into(),
        rate: "10r/s".into(),
        burst: 20,
        nodelay: true,
    };

    let login_rate_limit = RateLimitConfig {
        zone_name: "login_limit".into(),
        zone_size: "10m".into(),
        rate: "5r/m".into(),
        burst: 5,
        nodelay: false,
    };

    // Create upstream configuration
    let app_upstream = UpstreamConfig {
        name: "app_backend".into(),
        servers: vec![
            UpstreamServer {
                address: "127.0.0.1:8000".into(),
                weight: 1,
                max_fails: 3,
                fail_timeout: "30s".into(),
                backup: false,
            },
            UpstreamServer {
                address: "127.0.0.1:8001".into(),
                weight: 1,
                max_fails: 3,
                fail_timeout: "30s".into(),
                backup: true,
            },
        ],
        keepalive: 32,
        keepalive_timeout: "60s".into(),
    };

    // Create server configuration using builder
    let server = ServerConfigBuilder::new("example.com")
        .with_ssl_cert(
            PathBuf::from("/etc/nginx/ssl/example.com.pem"),
            PathBuf::from("/etc/nginx/ssl/example.com.key"),
        )
        .with_proxy_location("/api/", "app_backend")
        .with_static_location("/static/", PathBuf::from("/var/www/static"))
        .with_location(LocationConfig {
            path: "/auth/login".into(),
            proxy_pass: Some("http://app_backend".into()),
            rate_limit_zone: Some("login_limit".into()),
            ..Default::default()
        })
        .build();

    // Create WAF rules
    let waf = WafRules::default();

    // Generate complete configuration
    let generator = NginxConfigGenerator::new()
        .with_rate_limit(api_rate_limit)
        .with_rate_limit(login_rate_limit)
        .with_upstream(app_upstream)
        .with_server(server)
        .with_waf(waf);

    let config = generator.generate();

    println!("Generated Nginx Configuration:");
    println!("{}", "=".repeat(60));
    println!("{}", config);

    // Configuration validation summary
    println!("\nConfiguration Summary:");
    println!("  - Workers: {}", generator.worker_processes);
    println!("  - Rate limit zones: {}", generator.rate_limits.len());
    println!("  - Upstreams: {}", generator.upstreams.len());
    println!("  - Server blocks: {}", generator.servers.len());
    println!("  - WAF enabled: {}", generator.waf_rules.is_some());
    println!("  - Gzip enabled: {}", generator.gzip_enabled);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_generator() {
        let generator = NginxConfigGenerator::default();
        assert_eq!(generator.worker_processes, "auto");
        assert_eq!(generator.worker_connections, 1024);
        assert!(!generator.server_tokens);
    }

    #[test]
    fn test_tls_version_directive() {
        assert_eq!(TlsVersion::Tls12.as_nginx_directive(), "TLSv1.2");
        assert_eq!(TlsVersion::Tls13.as_nginx_directive(), "TLSv1.3");
        assert_eq!(
            TlsVersion::Tls12And13.as_nginx_directive(),
            "TLSv1.2 TLSv1.3"
        );
    }

    #[test]
    fn test_security_headers_default() {
        let headers = SecurityHeaders::default();
        assert!(headers.strict_transport_security.is_some());
        assert!(headers.content_security_policy.is_some());
        assert!(headers.x_content_type_options);
    }

    #[test]
    fn test_rate_limit_config() {
        let config = RateLimitConfig::default();
        assert_eq!(config.zone_name, "api_limit");
        assert_eq!(config.rate, "10r/s");
        assert_eq!(config.burst, 20);
    }

    #[test]
    fn test_server_builder() {
        let server = ServerConfigBuilder::new("test.com")
            .with_proxy_location("/api/", "backend")
            .build();

        assert_eq!(server.server_name, vec!["test.com"]);
        assert!(server.listen_ssl);
        assert_eq!(server.locations.len(), 1);
    }

    #[test]
    fn test_generate_config() {
        let generator = NginxConfigGenerator::new().with_rate_limit(RateLimitConfig::default());

        let config = generator.generate();
        assert!(config.contains("worker_processes auto"));
        assert!(config.contains("limit_req_zone"));
        assert!(config.contains("server_tokens off"));
    }

    #[test]
    fn test_waf_rules_default() {
        let waf = WafRules::default();
        assert!(waf.block_sql_injection);
        assert!(waf.block_xss);
        assert!(waf.block_path_traversal);
        assert!(!waf.blocked_user_agents.is_empty());
    }

    #[test]
    fn test_upstream_config() {
        let upstream = UpstreamConfig {
            name: "test".into(),
            servers: vec![UpstreamServer {
                address: "127.0.0.1:8000".into(),
                weight: 1,
                max_fails: 3,
                fail_timeout: "30s".into(),
                backup: false,
            }],
            keepalive: 32,
            keepalive_timeout: "60s".into(),
        };

        let generator = NginxConfigGenerator::new().with_upstream(upstream);
        let config = generator.generate();
        assert!(config.contains("upstream test"));
        assert!(config.contains("127.0.0.1:8000"));
    }

    #[test]
    fn test_ssl_config_generation() {
        let server = ServerConfigBuilder::new("secure.com")
            .with_ssl_cert(
                PathBuf::from("/ssl/cert.pem"),
                PathBuf::from("/ssl/key.pem"),
            )
            .build();

        let generator = NginxConfigGenerator::new().with_server(server);
        let config = generator.generate();
        assert!(config.contains("ssl_certificate /ssl/cert.pem"));
        assert!(config.contains("ssl_certificate_key /ssl/key.pem"));
        assert!(config.contains("ssl_protocols"));
    }
}
