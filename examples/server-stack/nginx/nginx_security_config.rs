//! Nginx Security Configuration Generator
//!
//! Generates security-hardened Nginx configuration with TLS, rate limiting,
//! security headers, and WAF-like protections.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as FmtWrite;

/// TLS protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl TlsVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsVersion::Tls10 => "TLSv1",
            TlsVersion::Tls11 => "TLSv1.1",
            TlsVersion::Tls12 => "TLSv1.2",
            TlsVersion::Tls13 => "TLSv1.3",
        }
    }
}

/// SSL cipher suite presets
#[derive(Debug, Clone, Copy)]
pub enum CipherPreset {
    Modern,
    Intermediate,
    Old,
    Custom,
}

impl CipherPreset {
    pub fn ciphers(&self) -> &'static str {
        match self {
            CipherPreset::Modern => {
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
                 ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
                 ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
            }
            CipherPreset::Intermediate => {
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
                 ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
                 ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
                 DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
            }
            CipherPreset::Old => {
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
                 ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
                 ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:\
                 ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384"
            }
            CipherPreset::Custom => "",
        }
    }

    pub fn min_tls_version(&self) -> TlsVersion {
        match self {
            CipherPreset::Modern => TlsVersion::Tls13,
            CipherPreset::Intermediate => TlsVersion::Tls12,
            CipherPreset::Old => TlsVersion::Tls10,
            CipherPreset::Custom => TlsVersion::Tls12,
        }
    }
}

/// Security header configuration
#[derive(Debug, Clone)]
pub struct SecurityHeaders {
    pub x_frame_options: Option<String>,
    pub x_content_type_options: bool,
    pub x_xss_protection: bool,
    pub referrer_policy: Option<String>,
    pub content_security_policy: Option<String>,
    pub permissions_policy: Option<String>,
    pub strict_transport_security: Option<HstsConfig>,
    pub cross_origin_embedder_policy: Option<String>,
    pub cross_origin_opener_policy: Option<String>,
    pub cross_origin_resource_policy: Option<String>,
    pub custom_headers: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct HstsConfig {
    pub max_age: u64,
    pub include_subdomains: bool,
    pub preload: bool,
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self {
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: true,
            x_xss_protection: true,
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            content_security_policy: None,
            permissions_policy: None,
            strict_transport_security: Some(HstsConfig {
                max_age: 31536000, // 1 year
                include_subdomains: true,
                preload: false,
            }),
            cross_origin_embedder_policy: Some("require-corp".to_string()),
            cross_origin_opener_policy: Some("same-origin".to_string()),
            cross_origin_resource_policy: Some("same-origin".to_string()),
            custom_headers: HashMap::new(),
        }
    }
}

impl SecurityHeaders {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn csp(mut self, policy: impl Into<String>) -> Self {
        self.content_security_policy = Some(policy.into());
        self
    }

    pub fn permissions_policy(mut self, policy: impl Into<String>) -> Self {
        self.permissions_policy = Some(policy.into());
        self
    }

    pub fn hsts(mut self, max_age: u64, include_subdomains: bool, preload: bool) -> Self {
        self.strict_transport_security = Some(HstsConfig {
            max_age,
            include_subdomains,
            preload,
        });
        self
    }

    pub fn frame_options(mut self, option: impl Into<String>) -> Self {
        self.x_frame_options = Some(option.into());
        self
    }

    pub fn custom_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom_headers.insert(name.into(), value.into());
        self
    }

    pub fn generate(&self) -> Vec<String> {
        let mut headers = Vec::new();

        if let Some(ref value) = self.x_frame_options {
            headers.push(format!("add_header X-Frame-Options \"{}\" always;", value));
        }

        if self.x_content_type_options {
            headers.push("add_header X-Content-Type-Options \"nosniff\" always;".to_string());
        }

        if self.x_xss_protection {
            headers.push("add_header X-XSS-Protection \"1; mode=block\" always;".to_string());
        }

        if let Some(ref value) = self.referrer_policy {
            headers.push(format!("add_header Referrer-Policy \"{}\" always;", value));
        }

        if let Some(ref value) = self.content_security_policy {
            headers.push(format!(
                "add_header Content-Security-Policy \"{}\" always;",
                value
            ));
        }

        if let Some(ref value) = self.permissions_policy {
            headers.push(format!(
                "add_header Permissions-Policy \"{}\" always;",
                value
            ));
        }

        if let Some(ref hsts) = self.strict_transport_security {
            let mut value = format!("max-age={}", hsts.max_age);
            if hsts.include_subdomains {
                value.push_str("; includeSubDomains");
            }
            if hsts.preload {
                value.push_str("; preload");
            }
            headers.push(format!(
                "add_header Strict-Transport-Security \"{}\" always;",
                value
            ));
        }

        if let Some(ref value) = self.cross_origin_embedder_policy {
            headers.push(format!(
                "add_header Cross-Origin-Embedder-Policy \"{}\" always;",
                value
            ));
        }

        if let Some(ref value) = self.cross_origin_opener_policy {
            headers.push(format!(
                "add_header Cross-Origin-Opener-Policy \"{}\" always;",
                value
            ));
        }

        if let Some(ref value) = self.cross_origin_resource_policy {
            headers.push(format!(
                "add_header Cross-Origin-Resource-Policy \"{}\" always;",
                value
            ));
        }

        for (name, value) in &self.custom_headers {
            headers.push(format!("add_header {} \"{}\" always;", name, value));
        }

        headers
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub zone_name: String,
    pub key: String,
    pub rate: String,
    pub zone_size: String,
    pub burst: Option<u32>,
    pub nodelay: bool,
}

impl RateLimitConfig {
    pub fn new(zone_name: impl Into<String>, rate: impl Into<String>) -> Self {
        Self {
            zone_name: zone_name.into(),
            key: "$binary_remote_addr".to_string(),
            rate: rate.into(),
            zone_size: "10m".to_string(),
            burst: None,
            nodelay: false,
        }
    }

    pub fn key(mut self, key: impl Into<String>) -> Self {
        self.key = key.into();
        self
    }

    pub fn zone_size(mut self, size: impl Into<String>) -> Self {
        self.zone_size = size.into();
        self
    }

    pub fn burst(mut self, burst: u32) -> Self {
        self.burst = Some(burst);
        self
    }

    pub fn nodelay(mut self) -> Self {
        self.nodelay = true;
        self
    }

    pub fn generate_zone(&self) -> String {
        format!(
            "limit_req_zone {} zone={}:{} rate={};",
            self.key, self.zone_name, self.zone_size, self.rate
        )
    }

    pub fn generate_limit(&self) -> String {
        let mut limit = format!("limit_req zone={}", self.zone_name);
        if let Some(burst) = self.burst {
            limit.push_str(&format!(" burst={}", burst));
        }
        if self.nodelay {
            limit.push_str(" nodelay");
        }
        limit.push(';');
        limit
    }
}

/// Upstream server configuration
#[derive(Debug, Clone)]
pub struct UpstreamServer {
    pub address: String,
    pub port: u16,
    pub weight: Option<u32>,
    pub max_fails: Option<u32>,
    pub fail_timeout: Option<String>,
    pub backup: bool,
    pub down: bool,
}

impl UpstreamServer {
    pub fn new(address: impl Into<String>, port: u16) -> Self {
        Self {
            address: address.into(),
            port,
            weight: None,
            max_fails: None,
            fail_timeout: None,
            backup: false,
            down: false,
        }
    }

    pub fn weight(mut self, weight: u32) -> Self {
        self.weight = Some(weight);
        self
    }

    pub fn max_fails(mut self, fails: u32) -> Self {
        self.max_fails = Some(fails);
        self
    }

    pub fn fail_timeout(mut self, timeout: impl Into<String>) -> Self {
        self.fail_timeout = Some(timeout.into());
        self
    }

    pub fn backup(mut self) -> Self {
        self.backup = true;
        self
    }

    pub fn generate(&self) -> String {
        let mut line = format!("server {}:{}", self.address, self.port);
        if let Some(weight) = self.weight {
            line.push_str(&format!(" weight={}", weight));
        }
        if let Some(max_fails) = self.max_fails {
            line.push_str(&format!(" max_fails={}", max_fails));
        }
        if let Some(ref timeout) = self.fail_timeout {
            line.push_str(&format!(" fail_timeout={}", timeout));
        }
        if self.backup {
            line.push_str(" backup");
        }
        if self.down {
            line.push_str(" down");
        }
        line.push(';');
        line
    }
}

/// Upstream configuration
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub name: String,
    pub servers: Vec<UpstreamServer>,
    pub keepalive: Option<u32>,
    pub keepalive_timeout: Option<String>,
    pub load_balancing: LoadBalancing,
}

#[derive(Debug, Clone, Copy)]
pub enum LoadBalancing {
    RoundRobin,
    LeastConn,
    IpHash,
    Hash,
}

impl UpstreamConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            servers: Vec::new(),
            keepalive: None,
            keepalive_timeout: None,
            load_balancing: LoadBalancing::RoundRobin,
        }
    }

    pub fn server(mut self, server: UpstreamServer) -> Self {
        self.servers.push(server);
        self
    }

    pub fn keepalive(mut self, connections: u32) -> Self {
        self.keepalive = Some(connections);
        self
    }

    pub fn load_balancing(mut self, method: LoadBalancing) -> Self {
        self.load_balancing = method;
        self
    }

    pub fn generate(&self) -> String {
        let mut config = format!("upstream {} {{\n", self.name);

        match self.load_balancing {
            LoadBalancing::LeastConn => config.push_str("    least_conn;\n"),
            LoadBalancing::IpHash => config.push_str("    ip_hash;\n"),
            LoadBalancing::Hash => config.push_str("    hash $request_uri consistent;\n"),
            LoadBalancing::RoundRobin => {}
        }

        for server in &self.servers {
            config.push_str(&format!("    {}\n", server.generate()));
        }

        if let Some(keepalive) = self.keepalive {
            config.push_str(&format!("    keepalive {};\n", keepalive));
        }

        config.push_str("}\n");
        config
    }
}

/// Location configuration
#[derive(Debug, Clone)]
pub struct LocationConfig {
    pub path: String,
    pub modifier: Option<String>,
    pub proxy_pass: Option<String>,
    pub root: Option<String>,
    pub index: Option<String>,
    pub try_files: Option<String>,
    pub rate_limit: Option<String>,
    pub auth_basic: Option<String>,
    pub auth_basic_user_file: Option<String>,
    pub allowed_methods: HashSet<String>,
    pub denied_methods: HashSet<String>,
    pub custom_directives: Vec<String>,
}

impl LocationConfig {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            modifier: None,
            proxy_pass: None,
            root: None,
            index: None,
            try_files: None,
            rate_limit: None,
            auth_basic: None,
            auth_basic_user_file: None,
            allowed_methods: HashSet::new(),
            denied_methods: HashSet::new(),
            custom_directives: Vec::new(),
        }
    }

    pub fn exact(mut self) -> Self {
        self.modifier = Some("=".to_string());
        self
    }

    pub fn regex(mut self) -> Self {
        self.modifier = Some("~".to_string());
        self
    }

    pub fn proxy_pass(mut self, upstream: impl Into<String>) -> Self {
        self.proxy_pass = Some(upstream.into());
        self
    }

    pub fn root(mut self, path: impl Into<String>) -> Self {
        self.root = Some(path.into());
        self
    }

    pub fn try_files(mut self, files: impl Into<String>) -> Self {
        self.try_files = Some(files.into());
        self
    }

    pub fn rate_limit(mut self, zone: impl Into<String>) -> Self {
        self.rate_limit = Some(zone.into());
        self
    }

    pub fn basic_auth(mut self, realm: impl Into<String>, user_file: impl Into<String>) -> Self {
        self.auth_basic = Some(realm.into());
        self.auth_basic_user_file = Some(user_file.into());
        self
    }

    pub fn allow_method(mut self, method: impl Into<String>) -> Self {
        self.allowed_methods.insert(method.into());
        self
    }

    pub fn deny_method(mut self, method: impl Into<String>) -> Self {
        self.denied_methods.insert(method.into());
        self
    }

    pub fn directive(mut self, directive: impl Into<String>) -> Self {
        self.custom_directives.push(directive.into());
        self
    }

    pub fn generate(&self, indent: usize) -> String {
        let prefix = "    ".repeat(indent);
        let inner = "    ".repeat(indent + 1);
        let mut config = String::new();

        let location = if let Some(ref modifier) = self.modifier {
            format!("{}location {} {} {{\n", prefix, modifier, self.path)
        } else {
            format!("{}location {} {{\n", prefix, self.path)
        };
        config.push_str(&location);

        if let Some(ref proxy) = self.proxy_pass {
            config.push_str(&format!("{}proxy_pass {};\n", inner, proxy));
            config.push_str(&format!("{}proxy_http_version 1.1;\n", inner));
            config.push_str(&format!("{}proxy_set_header Host $host;\n", inner));
            config.push_str(&format!(
                "{}proxy_set_header X-Real-IP $remote_addr;\n",
                inner
            ));
            config.push_str(&format!(
                "{}proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n",
                inner
            ));
            config.push_str(&format!(
                "{}proxy_set_header X-Forwarded-Proto $scheme;\n",
                inner
            ));
        }

        if let Some(ref root) = self.root {
            config.push_str(&format!("{}root {};\n", inner, root));
        }

        if let Some(ref index) = self.index {
            config.push_str(&format!("{}index {};\n", inner, index));
        }

        if let Some(ref try_files) = self.try_files {
            config.push_str(&format!("{}try_files {};\n", inner, try_files));
        }

        if let Some(ref zone) = self.rate_limit {
            config.push_str(&format!("{}limit_req zone={};\n", inner, zone));
        }

        if let Some(ref realm) = self.auth_basic {
            config.push_str(&format!("{}auth_basic \"{}\";\n", inner, realm));
            if let Some(ref file) = self.auth_basic_user_file {
                config.push_str(&format!("{}auth_basic_user_file {};\n", inner, file));
            }
        }

        if !self.allowed_methods.is_empty() {
            let methods: Vec<&String> = self.allowed_methods.iter().collect();
            config.push_str(&format!(
                "{}limit_except {} {{\n{}    deny all;\n{}}}\n",
                inner,
                methods.join(" "),
                inner,
                inner
            ));
        }

        for directive in &self.custom_directives {
            config.push_str(&format!("{}{}\n", inner, directive));
        }

        config.push_str(&format!("{}}}\n", prefix));
        config
    }
}

/// Server block configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub server_name: Vec<String>,
    pub listen_port: u16,
    pub listen_ssl: bool,
    pub ssl_certificate: Option<String>,
    pub ssl_certificate_key: Option<String>,
    pub ssl_dhparam: Option<String>,
    pub ssl_protocols: Vec<TlsVersion>,
    pub ssl_ciphers: String,
    pub ssl_prefer_server_ciphers: bool,
    pub ssl_session_timeout: String,
    pub ssl_session_cache: String,
    pub ssl_stapling: bool,
    pub root: Option<String>,
    pub access_log: Option<String>,
    pub error_log: Option<String>,
    pub security_headers: SecurityHeaders,
    pub locations: Vec<LocationConfig>,
    pub custom_directives: Vec<String>,
}

impl ServerConfig {
    pub fn new(server_name: impl Into<String>, port: u16) -> Self {
        Self {
            server_name: vec![server_name.into()],
            listen_port: port,
            listen_ssl: false,
            ssl_certificate: None,
            ssl_certificate_key: None,
            ssl_dhparam: None,
            ssl_protocols: vec![TlsVersion::Tls12, TlsVersion::Tls13],
            ssl_ciphers: CipherPreset::Modern.ciphers().to_string(),
            ssl_prefer_server_ciphers: true,
            ssl_session_timeout: "1d".to_string(),
            ssl_session_cache: "shared:SSL:50m".to_string(),
            ssl_stapling: true,
            root: None,
            access_log: None,
            error_log: None,
            security_headers: SecurityHeaders::default(),
            locations: Vec::new(),
            custom_directives: Vec::new(),
        }
    }

    pub fn add_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name.push(name.into());
        self
    }

    pub fn ssl(mut self, cert: impl Into<String>, key: impl Into<String>) -> Self {
        self.listen_ssl = true;
        self.ssl_certificate = Some(cert.into());
        self.ssl_certificate_key = Some(key.into());
        self
    }

    pub fn dhparam(mut self, path: impl Into<String>) -> Self {
        self.ssl_dhparam = Some(path.into());
        self
    }

    pub fn cipher_preset(mut self, preset: CipherPreset) -> Self {
        self.ssl_ciphers = preset.ciphers().to_string();
        self.ssl_protocols = vec![preset.min_tls_version()];
        if preset.min_tls_version() == TlsVersion::Tls12 {
            self.ssl_protocols.push(TlsVersion::Tls13);
        }
        self
    }

    pub fn root(mut self, path: impl Into<String>) -> Self {
        self.root = Some(path.into());
        self
    }

    pub fn access_log(mut self, path: impl Into<String>) -> Self {
        self.access_log = Some(path.into());
        self
    }

    pub fn error_log(mut self, path: impl Into<String>) -> Self {
        self.error_log = Some(path.into());
        self
    }

    pub fn security_headers(mut self, headers: SecurityHeaders) -> Self {
        self.security_headers = headers;
        self
    }

    pub fn location(mut self, location: LocationConfig) -> Self {
        self.locations.push(location);
        self
    }

    pub fn directive(mut self, directive: impl Into<String>) -> Self {
        self.custom_directives.push(directive.into());
        self
    }

    pub fn generate(&self) -> String {
        let mut config = String::new();

        config.push_str("server {\n");

        // Listen directive
        let listen = if self.listen_ssl {
            format!("    listen {} ssl http2;\n", self.listen_port)
        } else {
            format!("    listen {};\n", self.listen_port)
        };
        config.push_str(&listen);

        // Server name
        config.push_str(&format!(
            "    server_name {};\n",
            self.server_name.join(" ")
        ));

        // SSL configuration
        if self.listen_ssl {
            config.push('\n');
            config.push_str("    # SSL Configuration\n");

            if let Some(ref cert) = self.ssl_certificate {
                config.push_str(&format!("    ssl_certificate {};\n", cert));
            }
            if let Some(ref key) = self.ssl_certificate_key {
                config.push_str(&format!("    ssl_certificate_key {};\n", key));
            }
            if let Some(ref dhparam) = self.ssl_dhparam {
                config.push_str(&format!("    ssl_dhparam {};\n", dhparam));
            }

            let protocols: Vec<&str> = self.ssl_protocols.iter().map(|p| p.as_str()).collect();
            config.push_str(&format!("    ssl_protocols {};\n", protocols.join(" ")));
            config.push_str(&format!("    ssl_ciphers {};\n", self.ssl_ciphers));
            config.push_str(&format!(
                "    ssl_prefer_server_ciphers {};\n",
                if self.ssl_prefer_server_ciphers {
                    "on"
                } else {
                    "off"
                }
            ));
            config.push_str(&format!(
                "    ssl_session_timeout {};\n",
                self.ssl_session_timeout
            ));
            config.push_str(&format!(
                "    ssl_session_cache {};\n",
                self.ssl_session_cache
            ));
            config.push_str("    ssl_session_tickets off;\n");

            if self.ssl_stapling {
                config.push_str("    ssl_stapling on;\n");
                config.push_str("    ssl_stapling_verify on;\n");
            }
        }

        // Root
        if let Some(ref root) = self.root {
            config.push_str(&format!("\n    root {};\n", root));
        }

        // Logging
        if let Some(ref access) = self.access_log {
            config.push_str(&format!("    access_log {};\n", access));
        }
        if let Some(ref error) = self.error_log {
            config.push_str(&format!("    error_log {};\n", error));
        }

        // Security headers
        config.push_str("\n    # Security Headers\n");
        for header in self.security_headers.generate() {
            config.push_str(&format!("    {}\n", header));
        }

        // Custom directives
        if !self.custom_directives.is_empty() {
            config.push_str("\n    # Custom Directives\n");
            for directive in &self.custom_directives {
                config.push_str(&format!("    {}\n", directive));
            }
        }

        // Locations
        if !self.locations.is_empty() {
            config.push('\n');
            for location in &self.locations {
                config.push_str(&location.generate(1));
            }
        }

        config.push_str("}\n");
        config
    }
}

/// Main Nginx configuration generator
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
    pub gzip: bool,
    pub gzip_types: Vec<String>,
}

impl Default for NginxConfigGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl NginxConfigGenerator {
    pub fn new() -> Self {
        Self {
            worker_processes: "auto".to_string(),
            worker_connections: 1024,
            multi_accept: true,
            sendfile: true,
            tcp_nopush: true,
            tcp_nodelay: true,
            keepalive_timeout: 65,
            types_hash_max_size: 2048,
            server_tokens: false,
            client_max_body_size: "16M".to_string(),
            client_body_timeout: 60,
            client_header_timeout: 60,
            send_timeout: 60,
            rate_limits: Vec::new(),
            upstreams: Vec::new(),
            servers: Vec::new(),
            gzip: true,
            gzip_types: vec![
                "text/plain".to_string(),
                "text/css".to_string(),
                "text/xml".to_string(),
                "text/javascript".to_string(),
                "application/json".to_string(),
                "application/javascript".to_string(),
                "application/xml".to_string(),
            ],
        }
    }

    pub fn worker_processes(mut self, processes: impl Into<String>) -> Self {
        self.worker_processes = processes.into();
        self
    }

    pub fn worker_connections(mut self, connections: u32) -> Self {
        self.worker_connections = connections;
        self
    }

    pub fn client_max_body_size(mut self, size: impl Into<String>) -> Self {
        self.client_max_body_size = size.into();
        self
    }

    pub fn rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limits.push(config);
        self
    }

    pub fn upstream(mut self, upstream: UpstreamConfig) -> Self {
        self.upstreams.push(upstream);
        self
    }

    pub fn server(mut self, server: ServerConfig) -> Self {
        self.servers.push(server);
        self
    }

    pub fn generate(&self) -> String {
        let mut config = String::new();

        // Main context
        config.push_str("# Nginx Security Configuration\n");
        config.push_str("# Generated by Rust Nginx Config Generator\n\n");

        config.push_str(&format!("worker_processes {};\n", self.worker_processes));
        config.push_str("error_log /var/log/nginx/error.log warn;\n");
        config.push_str("pid /var/run/nginx.pid;\n\n");

        // Events block
        config.push_str("events {\n");
        config.push_str(&format!(
            "    worker_connections {};\n",
            self.worker_connections
        ));
        if self.multi_accept {
            config.push_str("    multi_accept on;\n");
        }
        config.push_str("}\n\n");

        // HTTP block
        config.push_str("http {\n");
        config.push_str("    include /etc/nginx/mime.types;\n");
        config.push_str("    default_type application/octet-stream;\n\n");

        // Logging format
        config.push_str("    # Logging\n");
        config.push_str(
            "    log_format main '$remote_addr - $remote_user [$time_local] \"$request\" '\n",
        );
        config.push_str("                    '$status $body_bytes_sent \"$http_referer\" '\n");
        config
            .push_str("                    '\"$http_user_agent\" \"$http_x_forwarded_for\"';\n\n");

        // Performance
        config.push_str("    # Performance\n");
        config.push_str(&format!(
            "    sendfile {};\n",
            if self.sendfile { "on" } else { "off" }
        ));
        config.push_str(&format!(
            "    tcp_nopush {};\n",
            if self.tcp_nopush { "on" } else { "off" }
        ));
        config.push_str(&format!(
            "    tcp_nodelay {};\n",
            if self.tcp_nodelay { "on" } else { "off" }
        ));
        config.push_str(&format!(
            "    keepalive_timeout {};\n",
            self.keepalive_timeout
        ));
        config.push_str(&format!(
            "    types_hash_max_size {};\n\n",
            self.types_hash_max_size
        ));

        // Security
        config.push_str("    # Security\n");
        config.push_str(&format!(
            "    server_tokens {};\n",
            if self.server_tokens { "on" } else { "off" }
        ));
        config.push_str(&format!(
            "    client_max_body_size {};\n",
            self.client_max_body_size
        ));
        config.push_str(&format!(
            "    client_body_timeout {};\n",
            self.client_body_timeout
        ));
        config.push_str(&format!(
            "    client_header_timeout {};\n",
            self.client_header_timeout
        ));
        config.push_str(&format!("    send_timeout {};\n\n", self.send_timeout));

        // Gzip
        if self.gzip {
            config.push_str("    # Gzip Compression\n");
            config.push_str("    gzip on;\n");
            config.push_str("    gzip_vary on;\n");
            config.push_str("    gzip_proxied any;\n");
            config.push_str("    gzip_comp_level 6;\n");
            config.push_str(&format!(
                "    gzip_types {};\n\n",
                self.gzip_types.join(" ")
            ));
        }

        // Rate limits
        if !self.rate_limits.is_empty() {
            config.push_str("    # Rate Limiting\n");
            for limit in &self.rate_limits {
                config.push_str(&format!("    {}\n", limit.generate_zone()));
            }
            config.push('\n');
        }

        // Upstreams
        for upstream in &self.upstreams {
            config.push_str(&format!(
                "    {}",
                upstream.generate().replace('\n', "\n    ")
            ));
            config.push('\n');
        }

        // Servers
        for server in &self.servers {
            config.push_str(&format!(
                "    {}",
                server.generate().replace('\n', "\n    ")
            ));
            config.push('\n');
        }

        config.push_str("}\n");
        config
    }
}

fn main() {
    println!("=== Nginx Security Configuration Generator Demo ===\n");

    // Create rate limits
    let api_rate_limit = RateLimitConfig::new("api_limit", "10r/s")
        .zone_size("10m")
        .burst(20)
        .nodelay();

    let login_rate_limit = RateLimitConfig::new("login_limit", "1r/s")
        .zone_size("5m")
        .burst(5);

    // Create upstream
    let backend = UpstreamConfig::new("backend")
        .server(UpstreamServer::new("127.0.0.1", 8000).weight(5))
        .server(UpstreamServer::new("127.0.0.1", 8001).weight(3))
        .server(UpstreamServer::new("127.0.0.1", 8002).backup())
        .keepalive(32)
        .load_balancing(LoadBalancing::LeastConn);

    // Create security headers with CSP
    let headers = SecurityHeaders::new()
        .csp("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'")
        .permissions_policy("geolocation=(), microphone=(), camera=()")
        .hsts(31536000, true, true);

    // Create server config
    let server = ServerConfig::new("example.com", 443)
        .add_server_name("www.example.com")
        .ssl(
            "/etc/ssl/certs/example.com.crt",
            "/etc/ssl/private/example.com.key",
        )
        .dhparam("/etc/ssl/certs/dhparam.pem")
        .cipher_preset(CipherPreset::Modern)
        .root("/var/www/html")
        .access_log("/var/log/nginx/example.access.log main")
        .error_log("/var/log/nginx/example.error.log")
        .security_headers(headers)
        .location(LocationConfig::new("/").try_files("$uri $uri/ /index.html"))
        .location(
            LocationConfig::new("/api/")
                .proxy_pass("http://backend")
                .rate_limit("api_limit"),
        )
        .location(
            LocationConfig::new("/login")
                .proxy_pass("http://backend")
                .rate_limit("login_limit")
                .allow_method("POST"),
        )
        .location(
            LocationConfig::new("/admin/")
                .proxy_pass("http://backend")
                .basic_auth("Admin Area", "/etc/nginx/.htpasswd"),
        )
        .directive("# Deny access to hidden files")
        .directive("location ~ /\\. { deny all; }");

    // HTTP to HTTPS redirect
    let redirect_server = ServerConfig::new("example.com", 80)
        .add_server_name("www.example.com")
        .directive("return 301 https://$server_name$request_uri;");

    // Generate full config
    let generator = NginxConfigGenerator::new()
        .worker_connections(2048)
        .client_max_body_size("50M")
        .rate_limit(api_rate_limit)
        .rate_limit(login_rate_limit)
        .upstream(backend)
        .server(server)
        .server(redirect_server);

    println!("Generated Nginx Configuration:");
    println!("{}", "=".repeat(60));
    println!("{}", generator.generate());
    println!("{}", "=".repeat(60));

    // Show security header details
    println!("\nSecurity Headers Summary:");
    let default_headers = SecurityHeaders::default();
    for header in default_headers.generate() {
        println!("  {}", header);
    }

    println!("\n=== Demo Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_version_ordering() {
        assert!(TlsVersion::Tls13 > TlsVersion::Tls12);
        assert!(TlsVersion::Tls12 > TlsVersion::Tls11);
    }

    #[test]
    fn test_cipher_preset_modern() {
        let preset = CipherPreset::Modern;
        assert!(preset.ciphers().contains("ECDHE"));
        assert_eq!(preset.min_tls_version(), TlsVersion::Tls13);
    }

    #[test]
    fn test_security_headers_default() {
        let headers = SecurityHeaders::default();
        let generated = headers.generate();

        assert!(generated.iter().any(|h| h.contains("X-Frame-Options")));
        assert!(generated
            .iter()
            .any(|h| h.contains("X-Content-Type-Options")));
        assert!(generated
            .iter()
            .any(|h| h.contains("Strict-Transport-Security")));
    }

    #[test]
    fn test_security_headers_csp() {
        let headers = SecurityHeaders::new().csp("default-src 'self'");
        let generated = headers.generate();

        assert!(generated
            .iter()
            .any(|h| h.contains("Content-Security-Policy")));
    }

    #[test]
    fn test_rate_limit_config() {
        let config = RateLimitConfig::new("test", "10r/s")
            .zone_size("10m")
            .burst(20)
            .nodelay();

        let zone = config.generate_zone();
        assert!(zone.contains("limit_req_zone"));
        assert!(zone.contains("10r/s"));

        let limit = config.generate_limit();
        assert!(limit.contains("burst=20"));
        assert!(limit.contains("nodelay"));
    }

    #[test]
    fn test_upstream_server() {
        let server = UpstreamServer::new("127.0.0.1", 8000)
            .weight(5)
            .max_fails(3)
            .fail_timeout("30s");

        let generated = server.generate();
        assert!(generated.contains("127.0.0.1:8000"));
        assert!(generated.contains("weight=5"));
        assert!(generated.contains("max_fails=3"));
    }

    #[test]
    fn test_upstream_config() {
        let upstream = UpstreamConfig::new("backend")
            .server(UpstreamServer::new("127.0.0.1", 8000))
            .load_balancing(LoadBalancing::LeastConn)
            .keepalive(32);

        let generated = upstream.generate();
        assert!(generated.contains("upstream backend"));
        assert!(generated.contains("least_conn"));
        assert!(generated.contains("keepalive 32"));
    }

    #[test]
    fn test_location_config_proxy() {
        let location = LocationConfig::new("/api/")
            .proxy_pass("http://backend")
            .rate_limit("api_limit");

        let generated = location.generate(0);
        assert!(generated.contains("location /api/"));
        assert!(generated.contains("proxy_pass http://backend"));
        assert!(generated.contains("limit_req zone=api_limit"));
    }

    #[test]
    fn test_location_config_static() {
        let location = LocationConfig::new("/")
            .root("/var/www/html")
            .try_files("$uri $uri/ /index.html");

        let generated = location.generate(0);
        assert!(generated.contains("root /var/www/html"));
        assert!(generated.contains("try_files"));
    }

    #[test]
    fn test_server_config_basic() {
        let server = ServerConfig::new("example.com", 80);
        let generated = server.generate();

        assert!(generated.contains("server {"));
        assert!(generated.contains("listen 80"));
        assert!(generated.contains("server_name example.com"));
    }

    #[test]
    fn test_server_config_ssl() {
        let server =
            ServerConfig::new("example.com", 443).ssl("/path/to/cert.crt", "/path/to/key.key");

        let generated = server.generate();
        assert!(generated.contains("listen 443 ssl"));
        assert!(generated.contains("ssl_certificate"));
        assert!(generated.contains("ssl_certificate_key"));
    }

    #[test]
    fn test_server_config_cipher_preset() {
        let server = ServerConfig::new("example.com", 443)
            .ssl("/cert.crt", "/key.key")
            .cipher_preset(CipherPreset::Modern);

        let generated = server.generate();
        assert!(generated.contains("TLSv1.3"));
    }

    #[test]
    fn test_nginx_generator() {
        let generator = NginxConfigGenerator::new()
            .worker_connections(2048)
            .server(ServerConfig::new("example.com", 80));

        let generated = generator.generate();
        assert!(generated.contains("worker_processes auto"));
        assert!(generated.contains("worker_connections 2048"));
        assert!(generated.contains("server_tokens off"));
    }

    #[test]
    fn test_hsts_config() {
        let headers = SecurityHeaders::new().hsts(31536000, true, true);
        let generated = headers.generate();

        let hsts = generated
            .iter()
            .find(|h| h.contains("Strict-Transport-Security"))
            .unwrap();
        assert!(hsts.contains("max-age=31536000"));
        assert!(hsts.contains("includeSubDomains"));
        assert!(hsts.contains("preload"));
    }

    #[test]
    fn test_location_basic_auth() {
        let location =
            LocationConfig::new("/admin/").basic_auth("Admin Area", "/etc/nginx/.htpasswd");

        let generated = location.generate(0);
        assert!(generated.contains("auth_basic \"Admin Area\""));
        assert!(generated.contains("auth_basic_user_file"));
    }

    #[test]
    fn test_load_balancing_methods() {
        let upstream_ip = UpstreamConfig::new("test")
            .load_balancing(LoadBalancing::IpHash)
            .server(UpstreamServer::new("127.0.0.1", 8000));
        assert!(upstream_ip.generate().contains("ip_hash"));

        let upstream_least = UpstreamConfig::new("test")
            .load_balancing(LoadBalancing::LeastConn)
            .server(UpstreamServer::new("127.0.0.1", 8000));
        assert!(upstream_least.generate().contains("least_conn"));
    }

    #[test]
    fn test_gzip_config() {
        let generator = NginxConfigGenerator::new();
        let generated = generator.generate();

        assert!(generated.contains("gzip on"));
        assert!(generated.contains("gzip_types"));
    }

    #[test]
    fn test_location_method_restriction() {
        let location = LocationConfig::new("/api/")
            .allow_method("GET")
            .allow_method("POST");

        let generated = location.generate(0);
        assert!(generated.contains("limit_except"));
    }

    #[test]
    fn test_custom_header() {
        let headers = SecurityHeaders::new().custom_header("X-Custom-Header", "custom-value");

        let generated = headers.generate();
        assert!(generated.iter().any(|h| h.contains("X-Custom-Header")));
    }
}
