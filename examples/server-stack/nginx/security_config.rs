//! Nginx Security Configuration Generator Example
//!
//! Demonstrates generating security-hardened Nginx configurations
//! with proper TLS settings, headers, and rate limiting.

use std::collections::HashMap;

/// TLS configuration level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsLevel {
    Modern,       // TLS 1.3 only
    Intermediate, // TLS 1.2 + 1.3
    Old,          // TLS 1.0 + 1.1 + 1.2 + 1.3 (not recommended)
}

impl TlsLevel {
    pub fn protocols(&self) -> &'static str {
        match self {
            TlsLevel::Modern => "TLSv1.3",
            TlsLevel::Intermediate => "TLSv1.2 TLSv1.3",
            TlsLevel::Old => "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3",
        }
    }

    pub fn ciphers(&self) -> &'static str {
        match self {
            TlsLevel::Modern => "", // TLS 1.3 handles ciphers automatically
            TlsLevel::Intermediate => {
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
                 ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
                 ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
                 DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
            }
            TlsLevel::Old => {
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
                 ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
                 ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
                 DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:\
                 DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA256"
            }
        }
    }
}

/// Security headers configuration
#[derive(Debug, Clone)]
pub struct SecurityHeaders {
    pub hsts: HstsConfig,
    pub csp: Option<String>,
    pub x_frame_options: String,
    pub x_content_type_options: bool,
    pub x_xss_protection: bool,
    pub referrer_policy: String,
    pub permissions_policy: Option<String>,
    pub custom_headers: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct HstsConfig {
    pub enabled: bool,
    pub max_age: u64,
    pub include_subdomains: bool,
    pub preload: bool,
}

impl Default for HstsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_age: 31536000, // 1 year
            include_subdomains: true,
            preload: true,
        }
    }
}

impl HstsConfig {
    pub fn to_header_value(&self) -> String {
        if !self.enabled {
            return String::new();
        }

        let mut value = format!("max-age={}", self.max_age);
        if self.include_subdomains {
            value.push_str("; includeSubDomains");
        }
        if self.preload {
            value.push_str("; preload");
        }
        value
    }
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self {
            hsts: HstsConfig::default(),
            csp: Some("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'".to_string()),
            x_frame_options: "DENY".to_string(),
            x_content_type_options: true,
            x_xss_protection: true,
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
            permissions_policy: Some("accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()".to_string()),
            custom_headers: HashMap::new(),
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub zone_name: String,
    pub zone_size: String,
    pub rate: String,
    pub burst: u32,
    pub nodelay: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            zone_name: "api_limit".to_string(),
            zone_size: "10m".to_string(),
            rate: "10r/s".to_string(),
            burst: 20,
            nodelay: true,
        }
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
}

impl UpstreamServer {
    pub fn new(address: &str, port: u16) -> Self {
        Self {
            address: address.to_string(),
            port,
            weight: None,
            max_fails: Some(3),
            fail_timeout: Some("30s".to_string()),
            backup: false,
        }
    }

    pub fn to_nginx(&self) -> String {
        let mut line = format!("server {}:{}", self.address, self.port);

        if let Some(w) = self.weight {
            line.push_str(&format!(" weight={}", w));
        }

        if let Some(mf) = self.max_fails {
            line.push_str(&format!(" max_fails={}", mf));
        }

        if let Some(ref ft) = self.fail_timeout {
            line.push_str(&format!(" fail_timeout={}", ft));
        }

        if self.backup {
            line.push_str(" backup");
        }

        line.push(';');
        line
    }
}

/// Location block configuration
#[derive(Debug, Clone)]
pub struct LocationConfig {
    pub path: String,
    pub proxy_pass: Option<String>,
    pub root: Option<String>,
    pub index: Option<String>,
    pub try_files: Option<String>,
    pub rate_limit: bool,
    pub auth_basic: Option<String>,
    pub deny_all: bool,
    pub custom_directives: Vec<String>,
}

impl LocationConfig {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
            proxy_pass: None,
            root: None,
            index: None,
            try_files: None,
            rate_limit: false,
            auth_basic: None,
            deny_all: false,
            custom_directives: Vec::new(),
        }
    }

    pub fn proxy(path: &str, upstream: &str) -> Self {
        Self {
            path: path.to_string(),
            proxy_pass: Some(upstream.to_string()),
            root: None,
            index: None,
            try_files: None,
            rate_limit: false,
            auth_basic: None,
            deny_all: false,
            custom_directives: Vec::new(),
        }
    }

    pub fn static_files(path: &str, root: &str) -> Self {
        Self {
            path: path.to_string(),
            proxy_pass: None,
            root: Some(root.to_string()),
            index: Some("index.html".to_string()),
            try_files: Some("$uri $uri/ =404".to_string()),
            rate_limit: false,
            auth_basic: None,
            deny_all: false,
            custom_directives: Vec::new(),
        }
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
    pub tls_level: TlsLevel,
    pub root: Option<String>,
    pub locations: Vec<LocationConfig>,
    pub security_headers: SecurityHeaders,
    pub rate_limit: Option<RateLimitConfig>,
    pub access_log: Option<String>,
    pub error_log: Option<String>,
}

impl ServerConfig {
    pub fn new(server_name: &str) -> Self {
        Self {
            server_name: vec![server_name.to_string()],
            listen_port: 443,
            listen_ssl: true,
            ssl_certificate: None,
            ssl_certificate_key: None,
            tls_level: TlsLevel::Modern,
            root: None,
            locations: Vec::new(),
            security_headers: SecurityHeaders::default(),
            rate_limit: None,
            access_log: None,
            error_log: None,
        }
    }

    pub fn with_ssl(mut self, cert: &str, key: &str) -> Self {
        self.ssl_certificate = Some(cert.to_string());
        self.ssl_certificate_key = Some(key.to_string());
        self.listen_ssl = true;
        self
    }

    pub fn with_tls_level(mut self, level: TlsLevel) -> Self {
        self.tls_level = level;
        self
    }

    pub fn add_location(&mut self, location: LocationConfig) {
        self.locations.push(location);
    }
}

/// Complete Nginx configuration generator
pub struct NginxConfigGenerator {
    pub worker_processes: String,
    pub worker_connections: u32,
    pub upstreams: HashMap<String, Vec<UpstreamServer>>,
    pub servers: Vec<ServerConfig>,
    pub rate_limit_zones: Vec<RateLimitConfig>,
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
            upstreams: HashMap::new(),
            servers: Vec::new(),
            rate_limit_zones: Vec::new(),
        }
    }

    pub fn add_upstream(&mut self, name: &str, servers: Vec<UpstreamServer>) {
        self.upstreams.insert(name.to_string(), servers);
    }

    pub fn add_server(&mut self, server: ServerConfig) {
        self.servers.push(server);
    }

    pub fn add_rate_limit_zone(&mut self, config: RateLimitConfig) {
        self.rate_limit_zones.push(config);
    }

    /// Generate the complete nginx.conf
    pub fn generate(&self) -> String {
        let mut config = String::new();

        // Main context
        config.push_str("# Generated by syntek-rust-security\n");
        config.push_str("# Security-hardened Nginx configuration\n\n");

        config.push_str(&format!("worker_processes {};\n", self.worker_processes));
        config.push_str("error_log /var/log/nginx/error.log warn;\n");
        config.push_str("pid /var/run/nginx.pid;\n\n");

        // Events context
        config.push_str("events {\n");
        config.push_str(&format!(
            "    worker_connections {};\n",
            self.worker_connections
        ));
        config.push_str("    use epoll;\n");
        config.push_str("    multi_accept on;\n");
        config.push_str("}\n\n");

        // HTTP context
        config.push_str("http {\n");
        config.push_str(&self.generate_http_block());
        config.push_str("}\n");

        config
    }

    fn generate_http_block(&self) -> String {
        let mut http = String::new();
        let indent = "    ";

        // Basic settings
        http.push_str(&format!("{}include /etc/nginx/mime.types;\n", indent));
        http.push_str(&format!(
            "{}default_type application/octet-stream;\n\n",
            indent
        ));

        // Logging format
        http.push_str(&format!(
            "{}log_format main '$remote_addr - $remote_user [$time_local] '\n",
            indent
        ));
        http.push_str(&format!(
            "{}                '\"$request\" $status $body_bytes_sent '\n",
            indent
        ));
        http.push_str(&format!(
            "{}                '\"$http_referer\" \"$http_user_agent\"';\n\n",
            indent
        ));

        // Security settings
        http.push_str(&format!("{}# Security settings\n", indent));
        http.push_str(&format!("{}server_tokens off;\n", indent));
        http.push_str(&format!("{}more_clear_headers Server;\n", indent));
        http.push_str(&format!("{}more_clear_headers X-Powered-By;\n\n", indent));

        // Performance settings
        http.push_str(&format!("{}# Performance\n", indent));
        http.push_str(&format!("{}sendfile on;\n", indent));
        http.push_str(&format!("{}tcp_nopush on;\n", indent));
        http.push_str(&format!("{}tcp_nodelay on;\n", indent));
        http.push_str(&format!("{}keepalive_timeout 65;\n\n", indent));

        // Gzip settings
        http.push_str(&format!("{}# Compression\n", indent));
        http.push_str(&format!("{}gzip on;\n", indent));
        http.push_str(&format!("{}gzip_vary on;\n", indent));
        http.push_str(&format!("{}gzip_min_length 1024;\n", indent));
        http.push_str(&format!("{}gzip_types text/plain text/css application/json application/javascript text/xml application/xml;\n\n", indent));

        // Rate limit zones
        for zone in &self.rate_limit_zones {
            http.push_str(&format!(
                "{}limit_req_zone $binary_remote_addr zone={}:{} rate={};\n",
                indent, zone.zone_name, zone.zone_size, zone.rate
            ));
        }
        if !self.rate_limit_zones.is_empty() {
            http.push('\n');
        }

        // Upstreams
        for (name, servers) in &self.upstreams {
            http.push_str(&format!("{}upstream {} {{\n", indent, name));
            http.push_str(&format!("{}    least_conn;\n", indent));
            for server in servers {
                http.push_str(&format!("{}    {}\n", indent, server.to_nginx()));
            }
            http.push_str(&format!("{}}}\n\n", indent));
        }

        // Server blocks
        for server in &self.servers {
            http.push_str(&self.generate_server_block(server, indent));
            http.push('\n');
        }

        http
    }

    fn generate_server_block(&self, server: &ServerConfig, indent: &str) -> String {
        let mut block = String::new();

        block.push_str(&format!("{}server {{\n", indent));

        // Listen directive
        let listen = if server.listen_ssl {
            format!("{}    listen {} ssl http2;\n", indent, server.listen_port)
        } else {
            format!("{}    listen {};\n", indent, server.listen_port)
        };
        block.push_str(&listen);

        // Server name
        block.push_str(&format!(
            "{}    server_name {};\n\n",
            indent,
            server.server_name.join(" ")
        ));

        // SSL configuration
        if server.listen_ssl {
            if let (Some(ref cert), Some(ref key)) =
                (&server.ssl_certificate, &server.ssl_certificate_key)
            {
                block.push_str(&format!("{}    # TLS Configuration\n", indent));
                block.push_str(&format!("{}    ssl_certificate {};\n", indent, cert));
                block.push_str(&format!("{}    ssl_certificate_key {};\n", indent, key));
                block.push_str(&format!(
                    "{}    ssl_protocols {};\n",
                    indent,
                    server.tls_level.protocols()
                ));

                if server.tls_level != TlsLevel::Modern {
                    block.push_str(&format!(
                        "{}    ssl_ciphers {};\n",
                        indent,
                        server.tls_level.ciphers()
                    ));
                    block.push_str(&format!("{}    ssl_prefer_server_ciphers on;\n", indent));
                }

                block.push_str(&format!(
                    "{}    ssl_session_cache shared:SSL:10m;\n",
                    indent
                ));
                block.push_str(&format!("{}    ssl_session_timeout 1d;\n", indent));
                block.push_str(&format!("{}    ssl_session_tickets off;\n\n", indent));
            }
        }

        // Security headers
        block.push_str(&format!("{}    # Security Headers\n", indent));

        if server.security_headers.hsts.enabled {
            block.push_str(&format!(
                "{}    add_header Strict-Transport-Security \"{}\" always;\n",
                indent,
                server.security_headers.hsts.to_header_value()
            ));
        }

        if let Some(ref csp) = server.security_headers.csp {
            block.push_str(&format!(
                "{}    add_header Content-Security-Policy \"{}\" always;\n",
                indent, csp
            ));
        }

        block.push_str(&format!(
            "{}    add_header X-Frame-Options \"{}\" always;\n",
            indent, server.security_headers.x_frame_options
        ));

        if server.security_headers.x_content_type_options {
            block.push_str(&format!(
                "{}    add_header X-Content-Type-Options \"nosniff\" always;\n",
                indent
            ));
        }

        block.push_str(&format!(
            "{}    add_header Referrer-Policy \"{}\" always;\n",
            indent, server.security_headers.referrer_policy
        ));

        if let Some(ref pp) = server.security_headers.permissions_policy {
            block.push_str(&format!(
                "{}    add_header Permissions-Policy \"{}\" always;\n",
                indent, pp
            ));
        }

        block.push('\n');

        // Root directory
        if let Some(ref root) = server.root {
            block.push_str(&format!("{}    root {};\n\n", indent, root));
        }

        // Location blocks
        for location in &server.locations {
            block.push_str(&self.generate_location_block(location, indent));
        }

        block.push_str(&format!("{}}}\n", indent));

        block
    }

    fn generate_location_block(&self, location: &LocationConfig, indent: &str) -> String {
        let mut block = String::new();

        block.push_str(&format!("{}    location {} {{\n", indent, location.path));

        if location.deny_all {
            block.push_str(&format!("{}        deny all;\n", indent));
        }

        if let Some(ref auth) = location.auth_basic {
            block.push_str(&format!("{}        auth_basic \"{}\";\n", indent, auth));
            block.push_str(&format!(
                "{}        auth_basic_user_file /etc/nginx/.htpasswd;\n",
                indent
            ));
        }

        if location.rate_limit {
            block.push_str(&format!(
                "{}        limit_req zone=api_limit burst=20 nodelay;\n",
                indent
            ));
        }

        if let Some(ref proxy) = location.proxy_pass {
            block.push_str(&format!("{}        proxy_pass {};\n", indent, proxy));
            block.push_str(&format!("{}        proxy_set_header Host $host;\n", indent));
            block.push_str(&format!(
                "{}        proxy_set_header X-Real-IP $remote_addr;\n",
                indent
            ));
            block.push_str(&format!(
                "{}        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n",
                indent
            ));
            block.push_str(&format!(
                "{}        proxy_set_header X-Forwarded-Proto $scheme;\n",
                indent
            ));
        }

        if let Some(ref root) = location.root {
            block.push_str(&format!("{}        root {};\n", indent, root));
        }

        if let Some(ref index) = location.index {
            block.push_str(&format!("{}        index {};\n", indent, index));
        }

        if let Some(ref try_files) = location.try_files {
            block.push_str(&format!("{}        try_files {};\n", indent, try_files));
        }

        for directive in &location.custom_directives {
            block.push_str(&format!("{}        {}\n", indent, directive));
        }

        block.push_str(&format!("{}    }}\n\n", indent));

        block
    }
}

fn main() {
    println!("Nginx Security Configuration Generator Example");
    println!("===============================================\n");

    // Create configuration generator
    let mut generator = NginxConfigGenerator::new();

    // Add upstream servers
    generator.add_upstream(
        "backend",
        vec![
            UpstreamServer::new("127.0.0.1", 8000),
            UpstreamServer::new("127.0.0.1", 8001),
        ],
    );

    // Add rate limit zone
    generator.add_rate_limit_zone(RateLimitConfig::default());

    // Create server configuration
    let mut server = ServerConfig::new("example.com")
        .with_ssl(
            "/etc/ssl/certs/example.com.crt",
            "/etc/ssl/private/example.com.key",
        )
        .with_tls_level(TlsLevel::Modern);

    server.server_name.push("www.example.com".to_string());
    server.root = Some("/var/www/html".to_string());

    // Add locations
    server.add_location(LocationConfig::static_files("/", "/var/www/html"));

    let mut api_location = LocationConfig::proxy("/api/", "http://backend");
    api_location.rate_limit = true;
    server.add_location(api_location);

    // Block sensitive paths
    let mut hidden = LocationConfig::new("~ /\\.");
    hidden.deny_all = true;
    server.add_location(hidden);

    generator.add_server(server);

    // Generate and print configuration
    let config = generator.generate();
    println!("{}", config);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_level_modern() {
        assert_eq!(TlsLevel::Modern.protocols(), "TLSv1.3");
    }

    #[test]
    fn test_tls_level_intermediate() {
        assert_eq!(TlsLevel::Intermediate.protocols(), "TLSv1.2 TLSv1.3");
        assert!(TlsLevel::Intermediate.ciphers().contains("ECDHE"));
    }

    #[test]
    fn test_hsts_header() {
        let hsts = HstsConfig::default();
        let value = hsts.to_header_value();

        assert!(value.contains("max-age=31536000"));
        assert!(value.contains("includeSubDomains"));
        assert!(value.contains("preload"));
    }

    #[test]
    fn test_upstream_server() {
        let server = UpstreamServer::new("127.0.0.1", 8000);
        let nginx = server.to_nginx();

        assert!(nginx.contains("127.0.0.1:8000"));
        assert!(nginx.contains("max_fails=3"));
    }

    #[test]
    fn test_location_proxy() {
        let location = LocationConfig::proxy("/api/", "http://backend");

        assert_eq!(location.path, "/api/");
        assert_eq!(location.proxy_pass, Some("http://backend".to_string()));
    }

    #[test]
    fn test_server_config_builder() {
        let server = ServerConfig::new("example.com")
            .with_ssl("/cert.pem", "/key.pem")
            .with_tls_level(TlsLevel::Intermediate);

        assert_eq!(server.server_name, vec!["example.com"]);
        assert!(server.ssl_certificate.is_some());
        assert_eq!(server.tls_level, TlsLevel::Intermediate);
    }

    #[test]
    fn test_config_generation() {
        let mut generator = NginxConfigGenerator::new();

        let server = ServerConfig::new("test.com");
        generator.add_server(server);

        let config = generator.generate();

        assert!(config.contains("worker_processes"));
        assert!(config.contains("server_name test.com"));
    }
}
