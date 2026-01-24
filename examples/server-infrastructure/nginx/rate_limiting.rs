//! Nginx Rate Limiting Configuration Generator
//!
//! This example demonstrates generating security-hardened Nginx
//! rate limiting configurations with zone management, burst handling,
//! and DDoS protection patterns.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

// ============================================================================
// Rate Limiting Types
// ============================================================================

/// Rate limit unit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateUnit {
    PerSecond,
    PerMinute,
    PerHour,
}

impl RateUnit {
    pub fn as_nginx_suffix(&self) -> &'static str {
        match self {
            RateUnit::PerSecond => "r/s",
            RateUnit::PerMinute => "r/m",
            RateUnit::PerHour => "r/h",
        }
    }

    pub fn to_seconds(&self) -> u64 {
        match self {
            RateUnit::PerSecond => 1,
            RateUnit::PerMinute => 60,
            RateUnit::PerHour => 3600,
        }
    }
}

/// Rate limit zone definition
#[derive(Debug, Clone)]
pub struct RateLimitZone {
    /// Zone name
    pub name: String,
    /// Key expression (e.g., $binary_remote_addr)
    pub key: String,
    /// Zone memory size
    pub size: String,
    /// Rate limit
    pub rate: u32,
    /// Rate unit
    pub unit: RateUnit,
    /// Optional sync for clustering
    pub sync: bool,
}

impl RateLimitZone {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            key: "$binary_remote_addr".to_string(),
            size: "10m".to_string(),
            rate: 10,
            unit: RateUnit::PerSecond,
            sync: false,
        }
    }

    pub fn key(mut self, key: &str) -> Self {
        self.key = key.to_string();
        self
    }

    pub fn size(mut self, size: &str) -> Self {
        self.size = size.to_string();
        self
    }

    pub fn rate(mut self, rate: u32, unit: RateUnit) -> Self {
        self.rate = rate;
        self.unit = unit;
        self
    }

    pub fn with_sync(mut self) -> Self {
        self.sync = true;
        self
    }

    /// Generate nginx config directive
    pub fn to_nginx(&self) -> String {
        let mut directive = format!(
            "limit_req_zone {} zone={}:{} rate={}{}",
            self.key,
            self.name,
            self.size,
            self.rate,
            self.unit.as_nginx_suffix()
        );

        if self.sync {
            directive.push_str(" sync");
        }

        format!("{};", directive)
    }
}

/// Rate limit application
#[derive(Debug, Clone)]
pub struct RateLimitRule {
    /// Zone name to use
    pub zone: String,
    /// Burst size
    pub burst: Option<u32>,
    /// Use nodelay
    pub nodelay: bool,
    /// Delay after N requests
    pub delay: Option<u32>,
    /// Dry run (log only)
    pub dry_run: bool,
}

impl RateLimitRule {
    pub fn new(zone: &str) -> Self {
        Self {
            zone: zone.to_string(),
            burst: None,
            nodelay: false,
            delay: None,
            dry_run: false,
        }
    }

    pub fn burst(mut self, burst: u32) -> Self {
        self.burst = Some(burst);
        self
    }

    pub fn nodelay(mut self) -> Self {
        self.nodelay = true;
        self
    }

    pub fn delay(mut self, delay: u32) -> Self {
        self.delay = Some(delay);
        self
    }

    pub fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    pub fn to_nginx(&self) -> String {
        let mut parts = vec![format!("limit_req zone={}", self.zone)];

        if let Some(burst) = self.burst {
            parts.push(format!("burst={}", burst));
        }

        if self.nodelay {
            parts.push("nodelay".to_string());
        } else if let Some(delay) = self.delay {
            parts.push(format!("delay={}", delay));
        }

        if self.dry_run {
            // Use limit_req_dry_run separately
        }

        format!("{};", parts.join(" "))
    }
}

// ============================================================================
// Connection Limiting
// ============================================================================

/// Connection limit zone
#[derive(Debug, Clone)]
pub struct ConnectionLimitZone {
    pub name: String,
    pub key: String,
    pub size: String,
}

impl ConnectionLimitZone {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            key: "$binary_remote_addr".to_string(),
            size: "10m".to_string(),
        }
    }

    pub fn key(mut self, key: &str) -> Self {
        self.key = key.to_string();
        self
    }

    pub fn size(mut self, size: &str) -> Self {
        self.size = size.to_string();
        self
    }

    pub fn to_nginx(&self) -> String {
        format!(
            "limit_conn_zone {} zone={}:{};",
            self.key, self.name, self.size
        )
    }
}

/// Connection limit rule
#[derive(Debug, Clone)]
pub struct ConnectionLimitRule {
    pub zone: String,
    pub limit: u32,
}

impl ConnectionLimitRule {
    pub fn new(zone: &str, limit: u32) -> Self {
        Self {
            zone: zone.to_string(),
            limit,
        }
    }

    pub fn to_nginx(&self) -> String {
        format!("limit_conn {} {};", self.zone, self.limit)
    }
}

// ============================================================================
// Bandwidth Limiting
// ============================================================================

/// Bandwidth limit configuration
#[derive(Debug, Clone)]
pub struct BandwidthLimit {
    /// Rate limit (e.g., "1m" for 1 megabyte/sec)
    pub rate: String,
    /// Bytes before limiting kicks in
    pub after: Option<String>,
}

impl BandwidthLimit {
    pub fn new(rate: &str) -> Self {
        Self {
            rate: rate.to_string(),
            after: None,
        }
    }

    pub fn after(mut self, bytes: &str) -> Self {
        self.after = Some(bytes.to_string());
        self
    }

    pub fn to_nginx(&self) -> Vec<String> {
        let mut lines = vec![format!("limit_rate {};", self.rate)];

        if let Some(after) = &self.after {
            lines.push(format!("limit_rate_after {};", after));
        }

        lines
    }
}

// ============================================================================
// DDoS Protection
// ============================================================================

/// DDoS protection profile
#[derive(Debug, Clone)]
pub struct DdosProtection {
    /// Enable SYN flood protection
    pub syn_flood_protection: bool,
    /// Rate limit per IP
    pub per_ip_rate: u32,
    /// Burst allowance
    pub burst: u32,
    /// Connection limit per IP
    pub conn_limit: u32,
    /// Request body size limit
    pub body_size_limit: String,
    /// Enable GeoIP blocking
    pub geo_blocking: bool,
    /// Blocked countries (ISO codes)
    pub blocked_countries: Vec<String>,
    /// Whitelisted IPs
    pub whitelist: Vec<String>,
}

impl Default for DdosProtection {
    fn default() -> Self {
        Self {
            syn_flood_protection: true,
            per_ip_rate: 10,
            burst: 20,
            conn_limit: 10,
            body_size_limit: "10m".to_string(),
            geo_blocking: false,
            blocked_countries: Vec::new(),
            whitelist: Vec::new(),
        }
    }
}

impl DdosProtection {
    pub fn aggressive() -> Self {
        Self {
            syn_flood_protection: true,
            per_ip_rate: 5,
            burst: 10,
            conn_limit: 5,
            body_size_limit: "1m".to_string(),
            geo_blocking: false,
            blocked_countries: Vec::new(),
            whitelist: Vec::new(),
        }
    }

    pub fn relaxed() -> Self {
        Self {
            syn_flood_protection: true,
            per_ip_rate: 50,
            burst: 100,
            conn_limit: 50,
            body_size_limit: "50m".to_string(),
            geo_blocking: false,
            blocked_countries: Vec::new(),
            whitelist: Vec::new(),
        }
    }

    pub fn with_geo_blocking(mut self, countries: Vec<&str>) -> Self {
        self.geo_blocking = true;
        self.blocked_countries = countries.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_whitelist(mut self, ips: Vec<&str>) -> Self {
        self.whitelist = ips.iter().map(|s| s.to_string()).collect();
        self
    }
}

// ============================================================================
// API Rate Limiting
// ============================================================================

/// API endpoint rate limiting
#[derive(Debug, Clone)]
pub struct ApiRateLimit {
    /// Endpoint pattern
    pub endpoint: String,
    /// Rate limit
    pub rate: u32,
    /// Rate unit
    pub unit: RateUnit,
    /// Burst
    pub burst: u32,
    /// Return status on limit
    pub limit_status: u16,
    /// Rate limit by API key
    pub by_api_key: bool,
}

impl ApiRateLimit {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            rate: 100,
            unit: RateUnit::PerMinute,
            burst: 20,
            limit_status: 429,
            by_api_key: false,
        }
    }

    pub fn rate(mut self, rate: u32, unit: RateUnit) -> Self {
        self.rate = rate;
        self.unit = unit;
        self
    }

    pub fn burst(mut self, burst: u32) -> Self {
        self.burst = burst;
        self
    }

    pub fn by_api_key(mut self) -> Self {
        self.by_api_key = true;
        self
    }

    pub fn limit_status(mut self, status: u16) -> Self {
        self.limit_status = status;
        self
    }
}

/// Tier-based rate limiting
#[derive(Debug, Clone)]
pub struct RateLimitTier {
    pub name: String,
    pub rate: u32,
    pub unit: RateUnit,
    pub burst: u32,
    pub daily_limit: Option<u32>,
}

impl RateLimitTier {
    pub fn free() -> Self {
        Self {
            name: "free".to_string(),
            rate: 10,
            unit: RateUnit::PerMinute,
            burst: 5,
            daily_limit: Some(1000),
        }
    }

    pub fn basic() -> Self {
        Self {
            name: "basic".to_string(),
            rate: 60,
            unit: RateUnit::PerMinute,
            burst: 20,
            daily_limit: Some(10000),
        }
    }

    pub fn pro() -> Self {
        Self {
            name: "pro".to_string(),
            rate: 300,
            unit: RateUnit::PerMinute,
            burst: 50,
            daily_limit: Some(100000),
        }
    }

    pub fn enterprise() -> Self {
        Self {
            name: "enterprise".to_string(),
            rate: 1000,
            unit: RateUnit::PerMinute,
            burst: 200,
            daily_limit: None,
        }
    }
}

// ============================================================================
// Configuration Generator
// ============================================================================

/// Nginx rate limiting configuration generator
pub struct RateLimitConfig {
    /// Rate limit zones
    pub zones: Vec<RateLimitZone>,
    /// Connection limit zones
    pub conn_zones: Vec<ConnectionLimitZone>,
    /// HTTP context rules
    pub http_rules: Vec<String>,
    /// Server context rules
    pub server_rules: Vec<String>,
    /// Location-specific rules
    pub location_rules: HashMap<String, Vec<String>>,
    /// DDoS protection settings
    pub ddos: Option<DdosProtection>,
    /// API rate limits
    pub api_limits: Vec<ApiRateLimit>,
    /// Rate limit tiers
    pub tiers: Vec<RateLimitTier>,
    /// Custom variables
    pub variables: HashMap<String, String>,
}

impl RateLimitConfig {
    pub fn new() -> Self {
        Self {
            zones: Vec::new(),
            conn_zones: Vec::new(),
            http_rules: Vec::new(),
            server_rules: Vec::new(),
            location_rules: HashMap::new(),
            ddos: None,
            api_limits: Vec::new(),
            tiers: Vec::new(),
            variables: HashMap::new(),
        }
    }

    /// Add a rate limit zone
    pub fn add_zone(mut self, zone: RateLimitZone) -> Self {
        self.zones.push(zone);
        self
    }

    /// Add a connection limit zone
    pub fn add_conn_zone(mut self, zone: ConnectionLimitZone) -> Self {
        self.conn_zones.push(zone);
        self
    }

    /// Enable DDoS protection
    pub fn with_ddos_protection(mut self, ddos: DdosProtection) -> Self {
        self.ddos = Some(ddos);
        self
    }

    /// Add API rate limit
    pub fn add_api_limit(mut self, limit: ApiRateLimit) -> Self {
        self.api_limits.push(limit);
        self
    }

    /// Add rate limit tier
    pub fn add_tier(mut self, tier: RateLimitTier) -> Self {
        self.tiers.push(tier);
        self
    }

    /// Generate complete configuration
    pub fn generate(&self) -> GeneratedConfig {
        let mut config = GeneratedConfig::new();

        // HTTP context
        config.add_section("# Rate Limiting Configuration");
        config.add_section("# Generated by syntek-rust-security\n");

        // Zone definitions
        config.add_section("# Rate limit zones");
        for zone in &self.zones {
            config.add_line(&zone.to_nginx());
        }

        for zone in &self.conn_zones {
            config.add_line(&zone.to_nginx());
        }

        // DDoS protection zones
        if let Some(ddos) = &self.ddos {
            config.add_section("\n# DDoS protection zones");
            config.add_line(&format!(
                "limit_req_zone $binary_remote_addr zone=ddos_protection:20m rate={}r/s;",
                ddos.per_ip_rate
            ));
            config.add_line(&format!(
                "limit_conn_zone $binary_remote_addr zone=conn_ddos:10m;"
            ));
        }

        // Tier zones
        if !self.tiers.is_empty() {
            config.add_section("\n# API tier zones");
            for tier in &self.tiers {
                config.add_line(&format!(
                    "limit_req_zone $api_key zone=tier_{}:10m rate={}{};",
                    tier.name,
                    tier.rate,
                    tier.unit.as_nginx_suffix()
                ));
            }
        }

        // API endpoint zones
        for api in &self.api_limits {
            let key = if api.by_api_key {
                "$http_x_api_key"
            } else {
                "$binary_remote_addr"
            };

            let zone_name = api.endpoint.replace("/", "_").replace("*", "any");
            config.add_line(&format!(
                "limit_req_zone {} zone=api{}:10m rate={}{};",
                key,
                zone_name,
                api.rate,
                api.unit.as_nginx_suffix()
            ));
        }

        // Error responses
        config.add_section("\n# Rate limit error responses");
        config.add_line("limit_req_status 429;");
        config.add_line("limit_conn_status 429;");

        // Logging
        config.add_section("\n# Rate limit logging");
        config.add_line("limit_req_log_level warn;");
        config.add_line("limit_conn_log_level warn;");

        // Whitelist map
        if let Some(ddos) = &self.ddos {
            if !ddos.whitelist.is_empty() {
                config.add_section("\n# Whitelist map");
                config.add_line("map $remote_addr $is_whitelisted {");
                config.add_line("    default 0;");
                for ip in &ddos.whitelist {
                    config.add_line(&format!("    {} 1;", ip));
                }
                config.add_line("}");
            }

            // Geo blocking
            if ddos.geo_blocking && !ddos.blocked_countries.is_empty() {
                config.add_section("\n# Geo blocking");
                config.add_line("# Requires ngx_http_geoip2_module");
                config.add_line("map $geoip2_country_code $blocked_country {");
                config.add_line("    default 0;");
                for country in &ddos.blocked_countries {
                    config.add_line(&format!("    {} 1;", country));
                }
                config.add_line("}");
            }
        }

        // Tier mapping
        if !self.tiers.is_empty() {
            config.add_section("\n# API tier mapping");
            config.add_line("map $http_x_api_key $api_tier {");
            config.add_line("    default free;");
            config.add_line("    # Add API keys and their tiers here");
            config.add_line("    # \"key123\" basic;");
            config.add_line("    # \"key456\" pro;");
            config.add_line("}");
        }

        config
    }

    /// Generate server block configuration
    pub fn generate_server_block(&self) -> GeneratedConfig {
        let mut config = GeneratedConfig::new();

        config.add_section("# Server-level rate limiting\n");

        // Apply DDoS protection
        if let Some(ddos) = &self.ddos {
            config.add_line(&format!(
                "limit_req zone=ddos_protection burst={} nodelay;",
                ddos.burst
            ));
            config.add_line(&format!("limit_conn conn_ddos {};", ddos.conn_limit));
            config.add_line(&format!("client_max_body_size {};", ddos.body_size_limit));

            // Geo blocking enforcement
            if ddos.geo_blocking {
                config.add_section("\n# Geo blocking enforcement");
                config.add_line("if ($blocked_country) {");
                config.add_line("    return 403;");
                config.add_line("}");
            }
        }

        // Apply general zones
        for zone in &self.zones {
            let rule = RateLimitRule::new(&zone.name).burst(10).nodelay();
            config.add_line(&rule.to_nginx());
        }

        config
    }

    /// Generate location blocks for API endpoints
    pub fn generate_api_locations(&self) -> GeneratedConfig {
        let mut config = GeneratedConfig::new();

        for api in &self.api_limits {
            let zone_name = api.endpoint.replace("/", "_").replace("*", "any");

            config.add_section(&format!("\n# Rate limiting for {}", api.endpoint));
            config.add_line(&format!("location {} {{", api.endpoint));
            config.add_line(&format!(
                "    limit_req zone=api{} burst={} nodelay;",
                zone_name, api.burst
            ));
            config.add_line(&format!("    limit_req_status {};", api.limit_status));

            // Proxy pass placeholder
            config.add_line("    proxy_pass http://backend;");
            config.add_line("}");
        }

        // Tier-based locations
        if !self.tiers.is_empty() {
            config.add_section("\n# Tier-based rate limiting");
            config.add_line("location /api/ {");
            config.add_line("    # Apply tier-based limits");

            for tier in &self.tiers {
                config.add_line(&format!(
                    "    # Tier: {} - {}{} burst={}",
                    tier.name,
                    tier.rate,
                    tier.unit.as_nginx_suffix(),
                    tier.burst
                ));
            }

            config.add_line("");
            config.add_line("    # Use map to select appropriate zone");
            config.add_line("    set $limit_zone \"tier_$api_tier\";");
            config.add_line("    # limit_req zone=$limit_zone burst=10 nodelay;");
            config.add_line("");
            config.add_line("    proxy_pass http://api_backend;");
            config.add_line("}");
        }

        config
    }

    /// Generate rate limit headers configuration
    pub fn generate_headers(&self) -> GeneratedConfig {
        let mut config = GeneratedConfig::new();

        config.add_section("# Rate limit headers\n");

        // Standard rate limit headers
        config.add_line("# Add rate limit headers to responses");
        config.add_line("add_header X-RateLimit-Limit $limit_rate always;");
        config.add_line("add_header X-RateLimit-Remaining $limit_remaining always;");
        config.add_line("add_header X-RateLimit-Reset $limit_reset always;");

        config.add_section("\n# Retry-After header on 429");
        config.add_line("map $status $retry_after {");
        config.add_line("    429 60;");
        config.add_line("    default \"\";");
        config.add_line("}");
        config.add_line("add_header Retry-After $retry_after always;");

        config
    }

    /// Generate Lua script for advanced rate limiting
    pub fn generate_lua_script(&self) -> String {
        let mut script = String::new();

        script.push_str("-- Advanced rate limiting with Lua\n");
        script.push_str("-- Requires lua-resty-limit-traffic\n\n");

        script.push_str("local limit_req = require \"resty.limit.req\"\n");
        script.push_str("local limit_conn = require \"resty.limit.conn\"\n\n");

        // Rate limiter initialization
        script.push_str("-- Create rate limiters\n");
        script.push_str("local rate_limiter, err = limit_req.new(\"rate_limit_store\", 10, 20)\n");
        script.push_str("if not rate_limiter then\n");
        script.push_str("    ngx.log(ngx.ERR, \"failed to create rate limiter: \", err)\n");
        script.push_str("    return ngx.exit(500)\n");
        script.push_str("end\n\n");

        // Key generation
        script.push_str("-- Generate rate limit key\n");
        script.push_str("local function get_limit_key()\n");
        script.push_str("    local api_key = ngx.var.http_x_api_key\n");
        script.push_str("    if api_key then\n");
        script.push_str("        return \"api:\" .. api_key\n");
        script.push_str("    end\n");
        script.push_str("    return \"ip:\" .. ngx.var.binary_remote_addr\n");
        script.push_str("end\n\n");

        // Rate limit check
        script.push_str("-- Check rate limit\n");
        script.push_str("local key = get_limit_key()\n");
        script.push_str("local delay, err = rate_limiter:incoming(key, true)\n\n");

        script.push_str("if not delay then\n");
        script.push_str("    if err == \"rejected\" then\n");
        script.push_str("        ngx.header[\"Retry-After\"] = 60\n");
        script.push_str("        return ngx.exit(429)\n");
        script.push_str("    end\n");
        script.push_str("    ngx.log(ngx.ERR, \"rate limiting error: \", err)\n");
        script.push_str("    return ngx.exit(500)\n");
        script.push_str("end\n\n");

        script.push_str("if delay > 0 then\n");
        script.push_str("    ngx.sleep(delay)\n");
        script.push_str("end\n");

        script
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Generated configuration
#[derive(Debug, Clone)]
pub struct GeneratedConfig {
    lines: Vec<String>,
}

impl GeneratedConfig {
    pub fn new() -> Self {
        Self { lines: Vec::new() }
    }

    pub fn add_line(&mut self, line: &str) {
        self.lines.push(line.to_string());
    }

    pub fn add_section(&mut self, comment: &str) {
        if !self.lines.is_empty() {
            self.lines.push(String::new());
        }
        self.lines.push(comment.to_string());
    }

    pub fn to_string(&self) -> String {
        self.lines.join("\n")
    }
}

impl Default for GeneratedConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for GeneratedConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

// ============================================================================
// Preset Configurations
// ============================================================================

/// Preset configurations for common use cases
pub struct RateLimitPresets;

impl RateLimitPresets {
    /// Web application preset
    pub fn web_app() -> RateLimitConfig {
        RateLimitConfig::new()
            .add_zone(
                RateLimitZone::new("general")
                    .rate(30, RateUnit::PerSecond)
                    .size("10m"),
            )
            .add_zone(
                RateLimitZone::new("login")
                    .rate(5, RateUnit::PerMinute)
                    .size("5m"),
            )
            .add_zone(
                RateLimitZone::new("search")
                    .rate(10, RateUnit::PerSecond)
                    .size("5m"),
            )
            .add_conn_zone(ConnectionLimitZone::new("conn_per_ip").size("10m"))
            .with_ddos_protection(DdosProtection::default())
    }

    /// API server preset
    pub fn api_server() -> RateLimitConfig {
        RateLimitConfig::new()
            .add_zone(
                RateLimitZone::new("api_general")
                    .key("$http_x_api_key")
                    .rate(100, RateUnit::PerMinute)
                    .size("20m"),
            )
            .add_tier(RateLimitTier::free())
            .add_tier(RateLimitTier::basic())
            .add_tier(RateLimitTier::pro())
            .add_tier(RateLimitTier::enterprise())
            .add_api_limit(
                ApiRateLimit::new("/api/v1/auth/*")
                    .rate(5, RateUnit::PerMinute)
                    .burst(2),
            )
            .add_api_limit(
                ApiRateLimit::new("/api/v1/search")
                    .rate(30, RateUnit::PerMinute)
                    .burst(10)
                    .by_api_key(),
            )
            .with_ddos_protection(
                DdosProtection::default().with_whitelist(vec!["10.0.0.0/8", "192.168.0.0/16"]),
            )
    }

    /// Static content preset
    pub fn static_content() -> RateLimitConfig {
        RateLimitConfig::new()
            .add_zone(
                RateLimitZone::new("static")
                    .rate(100, RateUnit::PerSecond)
                    .size("5m"),
            )
            .add_conn_zone(ConnectionLimitZone::new("static_conn").size("5m"))
            .with_ddos_protection(DdosProtection::relaxed())
    }

    /// High security preset
    pub fn high_security() -> RateLimitConfig {
        RateLimitConfig::new()
            .add_zone(
                RateLimitZone::new("strict")
                    .rate(5, RateUnit::PerSecond)
                    .size("20m"),
            )
            .add_zone(
                RateLimitZone::new("login_strict")
                    .rate(3, RateUnit::PerMinute)
                    .size("10m"),
            )
            .add_conn_zone(ConnectionLimitZone::new("conn_strict").size("20m"))
            .with_ddos_protection(
                DdosProtection::aggressive().with_geo_blocking(vec!["CN", "RU", "KP"]),
            )
    }
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== Nginx Rate Limiting Configuration Generator ===\n");

    // Example 1: Basic rate limit zone
    println!("1. Basic Rate Limit Zone:");
    let zone = RateLimitZone::new("general")
        .rate(10, RateUnit::PerSecond)
        .size("10m");
    println!("   {}", zone.to_nginx());

    // Example 2: Rate limit rule with burst
    println!("\n2. Rate Limit Rule:");
    let rule = RateLimitRule::new("general").burst(20).nodelay();
    println!("   {}", rule.to_nginx());

    // Example 3: Web application configuration
    println!("\n3. Web Application Configuration:");
    let config = RateLimitPresets::web_app();
    let generated = config.generate();
    for line in generated.to_string().lines().take(20) {
        println!("   {}", line);
    }
    println!("   ...");

    // Example 4: API server configuration
    println!("\n4. API Server Configuration:");
    let api_config = RateLimitPresets::api_server();
    let api_locations = api_config.generate_api_locations();
    for line in api_locations.to_string().lines().take(15) {
        println!("   {}", line);
    }
    println!("   ...");

    // Example 5: DDoS protection
    println!("\n5. DDoS Protection Configuration:");
    let ddos = DdosProtection::aggressive()
        .with_geo_blocking(vec!["CN", "RU"])
        .with_whitelist(vec!["10.0.0.1", "192.168.1.1"]);

    let ddos_config = RateLimitConfig::new().with_ddos_protection(ddos);
    let ddos_generated = ddos_config.generate();
    for line in ddos_generated.to_string().lines() {
        if line.contains("DDoS") || line.contains("Geo") || line.contains("Whitelist") {
            println!("   {}", line);
        }
    }

    // Example 6: Rate limit tiers
    println!("\n6. Rate Limit Tiers:");
    let tiers = vec![
        RateLimitTier::free(),
        RateLimitTier::basic(),
        RateLimitTier::pro(),
        RateLimitTier::enterprise(),
    ];

    for tier in &tiers {
        println!(
            "   {} - {}{} (burst: {}, daily: {:?})",
            tier.name,
            tier.rate,
            tier.unit.as_nginx_suffix(),
            tier.burst,
            tier.daily_limit
        );
    }

    // Example 7: High security preset
    println!("\n7. High Security Configuration:");
    let high_sec = RateLimitPresets::high_security();
    let server_block = high_sec.generate_server_block();
    for line in server_block.to_string().lines() {
        println!("   {}", line);
    }

    // Example 8: Rate limit headers
    println!("\n8. Rate Limit Headers:");
    let headers = RateLimitPresets::web_app().generate_headers();
    for line in headers.to_string().lines() {
        println!("   {}", line);
    }

    // Example 9: Lua script for advanced limiting
    println!("\n9. Lua Script (excerpt):");
    let lua = RateLimitPresets::api_server().generate_lua_script();
    for line in lua.lines().take(10) {
        println!("   {}", line);
    }
    println!("   ...");

    println!("\n=== Rate Limiting Configuration Complete ===");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_zone() {
        let zone = RateLimitZone::new("test")
            .rate(10, RateUnit::PerSecond)
            .size("5m");

        let nginx = zone.to_nginx();
        assert!(nginx.contains("zone=test:5m"));
        assert!(nginx.contains("rate=10r/s"));
    }

    #[test]
    fn test_rate_limit_zone_with_key() {
        let zone = RateLimitZone::new("api")
            .key("$http_x_api_key")
            .rate(100, RateUnit::PerMinute);

        let nginx = zone.to_nginx();
        assert!(nginx.contains("$http_x_api_key"));
        assert!(nginx.contains("rate=100r/m"));
    }

    #[test]
    fn test_rate_limit_rule() {
        let rule = RateLimitRule::new("test").burst(20).nodelay();

        let nginx = rule.to_nginx();
        assert!(nginx.contains("zone=test"));
        assert!(nginx.contains("burst=20"));
        assert!(nginx.contains("nodelay"));
    }

    #[test]
    fn test_rate_limit_rule_with_delay() {
        let rule = RateLimitRule::new("test").burst(30).delay(10);

        let nginx = rule.to_nginx();
        assert!(nginx.contains("delay=10"));
        assert!(!nginx.contains("nodelay"));
    }

    #[test]
    fn test_connection_limit_zone() {
        let zone = ConnectionLimitZone::new("conn").size("10m");

        let nginx = zone.to_nginx();
        assert!(nginx.contains("limit_conn_zone"));
        assert!(nginx.contains("zone=conn:10m"));
    }

    #[test]
    fn test_bandwidth_limit() {
        let limit = BandwidthLimit::new("1m").after("10m");

        let nginx = limit.to_nginx();
        assert_eq!(nginx.len(), 2);
        assert!(nginx[0].contains("limit_rate 1m"));
        assert!(nginx[1].contains("limit_rate_after 10m"));
    }

    #[test]
    fn test_rate_unit_suffix() {
        assert_eq!(RateUnit::PerSecond.as_nginx_suffix(), "r/s");
        assert_eq!(RateUnit::PerMinute.as_nginx_suffix(), "r/m");
        assert_eq!(RateUnit::PerHour.as_nginx_suffix(), "r/h");
    }

    #[test]
    fn test_rate_unit_seconds() {
        assert_eq!(RateUnit::PerSecond.to_seconds(), 1);
        assert_eq!(RateUnit::PerMinute.to_seconds(), 60);
        assert_eq!(RateUnit::PerHour.to_seconds(), 3600);
    }

    #[test]
    fn test_ddos_protection_default() {
        let ddos = DdosProtection::default();
        assert!(ddos.syn_flood_protection);
        assert_eq!(ddos.per_ip_rate, 10);
        assert_eq!(ddos.burst, 20);
    }

    #[test]
    fn test_ddos_protection_aggressive() {
        let ddos = DdosProtection::aggressive();
        assert_eq!(ddos.per_ip_rate, 5);
        assert_eq!(ddos.burst, 10);
        assert_eq!(ddos.conn_limit, 5);
    }

    #[test]
    fn test_ddos_with_geo_blocking() {
        let ddos = DdosProtection::default().with_geo_blocking(vec!["CN", "RU"]);

        assert!(ddos.geo_blocking);
        assert_eq!(ddos.blocked_countries.len(), 2);
    }

    #[test]
    fn test_api_rate_limit() {
        let limit = ApiRateLimit::new("/api/v1/users")
            .rate(60, RateUnit::PerMinute)
            .burst(10)
            .by_api_key();

        assert!(limit.by_api_key);
        assert_eq!(limit.burst, 10);
    }

    #[test]
    fn test_rate_limit_tier_free() {
        let tier = RateLimitTier::free();
        assert_eq!(tier.name, "free");
        assert_eq!(tier.rate, 10);
        assert!(tier.daily_limit.is_some());
    }

    #[test]
    fn test_rate_limit_tier_enterprise() {
        let tier = RateLimitTier::enterprise();
        assert_eq!(tier.name, "enterprise");
        assert!(tier.daily_limit.is_none());
    }

    #[test]
    fn test_config_generation() {
        let config = RateLimitConfig::new()
            .add_zone(RateLimitZone::new("test").rate(10, RateUnit::PerSecond));

        let generated = config.generate();
        let output = generated.to_string();
        assert!(output.contains("zone=test"));
    }

    #[test]
    fn test_web_app_preset() {
        let config = RateLimitPresets::web_app();
        assert!(!config.zones.is_empty());
        assert!(config.ddos.is_some());
    }

    #[test]
    fn test_api_server_preset() {
        let config = RateLimitPresets::api_server();
        assert!(!config.tiers.is_empty());
        assert!(!config.api_limits.is_empty());
    }

    #[test]
    fn test_high_security_preset() {
        let config = RateLimitPresets::high_security();
        let ddos = config.ddos.unwrap();
        assert!(ddos.geo_blocking);
    }

    #[test]
    fn test_generated_config_display() {
        let mut config = GeneratedConfig::new();
        config.add_line("test line");
        config.add_section("# Section");
        config.add_line("another line");

        let output = config.to_string();
        assert!(output.contains("test line"));
        assert!(output.contains("# Section"));
    }

    #[test]
    fn test_lua_script_generation() {
        let config = RateLimitPresets::api_server();
        let lua = config.generate_lua_script();
        assert!(lua.contains("limit_req"));
        assert!(lua.contains("ngx.exit(429)"));
    }
}
