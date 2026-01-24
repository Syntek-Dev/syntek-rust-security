//! Stack Protection and Binary Hardening
//!
//! This example demonstrates stack canary verification, ASLR detection,
//! NX/DEP validation, RELRO checking, and other binary hardening
//! techniques for Rust applications.

use std::collections::HashMap;
use std::fmt;
use std::process::Command;

// ============================================================================
// Binary Security Features
// ============================================================================

/// Security feature status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureStatus {
    Enabled,
    Partial,
    Disabled,
    Unknown,
}

impl fmt::Display for FeatureStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FeatureStatus::Enabled => write!(f, "ENABLED"),
            FeatureStatus::Partial => write!(f, "PARTIAL"),
            FeatureStatus::Disabled => write!(f, "DISABLED"),
            FeatureStatus::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Binary security check result
#[derive(Debug, Clone)]
pub struct SecurityCheck {
    pub name: String,
    pub status: FeatureStatus,
    pub description: String,
    pub recommendation: Option<String>,
}

impl SecurityCheck {
    pub fn new(name: &str, status: FeatureStatus, description: &str) -> Self {
        Self {
            name: name.to_string(),
            status,
            description: description.to_string(),
            recommendation: None,
        }
    }

    pub fn with_recommendation(mut self, rec: &str) -> Self {
        self.recommendation = Some(rec.to_string());
        self
    }

    pub fn is_secure(&self) -> bool {
        matches!(self.status, FeatureStatus::Enabled)
    }
}

/// Binary hardening analysis result
#[derive(Debug, Clone)]
pub struct HardeningReport {
    pub binary_path: String,
    pub checks: Vec<SecurityCheck>,
    pub score: u8,
    pub max_score: u8,
}

impl HardeningReport {
    pub fn new(path: &str) -> Self {
        Self {
            binary_path: path.to_string(),
            checks: Vec::new(),
            score: 0,
            max_score: 0,
        }
    }

    pub fn add_check(&mut self, check: SecurityCheck) {
        self.max_score += 10;
        self.score += match check.status {
            FeatureStatus::Enabled => 10,
            FeatureStatus::Partial => 5,
            FeatureStatus::Disabled => 0,
            FeatureStatus::Unknown => 2,
        };
        self.checks.push(check);
    }

    pub fn security_grade(&self) -> char {
        let percentage = (self.score as f32 / self.max_score as f32) * 100.0;
        if percentage >= 90.0 {
            'A'
        } else if percentage >= 80.0 {
            'B'
        } else if percentage >= 70.0 {
            'C'
        } else if percentage >= 60.0 {
            'D'
        } else {
            'F'
        }
    }

    pub fn failed_checks(&self) -> Vec<&SecurityCheck> {
        self.checks.iter().filter(|c| !c.is_secure()).collect()
    }
}

// ============================================================================
// Stack Canary Detection
// ============================================================================

/// Stack canary/cookie implementation
pub struct StackCanary {
    /// The canary value
    value: u64,
    /// Backup for verification
    backup: u64,
}

impl StackCanary {
    /// Generate a new stack canary
    pub fn new() -> Self {
        let value = Self::generate_canary();
        Self {
            value,
            backup: value,
        }
    }

    /// Generate random canary value
    fn generate_canary() -> u64 {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        use std::time::{SystemTime, UNIX_EPOCH};

        let state = RandomState::new();
        let mut hasher = state.build_hasher();

        // Mix in various entropy sources
        hasher.write_u128(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        );

        // Get process ID for additional entropy
        hasher.write_u32(std::process::id());

        // Include null byte to detect string-based overflows
        let mut value = hasher.finish();
        value = (value & 0xFFFFFFFFFFFFFF00) | 0x00; // Null byte at end

        value
    }

    /// Verify canary hasn't been modified
    pub fn verify(&self) -> bool {
        self.value == self.backup
    }

    /// Check and panic if corrupted
    pub fn check(&self) {
        if !self.verify() {
            // In real implementation, this would terminate safely
            panic!("Stack canary corruption detected! Possible buffer overflow.");
        }
    }

    /// Get the canary value (for demonstration)
    pub fn value(&self) -> u64 {
        self.value
    }
}

impl Default for StackCanary {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for StackCanary {
    fn drop(&mut self) {
        // Verify on drop to catch corruption
        if !self.verify() {
            // Log security event
            eprintln!("SECURITY: Stack canary corruption detected during cleanup");
        }

        // Zeroize the canary
        self.value = 0;
        self.backup = 0;
    }
}

/// Protected stack frame
pub struct ProtectedFrame<T> {
    canary_start: StackCanary,
    data: T,
    canary_end: StackCanary,
}

impl<T> ProtectedFrame<T> {
    pub fn new(data: T) -> Self {
        Self {
            canary_start: StackCanary::new(),
            data,
            canary_end: StackCanary::new(),
        }
    }

    pub fn get(&self) -> &T {
        self.verify();
        &self.data
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.verify();
        &mut self.data
    }

    pub fn verify(&self) {
        if !self.canary_start.verify() {
            panic!("Stack underflow detected!");
        }
        if !self.canary_end.verify() {
            panic!("Stack overflow detected!");
        }
    }

    pub fn into_inner(self) -> T {
        self.verify();
        self.data
    }
}

// ============================================================================
// ASLR Detection
// ============================================================================

/// Address Space Layout Randomization detector
pub struct AslrDetector;

impl AslrDetector {
    /// Check if ASLR is enabled for current process
    pub fn check_enabled() -> AslrStatus {
        #[cfg(target_os = "linux")]
        {
            Self::check_linux_aslr()
        }

        #[cfg(not(target_os = "linux"))]
        {
            AslrStatus::Unknown
        }
    }

    #[cfg(target_os = "linux")]
    fn check_linux_aslr() -> AslrStatus {
        use std::fs;

        if let Ok(content) = fs::read_to_string("/proc/sys/kernel/randomize_va_space") {
            match content.trim() {
                "0" => AslrStatus::Disabled,
                "1" => AslrStatus::Partial, // Stack only
                "2" => AslrStatus::Full,    // Stack, VDSO, shared memory, mmap
                _ => AslrStatus::Unknown,
            }
        } else {
            AslrStatus::Unknown
        }
    }

    /// Sample stack address to verify randomization
    pub fn sample_addresses() -> AddressSample {
        let stack_var = 0u64;
        let heap_var = Box::new(0u64);

        // Function address
        fn sample_fn() {}
        let fn_addr = sample_fn as *const () as usize;

        AddressSample {
            stack_address: &stack_var as *const u64 as usize,
            heap_address: &*heap_var as *const u64 as usize,
            code_address: fn_addr,
            timestamp: std::time::Instant::now(),
        }
    }

    /// Compare samples to detect randomization
    pub fn verify_randomization(samples: &[AddressSample]) -> RandomizationResult {
        if samples.len() < 2 {
            return RandomizationResult {
                stack_randomized: false,
                heap_randomized: false,
                code_randomized: false,
                confidence: 0.0,
            };
        }

        let stack_addrs: Vec<usize> = samples.iter().map(|s| s.stack_address).collect();
        let heap_addrs: Vec<usize> = samples.iter().map(|s| s.heap_address).collect();
        let code_addrs: Vec<usize> = samples.iter().map(|s| s.code_address).collect();

        RandomizationResult {
            stack_randomized: Self::check_variance(&stack_addrs),
            heap_randomized: Self::check_variance(&heap_addrs),
            code_randomized: Self::check_variance(&code_addrs),
            confidence: 1.0 - (1.0 / samples.len() as f64),
        }
    }

    fn check_variance(addrs: &[usize]) -> bool {
        if addrs.is_empty() {
            return false;
        }
        let first = addrs[0];
        addrs.iter().any(|&a| a != first)
    }
}

/// ASLR status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AslrStatus {
    Disabled,
    Partial,
    Full,
    Unknown,
}

/// Address sample for ASLR verification
#[derive(Debug, Clone)]
pub struct AddressSample {
    pub stack_address: usize,
    pub heap_address: usize,
    pub code_address: usize,
    pub timestamp: std::time::Instant,
}

/// Randomization verification result
#[derive(Debug, Clone)]
pub struct RandomizationResult {
    pub stack_randomized: bool,
    pub heap_randomized: bool,
    pub code_randomized: bool,
    pub confidence: f64,
}

// ============================================================================
// NX/DEP Detection
// ============================================================================

/// NX (No-Execute) / DEP (Data Execution Prevention) checker
pub struct NxChecker;

impl NxChecker {
    /// Check if NX bit is supported and enabled
    pub fn check_enabled() -> NxStatus {
        #[cfg(target_arch = "x86_64")]
        {
            Self::check_cpuid_nx()
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            NxStatus::Unknown
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn check_cpuid_nx() -> NxStatus {
        // Check CPUID for NX bit support
        // In real implementation, would use inline assembly or cpuid crate
        // For demonstration, we'll check /proc/cpuinfo on Linux

        #[cfg(target_os = "linux")]
        {
            use std::fs;
            if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
                if cpuinfo.contains(" nx ") || cpuinfo.contains(" nx\n") {
                    return NxStatus::Enabled;
                }
                return NxStatus::NotSupported;
            }
        }

        NxStatus::Unknown
    }

    /// Verify memory region is non-executable
    #[cfg(target_os = "linux")]
    pub fn check_memory_region(addr: usize) -> MemoryProtection {
        use std::fs;

        let maps = match fs::read_to_string("/proc/self/maps") {
            Ok(m) => m,
            Err(_) => return MemoryProtection::Unknown,
        };

        for line in maps.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            // Parse address range
            let range_parts: Vec<&str> = parts[0].split('-').collect();
            if range_parts.len() != 2 {
                continue;
            }

            let start = usize::from_str_radix(range_parts[0], 16).unwrap_or(0);
            let end = usize::from_str_radix(range_parts[1], 16).unwrap_or(0);

            if addr >= start && addr < end {
                let perms = parts.get(1).unwrap_or(&"");
                return MemoryProtection::from_perms(perms);
            }
        }

        MemoryProtection::Unknown
    }

    #[cfg(not(target_os = "linux"))]
    pub fn check_memory_region(_addr: usize) -> MemoryProtection {
        MemoryProtection::Unknown
    }
}

/// NX status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NxStatus {
    Enabled,
    Disabled,
    NotSupported,
    Unknown,
}

/// Memory protection flags
#[derive(Debug, Clone)]
pub struct MemoryProtection {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub private: bool,
}

impl MemoryProtection {
    pub fn from_perms(perms: &str) -> Self {
        let chars: Vec<char> = perms.chars().collect();
        Self {
            readable: chars.first() == Some(&'r'),
            writable: chars.get(1) == Some(&'w'),
            executable: chars.get(2) == Some(&'x'),
            private: chars.get(3) == Some(&'p'),
        }
    }

    pub fn is_writable_and_executable(&self) -> bool {
        self.writable && self.executable
    }
}

impl Default for MemoryProtection {
    fn default() -> Self {
        Self::Unknown
    }
}

impl MemoryProtection {
    pub const Unknown: Self = Self {
        readable: false,
        writable: false,
        executable: false,
        private: false,
    };
}

// ============================================================================
// RELRO Detection
// ============================================================================

/// RELRO (Relocation Read-Only) checker
pub struct RelroChecker;

impl RelroChecker {
    /// Check RELRO status of a binary
    pub fn check_binary(path: &str) -> RelroStatus {
        // Use readelf or objdump to check
        if let Ok(output) = Command::new("readelf").args(["-l", path]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            let has_relro = stdout.contains("GNU_RELRO");
            let has_bind_now = Self::check_bind_now(path);

            if has_relro && has_bind_now {
                RelroStatus::Full
            } else if has_relro {
                RelroStatus::Partial
            } else {
                RelroStatus::Disabled
            }
        } else {
            RelroStatus::Unknown
        }
    }

    fn check_bind_now(path: &str) -> bool {
        if let Ok(output) = Command::new("readelf").args(["-d", path]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.contains("BIND_NOW") || stdout.contains("NOW")
        } else {
            false
        }
    }
}

/// RELRO status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelroStatus {
    Full,
    Partial,
    Disabled,
    Unknown,
}

// ============================================================================
// PIE Detection
// ============================================================================

/// PIE (Position Independent Executable) checker
pub struct PieChecker;

impl PieChecker {
    /// Check if binary is compiled as PIE
    pub fn check_binary(path: &str) -> PieStatus {
        if let Ok(output) = Command::new("readelf").args(["-h", path]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            if stdout.contains("DYN (Shared object file)")
                || stdout.contains("DYN (Position-Independent Executable)")
            {
                PieStatus::Enabled
            } else if stdout.contains("EXEC (Executable file)") {
                PieStatus::Disabled
            } else {
                PieStatus::Unknown
            }
        } else {
            PieStatus::Unknown
        }
    }
}

/// PIE status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PieStatus {
    Enabled,
    Disabled,
    Unknown,
}

// ============================================================================
// Fortify Source Detection
// ============================================================================

/// FORTIFY_SOURCE checker
pub struct FortifyChecker;

impl FortifyChecker {
    /// Check for fortified functions in binary
    pub fn check_binary(path: &str) -> FortifyStatus {
        if let Ok(output) = Command::new("nm").args(["-D", path]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            // Look for __*_chk functions which indicate FORTIFY_SOURCE
            let fortified_funcs: Vec<&str> = stdout
                .lines()
                .filter(|line| line.contains("__") && line.contains("_chk"))
                .collect();

            if fortified_funcs.len() > 5 {
                FortifyStatus::Full
            } else if !fortified_funcs.is_empty() {
                FortifyStatus::Partial
            } else {
                FortifyStatus::Disabled
            }
        } else {
            FortifyStatus::Unknown
        }
    }
}

/// FORTIFY_SOURCE status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FortifyStatus {
    Full,
    Partial,
    Disabled,
    Unknown,
}

// ============================================================================
// Comprehensive Binary Analyzer
// ============================================================================

/// Binary security analyzer
pub struct BinaryAnalyzer {
    path: String,
}

impl BinaryAnalyzer {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }

    /// Run all security checks
    pub fn analyze(&self) -> HardeningReport {
        let mut report = HardeningReport::new(&self.path);

        // Stack Canary
        report.add_check(self.check_stack_protector());

        // PIE
        report.add_check(self.check_pie());

        // RELRO
        report.add_check(self.check_relro());

        // NX
        report.add_check(self.check_nx());

        // Fortify Source
        report.add_check(self.check_fortify());

        // RPATH/RUNPATH
        report.add_check(self.check_rpath());

        // Symbol visibility
        report.add_check(self.check_symbols());

        report
    }

    fn check_stack_protector(&self) -> SecurityCheck {
        if let Ok(output) = Command::new("readelf").args(["-s", &self.path]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            if stdout.contains("__stack_chk_fail") {
                SecurityCheck::new(
                    "Stack Protector",
                    FeatureStatus::Enabled,
                    "Stack canaries are enabled (-fstack-protector)",
                )
            } else {
                SecurityCheck::new(
                    "Stack Protector",
                    FeatureStatus::Disabled,
                    "No stack protection detected",
                )
                .with_recommendation(
                    "Compile with -fstack-protector-strong or -fstack-protector-all",
                )
            }
        } else {
            SecurityCheck::new(
                "Stack Protector",
                FeatureStatus::Unknown,
                "Could not analyze binary",
            )
        }
    }

    fn check_pie(&self) -> SecurityCheck {
        match PieChecker::check_binary(&self.path) {
            PieStatus::Enabled => SecurityCheck::new(
                "PIE (Position Independent Executable)",
                FeatureStatus::Enabled,
                "Binary is position-independent",
            ),
            PieStatus::Disabled => SecurityCheck::new(
                "PIE (Position Independent Executable)",
                FeatureStatus::Disabled,
                "Binary has fixed addresses",
            )
            .with_recommendation("Compile with -pie -fPIE"),
            PieStatus::Unknown => SecurityCheck::new(
                "PIE (Position Independent Executable)",
                FeatureStatus::Unknown,
                "Could not determine PIE status",
            ),
        }
    }

    fn check_relro(&self) -> SecurityCheck {
        match RelroChecker::check_binary(&self.path) {
            RelroStatus::Full => SecurityCheck::new(
                "RELRO (Relocation Read-Only)",
                FeatureStatus::Enabled,
                "Full RELRO enabled (GOT is read-only)",
            ),
            RelroStatus::Partial => SecurityCheck::new(
                "RELRO (Relocation Read-Only)",
                FeatureStatus::Partial,
                "Partial RELRO (some sections protected)",
            )
            .with_recommendation("Link with -Wl,-z,relro,-z,now for full RELRO"),
            RelroStatus::Disabled => SecurityCheck::new(
                "RELRO (Relocation Read-Only)",
                FeatureStatus::Disabled,
                "No RELRO protection",
            )
            .with_recommendation("Link with -Wl,-z,relro,-z,now"),
            RelroStatus::Unknown => SecurityCheck::new(
                "RELRO (Relocation Read-Only)",
                FeatureStatus::Unknown,
                "Could not determine RELRO status",
            ),
        }
    }

    fn check_nx(&self) -> SecurityCheck {
        if let Ok(output) = Command::new("readelf").args(["-l", &self.path]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            if stdout.contains("GNU_STACK") && !stdout.contains("RWE") {
                SecurityCheck::new(
                    "NX (No-Execute)",
                    FeatureStatus::Enabled,
                    "Stack is non-executable",
                )
            } else {
                SecurityCheck::new(
                    "NX (No-Execute)",
                    FeatureStatus::Disabled,
                    "Stack may be executable",
                )
                .with_recommendation("Link with -Wl,-z,noexecstack")
            }
        } else {
            SecurityCheck::new(
                "NX (No-Execute)",
                FeatureStatus::Unknown,
                "Could not check NX status",
            )
        }
    }

    fn check_fortify(&self) -> SecurityCheck {
        match FortifyChecker::check_binary(&self.path) {
            FortifyStatus::Full => SecurityCheck::new(
                "FORTIFY_SOURCE",
                FeatureStatus::Enabled,
                "Buffer overflow protection enabled",
            ),
            FortifyStatus::Partial => SecurityCheck::new(
                "FORTIFY_SOURCE",
                FeatureStatus::Partial,
                "Some fortified functions present",
            )
            .with_recommendation("Compile with -D_FORTIFY_SOURCE=2"),
            FortifyStatus::Disabled => SecurityCheck::new(
                "FORTIFY_SOURCE",
                FeatureStatus::Disabled,
                "No fortified functions detected",
            )
            .with_recommendation("Compile with -D_FORTIFY_SOURCE=2 -O2"),
            FortifyStatus::Unknown => SecurityCheck::new(
                "FORTIFY_SOURCE",
                FeatureStatus::Unknown,
                "Could not determine fortify status",
            ),
        }
    }

    fn check_rpath(&self) -> SecurityCheck {
        if let Ok(output) = Command::new("readelf").args(["-d", &self.path]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            let has_rpath = stdout.contains("RPATH");
            let has_runpath = stdout.contains("RUNPATH");

            if !has_rpath && !has_runpath {
                SecurityCheck::new(
                    "RPATH/RUNPATH",
                    FeatureStatus::Enabled,
                    "No hardcoded library paths",
                )
            } else {
                SecurityCheck::new(
                    "RPATH/RUNPATH",
                    FeatureStatus::Partial,
                    "Hardcoded library paths present",
                )
                .with_recommendation("Avoid -rpath; use system library paths")
            }
        } else {
            SecurityCheck::new(
                "RPATH/RUNPATH",
                FeatureStatus::Unknown,
                "Could not check RPATH",
            )
        }
    }

    fn check_symbols(&self) -> SecurityCheck {
        if let Ok(output) = Command::new("nm").args(["--dynamic", &self.path]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let symbol_count = stdout.lines().count();

            if symbol_count < 50 {
                SecurityCheck::new(
                    "Symbol Visibility",
                    FeatureStatus::Enabled,
                    "Minimal dynamic symbol exposure",
                )
            } else if symbol_count < 200 {
                SecurityCheck::new(
                    "Symbol Visibility",
                    FeatureStatus::Partial,
                    &format!("{} dynamic symbols exposed", symbol_count),
                )
                .with_recommendation("Use -fvisibility=hidden and explicit exports")
            } else {
                SecurityCheck::new(
                    "Symbol Visibility",
                    FeatureStatus::Disabled,
                    &format!("{} dynamic symbols exposed", symbol_count),
                )
                .with_recommendation("Compile with -fvisibility=hidden")
            }
        } else {
            SecurityCheck::new(
                "Symbol Visibility",
                FeatureStatus::Unknown,
                "Could not analyze symbols",
            )
        }
    }
}

// ============================================================================
// Compiler Flags Recommender
// ============================================================================

/// Recommended compiler flags for hardening
pub struct HardeningFlags;

impl HardeningFlags {
    /// Get recommended RUSTFLAGS for hardened builds
    pub fn rust_flags() -> Vec<&'static str> {
        vec![
            "-C",
            "link-arg=-Wl,-z,relro,-z,now", // Full RELRO
            "-C",
            "link-arg=-Wl,-z,noexecstack", // NX stack
            "-C",
            "overflow-checks=on", // Integer overflow checks
            "-C",
            "panic=abort", // Abort on panic (no unwinding exploits)
            "-C",
            "opt-level=2", // Optimization for fortify
        ]
    }

    /// Get recommended Cargo profile settings
    pub fn cargo_profile() -> HashMap<&'static str, &'static str> {
        let mut profile = HashMap::new();
        profile.insert("opt-level", "2");
        profile.insert("lto", "thin");
        profile.insert("codegen-units", "1");
        profile.insert("panic", "abort");
        profile.insert("overflow-checks", "true");
        profile
    }

    /// Get environment variables for hardened builds
    pub fn env_vars() -> HashMap<&'static str, &'static str> {
        let mut vars = HashMap::new();
        vars.insert(
            "RUSTFLAGS",
            "-C link-arg=-Wl,-z,relro,-z,now -C link-arg=-Wl,-z,noexecstack",
        );
        vars
    }

    /// Generate Cargo.toml profile section
    pub fn cargo_toml_section() -> String {
        r#"[profile.release]
opt-level = 2
lto = "thin"
codegen-units = 1
panic = "abort"
overflow-checks = true
strip = "symbols"

[profile.release.build-override]
opt-level = 2
"#
        .to_string()
    }
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== Stack Protection and Binary Hardening ===\n");

    // Example 1: Stack Canary
    println!("1. Stack Canary Protection:");
    let canary = StackCanary::new();
    println!("   Generated canary: 0x{:016X}", canary.value());
    println!("   Canary verified: {}", canary.verify());

    // Example 2: Protected Stack Frame
    println!("\n2. Protected Stack Frame:");
    let protected_data = ProtectedFrame::new(vec![1, 2, 3, 4, 5]);
    println!("   Data: {:?}", protected_data.get());
    protected_data.verify();
    println!("   Frame integrity verified");

    // Example 3: ASLR Detection
    println!("\n3. ASLR Status:");
    let aslr_status = AslrDetector::check_enabled();
    println!("   System ASLR: {:?}", aslr_status);

    let sample1 = AslrDetector::sample_addresses();
    println!("   Stack address: 0x{:X}", sample1.stack_address);
    println!("   Heap address:  0x{:X}", sample1.heap_address);
    println!("   Code address:  0x{:X}", sample1.code_address);

    // Example 4: NX/DEP Status
    println!("\n4. NX/DEP Status:");
    let nx_status = NxChecker::check_enabled();
    println!("   NX bit: {:?}", nx_status);

    // Check a memory region
    let stack_var = 0u64;
    let addr = &stack_var as *const u64 as usize;
    let protection = NxChecker::check_memory_region(addr);
    println!(
        "   Stack region protection: R={} W={} X={}",
        protection.readable, protection.writable, protection.executable
    );

    // Example 5: Binary Analysis (self)
    println!("\n5. Binary Analysis:");
    let current_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "/proc/self/exe".to_string());

    println!("   Analyzing: {}", current_exe);

    let analyzer = BinaryAnalyzer::new(&current_exe);
    let report = analyzer.analyze();

    println!("\n   Security Report:");
    println!("   ================");
    for check in &report.checks {
        let status_icon = match check.status {
            FeatureStatus::Enabled => "[+]",
            FeatureStatus::Partial => "[~]",
            FeatureStatus::Disabled => "[-]",
            FeatureStatus::Unknown => "[?]",
        };
        println!("   {} {} - {}", status_icon, check.name, check.status);
        if let Some(rec) = &check.recommendation {
            println!("       Recommendation: {}", rec);
        }
    }

    println!(
        "\n   Score: {}/{} (Grade: {})",
        report.score,
        report.max_score,
        report.security_grade()
    );

    // Example 6: Hardening Recommendations
    println!("\n6. Hardening Flags:");
    println!("   Recommended RUSTFLAGS:");
    for flag in HardeningFlags::rust_flags() {
        println!("     {}", flag);
    }

    println!("\n   Cargo.toml profile:");
    for line in HardeningFlags::cargo_toml_section().lines() {
        println!("     {}", line);
    }

    // Example 7: Failed Checks Summary
    let failed = report.failed_checks();
    if !failed.is_empty() {
        println!("\n7. Security Issues to Address:");
        for check in failed {
            println!("   - {}: {}", check.name, check.description);
        }
    } else {
        println!("\n7. All security checks passed!");
    }

    println!("\n=== Binary Hardening Analysis Complete ===");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_canary_creation() {
        let canary = StackCanary::new();
        assert_ne!(canary.value(), 0);
        assert!(canary.verify());
    }

    #[test]
    fn test_stack_canary_null_byte() {
        let canary = StackCanary::new();
        // Check for null byte at end (protection against string overflows)
        assert_eq!(canary.value() & 0xFF, 0);
    }

    #[test]
    fn test_protected_frame() {
        let frame = ProtectedFrame::new(42u32);
        assert_eq!(*frame.get(), 42);
    }

    #[test]
    fn test_protected_frame_mutation() {
        let mut frame = ProtectedFrame::new(vec![1, 2, 3]);
        frame.get_mut().push(4);
        assert_eq!(frame.get().len(), 4);
    }

    #[test]
    fn test_protected_frame_into_inner() {
        let frame = ProtectedFrame::new("hello".to_string());
        let value = frame.into_inner();
        assert_eq!(value, "hello");
    }

    #[test]
    fn test_address_sample() {
        let sample = AslrDetector::sample_addresses();
        assert!(sample.stack_address > 0);
        assert!(sample.heap_address > 0);
        assert!(sample.code_address > 0);
    }

    #[test]
    fn test_memory_protection_parsing() {
        let prot = MemoryProtection::from_perms("r-xp");
        assert!(prot.readable);
        assert!(!prot.writable);
        assert!(prot.executable);
        assert!(prot.private);
    }

    #[test]
    fn test_writable_executable_detection() {
        let dangerous = MemoryProtection {
            readable: true,
            writable: true,
            executable: true,
            private: false,
        };
        assert!(dangerous.is_writable_and_executable());

        let safe = MemoryProtection {
            readable: true,
            writable: true,
            executable: false,
            private: true,
        };
        assert!(!safe.is_writable_and_executable());
    }

    #[test]
    fn test_security_check_creation() {
        let check = SecurityCheck::new("Test Check", FeatureStatus::Enabled, "Test description");
        assert!(check.is_secure());
        assert!(check.recommendation.is_none());
    }

    #[test]
    fn test_security_check_with_recommendation() {
        let check = SecurityCheck::new("Test", FeatureStatus::Disabled, "Disabled feature")
            .with_recommendation("Enable it");

        assert!(!check.is_secure());
        assert_eq!(check.recommendation, Some("Enable it".to_string()));
    }

    #[test]
    fn test_hardening_report_scoring() {
        let mut report = HardeningReport::new("/test");

        report.add_check(SecurityCheck::new("A", FeatureStatus::Enabled, ""));
        report.add_check(SecurityCheck::new("B", FeatureStatus::Enabled, ""));
        report.add_check(SecurityCheck::new("C", FeatureStatus::Disabled, ""));

        assert_eq!(report.score, 20);
        assert_eq!(report.max_score, 30);
        assert_eq!(report.failed_checks().len(), 1);
    }

    #[test]
    fn test_security_grade_calculation() {
        let mut report = HardeningReport::new("/test");

        // All enabled = 100% = A
        for _ in 0..10 {
            report.add_check(SecurityCheck::new("Test", FeatureStatus::Enabled, ""));
        }
        assert_eq!(report.security_grade(), 'A');
    }

    #[test]
    fn test_hardening_flags() {
        let flags = HardeningFlags::rust_flags();
        assert!(flags.contains(&"-C"));
        assert!(flags.iter().any(|f| f.contains("relro")));
    }

    #[test]
    fn test_cargo_profile() {
        let profile = HardeningFlags::cargo_profile();
        assert_eq!(profile.get("panic"), Some(&"abort"));
        assert_eq!(profile.get("overflow-checks"), Some(&"true"));
    }

    #[test]
    fn test_cargo_toml_generation() {
        let toml = HardeningFlags::cargo_toml_section();
        assert!(toml.contains("[profile.release]"));
        assert!(toml.contains("panic = \"abort\""));
        assert!(toml.contains("overflow-checks = true"));
    }

    #[test]
    fn test_aslr_status_variants() {
        assert_ne!(AslrStatus::Full, AslrStatus::Partial);
        assert_ne!(AslrStatus::Disabled, AslrStatus::Unknown);
    }

    #[test]
    fn test_relro_status_variants() {
        assert_ne!(RelroStatus::Full, RelroStatus::Partial);
        assert_ne!(RelroStatus::Disabled, RelroStatus::Unknown);
    }

    #[test]
    fn test_randomization_result() {
        let samples = vec![
            AddressSample {
                stack_address: 0x1000,
                heap_address: 0x2000,
                code_address: 0x3000,
                timestamp: std::time::Instant::now(),
            },
            AddressSample {
                stack_address: 0x1100, // Different
                heap_address: 0x2000,  // Same
                code_address: 0x3000,  // Same
                timestamp: std::time::Instant::now(),
            },
        ];

        let result = AslrDetector::verify_randomization(&samples);
        assert!(result.stack_randomized);
        assert!(!result.heap_randomized);
        assert!(!result.code_randomized);
    }
}
