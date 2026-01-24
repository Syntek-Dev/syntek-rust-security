//! Mutation Testing Framework for Security Code
//!
//! This example demonstrates mutation testing patterns for verifying test suite
//! effectiveness in security-critical Rust code. Mutation testing introduces
//! small changes (mutants) to code and verifies that tests catch them.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ============================================================================
// Mutation Types and Operators
// ============================================================================

/// Types of mutations that can be applied to code
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MutationType {
    // Arithmetic mutations
    ArithmeticPlus,     // + -> -
    ArithmeticMinus,    // - -> +
    ArithmeticMultiply, // * -> /
    ArithmeticDivide,   // / -> *
    ArithmeticModulo,   // % -> *

    // Relational mutations
    RelationalLt,  // < -> <=
    RelationalLte, // <= -> <
    RelationalGt,  // > -> >=
    RelationalGte, // >= -> >
    RelationalEq,  // == -> !=
    RelationalNeq, // != -> ==

    // Logical mutations
    LogicalAnd, // && -> ||
    LogicalOr,  // || -> &&
    LogicalNot, // !x -> x

    // Bitwise mutations
    BitwiseAnd,        // & -> |
    BitwiseOr,         // | -> &
    BitwiseXor,        // ^ -> &
    BitwiseShiftLeft,  // << -> >>
    BitwiseShiftRight, // >> -> <<

    // Constant mutations
    ConstantZero,      // n -> 0
    ConstantOne,       // n -> 1
    ConstantNegate,    // n -> -n
    ConstantIncrement, // n -> n + 1
    ConstantDecrement, // n -> n - 1

    // Control flow mutations
    IfConditionNegate,  // if (c) -> if (!c)
    IfRemoveElse,       // if-else -> if
    LoopBreakRemove,    // remove break
    LoopContinueRemove, // remove continue
    EarlyReturnRemove,  // remove early return

    // Boundary mutations
    BoundaryOff,   // array[i] -> array[i+1]
    BoundaryUnder, // array[i] -> array[i-1]

    // Security-specific mutations
    AuthBypass,        // auth check -> true
    ValidationSkip,    // validation -> success
    EncryptionWeaken,  // strong algo -> weak
    TimingRemove,      // constant-time -> variable-time
    RandomSeedFixed,   // random -> fixed value
    PermissionElevate, // user -> admin
}

impl MutationType {
    pub fn all() -> Vec<MutationType> {
        vec![
            MutationType::ArithmeticPlus,
            MutationType::ArithmeticMinus,
            MutationType::ArithmeticMultiply,
            MutationType::ArithmeticDivide,
            MutationType::RelationalLt,
            MutationType::RelationalLte,
            MutationType::RelationalGt,
            MutationType::RelationalGte,
            MutationType::RelationalEq,
            MutationType::RelationalNeq,
            MutationType::LogicalAnd,
            MutationType::LogicalOr,
            MutationType::LogicalNot,
            MutationType::ConstantZero,
            MutationType::ConstantOne,
            MutationType::ConstantNegate,
            MutationType::IfConditionNegate,
            MutationType::AuthBypass,
            MutationType::ValidationSkip,
            MutationType::TimingRemove,
        ]
    }

    pub fn security_critical() -> Vec<MutationType> {
        vec![
            MutationType::AuthBypass,
            MutationType::ValidationSkip,
            MutationType::EncryptionWeaken,
            MutationType::TimingRemove,
            MutationType::RandomSeedFixed,
            MutationType::PermissionElevate,
            MutationType::RelationalEq,
            MutationType::RelationalNeq,
            MutationType::LogicalAnd,
            MutationType::LogicalOr,
        ]
    }

    pub fn category(&self) -> &'static str {
        match self {
            MutationType::ArithmeticPlus
            | MutationType::ArithmeticMinus
            | MutationType::ArithmeticMultiply
            | MutationType::ArithmeticDivide
            | MutationType::ArithmeticModulo => "Arithmetic",

            MutationType::RelationalLt
            | MutationType::RelationalLte
            | MutationType::RelationalGt
            | MutationType::RelationalGte
            | MutationType::RelationalEq
            | MutationType::RelationalNeq => "Relational",

            MutationType::LogicalAnd | MutationType::LogicalOr | MutationType::LogicalNot => {
                "Logical"
            }

            MutationType::BitwiseAnd
            | MutationType::BitwiseOr
            | MutationType::BitwiseXor
            | MutationType::BitwiseShiftLeft
            | MutationType::BitwiseShiftRight => "Bitwise",

            MutationType::ConstantZero
            | MutationType::ConstantOne
            | MutationType::ConstantNegate
            | MutationType::ConstantIncrement
            | MutationType::ConstantDecrement => "Constant",

            MutationType::IfConditionNegate
            | MutationType::IfRemoveElse
            | MutationType::LoopBreakRemove
            | MutationType::LoopContinueRemove
            | MutationType::EarlyReturnRemove => "Control Flow",

            MutationType::BoundaryOff | MutationType::BoundaryUnder => "Boundary",

            MutationType::AuthBypass
            | MutationType::ValidationSkip
            | MutationType::EncryptionWeaken
            | MutationType::TimingRemove
            | MutationType::RandomSeedFixed
            | MutationType::PermissionElevate => "Security",
        }
    }
}

impl fmt::Display for MutationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = match self {
            MutationType::ArithmeticPlus => "+ → -",
            MutationType::ArithmeticMinus => "- → +",
            MutationType::ArithmeticMultiply => "* → /",
            MutationType::ArithmeticDivide => "/ → *",
            MutationType::ArithmeticModulo => "% → *",
            MutationType::RelationalLt => "< → <=",
            MutationType::RelationalLte => "<= → <",
            MutationType::RelationalGt => "> → >=",
            MutationType::RelationalGte => ">= → >",
            MutationType::RelationalEq => "== → !=",
            MutationType::RelationalNeq => "!= → ==",
            MutationType::LogicalAnd => "&& → ||",
            MutationType::LogicalOr => "|| → &&",
            MutationType::LogicalNot => "!x → x",
            MutationType::BitwiseAnd => "& → |",
            MutationType::BitwiseOr => "| → &",
            MutationType::BitwiseXor => "^ → &",
            MutationType::BitwiseShiftLeft => "<< → >>",
            MutationType::BitwiseShiftRight => ">> → <<",
            MutationType::ConstantZero => "n → 0",
            MutationType::ConstantOne => "n → 1",
            MutationType::ConstantNegate => "n → -n",
            MutationType::ConstantIncrement => "n → n+1",
            MutationType::ConstantDecrement => "n → n-1",
            MutationType::IfConditionNegate => "if(c) → if(!c)",
            MutationType::IfRemoveElse => "if-else → if",
            MutationType::LoopBreakRemove => "remove break",
            MutationType::LoopContinueRemove => "remove continue",
            MutationType::EarlyReturnRemove => "remove early return",
            MutationType::BoundaryOff => "[i] → [i+1]",
            MutationType::BoundaryUnder => "[i] → [i-1]",
            MutationType::AuthBypass => "auth → true",
            MutationType::ValidationSkip => "validate → ok",
            MutationType::EncryptionWeaken => "strong → weak crypto",
            MutationType::TimingRemove => "const-time → var-time",
            MutationType::RandomSeedFixed => "random → fixed",
            MutationType::PermissionElevate => "user → admin",
        };
        write!(f, "{}", desc)
    }
}

// ============================================================================
// Mutant Representation
// ============================================================================

/// Represents a single mutation applied to code
#[derive(Clone, Debug)]
pub struct Mutant {
    pub id: u64,
    pub mutation_type: MutationType,
    pub location: CodeLocation,
    pub original: String,
    pub mutated: String,
    pub status: MutantStatus,
}

#[derive(Clone, Debug)]
pub struct CodeLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub function: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum MutantStatus {
    Pending,
    Killed,
    Survived,
    TimedOut,
    Error(String),
    Skipped,
}

impl Mutant {
    pub fn new(
        id: u64,
        mutation_type: MutationType,
        location: CodeLocation,
        original: String,
        mutated: String,
    ) -> Self {
        Self {
            id,
            mutation_type,
            location,
            original,
            mutated,
            status: MutantStatus::Pending,
        }
    }

    pub fn is_security_critical(&self) -> bool {
        matches!(
            self.mutation_type,
            MutationType::AuthBypass
                | MutationType::ValidationSkip
                | MutationType::EncryptionWeaken
                | MutationType::TimingRemove
                | MutationType::RandomSeedFixed
                | MutationType::PermissionElevate
        )
    }
}

// ============================================================================
// Mutation Testing Engine
// ============================================================================

/// Configuration for mutation testing
#[derive(Clone)]
pub struct MutationConfig {
    pub mutation_types: Vec<MutationType>,
    pub timeout: Duration,
    pub max_mutants: Option<usize>,
    pub parallel: bool,
    pub focus_security: bool,
    pub fail_fast: bool,
}

impl Default for MutationConfig {
    fn default() -> Self {
        Self {
            mutation_types: MutationType::all(),
            timeout: Duration::from_secs(30),
            max_mutants: None,
            parallel: true,
            focus_security: false,
            fail_fast: false,
        }
    }
}

impl MutationConfig {
    pub fn security_focused() -> Self {
        Self {
            mutation_types: MutationType::security_critical(),
            focus_security: true,
            ..Default::default()
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_mutants(mut self, max: usize) -> Self {
        self.max_mutants = Some(max);
        self
    }
}

/// Statistics for mutation testing
#[derive(Default)]
pub struct MutationStats {
    pub total: AtomicU64,
    pub killed: AtomicU64,
    pub survived: AtomicU64,
    pub timed_out: AtomicU64,
    pub errors: AtomicU64,
    pub skipped: AtomicU64,
    pub duration_ms: AtomicU64,
}

impl MutationStats {
    pub fn mutation_score(&self) -> f64 {
        let killed = self.killed.load(Ordering::Relaxed);
        let total = self.total.load(Ordering::Relaxed);
        let skipped = self.skipped.load(Ordering::Relaxed);
        let timed_out = self.timed_out.load(Ordering::Relaxed);

        let effective_total = total - skipped - timed_out;
        if effective_total == 0 {
            100.0
        } else {
            (killed as f64 / effective_total as f64) * 100.0
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "Total: {}, Killed: {}, Survived: {}, Timed out: {}, Errors: {}, Skipped: {}\n\
             Mutation Score: {:.2}%",
            self.total.load(Ordering::Relaxed),
            self.killed.load(Ordering::Relaxed),
            self.survived.load(Ordering::Relaxed),
            self.timed_out.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
            self.skipped.load(Ordering::Relaxed),
            self.mutation_score(),
        )
    }
}

/// Result of testing a single mutant
#[derive(Debug)]
pub struct MutantTestResult {
    pub mutant_id: u64,
    pub status: MutantStatus,
    pub killing_test: Option<String>,
    pub duration: Duration,
}

/// Mutation testing engine
pub struct MutationEngine {
    config: MutationConfig,
    mutants: Vec<Mutant>,
    stats: MutationStats,
    next_id: AtomicU64,
}

impl MutationEngine {
    pub fn new(config: MutationConfig) -> Self {
        Self {
            config,
            mutants: Vec::new(),
            stats: MutationStats::default(),
            next_id: AtomicU64::new(1),
        }
    }

    pub fn add_mutant(&mut self, mutant: Mutant) {
        self.mutants.push(mutant);
    }

    pub fn generate_mutant(
        &self,
        mutation_type: MutationType,
        location: CodeLocation,
        original: String,
        mutated: String,
    ) -> Mutant {
        Mutant::new(
            self.next_id.fetch_add(1, Ordering::Relaxed),
            mutation_type,
            location,
            original,
            mutated,
        )
    }

    /// Run mutation testing with a test function
    pub fn run_tests<F>(&mut self, test_fn: F) -> Vec<MutantTestResult>
    where
        F: Fn(&Mutant) -> bool + Sync,
    {
        let start = Instant::now();
        let mut results = Vec::new();

        let mutants_to_test: Vec<_> = if let Some(max) = self.config.max_mutants {
            self.mutants.iter().take(max).collect()
        } else {
            self.mutants.iter().collect()
        };

        self.stats
            .total
            .store(mutants_to_test.len() as u64, Ordering::Relaxed);

        for mutant in mutants_to_test {
            let test_start = Instant::now();

            // Check timeout
            if start.elapsed() > self.config.timeout {
                let result = MutantTestResult {
                    mutant_id: mutant.id,
                    status: MutantStatus::TimedOut,
                    killing_test: None,
                    duration: test_start.elapsed(),
                };
                self.stats.timed_out.fetch_add(1, Ordering::Relaxed);
                results.push(result);
                continue;
            }

            // Run the test
            let killed = test_fn(mutant);
            let status = if killed {
                self.stats.killed.fetch_add(1, Ordering::Relaxed);
                MutantStatus::Killed
            } else {
                self.stats.survived.fetch_add(1, Ordering::Relaxed);
                MutantStatus::Survived
            };

            let result = MutantTestResult {
                mutant_id: mutant.id,
                status,
                killing_test: if killed {
                    Some("test_detected_mutation".to_string())
                } else {
                    None
                },
                duration: test_start.elapsed(),
            };

            results.push(result);

            if self.config.fail_fast && !killed && mutant.is_security_critical() {
                break;
            }
        }

        self.stats
            .duration_ms
            .store(start.elapsed().as_millis() as u64, Ordering::Relaxed);

        results
    }

    pub fn stats(&self) -> &MutationStats {
        &self.stats
    }

    pub fn mutants(&self) -> &[Mutant] {
        &self.mutants
    }

    pub fn survived_mutants(&self) -> Vec<&Mutant> {
        self.mutants
            .iter()
            .filter(|m| m.status == MutantStatus::Survived)
            .collect()
    }

    pub fn security_gaps(&self) -> Vec<&Mutant> {
        self.mutants
            .iter()
            .filter(|m| m.status == MutantStatus::Survived && m.is_security_critical())
            .collect()
    }
}

// ============================================================================
// Report Generation
// ============================================================================

/// Mutation testing report
pub struct MutationReport {
    pub project: String,
    pub timestamp: String,
    pub config: MutationConfig,
    pub stats: MutationStats,
    pub mutants: Vec<Mutant>,
    pub results: Vec<MutantTestResult>,
}

impl MutationReport {
    pub fn generate_text(&self) -> String {
        let mut report = String::new();

        report.push_str("╔════════════════════════════════════════════════════════════════════╗\n");
        report.push_str("║                    MUTATION TESTING REPORT                         ║\n");
        report
            .push_str("╚════════════════════════════════════════════════════════════════════╝\n\n");

        report.push_str(&format!("Project: {}\n", self.project));
        report.push_str(&format!("Generated: {}\n\n", self.timestamp));

        report
            .push_str("═══════════════════════════════════════════════════════════════════════\n");
        report.push_str("                              SUMMARY\n");
        report.push_str(
            "═══════════════════════════════════════════════════════════════════════\n\n",
        );
        report.push_str(&self.stats.summary());
        report.push_str("\n\n");

        // Mutations by category
        report
            .push_str("═══════════════════════════════════════════════════════════════════════\n");
        report.push_str("                         MUTATIONS BY CATEGORY\n");
        report.push_str(
            "═══════════════════════════════════════════════════════════════════════\n\n",
        );

        let mut by_category: HashMap<&str, (usize, usize)> = HashMap::new();
        for mutant in &self.mutants {
            let category = mutant.mutation_type.category();
            let entry = by_category.entry(category).or_insert((0, 0));
            entry.0 += 1;
            if mutant.status == MutantStatus::Killed {
                entry.1 += 1;
            }
        }

        for (category, (total, killed)) in &by_category {
            let score = if *total > 0 {
                (*killed as f64 / *total as f64) * 100.0
            } else {
                100.0
            };
            report.push_str(&format!(
                "  {:20} {:3}/{:3} killed ({:.1}%)\n",
                category, killed, total, score
            ));
        }
        report.push('\n');

        // Survived mutants
        let survived: Vec<_> = self
            .mutants
            .iter()
            .filter(|m| m.status == MutantStatus::Survived)
            .collect();

        if !survived.is_empty() {
            report.push_str(
                "═══════════════════════════════════════════════════════════════════════\n",
            );
            report.push_str("                         SURVIVED MUTANTS\n");
            report.push_str(
                "═══════════════════════════════════════════════════════════════════════\n\n",
            );

            for mutant in survived.iter().take(20) {
                report.push_str(&format!(
                    "  [{}] {}:{}:{}\n",
                    mutant.id, mutant.location.file, mutant.location.line, mutant.location.column
                ));
                if let Some(ref func) = mutant.location.function {
                    report.push_str(&format!("      Function: {}\n", func));
                }
                report.push_str(&format!("      Mutation: {}\n", mutant.mutation_type));
                report.push_str(&format!("      Original: {}\n", mutant.original));
                report.push_str(&format!("      Mutated:  {}\n\n", mutant.mutated));
            }

            if survived.len() > 20 {
                report.push_str(&format!("  ... and {} more\n\n", survived.len() - 20));
            }
        }

        // Security gaps
        let security_gaps: Vec<_> = self
            .mutants
            .iter()
            .filter(|m| m.status == MutantStatus::Survived && m.is_security_critical())
            .collect();

        if !security_gaps.is_empty() {
            report.push_str(
                "═══════════════════════════════════════════════════════════════════════\n",
            );
            report.push_str("                    ⚠️  SECURITY GAPS DETECTED  ⚠️\n");
            report.push_str(
                "═══════════════════════════════════════════════════════════════════════\n\n",
            );

            report.push_str(
                "  The following security-critical mutations were NOT detected by tests:\n\n",
            );

            for mutant in security_gaps {
                report.push_str(&format!(
                    "  🔓 [{}] {} - {}\n",
                    mutant.id, mutant.mutation_type, mutant.location.file
                ));
                report.push_str(&format!(
                    "      Line {}: {} → {}\n\n",
                    mutant.location.line, mutant.original, mutant.mutated
                ));
            }
        }

        // Recommendations
        report
            .push_str("═══════════════════════════════════════════════════════════════════════\n");
        report.push_str("                          RECOMMENDATIONS\n");
        report.push_str(
            "═══════════════════════════════════════════════════════════════════════\n\n",
        );

        let score = self.stats.mutation_score();
        if score < 60.0 {
            report.push_str("  ❌ CRITICAL: Mutation score below 60%. Test suite needs significant improvement.\n");
        } else if score < 80.0 {
            report
                .push_str("  ⚠️  WARNING: Mutation score below 80%. Consider adding more tests.\n");
        } else if score < 95.0 {
            report.push_str("  ✓ GOOD: Mutation score above 80%. Some improvements possible.\n");
        } else {
            report.push_str("  ✓ EXCELLENT: Mutation score above 95%. Well-tested codebase.\n");
        }

        if !security_gaps.is_empty() {
            report.push_str("\n  🔒 SECURITY: Add tests for authentication, authorization, and input validation.\n");
        }

        report
    }

    pub fn generate_json(&self) -> String {
        let mut json = String::from("{\n");

        json.push_str(&format!("  \"project\": \"{}\",\n", self.project));
        json.push_str(&format!("  \"timestamp\": \"{}\",\n", self.timestamp));
        json.push_str(&format!(
            "  \"mutation_score\": {:.2},\n",
            self.stats.mutation_score()
        ));
        json.push_str(&format!(
            "  \"total_mutants\": {},\n",
            self.stats.total.load(Ordering::Relaxed)
        ));
        json.push_str(&format!(
            "  \"killed\": {},\n",
            self.stats.killed.load(Ordering::Relaxed)
        ));
        json.push_str(&format!(
            "  \"survived\": {},\n",
            self.stats.survived.load(Ordering::Relaxed)
        ));
        json.push_str(&format!(
            "  \"timed_out\": {},\n",
            self.stats.timed_out.load(Ordering::Relaxed)
        ));

        json.push_str("  \"mutants\": [\n");
        for (i, mutant) in self.mutants.iter().enumerate() {
            json.push_str("    {\n");
            json.push_str(&format!("      \"id\": {},\n", mutant.id));
            json.push_str(&format!(
                "      \"type\": \"{:?}\",\n",
                mutant.mutation_type
            ));
            json.push_str(&format!("      \"file\": \"{}\",\n", mutant.location.file));
            json.push_str(&format!("      \"line\": {},\n", mutant.location.line));
            json.push_str(&format!("      \"status\": \"{:?}\",\n", mutant.status));
            json.push_str(&format!(
                "      \"security_critical\": {}\n",
                mutant.is_security_critical()
            ));
            json.push_str("    }");
            if i < self.mutants.len() - 1 {
                json.push(',');
            }
            json.push('\n');
        }
        json.push_str("  ]\n");

        json.push_str("}\n");
        json
    }
}

// ============================================================================
// Example Code to Mutate and Test
// ============================================================================

/// Authentication service (example code to test)
pub struct AuthService {
    users: HashMap<String, UserCredentials>,
    sessions: HashMap<String, Session>,
    max_attempts: u32,
}

#[derive(Clone)]
struct UserCredentials {
    username: String,
    password_hash: Vec<u8>,
    role: UserRole,
    failed_attempts: u32,
    locked: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum UserRole {
    Guest,
    User,
    Admin,
}

#[derive(Clone)]
struct Session {
    user_id: String,
    role: UserRole,
    expires_at: u64,
}

impl AuthService {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            sessions: HashMap::new(),
            max_attempts: 5,
        }
    }

    pub fn register(&mut self, username: &str, password: &str, role: UserRole) -> bool {
        if username.is_empty() || password.len() < 8 {
            return false;
        }

        if self.users.contains_key(username) {
            return false;
        }

        let password_hash = Self::hash_password(password);
        self.users.insert(
            username.to_string(),
            UserCredentials {
                username: username.to_string(),
                password_hash,
                role,
                failed_attempts: 0,
                locked: false,
            },
        );

        true
    }

    pub fn authenticate(&mut self, username: &str, password: &str) -> Option<String> {
        let user = self.users.get_mut(username)?;

        // Check if account is locked (SECURITY CRITICAL)
        if user.locked {
            return None;
        }

        // Verify password (SECURITY CRITICAL)
        let password_hash = Self::hash_password(password);
        if !Self::constant_time_compare(&user.password_hash, &password_hash) {
            user.failed_attempts += 1;

            // Lock after max attempts (SECURITY CRITICAL)
            if user.failed_attempts >= self.max_attempts {
                user.locked = true;
            }

            return None;
        }

        // Reset failed attempts on success
        user.failed_attempts = 0;

        // Create session
        let session_id = Self::generate_session_id();
        let session = Session {
            user_id: username.to_string(),
            role: user.role.clone(),
            expires_at: Self::current_time() + 3600,
        };

        self.sessions.insert(session_id.clone(), session);
        Some(session_id)
    }

    pub fn authorize(&self, session_id: &str, required_role: UserRole) -> bool {
        let session = match self.sessions.get(session_id) {
            Some(s) => s,
            None => return false,
        };

        // Check session expiration (SECURITY CRITICAL)
        if session.expires_at < Self::current_time() {
            return false;
        }

        // Check role (SECURITY CRITICAL)
        match (&session.role, &required_role) {
            (UserRole::Admin, _) => true,
            (UserRole::User, UserRole::User) => true,
            (UserRole::User, UserRole::Guest) => true,
            (UserRole::Guest, UserRole::Guest) => true,
            _ => false,
        }
    }

    pub fn validate_input(&self, input: &str) -> bool {
        // Length check (SECURITY CRITICAL)
        if input.len() > 1000 {
            return false;
        }

        // SQL injection check (SECURITY CRITICAL)
        let dangerous = [
            "'", "\"", ";", "--", "/*", "*/", "DROP", "DELETE", "INSERT", "UPDATE",
        ];
        for pattern in dangerous {
            if input.to_uppercase().contains(pattern) {
                return false;
            }
        }

        true
    }

    fn hash_password(password: &str) -> Vec<u8> {
        // Simplified hash for demonstration
        let mut hash = vec![0u8; 32];
        for (i, byte) in password.bytes().enumerate() {
            hash[i % 32] ^= byte;
            hash[(i + 1) % 32] = hash[(i + 1) % 32].wrapping_add(byte);
        }
        hash
    }

    fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
    }

    fn generate_session_id() -> String {
        format!("session_{:016x}", 0xDEADBEEF12345678u64)
    }

    fn current_time() -> u64 {
        1700000000
    }
}

// ============================================================================
// Test Functions for Mutation Testing
// ============================================================================

/// Tests that should detect mutations
pub fn test_authentication_required(auth: &mut AuthService) -> bool {
    auth.register("user1", "password123", UserRole::User);

    // Should fail with wrong password
    assert!(auth.authenticate("user1", "wrongpassword").is_none());

    // Should succeed with correct password
    assert!(auth.authenticate("user1", "password123").is_some());

    true
}

pub fn test_account_locking(auth: &mut AuthService) -> bool {
    auth.register("user2", "password123", UserRole::User);

    // Fail 5 times
    for _ in 0..5 {
        auth.authenticate("user2", "wrong");
    }

    // Account should be locked
    assert!(auth.authenticate("user2", "password123").is_none());

    true
}

pub fn test_authorization_levels(auth: &mut AuthService) -> bool {
    auth.register("admin", "adminpass123", UserRole::Admin);
    auth.register("user", "userpass123", UserRole::User);
    auth.register("guest", "guestpass123", UserRole::Guest);

    let admin_session = auth.authenticate("admin", "adminpass123").unwrap();
    let user_session = auth.authenticate("user", "userpass123").unwrap();
    let guest_session = auth.authenticate("guest", "guestpass123").unwrap();

    // Admin can access everything
    assert!(auth.authorize(&admin_session, UserRole::Admin));
    assert!(auth.authorize(&admin_session, UserRole::User));
    assert!(auth.authorize(&admin_session, UserRole::Guest));

    // User cannot access admin
    assert!(!auth.authorize(&user_session, UserRole::Admin));
    assert!(auth.authorize(&user_session, UserRole::User));

    // Guest is most restricted
    assert!(!auth.authorize(&guest_session, UserRole::Admin));
    assert!(!auth.authorize(&guest_session, UserRole::User));
    assert!(auth.authorize(&guest_session, UserRole::Guest));

    true
}

pub fn test_input_validation(auth: &AuthService) -> bool {
    // Normal input should pass
    assert!(auth.validate_input("hello world"));

    // SQL injection should be blocked
    assert!(!auth.validate_input("'; DROP TABLE users; --"));
    assert!(!auth.validate_input("1 OR 1=1"));

    // Long input should be blocked
    let long_input = "a".repeat(1001);
    assert!(!auth.validate_input(&long_input));

    true
}

// ============================================================================
// Main Demonstration
// ============================================================================

fn main() {
    println!("=== Mutation Testing for Security Code ===\n");

    // Create mutation engine
    let config = MutationConfig::security_focused().with_max_mutants(50);
    let mut engine = MutationEngine::new(config);

    // Generate sample mutants
    println!("Generating mutants...\n");

    // Authentication bypass mutant
    engine.add_mutant(engine.generate_mutant(
        MutationType::AuthBypass,
        CodeLocation {
            file: "auth.rs".to_string(),
            line: 45,
            column: 8,
            function: Some("authenticate".to_string()),
        },
        "if user.locked { return None; }".to_string(),
        "if false { return None; }".to_string(),
    ));

    // Password validation skip
    engine.add_mutant(engine.generate_mutant(
        MutationType::ValidationSkip,
        CodeLocation {
            file: "auth.rs".to_string(),
            line: 52,
            column: 8,
            function: Some("authenticate".to_string()),
        },
        "if !Self::constant_time_compare(...) { ... }".to_string(),
        "if false { ... }".to_string(),
    ));

    // Account lock threshold mutation
    engine.add_mutant(engine.generate_mutant(
        MutationType::RelationalGte,
        CodeLocation {
            file: "auth.rs".to_string(),
            line: 58,
            column: 12,
            function: Some("authenticate".to_string()),
        },
        "if user.failed_attempts >= self.max_attempts".to_string(),
        "if user.failed_attempts > self.max_attempts".to_string(),
    ));

    // Role check mutation
    engine.add_mutant(engine.generate_mutant(
        MutationType::PermissionElevate,
        CodeLocation {
            file: "auth.rs".to_string(),
            line: 78,
            column: 8,
            function: Some("authorize".to_string()),
        },
        "(UserRole::Guest, UserRole::Guest) => true".to_string(),
        "(UserRole::Guest, _) => true".to_string(),
    ));

    // Expiration check removal
    engine.add_mutant(engine.generate_mutant(
        MutationType::IfConditionNegate,
        CodeLocation {
            file: "auth.rs".to_string(),
            line: 73,
            column: 8,
            function: Some("authorize".to_string()),
        },
        "if session.expires_at < Self::current_time()".to_string(),
        "if session.expires_at > Self::current_time()".to_string(),
    ));

    // SQL injection check mutation
    engine.add_mutant(engine.generate_mutant(
        MutationType::ValidationSkip,
        CodeLocation {
            file: "auth.rs".to_string(),
            line: 95,
            column: 12,
            function: Some("validate_input".to_string()),
        },
        "if input.to_uppercase().contains(pattern) { return false; }".to_string(),
        "if false { return false; }".to_string(),
    ));

    // Constant time comparison mutation
    engine.add_mutant(engine.generate_mutant(
        MutationType::TimingRemove,
        CodeLocation {
            file: "auth.rs".to_string(),
            line: 110,
            column: 8,
            function: Some("constant_time_compare".to_string()),
        },
        "result |= x ^ y".to_string(),
        "if x != y { return false; }".to_string(),
    ));

    // Length check mutation
    engine.add_mutant(engine.generate_mutant(
        MutationType::RelationalGt,
        CodeLocation {
            file: "auth.rs".to_string(),
            line: 88,
            column: 8,
            function: Some("validate_input".to_string()),
        },
        "if input.len() > 1000".to_string(),
        "if input.len() >= 1000".to_string(),
    ));

    println!("Generated {} mutants\n", engine.mutants().len());

    // Run mutation tests
    println!("Running mutation tests...\n");

    let results = engine.run_tests(|mutant| {
        let mut auth = AuthService::new();

        // Run all tests - if any fails, the mutant is killed
        let tests_pass = test_authentication_required(&mut auth)
            && test_account_locking(&mut AuthService::new())
            && test_authorization_levels(&mut AuthService::new())
            && test_input_validation(&AuthService::new());

        // Simulate mutation detection based on mutation type
        // In real mutation testing, the mutated code would be compiled and run
        let detected = match &mutant.mutation_type {
            MutationType::AuthBypass => true,        // Detected by auth test
            MutationType::ValidationSkip => true,    // Detected by validation test
            MutationType::RelationalGte => true,     // Detected by locking test
            MutationType::PermissionElevate => true, // Detected by auth levels test
            MutationType::IfConditionNegate => true, // Would be detected
            MutationType::TimingRemove => false,     // Timing attacks hard to detect
            MutationType::RelationalGt => false,     // Off-by-one might survive
            _ => tests_pass,
        };

        detected
    });

    // Update mutant statuses
    for result in &results {
        if let Some(mutant) = engine.mutants.iter_mut().find(|m| m.id == result.mutant_id) {
            mutant.status = result.status.clone();
        }
    }

    // Generate report
    let report = MutationReport {
        project: "AuthService".to_string(),
        timestamp: "2024-01-15T10:30:00Z".to_string(),
        config: engine.config.clone(),
        stats: MutationStats {
            total: AtomicU64::new(engine.mutants().len() as u64),
            killed: engine.stats.killed.clone(),
            survived: engine.stats.survived.clone(),
            timed_out: engine.stats.timed_out.clone(),
            errors: engine.stats.errors.clone(),
            skipped: engine.stats.skipped.clone(),
            duration_ms: engine.stats.duration_ms.clone(),
        },
        mutants: engine.mutants().to_vec(),
        results,
    };

    println!("{}", report.generate_text());

    // Show security gaps
    let gaps = engine.security_gaps();
    if !gaps.is_empty() {
        println!("\n⚠️  Security gaps that need test coverage:");
        for gap in gaps {
            println!(
                "  - {} in {}",
                gap.mutation_type,
                gap.location.function.as_deref().unwrap_or("unknown")
            );
        }
    }

    println!("\n=== Mutation Testing Complete ===");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutation_type_all() {
        let all = MutationType::all();
        assert!(all.len() >= 20);
    }

    #[test]
    fn test_mutation_type_security() {
        let security = MutationType::security_critical();
        assert!(security.len() >= 6);

        for mutation in security {
            assert!(matches!(
                mutation,
                MutationType::AuthBypass
                    | MutationType::ValidationSkip
                    | MutationType::EncryptionWeaken
                    | MutationType::TimingRemove
                    | MutationType::RandomSeedFixed
                    | MutationType::PermissionElevate
                    | MutationType::RelationalEq
                    | MutationType::RelationalNeq
                    | MutationType::LogicalAnd
                    | MutationType::LogicalOr
            ));
        }
    }

    #[test]
    fn test_mutant_security_critical() {
        let location = CodeLocation {
            file: "test.rs".to_string(),
            line: 1,
            column: 1,
            function: None,
        };

        let auth_bypass = Mutant::new(
            1,
            MutationType::AuthBypass,
            location.clone(),
            "original".to_string(),
            "mutated".to_string(),
        );
        assert!(auth_bypass.is_security_critical());

        let arithmetic = Mutant::new(
            2,
            MutationType::ArithmeticPlus,
            location,
            "original".to_string(),
            "mutated".to_string(),
        );
        assert!(!arithmetic.is_security_critical());
    }

    #[test]
    fn test_mutation_stats() {
        let stats = MutationStats::default();

        stats.total.store(100, Ordering::Relaxed);
        stats.killed.store(80, Ordering::Relaxed);
        stats.survived.store(15, Ordering::Relaxed);
        stats.skipped.store(5, Ordering::Relaxed);

        // Score = killed / (total - skipped - timed_out)
        // = 80 / (100 - 5 - 0) = 80 / 95 = 84.21%
        let score = stats.mutation_score();
        assert!(score > 84.0 && score < 85.0);
    }

    #[test]
    fn test_mutation_engine_basic() {
        let config = MutationConfig::default().with_max_mutants(10);
        let mut engine = MutationEngine::new(config);

        let location = CodeLocation {
            file: "test.rs".to_string(),
            line: 10,
            column: 5,
            function: Some("test_fn".to_string()),
        };

        engine.add_mutant(engine.generate_mutant(
            MutationType::ArithmeticPlus,
            location,
            "a + b".to_string(),
            "a - b".to_string(),
        ));

        assert_eq!(engine.mutants().len(), 1);
    }

    #[test]
    fn test_mutation_engine_run() {
        let config = MutationConfig::default().with_max_mutants(5);
        let mut engine = MutationEngine::new(config);

        for i in 0..5 {
            let location = CodeLocation {
                file: "test.rs".to_string(),
                line: i + 1,
                column: 1,
                function: None,
            };

            engine.add_mutant(engine.generate_mutant(
                MutationType::ArithmeticPlus,
                location,
                format!("a + {}", i),
                format!("a - {}", i),
            ));
        }

        // Test function that kills all mutants
        let results = engine.run_tests(|_| true);

        assert_eq!(results.len(), 5);
        assert!(results.iter().all(|r| r.status == MutantStatus::Killed));
    }

    #[test]
    fn test_auth_service_register() {
        let mut auth = AuthService::new();

        assert!(auth.register("user", "password123", UserRole::User));
        assert!(!auth.register("user", "password456", UserRole::User)); // Duplicate
        assert!(!auth.register("", "password123", UserRole::User)); // Empty username
        assert!(!auth.register("user2", "short", UserRole::User)); // Short password
    }

    #[test]
    fn test_auth_service_authenticate() {
        let mut auth = AuthService::new();
        auth.register("user", "password123", UserRole::User);

        assert!(auth.authenticate("user", "password123").is_some());
        assert!(auth.authenticate("user", "wrongpassword").is_none());
        assert!(auth.authenticate("nonexistent", "password123").is_none());
    }

    #[test]
    fn test_auth_service_locking() {
        let mut auth = AuthService::new();
        auth.register("user", "password123", UserRole::User);

        // Fail 5 times
        for _ in 0..5 {
            auth.authenticate("user", "wrong");
        }

        // Should be locked now
        assert!(auth.authenticate("user", "password123").is_none());
    }

    #[test]
    fn test_auth_service_authorization() {
        let mut auth = AuthService::new();
        auth.register("admin", "adminpass123", UserRole::Admin);
        auth.register("user", "userpass123", UserRole::User);

        let admin_session = auth.authenticate("admin", "adminpass123").unwrap();
        let user_session = auth.authenticate("user", "userpass123").unwrap();

        assert!(auth.authorize(&admin_session, UserRole::Admin));
        assert!(auth.authorize(&admin_session, UserRole::User));
        assert!(!auth.authorize(&user_session, UserRole::Admin));
        assert!(auth.authorize(&user_session, UserRole::User));
    }

    #[test]
    fn test_auth_service_input_validation() {
        let auth = AuthService::new();

        assert!(auth.validate_input("normal input"));
        assert!(!auth.validate_input("'; DROP TABLE users;--"));
        assert!(!auth.validate_input(&"a".repeat(1001)));
    }

    #[test]
    fn test_report_generation() {
        let stats = MutationStats::default();
        stats.total.store(10, Ordering::Relaxed);
        stats.killed.store(8, Ordering::Relaxed);
        stats.survived.store(2, Ordering::Relaxed);

        let report = MutationReport {
            project: "TestProject".to_string(),
            timestamp: "2024-01-15".to_string(),
            config: MutationConfig::default(),
            stats,
            mutants: vec![],
            results: vec![],
        };

        let text = report.generate_text();
        assert!(text.contains("MUTATION TESTING REPORT"));
        assert!(text.contains("TestProject"));

        let json = report.generate_json();
        assert!(json.contains("\"project\": \"TestProject\""));
    }
}
