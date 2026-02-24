# Coding Principles

These principles apply to **all code** in this project. Read and apply them
before writing or reviewing any code.

---

## Length of Coding Files

Each coding file should be a maximum of 750 lines with a grace of 50 lines,
this includes comments. If a file gets above 750 lines (or the grace lines),
make the code file into modules and import them into a central file.

## Rob Pike's 5 Rules of Programming

Rob Pike is the co-creator of Go. These rules govern when and how to optimise.

**Rule 1 — Don't guess where the bottleneck is**
You can't tell where a programme is going to spend its time. Bottlenecks occur
in surprising places, so don't try to second-guess and put in a speed hack until
you know that is where the bottleneck is.

**Rule 2 — Measure before you tune**
Don't tune for speed until you've measured, and even then don't unless one part
of the code overwhelms the rest.

**Rule 3 — Fancy algorithms are slow when N is small**
N is usually small. Fancy algorithms have big constants. Until you know that N
is frequently going to be large, don't get fancy. Even if N does get large, use
Rule 2 first.

**Rule 4 — Fancy algorithms are buggier**
Fancy algorithms are harder to implement. Use simple, reusable, easy-to-maintain
algorithms and simple data structures.

**Rule 5 — Data dominates**
If you have chosen the right data structures and organised things well, the
algorithms will almost always be self-evident. Data structures are central to
programming — not algorithms.

---

## Linus Torvalds' Coding Principles

Derived from Linus Torvalds' coding style, talks, and mailing list
contributions. Focused on efficiency, simplicity, readability, and a deep
understanding of data structures.

**Rule 1 — Data structures over algorithms**
_"Show me your flowcharts and conceal your tables, and I shall continue to be
mystified. Show me your tables, and I won't usually need your flowcharts;
they'll be obvious."_
Focus on how data is organised — the code (logic) will naturally follow. A
solid data model often eliminates the need for complex, messy code.

**Rule 2 — "Good taste" in coding**

- Remove special cases: good code eliminates edge cases rather than adding `if`
  statements for them.
- Simplify logic: avoid tricky expressions or complex, nested control flows.
- Reduce branches: fewer conditional statements make code faster (CPU branch
  prediction) and easier to reason about.

**Rule 3 — Readability and maintainability**

- Short functions: functions do one thing, are short, and fit on one or two
  screenfuls of text.
- Descriptive names: variables and functions should be descriptive but concise.
- Avoid excessive indentation: deep nesting makes code hard to read, especially
  after looking at it for 20 hours.

**Rule 4 — Code structure and style**
Avoid multiple assignments on a single line. One action per statement.

**Rule 5 — Favour stability over complexity**
Doing something clever is not a virtue. Stability and predictability matter more
than doing something cool.

**Rule 6 — The bad code principle**
Make it work, then make it better. Don't over-optimise — get it working first,
then optimise. All code should be maintainable by anyone, not just yourself.

---

## Error Handling

Prefer explicit error handling over silent failures. Never swallow an error
without logging it — silent failures are the hardest class of bug to diagnose.

- Use custom error types over generic ones. An error that says `VaultFetchError`
  with a path and reason is more actionable than a bare `std::io::Error`.
- Every error message should answer three questions: **what** went wrong,
  **why** it happened, and ideally **what to do** about it.
- Propagate errors with `?` and attach context at the caller boundary using
  `context()` / `with_context()` from `anyhow` or define domain types with
  `thiserror`. Never lose the original error — wrap it, don't replace it.
- Do not return `Option` where an error is the more honest type. Use `Result`
  when the absence of a value is unexpected or requires explanation.
- Avoid `unwrap()` and `expect()` in production code. Use them only in tests or
  where the invariant is provably upheld, and annotate why with a comment.
- Security errors must not leak sensitive context. An `AuthError` returned to
  the caller must never include the candidate password or token value in its
  message.

---

## Naming Conventions

Beyond Linus's "descriptive but concise" rule, follow these concrete
conventions across all code in this project:

- **Booleans** read as questions: `is_active`, `has_permission`, `can_retry`.
- **Functions** are verbs: `fetch_secret`, `validate_token`, `rotate_cert`.
- **Avoid abbreviations** unless universally understood in context (`url`, `id`,
  `cfg` are acceptable; `usr`, `mgr`, `svc` are not).
- **No single-letter variables** except in tight loops (`i`, `j`) or clear
  mathematical contexts.
- **Rust** follows `snake_case` for variables, functions, and modules;
  `PascalCase` for types, traits, and enums; `SCREAMING_SNAKE_CASE` for
  constants and statics.
- **Error types** are named by domain and outcome: `VaultConnectionError`,
  `CertRotationFailed`, `InvalidTokenFormat`.
- **Security-sensitive types** should be wrapped in newtypes to prevent
  accidental misuse: `struct ApiKey(String)` not `type ApiKey = String`.
- **Lifetimes** use short, meaningful names: `'key`, `'conn`, `'buf` — not just
  `'a` when the lifetime has a clear semantic role.

---

## Unsafe Code

Unsafe Rust requires explicit justification and must follow strict conventions.

- Every `unsafe` block must have a `// SAFETY:` comment immediately above it
  explaining why the invariants required by the unsafe operation are upheld.
- Minimise the scope of `unsafe` blocks — wrap only the specific lines that
  require it, not surrounding safe code.
- Never use `unsafe` to bypass a borrow checker error without first proving
  that safe alternatives are genuinely insufficient.
- FFI boundary code (PyO3, Neon, UniFFI) is the primary legitimate use for
  `unsafe`. Document the ownership model at every FFI call site.
- Prefer `zerocopy`, `bytemuck`, or safe wrappers over raw pointer arithmetic
  for data layout concerns.
- Run `cargo geiger` to track the unsafe surface area. Do not increase it
  without justification.

---

## Memory Safety and Zeroisation

Sensitive data in memory requires active management — the language does not
erase it automatically.

- Wrap sensitive values in `secrecy::Secret<T>` to prevent them from appearing
  in `Debug` output or `Display` formatting.
- Use `zeroize::Zeroize` (or `ZeroizeOnDrop`) on all types that hold
  cryptographic keys, passwords, tokens, or private key material.
- Never store sensitive data in `String` or `Vec<u8>` without a zeroising
  wrapper — these types do not erase their contents on drop.
- Avoid cloning sensitive types. If you must clone, ensure the clone is also
  wrapped in a zeroising type.
- Do not return sensitive values from functions by value across an FFI boundary
  without explicit zeroisation before the return.

---

## Cryptography

Cryptographic code is held to a higher standard than general application code.

- Use established, audited crates: `ring`, `aes-gcm`, `chacha20poly1305`,
  `argon2`, `blake3`, `ed25519-dalek`. Do not implement primitives from scratch.
- Choose the right algorithm for the context — AES-256-GCM or
  ChaCha20-Poly1305 for symmetric encryption; Argon2id for password hashing;
  X25519 for key exchange.
- Never reuse nonces/IVs with the same key. Use random nonces from
  `rand::rngs::OsRng` or XChaCha20 (192-bit nonce reduces collision risk).
- Use constant-time comparison (`subtle::ConstantTimeEq`) for all comparisons
  involving secrets to prevent timing side-channel attacks.
- Cryptographic code must be reviewed by a second pair of eyes before merging.
  Tag the PR with `crypto-review` and run `/crypto-review`.

---

## Testing

Every public function, module, and agent tool requires tests. See
**[TESTING.md](TESTING.md)** for the full testing guide, patterns, and examples
adapted to this project's stack (Rust, Tokio, mockall, proptest).

Summary of requirements:

- Every public Rust function has at least one unit test.
- Every HTTP endpoint and CLI command has integration tests covering the happy
  path, error paths, and authentication failures.
- Security-critical functions (crypto, token parsing, input validation) have
  property-based tests with `proptest` in addition to manual cases.
- Tests are independent — no test relies on another having run first.
- Test names describe the scenario: `test_vault_fetch_returns_none_on_missing_path`
  not `test_fetch_2`.

---

## Comments and Documentation

Comments explain **why**, not **what**. If code needs a comment to explain what
it does, rewrite the code to be clearer instead.

- **Docstrings** are mandatory on all public APIs. Use `///` doc comments for
  public functions, types, and modules. Include an example in `# Examples` for
  non-trivial APIs.
- **`// SAFETY:`** comments are mandatory above every `unsafe` block — see
  Unsafe Code above.
- **TODO comments** must include a name or ticket reference:
  `// TODO(sam): remove after STORY-030 deploys`.
- Avoid commented-out code in committed files. Delete it; git history is the
  recovery mechanism.
- Security assumptions must be documented at the call site — document what
  invariants the caller is responsible for upholding.

---

## Security

- **Never hardcode** secrets, API keys, or credentials in any file committed to
  this repository. All secrets are retrieved from HashiCorp Vault at runtime.
- **Always validate and sanitise** user input at system boundaries. Assume all
  external input is hostile until proven otherwise. This includes data from
  network sockets, environment variables, files, and FFI callers.
- **Parameterised queries** for all database access. String interpolation into
  SQL is never acceptable.
- **Principle of least privilege**: every service, process, token, and API key
  has only the permissions it needs and nothing more. Request narrow Vault
  policies; use short-lived tokens.
- **Pin all dependencies** explicitly. `Cargo.lock` must be committed for
  binaries. Run `cargo audit` on every dependency change.
- See **[SECURITY.md](SECURITY.md)** for detailed security patterns, the
  compliance checklist, and the cryptographic guidelines.

---

## Dependencies

Don't add a dependency for something you can write correctly in under 50 lines.
Before adding any dependency, answer all five questions:

1. Can this be implemented simply without it? If yes, write it.
2. Is it actively maintained? (Recent commits, issues acknowledged and resolved)
3. Does it have a clean security track record? (Check RustSec advisory database)
4. Is the licence compatible? (MIT, Apache 2.0, MPL 2.0 are acceptable; GPL
   requires careful review)
5. Is the version pinned explicitly? Use exact or tightly bounded versions in
   `Cargo.toml`.

Run `/supply-chain-audit` before adding any new crate to the dependency tree.
Run `/manage-deps` to review and update existing dependencies.

---

## Git and Version Control

- **Atomic commits**: each commit does exactly one thing. Mixed concerns belong
  in separate commits.
- **Conventional Commits format**: `feat:`, `fix:`, `refactor:`, `docs:`,
  `chore:`. Subject line under 72 characters. Body explains the reasoning and
  context, not the diff.
- **Never commit** generated files, secrets, `.env` files, or compiled
  artefacts (`target/`).
- **Branch naming** follows `<story-id>/<short-description>`:
  `us028/vault-cert-rotation`.
- **Pull requests** require a description explaining what changed and why, with
  a reference to the story ID.
- Force-push is only permitted on personal feature branches before a PR is
  opened, never after.

---

## Code Review Checklist

Before submitting code for review or marking a task complete, verify:

- [ ] Errors are handled explicitly — no silent failures or unchecked `unwrap()`
- [ ] All public functions have tests; security-critical functions have proptest
- [ ] Test names describe the scenario being tested
- [ ] The code follows existing patterns in the codebase
- [ ] A stranger could understand this code in six months without context
- [ ] No secrets, credentials, or API keys are present in the diff
- [ ] No new dependency was added without evaluation (see Dependencies above)
- [ ] Every `unsafe` block has a `// SAFETY:` comment
- [ ] Sensitive types use `secrecy::Secret` and `zeroize::Zeroize`
- [ ] Every modified file stays within the 750-line limit
- [ ] Relevant documentation has been updated (README.md, CLAUDE.md, etc.)

---

## DRY vs WET — The Rule of Three

Don't abstract prematurely. Duplication is acceptable the first and second time
you write something. On the **third occurrence**, refactor into a shared
abstraction.

The wrong abstraction is worse than duplication: a premature abstraction forces
every future use into a shape that doesn't quite fit, creating complexity that's
painful to undo. Three clear, slightly repetitive implementations are preferable
to one clever abstraction that obscures intent.

In Rust, extract a shared function or trait when the same logic appears in three
or more places. Extract a module when a group of related functions grows to the
point where a single file becomes hard to navigate.

---

## Logging

Log at the appropriate level for the audience and severity:

| Level   | Use for                                                        |
| ------- | -------------------------------------------------------------- |
| `TRACE` | Extremely detailed internals — crypto operations, byte counts  |
| `DEBUG` | Development detail — request payloads, query parameters        |
| `INFO`  | Significant state changes — service started, rotation complete |
| `WARN`  | Recoverable issues — retry attempted, fallback used            |
| `ERROR` | Failures requiring attention — request failed, write error     |

Rules:

- Include enough context to diagnose the issue without re-running: include
  IDs, paths, and relevant values alongside the error.
- **Never log sensitive data**: passwords, tokens, private keys, or secret
  values. Wrap sensitive types in `secrecy::Secret` so they cannot be
  accidentally formatted into log output.
- Use the `tracing` crate with structured fields for production services.
  Prefer `tracing::instrument` on public async functions for distributed tracing.
- Log at `ERROR` when an error propagates to the top of the call stack
  unhandled. Log at `WARN` or `DEBUG` when it is caught and recovered from.
- Security events (auth failures, vault access denied, certificate errors) must
  always be logged at `WARN` or above, never silently ignored.
