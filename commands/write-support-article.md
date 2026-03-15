# Write Support Article Command

## Table of Contents

- [Overview](#overview)
- [When to Use](#when-to-use)
- [What It Does](#what-it-does)
- [Parameters](#parameters)
- [Output](#output)
- [Examples](#examples)
- [Best Practices](#best-practices)
- [Related Commands](#related-commands)

---

## Overview

**Command:** `/rust-security:write-support-article`

Creates user-facing help documentation and support articles for Rust applications. Generates troubleshooting guides, FAQ entries, security best practices guides, and error message explanations tailored for end users.

**Agent:** `rust-support-articles` (Sonnet - Standard Analysis)

---

## When to Use

Use this command when:

- **Launching new features** - Create user documentation for new functionality
- **Addressing common issues** - Document frequently encountered problems
- **Security feature documentation** - Explain security features to users
- **Error message clarification** - Provide helpful troubleshooting steps
- **Onboarding users** - Create getting started guides
- **Before major releases** - Update documentation for new versions

---

## What It Does

1. **Analyzes application features** to identify documentation needs
2. **Creates troubleshooting guides** for common error scenarios
3. **Generates FAQ entries** from issue tracker and user questions
4. **Documents security features** in user-friendly language
5. **Creates step-by-step tutorials** with screenshots and examples
6. **Builds searchable knowledge base** articles
7. **Validates documentation clarity** for non-technical users

---

## Parameters

| Parameter          | Type     | Required | Default       | Description                                      |
| ------------------ | -------- | -------- | ------------- | ------------------------------------------------ |
| `--topic`          | string   | No       | Auto-detect   | Article topic or feature name                    |
| `--type`           | string   | No       | `guide`       | Type: `guide`, `faq`, `troubleshooting`, `security` |
| `--output-dir`     | string   | No       | `docs/support/` | Output directory                               |
| `--audience`       | string   | No       | `users`       | Target audience: `users`, `developers`, `admins` |
| `--format`         | string   | No       | `markdown`    | Format: `markdown`, `html`, `pdf`                |

---

## Output

### Console Output

```
📖 Syntek Rust Security - Support Article Generation

📦 Project: secure-messenger v2.0.0
📝 Article type: Security Guide
👥 Target audience: End Users

✅ Generated support articles:

Security Guides:
  - docs/support/end-to-end-encryption.md
  - docs/support/two-factor-authentication.md
  - docs/support/secure-backups.md

Troubleshooting:
  - docs/support/connection-errors.md
  - docs/support/sync-issues.md
  - docs/support/login-problems.md

FAQ:
  - docs/support/faq-encryption.md
  - docs/support/faq-privacy.md

Getting Started:
  - docs/support/quick-start-guide.md
  - docs/support/first-time-setup.md

📊 Documentation metrics:
  - Total articles: 10
  - Reading level: Grade 8
  - Average length: 850 words
  - Code examples: 15
  - Screenshots: 8

🌐 Articles ready for knowledge base deployment
```

---

## Examples

### Example 1: Security Feature Guide

```bash
/rust-security:write-support-article --topic=encryption --type=security
```

Creates user-friendly guide explaining encryption features.

### Example 2: Troubleshooting Guide

```bash
/rust-security:write-support-article --type=troubleshooting --topic=authentication
```

Generates troubleshooting guide for authentication issues.

### Example 3: FAQ Generation

```bash
/rust-security:write-support-article --type=faq --audience=users
```

Creates FAQ from common user questions and issues.

### Example 4: Admin Documentation

```bash
/rust-security:write-support-article --audience=admins --type=guide
```

Generates administrator-focused configuration guides.

### Example 5: Multi-Format Output

```bash
/rust-security:write-support-article --format=html --output-dir=kb/articles/
```

Creates HTML articles for knowledge base integration.

---

## Best Practices

### User-Friendly Security Documentation

```markdown
# How to Enable Two-Factor Authentication

Two-factor authentication (2FA) adds an extra layer of security to your account. Even if someone knows your password, they won't be able to access your account without the second factor.

## What You'll Need

- Your smartphone
- An authenticator app (we recommend Google Authenticator or Authy)
- 5 minutes

## Step-by-Step Guide

### Step 1: Open Security Settings

1. Click your profile picture in the top right
2. Select "Settings" from the dropdown
3. Click "Security" in the left sidebar

### Step 2: Enable Two-Factor Authentication

1. Find the "Two-Factor Authentication" section
2. Click "Enable 2FA"
3. You'll see a QR code on screen

### Step 3: Set Up Your Authenticator App

1. Open your authenticator app
2. Tap the "+" button to add a new account
3. Scan the QR code displayed on screen
4. The app will generate a 6-digit code

### Step 4: Confirm Setup

1. Enter the 6-digit code from your app
2. Click "Verify"
3. Save your backup codes in a safe place

## Troubleshooting

**Problem: QR code won't scan**
- Solution: Click "Enter code manually" and type the setup key

**Problem: Code keeps saying "Invalid"**
- Solution: Check your phone's time is set to automatic

**Problem: Lost access to authenticator app**
- Solution: Use one of your backup codes to log in, then disable and re-enable 2FA

## Keeping Your Account Secure

✅ DO:
- Keep backup codes in a safe place
- Use a different password for each account
- Enable 2FA on all important accounts

❌ DON'T:
- Share your authenticator codes
- Screenshot your QR code
- Disable 2FA unless necessary
```

---

## Reference Documents

This command invokes the `rust-support-articles` agent. The agent reads these documents
from the target project's `.claude/` directory before starting work. Ensure the
project has been initialised with `/init`:

- **[CODING-PRINCIPLES.md](.claude/CODING-PRINCIPLES.md)**
- **[SECURITY.md](.claude/SECURITY.md)**
- **[TESTING.md](.claude/TESTING.md)**
- **[DEVELOPMENT.md](.claude/DEVELOPMENT.md)**

## Related Commands

- **[/rust-security:generate-docs](generate-docs.md)** - Technical API documentation
- **[/rust-security:review-code](review-code.md)** - Code review before documentation
- **[/rust-security:compliance-report](compliance-report.md)** - Compliance documentation

---

**Note:** Support articles should be written for non-technical users. Use simple language, screenshots, and step-by-step instructions.
