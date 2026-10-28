# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AutoOTP, please report it privately through **GitHub Private Vulnerability Reporting**:

- Open a private advisory report at: [GitHub Security Advisories](https://github.com/ab-pro-dev/AutoOTP/security/advisories/new)

Please do not disclose security vulnerabilities through public GitHub issues, pull requests, or discussions.

## Scope

### In Scope
- **Local WebSocket Server Security**: Authentication token verification, Host and Origin header enforcement, loopback-only binding (`127.0.0.1`), and connection limits.
- **Credential Storage**: AES-256-GCM encryption of Google OAuth refresh tokens and local file permissions (`0600`).
- **Browser Extension Isolation**: Secure storage of pairing credentials, restricted extension permissions (`storage`, `alarms`), and locking the pairing token away from page content scripts.
- **Log and Status Sanitization**: Proper masking of OTP codes in daemon logs, diagnostics, status files, and error traces.
- **History Database Security**: Encryption and automated retention cleanup of stored OTP records.
- **Sender Verification and Autofill Logic**: Accurate evaluation of DMARC authentication verdicts and domain matching before triggering automated autofill.

### Out of Scope
- Attacks requiring existing root privileges or unauthorized execution under the same local operating system user account.
- Vulnerabilities within external runtime environments, browsers, or upstream services (Node.js, Google Cloud/Gmail API) unless directly misconfigured or mishandled by AutoOTP.
- Issues related to email spoofing where the sending domain lacks SPF/DKIM/DMARC authentication policies.

## Response Expectations

Security reports are reviewed and acknowledged on a **best-effort basis**, with a goal of responding to actionable reports within 72 hours. Please note that this timeline is a target goal and not a legally binding service level agreement (SLA) or formal guarantee.
