# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.1.x   | ✅ Active  |
| 1.0.x   | ✅ Active  |

## Reporting a Vulnerability

If you discover a security vulnerability in Appraisal: DEX itself
(e.g., a path traversal in APK parsing, arbitrary code execution via
maliciously crafted APK, or credential exposure in report output),
please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

### Contact

Open a [GitHub Security Advisory](https://github.com/rithinkrishnakv/appraisal-dex/security/advisories/new)
on this repository — this is a private, coordinated disclosure channel.

### What to Include

- Description of the vulnerability
- Steps to reproduce (with a minimal test case if possible)
- Impact assessment
- Suggested fix (optional)

### Response Timeline

- **Acknowledgement**: within 48 hours
- **Assessment**: within 7 days
- **Fix / CVE filing**: within 30 days

### Scope

In scope:
- Arbitrary code execution via crafted APK input
- Path traversal reading files outside intended scope
- Credential exposure in generated reports
- Dependency vulnerabilities with direct exploit path

Out of scope:
- The tool correctly identifying vulnerabilities in third-party APKs
- Frida scripts that bypass app security (this is intended functionality)
- Social engineering

## Responsible Use

Appraisal: DEX is a security research tool. Use it only on applications
you own or have explicit written authorization to test.
Unauthorized security testing may violate the Computer Fraud and Abuse Act,
the Computer Misuse Act, and equivalent laws in your jurisdiction.
