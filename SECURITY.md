# Security Policy

## Security Philosophy

BHEESHMA is a security tool designed to protect Node.js applications from supply-chain attacks. We take security seriously and follow strict secure coding practices.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Our Security Guarantees

### What BHEESHMA Does NOT Do

- ❌ **No telemetry** - Zero outbound network communication
- ❌ **No cloud services** - All processing is local
- ❌ **No persistent storage** - Data exists only in memory
- ❌ **No secret capture** - Only metadata (variable names, paths, hosts)
- ❌ **No behavior modification** - Observes only, never alters

### What BHEESHMA Protects Against

- ✅ Credential theft (environment variable access)
- ✅ Data exfiltration (network connections)
- ✅ Persistence mechanisms (filesystem writes)
- ✅ Arbitrary code execution (shell commands)

### Security Standards Followed

- **OWASP Secure Coding Practices**
- **CERT/SEI Secure Coding Standards**
- **Node.js Security Best Practices**

## Reporting a Vulnerability

### Where to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead:
1. **Email**: [Your security email - e.g., security@yourdomain.com]
2. **Subject**: `[SECURITY] BHEESHMA - <brief description>`

Alternatively, use GitHub Security Advisories:
- Go to the Security tab
- Click "Report a vulnerability"

### What to Include

Please provide:
- **Vulnerability Description**: What is the security issue?
- **Impact**: What can an attacker do?
- **Affected Versions**: Which versions are vulnerable?
- **Reproduction Steps**: How to reproduce the issue
- **Proposed Fix**: If you have suggestions
- **Disclosure Timeline**: When you plan to disclose publicly

### Response Process

1. **Acknowledgment**: Within 48 hours
2. **Triage**: Within 1 week
3. **Fix Development**: Depends on severity
4. **Disclosure**: Coordinated with reporter

### Severity Levels

| Severity | Response Time | Example |
|----------|---------------|---------|
| **Critical** | 48 hours | Remote code execution, secret leakage |
| **High** | 1 week | Privilege escalation, data corruption |
| **Medium** | 2 weeks | Denial of service, info disclosure |
| **Low** | 1 month | Minor issues with limited impact |

## Security Best Practices for Users

### Installation

```bash
# Always verify package integrity
npm install bheeshma --package-lock
```

### Usage

```bash
# Run in isolated environment for untrusted code
# BHEESHMA itself is safe, but the code it monitors may not be
```

### Trust Scores

- **0-29 (CRITICAL)**: Immediate investigation required
- **30-59 (HIGH)**: Review before production
- **60-79 (MEDIUM)**: Monitor over time
- **80-100 (LOW)**: Generally safe

## Known Limitations

### Out of Scope

BHEESHMA cannot detect:
- **Pre-hook activity**: Behaviors before `init()` is called
- **Native addons**: C++ modules bypass JavaScript hooks
- **Worker threads**: Currently not monitored (V2 feature)
- **Time bombs**: Delayed execution after monitoring stops

### Not Vulnerability Fixes

These are design limitations, not bugs:
- First-party code is not attributed (by design)
- Signals require node_modules structure
- ESM support is partial (full support in V2)

## Disclosure Policy

We follow **responsible disclosure**:
1. Reporter notifies us privately
2. We develop and test fix
3. We notify affected users
4. We release patched version
5. **30 days later**: Public disclosure (or earlier with reporter agreement)

## Hall of Fame

Security researchers who responsibly disclose vulnerabilities will be:
- Listed here with gratitude
- Acknowledged in release notes
- Credited in CVE (if applicable)

*No researchers yet - be the first!*

## Security Updates

Subscribe to:
- **GitHub Releases**: Watch this repository
- **Security Advisories**: Enable notifications
- **npm**: `npm outdated` to check for updates

## Questions?

For **non-security questions**, use GitHub Issues or Discussions.

For **security matters only**, use the private reporting channels above.

---

**Last Updated**: 2026-01-18
