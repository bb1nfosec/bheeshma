<div align="center">

# 🛡️ BHEESHMA

**Runtime Dependency Behavior Monitor for Node.js**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen.svg)](https://nodejs.org/)
[![CI](https://github.com/bbinfosec/bheeshma/actions/workflows/ci.yml/badge.svg)](https://github.com/bbinfosec/bheeshma/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-22%2F22%20passing-success.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

*Detect software supply-chain abuse at runtime by observing what third-party npm dependencies actually do.*

[Installation](#installation) • [Usage](#usage) • [CI/CD Enforcement](#policy-enforcement-mode) • [Examples](#example-output) • [Documentation](#documentation)

</div>

---

Modern applications depend on hundreds of third-party npm packages. While static analysis and CVE scanning help, they cannot detect:

- **Zero-day malicious packages** not yet in vulnerability databases
- **Compromised legitimate packages** (e.g., event-stream, ua-parser-js incidents)
- **Dependency confusion attacks** that execute malicious code at install or runtime
- **Behavioral abuse** that doesn't match known CVE signatures
- **DNS tunneling** that exfiltrates data before any HTTP connection opens
- **Obfuscated payloads** hidden in encoded strings

**Traditional tools tell you what dependencies _are_. BHEESHMA tells you what dependencies _do_.**

---

## What's New in v3.0

| Feature | Description |
|---------|-------------|
| **🚦 Policy Enforcement** | `--enforce` flag for CI/CD pipelines — exit(1) on CRITICAL packages |
| **🌐 DNS Monitoring** | Detects DNS tunneling, high-entropy subdomains, known exfil services |
| **🔍 Obfuscation Detection** | Static analysis: eval(), hex escapes, Base64 chains, Function() |
| **📦 ESM Support** | `--loader` API catches pure ESM packages (got, node-fetch v3+) |
| **🔧 Worker Threads** | Signal collection from `worker_threads` via bootstrap injection |
| **🎯 Per-Package Thresholds** | Custom trust score thresholds per package |
| **📊 HTML Reports** | Self-contained HTML with dark theme, filtering, JSON export |
| **🔔 Webhook Alerts** | POST critical findings to Slack, Discord, ntfy.sh |
| **🧹 Signal Deduplication** | Collapses 300 identical HTTP calls into 1 readable entry |
| **📍 Accurate Attribution** | Outermost node_modules resolution (no more transitive mislabels) |

---

## What BHEESHMA Monitors

| Behavior | Risk | What It Detects |
|----------|------|------------------|
| **Environment Variable Access** | Medium | Credential theft, API key exfiltration |
| **File System Reads** | Low-Medium | Reconnaissance, credential file access |
| **File System Writes** | High | Persistence mechanisms, data exfiltration |
| **Network Connections** | Medium-High | Data exfiltration, C&C communication |
| **HTTP/HTTPS Requests** | Medium-High | Data exfiltration, suspicious service communication |
| **Shell Execution** | Critical | Arbitrary code execution, system compromise |
| **DNS Queries** | Medium-High | DNS tunneling, encoded subdomain exfiltration |
| **Obfuscated Code** | Critical | Hidden payloads, eval/Function constructors |

### Trust Scoring

BHEESHMA calculates a **deterministic trust score** [0-100] for each package:

- **80-100 (LOW risk)**: Minimal or benign behavior
- **60-79 (MEDIUM risk)**: Moderate activity, review recommended
- **30-59 (HIGH risk)**: Elevated activity, investigation required
- **0-29 (CRITICAL risk)**: Highly suspicious, immediate action needed

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

### Basic Monitoring

```bash
bheeshma -- node app.js
```

### Policy Enforcement Mode (CI/CD)

```bash
# Exit with code 1 if any package exceeds risk threshold
bheeshma --enforce -- npm test

# JSON output + enforcement for CI pipelines
bheeshma --enforce --format json --output report.json -- npm test
```

### HTML Reports

```bash
# Generate a self-contained HTML report
bheeshma --format html --output report.html -- node app.js
```

### Webhook Alerts

```bash
# Alert to Slack/Discord on critical findings
bheeshma --alert-webhook https://hooks.slack.com/services/XXX -- node app.js
```

### Custom Configuration

```bash
bheeshma --config .bheeshmarc.json -- node app.js
```

### Programmatic API

```javascript
const bheeshma = require('bheeshma');

// Initialize with default settings
bheeshma.init();

// Your application code
require('./your-app');

// Check enforcement policy
const result = bheeshma.enforcePolicy();
if (!result.passed) {
  console.error('Policy violation:', result.message);
  process.exit(1);
}

// Generate report
console.log(bheeshma.generateReport('cli'));
```

---

## Policy Enforcement Mode

The `--enforce` flag makes BHEESHMA immediately useful in CI pipelines:

```yaml
# GitHub Actions example
- name: Security Check
  run: npx bheeshma --enforce --format json --output report.json -- npm test
```

When enabled, BHEESHMA will:
1. Run your command normally
2. Generate a report with trust scores
3. Check each package against thresholds (default CRITICAL: < 30)
4. Exit with code 1 if any package is CRITICAL, printing the offender
5. Optionally send a webhook alert

### Per-Package Thresholds

Tune known-noisy packages without fully whitelisting them:

```json
{
  "packageThresholds": {
    "axios": 40,
    "express": 50
  }
}
```

### Whitelist Suppression

Whitelisted packages are suppressed at the hook layer — signals are never even recorded:

```json
{
  "whitelist": ["express@*", "@types/*"]
}
```

---

## Configuration

Create `.bheeshmarc.json` in your project root:

```json
{
  "hooks": {
    "env": true,
    "fs": true,
    "net": true,
    "childProcess": true,
    "http": true,
    "dns": true
  },
  "riskWeights": {
    "SHELL_EXEC": 20,
    "FS_WRITE": 10,
    "HTTP_REQUEST": 10,
    "HTTPS_REQUEST": 8,
    "NET_CONNECT": 8,
    "DNS_QUERY": 4,
    "ENV_ACCESS": 5,
    "FS_READ": 3,
    "OBFUSCATION_DETECTED": 25
  },
  "thresholds": {
    "critical": 30,
    "high": 60,
    "medium": 80
  },
  "packageThresholds": {
    "axios": 40
  },
  "whitelist": ["express@*"],
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
    "maxSignals": 10000,
    "deduplicateSignals": true
  },
  "output": {
    "formats": ["cli"],
    "verbosity": "normal",
    "includeStackTraces": true
  },
  "enforce": false,
  "alertWebhook": null
}
```

---

## DNS Monitoring

BHEESHMA wraps `dns.lookup`, `dns.resolve`, `dns.resolve4`, `dns.resolve6`, and `dns.resolveTxt` to detect:

- **Abnormally long subdomains** (>50 chars, indicating encoded data)
- **High-entropy subdomains** (Shannon entropy > 4.0 bits)
- **Base64/hex encoded subdomains**
- **Known exfiltration services** (dnshook.site, webhook.site, ngrok.io)

DNS tunneling — data exfiltration via encoded subdomains like `c2-payload.evil.io` — goes completely undetected by HTTP-level monitoring. BHEESHMA catches it at the resolver.

---

## Obfuscation Detection

At module load time, BHEESHMA performs static analysis on each package's entry point:

| Pattern | Severity | Description |
|---------|----------|-------------|
| `eval()` | HIGH | Dynamic code execution |
| `Function()` | HIGH | Constructor-based code execution |
| `Buffer.from().toString()` | MEDIUM | Base64 payload decoding |
| Long hex literals (>100 chars) | HIGH | Hex-encoded payloads |
| `\x` escape density > 10% | HIGH | Heavily obfuscated source |
| `String.fromCharCode` chains | HIGH | String obfuscation |
| `atob()` | MEDIUM | Base64 decoding |

---

## Example Output

### CLI Format

```
======================================================================
  BHEESHMA Runtime Dependency Behavior Report
======================================================================

Summary:
  Total Packages Monitored: 3
  Total Signals Captured: 24

  Risk Distribution:
    CRITICAL: 1
    HIGH: 1
    LOW: 1

📦 suspicious-package@1.0.0
   Trust Score: 15/100 [CRITICAL]

   Observed Behaviors:
     ⚡  SHELL EXEC: 1 occurrence
     📝  FS WRITE: 2 occurrence
     🔐  ENV ACCESS: 5 occurrence (3 unique)
     🌐  DNS QUERY: 1 occurrence
```

### JSON Format

```json
{
  "version": "1.0",
  "summary": {
    "totalPackages": 2,
    "riskDistribution": { "critical": 1, "high": 0, "medium": 0, "low": 1 }
  },
  "packages": [...]
}
```

---

## Security Guarantees

- ✅ **Zero telemetry** — No outbound communication (except webhook alerts if configured)
- ✅ **Local-only** — All processing happens on your machine
- ✅ **No external dependencies** — Pure Node.js, no npm packages required
- ✅ **Non-invasive hooks** — Observes behavior without modifying it
- ✅ **Fail-safe** — Hook errors never break your application
- ✅ **Data minimization** — Metadata only, never captures secrets or content

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│              CLI / Programmatic API              │
│         --enforce, --alert-webhook, --html      │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│           Output Formatters                     │
│        (CLI, JSON, HTML)                        │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│     Policy Engine + Trust Scoring               │
│   (Enforcement, Thresholds, Dedup, Whitelist)   │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│           Signal Normalization Layer              │
│         (Immutable, Type-Safe)                  │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│          Attribution Engine                       │
│   (Outermost node_modules, ESM loader)          │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│           Runtime Hooks                          │
│   (env, fs, net, http, dns, child_process)     │
├─────────────────────────────────────────────────┤
│        Pattern + Obfuscation Detection           │
│     (Crypto, Exfil, Backdoors, Static Analysis) │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│   Worker Thread Support (signal relay)           │
│   ESM Loader (import interception)              │
└─────────────────────────────────────────────────┘
```

---

## Testing

```bash
npm test
```

All tests run **without network access** and produce **deterministic results**.

---

## Contributing

Contributions welcome! See `CONTRIBUTING.md` for guidelines.

---

## License

**Apache License 2.0**

---

## Credits

Built with discipline by security engineers who believe AI-assisted coding can produce production-grade software when guided by strong engineering principles.

**BHEESHMA**: Trust, but verify. At runtime.
