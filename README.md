<div align="center">

# BHEESHMA

**Runtime Dependency Behavior Monitor for Node.js**
*The strace for npm packages.*

[![npm version](https://img.shields.io/npm/v/bheeshma.svg)](https://www.npmjs.com/package/bheeshma)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen.svg)](https://nodejs.org/)
[![CI](https://github.com/bbinfosec/bheeshma/actions/workflows/ci.yml/badge.svg)](https://github.com/bbinfosec/bheeshma/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-41%2F41%20passing-success.svg)]()
[![Wall of Shame](https://img.shields.io/badge/Wall%20of%20Shame-20%20threats-red.svg)](https://bbinfosec.github.io/bheeshma/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

*Catches supply-chain attacks that static analysis misses.*

[Quick Start](#-30-second-quick-start) | [GitHub Actions](#-github-actions-integration) | [npm install Monitor](#-npm-install-monitor) | [Wall of Shame](#-wall-of-shame-dashboard) | [CLI](#cli-usage) | [Configuration](#configuration)

</div>

---

## Why BHEESHMA?

In 2025-2026, the npm ecosystem was hit by a wave of supply-chain attacks:

| Attack | When | Impact |
|--------|------|--------|
| **Shai-Hulud Worm** | Sept 2025 | 200+ packages, automated CI/CD hijacking |
| **axios compromise** | Early 2026 | Stolen npm credentials, 10K+ systems, RAT malware |
| **Mini Shai-Hulud** | May 2026 | 84 TanStack packages compromised |
| **CanisterWorm** | 2026 | Self-propagating, exfiltration + persistence |

**Every major tool — Socket.dev, Snyk, Dependabot, npm audit — is pre-install static analysis.** They scan code *before* it runs. They cannot see what a package *actually does at runtime*.

BHEESHMA is different. It **monitors runtime behavior** — what your dependencies actually do when they execute. It catches:

- Malicious postinstall scripts stealing CI secrets
- Packages making outbound connections to exfiltration endpoints
- Obfuscated code executing at runtime
- Credential theft, crypto miners, data exfiltration
- Typosquat packages impersonating popular libraries
- DNS tunneling that bypasses HTTP-level monitoring

**Zero dependencies. Zero configuration. Zero telemetry.**

---

## 30-Second Quick Start

### GitHub Actions (recommended)

Add to your CI pipeline — one YAML line:

```yaml
# .github/workflows/ci.yml
- uses: bb1nfosec/bheeshma/.github/actions/bheeshma@main
  with:
    command: 'npm test'
    fail-level: 'critical'
```

Every PR will now show **runtime behavior annotations** from bheeshma directly in the GitHub diff view.

### npm install Monitor

Watch what packages do during installation:

```bash
npx bheeshma install
```

### Basic Monitoring

```bash
npx bheeshma -- node app.js
```

---

## GitHub Actions Integration

BHEESHMA outputs **SARIF v2.1.0** — the standard format for GitHub Code Scanning. Findings appear as inline annotations on every PR.

### Basic Setup

```yaml
name: CI
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: npm ci

      - uses: bb1nfosec/bheeshma/.github/actions/bheeshma@main
        with:
          command: 'npm test'
          fail-level: 'critical'    # fail on CRITICAL (default)
          upload-sarif: 'true'      # upload to Code Scanning
```

### All Options

| Input | Default | Description |
|-------|---------|-------------|
| `command` | _(required)_ | Command to run under monitoring |
| `fail-level` | `critical` | Minimum risk level to fail build (`critical`, `high`, `medium`, `low`) |
| `config` | `''` | Path to `.bheeshmarc.json` |
| `sarif-output` | `bheeshma-results.sarif` | SARIF output file path |
| `skip-low` | `true` | Skip LOW-risk signals in SARIF (reduces noise) |
| `upload-sarif` | `true` | Upload SARIF to GitHub Code Scanning |

### Advanced: Multiple Commands

```yaml
- name: Monitor npm install
  uses: bb1nfosec/bheeshma/.github/actions/bheeshma@main
  with:
    command: 'npm ci'
    fail-level: 'high'

- name: Monitor tests
  uses: bb1nfosec/bheeshma/.github/actions/bheeshma@main
  with:
    command: 'npm test'
    fail-level: 'critical'
    sarif-output: 'bheeshma-test-results.sarif'
```

---

## npm install Monitor

The **#1 attack vector** in 2025-2026 is malicious packages that steal CI secrets during `npm install`. BHEESHMA watches every package's install-time behavior:

```bash
# Monitor npm install
npx bheeshma install

# Monitor npm ci (lockfile-strict)
npx bheeshma install ci

# Monitor installing a specific package
npx bheeshma install -- --save-dev some-package

# Output SARIF for CI
npx bheeshma install -- --sarif --output install-results.sarif
```

What it catches:
- Postinstall scripts running shell commands
- Packages reading `.npmrc`, `.env`, or credential files
- Outbound network connections during install
- File writes outside `node_modules/`

---

## CLI Usage

### Monitor any command

```bash
# Monitor a Node.js app
bheeshma -- node app.js

# Monitor test suite
bheeshma -- npm test

# Monitor a specific script
bheeshma -- node scripts/build.js
```

### Output formats

```bash
# CLI (default, color-coded terminal output)
bheeshma -- node app.js

# JSON (machine-readable, for pipelines)
bheeshma --format json --output report.json -- npm test

# HTML (self-contained dark-themed report)
bheeshma --format html --output report.html -- node app.js

# SARIF (GitHub Code Scanning integration)
bheeshma --format sarif --output results.sarif -- npm test
```

### Enforcement mode

```bash
# Exit code 1 if any package is CRITICAL
bheeshma --enforce -- npm test

# Fail on HIGH or above
bheeshma-ci --fail-level high -- npm test

# JSON output + enforcement
bheeshma --enforce --format json --output report.json -- npm test
```

### CI-optimized mode

```bash
# bheeshma-ci is a thin wrapper optimized for CI pipelines
# - No ANSI colors, no HTML
# - SARIF output by default
# - Exit codes for policy enforcement
# - GitHub Actions ::error annotations

bheeshma-ci -- npm test
bheeshma-ci --fail-level high --output results.sarif -- npm test
```

### Subcommands

```bash
bheeshma install            # Monitor npm install
bheeshma ci -- <command>    # CI-optimized mode
bheeshma -- <command>       # Standard monitoring
```

### Programmatic API

```javascript
const bheeshma = require('bheeshma');

// Initialize with default settings
bheeshma.init();

// Your application code runs here
require('./your-app');

// Generate report in any format
console.log(bheeshma.generateReport('cli'));
console.log(bheeshma.generateReport('json'));
console.log(bheeshma.generateReport('sarif'));

// Check enforcement policy
const result = bheeshma.enforcePolicy();
if (!result.passed) {
  console.error('Policy violation:', result.message);
  process.exit(1);
}
```

---

## What BHEESHMA Monitors

| Behavior | Signal Type | Risk | What It Detects |
|----------|-------------|------|------------------|
| Environment variable access | `ENV_ACCESS` | Medium | Credential theft, API key exfiltration |
| File system reads | `FS_READ` | Low | Reconnaissance, credential file access |
| File system writes | `FS_WRITE` | High | Persistence, backdoor installation |
| Raw TCP connections | `NET_CONNECT` | High | Reverse shells, C2 communication |
| HTTP requests | `HTTP_REQUEST` | High | Unencrypted data exfiltration |
| HTTPS requests | `HTTPS_REQUEST` | Medium-High | Encrypted data exfiltration |
| DNS queries | `DNS_QUERY` | Medium-High | DNS tunneling, encoded subdomain exfil |
| Shell execution | `SHELL_EXEC` | Critical | Arbitrary code execution |
| Obfuscated code | `OBFUSCATION_DETECTED` | Critical | Hidden payloads, eval/Function |
| Blacklisted packages | `BLACKLISTED_PACKAGE` | Critical | Known malicious packages |

### Pattern Detection

BHEESHMA correlates signals to detect complex attack patterns:

| Pattern | Signals | Severity |
|---------|---------|----------|
| **Crypto mining** | `WALLET_ADDRESS` + `MINING_POOL` env vars | CRITICAL |
| **Data exfiltration** | Credential file read + outbound HTTP | CRITICAL |
| **Backdoor** | Shell exec + reverse connection | CRITICAL |
| **Credential theft** | `.env`/`.npmrc` read (context-aware) | HIGH/LOW* |
| **Typosquat** | Package name similar to popular package | HIGH |

*Context-aware: dotenv reading `.env` = LOW (expected). A random package reading `.env` = HIGH (suspicious).

### Trust Scoring

Each package gets a **deterministic trust score [0-100]**:

- **80-100 (LOW risk)**: Minimal or benign behavior
- **60-79 (MEDIUM risk)**: Moderate activity, review recommended
- **30-59 (HIGH risk)**: Elevated activity, investigation required
- **0-29 (CRITICAL risk)**: Highly suspicious, immediate action needed

---

## Configuration

Create `.bheeshmarc.json` in your project root (fully optional):

```json
{
  "thresholds": {
    "critical": 30,
    "high": 60,
    "medium": 80
  },
  "packageThresholds": {
    "axios": 40,
    "express": 50
  },
  "whitelist": ["express@*", "@types/*"],
  "blacklist": ["malicious-package"],
  "patterns": {
    "enabled": true,
    "detectCryptoMiners": true,
    "detectDataExfiltration": true,
    "detectBackdoors": true
  },
  "performance": {
    "maxSignals": 10000,
    "deduplicateSignals": true
  }
}
```

Or use `bheeshma --config .bheeshmarc.json -- node app.js`.

---

## Wall of Shame Dashboard

[![Visit Wall of Shame](https://img.shields.io/badge/Visit-Wall%20of%20Shame-red?style=for-the-badge)](https://bbinfosec.github.io/bheeshma/)

The **bheeshma Wall of Shame** is a live threat intelligence dashboard that tracks every known npm supply chain attack and shows how bheeshma catches them.

**Live at:** [bbinfosec.github.io/bheeshma](https://bbinfosec.github.io/bheeshma/)

### What It Shows

- **20+ curated supply chain threats** — from the axios compromise to Shai-Hulud to AI-themed phishing packages
- **Live OSV feed** — real-time npm vulnerabilities from the Open Source Vulnerabilities database
- **100% bheeshma coverage** — every tracked threat is caught by bheeshma signals at runtime
- **Trend charts** — supply chain attack frequency over time (2024-2025)
- **Attack type breakdown** — malware, typosquats, backdoors, credential theft, protest-ware, data exfiltration
- **Signal detection bars** — which bheeshma signals fire most across all known attacks

### Auto-Updates

The dashboard refreshes **daily at 06:00 UTC** via GitHub Actions:

1. `scripts/fetch-threats.js` fetches the latest npm vulnerabilities from the **OSV API**
2. Merges with the curated local threat database
3. Regenerates `dashboard/data/threats.json`
4. Commits and pushes the updated data
5. GitHub Pages deploys the updated dashboard automatically

### Add Your Own Threats

Edit `scripts/fetch-threats.js` and add entries to the `CURATED_THREATS` array. The format:

```javascript
{
  id: 'T2025-021',
  package: 'package-name',
  version: '1.0.0',
  title: 'Short descriptive title',
  description: 'Full description of the attack',
  severity: 'critical', // critical | high | medium | low
  type: 'backdoor',   // malware | typosquat | backdoor | data-exfil | etc.
  date: '2025-05-01',
  status: 'removed',  // active | removed | patched | unpublished
  downloads: '50K+',
  bheeshma_signals: ['NETWORK_CONNECTION', 'SHELL_EXEC', 'DNS_QUERY'],
  references: ['https://source-url'],
  cve: 'CVE-YYYY-XXXXX' // optional
}
```

---

## Security Guarantees

- **Zero telemetry** — No outbound communication (except webhook alerts if configured)
- **Local-only** — All processing happens on your machine
- **Zero dependencies** — Pure Node.js, no npm packages required
- **Metadata only** — Never captures secrets, file contents, or request bodies
- **Non-invasive** — Observes behavior without modifying it
- **Fail-safe** — Hook errors never break your application
- **Immutable signals** — All signals are frozen after creation

---

## Installation

```bash
# Global install
npm install -g bheeshma

# Or use with npx (no install needed)
npx bheeshma -- node app.js
```

**Requirements:** Node.js >= 14.0.0. No other dependencies.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    CLI Layer                         │
│   bheeshma  │  bheeshma-ci  │  bheeshma-install     │
└──────────────────┬───────────────────────────────────┘
                   │
┌──────────────────▼───────────────────────────────────┐
│              Output Formatters                        │
│   CLI  │  JSON  │  HTML  │  SARIF v2.1.0            │
└──────────────────┬───────────────────────────────────┘
                   │
┌──────────────────▼───────────────────────────────────┐
│     Policy Engine + Trust Scoring                     │
│   Enforcement │ Thresholds │ Dedup │ Blacklist        │
└──────────────────┬───────────────────────────────────┘
                   │
┌──────────────────▼───────────────────────────────────┐
│        Pattern + Obfuscation Detection                 │
│   Crypto │ Exfil │ Backdoors │ Typosquat │ Static    │
└──────────────────┬───────────────────────────────────┘
                   │
┌──────────────────▼───────────────────────────────────┐
│          Attribution Engine                            │
│   Stack trace → outermost node_modules resolution    │
└──────────────────┬───────────────────────────────────┘
                   │
┌──────────────────▼───────────────────────────────────┐
│            Runtime Hooks (6 types)                    │
│   env │ fs │ net │ http │ dns │ child_process         │
├──────────────────────────────────────────────────────┤
│   Worker Thread Support  │  ESM Loader                │
└──────────────────────────────────────────────────────┘
```

---

## Testing

```bash
npm test        # 41/41 tests, no network required
```

All tests run **offline** with **deterministic results**.

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**We especially want:**
- Real-world attack replay scripts (like our [demos/](demos/))
- False positive reports with reproduction steps
- New hook types (e.g., `crypto`, `fs.watch`)
- Performance optimizations for large codebases

---

## License

**Apache License 2.0**

---

## Credits

Built by security engineers who believe the npm ecosystem deserves a runtime monitoring tool that anyone can use, understand, and trust.

**BHEESHMA**: Trust, but verify. At runtime.
