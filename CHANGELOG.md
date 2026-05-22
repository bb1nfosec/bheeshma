# Changelog

All notable changes to BHEESHMA will be documented in this file.

<<<<<<< HEAD
## [2.1.0] - 2026-05-16

### Fixed

- **GitHub Action installs from repo, not npm**: The composite action now uses the checked-out source directly instead of `npm install bheeshma@latest`, which was pulling the stale v2.0.0
- **SARIF formatter export mismatch**: `bheeshma-ci.js` imported `formatSarifReport` but the module exported `formatReport` — fixed with alias import
- **package.json repository URL**: Fixed typo `bbinfosec` → `bb1nfosec` across repository, bugs, and homepage fields
- **CI workflow**: Cleaned up branch config (removed `master`), added Node 22.x to matrix, added self-monitoring test
- **Wall of Shame pipeline**: Auto-update now syncs fresh data to `gh-pages` branch after committing to `main`

### Added

- **Issue templates**: Bug report, feature request, and security vulnerability report forms
- **PR template**: Checklist for tests, compatibility, and documentation
- **CODE_OF_CONDUCT.md**: Contributor Covenant v2.1
- **FUNDING.yml**: GitHub Sponsors link
- **Lockfile**: `package-lock.json` for build reproducibility
- **Post-install message**: Global installs display version, description, and GitHub star link
- **New keywords**: `strace`, `threat-intelligence`, `devsecops`

### Changed

- **Version**: 1.0.0 → 2.1.0 (supersedes stale npm v2.0.0)
- **Homepage**: Points to Wall of Shame dashboard at `bb1nfosec.github.io/bheeshma`
=======
## [1.1.0] - 2026-05-17

### Added

#### New Runtime Hooks
- **VM hook** (`src/hooks/vmHook.js`): Detects `vm.runInNewContext()`, `vm.runInThisContext()`, `vm.runInContext()`, `vm.compileFunction()`, `new vm.Script()` — closes hook-evasion via fresh V8 contexts. Emits `VM_EXEC` signal.
- **Crypto hook** (`src/hooks/cryptoHook.js`): Monitors `createCipheriv`, `createDecipheriv`, `createHash`, `createHmac`, `randomBytes`, `randomFill`, `pbkdf2`, `scrypt` — flags unexpected cipher/decipher ops indicating embedded encrypted payloads. Emits `CRYPTO_OP` signal.
- **IPC/Unix socket detection**: `net.connect()` now handles string path args (e.g. `/var/run/docker.sock`).

#### New Signal Types
- `VM_EXEC` (weight: 20) — vm module code execution
- `CRYPTO_OP` (weight: 8) — cryptographic operations
- `HOOK_TAMPER` (weight: 100) — active replacement of bheeshma's hook wrappers
- `PROTO_POLLUTION` (weight: 30) — `Object.prototype` / `__proto__` mutation (static detection)

#### Behavioral Baseline Mode
- **`src/baseline/baselineManager.js`**: Capture, load, filter, and diff behavioral baselines.
- **`--learn <file>` CLI flag**: Run the app, save all signals as known-good baseline.
- **`--baseline <file>` CLI flag**: Suppress known-good signals from scoring so only new behaviors trigger alerts. Eliminates false-positive fatigue on apps with many legitimate network-calling dependencies.

#### Hook Tamper Detection
- After all hooks are installed, `src/index.js` snapshots each wrapper reference.
- At `generateReport()` time, stale references inject `HOOK_TAMPER` signals automatically.
- Catches malicious packages that overwrite `require('fs').readFile` or `require('net').connect`.

#### Sampling Mode
- `performance.sampleRate` config key (0.0–1.0, default 1.0).
- First occurrence of any dedup key is always recorded; subsequent occurrences are probabilistically dropped. Reduces memory pressure from high-frequency duplicate signals (e.g., a package calling `readFile` thousands of times per second).

#### Persistent Signal Log
- `logging.logFile` config key: append every accepted signal as NDJSON to a file.
- Survives process crashes. Useful for auditing long-running servers post-incident.

#### CycloneDX SBOM Output
- **`src/output/sbomFormatter.js`**: Generates CycloneDX 1.4 JSON SBOMs from observed packages.
- Includes purl, bom-ref, bheeshma trust score, risk level, signal counts, and per-signal-type breakdown as CycloneDX properties.
- Sorted by trust score ascending (most risky first).
- Compliant with US EO 14028 and EU Cyber Resilience Act.

#### Structured Webhook Payloads
- `webhookFormat` config key: `generic` | `slack` | `pagerduty` | `teams`.
- **`--webhook-format <format>` CLI flag** for per-run override.
- Slack: Block Kit message with header + section + context blocks.
- PagerDuty: Events API v2 `trigger` payload.
- Microsoft Teams: Adaptive Card (MessageCard format).

#### Three New CLI Tools
- **`bheeshma-diff`** (`bin/bheeshma-diff.js`): Compare two JSON reports side-by-side. Shows new packages and score regressions. Exit 1 if new findings. Supports `--format json` for machine-readable output.
- **`bheeshma-lock`** (`bin/bheeshma-lock.js`): SHA-256 lockfile integrity checker. `--save` records hashes of all lockfiles; `--verify` detects tampering. Supports `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `npm-shrinkwrap.json`.
- **`bheeshma-explain`** (`bin/bheeshma-explain.js`): Plain-English explanation of a JSON report. Describes what each package did, why it's suspicious, and recommended remediation. Supports `--package`, `--min-risk` filters.

#### Enhanced Pattern Detection
- **Temporal correlation** in data exfiltration: measures time gap between sensitive file read and HTTP request. ≤2s = CRITICAL, ≤30s = HIGH, >30s or no timing = MEDIUM.
- **Context-aware safe packages**: `KNOWN_SAFE_CONTEXTS` map downgrades severity for well-known build tools (jest, webpack, typescript, esbuild, vite, babel, etc.).
- **Prototype pollution static patterns** in obfuscation detector: `Object.prototype.x =`, `__proto__ =`, `constructor.prototype.x =`.
- **10 obfuscation patterns** (up from 8): added `CHAR_CODE_ARRAY` (long integer arrays) and `PROCESS_BINDING` (direct Node.js C++ internal access).

#### DNS Hook Expansion
- Added 8 more `dns` module methods: `resolveMx`, `resolveCname`, `resolveNs`, `resolveSrv`, `resolveCaa`, `resolveNaptr`, `resolvePtr`, `reverse`.
- Added full `dns.promises.*` coverage — Node 10+ async DNS API now monitored.

#### Attribution Accuracy
- Improved stack frame extraction with dual-regex approach.
- Self-exclusion: signals are never attributed to `bheeshma` itself when installed as a package in the monitored project.

### Changed
- **`src/index.js`**: Wired vmHook + cryptoHook into init/teardown, added hook tamper detection, sampling, persistent log, baseline filtering, multi-format webhook support.
- **`bin/bheeshma.js`**: Added `diff`, `lock`, `explain`, `learn` subcommands; `--fail-level`, `--baseline`, `--learn`, `--webhook-format` flags; updated help text.
- **`package.json`**: Added 3 new bin entries (`bheeshma-diff`, `bheeshma-lock`, `bheeshma-explain`).
- **`src/config/schema.js`**: Added `hooks.vm`, `hooks.crypto`, `performance.sampleRate`, `logging.logFile`, `baselineFile`, `webhookFormat` with full validation.
- **`src/signals/signalTypes.js`**: Added `VM_EXEC`, `CRYPTO_OP`, `HOOK_TAMPER`, `PROTO_POLLUTION` signal types.
- **`src/scoring/trustScore.js`**: Added risk weights for new signal types; added `findViolatingPackages(scores, failLevel)` for configurable enforcement level.

### Fixed
- **ESM loader crash** (`src/esm-loader.mjs`): `Identifier 'resolve' has already been declared` — complete rewrite using `createRequire(import.meta.url)`.
- **Worker bootstrap path** (`src/worker-bootstrap.js`): `require('../index')` resolved to non-existent repo root — fixed to `require('./index')`.
- **SARIF function name** (`bin/bheeshma-ci.js`, `bin/bheeshma-install.js`): `formatSarifReport is not a function` — fixed import to `formatReport`.
- **`enforcePolicy()` fail levels**: Only returned CRITICAL packages regardless of `--fail-level` — rewrote with `findViolatingPackages()` and `RISK_PRIORITY` map.
>>>>>>> 1995263 (feat: v1.1.0 — vm/crypto hooks, baseline mode, lockfile integrity, diff/explain CLI)

---

## [1.0.0] - 2026-05-16

### The v1.0.0 Release

Complete rewrite from v3.0.0 with a new focus: **CI/CD pipeline guard**. This release positions BHEESHMA as the only open-source runtime behavioral monitor for Node.js dependencies, catching supply-chain attacks that static analysis tools (Socket.dev, Snyk, Dependabot, npm audit) miss.

### Added

#### GitHub Actions Integration
- **SARIF v2.1.0 formatter** (`src/output/sarifFormatter.js`): GitHub Code Scanning compatible output
  - All 9 signal types mapped to SARIF rules with descriptions and help URIs
  - 5 pattern categories (crypto mining, exfiltration, backdoors, credential theft, typosquats)
  - Signal deduplication in SARIF output (300 identical HTTP calls = 1 result)
  - LOW-risk signals skipped by default for noise reduction
  - Trust score and risk level as SARIF result properties
  - Stack trace location extraction for file-level annotations
- **GitHub Action** (`.github/actions/bheeshma/action.yml`): Composite action for one-line CI setup
  - Auto-installs bheeshma and runs monitoring
  - Auto-uploads SARIF to Code Scanning via `github/codeql-action/upload-sarif`
  - Configurable fail-level and SARIF options

#### npm install Monitor
- **`bheeshma install` CLI** (`bin/bheeshma-install.js`): Monitors npm install for malicious behavior
  - Watches postinstall scripts, network connections, file writes, env reads during install
  - Install-specific summary with per-package risk assessment
  - SARIF output mode for CI integration
  - Supports `npm install`, `npm ci`, and package-specific installs

#### CI-Optimized CLI
- **`bheeshma-ci` CLI** (`bin/bheeshma-ci.js`): Thin CI wrapper
  - No ANSI colors, no HTML, just SARIF + exit codes
  - GitHub Actions annotation format (`::error`, `::warning`, `::notice`)
  - Configurable fail-level (`critical`, `high`, `medium`, `low`)
  - Proper signal propagation for child processes

#### Updated CLI
- **Main CLI** (`bin/bheeshma.js`): Subcommands and new format
  - `bheeshma install` — npm install monitoring
  - `bheeshma ci -- <command>` — CI-optimized mode
  - `--format sarif` — SARIF output option
  - `--version` / `-v` — version flag
- **3 bin entries**: `bheeshma`, `bheeshma-ci`, `bheeshma-install`

#### Bug Fixes
- **envHook Node 18+ compatibility**: Fixed `Reflect.set()` Proxy receiver issue
  - Root cause: Node 18+ `process.env` has strict internal property descriptors
  - Fix: Use `Reflect.set(target, prop, value)` without passing Proxy as receiver
  - Also fixed proxy-in-proxy issue on repeated init/teardown cycles
  - Stores original env object for clean restore on uninstall

#### Tests
- **41 tests** (up from 35), all passing
  - SARIF format validation (version 2.1.0, results array, tool rules)
  - SARIF with pattern analysis (PATTERN_* rules included)
  - SARIF deduplication (signal results <= raw signals)
- All tests run offline with deterministic results

### Changed
- **Version**: Bumped from 3.0.0 to 1.0.0 (fresh start)
- **package.json**: Updated description, keywords, 3 bin entries, action files in published package
- **src/index.js**: Added SARIF format to `generateReport()`
- **SECURITY.md**: Updated known limitations (worker threads now supported)
- **CONTRIBUTING.md**: Updated test count, project structure
- **README.md**: Complete rewrite for v1.0.0 launch

### Removed
- None (backward compatible)

---

## [3.0.0] - 2026-05-16

### Added

#### Policy Enforcement Mode
- **`--enforce` CLI flag**: Exit with code 1 if any package has CRITICAL trust score
- **`enforcePolicy()` API**: Programmatic enforcement check
- **Whitelist suppression at hook layer**: Signals never recorded for whitelisted packages
- **Per-package threshold overrides**: Custom trust score thresholds per package
- **Webhook alerts**: POST critical findings to Slack, Discord, ntfy.sh

#### ESM + Worker Thread Support
- **ESM loader hook** (`src/esm-loader.mjs`): Node.js `--loader` API for pure ESM packages
- **Worker thread bootstrap** (`src/worker-bootstrap.js`): Signal relay from worker threads

#### Attribution Accuracy
- **Outermost node_modules resolution**: Walks entire call stack for correct attribution
- **Signal deduplication**: Collapses identical signals for readable reports

#### DNS Monitoring
- **DNS hook** (`src/hooks/dnsHook.js`): DNS tunneling detection
- High-entropy subdomains, Base64/hex encoded subdomains, known exfil services

#### Obfuscation Detection
- **Static analysis module** (`src/obfuscation/detector.js`): eval(), Function(), hex, Base64

#### Pattern Detection
- **Typosquat detection**: Levenshtein distance + character swap analysis
- **Context-aware credential theft**: dotenv reading .env = LOW, others = HIGH

#### Release Pipeline
- **CI workflow**: Node 14/16/18/20, npm audit, secret scanning
- **Release workflow**: Auto-publish to npm on tag push
- **HTML report formatter**: Self-contained dark-themed HTML

### Changed
- **Signal types**: Added `DNS_QUERY`, `OBFUSCATION_DETECTED`, `BLACKLISTED_PACKAGE`

---

## [2.0.0] - 2026-01-18

### Added
- Configuration system (`.bheeshmarc.json`)
- HTTP/HTTPS monitoring hooks
- Pattern detection engine (crypto mining, exfiltration, backdoors)
- Malware signature database

---

## [1.0.0-beta] - 2026-01-17

Initial release — basic runtime behavior monitoring.
