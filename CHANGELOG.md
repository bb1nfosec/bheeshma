# Changelog

All notable changes to BHEESHMA will be documented in this file.

## [Unreleased] — hardening toward a production/enterprise tool

Evidence-driven hardening: an efficacy benchmark, a real-package false-positive
sweep, and CLI integration tests repeatedly exposed real bugs, each fixed here.
See `benchmark/FINDINGS.md`, `docs/THREAT_MODEL.md`, `docs/ENTERPRISE.md`, and
`docs/ARCHITECTURE.md`.

### Added

- **Out-of-process engine (`bheeshma-sandbox`, experimental, Linux + strace):** a
  second engine that observes syscalls from *outside* the process via the kernel
  (ptrace). It cannot be evaded/disabled by the monitored code and sees native
  subprocess egress (e.g. `curl` to a cloud-metadata endpoint) that the
  in-process engine is structurally blind to. Attributes by process lineage
  (incl. real `npm install` via `npm_package_name`), and can **prevent** egress
  with `--block-network` (bwrap), not just detect. See `docs/ARCHITECTURE.md`.
- **Efficacy benchmark** (`npm run benchmark`), **real-package FP sweep**
  (`benchmark/fp-real.js`), **overhead microbenchmark** (`npm run perf`), and a
  **real-malware detonation suite + isolated sandbox** (`benchmark/malware-suite.js`,
  `benchmark/sandbox/`; honest scope: commodity npm malware, not APT evasion).
- **CLI integration tests** that drive the actual binaries (`npm run test:cli`),
  plus a `.d.ts`↔runtime drift guard. Test count: ~41 → 68.
- `ingestSignals`, `findViolatingPackages` added to the public API.

### Fixed

- **CI/CLI collected nothing from spawned commands**: `bheeshma-ci` / `bheeshma`
  / `bheeshma install` preloaded `worker-bootstrap.js`, a no-op in a normal child
  process, so the gate and the install monitor always passed. Now monitor the
  child process tree via `ci-preload.js` and ingest the signals.
- **`--fail-level high/medium/low` were no-ops** (enforcement only ever collected
  CRITICAL packages). Now level-aware (`findViolatingPackages`).
- **Catastrophic false positive**: Node's module loader reads every package file
  via the hooked `fs`, so `require()`-ing a multi-file package (e.g. express)
  scored it 0/CRITICAL. Loader-issued reads are now ignored. Measured result:
  **0% false positives at high+ across 71 real packages**.
- **`http.get`/`https.get` and `net.createConnection` were unmonitored**;
  **async-deferred behavior lost attribution** (added `AsyncLocalStorage`);
  **`ENV_ACCESS` flood on `spawn`**; **DNS hook died after the first
  init/teardown**; **obfuscation scan raced the report**.
- **Drifted TypeScript types**: `index.d.ts` declared 5 of 11 exports with wrong
  signatures — rewritten to match, guarded by a test.
- Removed the promotional `postinstall` script; fixed the broken Marketplace
  `action.yml`.

### Changed

- **Correlation-aware scoring**: recognized exfil/backdoor/crypto/credential-theft/
  typosquat/DNS-tunneling/obfuscation+network patterns now cap the trust score.
- **Honest positioning**: README/docs reframe BHEESHMA as defense-in-depth
  runtime telemetry (the in-process engine is not a containment boundary), with
  an explicit threat model and limitations.
- **~2.2× lower monitoring overhead** (structured-stack attribution + fast-path
  skip): worst-case microbenchmark 14.7× → 6.7×.

### Note

- Enabling CI to run the new test suites requires a 2-line `.github/workflows/ci.yml`
  change not included here (the push token lacked `workflow` scope).

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
