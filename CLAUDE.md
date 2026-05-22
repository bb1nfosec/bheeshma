# BHEESHMA — Codebase Guide

## What This Project Is

**Bheeshma** is a zero-dependency Node.js runtime security monitor — described as "strace for npm packages." It instruments a running Node.js process by monkey-patching core modules, intercepts behaviors of installed npm dependencies at runtime, and generates trust-score reports to detect supply-chain attacks that static analysis misses.

- **npm package name:** `bheeshma` v1.0.0
- **Author:** bb1nfosec / bbinfosec
- **License:** Apache-2.0
- **Node.js requirement:** ≥14.0.0
- **Zero external dependencies** — everything is plain Node.js stdlib

---

## Architecture Overview

```
src/
├── index.js                 # Main API — init/teardown/report/monitor
├── hooks/                   # Runtime monkey-patches for each behavior class
│   ├── envHook.js           # process.env access (Proxy)
│   ├── fsHook.js            # fs module reads/writes
│   ├── netHook.js           # net.connect (raw TCP + IPC/Unix sockets)
│   ├── httpHook.js          # http.request + https.request
│   ├── dnsHook.js           # dns.lookup / resolve* / reverse + dns.promises.*
│   ├── childProcHook.js     # child_process.exec/spawn/fork/...
│   ├── vmHook.js            # vm.run*/compileFunction/Script — hook-evasion detection
│   └── cryptoHook.js        # crypto cipher/decipher/hash/kdf operations
├── signals/
│   └── signalTypes.js       # Immutable signal schema + SignalType enum
├── scoring/
│   └── trustScore.js        # Trust score calculator [0–100]
├── patterns/
│   ├── patternMatcher.js    # Behavioral pattern detection engine
│   └── malwareSignatures.js # Signature database + KNOWN_SAFE_CONTEXTS
├── obfuscation/
│   └── detector.js          # Static source scan (10 obfuscation patterns)
├── attribution/
│   └── resolver.js          # Stack trace → npm package attribution
├── baseline/
│   └── baselineManager.js   # Capture / load / filter / diff behavioral baselines
├── config/
│   ├── configLoader.js      # File-based config loading (.bheeshmarc.json etc.)
│   └── schema.js            # Config schema + defaults + mergeConfig/validateConfig
├── output/
│   ├── cliFormatter.js      # ANSI terminal report
│   ├── jsonFormatter.js     # JSON report
│   ├── htmlFormatter.js     # HTML report
│   ├── sarifFormatter.js    # SARIF v2.1.0 (GitHub Code Scanning)
│   └── sbomFormatter.js     # CycloneDX 1.4 JSON SBOM
├── esm-loader.mjs           # ESM loader hook (for ESM packages)
└── worker-bootstrap.js      # Re-installs hooks inside worker threads
bin/
├── bheeshma.js              # Main CLI entry point
├── bheeshma-ci.js           # CI-mode CLI (SARIF output + exit codes)
├── bheeshma-install.js      # npm install monitor mode
├── bheeshma-diff.js         # Compare two JSON reports, show regressions
├── bheeshma-lock.js         # SHA-256 lockfile integrity (--save / --verify)
└── bheeshma-explain.js      # Plain-English explanation of a report
dashboard/
├── index.html               # Static "Wall of Shame" dashboard (GitHub Pages)
└── data/threats.json        # Auto-updated threat feed
scripts/
└── fetch-threats.js         # Fetches threat data for the dashboard
```

---

## Core Data Flow

1. **`bheeshma.init(options)`** — called once, installs all hooks, returns `{ success, installed[], failed[] }`.
2. Each hook wraps a stdlib module function; on every call it:
   - Calls `resolveCurrentStack()` → walks the Error stack trace to find the outermost `node_modules` entry → returns `{ name, version, path }`.
   - If attribution is a third-party package, pushes a frozen **Signal** object via `signalRecorder.push()`.
3. **`signalRecorder.push(signal)`** — proxy around the global `signals[]` array. Enforces:
   - `maxSignals` cap
   - Whitelist suppression (signals from whitelisted packages are dropped here, before storage)
   - Blacklist injection (adds a synthetic `BLACKLISTED_PACKAGE` signal, guaranteeing score=0)
   - **Sampling** — if `performance.sampleRate < 1.0`, duplicate signals beyond the first are probabilistically dropped
   - **Persistent log** — if `logging.logFile` is set, appends JSON line to NDJSON file
   - Triggers one-time async obfuscation scan per package via `setImmediate`
4. **`bheeshma.generateReport(format)`** — runs hook tamper check, applies baseline filtering, calculates trust scores, runs pattern analysis, formats output.

---

## Signal Types (src/signals/signalTypes.js)

| Type | Triggered by | Risk Weight |
|---|---|---|
| `ENV_ACCESS` | process.env property get/set/has | 5 |
| `FS_READ` | readFile, readFileSync, createReadStream, etc. | 3 |
| `FS_WRITE` | writeFile, appendFile, mkdir, unlink, rename, etc. | 10 |
| `SHELL_EXEC` | exec, execSync, spawn, spawnSync, fork | 20 |
| `NET_CONNECT` | net.connect (raw TCP or IPC/Unix socket path) | 8 |
| `HTTP_REQUEST` | http.request | 10 |
| `HTTPS_REQUEST` | https.request | 8 |
| `DNS_QUERY` | dns.lookup/resolve*/reverse + dns.promises.* | 4 |
| `OBFUSCATION_DETECTED` | Static scan of package entry point | 25 |
| `VM_EXEC` | vm.runInNewContext/runInThisContext/Script/compileFunction | 20 |
| `CRYPTO_OP` | createCipheriv/createDecipheriv/createHash/pbkdf2/scrypt etc. | 8 |
| `HOOK_TAMPER` | Hook wrapper replaced after bheeshma installation | 100 |
| `PROTO_POLLUTION` | Object.prototype / __proto__ mutation (static scan) | 30 |
| `BLACKLISTED_PACKAGE` | (synthetic, injected by recorder) | 100 |

All signal objects are **frozen** (`Object.freeze`). Fields: `timestamp`, `type`, `package`, `version`, `metadata`, `stackTrace`.

---

## Trust Scoring (src/scoring/trustScore.js)

- Starts at **100**, deducts the risk weight for each unique signal.
- Floor is **0** (no negatives).
- Signals are deduplicated before scoring: key = `pkg:type:destination`. A package making 300 identical HTTP calls scores as 1 deduction.
- Risk levels: `CRITICAL` (<30), `HIGH` (<60), `MEDIUM` (<80), `LOW` (≥80). Thresholds are configurable per-package.

---

## Attribution (src/attribution/resolver.js)

- Captures `new Error().stack`, walks ALL frames, finds the **last** (outermost, closest to user code) `node_modules` path.
- This prevents mislabeling: if `lodash` calls `evil-dep`, the signal is attributed to `evil-dep`, not `lodash`.
- Reads `package.json` from the package directory (cached in-memory) to get name + version.
- Dual-regex frame extraction handles both `(path:line:col)` and bare `at path:line:col` formats.
- **Self-exclusion**: signals are never attributed to `bheeshma` itself when installed as a dependency.
- Whitelist patterns supported: exact name, `pkg@*` (any version), `@scope/*` (all scoped).

---

## Hooks Detail

### envHook.js
- Uses `Proxy` on `process.env` (intercepts `get`, `set`, `has`).
- Captures **variable name only** — never the value (security by design).
- Node 18+ compatibility: uses `Reflect.set(target, ...)` not the receiver to avoid `ERR_INVALID_OBJECT_DEFINE_PROPERTY`.

### fsHook.js
- Wraps: `readFile`, `readFileSync`, `readdir`, `readdirSync`, `readlink`, `readlinkSync`, `createReadStream`, `writeFile`, `writeFileSync`, `appendFile`, `appendFileSync`, `mkdir`, `mkdirSync`, `rmdir`, `rmdirSync`, `unlink`, `unlinkSync`, `rename`, `renameSync`, `createWriteStream`.
- Captures normalized absolute path only — never file contents.

### httpHook.js
- Wraps `http.request` and `https.request`.
- Parses all call signatures (string URL, URL object, options object).
- Redacts auth/token headers: replaces values with `[REDACTED]`, all others with `[PRESENT]`.
- Analyzes suspiciousness: direct IP, suspicious TLD (.tk/.ml/.ga/.cf/.gq/.xyz), non-standard ports, pastebin-like hosts.

### dnsHook.js
- Wraps callback API: `lookup`, `resolve`, `resolve4`, `resolve6`, `resolveTxt`, `resolveMx`, `resolveCname`, `resolveNs`, `resolveSrv`, `resolveCaa`, `resolveNaptr`, `resolvePtr`, `reverse`.
- Wraps promise API: all `dns.promises.*` equivalents (Node 10+).
- Detects DNS tunneling: long subdomains (>50 chars), high Shannon entropy (>4.0 bits), base64-like labels, hex-encoded subdomains, known exfil services.
- Calculates Shannon entropy per subdomain label.

### childProcHook.js
- Wraps all of: `exec`, `execSync`, `execFile`, `execFileSync`, `spawn`, `spawnSync`, `fork`.
- Sanitizes commands: truncates at 200 chars, redacts `--password=`, `--token=`, `--api-key=`, `--secret=`, `*_KEY=`, `*_TOKEN=`, `*_SECRET=`.
- Captures command structure only — never stdin/stdout/stderr.

### netHook.js
- Wraps `net.connect` for raw TCP connections and IPC/Unix socket paths.
- String first-arg or `opts.path` → `protocol: 'ipc'`; emits `NET_CONNECT` signal with `host` = socket path, `port` = 0.
- Does NOT re-wrap http/https (httpHook handles those to avoid conflicts).

### vmHook.js
- Wraps: `vm.runInNewContext`, `vm.runInThisContext`, `vm.runInContext`, `vm.compileFunction`, `new vm.Script()`.
- Each vm context is a fresh V8 context where bheeshma hooks are not installed — this is the primary hook-evasion technique.
- Captures `codePreview` (first 120 chars of code string) for forensic context.
- Emits `VM_EXEC` signal; risk weight 20.

### cryptoHook.js
- Wraps: `createCipheriv`, `createDecipheriv`, `createHash`, `createHmac`, `randomBytes`, `randomFill`, `pbkdf2`, `pbkdf2Sync`, `scrypt`, `scryptSync`.
- High-suspicion operations (decipher, pbkdf2, scrypt, ECDH): `isHighSuspicion: true`.
- Captures `operation` and `algorithm` (first string arg) — never key material or plaintexts.
- Emits `CRYPTO_OP` signal; risk weight 8.

---

## Pattern Matcher (src/patterns/patternMatcher.js)

Runs after signals are collected, at report time. Detects:

| Pattern | Method | Severity |
|---|---|---|
| Crypto miners | Process names (xmrig etc.), mining pool domains, miner env vars | CRITICAL/HIGH |
| Data exfiltration | Sensitive file reads + HTTP request — **temporal correlation**: ≤2s = CRITICAL, ≤30s = HIGH, else MEDIUM | CRITICAL |
| Direct exfil services | HTTP request to pastebin/webhook/requestbin/pipedream | CRITICAL |
| Backdoors | Reverse shell commands, RAT tools, suspicious ports (1337, 4444, 5555, etc.) | CRITICAL/HIGH |
| Credential theft | Secret env vars (AWS_*, GITHUB_TOKEN, etc.), credential file reads | HIGH (LOW for known config loaders) |
| Typosquats | Levenshtein distance=1 from popular packages, character swaps (o→0, i→l, e→3) | MEDIUM |

**Context-aware:** `dotenv`, `convict`, `config`, `cosmiconfig`, etc. reading `.env` is downgraded to LOW severity.
`KNOWN_SAFE_CONTEXTS` in `malwareSignatures.js` maps package name prefixes to expected behavior categories (shellExec, fsRead, credentialFiles, httpRequest), suppressing false positives for well-known build tools and package managers.

---

## Obfuscation Detector (src/obfuscation/detector.js)

- Runs **once per package**, lazily on first signal, via `setImmediate` (non-blocking).
- Reads the package's `main` entry point source.
- Detects **10 patterns**:
  1. `eval()` usage (HIGH)
  2. `Function()` constructor (HIGH)
  3. `Buffer.from().toString()` > 2× (MEDIUM)
  4. Long hex string literals > 100 chars (HIGH)
  5. `\x` escape density > 10% (HIGH)
  6. `String.fromCharCode` chains > 3× (HIGH)
  7. `atob()` usage (MEDIUM)
  8. Excessive short-string concatenation > 5 chains (MEDIUM)
  9. `process.binding()` — direct Node.js C++ internal access (HIGH)
  10. Long integer arrays > 8 elements — charCode payload (HIGH)
- **Prototype pollution patterns** (static, HIGH): `Object.prototype.x =`, `__proto__ =`, `['__proto__']`, `constructor.prototype.x =`
- Emits an `OBFUSCATION_DETECTED` signal (weight=25) if any indicator found.

---

## Worker Thread Support (src/worker-bootstrap.js + src/index.js)

- `setupWorkerSignalCollection()` intercepts the `Worker` constructor.
- Each new `Worker` gets `--require worker-bootstrap.js` injected into `execArgv`.
- Worker threads relay signals to the main thread via `parentPort.postMessage({ type: 'BHEESHMA_SIGNAL', signal })`.
- Main thread collects them on `worker.on('message', ...)`.

---

## CLI Modes (bin/)

| Command | Description |
|---|---|
| `bheeshma -- node app.js` | Monitor a Node.js script |
| `bheeshma script.js` | Direct script monitoring |
| `bheeshma --format json -o report.json -- node app.js` | JSON output to file |
| `bheeshma --format sarif --output results.sarif -- npm test` | SARIF output |
| `bheeshma --enforce -- node app.js` | Exit 1 if any package is CRITICAL |
| `bheeshma --enforce --fail-level high -- node app.js` | Exit 1 if any package is HIGH or worse |
| `bheeshma --alert-webhook <url> --webhook-format slack -- ...` | Slack alert on findings |
| `bheeshma --baseline baseline.json -- node app.js` | Suppress known-good signals from report |
| `bheeshma learn baseline.json -- node app.js` | Record baseline, then run |
| `bheeshma install` | Monitor `npm install` (postinstall behavior) |
| `bheeshma ci -- <command>` | CI-optimized mode (SARIF + GitHub annotations) |
| `bheeshma diff <base.json> <curr.json>` | Show new findings vs a previous report |
| `bheeshma lock --save` | Record lockfile SHA-256 hashes |
| `bheeshma lock --verify` | Detect lockfile tampering (exit 1 on mismatch) |
| `bheeshma explain report.json` | Plain-English findings summary with remediation |

Output formats: `cli` (ANSI), `json`, `html`, `sarif` (GitHub Code Scanning), `sbom` (CycloneDX 1.4).

---

## Configuration

Config files searched in CWD (in order): `.bheeshmarc.json`, `.bheeshmarc`, `bheeshma.config.json`, `bheeshma.config.js`.

Key config fields:
```json
{
  "hooks": {
    "env": true, "fs": true, "net": true, "childProcess": true,
    "http": true, "dns": true,
    "vm": true,     ← vm module hook-evasion detection
    "crypto": true  ← crypto cipher/kdf misuse detection
  },
  "thresholds": { "critical": 30, "high": 60, "medium": 80 },
  "packageThresholds": { "axios": 40 },
  "whitelist": ["express@*", "@types/*"],
  "blacklist": [],
  "patterns": {
    "enabled": true,
    "detectCryptoMiners": true,
    "detectDataExfiltration": true,
    "detectBackdoors": true
  },
  "performance": {
    "maxSignals": 10000,
    "deduplicateSignals": true,
    "sampleRate": 1.0   ← 0.01–1.0, first occurrence always kept
  },
  "logging": {
    "logFile": null     ← path for persistent NDJSON signal log
  },
  "baselineFile": null, ← path to .bheeshma-baseline.json
  "webhookFormat": "generic",  ← generic | slack | pagerduty | teams
  "alertWebhook": null,
  "enforce": false
}
```

---

## Behavioral Baseline (src/baseline/baselineManager.js)

- `captureBaseline(signals, outputPath)` — writes a JSON file mapping dedup keys → `{ package, version, type, count }`.
- `loadBaseline(path)` — reads and parses the baseline file.
- `filterBaselineSignals(signals, baseline)` — removes signals whose dedup key exists in the baseline, returning only new behaviors.
- `diffBaseline(signals, baseline)` — returns `{ newCount, baselineCount, newSignals }`.
- Dedup key format: `pkg:type:destination` — mirrors `trustScore.buildDedupKey`.

Baseline workflow:
```bash
bheeshma learn baseline.json -- node app.js   # learns normal behavior
bheeshma --baseline baseline.json -- node app.js  # next run: only new behaviors scored
```

---

## SBOM Generation (src/output/sbomFormatter.js)

- `formatSbom(scores, allSignals, options)` — returns CycloneDX 1.4 JSON string.
- Each observed package becomes a `component` with `purl`, `bom-ref`, and bheeshma-specific `properties`.
- Properties: `bheeshma:trustScore`, `bheeshma:riskLevel`, `bheeshma:signalCount`, `bheeshma:uniqueSignalCount`, `bheeshma:severity`, `bheeshma:signal:<type>`.
- Sorted by trust score ascending (most risky first).
- Scoped packages (`@scope/name`) URL-encoded correctly in purl.

---

## GitHub Actions Integration

Custom action at `.github/actions/bheeshma/action.yml`. Usage:
```yaml
- uses: bb1nfosec/bheeshma/.github/actions/bheeshma@main
  with:
    command: 'npm test'
    fail-level: 'critical'
```

Workflows:
- `ci.yml` — runs tests on push/PR
- `release.yml` — publishes to npm on tag
- `update-wall-of-shame.yml` — fetches latest threat data daily
- `deploy-dashboard.yml` — deploys dashboard to GitHub Pages

---

## Testing

```bash
node test/harness.js    # npm test
```

Test fixtures: `test/fixtures/malicious-package/` — a fake malicious package for testing detection. Test files: `test/benign.js`, `test/suspicious.js`.

---

## Security Design Principles

- **Observe-only**: hooks never modify arguments, return values, or file contents.
- **No secret capture**: env values, file contents, process output, auth headers are never recorded.
- **Fail-safe**: all hooks have try/catch — a hook error never breaks the monitored application.
- **Whitelist at push time**: whitelisted packages are suppressed before signals are stored, not filtered at report time.
- **Immutable signals**: `Object.freeze()` prevents post-creation tampering.
- **Zero dependencies**: no npm packages are used; pure Node.js stdlib.
- **Zero telemetry**: all analysis is local-only, no data leaves the machine.
