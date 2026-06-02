# RESUME — bheeshma hardening session

Saved 2026-06-01. Resume from here when token limits reset.

## Where the work lives
- **Durable copy:** `/home/bbinfosec/bheeshma-wip` (this dir — survives /tmp wipes).
- Original clone was `/tmp/bheeshma` (ephemeral; may be gone on reboot).
- Git branch: `harden/p0-correctness`, commit `7dc7170` (committed locally, **NOT pushed** — user said hold).
- Memory: `~/.claude/projects/-home-bbinfosec/memory/bheeshma-hardening.md` (full findings + roadmap).

## Strategy decided
Treat ambitions 1→2→3 as ONE sequenced ladder with evidence gates (not competing choices):
- **Stage 0 Correctness** — DONE (this branch).
- **Stage 1** best-in-class OSS audit tool → gate: adoption + low false positives.
- **Stage 2** defense-in-depth telemetry complementing Socket/Snyk + efficacy benchmark → gate: measured detection/FP rate + design partners would pay.
- **Stage 3** procurable re-architecture (out-of-process sandbox + eBPF/seccomp/ptrace = the real "strace for npm", or capability enforcement). Different codebase, multi-quarter. Only past Stage 2 gate. Never start on belief.

Honesty principle: never claim more than the in-process design can deliver (telemetry, not containment). See `ROADMAP.md` and `docs/THREAT_MODEL.md`.

## Stage 0 — what was fixed (validated against real Node, 44/44 tests pass)
- `src/hooks/httpHook.js` — wrap `http.get`/`https.get` (were bypassing the request hook → 0 capture).
- `src/hooks/netHook.js` — wrap `net.createConnection` (separate export from net.connect; confirmed no double-count with httpHook).
- `src/attribution/resolver.js` + `src/index.js` — AsyncLocalStorage attribution context seeded by wrapping `Module._load`, so behavior deferred across setImmediate/timers/promises is still attributed. New exports: `resolveResponsible`, `runWithPackageContext`, `getCurrentPackage`, `getPackageFromPath`.
- `package.json` — removed promotional `postinstall`.
- `action.yml` — fixed broken root Marketplace action (routed to bheeshma-ci.js, honors enforce:false).
- `src/worker-bootstrap.js` — `.unref()` flush timer.
- `test/harness.js` — added async-deferred capture+attribution regression test.

## Session 2 progress (commit after 7dc7170 — see `git log`)
Built the efficacy benchmark + fixed two more bugs it exposed:
- `benchmark/run.js` + `benchmark/fixtures.js` + `benchmark/FINDINGS.md` + `benchmark/results.json` — labeled corpus (7 malicious + 7 benign), detection/FP across thresholds.
- Fixed `dnsHook.uninstall` not clearing originals (DNS hook silently died after first init/teardown). Rewrote vacuous DNS test into a real assertion.
- Fixed `ENV_ACCESS` flood on spawn in `envHook` (Node's full-env copy via `copyProcessEnvToEnv` was recording 60+ signals → flooring score → benign spawners looked CRITICAL + fake detection). Now skips reads whose stack is in `child_process` internals.
- Honest README: dropped "strace/catches what static misses", reframed as defense-in-depth telemetry, linked THREAT_MODEL + FINDINGS, badge 41→44.
- Tests: 44/44 pass.

**KEY EVIDENCE (benchmark progression, all measured):** default gate (critical-only) 43%*→0%→29%; **high+ gate 43%*→29%→71%→86% recall at 100% precision / 0% FP (F1 0.92)**. (*the 43% "as shipped" was the env-flood artifact.) Two more wins landed this session: correlation-aware scoring (pattern severity caps trust score) + DNS-tunneling detection. Only obfuscated-loader (87, LOW) still missed.

## Done this session (commits 2523238, 4484d18, 043b861, f2f7339)
- Efficacy benchmark + FINDINGS + results.json
- Fixed dnsHook reinstall bug + vacuous DNS test
- Fixed ENV_ACCESS flood on spawn
- Honest README + THREAT_MODEL
- Correlation-aware scoring (pattern severity → score cap; dotenv LOW exemption preserved)
- DNS tunneling/exfil detection (via existing dnsHook indicators → dataExfiltration pattern)

## Session 3 (commits c488d6a, 702ddb2) — DONE
- **Obfuscation now reliably detected:** scan runs synchronously (was setImmediate race) with ALS-context path fallback; added obfuscation+network HIGH pattern; introspection reads use pristine readFileSync (no self-attributed FS_READ). → benchmark high+ 86%→**100% recall / 100% precision / 0% FP**.
- **TWO CRITICAL real-world bugs fixed (were blockers for actual use):**
  1. **CI/CLI collected NOTHING from spawned commands.** `bheeshma-ci`/`bheeshma` spawned the target + preloaded worker-bootstrap.js, which is a no-op in a normal child process → "0 packages, 0 signals", gate always passed. Fixed: new `src/ci-preload.js` monitors IN the child (NODE_OPTIONS inherited), writes per-PID signal files to BHEESHMA_SIGNAL_DIR, parent ingests via new `bheeshma.ingestSignals`. E2E verified.
  2. **`--fail-level high/medium/low` were no-ops** (enforcePolicy returned only CRITICAL, then CI filtered that CRITICAL-only list). Fixed: `findViolatingPackages(scores, level)` + `enforcePolicy({failLevel})`. E2E verified (high→exit1 on HIGH pkg).
- Tests 44→48.

## Immediate next steps (when resuming)
1. **Default-gate decision:** wiring now works; default still 'critical' (conservative, high precision). Consider recommending 'high' in README/action (corpus: critical=29%, high=100%/0%FP) — but synthetic corpus; weigh real-world FP. Non-urgent.
2. P1 reliability: node:test runner replacing sleep()-based harness + coverage; TypeScript migration (index.d.ts can drift).
3. P2: scan all package files not just entry point.
4. [minor] suppress module-loader FS_READ (Node's require reading a package's own index.js → 1 cosmetic FS_READ/pkg).
5. **Real-malware benchmark in a sandbox** (Stage-2→3 gate) — replace synthetic corpus.
6. Decide push/PR of branch harden/p0-correctness (still held).

## Open decision for user
Whether/when to push `harden/p0-correctness` and open a PR (currently held). Options discussed: hold / push+PR / push only after README made honest.

## To verify state on resume
```
cd /home/bbinfosec/bheeshma-wip && git log --oneline -1 && git status && node test/harness.js | tail -5
```
