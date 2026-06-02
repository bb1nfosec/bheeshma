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

## Immediate next steps (when resuming)
1. Finish honest README repositioning (drop "strace/catches what static misses" overclaim; link THREAT_MODEL.md; badge says 41/41 but it's now 44).
2. Build the **efficacy benchmark harness** (Stage 2 keystone, report-only): measure real detection rate vs known-malware corpus + false-positive rate vs large benign trees. De-risks the whole ladder.
3. Then P1 reliability: node:test runner replacing sleep()-based harness + coverage; TypeScript migration (index.d.ts can drift); fix obfuscation-scan-vs-report race (setImmediate scan may not finish before exit — watch fsHook reentrancy).
4. P2: non-additive scoring; scan all package files not just entry point.

## Open decision for user
Whether/when to push `harden/p0-correctness` and open a PR (currently held). Options discussed: hold / push+PR / push only after README made honest.

## To verify state on resume
```
cd /home/bbinfosec/bheeshma-wip && git log --oneline -1 && git status && node test/harness.js | tail -5
```
