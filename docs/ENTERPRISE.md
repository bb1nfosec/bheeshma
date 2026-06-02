# BHEESHMA for Enterprises

A short, honest guide for security and platform teams evaluating BHEESHMA for
use in their software supply chain. It is paired with two documents you should
read alongside it: the [Threat Model](THREAT_MODEL.md) (what it does and does
not catch) and the [benchmark findings](../benchmark/FINDINGS.md) (measured
detection and false-positive behavior).

## What BHEESHMA is — and where it fits

BHEESHMA is **runtime dependency-behavior telemetry** for Node.js. It observes
what your third-party packages actually do when they execute — environment
access, file I/O, outbound network (HTTP/HTTPS/raw TCP/DNS), and subprocess
execution — attributes each behavior to the responsible package, and gates your
build on it (SARIF + exit codes).

Position it as a **defense-in-depth layer alongside** your existing static and
registry-graph scanners (Socket, Snyk, Phylum, npm audit), **not as a
replacement**. Static tooling reasons about a package before it runs and across
the whole registry; BHEESHMA adds the complementary "what did it actually do"
view and a CI gate you fully control and host yourself.

It is honest about its boundaries: it runs in-process with the code it watches,
so it is **telemetry and a detection aid, not a sandbox or containment
boundary**. See the [Threat Model](THREAT_MODEL.md) before relying on it.

## Why a regulated/enterprise team would adopt it

- **No data leaves your environment.** All analysis is local. There is no
  telemetry, no account, no SaaS, no callback. BHEESHMA records *metadata*
  (hosts, ports, paths, env-var names) — never secret values, file contents, or
  request bodies. For teams that cannot send dependency/build data to a
  third-party scanner, this is the differentiator.
- **Zero dependencies.** Pure Node.js. Nothing transitive to vet or to become a
  supply-chain risk of its own. (And it ships **no install scripts** — a
  security tool should not run the very thing it warns you about.)
- **Open source, auditable, deterministic.** Same inputs produce the same
  scores. No ML black box. You can read every rule.
- **Self-hosted CI gate** with standard outputs (SARIF → GitHub Code Scanning,
  JSON, exit codes) that drop into existing pipelines.

## Deployment patterns

### 1. CI gate (recommended)
```yaml
- uses: bb1nfosec/bheeshma/.github/actions/bheeshma@<pinned-sha>
  with:
    command: 'npm test'      # run your suite under monitoring
    fail-level: 'high'       # see "Gating posture" below
    upload-sarif: 'true'     # inline annotations in PRs
```
Pin to a commit SHA (not a moving tag) as you would any third-party action.

### 2. Install-time monitoring
Catches behavior of `preinstall`/`postinstall` lifecycle scripts — a primary
supply-chain vector — by monitoring the install's child process tree:
```bash
npx bheeshma install            # monitors `npm install`
npx bheeshma install ci         # monitors `npm ci`
```

### 3. Local / ad hoc
```bash
npx bheeshma --format sarif --output results.sarif -- node app.js
```

## Gating posture and exit codes

`bheeshma-ci` and the Action gate on a **fail level**; any package whose risk
level is at or above it fails the build (exit code `1`, else `0`).

| fail-level | Fails on | Posture |
|---|---|---|
| `high` (**default**) | HIGH + CRITICAL | Recommended. On the project's corpora this caught every modeled attack at **100%** with **0% false positives across 71 real packages**. Corpora are limited — validate against your own dependency tree. |
| `critical` | CRITICAL only | Most conservative; blocks only near-certain malice (credential read + exfiltration). Catches far less; use if you need an extremely low false-positive bar. |
| `medium` / `low` | broader | Noisier; useful for investigation, not as a hard gate. |

**Recommended rollout:** start in **report-only** (collect SARIF, don't fail
builds), characterize the false positives on *your* dependencies for a sprint,
then enable a hard gate at `high`. Use `whitelist`/`packageThresholds` in
`.bheeshmarc.json` to tune.

## Assurance / quality signals

- **64 automated tests**: in-process unit/integration (`npm run test:unit`)
  **plus CLI integration tests that drive the actual binaries**
  (`npm run test:cli`) — the latter specifically guards the CI signal-collection
  and fail-level enforcement paths.
- **Efficacy benchmark** (`npm run benchmark`): a labeled corpus producing
  detection and false-positive rates per fail level, re-run in CI to catch
  regressions. Numbers and their caveats are in
  [benchmark/FINDINGS.md](../benchmark/FINDINGS.md).
- **CI across Node 14–22**; offline and deterministic.

## What BHEESHMA does NOT do (read before relying on it)

From the [Threat Model](THREAT_MODEL.md): a motivated attacker who controls a
dependency can evade or disable in-process monitoring; native/WASM code paths
are not visible; and dormant payloads that don't execute during the observed run
are not seen. Treat findings as **strong signals to investigate** within a
layered program — not as a guarantee of safety.

## Current maturity and honest gaps

We would rather you procure with clear eyes:

- The benchmark corpus is **synthetic** today; independent, real-malware
  benchmarking in a sandbox is the next milestone before any efficacy guarantee.
- This is currently a **community open-source project** — there is no commercial
  support contract, SLA, or vendor security certification yet. Evaluate it as
  you would any OSS dependency you self-host.
- Default gating is intentionally conservative (`critical`); reaching higher
  recall safely depends on tuning to your dependency set.

## Evaluation checklist for a security team

- [ ] Run `npm run test:cli` and `npm run benchmark` and review the output.
- [ ] Read [THREAT_MODEL.md](THREAT_MODEL.md); confirm the boundaries fit your
      use as a defense-in-depth layer.
- [ ] Pilot in **report-only** mode on a representative repo for one sprint.
- [ ] Measure false positives on your dependency tree; tune `.bheeshmarc.json`.
- [ ] Confirm "no data egress" matches your inspection of the source/network.
- [ ] Pin the Action to a commit SHA; review on upgrades.
- [ ] Decide a fail level (`high` recommended once tuned) and enable the gate.
