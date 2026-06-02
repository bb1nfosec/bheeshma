# BHEESHMA Roadmap

The goal is a mature product. The path is **not** three competing directions —
it is one ladder. Each stage earns the credibility and evidence that justifies
investing in the next. We do not start an expensive stage on belief; we gate it
on data from the stage before.

```
Stage 0  Correctness        ── make the telemetry actually work and be honest
   │
Stage 1  Best-in-class OSS  ── win the "what do my deps do?" niche, build trust
   │      audit tool
   │                         GATE: real adoption + low false positives
Stage 2  Defense-in-depth   ── complement Socket/Snyk; produce efficacy evidence
   │      telemetry layer
   │                         GATE: measured detection + FP rate, design partners
Stage 3  Procurable product ── new trust boundary (out-of-process), vendor maturity
```

A non-negotiable principle runs through all of it: **never claim more than the
architecture can deliver.** See [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Stage 0 — Correctness (in progress)

Make the in-process telemetry functional and honest. Most of this is done on the
`harden/p0-correctness` branch.

- [x] Capture `http.get`/`https.get` and `net.createConnection` (previously bypassed).
- [x] Async-aware attribution via `AsyncLocalStorage` seeded at module load.
- [x] Remove promotional `postinstall` (a security tool must not run install scripts).
- [x] Fix the broken Marketplace `action.yml`.
- [x] `.unref()` the worker flush timer; add async-deferred regression test.
- [ ] Honest repositioning of README; ship [THREAT_MODEL.md](THREAT_MODEL.md).
- [ ] Fix obfuscation-scan-vs-report race (scan may not complete before exit).

**Exit:** the tool does what it says, the docs say only what it does.

## Stage 1 — Best-in-class OSS audit tool

Own the honest, underserved niche: *"see what your dependencies actually do,"*
zero-config, zero-data-exfil, with reports people enjoy reading.

- Reliability: replace the `sleep()`-based harness with `node:test` + coverage;
  benchmark the cost of per-call stack capture; reduce false positives against
  the top ~1000 npm packages.
- Type safety: migrate `src/` to TypeScript (or `tsc --checkJs`) so `index.d.ts`
  cannot drift from the implementation.
- UX: a first-class **behavioral diff** ("what changed in this dependency's
  behavior between versions?"), clearer CLI/HTML reports, baseline/allowlist flow.
- Distribution: npm provenance, signed releases, tidy `files`/exports.

**Gate to Stage 2:** demonstrable adoption + a published false-positive profile
on real dependency trees. If people don't find the audit story valuable, stop here.

## Stage 2 — Defense-in-depth telemetry layer

Position explicitly as a runtime layer that *complements* registry-graph and
capability scanners — and back the positioning with numbers.

- **Efficacy benchmark harness** (the most important deliverable): run BHEESHMA
  against a corpus of known-malicious packages (OSV-sourced + curated samples)
  inside a sandbox, and against large benign trees, to produce a real
  **detection rate** and **false-positive rate**. This is what turns marketing
  claims into evidence — and is the gate for Stage 3.
- Policy-as-code: declarative allow/deny of capabilities per package.
- Integration: SARIF polish, baselining, CI patterns; honest "use us with X" docs.
- A handful of **design-partner teams** running it in CI and giving feedback.

**Gate to Stage 3:** the benchmark shows real, defensible value *and* design
partners say they would pay to rely on it. No demand, no Stage 3.

## Stage 3 — Procurable product (only past the Stage 2 gate)

Break the architectural ceiling. The in-process design cannot be *relied upon*
against a motivated adversary; procurement requires a real trust boundary.

- New core: observe the install/build **out-of-process** inside a sandbox
  (container / gVisor / microVM) via **eBPF / seccomp / ptrace** syscall
  monitoring — the actual "strace for npm" — and/or move to **enforcement**
  (capability denial) rather than observation. The current in-process engine
  becomes a lightweight "quick mode."
- Vendor maturity: legal entity, support/SLA, the project's *own* security
  posture and disclosures, pricing.
- Convert design partners to paying customers.

**This is a different codebase and a multi-quarter, likely multi-person effort.**
It is justified only by Stage 2 evidence — not before.

---

## Immediate next step

Stand up the **efficacy benchmark harness** (Stage 2's keystone) early, in
report-only form, and finish the honest repositioning (Stage 0). Measuring real
detection and false-positive rates de-risks every decision above — including
whether Stage 3 is worth attempting at all.
