# BHEESHMA Threat Model

> This document is deliberately candid. BHEESHMA is a security tool, and a
> security tool that overstates what it does is worse than no tool — it creates
> false confidence. Read this before relying on BHEESHMA for anything.

## What BHEESHMA is

BHEESHMA is an **in-process runtime behavior monitor** for Node.js. It
monkey-patches a set of Node core APIs (`env`, `fs`, `net`, `http`/`https`,
`dns`, `child_process`) and records what your third-party dependencies do when
they execute, attributing each observed behavior to the responsible npm package.

It is best understood as **dependency-behavior telemetry and a detection aid** —
not as a sandbox, not as an enforcement control, and not as a guaranteed
malware blocker.

## Trust model (read this twice)

BHEESHMA runs **in the same process, with the same privileges, as the code it
observes.** There is no privilege boundary between the monitor and a potentially
malicious dependency. This is the single most important fact about the tool and
it bounds everything below.

A real `strace` observes a process from the *outside* via the kernel; the
observed process cannot tamper with it. BHEESHMA cannot offer that guarantee,
because it is JavaScript running alongside the very code it watches.

## What BHEESHMA detects well

- **Opportunistic / unsophisticated malware** that fires immediately and uses
  ordinary Node APIs: a postinstall script that shells out, reads `.npmrc`, and
  POSTs to an exfil host will be seen.
- **Behavioral visibility / auditing**: "what do my dependencies actually touch
  — env vars, files, hosts, subprocesses?" This is the core value.
- **Behavioral change between versions** of a dependency (regression of trust).
- **Known-bad indicators**: blacklisted packages, typosquat-shaped names,
  obfuscation patterns in entry-point source, DNS-tunneling-shaped hostnames.

## What BHEESHMA does NOT catch (known limitations)

These are not bugs to be fixed incrementally; several are inherent to the
in-process design.

1. **An adversary who disables or evades the monitor.** Malicious code can
   restore patched functions, read/alter the in-process signal store, or run
   before BHEESHMA initializes. The tool is open-source and simple by design;
   assume a motivated attacker has read it.
2. **Primitives BHEESHMA does not wrap.** Native/N-API addons, WebAssembly,
   `process.binding`, the `vm` module, and other low-level paths bypass the
   JavaScript-level hooks entirely.
3. **Dormant / gated payloads.** Dynamic analysis only sees what *executes
   during the observed run*. Malware that waits for production, a specific date,
   or a CI-environment fingerprint will produce a (false) "all clear."
4. **Async attribution edge cases.** BHEESHMA propagates attribution across
   async boundaries via `AsyncLocalStorage` seeded at module load, which closes
   the common cases — but exotic continuation patterns can still detach a
   behavior from its originating package.
5. **Coverage gaps.** A behavior on a code path your test/CI run never exercises
   is never observed.

## Recommended deployment

Use BHEESHMA as a **defense-in-depth telemetry layer**, alongside — never
instead of — registry-graph and capability scanners (e.g. Socket, Snyk,
Phylum) and your normal install hardening (`--ignore-scripts`, lockfile
integrity, npm provenance, 2FA on publishing). Concretely:

- Run `bheeshma install` in CI to surface install-time behavior, and treat
  findings as **signals to investigate**, not as a pass/fail oracle.
- Gate builds on CRITICAL findings only when you have tuned false positives for
  your dependency tree; start in report-only mode.
- Pair it with static/graph tooling that catches dormant and out-of-band risk
  BHEESHMA cannot see.

## Data handling

BHEESHMA performs **all analysis locally** and sends **no telemetry**. It
records connection/behavior *metadata* (hosts, ports, paths, env-var names),
never request/response bodies, file contents, or secret values. Optional webhook
alerts are the only outbound communication, and only when you configure one.
This "no data leaves the machine" property is intentional and a primary reason
to prefer it over SaaS scanners in regulated environments.
