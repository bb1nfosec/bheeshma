# BHEESHMA Architecture

BHEESHMA has **two complementary engines**. They make different trade-offs on
the one axis that matters for a security tool — the **trust boundary** — and are
meant to be used together, not as alternatives.

```
                        what runs the dependency code
                                    │
        ┌───────────────────────────┴───────────────────────────┐
        │                                                        │
  In-process engine                                    Out-of-process engine
  (src/index.js, hooks/)                                (src/sandbox/, strace)
        │                                                        │
  monkey-patches Node APIs                          observes syscalls via the
  in the same process                               kernel (ptrace), from
                                                    outside the process
```

## Engine 1 — in-process (default; `bheeshma`, `bheeshma-ci`, `bheeshma install`)

Monkey-patches `env`/`fs`/`net`/`http(s)`/`dns`/`child_process` and attributes
each call to a package via the JavaScript stack (with an `AsyncLocalStorage`
fallback for async-deferred behavior).

- **Strengths:** precise *per-package* attribution of require-time JavaScript
  behavior; zero dependencies; works anywhere Node runs; cheap to adopt.
- **Boundary:** *none.* It runs with the same privileges as the code it watches.
  A motivated dependency can disable it, and it cannot see behavior that doesn't
  go through the Node APIs it wraps — most importantly, **native subprocesses**
  (e.g. a payload that shells out to `curl`) and native/WASM code.
- **Use it for:** developer-time visibility, fast CI signal, and per-package
  behavioral diffing. It is **telemetry, not containment.**

## Engine 2 — out-of-process (experimental; `bheeshma-sandbox`)

Runs the command under kernel-level syscall observation (`strace`/ptrace) and,
optionally, kernel-level confinement (`bwrap`/namespaces). The monitored code
**cannot tamper with the observer**, and behavior is captured regardless of
language or runtime.

- **Strengths:** a real trust boundary; sees `connect`/`execve`/file syscalls
  made by **any** process in the tree, including native binaries the in-process
  engine is blind to; can **prevent** (e.g. `--block-network` denies egress via
  `bwrap --unshare-net`), not just detect.
- **Attribution:** by process lineage — a dependency's lifecycle script is its
  own process whose `execve` argv contains `node_modules/<pkg>`, so that process
  and its descendants are attributed to the package; the package manager's own
  process is not. This is robust for **install-time** monitoring; it cannot
  separate two packages running inside the *same* Node process (that is what
  Engine 1's stack attribution is for).
- **Requirements:** Linux + `strace` (+ `bwrap` for `--block-network`). No root.
- **Use it for:** install/build monitoring where native egress and evasion
  resistance matter, and where you want enforcement, not just observation.

## Why both

Neither engine alone is the whole answer, and saying so is part of being honest
about what a runtime tool can do (see [THREAT_MODEL.md](THREAT_MODEL.md)):

| | In-process | Out-of-process |
|---|---|---|
| Per-package attribution of require-time JS | ✅ | ✖ (per-process) |
| Sees native subprocess egress (`curl`, …) | ✖ | ✅ |
| Resistant to the monitored code disabling it | ✖ | ✅ |
| Can prevent (not just detect) | ✖ | ✅ (`--block-network`) |
| Zero dependencies / runs anywhere | ✅ | ✖ (Linux + strace) |

A demonstration of the gap: a package whose payload runs
`curl http://169.254.169.254/` (cloud-metadata credential theft) produces **zero
in-process signals** — the egress is done by a native process — while the
out-of-process engine records the `execve` + `connect` and attributes them to
the package. See `bin/bheeshma-sandbox.js`.

## CI usage

`bheeshma-sandbox` emits SARIF (`--format sarif`), so it plugs into GitHub Code
Scanning like the in-process engine. `ubuntu-latest` runners ship `strace`:

```yaml
- run: npx bheeshma-sandbox --enforce --fail-level high --format sarif \
       --output bheeshma-sandbox.sarif -- npm ci
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: bheeshma-sandbox.sarif }
```

## Roadmap for the out-of-process engine

The strace-based engine is a proof of concept. Network connects, raw sockets,
process execs, sensitive-file reads, and **DNS query names** (parsed from the
wire payload) are covered. The intended trajectory:
- remaining syscall coverage (compressed DNS names, broader file semantics);
- lower-overhead observation via **eBPF** where privileges allow;
- policy-as-code enforcement (seccomp/Landlock) for fine-grained allow/deny;
- a hardened, reusable sandbox profile (the `benchmark/sandbox/` image is a start).
