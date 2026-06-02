# Real-malware detonation sandbox

This lets you measure BHEESHMA's detection rate against **real** malicious npm
package samples (e.g. from vx-underground or public IOC corpora) safely.

## Read first — scope and safety

- **Scope (honest):** this validates detection of real-world *commodity* npm
  supply-chain malware — credential theft, miners, backdoors, typosquats. It
  does **not** validate resistance to an evasion-capable adversary. BHEESHMA is
  in-process telemetry and is evadable by design; see
  [../../docs/THREAT_MODEL.md](../../docs/THREAT_MODEL.md). Report results as
  "detection of real npm malware," not "stops APTs."
- **Safety:** the samples are live attacker code. Detonate them only in a
  disposable, network-isolated VM/container with **no real secrets**. Never on a
  workstation or CI runner with real `~/.npmrc`, SSH keys, cloud creds, or a
  usable network egress. The harness refuses to run unless `BHEESHMA_SANDBOX=1`
  and seeds decoy credentials, but that is defense-in-depth, **not** isolation.

## Layout

Put one package per subdirectory under `benchmark/samples/` (gitignored — never
committed):

```
benchmark/samples/
  sample-shai-hulud/   package.json + payload files
  sample-miner/        package.json + payload files
  ...
```

## Run

```bash
# Build the throwaway image (from the repo root)
docker build -t bheeshma-sandbox -f benchmark/sandbox/Dockerfile .

# Detonate with NO network (samples can't reach anything real)
docker run --rm --network=none -e BHEESHMA_SANDBOX=1 \
  -v "$PWD/benchmark/samples:/work/samples:ro" \
  bheeshma-sandbox
```

To **observe** exfiltration attempts instead of blocking them, point the
container at a recording blackhole proxy instead of `--network=none` (e.g. a
sink that logs every connection and returns nothing). bheeshma records the
connection metadata either way.

## Output

The suite prints per-sample CAUGHT/MISSED + a detection rate at the `high+` and
`critical` gates, and writes `benchmark/malware-results.json`. Share that JSON
(not the samples) and we can analyze misses and tune detection.
