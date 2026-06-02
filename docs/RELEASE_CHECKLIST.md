# Release checklist

A repeatable runbook for cutting a BHEESHMA release. BHEESHMA is a *security*
tool, so the bar is higher than usual: a bad release can break CI gates or, worse,
ship a tool that silently stops detecting.

## 1. Pre-flight (on `main`, clean tree)

- [ ] `git checkout main && git pull` — start from the merged state.
- [ ] `npm test` → all green (in-process + CLI integration; currently 75).
- [ ] `npm run benchmark` → detection unchanged (high+ should stay 100% / 0% FP).
- [ ] `npm run perf` → overhead in the expected range (no regression).
- [ ] `node benchmark/fp-real.js` (network) → false-positive rate acceptable on real packages.
- [ ] If on Linux with strace: `node test/cli.test.js` exercises the out-of-process engine; otherwise note it was skipped.
- [ ] `npm pack --dry-run` → confirm the tarball contains only `files` (src/, bin/, the action, README/LICENSE/CHANGELOG/SECURITY) and **no** tests, samples, or benchmark malware.
- [ ] Confirm **no install scripts** in `package.json` (`scripts.preinstall/install/postinstall` absent).
- [ ] `npm audit` / dependency check — there are zero runtime deps; verify it stays zero.

## 2. Version + changelog

- [ ] Choose the version per semver. **A change to the default `fail-level`, or
      any change that makes a previously-passing build fail, is BREAKING → major.**
      Additive engines/exports → minor. Fixes only → patch.
- [ ] `package.json` `version` bumped.
- [ ] `CHANGELOG.md`: rename `[Unreleased]` to `[<version>] - <YYYY-MM-DD>` and
      start a fresh empty `[Unreleased]` above it.
- [ ] README badges / version references updated if any are hardcoded.
- [ ] `src/index.d.ts` matches the runtime API (the drift-guard test enforces this).

## 3. Docs sanity

- [ ] `README.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`,
      `docs/ENTERPRISE.md` reflect reality (no overclaiming; honest scope).
- [ ] Default `fail-level` documented consistently across README, action.yml, and bins.

## 4. CI must be green first

- [ ] CI runs `npm test` **and** `node test/cli.test.js` **and** the benchmark
      on the Node matrix (14/18/20/22). If the workflow doesn't yet run the new
      suites, add them before releasing (see "Known gap" below).

## 5. Tag, publish, verify

- [ ] Merge the release-prep PR to `main`.
- [ ] Tag: `git tag v<version> && git push origin v<version>`.
- [ ] Publish with provenance + 2FA: `npm publish --provenance --access public`
      (requires `id-token: write` in the publishing workflow, or a local 2FA OTP).
- [ ] Create the GitHub Release from the tag, pasting the CHANGELOG section.
- [ ] **Verify the published artifact**: in a clean dir, `npm i -g bheeshma@<version>`
      then run `bheeshma --version`, `bheeshma --help`, and a quick
      `bheeshma --enforce -- node -e "require('some-dep')"` smoke test.
- [ ] Confirm the GitHub Action still resolves (pin examples to the new tag/SHA).

## 6. Post-release

- [ ] Announce / update the dashboard if applicable.
- [ ] Open issues for the deferred roadmap items (see `ROADMAP.md`).

## Known gap (resolve before/with the release)

The CI workflow (`.github/workflows/ci.yml`) does not yet run `test/cli.test.js`
or the benchmark — the change needs the `workflow` OAuth scope to push. Apply
via the GitHub web editor:

```yaml
- name: Run CLI integration tests
  run: node test/cli.test.js
- name: Run efficacy benchmark
  run: node benchmark/run.js
```
