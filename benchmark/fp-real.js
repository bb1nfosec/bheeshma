#!/usr/bin/env node
/**
 * BHEESHMA Real-Package False-Positive Sweep
 *
 * Installs a set of popular, legitimate npm packages into a throwaway directory
 * and measures how many BHEESHMA would flag at each enforcement level — i.e. the
 * false-positive rate on real-world dependency trees, the number that decides
 * whether a CI gate is usable.
 *
 * Unlike the unit/CLI tests and the detection benchmark, this REQUIRES NETWORK
 * (it runs `npm install`), so it is intentionally NOT part of `npm test` / CI.
 * Run it manually:
 *
 *   node benchmark/fp-real.js                  # default curated set
 *   node benchmark/fp-real.js lodash chalk ... # custom set
 *
 * Each package is required in a FRESH process under monitoring (no cross-run
 * state), and we record its trust score / risk level.
 */

'use strict';

const { spawnSync, execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const DEFAULT_SET = [
    'lodash', 'chalk', 'express', 'commander', 'debug', 'semver',
    'qs', 'ms', 'uuid', 'dotenv', 'axios', 'yargs', 'glob', 'rimraf'
];

const requested = process.argv.slice(2);
const topLevel = requested.length ? requested : DEFAULT_SET;

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'bheeshma-fp-'));
fs.writeFileSync(path.join(work, 'package.json'), JSON.stringify({ name: 'fp', version: '1.0.0' }));

console.log(`Installing ${topLevel.length} packages (+ transitive) into a temp dir…`);
try {
    execSync(`npm install --ignore-scripts --no-audit --no-fund --loglevel=error ${topLevel.join(' ')}`,
        { cwd: work, stdio: 'inherit' });
} catch (e) {
    console.error('npm install failed (network required for this benchmark).');
    fs.rmSync(work, { recursive: true, force: true });
    process.exit(1);
}

const probe = path.join(work, '_probe.js');
fs.writeFileSync(probe, `
    const path = require('path');
    const bh = require(${JSON.stringify(path.resolve(__dirname, '../src/index'))});
    bh.init();
    const name = process.argv[2];
    try { require(path.resolve(process.cwd(), 'node_modules', name)); } catch (e) {}
    setTimeout(() => {
        let me = null;
        for (const v of bh.getTrustScores().values()) { if (v.name === name) me = v; }
        process.stdout.write(JSON.stringify({ name, score: me ? me.score : 100, risk: me ? me.riskLevel : 'LOW', sig: me ? me.signalCount : 0 }) + '\\n');
        bh.teardown();
    }, 250);
`);

const allPkgs = fs.readdirSync(path.join(work, 'node_modules')).filter(n => !n.startsWith('.'));
const rows = [];
for (const name of allPkgs) {
    const r = spawnSync(process.execPath, [probe, name], { cwd: work, encoding: 'utf8' });
    try { rows.push(JSON.parse((r.stdout || '').trim().split('\n').pop())); } catch (e) { /* skip */ }
}

fs.rmSync(work, { recursive: true, force: true });

const n = rows.length;
const at = (levels) => rows.filter(r => levels.includes(r.risk)).length;
const pct = (k) => `${k} (${n ? (k / n * 100).toFixed(0) : 0}%)`;

console.log(`\nReal-package false-positive sweep — ${n} packages required (fresh process each)`);
console.log('-'.repeat(64));
console.log('flagged critical (<30):', pct(at(['CRITICAL'])));
console.log('flagged high+   (<60):', pct(at(['CRITICAL', 'HIGH'])), '  <-- recommended gate');
console.log('flagged medium+ (<80):', pct(at(['CRITICAL', 'HIGH', 'MEDIUM'])));
rows.sort((a, b) => a.score - b.score);
console.log('\nlowest-scoring packages:');
for (const r of rows.slice(0, 12)) {
    console.log('  ', String(r.name).padEnd(24), 'score=' + r.score, r.risk, 'signals=' + r.sig);
}
