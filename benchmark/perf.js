#!/usr/bin/env node
/**
 * BHEESHMA Monitoring Overhead Microbenchmark
 *
 * Measures the per-operation cost the hooks add, using a deliberately
 * worst-case workload: a tight loop that does almost nothing BUT hookable
 * operations (an env read + a file read each iteration). Real applications and
 * test suites spend most of their time in non-hooked work, so their observed
 * overhead is far lower than the multiplier reported here — treat this as an
 * upper bound, not a typical figure.
 *
 * Usage: node benchmark/perf.js
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const N = Number(process.env.PERF_ITERS || 20000);

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bheeshma-perf-'));
const pkgDir = path.join(root, 'node_modules', 'workpkg');
fs.mkdirSync(pkgDir, { recursive: true });
fs.writeFileSync(path.join(pkgDir, 'package.json'),
    JSON.stringify({ name: 'workpkg', version: '1.0.0', main: 'index.js' }));
fs.writeFileSync(path.join(pkgDir, 'index.js'), `
    const fs = require('fs');
    module.exports.work = function (n) {
        let acc = 0;
        for (let i = 0; i < n; i++) {
            const v = process.env.PATH;                 // ENV_ACCESS hook
            try { fs.readFileSync('/etc/hostname', 'utf8'); } catch (e) {} // FS_READ hook
            acc += v ? v.length : 0;
        }
        return acc;
    };
`);

const workpkg = require(path.join(pkgDir, 'index.js'));

function timed(fn) {
    const t = process.hrtime.bigint();
    fn();
    return Number(process.hrtime.bigint() - t) / 1e6; // ms
}

// Warm caches.
workpkg.work(1000);

const baseline = timed(() => workpkg.work(N));

const bheeshma = require('../src/index');
bheeshma.init();
const monitored = timed(() => workpkg.work(N));
const signals = bheeshma.getSignals().length;
bheeshma.teardown();

const opsPerIter = 2; // one env read + one fs read
const overheadMs = monitored - baseline;
const perOpUs = (overheadMs / (N * opsPerIter)) * 1000;

console.log('BHEESHMA monitoring overhead (worst-case: pure hook spam)');
console.log('-'.repeat(60));
console.log(`iterations:      ${N} x (1 env read + 1 fs read)`);
console.log(`baseline:        ${baseline.toFixed(1)} ms`);
console.log(`monitored:       ${monitored.toFixed(1)} ms`);
console.log(`overhead:        ${overheadMs.toFixed(1)} ms  (${(monitored / baseline).toFixed(1)}x)`);
console.log(`per hooked op:   ${perOpUs.toFixed(1)} us`);
console.log(`signals stored:  ${signals} (capped at maxSignals)`);
console.log('-'.repeat(60));
console.log('Note: real workloads do far more non-hooked work between hooked');
console.log('calls, so their overhead is much lower than the multiplier above.');

fs.rmSync(root, { recursive: true, force: true });
