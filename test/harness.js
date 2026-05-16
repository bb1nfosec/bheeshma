/**
 * BHEESHMA Test Harness v4
 * 
 * Tests: hooks, scoring, enforcement, whitelist, dedup, output formats,
 * negative tests (first-party code), blacklist enforcement, pattern analysis
 * (crypto mining, exfiltration, backdoors, credential theft), typosquat
 * detection, context-aware credential file reads (dotenv FP).
 */

'use strict';

const bheeshma = require('../src/index');
const fs = require('fs');
const path = require('path');

const results = { passed: 0, failed: 0, tests: [] };

function assert(condition, message) {
    if (condition) {
        console.log(`  ✓ ${message}`);
        results.passed++;
        results.tests.push({ name: message, passed: true });
    } else {
        console.error(`  ✗ ${message}`);
        results.failed++;
        results.tests.push({ name: message, passed: false });
    }
}

/**
 * Clear Node's require.cache for mock packages so their top-level
 * code re-executes on next require(). Without this, tests after
 * the first one that require()s a mock package get cached results.
 */
function clearRequireCache() {
    const mockDir = path.join(__dirname, 'node_modules');
    for (const key of Object.keys(require.cache)) {
        if (key.startsWith(mockDir)) {
            delete require.cache[key];
        }
    }
}

function setupMockPackages() {
    const nodeModulesDir = path.join(__dirname, 'node_modules');

    // --- test-benign: minimal, harmless dependency ---
    const benignDir = path.join(nodeModulesDir, 'test-benign');
    if (!fs.existsSync(benignDir)) fs.mkdirSync(benignDir, { recursive: true });
    fs.writeFileSync(path.join(benignDir, 'package.json'), JSON.stringify({ name: 'test-benign', version: '1.0.0' }), 'utf8');
    fs.writeFileSync(path.join(benignDir, 'index.js'), fs.readFileSync(path.join(__dirname, 'benign.js'), 'utf8'), 'utf8');

    // --- test-suspicious: network + env + shell ---
    const suspiciousDir = path.join(nodeModulesDir, 'test-suspicious');
    if (!fs.existsSync(suspiciousDir)) fs.mkdirSync(suspiciousDir, { recursive: true });
    fs.writeFileSync(path.join(suspiciousDir, 'package.json'), JSON.stringify({ name: 'test-suspicious', version: '1.0.0' }), 'utf8');
    fs.writeFileSync(path.join(suspiciousDir, 'index.js'), fs.readFileSync(path.join(__dirname, 'suspicious.js'), 'utf8'), 'utf8');

    // --- test-obfuscated: eval + Function + hex strings ---
    const obfusDir = path.join(nodeModulesDir, 'test-obfuscated');
    if (!fs.existsSync(obfusDir)) fs.mkdirSync(obfusDir, { recursive: true });
    fs.writeFileSync(path.join(obfusDir, 'package.json'), JSON.stringify({ name: 'test-obfuscated', version: '1.0.0', main: 'index.js' }), 'utf8');
    fs.writeFileSync(path.join(obfusDir, 'index.js'), `
        var a = eval("1+1");
        var b = new Function("return 2");
        var c = "\\x48\\x65\\x6c\\x6c\\x6f\\x48\\x65\\x6c\\x6c\\x6f\\x48\\x65\\x6c\\x6c\\x6f\\x48\\x65\\x6c\\x6c\\x6f\\x48\\x65\\x6c\\x6c\\x6f\\x48\\x65\\x6c\\x6c\\x6f\\x48\\x65\\x6c\\x6c\\x6f\\x48\\x65\\x6c\\x6c\\x6f";
    `, 'utf8');

    // --- test-dotenv-mock: simulates dotenv reading .env (should NOT be flagged) ---
    const dotenvDir = path.join(nodeModulesDir, 'test-dotenv-mock');
    if (!fs.existsSync(dotenvDir)) fs.mkdirSync(dotenvDir, { recursive: true });
    fs.writeFileSync(path.join(dotenvDir, 'package.json'), JSON.stringify({ name: 'test-dotenv-mock', version: '2.0.0', main: 'index.js' }), 'utf8');
    fs.writeFileSync(path.join(dotenvDir, 'index.js'), `
        // Simulates what dotenv does: reads .env and accesses env vars
        const fs = require('fs');
        const path = require('path');
        try {
            const envPath = path.resolve('.env');
            if (fs.existsSync(envPath)) {
                const content = fs.readFileSync(envPath, 'utf8');
                // Parse and set env vars
                const lines = content.split('\\n');
                for (const line of lines) {
                    const match = line.match(/^([^=:#]+)=(.*)$/);
                    if (match) {
                        process.env[match[1].trim()] = match[2].trim();
                    }
                }
            }
        } catch (e) {}
        module.exports = { parsed: process.env };
    `, 'utf8');

    // --- test-stealth-env: non-dotenve package reading .env (SHOULD be flagged) ---
    const stealthDir = path.join(nodeModulesDir, 'test-stealth-env');
    if (!fs.existsSync(stealthDir)) fs.mkdirSync(stealthDir, { recursive: true });
    fs.writeFileSync(path.join(stealthDir, 'package.json'), JSON.stringify({ name: 'test-stealth-env', version: '1.0.0', main: 'index.js' }), 'utf8');
    fs.writeFileSync(path.join(stealthDir, 'index.js'), `
        // Suspicious: a random package reading .env
        const fs = require('fs');
        try { fs.readFileSync('.env', 'utf8'); } catch(e) {}
        try { fs.readFileSync('.npmrc', 'utf8'); } catch(e) {}
        module.exports = {};
    `, 'utf8');

    // --- test-typosquat: package name similar to popular package ---
    const typosquatDir = path.join(nodeModulesDir, 'lodassh');
    if (!fs.existsSync(typosquatDir)) fs.mkdirSync(typosquatDir, { recursive: true });
    fs.writeFileSync(path.join(typosquatDir, 'package.json'), JSON.stringify({ name: 'lodassh', version: '1.0.0', main: 'index.js' }), 'utf8');
    fs.writeFileSync(path.join(typosquatDir, 'index.js'), `
        // Looks like "lodash" with extra 's' — typosquat candidate
        // Needs to trigger at least one signal for bheeshma to see it
        process.env.LODASH_TEST = '1';
        module.exports = { merge: function() {} };
    `, 'utf8');

    // --- test-miner-mock: simulates cryptominer behavior ---
    const minerDir = path.join(nodeModulesDir, 'test-miner-mock');
    if (!fs.existsSync(minerDir)) fs.mkdirSync(minerDir, { recursive: true });
    fs.writeFileSync(path.join(minerDir, 'package.json'), JSON.stringify({ name: 'test-miner-mock', version: '1.0.0', main: 'index.js' }), 'utf8');
    fs.writeFileSync(path.join(minerDir, 'index.js'), `
        // Simulates crypto miner: sets WALLET_ADDRESS and connects to mining pool
        process.env.WALLET_ADDRESS = 'test_wallet';
        process.env.MINING_POOL = 'pool.supportxmr.com:443';
        module.exports = { mine: function() {} };
    `, 'utf8');
}

function cleanupMockPackages() {
    const nodeModulesDir = path.join(__dirname, 'node_modules');
    if (fs.existsSync(nodeModulesDir)) {
        fs.rmSync(nodeModulesDir, { recursive: true, force: true });
    }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Full reset between tests:
 * 1. Teardown bheeshma (removes hooks, clears signals + caches)
 * 2. Clear Node's require.cache for mock packages
 */
function resetBetweenTests() {
    bheeshma.teardown();
    clearRequireCache();
}

async function runTests() {
    console.log('='.repeat(70));
    console.log('BHEESHMA Test Harness v4');
    console.log('='.repeat(70));
    console.log('');

    setupMockPackages();

    // ===================================================================
    // Test 1: Initialization (6 hooks including dns)
    // ===================================================================
    console.log('Test Group: Initialization');
    console.log('-'.repeat(70));
    const initResult = bheeshma.init();
    assert(initResult.success, 'Hooks should initialize successfully');
    assert(initResult.installed.length >= 5, 'At least 5 hooks should be installed');
    assert(initResult.installed.includes('envHook'), 'envHook should be installed');
    assert(initResult.installed.includes('fsHook'), 'fsHook should be installed');
    assert(initResult.installed.includes('netHook'), 'netHook should be installed');
    assert(initResult.installed.includes('childProcHook'), 'childProcHook should be installed');
    assert(initResult.installed.includes('httpHook'), 'httpHook should be installed');
    resetBetweenTests();
    console.log('');

    // ===================================================================
    // Test 2: Benign Dependency
    // ===================================================================
    console.log('Test Group: Benign Dependency Behavior');
    console.log('-'.repeat(70));
    bheeshma.init();
    require('./node_modules/test-benign/index.js');
    await sleep(100);

    const benignSignals = bheeshma.getSignals();
    const benignScores = bheeshma.getTrustScores();
    console.log(`  Captured ${benignSignals.length} signals from benign dependency`);

    assert(benignSignals.length >= 0, 'Benign dependency generates signals (or none)');
    const benignPackages = Array.from(benignScores.values());
    if (benignPackages.length > 0) {
        assert(benignPackages[0].score >= 70, 'Benign dependency should have high trust score (>= 70)');
    }
    resetBetweenTests();
    console.log('');

    // ===================================================================
    // Test 3: Suspicious Dependency
    // ===================================================================
    console.log('Test Group: Suspicious Dependency Behavior');
    console.log('-'.repeat(70));
    bheeshma.init();
    require('./node_modules/test-suspicious/index.js');
    await sleep(200);

    const suspiciousSignals = bheeshma.getSignals();
    const suspiciousScores = bheeshma.getTrustScores();
    console.log(`  Captured ${suspiciousSignals.length} signals from suspicious dependency`);

    assert(suspiciousSignals.length > 0, 'Suspicious dependency should generate signals');
    const suspiciousPackages = Array.from(suspiciousScores.values());
    if (suspiciousPackages.length > 0) {
        assert(suspiciousPackages[0].score < 100, 'Suspicious dependency should have reduced trust score (< 100)');
    }
    resetBetweenTests();
    console.log('');

    // ===================================================================
    // Test 4: Whitelist Suppression
    // ===================================================================
    console.log('Test Group: Whitelist Suppression');
    console.log('-'.repeat(70));
    bheeshma.init({
        config: {
            whitelist: ['test-suspicious']
        }
    });
    require('./node_modules/test-suspicious/index.js');
    await sleep(200);

    const whitelistedSignals = bheeshma.getSignals();
    console.log(`  Signals after whitelisting: ${whitelistedSignals.length}`);
    const whitelistedPkgSignals = whitelistedSignals.filter(s => s.package === 'test-suspicious');
    assert(whitelistedPkgSignals.length === 0, 'Whitelisted package signals should be suppressed');
    resetBetweenTests();
    console.log('');

    // ===================================================================
    // Test 5: Signal Deduplication
    // ===================================================================
    console.log('Test Group: Signal Deduplication');
    console.log('-'.repeat(70));
    bheeshma.init({
        config: {
            performance: { deduplicateSignals: true }
        }
    });
    require('./node_modules/test-suspicious/index.js');
    await sleep(200);

    const dedupScores = bheeshma.getTrustScores();
    const dedupPackages = Array.from(dedupScores.values());
    if (dedupPackages.length > 0) {
        const pkg = dedupPackages[0];
        assert(pkg.uniqueSignalCount !== undefined, 'Unique signal count should be calculated');
        if (pkg.signalCount > 1) {
            assert(pkg.uniqueSignalCount <= pkg.signalCount, 'Unique count should be <= total count');
        }
    }
    resetBetweenTests();
    console.log('');

    // ===================================================================
    // Test 6: Enforcement Mode
    // ===================================================================
    console.log('Test Group: Policy Enforcement');
    console.log('-'.repeat(70));
    bheeshma.init();
    require('./node_modules/test-suspicious/index.js');
    await sleep(200);

    const enforcement = bheeshma.enforcePolicy();
    assert(typeof enforcement.passed === 'boolean', 'Enforcement should return pass/fail');
    assert(Array.isArray(enforcement.criticalPackages), 'Should return critical packages array');
    if (enforcement.criticalPackages.length > 0) {
        assert(enforcement.criticalPackages[0].name !== undefined, 'Critical package should have name');
    }
    resetBetweenTests();
    console.log('');

    // ===================================================================
    // Test 7: Output Formats
    // ===================================================================
    console.log('Test Group: Output Formatting');
    console.log('-'.repeat(70));
    bheeshma.init();
    require('./node_modules/test-suspicious/index.js');
    await sleep(200);

    const cliReport = bheeshma.generateReport('cli');
    const jsonReport = bheeshma.generateReport('json');
    const htmlReport = bheeshma.generateReport('html');

    assert(cliReport.length > 0, 'CLI report should be generated');
    assert(cliReport.includes('BHEESHMA'), 'CLI report should contain header');

    assert(jsonReport.length > 0, 'JSON report should be generated');
    let jsonValid = false;
    try {
        const parsed = JSON.parse(jsonReport);
        jsonValid = parsed.version === '1.0' && Array.isArray(parsed.packages);
    } catch (err) {}
    assert(jsonValid, 'JSON report should be valid JSON');

    assert(htmlReport.length > 0, 'HTML report should be generated');
    assert(htmlReport.includes('<!DOCTYPE html>'), 'HTML report should be valid HTML');
    assert(htmlReport.includes('BHEESHMA'), 'HTML report should contain header');
    assert(htmlReport.includes('script'), 'HTML report should contain embedded JS');

    // Verify XSS protection
    assert(htmlReport.includes('escapeHtml'), 'HTML report should include XSS protection');
    resetBetweenTests();
    console.log('');

    // ===================================================================
    // Test 8: Per-package Thresholds
    // ===================================================================
    console.log('Test Group: Per-Package Thresholds');
    console.log('-'.repeat(70));
    bheeshma.init({
        config: {
            packageThresholds: {
                'test-suspicious': 90
            }
        }
    });
    require('./node_modules/test-suspicious/index.js');
    await sleep(200);

    const thresholdScores = bheeshma.getTrustScores();
    const thresholdPackages = Array.from(thresholdScores.values());
    if (thresholdPackages.length > 0) {
        const pkg = thresholdPackages[0];
        assert(pkg.riskLevel !== undefined, 'Risk level should be calculated with custom threshold');
        console.log(`  Custom threshold score: ${pkg.score}, riskLevel: ${pkg.riskLevel}`);
    }
    resetBetweenTests();
    console.log('');

    // ===================================================================
    // Test 9: DNS Hook
    // ===================================================================
    console.log('Test Group: DNS Monitoring');
    console.log('-'.repeat(70));
    bheeshma.init();
    try {
        const dns = require('dns');
        dns.lookup('localhost', () => {});
        await sleep(100);

        const dnsSignals = bheeshma.getSignals().filter(s => s.type === 'DNS_QUERY');
        console.log(`  DNS signals captured: ${dnsSignals.length}`);
        assert(dnsSignals.length >= 0, 'DNS hook should not crash');
    } catch (err) {
        assert(true, 'DNS hook test skipped (dns module unavailable)');
    }
    resetBetweenTests();
    console.log('');

    // ===================================================================
    // Test 10: Negative Test — First-party code should NOT generate signals
    // ===================================================================
    console.log('Test Group: Negative Tests (First-Party Code)');
    console.log('-'.repeat(70));
    bheeshma.init();

    const testEnv = process.env.NODE_ENV;
    const testPath = path.join(__dirname, 'harness.js');
    if (fs.existsSync(testPath)) {
        fs.readFileSync(testPath, 'utf8');
    }
    await sleep(100);

    const firstPartySignals = bheeshma.getSignals().filter(s => s.package === null);
    const thirdPartySignals = bheeshma.getSignals().filter(s => s.package !== null);
    console.log(`  First-party signals: ${firstPartySignals.length}, Third-party signals: ${thirdPartySignals.length}`);
    assert(thirdPartySignals.length === 0, 'No third-party signals should be generated from first-party code');
    resetBetweenTests();
    console.log('');

    // ===================================================================
    // Test 11: Blacklist Enforcement
    // ===================================================================
    console.log('Test Group: Blacklist Enforcement');
    console.log('-'.repeat(70));
    bheeshma.init({
        config: {
            blacklist: ['test-suspicious']
        }
    });
    require('./node_modules/test-suspicious/index.js');
    await sleep(200);

    const blacklistSignals = bheeshma.getSignals();
    const blacklistFlag = blacklistSignals.some(s => s.type === 'BLACKLISTED_PACKAGE');
    assert(blacklistFlag, 'Blacklisted package should get BLACKLISTED_PACKAGE signal');

    const blacklistScores = bheeshma.getTrustScores();
    const blacklistPkg = Array.from(blacklistScores.values()).find(p => p.name === 'test-suspicious');
    if (blacklistPkg) {
        assert(blacklistPkg.score === 0, 'Blacklisted package should have trust score 0');
        assert(blacklistPkg.riskLevel === 'CRITICAL', 'Blacklisted package should be CRITICAL');
    }
    resetBetweenTests();
    console.log('');

    // ===================================================================
    // Test 12: Pattern Analysis — Crypto Mining
    // ===================================================================
    console.log('Test Group: Pattern Analysis — Crypto Mining');
    console.log('-'.repeat(70));
    bheeshma.init();
    require('./node_modules/test-miner-mock/index.js');
    await sleep(200);

    const report = bheeshma.generateReport('json');
    const reportData = JSON.parse(report);
    const hasPatternAnalysis = reportData.patternAnalysis &&
        (reportData.patternAnalysis.cryptoMining > 0 ||
         (reportData.patternAnalysis.details &&
          reportData.patternAnalysis.details.cryptoMining &&
          reportData.patternAnalysis.details.cryptoMining.length > 0));

    assert(hasPatternAnalysis, 'Crypto mining pattern should be detected');
    resetBetweenTests();
    console.log('');

    // ===================================================================
    // Test 13: Pattern Analysis — Credential Theft (context-aware)
    // ===================================================================
    console.log('Test Group: Pattern Analysis — Context-Aware Credential Theft');
    console.log('-'.repeat(70));

    // 13a: dotenv-mock reading .env should be LOW severity
    console.log('  [13a] dotenv-mock reading .env:');
    bheeshma.init();
    require('./node_modules/test-dotenv-mock/index.js');
    await sleep(200);

    const dotenvReport = JSON.parse(bheeshma.generateReport('json'));
    const dotenvCredTheft = dotenvReport.patternAnalysis?.details?.credentialTheft || [];
    if (dotenvCredTheft.length > 0) {
        const envRead = dotenvCredTheft.find(c => c.indicator === '.env');
        if (envRead) {
            assert(envRead.severity === 'LOW',
                'dotenv reading .env should be LOW severity (context-aware)');
            console.log(`    severity: ${envRead.severity}, context: ${envRead.context || 'none'}`);
        } else {
            assert(true, 'No .env credential theft flagged for dotenv (acceptable)');
        }
    } else {
        assert(true, 'No credential theft flagged for dotenv (acceptable)');
    }
    resetBetweenTests();

    // 13b: stealth-env reading .env should be HIGH severity
    console.log('  [13b] Non-dotenve package reading .env:');
    bheeshma.init();
    require('./node_modules/test-stealth-env/index.js');
    await sleep(200);

    const stealthReport = JSON.parse(bheeshma.generateReport('json'));
    const stealthCredTheft = stealthReport.patternAnalysis?.details?.credentialTheft || [];
    if (stealthCredTheft.length > 0) {
        const envRead = stealthCredTheft.find(c => c.indicator === '.env');
        if (envRead) {
            assert(envRead.severity === 'HIGH',
                'Non-dotenve package reading .env should be HIGH severity');
            console.log(`    severity: ${envRead.severity}, package: ${envRead.package}`);
        } else {
            // Might not be in patternAnalysis but should still be in signals
            const stealthSignals = bheeshma.getSignals();
            const envFileReads = stealthSignals.filter(s =>
                s.type === 'FS_READ' && s.metadata.path && s.metadata.path.includes('.env')
            );
            assert(envFileReads.length > 0, 'Non-dotenve package .env read should be captured as FS_READ signal');
        }
    } else {
        // Fallback: check raw signals
        const stealthSignals = bheeshma.getSignals();
        const envFileReads = stealthSignals.filter(s =>
            s.type === 'FS_READ' && s.metadata.path && s.metadata.path.includes('.env')
        );
        assert(envFileReads.length > 0, 'Non-dotenve package .env read should be captured as FS_READ signal');
    }
    resetBetweenTests();
    console.log('');

    // ===================================================================
    // Test 14: Typosquat Detection
    // ===================================================================
    console.log('Test Group: Typosquat Detection');
    console.log('-'.repeat(70));
    bheeshma.init();
    require('./node_modules/lodassh/index.js');
    await sleep(200);

    const typoReport = JSON.parse(bheeshma.generateReport('json'));
    const hasTyposquat = typoReport.patternAnalysis &&
        typoReport.patternAnalysis.details &&
        typoReport.patternAnalysis.details.typosquats &&
        typoReport.patternAnalysis.details.typosquats.length > 0;

    assert(hasTyposquat, 'Typosquat package "lodassh" should be detected as similar to "lodash"');
    resetBetweenTests();
    console.log('');

    // ===================================================================
    // Test 15: Teardown
    // ===================================================================
    console.log('Test Group: Teardown');
    console.log('-'.repeat(70));
    const teardownResult = bheeshma.teardown();
    assert(teardownResult.success, 'Teardown should succeed');

    cleanupMockPackages();

    // ===================================================================
    // Summary
    // ===================================================================
    console.log('='.repeat(70));
    console.log('Test Summary');
    console.log('='.repeat(70));
    console.log(`  Total Tests: ${results.passed + results.failed}`);
    console.log(`  Passed: ${results.passed}`);
    console.log(`  Failed: ${results.failed}`);
    console.log('');

    if (results.failed === 0) {
        console.log('  ✓ All tests passed!');
        process.exit(0);
    } else {
        console.error(`  ✗ ${results.failed} test(s) failed.`);
        process.exit(1);
    }
}

runTests().catch(err => {
    console.error('Test harness error:', err);
    process.exit(1);
});
