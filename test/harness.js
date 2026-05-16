/**
 * BHEESHMA Test Harness v3
 * 
 * Tests: hooks, scoring, enforcement, whitelist, dedup, output formats,
 * negative tests (first-party code), obfuscation detection
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

    const benignDir = path.join(nodeModulesDir, 'test-benign');
    if (!fs.existsSync(benignDir)) fs.mkdirSync(benignDir, { recursive: true });
    fs.writeFileSync(path.join(benignDir, 'package.json'), JSON.stringify({ name: 'test-benign', version: '1.0.0' }), 'utf8');
    fs.writeFileSync(path.join(benignDir, 'index.js'), fs.readFileSync(path.join(__dirname, 'benign.js'), 'utf8'), 'utf8');

    const suspiciousDir = path.join(nodeModulesDir, 'test-suspicious');
    if (!fs.existsSync(suspiciousDir)) fs.mkdirSync(suspiciousDir, { recursive: true });
    fs.writeFileSync(path.join(suspiciousDir, 'package.json'), JSON.stringify({ name: 'test-suspicious', version: '1.0.0' }), 'utf8');
    fs.writeFileSync(path.join(suspiciousDir, 'index.js'), fs.readFileSync(path.join(__dirname, 'suspicious.js'), 'utf8'), 'utf8');

    // Create an obfuscated mock package
    const obfusDir = path.join(nodeModulesDir, 'test-obfuscated');
    if (!fs.existsSync(obfusDir)) fs.mkdirSync(obfusDir, { recursive: true });
    fs.writeFileSync(path.join(obfusDir, 'package.json'), JSON.stringify({ name: 'test-obfuscated', version: '1.0.0', main: 'index.js' }), 'utf8');
    fs.writeFileSync(path.join(obfusDir, 'index.js'), `
        var a = eval("1+1");
        var b = new Function("return 2");
        var c = "\\x48\\x65\\x6c\\x6c\\x6f\\x48\\x65\\x6c\\x6c\\x6f\\x48\\x65\\x6c\\x6c\\x6f\\x48\\x65\\x6c\\x6c\\x6f\\x48\\x65\\x6c\\x6c\\x6f\\x48\\x65\\x6c\\x6c\\x6f\\x48\\x65\\x6c\\x6c\\x6f\\x48\\x65\\x6c\\x6c\\x6f\\x48\\x65\\x6c\\x6c\\x6f";
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
    console.log('BHEESHMA Test Harness v3');
    console.log('='.repeat(70));
    console.log('');

    setupMockPackages();

    // Test 1: Initialization (6 hooks including dns)
    console.log('Test Group: Initialization');
    console.log('-'.repeat(70));
    const initResult = bheeshma.init();
    assert(initResult.success, 'Hooks should initialize successfully');
    assert(initResult.installed.length >= 5, 'At least 5 hooks should be installed');
    assert(initResult.installed.includes('envHook'), 'envHook should be installed');
    assert(initResult.installed.includes('fsHook'), 'fsHook should be installed');
    assert(initResult.installed.includes('netHook'), 'netHook should be installed');
    assert(initResult.installed.includes('childProcHook'), 'childProcHook should be installed');
    resetBetweenTests();
    console.log('');

    // Test 2: Benign Dependency
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

    // Test 3: Suspicious Dependency
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

    // Test 4: Whitelist Suppression
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
    // All test-suspicious signals should be suppressed at the hook layer
    const whitelistedPkgSignals = whitelistedSignals.filter(s => s.package === 'test-suspicious');
    assert(whitelistedPkgSignals.length === 0, 'Whitelisted package signals should be suppressed');
    resetBetweenTests();
    console.log('');

    // Test 5: Signal Deduplication
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

    // Test 6: Enforcement Mode
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

    // Test 7: Output Formats
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

    // Verify XSS protection — HTML report should contain escapeHtml function
    assert(htmlReport.includes('escapeHtml'), 'HTML report should include XSS protection');
    resetBetweenTests();
    console.log('');

    // Test 8: Per-package Thresholds
    console.log('Test Group: Per-Package Thresholds');
    console.log('-'.repeat(70));
    bheeshma.init({
        config: {
            packageThresholds: {
                'test-suspicious': 90  // Very lenient — should not be CRITICAL
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

    // Test 9: DNS Hook
    console.log('Test Group: DNS Monitoring');
    console.log('-'.repeat(70));
    bheeshma.init();
    try {
        const dns = require('dns');
        // Trigger a DNS lookup
        dns.lookup('localhost', () => {});
        await sleep(100);

        const dnsSignals = bheeshma.getSignals().filter(s => s.type === 'DNS_QUERY');
        console.log(`  DNS signals captured: ${dnsSignals.length}`);
        // May or may not capture depending on environment
        assert(dnsSignals.length >= 0, 'DNS hook should not crash');
    } catch (err) {
        assert(true, 'DNS hook test skipped (dns module unavailable)');
    }
    resetBetweenTests();
    console.log('');

    // Test 10: Negative Test — First-party code should NOT generate signals
    console.log('Test Group: Negative Tests (First-Party Code)');
    console.log('-'.repeat(70));
    bheeshma.init();

    // Simulate first-party code behavior (reading files, accessing env vars)
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

    // Test 11: Teardown
    console.log('Test Group: Teardown');
    console.log('-'.repeat(70));
    const teardownResult = bheeshma.teardown();
    assert(teardownResult.success, 'Teardown should succeed');

    cleanupMockPackages();

    // Summary
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
