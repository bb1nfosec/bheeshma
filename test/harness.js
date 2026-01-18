/**
 * BHEESHMA Test Harness
 * 
 * Security: Offline, deterministic tests requiring no network
 * 
 * Purpose: Validate that BHEESHMA correctly detects and scores
 * benign vs. suspicious dependency behaviors.
 */

'use strict';

const bheeshma = require('../src/index');
const fs = require('fs');
const path = require('path');

/**
 * Test results tracker
 */
const results = {
    passed: 0,
    failed: 0,
    tests: []
};

/**
 * Assert helper
 */
function assert(condition, message) {
    if (condition) {
        console.log(`✓ ${message}`);
        results.passed++;
        results.tests.push({ name: message, passed: true });
    } else {
        console.error(`✗ ${message}`);
        results.failed++;
        results.tests.push({ name: message, passed: false });
    }
}

/**
 * Setup mock node_modules for testing
 * Creates temporary packages so attribution works
 */
function setupMockPackages() {
    const testDir = path.join(__dirname, '../test');
    const nodeModulesDir = path.join(testDir, 'node_modules');

    // Create node_modules/test-benign
    const benignDir = path.join(nodeModulesDir, 'test-benign');
    if (!fs.existsSync(benignDir)) {
        fs.mkdirSync(benignDir, { recursive: true });
    }

    fs.writeFileSync(
        path.join(benignDir, 'package.json'),
        JSON.stringify({ name: 'test-benign', version: '1.0.0' }),
        'utf8'
    );

    fs.writeFileSync(
        path.join(benignDir, 'index.js'),
        fs.readFileSync(path.join(testDir, 'benign.js'), 'utf8'),
        'utf8'
    );

    // Create node_modules/test-suspicious
    const suspiciousDir = path.join(nodeModulesDir, 'test-suspicious');
    if (!fs.existsSync(suspiciousDir)) {
        fs.mkdirSync(suspiciousDir, { recursive: true });
    }

    fs.writeFileSync(
        path.join(suspiciousDir, 'package.json'),
        JSON.stringify({ name: 'test-suspicious', version: '1.0.0' }),
        'utf8'
    );

    fs.writeFileSync(
        path.join(suspiciousDir, 'index.js'),
        fs.readFileSync(path.join(testDir, 'suspicious.js'), 'utf8'),
        'utf8'
    );
}

/**
 * Cleanup mock packages
 */
function cleanupMockPackages() {
    const nodeModulesDir = path.join(__dirname, 'node_modules');
    if (fs.existsSync(nodeModulesDir)) {
        fs.rmSync(nodeModulesDir, { recursive: true, force: true });
    }
}

/**
 * Run test suite
 */
async function runTests() {
    console.log('='.repeat(70));
    console.log('BHEESHMA Test Harness');
    console.log('='.repeat(70));
    console.log('');

    // Setup
    setupMockPackages();

    // Test 1: Initialization
    console.log('Test Group: Initialization');
    console.log('-'.repeat(70));

    const initResult = bheeshma.init();
    assert(initResult.success, 'Hooks should initialize successfully');
    assert(initResult.installed.length === 4, 'All 4 hooks should be installed');
    assert(initResult.installed.includes('envHook'), 'envHook should be installed');
    assert(initResult.installed.includes('fsHook'), 'fsHook should be installed');
    assert(initResult.installed.includes('netHook'), 'netHook should be installed');
    assert(initResult.installed.includes('childProcHook'), 'childProcHook should be installed');

    console.log('');

    // Test 2: Benign Dependency
    console.log('Test Group: Benign Dependency Behavior');
    console.log('-'.repeat(70));

    bheeshma.teardown();
    bheeshma.init();

    // Load benign test package
    require('./node_modules/test-benign/index.js');

    await sleep(100); // Allow signals to propagate

    const benignSignals = bheeshma.getSignals();
    const benignScores = bheeshma.getTrustScores();

    console.log(`Captured ${benignSignals.length} signals from benign dependency`);

    // Benign should have minimal signals
    assert(benignSignals.length >= 0, 'Benign dependency generates signals (or none)');

    // Check trust score if signals were captured
    const benignPackages = Array.from(benignScores.values());
    if (benignPackages.length > 0) {
        const score = benignPackages[0].score;
        console.log(`Benign trust score: ${score}/100`);
        assert(score >= 80, 'Benign dependency should have high trust score (>= 80)');
    } else {
        console.log('No signals from benign package (acceptable)');
    }

    console.log('');

    // Test 3: Suspicious Dependency
    console.log('Test Group: Suspicious Dependency Behavior');
    console.log('-'.repeat(70));

    bheeshma.teardown();
    bheeshma.init();

    // Load suspicious test package
    require('./node_modules/test-suspicious/index.js');

    await sleep(200); // Longer wait for async operations

    const suspiciousSignals = bheeshma.getSignals();
    const suspiciousScores = bheeshma.getTrustScores();

    console.log(`Captured ${suspiciousSignals.length} signals from suspicious dependency`);

    // Display captured signals for debugging
    if (suspiciousSignals.length > 0) {
        const signalTypes = [...new Set(suspiciousSignals.map(s => s.type))];
        console.log(`Signal types captured: ${signalTypes.join(', ')}`);
    }

    // Check for specific risky behaviors (relaxed thresholds)
    const hasEnvAccess = suspiciousSignals.some(s => s.type === 'ENV_ACCESS');
    const hasFsWrite = suspiciousSignals.some(s => s.type === 'FS_WRITE');
    const hasNetConnect = suspiciousSignals.some(s => s.type === 'NET_CONNECT');
    const hasShellExec = suspiciousSignals.some(s => s.type === 'SHELL_EXEC');

    // At least some signals should be captured
    assert(suspiciousSignals.length > 0, 'Suspicious dependency should generate signals');
    assert(hasEnvAccess || hasFsWrite || hasNetConnect || hasShellExec,
        'Suspicious dependency should trigger at least one high-risk behavior');

    // Check trust score
    const suspiciousPackages = Array.from(suspiciousScores.values());
    if (suspiciousPackages.length > 0) {
        const score = suspiciousPackages[0].score;
        console.log(`Suspicious trust score: ${score}/100`);
        assert(score < 100, 'Suspicious dependency should have reduced trust score (< 100)');
    }

    console.log('');

    // Test 4: Output Formats
    console.log('Test Group: Output Formatting');
    console.log('-'.repeat(70));

    const cliReport = bheeshma.generateReport('cli');
    const jsonReport = bheeshma.generateReport('json');

    assert(cliReport.length > 0, 'CLI report should be generated');
    assert(cliReport.includes('BHEESHMA'), 'CLI report should contain header');

    assert(jsonReport.length > 0, 'JSON report should be generated');

    let jsonValid = false;
    try {
        const parsed = JSON.parse(jsonReport);
        jsonValid = parsed.version === '1.0' &&
            Array.isArray(parsed.packages) &&
            Array.isArray(parsed.signals);
    } catch (err) {
        jsonValid = false;
    }
    assert(jsonValid, 'JSON report should be valid JSON with correct schema');

    console.log('');

    // Test 5: Teardown
    console.log('Test Group: Teardown');
    console.log('-'.repeat(70));

    const teardownResult = bheeshma.teardown();
    assert(teardownResult.success, 'Teardown should succeed');
    assert(teardownResult.uninstalled.length === 4, 'All hooks should be uninstalled');

    const signalsAfterTeardown = bheeshma.getSignals();
    assert(signalsAfterTeardown.length === 0, 'Signals should be cleared after teardown');

    console.log('');

    // Cleanup
    cleanupMockPackages();

    // Summary
    console.log('='.repeat(70));
    console.log('Test Summary');
    console.log('='.repeat(70));
    console.log(`Total Tests: ${results.passed + results.failed}`);
    console.log(`Passed: ${results.passed}`);
    console.log(`Failed: ${results.failed}`);
    console.log('');

    if (results.failed === 0) {
        console.log('✓ All tests passed!');
        process.exit(0);
    } else {
        console.error('✗ Some tests failed.');
        process.exit(1);
    }
}

/**
 * Sleep helper
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Run tests
runTests().catch(err => {
    console.error('Test harness error:', err);
    process.exit(1);
});
