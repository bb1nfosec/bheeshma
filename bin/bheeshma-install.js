#!/usr/bin/env node

/**
 * BHEESHMA Install — npm install monitor mode
 *
 * Wraps `npm install` and monitors every package's install-time behavior:
 * - What postinstall scripts run (and what they do)
 * - What network connections are made during install
 * - What files are created/modified outside node_modules
 * - What environment variables are read (credential theft during install)
 *
 * This catches the #1 attack vector of 2025-2026: malicious packages
 * that steal CI secrets during `npm install` (Shai-Hulud, axios compromise).
 *
 * Usage:
 *   bheeshma-install              # monitor `npm install`
 *   bheeshma-install ci           # monitor `npm ci`
 *   bheeshma-install <package>    # monitor `npm install <package>`
 *   bheeshma-install -- --save-dev <package>  # pass flags to npm
 */

'use strict';

const bheeshma = require('../src/index');
const path = require('path');
const fs = require('fs');

/**
 * Parse install-specific arguments
 */
function parseArgs() {
    const args = process.argv.slice(2);
    const options = {
        npmCommand: null,   // 'install', 'ci', 'i'
        npmArgs: [],
        output: null,
        enforce: true,
        configPath: null,
        format: 'cli'
    };

    for (const arg of args) {
        if (arg === '--' || arg.startsWith('-')) {
            options.npmArgs.push(arg);
        } else if (arg === 'install' || arg === 'i') {
            options.npmCommand = 'install';
        } else if (arg === 'ci') {
            options.npmCommand = 'ci';
        } else if (arg === '--output' || arg === '-o') {
            // Next arg is the output path — skip it (handled below)
        } else if (arg === '--format') {
            // Next arg is the format — skip it
        } else if (arg === '--config') {
            // Next arg is config path — skip it
        } else if (arg === '--no-enforce') {
            options.enforce = false;
        } else if (arg === '--sarif') {
            options.format = 'sarif';
        } else {
            // Treat as npm argument (package name)
            if (options.npmArgs.length === 0 || !options.npmArgs[options.npmArgs.length - 1].startsWith('-')) {
                options.npmArgs.push(arg);
            }
        }
    }

    // Actually re-parse properly
    const reparsed = { ...options, npmArgs: [], npmCommand: options.npmCommand || 'install' };
    let i = 0;
    while (i < args.length) {
        const arg = args[i];
        if (arg === '--output' || arg === '-o') {
            reparsed.output = args[i + 1];
            i += 2;
        } else if (arg === '--format') {
            reparsed.format = args[i + 1];
            i += 2;
        } else if (arg === '--config') {
            reparsed.configPath = args[i + 1];
            i += 2;
        } else if (arg === '--no-enforce') {
            reparsed.enforce = false;
            i += 1;
        } else if (arg === '--sarif') {
            reparsed.format = 'sarif';
            i += 1;
        } else if (arg === 'ci') {
            reparsed.npmCommand = 'ci';
            i += 1;
        } else if (arg === 'install' || arg === 'i') {
            reparsed.npmCommand = 'install';
            i += 1;
        } else {
            reparsed.npmArgs.push(arg);
            i += 1;
        }
    }

    return reparsed;
}

/**
 * Write structured log to stderr
 */
function log(level, message) {
    const prefix = level === 'error' ? '✗' : level === 'warning' ? '⚠' : level === 'success' ? '✓' : '→';
    process.stderr.write(`[bheeshma-install] ${prefix} ${message}\n`);
}

/**
 * Generate install-specific summary
 */
function generateInstallSummary() {
    const scores = bheeshma.getTrustScores();
    const signals = bheeshma.getSignals();

    if (signals.length === 0) {
        log('success', 'No suspicious behavior detected during npm install');
        return;
    }

    // Focus on install-time risk signals
    const highRiskSignals = signals.filter(s => {
        if (!s.package) return false;
        const pkgKey = `${s.package}@${s.version}`;
        const score = scores.get(pkgKey);
        return score && (score.riskLevel === 'CRITICAL' || score.riskLevel === 'HIGH');
    });

    if (highRiskSignals.length === 0) {
        log('success', `${signals.length} signals captured, all packages within acceptable thresholds`);
        return;
    }

    // Group by package
    const byPackage = new Map();
    for (const sig of highRiskSignals) {
        const key = sig.package || 'unknown';
        if (!byPackage.has(key)) {
            byPackage.set(key, []);
        }
        byPackage.get(key).push(sig);
    }

    log('warning', `${byPackage.size} package(s) exhibited suspicious install-time behavior:`);

    for (const [pkg, sigs] of byPackage) {
        const pkgKey = sigs[0].package + '@' + sigs[0].version;
        const score = scores.get(pkgKey);
        log('error', `${pkgKey} — trust score: ${score ? score.score : '?'}, risk: ${score ? score.riskLevel : '?'}`);

        for (const sig of sigs.slice(0, 5)) { // Show top 5 signals per package
            const detail = describeSignal(sig);
            log('error', `  ${sig.type}: ${detail}`);
        }
        if (sigs.length > 5) {
            log('error', `  ... and ${sigs.length - 5} more signals`);
        }
    }
}

/**
 * Human-readable signal description for install mode
 */
function describeSignal(signal) {
    switch (signal.type) {
        case 'SHELL_EXEC':
            return `ran: ${signal.metadata.command || '?'}`;
        case 'ENV_ACCESS':
            return `read env: ${signal.metadata.variable || '?'}`;
        case 'FS_WRITE':
            return `wrote: ${signal.metadata.path || '?'}`;
        case 'FS_READ':
            return `read: ${signal.metadata.path || '?'}`;
        case 'HTTP_REQUEST':
            return `HTTP ${signal.metadata.method} ${signal.metadata.host || signal.metadata.url || '?'}`;
        case 'HTTPS_REQUEST':
            return `HTTPS ${signal.metadata.method} ${signal.metadata.host || signal.metadata.url || '?'}`;
        case 'NET_CONNECT':
            return `TCP connect: ${signal.metadata.host}:${signal.metadata.port}`;
        case 'DNS_QUERY':
            return `DNS lookup: ${signal.metadata.hostname || '?'}`;
        case 'OBFUSCATION_DETECTED':
            return `obfuscated code: ${(signal.metadata.indicators || []).join(', ')}`;
        case 'BLACKLISTED_PACKAGE':
            return `blacklisted: ${signal.metadata.reason || 'known malicious'}`;
        default:
            return JSON.stringify(signal.metadata || {});
    }
}

/**
 * Main install monitor
 */
async function main() {
    const options = parseArgs();

    // Check if npm is available
    let npmBin = 'npm';
    try {
        const { execSync } = require('child_process');
        execSync('npm --version', { stdio: 'pipe' });
    } catch (e) {
        log('error', 'npm not found. bheeshma-install requires npm to be installed.');
        process.exit(1);
    }

    log('info', `Monitoring: npm ${options.npmCommand} ${options.npmArgs.join(' ')}`);
    log('info', 'Hooks will observe all install-time behavior...\n');

    // Initialize bheeshma hooks BEFORE running npm install
    const initResult = bheeshma.init({ configPath: options.configPath });
    if (!initResult.success) {
        log('warning', `Some hooks failed: ${initResult.failed ? initResult.failed.join(', ') : 'unknown'}`);
    }

    // Run npm install under monitoring
    const { spawn } = require('child_process');
    const npmArgs = [options.npmCommand, ...options.npmArgs];

    const child = spawn(npmBin, npmArgs, {
        stdio: 'inherit',
        cwd: process.cwd()
    });

    let npmExitCode = 0;

    await new Promise((resolve) => {
        child.on('exit', (code) => {
            npmExitCode = code || 0;
            resolve();
        });
        child.on('error', (err) => {
            log('error', `npm ${options.npmCommand} failed: ${err.message}`);
            npmExitCode = 1;
            resolve();
        });
    });

    // Give hooks a moment to flush
    await new Promise(resolve => setTimeout(resolve, 300));

    // Generate report
    process.stderr.write('\n');
    log('info', '─'.repeat(50));
    log('info', 'BHEESHMA INSTALL REPORT');
    log('info', '─'.repeat(50));
    process.stderr.write('\n');

    if (options.format === 'sarif') {
        // SARIF output
        const { formatReport: formatSarifReport } = require('../src/output/sarifFormatter');
        const { analyzePatterns } = require('../src/patterns/patternMatcher');
        const scores = bheeshma.getTrustScores();
        const signals = bheeshma.getSignals();
        const config = bheeshma.getConfig();
        const patternResults = analyzePatterns(signals, config ? config.patterns : {});

        let toolVersion = '1.0.0';
        try {
            const pkgJson = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../package.json'), 'utf8'));
            toolVersion = pkgJson.version;
        } catch (e) { /* default */ }

        const sarif = formatSarifReport(scores, signals, patternResults, {
            toolVersion,
            skipLow: true
        });

        const outputPath = options.output || 'bheeshma-install.sarif';
        fs.writeFileSync(outputPath, sarif, 'utf8');
        log('info', `SARIF report written to: ${outputPath}`);
    } else {
        // CLI output
        generateInstallSummary();
    }

    // Enforcement: fail if any package is CRITICAL during install
    if (options.enforce) {
        const enforcement = bheeshma.enforcePolicy();
        if (!enforcement.passed) {
            log('error', enforcement.message);
            process.exit(1);
        }
    }

    // Propagate npm's exit code
    if (npmExitCode !== 0) {
        process.exit(npmExitCode);
    }
}

main().catch(err => {
    log('error', `Fatal error: ${err.message}`);
    process.exit(1);
});
