#!/usr/bin/env node

/**
 * BHEESHMA CI — CI/CD-optimized CLI for GitHub Actions
 *
 * Thin wrapper around bheeshma's core engine.
 * Outputs SARIF for GitHub Code Scanning annotations.
 * Exit code 0 = pass, exit code 1 = policy violation.
 *
 * Usage:
 *   bheeshma-ci -- node app.js
 *   bheeshma-ci -- npm test
 *   bheeshma-ci -- npm install
 */

'use strict';

const bheeshma = require('../src/index');
const fs = require('fs');
const os = require('os');
const path = require('path');

/**
 * Parse CI-specific arguments
 */
function parseArgs() {
    const args = process.argv.slice(2);
    const options = {
        output: null,        // SARIF output path
        enforce: true,       // Always enforce in CI mode
        failLevel: 'high', // minimum level to fail on (recommended gate; see docs)
        configPath: null,
        skipLow: true,       // Skip LOW-risk signals in SARIF (noise reduction)
        command: null,
        commandArgs: []
    };

    let i = 0;
    while (i < args.length) {
        const arg = args[i];
        if (arg === '--output' || arg === '-o') {
            options.output = args[i + 1];
            i += 2;
        } else if (arg === '--fail-level') {
            options.failLevel = args[i + 1];
            i += 2;
        } else if (arg === '--config') {
            options.configPath = args[i + 1];
            i += 2;
        } else if (arg === '--no-skip-low') {
            options.skipLow = false;
            i += 1;
        } else if (arg === '--' || arg.startsWith('-')) {
            // Treat everything after -- or after first unknown flag as the command
            options.commandArgs = arg === '--' ? args.slice(i + 1) : args.slice(i);
            break;
        } else {
            options.command = arg;
            options.commandArgs = args.slice(i + 1);
            break;
        }
    }

    // If no -- separator, first arg is command
    if (!options.command && options.commandArgs.length > 0) {
        options.command = options.commandArgs.shift();
    }

    return options;
}

/**
 * Write a structured CI log line to stderr.
 * CI systems parse stderr for annotations.
 */
function ciLog(level, message) {
    // GitHub Actions annotation format
    const ts = new Date().toISOString();
    if (process.env.GITHUB_ACTIONS) {
        switch (level) {
            case 'error':
                process.stderr.write(`::error::[bheeshma] ${message}\n`);
                break;
            case 'warning':
                process.stderr.write(`::warning::[bheeshma] ${message}\n`);
                break;
            case 'notice':
                process.stderr.write(`::notice::[bheeshma] ${message}\n`);
                break;
            default:
                process.stderr.write(`[bheeshma ${ts}] ${message}\n`);
        }
    } else {
        process.stderr.write(`[bheeshma ${level.toUpperCase()} ${ts}] ${message}\n`);
    }
}

/**
 * Generate SARIF report and write to file
 */
function writeSarifReport(outputPath, options) {
    const { formatReport: formatSarifReport } = require('../src/output/sarifFormatter');
    const { analyzePatterns } = require('../src/patterns/patternMatcher');

    const scores = bheeshma.getTrustScores();
    const signals = bheeshma.getSignals();
    const config = bheeshma.getConfig();
    const patternResults = analyzePatterns(signals, config ? config.patterns : {});

    // Get version from package.json
    let toolVersion = '1.0.0';
    try {
        const pkgJson = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../package.json'), 'utf8'));
        toolVersion = pkgJson.version;
    } catch (e) { /* use default */ }

    const sarif = formatSarifReport(scores, signals, patternResults, {
        toolVersion,
        skipLow: options.skipLow
    });

    const finalPath = outputPath || 'bheeshma-results.sarif';
    fs.writeFileSync(finalPath, sarif, 'utf8');
    return finalPath;
}

/**
 * Main CI execution
 */
async function main() {
    const options = parseArgs();

    if (!options.command) {
        ciLog('error', 'No command specified. Usage: bheeshma-ci -- <command>');
        process.exit(1);
    }

    // Validate fail level
    const validLevels = ['critical', 'high', 'medium', 'low'];
    if (!validLevels.includes(options.failLevel)) {
        ciLog('error', `Invalid fail level "${options.failLevel}". Use: ${validLevels.join(', ')}`);
        process.exit(1);
    }

    // Initialize hooks
    ciLog('info', 'Initializing runtime monitoring...');
    const initResult = bheeshma.init({ configPath: options.configPath });

    if (!initResult.success) {
        ciLog('warning', `Some hooks failed: ${initResult.failed ? initResult.failed.join(', ') : 'unknown'}`);
    }
    ciLog('info', `Hooks active: ${initResult.installed.join(', ')}`);

    // Execute the target command
    ciLog('info', `Executing: ${options.command} ${options.commandArgs.join(' ')}`);
    let exitCode = 0;

    // Collect signals from the process tree that actually runs the command.
    // The monitored command runs in a CHILD process, so we preload ci-preload.js
    // there (NODE_OPTIONS is inherited by the whole node tree) and have each
    // process write its signals to a per-PID file we ingest afterwards.
    const signalDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bheeshma-ci-'));

    try {
        const { spawn } = require('child_process');
        const child = spawn(options.command, options.commandArgs, {
            stdio: 'inherit',
            env: {
                ...process.env,
                BHEESHMA_SIGNAL_DIR: signalDir,
                ...(options.configPath ? { BHEESHMA_CONFIG_PATH: options.configPath } : {}),
                NODE_OPTIONS: [
                    process.env.NODE_OPTIONS || '',
                    '--require', path.resolve(__dirname, '../src/ci-preload.js')
                ].filter(Boolean).join(' ')
            }
        });

        await new Promise((resolve, reject) => {
            child.on('exit', (code) => {
                exitCode = code || 0;
                resolve();
            });
            child.on('error', (err) => {
                ciLog('error', `Command failed: ${err.message}`);
                exitCode = 1;
                resolve();
            });
        });
    } catch (err) {
        ciLog('error', `Execution error: ${err.message}`);
        exitCode = 1;
    }

    // Give the process tree a moment to finish flushing signal files.
    await new Promise(resolve => setTimeout(resolve, 200));

    // Ingest signals collected by the monitored process tree.
    try {
        const files = fs.readdirSync(signalDir).filter(f => f.endsWith('.json'));
        let ingested = 0;
        for (const file of files) {
            try {
                const arr = JSON.parse(fs.readFileSync(path.join(signalDir, file), 'utf8'));
                ingested += bheeshma.ingestSignals(arr);
            } catch (e) { /* skip unreadable file */ }
        }
        ciLog('info', `Ingested ${ingested} signal(s) from monitored process tree`);
    } catch (e) {
        ciLog('warning', 'Could not read collected signals');
    } finally {
        try { fs.rmSync(signalDir, { recursive: true, force: true }); } catch (e) { /* ignore */ }
    }

    // Generate SARIF report
    ciLog('info', 'Generating SARIF report...');
    const sarifPath = writeSarifReport(options.output, options);
    ciLog('info', `SARIF report: ${sarifPath}`);

    // Check policy
    // The fail level is applied inside enforcePolicy now (it returns every
    // package at or above the level), so a violation here is authoritative.
    const enforcement = bheeshma.enforcePolicy({ failLevel: options.failLevel });

    // Log summary to stderr
    const scores = bheeshma.getTrustScores();
    const signals = bheeshma.getSignals();
    ciLog('info', `Monitored ${scores.size} packages, ${signals.length} signals captured`);

    if (!enforcement.passed) {
        for (const pkg of enforcement.violatingPackages) {
            ciLog('error', `POLICY VIOLATION: ${pkg.name}@${pkg.version} — trust score ${pkg.score} (${pkg.riskLevel})`);
        }
        ciLog('error', enforcement.message);
        process.exit(1);
    } else {
        ciLog('info', `All packages within acceptable risk thresholds (fail-level: ${options.failLevel})`);
    }

    // Propagate original command's exit code if it failed
    if (exitCode !== 0) {
        process.exit(exitCode);
    }
}

main().catch(err => {
    ciLog('error', `Fatal error: ${err.message}`);
    process.exit(1);
});
