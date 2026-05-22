#!/usr/bin/env node

/**
 * BHEESHMA CLI Entry Point
 *
 * Usage:
 *   bheeshma [options] -- <command>
 *   bheeshma --format json --output report.json -- node app.js
 *   bheeshma --enforce -- node app.js          (CI mode - exit 1 on CRITICAL)
 *   bheeshma --format sarif --output results.sarif -- node app.js
 *   bheeshma install [-- sarif]                (monitor npm install)
 *   bheeshma ci -- <command>                   (CI-optimized mode)
 */

'use strict';

const bheeshma = require('../src/index');
const fs = require('fs');
const path = require('path');

/**
 * Detect subcommand from first argument
 */
function detectSubcommand(args) {
    const first = args[0];
    if (first === 'install' || first === 'i') return 'install';
    if (first === 'ci') return 'ci';
    if (first === 'diff') return 'diff';
    if (first === 'lock') return 'lock';
    if (first === 'explain') return 'explain';
    if (first === 'learn') return 'learn';
    return null;
}

/**
 * Parse CLI arguments
 */
function parseArgs() {
    const args = process.argv.slice(2);

    // Check for subcommands first
    const sub = detectSubcommand(args);
    if (sub === 'install') return { subcommand: 'install', subArgs: args.slice(1) };
    if (sub === 'ci')      return { subcommand: 'ci',      subArgs: args.slice(1) };
    if (sub === 'diff')    return { subcommand: 'diff',    subArgs: args.slice(1) };
    if (sub === 'lock')    return { subcommand: 'lock',    subArgs: args.slice(1) };
    if (sub === 'explain') return { subcommand: 'explain', subArgs: args.slice(1) };
    if (sub === 'learn')   return { subcommand: 'learn',   subArgs: args.slice(1) };

    const options = {
        format: 'cli',
        output: null,
        enforce: false,
        alertWebhook: null,
        configPath: null,
        scriptPath: null,
        scriptArgs: []
    };

    let i = 0;
    while (i < args.length) {
        const arg = args[i];

        if (arg === '--learn') {
            options.learn = args[i + 1];
            i += 2;
        } else if (arg === '--baseline') {
            options.baseline = args[i + 1];
            i += 2;
        } else if (arg === '--fail-level') {
            options.failLevel = args[i + 1];
            i += 2;
        } else if (arg === '--webhook-format') {
            options.webhookFormat = args[i + 1];
            i += 2;
        } else if (arg === '--format') {
            options.format = args[i + 1];
            i += 2;
        } else if (arg === '--output' || arg === '-o') {
            options.output = args[i + 1];
            i += 2;
        } else if (arg === '--enforce') {
            options.enforce = true;
            i += 1;
        } else if (arg === '--alert-webhook') {
            options.alertWebhook = args[i + 1];
            i += 2;
        } else if (arg === '--config') {
            options.configPath = args[i + 1];
            i += 2;
        } else if (arg === '--help' || arg === '-h') {
            printHelp();
            process.exit(0);
        } else if (arg === '--version' || arg === '-v') {
            try {
                const pkg = require('../package.json');
                console.log(`bheeshma v${pkg.version}`);
            } catch (e) {
                console.log('bheeshma v1.0.0');
            }
            process.exit(0);
        } else if (arg === '--') {
            options.scriptArgs = args.slice(i + 1);
            break;
        } else {
            options.scriptPath = arg;
            options.scriptArgs = args.slice(i + 1);
            break;
        }
    }

    return options;
}

/**
 * Print help message
 */
function printHelp() {
    console.log(`
BHEESHMA - Runtime Dependency Behavior Monitor
The strace for npm packages. Zero dependencies. Zero config. Zero telemetry.

Usage:
  bheeshma [options] -- <command>
  bheeshma [options] <script.js>
  bheeshma install [options] [-- npm args]    Monitor npm install
  bheeshma ci -- <command>                    CI-optimized mode (SARIF output)
  bheeshma diff <baseline.json> <current.json>  Compare two reports
  bheeshma lock --save | --verify             Lockfile integrity check
  bheeshma explain <report.json>              Plain-English report summary
  bheeshma learn [baseline.json] -- <cmd>    Record behavioral baseline

Modes:
  (default)     Monitor any Node.js command or script
  install       Monitor npm install for malicious postinstall behavior
  ci            CI/CD-optimized mode with SARIF + exit codes
  diff          Show new findings between two JSON reports
  lock          Hash or verify package-lock.json / yarn.lock integrity
  explain       Summarize findings in plain English
  learn         Run app and record all signals as a known-good baseline

Options:
  --format <cli|json|html|sarif>         Output format (default: cli)
  --output <file>                        Write report to file
  -o <file>                              Alias for --output
  --enforce                              Exit 1 if any package exceeds fail level
  --fail-level <critical|high|medium|low>  Threshold for --enforce (default: critical)
  --alert-webhook <url>                  POST alert to webhook on findings
  --webhook-format <generic|slack|pagerduty|teams>  Webhook payload format
  --baseline <file>                      Suppress known-good signals from report
  --learn <file>                         Save all signals as baseline after run
  --config <path>                        Path to .bheeshmarc.json config file
  --help, -h                             Show this help message
  --version, -v                          Show version

Quick Start:
  npx bheeshma -- node app.js
  npx bheeshma install
  npx bheeshma learn baseline.json -- node app.js
  npx bheeshma --baseline baseline.json -- node app.js

CI/CD (GitHub Actions):
  - uses: bb1nfosec/bheeshma/.github/actions/bheeshma@main
    with:
      command: 'npm test'
      fail-level: 'critical'

<<<<<<< HEAD
Install Monitoring:
  npx bheeshma install                      # Watch npm install behavior
  npx bheeshma install -- --save-dev axios   # Monitor installing a specific package
  npx bheeshma install ci                   # Monitor npm ci (lockfile-strict)

Output Examples:
  bheeshma --format html --output report.html -- node app.js
  bheeshma --format json --output report.json -- node app.js
  bheeshma --format sarif --output results.sarif -- npm test

Security:
  BHEESHMA monitors runtime behavior of third-party npm dependencies.
  All data is local-only. No telemetry. No network communication.
  Zero dependencies. Zero configuration required.

For more information: https://github.com/bb1nfosec/bheeshma
=======
For more information: https://github.com/bbinfosec/bheeshma
>>>>>>> 1995263 (feat: v1.1.0 — vm/crypto hooks, baseline mode, lockfile integrity, diff/explain CLI)
`);
}

/**
 * Main CLI execution
 */
async function main() {
    const options = parseArgs();

    // Delegate to subcommands
    if (options.subcommand === 'install') {
        // Delegate to bheeshma-install.js
        const installCli = path.resolve(__dirname, 'bheeshma-install.js');
        const { spawn } = require('child_process');
        const child = spawn(process.execPath, [installCli, ...options.subArgs], {
            stdio: 'inherit'
        });
        child.on('exit', (code) => process.exit(code || 0));
        child.on('error', (err) => {
            console.error('Error running install mode:', err.message);
            process.exit(1);
        });
        return;
    }

    if (options.subcommand === 'ci') {
        const ciCli = path.resolve(__dirname, 'bheeshma-ci.js');
        const { spawn } = require('child_process');
        const child = spawn(process.execPath, [ciCli, ...options.subArgs], { stdio: 'inherit' });
        child.on('exit', (code) => process.exit(code || 0));
        child.on('error', (err) => { console.error('Error running CI mode:', err.message); process.exit(1); });
        return;
    }

    if (options.subcommand === 'diff') {
        const diffCli = path.resolve(__dirname, 'bheeshma-diff.js');
        const { spawn } = require('child_process');
        const child = spawn(process.execPath, [diffCli, ...options.subArgs], { stdio: 'inherit' });
        child.on('exit', (code) => process.exit(code || 0));
        child.on('error', (err) => { console.error('Error running diff mode:', err.message); process.exit(1); });
        return;
    }

    if (options.subcommand === 'lock') {
        const lockCli = path.resolve(__dirname, 'bheeshma-lock.js');
        const { spawn } = require('child_process');
        const child = spawn(process.execPath, [lockCli, ...options.subArgs], { stdio: 'inherit' });
        child.on('exit', (code) => process.exit(code || 0));
        child.on('error', (err) => { console.error('Error running lock mode:', err.message); process.exit(1); });
        return;
    }

    if (options.subcommand === 'explain') {
        const explainCli = path.resolve(__dirname, 'bheeshma-explain.js');
        const { spawn } = require('child_process');
        const child = spawn(process.execPath, [explainCli, ...options.subArgs], { stdio: 'inherit' });
        child.on('exit', (code) => process.exit(code || 0));
        child.on('error', (err) => { console.error('Error running explain mode:', err.message); process.exit(1); });
        return;
    }

    if (options.subcommand === 'learn') {
        // --learn mode: run with --learn <outputFile> injected as config
        const learnArgs = options.subArgs;
        let learnFile = '.bheeshma-baseline.json';
        const dashIdx = learnArgs.indexOf('--');
        const restArgs = dashIdx >= 0 ? learnArgs.slice(dashIdx + 1) : learnArgs;
        if (learnArgs[0] && !learnArgs[0].startsWith('--')) {
            learnFile = learnArgs[0];
        }
        // Rewrite as normal monitor with --learn option
        process.argv = [process.argv[0], process.argv[1], '--learn', learnFile, '--', ...restArgs];
        // Fall through to normal execution with learn mode handled below
    }

    // Validate options
    if (!options.scriptPath && options.scriptArgs.length === 0) {
        console.error('Error: No command specified to monitor.\n');
        printHelp();
        process.exit(1);
    }

    // Validate format
    const validFormats = ['cli', 'json', 'html', 'sarif'];
    if (!validFormats.includes(options.format)) {
        console.error(`Error: Invalid format "${options.format}". Use: ${validFormats.join(', ')}`);
        process.exit(1);
    }

    // Initialize BHEESHMA hooks
    console.error('[BHEESHMA] Initializing monitoring...');
    const initConfig = { configPath: options.configPath };
    if (options.baseline) initConfig.config = { baselineFile: options.baseline };
    if (options.webhookFormat) {
        initConfig.config = { ...(initConfig.config || {}), webhookFormat: options.webhookFormat };
    }
    const initResult = bheeshma.init(initConfig);

    if (!initResult.success) {
        console.error('[BHEESHMA] Warning: Some hooks failed to install');
        if (initResult.failed) {
            console.error('[BHEESHMA] Failed hooks:', initResult.failed.join(', '));
        }
    } else {
        console.error('[BHEESHMA] Hooks installed:', initResult.installed.join(', '));
    }

    // Expose signal store for ESM loader
    process.bheeshmaSignals = bheeshma.getSignals();
    process.bheeshmaConfig = bheeshma.getConfig();

    // Determine what to execute
    let scriptToRun;
    let scriptArgsDirect = [];

    if (options.scriptArgs.length > 0) {
        scriptToRun = options.scriptArgs[0];
        scriptArgsDirect = options.scriptArgs.slice(1);
    } else if (options.scriptPath) {
        scriptToRun = options.scriptPath;
    }

    // Set up exit handler to generate report
    let reportGenerated = false;

    const generateAndOutputReport = (exitCode) => {
        if (reportGenerated) return;
        reportGenerated = true;

        console.error('\n[BHEESHMA] Generating report...\n');

        const report = bheeshma.generateReport(options.format);

        if (options.output) {
            try {
                fs.writeFileSync(options.output, report, 'utf8');
                console.error(`[BHEESHMA] Report written to: ${options.output}`);
            } catch (err) {
                console.error(`[BHEESHMA] Error writing report: ${err.message}`);
                console.log(report);
            }
        } else if (options.format === 'html') {
            // HTML should always go to a file
            const htmlPath = 'bheeshma-report.html';
            try {
                fs.writeFileSync(htmlPath, report, 'utf8');
                console.error(`[BHEESHMA] HTML report written to: ${htmlPath}`);
            } catch (err) {
                console.error(`[BHEESHMA] Error writing HTML report: ${err.message}`);
            }
        } else if (options.format === 'sarif') {
            // SARIF should also default to file
            const sarifPath = 'bheeshma-results.sarif';
            try {
                fs.writeFileSync(sarifPath, report, 'utf8');
                console.error(`[BHEESHMA] SARIF report written to: ${sarifPath}`);
            } catch (err) {
                console.error(`[BHEESHMA] Error writing SARIF report: ${err.message}`);
                console.log(report);
            }
        } else {
            console.log(report);
        }

        // Learn mode: save baseline from observed signals
        if (options.learn) {
            try {
                const { captureBaseline } = require('../src/baseline/baselineManager');
                const result = captureBaseline(bheeshma.getSignals(), options.learn);
                console.error(`[BHEESHMA] Baseline saved: ${result.saved} behaviors → ${result.path}`);
            } catch (err) {
                console.error(`[BHEESHMA] Could not save baseline: ${err.message}`);
            }
        }

        // Enforcement mode: exit(1) if any package exceeds fail level
        if (options.enforce) {
            const enforcement = bheeshma.enforcePolicy({ failLevel: options.failLevel || 'critical' });
            if (!enforcement.passed) {
                console.error(`\n[BHEESHMA] ${enforcement.message}`);
                for (const pkg of enforcement.criticalPackages) {
                    console.error(`  - ${pkg.name}@${pkg.version}: score=${pkg.score}`);
                }

                // Send webhook alert if configured
                const config = bheeshma.getConfig();
                const webhookUrl = options.alertWebhook || (config && config.alertWebhook);
                if (webhookUrl) {
                    console.error(`[BHEESHMA] Sending alert webhook...`);
                    bheeshma.sendAlertWebhook(webhookUrl, enforcement.criticalPackages);
                }

                process.exit(1);
            } else {
                console.error('\n[BHEESHMA] Policy check passed. All packages within thresholds.');
            }
        }

        // Non-enforce mode: still check for webhook
        if (!options.enforce) {
            const config = bheeshma.getConfig();
            const webhookUrl = options.alertWebhook || (config && config.alertWebhook);
            if (webhookUrl) {
                const enforcement = bheeshma.enforcePolicy();
                if (!enforcement.passed) {
                    bheeshma.sendAlertWebhook(webhookUrl, enforcement.criticalPackages);
                }
            }
        }
    };

    // Register exit handlers
    process.on('exit', () => generateAndOutputReport(0));
    process.on('SIGINT', () => {
        generateAndOutputReport(130);
        process.exit(130);
    });
    process.on('SIGTERM', () => {
        generateAndOutputReport(143);
        process.exit(143);
    });

    // Execute the target script
    try {
        if (scriptToRun.endsWith('.js')) {
            const absolutePath = path.resolve(process.cwd(), scriptToRun);
            console.error(`[BHEESHMA] Executing: ${absolutePath}\n`);
            require(absolutePath);
        } else {
            // For non-JS files or commands like 'npm test', spawn as child process
            console.error(`[BHEESHMA] Executing: ${scriptToRun} ${scriptArgsDirect.join(' ')}\n`);

            const { spawn } = require('child_process');
            const child = spawn(scriptToRun, scriptArgsDirect, {
                stdio: 'inherit',
                env: {
                    ...process.env,
                    NODE_OPTIONS: [
                        process.env.NODE_OPTIONS || '',
                        '--require', path.resolve(__dirname, '../src/worker-bootstrap.js')
                    ].filter(Boolean).join(' ')
                }
            });

            child.on('exit', (code) => {
                generateAndOutputReport(code || 0);
                process.exit(code || 0);
            });

            child.on('error', (err) => {
                console.error(`[BHEESHMA] Error executing command: ${err.message}`);
                generateAndOutputReport(1);
                process.exit(1);
            });
        }
    } catch (err) {
        console.error(`[BHEESHMA] Error executing script: ${err.message}`);
        console.error(err.stack);
        generateAndOutputReport(1);
        process.exit(1);
    }
}

// Run CLI
main().catch(err => {
    console.error('[BHEESHMA] Fatal error:', err);
    process.exit(1);
});
