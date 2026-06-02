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
    return null;
}

/**
 * Parse CLI arguments
 */
function parseArgs() {
    const args = process.argv.slice(2);

    // Check for subcommands first
    const sub = detectSubcommand(args);
    if (sub === 'install') {
        return { subcommand: 'install', subArgs: args.slice(1) };
    }
    if (sub === 'ci') {
        return { subcommand: 'ci', subArgs: args.slice(1) };
    }

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

        if (arg === '--format') {
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

Modes:
  (default)     Monitor any Node.js command or script
  install       Monitor npm install for malicious postinstall behavior
  ci            CI/CD-optimized mode with SARIF + exit codes

Options:
  --format <cli|json|html|sarif>  Output format (default: cli)
  --output <file>                 Write report to file instead of stdout
  -o <file>                       Alias for --output
  --enforce                       Exit code 1 if any package is CRITICAL
  --alert-webhook <url>           POST alert to webhook on CRITICAL findings
  --config <path>                 Path to .bheeshmarc.json config file
  --help, -h                      Show this help message
  --version, -v                   Show version

Quick Start (30 seconds):
  npx bheeshma -- node app.js
  npx bheeshma install
  npx bheeshma --format sarif --output results.sarif -- npm test

CI/CD (GitHub Actions):
  - uses: bb1nfosec/bheeshma/.github/actions/bheeshma@main
    with:
      command: 'npm test'
      fail-level: 'critical'

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
        // Delegate to bheeshma-ci.js
        const ciCli = path.resolve(__dirname, 'bheeshma-ci.js');
        const { spawn } = require('child_process');
        const child = spawn(process.execPath, [ciCli, ...options.subArgs], {
            stdio: 'inherit'
        });
        child.on('exit', (code) => process.exit(code || 0));
        child.on('error', (err) => {
            console.error('Error running CI mode:', err.message);
            process.exit(1);
        });
        return;
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
    const initResult = bheeshma.init({
        configPath: options.configPath
    });

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

        // Enforcement mode: exit(1) if any package is CRITICAL
        if (options.enforce) {
            const enforcement = bheeshma.enforcePolicy();
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
            // For non-JS files or commands like 'npm test', spawn as child
            // process. The command runs in the child, so monitoring must happen
            // there: preload ci-preload.js (inherited across the node tree) and
            // ingest the signals each process writes to BHEESHMA_SIGNAL_DIR.
            console.error(`[BHEESHMA] Executing: ${scriptToRun} ${scriptArgsDirect.join(' ')}\n`);

            const os = require('os');
            const signalDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bheeshma-'));

            const ingestFromDir = () => {
                try {
                    for (const file of fs.readdirSync(signalDir)) {
                        if (!file.endsWith('.json')) continue;
                        try {
                            const arr = JSON.parse(fs.readFileSync(path.join(signalDir, file), 'utf8'));
                            bheeshma.ingestSignals(arr);
                        } catch (e) { /* skip */ }
                    }
                } catch (e) { /* ignore */ }
                finally {
                    try { fs.rmSync(signalDir, { recursive: true, force: true }); } catch (e) { /* ignore */ }
                }
            };

            const { spawn } = require('child_process');
            const child = spawn(scriptToRun, scriptArgsDirect, {
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

            child.on('exit', (code) => {
                ingestFromDir();
                generateAndOutputReport(code || 0);
                process.exit(code || 0);
            });

            child.on('error', (err) => {
                console.error(`[BHEESHMA] Error executing command: ${err.message}`);
                ingestFromDir();
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
