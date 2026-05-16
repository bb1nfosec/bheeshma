#!/usr/bin/env node

/**
 * BHEESHMA CLI Entry Point
 * 
 * Usage:
 *   bheeshma [options] -- <command>
 *   bheeshma --format json --output report.json -- node app.js
 *   bheeshma --enforce -- node app.js          (CI mode - exit 1 on CRITICAL)
 *   bheeshma --alert-webhook <url> -- node app.js
 *   bheeshma --format html --output report.html -- node app.js
 */

'use strict';

const bheeshma = require('../src/index');
const fs = require('fs');
const path = require('path');

/**
 * Parse CLI arguments
 */
function parseArgs() {
    const args = process.argv.slice(2);

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

Usage:
  bheeshma [options] -- <command>
  bheeshma [options] <script.js>

Options:
  --format <cli|json|html>   Output format (default: cli)
  --output <file>            Write report to file instead of stdout
  -o <file>                  Alias for --output
  --enforce                  Exit with code 1 if any package is CRITICAL (CI mode)
  --alert-webhook <url>      POST alert to webhook URL on CRITICAL findings
  --config <path>            Path to .bheeshmarc.json config file
  --help, -h                 Show this help message

Enforcement Examples (CI/CD):
  bheeshma --enforce -- node app.js
  bheeshma --enforce --format json --output report.json -- npm test

Output Examples:
  bheeshma --format html --output report.html -- node app.js
  bheeshma --format json --output report.json -- node app.js

Advanced:
  bheeshma --enforce --alert-webhook https://hooks.slack.com/xxx -- node app.js
  bheeshma --config .bheeshmarc.json -- node app.js

Security:
  BHEESHMA monitors runtime behavior of third-party npm dependencies.
  All data is local-only. No telemetry. No network communication.

For more information: https://github.com/bbinfosec/bheeshma
`);
}

/**
 * Main CLI execution
 */
async function main() {
    const options = parseArgs();

    // Validate options
    if (!options.scriptPath && options.scriptArgs.length === 0) {
        console.error('Error: No script specified to monitor.\n');
        printHelp();
        process.exit(1);
    }

    // Validate format
    const validFormats = ['cli', 'json', 'html'];
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
