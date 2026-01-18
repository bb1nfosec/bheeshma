#!/usr/bin/env node

/**
 * BHEESHMA CLI Entry Point
 * 
 * Security: Minimal CLI wrapper with no external dependencies
 * 
 * Usage:
 *   bheeshma [options] -- <command>
 *   bheeshma --format json --output report.json -- node app.js
 * 
 * This CLI wrapper:
 * 1. Parses command-line arguments
 * 2. Initializes BHEESHMA hooks
 * 3. Executes target command/script
 * 4. Outputs report on exit
 */

'use strict';

const bheeshma = require('../src/index');
const fs = require('fs');
const path = require('path');

/**
 * Parse CLI arguments
 * 
 * Simple argument parser without external dependencies.
 * Security: No eval, no code execution from args
 * 
 * @returns {object} Parsed options
 */
function parseArgs() {
    const args = process.argv.slice(2);

    const options = {
        format: 'cli',
        output: null,
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
        } else if (arg === '--help' || arg === '-h') {
            printHelp();
            process.exit(0);
        } else if (arg === '--') {
            // Everything after -- is the command to run
            options.scriptArgs = args.slice(i + 1);
            break;
        } else {
            // Assume this is the script to run
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
  --format <cli|json>   Output format (default: cli)
  --output <file>       Write report to file instead of stdout
  -o <file>             Alias for --output
  --help, -h            Show this help message

Examples:
  bheeshma -- node app.js
  bheeshma --format json --output report.json -- node app.js
  bheeshma my-script.js

Security:
  BHEESHMA monitors runtime behavior of third-party npm dependencies.
  All data is local-only. No telemetry. No network communication.

For more information: https://github.com/yourusername/bheeshma
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

    // Initialize BHEESHMA hooks
    console.error('[BHEESHMA] Initializing monitoring...');
    const initResult = bheeshma.init();

    if (!initResult.success) {
        console.error('[BHEESHMA] Warning: Some hooks failed to install');
        if (initResult.failed) {
            console.error('[BHEESHMA] Failed hooks:', initResult.failed.join(', '));
        }
    } else {
        console.error('[BHEESHMA] Hooks installed:', initResult.installed.join(', '));
    }

    // Determine what to execute
    let scriptToRun;
    let scriptArgsDirect = [];

    if (options.scriptArgs.length > 0) {
        // Format: bheeshma -- node script.js args...
        // or: bheeshma -- npm test
        scriptToRun = options.scriptArgs[0];
        scriptArgsDirect = options.scriptArgs.slice(1);
    } else if (options.scriptPath) {
        // Format: bheeshma script.js
        scriptToRun = options.scriptPath;
    }

    // Set up exit handler to generate report
    let reportGenerated = false;

    const generateAndOutputReport = () => {
        if (reportGenerated) return;
        reportGenerated = true;

        console.error('\n[BHEESHMA] Generating report...\n');

        const report = bheeshma.generateReport(options.format);

        if (options.output) {
            // Write to file
            try {
                fs.writeFileSync(options.output, report, 'utf8');
                console.error(`[BHEESHMA] Report written to: ${options.output}`);
            } catch (err) {
                console.error(`[BHEESHMA] Error writing report: ${err.message}`);
                console.log(report);
            }
        } else {
            // Write to stdout
            console.log(report);
        }
    };

    // Register exit handlers
    process.on('exit', generateAndOutputReport);
    process.on('SIGINT', () => {
        generateAndOutputReport();
        process.exit(130);
    });
    process.on('SIGTERM', () => {
        generateAndOutputReport();
        process.exit(143);
    });

    // Execute the target script
    try {
        if (scriptToRun.endsWith('.js')) {
            // Require and execute a JavaScript file
            const absolutePath = path.resolve(process.cwd(), scriptToRun);

            console.error(`[BHEESHMA] Executing: ${absolutePath}\n`);

            // Security: Use require, not eval
            require(absolutePath);

            // Note: If the script doesn't exit on its own (e.g., server),
            // the process will keep running and report will be generated on Ctrl+C
        } else {
            // For non-JS files or commands like 'npm test', we would need child_process
            // For simplicity in V1, we only support .js files directly
            console.error(`[BHEESHMA] Error: Direct execution only supports .js files`);
            console.error(`[BHEESHMA] Use: bheeshma -- node ${scriptToRun}`);
            process.exit(1);
        }
    } catch (err) {
        console.error(`[BHEESHMA] Error executing script: ${err.message}`);
        console.error(err.stack);
        process.exit(1);
    }
}

// Run CLI
main().catch(err => {
    console.error('[BHEESHMA] Fatal error:', err);
    process.exit(1);
});
