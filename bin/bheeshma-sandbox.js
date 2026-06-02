#!/usr/bin/env node

/**
 * BHEESHMA Sandbox — out-of-process monitoring (experimental)
 *
 * Runs a command under kernel-level syscall observation (strace / ptrace),
 * which — unlike the in-process engine — cannot be evaded or disabled by the
 * monitored code and sees native subprocesses (e.g. `curl`) and any language.
 * Signals are scored and enforced exactly like the rest of BHEESHMA.
 *
 * Usage:
 *   bheeshma-sandbox [--enforce] [--fail-level high] [--format json] -- <command>
 *   bheeshma-sandbox --block-network -- npm install   (prevent egress via bwrap)
 *
 * Requires Linux + strace. With --block-network it also requires bwrap
 * (bubblewrap); egress is then denied, turning detection into prevention.
 */

'use strict';

const path = require('path');
const fs = require('fs');
const straceRunner = require('../src/sandbox/straceRunner');
const { analyzePatterns } = require('../src/patterns/patternMatcher');
const { calculateAllScores, findViolatingPackages } = require('../src/scoring/trustScore');
const { getDefaultConfig } = require('../src/config/configLoader');
const cliFormatter = require('../src/output/cliFormatter');
const jsonFormatter = require('../src/output/jsonFormatter');

function parseArgs(argv) {
    const o = { enforce: false, failLevel: 'critical', format: 'cli', output: null, blockNetwork: false, command: null, commandArgs: [] };
    let i = 0;
    while (i < argv.length) {
        const a = argv[i];
        if (a === '--enforce') { o.enforce = true; i++; }
        else if (a === '--fail-level') { o.failLevel = argv[++i]; i++; }
        else if (a === '--format') { o.format = argv[++i]; i++; }
        else if (a === '--output' || a === '-o') { o.output = argv[++i]; i++; }
        else if (a === '--block-network') { o.blockNetwork = true; i++; }
        else if (a === '--') { o.command = argv[i + 1]; o.commandArgs = argv.slice(i + 2); break; }
        else { o.command = a; o.commandArgs = argv.slice(i + 1); break; }
    }
    return o;
}

function log(msg) { process.stderr.write(`[bheeshma-sandbox] ${msg}\n`); }

async function main() {
    const opts = parseArgs(process.argv.slice(2));
    if (!opts.command) {
        log('No command specified. Usage: bheeshma-sandbox [options] -- <command>');
        process.exit(2);
    }

    let command = opts.command;
    let args = opts.commandArgs;
    if (opts.blockNetwork) {
        // Wrap the command so it runs with no network namespace — egress is
        // denied at the kernel, not merely observed. strace still follows it.
        args = ['--unshare-net', '--dev-bind', '/', '/', command, ...args];
        command = 'bwrap';
        log('network egress will be BLOCKED (bwrap --unshare-net)');
    }

    log(`observing (out-of-process / strace): ${opts.command} ${opts.commandArgs.join(' ')}`);
    const result = await straceRunner.run(command, args, {});

    if (!result.straceAvailable) {
        log('ERROR: strace is required for sandbox mode and was not available.');
        process.exit(1);
    }

    const config = getDefaultConfig();
    const patternResults = analyzePatterns(result.signals, config.patterns);
    const scores = calculateAllScores(result.signals, { patternResults });

    let report;
    if (opts.format === 'json') {
        report = jsonFormatter.formatReport(scores, result.signals, patternResults);
    } else {
        report = cliFormatter.formatReport(scores, result.signals, patternResults);
    }

    if (opts.output) {
        fs.writeFileSync(opts.output, report, 'utf8');
        log(`report written to ${opts.output}`);
    } else if (opts.format === 'json') {
        process.stdout.write(report + '\n');
    } else {
        process.stderr.write('\n' + report + '\n');
    }

    log(`captured ${result.signals.length} syscall-derived signal(s) across ${scores.size} package(s)`);

    if (opts.enforce) {
        const violating = findViolatingPackages(scores, opts.failLevel);
        if (violating.length > 0) {
            for (const p of violating) log(`POLICY VIOLATION: ${p.name} score=${p.score} (${p.riskLevel})`);
            process.exit(1);
        }
        log(`policy check passed (fail-level: ${opts.failLevel})`);
    }

    process.exit(result.exitCode || 0);
}

main().catch((err) => { log(`fatal: ${err.message}`); process.exit(1); });
