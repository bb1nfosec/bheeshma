#!/usr/bin/env node

/**
 * bheeshma diff — compare two bheeshma JSON reports and show only new findings.
 *
 * Usage:
 *   bheeshma-diff <baseline.json> <current.json>
 *   bheeshma-diff --format sarif <baseline.sarif> <current.sarif>
 *   bheeshma-diff --output diff.json <baseline.json> <current.json>
 *
 * Exit codes:
 *   0 — no new findings
 *   1 — new findings detected
 *   2 — usage / parse error
 */

'use strict';

const fs = require('fs');
const path = require('path');

function printHelp() {
    console.log(`
bheeshma diff — compare two bheeshma JSON reports

Usage:
  bheeshma-diff [options] <baseline.json> <current.json>

Options:
  --format <json|cli>   Output format (default: cli)
  --output <file>       Write diff to file instead of stdout
  -o <file>             Alias for --output
  --help, -h            Show this help

Exit codes:
  0 — no new findings (safe)
  1 — new findings detected
  2 — usage or parse error
`);
}

function parseArgs() {
    const args = process.argv.slice(2);
    const opts = { format: 'cli', output: null, files: [] };
    let i = 0;
    while (i < args.length) {
        const arg = args[i];
        if (arg === '--format') { opts.format = args[++i]; i++; }
        else if (arg === '--output' || arg === '-o') { opts.output = args[++i]; i++; }
        else if (arg === '--help' || arg === '-h') { printHelp(); process.exit(0); }
        else { opts.files.push(arg); i++; }
    }
    return opts;
}

function loadJsonReport(filePath) {
    try {
        const raw = fs.readFileSync(path.resolve(filePath), 'utf8');
        return JSON.parse(raw);
    } catch (err) {
        console.error(`[bheeshma-diff] Cannot read ${filePath}: ${err.message}`);
        process.exit(2);
    }
}

/**
 * Extract a normalized package map from a bheeshma JSON report.
 * Returns Map<packageKey, { name, version, score, riskLevel, signalCount }>
 */
function extractPackageMap(report) {
    const map = new Map();

    // bheeshma JSON report structure: { packages: [...] } or { components: [...] }
    const packages = report.packages || report.components || [];
    for (const pkg of packages) {
        const name    = pkg.name || pkg.packageName || '';
        const version = pkg.version || 'unknown';
        const score   = pkg.trustScore !== undefined ? pkg.trustScore
                      : pkg.score !== undefined      ? pkg.score
                      : 100;
        const riskLevel    = pkg.riskLevel    || 'LOW';
        const signalCount  = pkg.signalCount  || 0;
        const key = `${name}@${version}`;
        map.set(key, { name, version, score, riskLevel, signalCount });
    }
    return map;
}

/**
 * Compare baseline and current package maps.
 * Returns { newPackages, regressions, resolved }
 */
function diffReports(baselineMap, currentMap) {
    const newPackages   = [];
    const regressions   = [];
    const resolved      = [];

    for (const [key, curr] of currentMap.entries()) {
        if (!baselineMap.has(key)) {
            newPackages.push(curr);
        } else {
            const base = baselineMap.get(key);
            if (curr.score < base.score) {
                regressions.push({ ...curr, baseScore: base.score, delta: curr.score - base.score });
            }
        }
    }

    for (const [key, base] of baselineMap.entries()) {
        if (!currentMap.has(key) && base.riskLevel !== 'LOW') {
            resolved.push(base);
        }
    }

    return { newPackages, regressions, resolved };
}

function formatCli(diff, baseline, current) {
    const lines = [];
    const ts = new Date().toISOString();
    lines.push(`\nbheeshma diff — ${ts}`);
    lines.push(`Baseline: ${baseline} | Current: ${current}\n`);

    if (diff.newPackages.length === 0 && diff.regressions.length === 0) {
        lines.push('✓ No new findings. All packages within baseline.');
    } else {
        if (diff.newPackages.length > 0) {
            lines.push(`NEW PACKAGES (${diff.newPackages.length}):`);
            for (const p of diff.newPackages) {
                lines.push(`  + ${p.name}@${p.version}  score=${p.score}  [${p.riskLevel}]  signals=${p.signalCount}`);
            }
        }
        if (diff.regressions.length > 0) {
            lines.push(`\nREGRESSIONS — score dropped (${diff.regressions.length}):`);
            for (const p of diff.regressions) {
                lines.push(`  ↓ ${p.name}@${p.version}  score=${p.score} (was ${p.baseScore}, Δ=${p.delta})  [${p.riskLevel}]`);
            }
        }
    }

    if (diff.resolved.length > 0) {
        lines.push(`\nRESOLVED — no longer flagged (${diff.resolved.length}):`);
        for (const p of diff.resolved) {
            lines.push(`  ✓ ${p.name}@${p.version}  (was ${p.riskLevel})`);
        }
    }

    lines.push('');
    return lines.join('\n');
}

function main() {
    const opts = parseArgs();

    if (opts.files.length < 2) {
        console.error('[bheeshma-diff] Error: provide two report files to compare.\n');
        printHelp();
        process.exit(2);
    }

    const [baselineFile, currentFile] = opts.files;
    const baselineReport = loadJsonReport(baselineFile);
    const currentReport  = loadJsonReport(currentFile);

    const baselineMap = extractPackageMap(baselineReport);
    const currentMap  = extractPackageMap(currentReport);
    const diff        = diffReports(baselineMap, currentMap);

    let output;
    if (opts.format === 'json') {
        output = JSON.stringify({
            baseline: baselineFile,
            current:  currentFile,
            timestamp: new Date().toISOString(),
            newPackages:  diff.newPackages,
            regressions:  diff.regressions,
            resolved:     diff.resolved,
            hasNewFindings: diff.newPackages.length > 0 || diff.regressions.length > 0
        }, null, 2);
    } else {
        output = formatCli(diff, baselineFile, currentFile);
    }

    if (opts.output) {
        try {
            fs.writeFileSync(opts.output, output, 'utf8');
            console.error(`[bheeshma-diff] Diff written to: ${opts.output}`);
        } catch (err) {
            console.error(`[bheeshma-diff] Could not write output: ${err.message}`);
            console.log(output);
        }
    } else {
        console.log(output);
    }

    const hasNewFindings = diff.newPackages.length > 0 || diff.regressions.length > 0;
    process.exit(hasNewFindings ? 1 : 0);
}

main();
