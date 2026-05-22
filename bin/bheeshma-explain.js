#!/usr/bin/env node

/**
 * bheeshma explain — human-readable package explanation from a bheeshma JSON report.
 *
 * Usage:
 *   bheeshma-explain report.json
 *   bheeshma-explain report.json --package lodash
 *   bheeshma-explain report.json --min-risk HIGH
 *
 * Produces plain-English summaries of what each flagged package did at runtime,
 * why it's suspicious, and a recommended remediation step.
 *
 * Exit codes:
 *   0 — no suspicious packages (or all within min-risk threshold)
 *   1 — suspicious packages found
 *   2 — usage / parse error
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const RISK_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0 };

function printHelp() {
    console.log(`
bheeshma explain — plain-English explanation of a bheeshma JSON report

Usage:
  bheeshma-explain [options] <report.json>

Options:
  --package <name>             Explain a specific package only
  --min-risk <CRITICAL|HIGH|MEDIUM|LOW>   Only show packages at or above this risk (default: LOW)
  --help, -h                   Show this help

Exit codes:
  0 — no packages above threshold
  1 — findings above threshold
  2 — usage error
`);
}

function parseArgs() {
    const args = process.argv.slice(2);
    const opts = { file: null, pkg: null, minRisk: 'LOW' };
    let i = 0;
    while (i < args.length) {
        const arg = args[i];
        if (arg === '--package')  { opts.pkg     = args[++i]; i++; }
        else if (arg === '--min-risk') { opts.minRisk = (args[++i] || 'LOW').toUpperCase(); i++; }
        else if (arg === '--help' || arg === '-h') { printHelp(); process.exit(0); }
        else if (!opts.file) { opts.file = arg; i++; }
        else i++;
    }
    return opts;
}

function loadReport(filePath) {
    try {
        const raw = fs.readFileSync(path.resolve(filePath), 'utf8');
        return JSON.parse(raw);
    } catch (err) {
        console.error(`[bheeshma-explain] Cannot read ${filePath}: ${err.message}`);
        process.exit(2);
    }
}

/** Map a signal type to a plain-English verb phrase */
function signalDescription(type, count) {
    const countLabel = count > 1 ? ` (×${count})` : '';
    switch (type) {
        case 'ENV_ACCESS':          return `accessed environment variables${countLabel}`;
        case 'FS_READ':             return `read files from disk${countLabel}`;
        case 'FS_WRITE':            return `wrote to the filesystem${countLabel}`;
        case 'SHELL_EXEC':          return `executed shell commands${countLabel}`;
        case 'NET_CONNECT':         return `opened raw TCP connections${countLabel}`;
        case 'HTTP_REQUEST':        return `made HTTP requests${countLabel}`;
        case 'HTTPS_REQUEST':       return `made HTTPS requests${countLabel}`;
        case 'DNS_QUERY':           return `performed DNS lookups${countLabel}`;
        case 'OBFUSCATION_DETECTED':return `contains obfuscated source code${countLabel}`;
        case 'BLACKLISTED_PACKAGE': return `is on your blacklist — treat as untrusted`;
        case 'VM_EXEC':             return `executed code via the vm module${countLabel}`;
        case 'CRYPTO_OP':           return `used cryptographic operations${countLabel}`;
        case 'HOOK_TAMPER':         return `attempted to remove bheeshma's monitoring hooks${countLabel}`;
        case 'PROTO_POLLUTION':     return `contains prototype pollution patterns${countLabel}`;
        default:                    return `emitted a ${type} signal${countLabel}`;
    }
}

/** Suggest a remediation step based on risk level and signal types */
function remediation(riskLevel, signalTypes, name) {
    if (riskLevel === 'CRITICAL') {
        if (signalTypes.includes('HOOK_TAMPER')) {
            return `URGENT: This package actively fights monitoring. Remove it immediately and audit your dependency tree.`;
        }
        if (signalTypes.includes('BLACKLISTED_PACKAGE')) {
            return `Remove ${name} from your dependencies. It is on your blacklist.`;
        }
        if (signalTypes.includes('SHELL_EXEC')) {
            return `Treat as malicious. File a report at https://github.com/bbinfosec/bheeshma/issues and remove this package.`;
        }
        return `Score is critically low. Audit the package source before using in production.`;
    }
    if (riskLevel === 'HIGH') {
        if (signalTypes.includes('OBFUSCATION_DETECTED')) {
            return `Review the package source manually — obfuscated code is unusual in legitimate packages.`;
        }
        return `Investigate why this package needs these permissions. Consider a safer alternative.`;
    }
    if (riskLevel === 'MEDIUM') {
        return `Verify the behavior is expected for this package's stated purpose.`;
    }
    return `Behavior is low risk. Review if it doesn't match what you'd expect this package to do.`;
}

function explainPackage(pkg) {
    const lines = [];
    const riskEmoji = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' }[pkg.riskLevel] || '⚪';

    lines.push(`${riskEmoji} ${pkg.name}@${pkg.version}  [${pkg.riskLevel}]  Trust score: ${pkg.score}/100`);

    if (pkg.signals && pkg.signals.length > 0) {
        // Aggregate by signal type
        const byType = {};
        for (const sig of pkg.signals) {
            byType[sig.type] = (byType[sig.type] || 0) + 1;
        }
        lines.push(`  Behaviors observed:`);
        for (const [type, count] of Object.entries(byType)) {
            lines.push(`    • ${signalDescription(type, count)}`);
        }
    } else if (pkg.signalCount > 0) {
        lines.push(`  Emitted ${pkg.signalCount} signal(s).`);
    }

    const signalTypes = pkg.signals
        ? [...new Set(pkg.signals.map(s => s.type))]
        : [];
    lines.push(`  Recommendation: ${remediation(pkg.riskLevel, signalTypes, pkg.name)}`);
    lines.push('');

    return lines.join('\n');
}

function main() {
    const opts = parseArgs();

    if (!opts.file) {
        console.error('[bheeshma-explain] Provide a report file.\n');
        printHelp();
        process.exit(2);
    }

    const report = loadReport(opts.file);
    const packages = report.packages || report.components || [];

    if (packages.length === 0) {
        console.log('[bheeshma-explain] No packages in report.');
        process.exit(0);
    }

    const minRiskNum = RISK_ORDER[opts.minRisk] || 0;

    let filtered = packages.filter(p => {
        const riskNum = RISK_ORDER[(p.riskLevel || 'LOW').toUpperCase()] || 0;
        return riskNum >= minRiskNum;
    });

    if (opts.pkg) {
        filtered = filtered.filter(p => p.name === opts.pkg || `${p.name}@${p.version}` === opts.pkg);
    }

    if (filtered.length === 0) {
        console.log(`[bheeshma-explain] No packages at or above ${opts.minRisk} risk.`);
        process.exit(0);
    }

    // Sort by score ascending (most risky first)
    filtered.sort((a, b) => (a.score || 100) - (b.score || 100));

    console.log(`\nbheeshma explain — ${opts.file}\n`);
    console.log(`Showing ${filtered.length} package(s) at or above ${opts.minRisk} risk:\n`);

    for (const pkg of filtered) {
        console.log(explainPackage(pkg));
    }

    const hasHighRisk = filtered.some(p =>
        (RISK_ORDER[(p.riskLevel || 'LOW').toUpperCase()] || 0) >= RISK_ORDER.HIGH
    );

    process.exit(hasHighRisk ? 1 : 0);
}

main();
