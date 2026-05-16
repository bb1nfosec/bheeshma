/**
 * BHEESHMA SARIF Output Formatter
 *
 * Generates SARIF v2.1.0 output for GitHub Code Scanning integration.
 * https://docs.github.com/en/code-security/sarif-support
 *
 * Each bheeshma signal becomes a SARIF "result" with:
 * - ruleId: signal type (e.g., SHELL_EXEC, HTTP_REQUEST)
 * - level: error/warning/note based on risk severity
 * - message: human-readable description with package attribution
 * - locations: the package entry point or npm module path
 * - properties: package name, version, trust score, signal metadata
 *
 * Security: Metadata-only output. No secrets, no file contents.
 */

'use strict';

const { getRiskLevel } = require('../scoring/trustScore');

/**
 * SARIF rule definitions — one per signal type.
 * GitHub Code Scanning uses these to group and display findings.
 */
const SARIF_RULES = [
    {
        id: 'SHELL_EXEC',
        shortDescription: { text: 'Shell command execution by third-party package' },
        fullDescription: { text: 'A third-party npm package spawned a shell command or child process. This is the highest-risk behavior — supply chain attacks commonly use shell execution to install backdoors, steal credentials, or deploy miners.' },
        helpUri: 'https://github.com/bbinfosec/bheeshma#signal-types'
    },
    {
        id: 'OBFUSCATION_DETECTED',
        shortDescription: { text: 'Code obfuscation detected in third-party package' },
        fullDescription: { text: 'A third-party npm package contains obfuscated code (eval, Function constructor, hex/Base64 encoding, string concatenation). Obfuscation is a strong indicator of malicious intent — legitimate packages rarely need to hide their logic.' },
        helpUri: 'https://github.com/bbinfosec/bheeshma#signal-types'
    },
    {
        id: 'BLACKLISTED_PACKAGE',
        shortDescription: { text: 'Package is on the deny list' },
        fullDescription: { text: 'A third-party npm package is explicitly blacklisted in your bheeshma configuration. This package is known to be malicious or unwanted.' },
        helpUri: 'https://github.com/bbinfosec/bheeshma#configuration'
    },
    {
        id: 'FS_WRITE',
        shortDescription: { text: 'File system write by third-party package' },
        fullDescription: { text: 'A third-party npm package wrote to the file system. Malicious packages use file writes to install backdoors (e.g., ~/.ssh/authorized_keys), modify scripts, or deploy payloads.' },
        helpUri: 'https://github.com/bbinfosec/bheeshma#signal-types'
    },
    {
        id: 'HTTP_REQUEST',
        shortDescription: { text: 'Outbound HTTP request by third-party package' },
        fullDescription: { text: 'A third-party npm package made an outbound HTTP (non-TLS) request. Unencrypted HTTP requests can leak data and are commonly used for data exfiltration.' },
        helpUri: 'https://github.com/bbinfosec/bheeshma#signal-types'
    },
    {
        id: 'HTTPS_REQUEST',
        shortDescription: { text: 'Outbound HTTPS request by third-party package' },
        fullDescription: { text: 'A third-party npm package made an outbound HTTPS request. While encrypted, the destination host may still be a data exfiltration endpoint.' },
        helpUri: 'https://github.com/bbinfosec/bheeshma#signal-types'
    },
    {
        id: 'NET_CONNECT',
        shortDescription: { text: 'Raw TCP connection by third-party package' },
        fullDescription: { text: 'A third-party npm package opened a raw TCP connection. This is often used for reverse shells, C2 communication, or data exfiltration.' },
        helpUri: 'https://github.com/bbinfosec/bheeshma#signal-types'
    },
    {
        id: 'ENV_ACCESS',
        shortDescription: { text: 'Environment variable access by third-party package' },
        fullDescription: { text: 'A third-party npm package accessed an environment variable. This is benign for config loaders (dotenv) but suspicious for packages that should not need env access — e.g., a string utility reading AWS_SECRET_ACCESS_KEY.' },
        helpUri: 'https://github.com/bbinfosec/bheeshma#signal-types'
    },
    {
        id: 'FS_READ',
        shortDescription: { text: 'File system read by third-party package' },
        fullDescription: { text: 'A third-party npm package read a file from the file system. Malicious packages commonly read ~/.npmrc, ~/.ssh/, .env, and credential files for exfiltration.' },
        helpUri: 'https://github.com/bbinfosec/bheeshma#signal-types'
    },
    {
        id: 'DNS_QUERY',
        shortDescription: { text: 'DNS query by third-party package' },
        fullDescription: { text: 'A third-party npm package performed a DNS lookup. DNS tunneling is a data exfiltration technique that encodes stolen data in DNS queries to bypass firewalls.' },
        helpUri: 'https://github.com/bbinfosec/bheeshma#signal-types'
    }
];

/**
 * Map bheeshma risk levels to SARIF severity levels.
 * CRITICAL/HIGH → error, MEDIUM → warning, LOW → note
 */
function riskLevelToSarifLevel(riskLevel) {
    switch (riskLevel) {
        case 'CRITICAL':
        case 'HIGH':
            return 'error';
        case 'MEDIUM':
            return 'warning';
        case 'LOW':
            return 'note';
        default:
            return 'none';
    }
}

/**
 * Build a human-readable message for a signal.
 *
 * @param {object} signal - Bheeshma signal
 * @param {string} riskLevel - Package risk level
 * @returns {string} Human-readable message
 */
function buildSignalMessage(signal, riskLevel) {
    const pkg = signal.package || 'unknown';
    const ver = signal.version || '?';
    const prefix = `**[${pkg}@${ver}]** (${riskLevel})`;

    switch (signal.type) {
        case 'SHELL_EXEC':
            return `${prefix}: Shell execution detected — \`${truncate(signal.metadata.command, 200)}\``;
        case 'OBFUSCATION_DETECTED': {
            const indicators = (signal.metadata.indicators || []);
            return `${prefix}: Obfuscated code detected — ${indicators.join(', ')}`;
        }
        case 'BLACKLISTED_PACKAGE':
            return `${prefix}: Package is explicitly blacklisted — ${signal.metadata.reason || 'known malicious'}`;
        case 'FS_WRITE':
            return `${prefix}: File write detected — \`${sanitizePath(signal.metadata.path)}\``;
        case 'FS_READ':
            return `${prefix}: File read detected — \`${sanitizePath(signal.metadata.path)}\``;
        case 'HTTP_REQUEST':
            return `${prefix}: HTTP request to \`${signal.metadata.host || signal.metadata.url}\` (${signal.metadata.method})`;
        case 'HTTPS_REQUEST':
            return `${prefix}: HTTPS request to \`${signal.metadata.host || signal.metadata.url}\` (${signal.metadata.method})`;
        case 'NET_CONNECT':
            return `${prefix}: TCP connection to \`${signal.metadata.host}:${signal.metadata.port}\``;
        case 'ENV_ACCESS':
            return `${prefix}: Environment variable access — \`${signal.metadata.variable}\``;
        case 'DNS_QUERY':
            return `${prefix}: DNS query for \`${signal.metadata.hostname}\``;
        default:
            return `${prefix}: ${signal.type}`;
    }
}

/**
 * Truncate a string for display.
 */
function truncate(str, max) {
    if (!str) return '(unknown)';
    return str.length > max ? str.substring(0, max) + '...' : str;
}

/**
 * Sanitize file paths — mask home directory paths.
 */
function sanitizePath(p) {
    if (!p) return '(unknown)';
    // Mask sensitive home dir paths but keep package paths visible
    return p
        .replace(/\/home\/[^/]+/g, '~')
        .replace(/\/Users\/[^/]+/g, '~');
}

/**
 * Extract file location from a signal's stack trace.
 * Returns the npm package entry point for SARIF location.
 */
function extractLocation(signal) {
    if (!signal.stackTrace) {
        return null;
    }

    // Look for a node_modules path in the stack trace
    const lines = signal.stackTrace.split('\n');
    for (const line of lines) {
        // Match patterns like: at something (/path/to/node_modules/pkg/index.js:10:5)
        const match = line.match(/\((.+\/node_modules\/[^:)]+)/);
        if (match) {
            return match[1];
        }
        // Match patterns like: at /path/to/node_modules/pkg/index.js:10:5
        const match2 = line.match(/at\s+([^\s]+\/node_modules\/[^:)]+)/);
        if (match2) {
            return match2[1];
        }
    }

    return null;
}

/**
 * Build deduplication key for grouping similar signals into one SARIF result.
 * Collapses repeated identical behaviors into a single finding with a count.
 */
function buildResultFingerprint(signal) {
    const pkg = signal.package || 'unknown';
    const type = signal.type;

    let dest = '';
    switch (signal.type) {
        case 'SHELL_EXEC':
            dest = (signal.metadata.command || '').split(/\s+/).slice(0, 3).join(' ');
            break;
        case 'FS_READ':
        case 'FS_WRITE':
            dest = signal.metadata.path || '';
            break;
        case 'HTTP_REQUEST':
        case 'HTTPS_REQUEST':
            dest = `${signal.metadata.host || ''}:${signal.metadata.method || ''}`;
            break;
        case 'NET_CONNECT':
            dest = `${signal.metadata.host}:${signal.metadata.port}`;
            break;
        case 'ENV_ACCESS':
            dest = signal.metadata.variable || '';
            break;
        case 'DNS_QUERY':
            dest = signal.metadata.hostname || '';
            break;
        default:
            dest = '';
    }

    return `${pkg}:${type}:${dest}`;
}

/**
 * Format a complete SARIF report.
 *
 * @param {Map} scores - Trust scores by package (from trustScore.calculateAllScores)
 * @param {Array} allSignals - All captured signals
 * @param {object} patternResults - Pattern analysis results (from patternMatcher)
 * @param {object} options - { toolVersion: string, repoUri: string }
 * @returns {string} SARIF JSON string
 */
function formatReport(scores, allSignals, patternResults, options = {}) {
    const toolVersion = options.toolVersion || '1.0.0';
    const repoUri = options.repoUri || 'https://github.com/bbinfosec/bheeshma';

    // Deduplicate signals for cleaner SARIF output
    const fingerprintMap = new Map();
    for (const signal of allSignals) {
        if (!signal.package) continue; // Skip first-party signals

        const fp = buildResultFingerprint(signal);
        if (fingerprintMap.has(fp)) {
            const entry = fingerprintMap.get(fp);
            entry.count++;
            // Keep the signal with richest metadata
            if (Object.keys(signal.metadata).length > Object.keys(entry.signal.metadata).length) {
                entry.signal = signal;
            }
        } else {
            fingerprintMap.set(fp, { signal, count: 1 });
        }
    }

    // Build SARIF results
    const results = [];
    for (const [, entry] of fingerprintMap) {
        const signal = entry.signal;

        // Look up the package's trust score and risk level
        const pkgKey = `${signal.package}@${signal.version}`;
        const pkgScore = scores.get(pkgKey);
        const riskLevel = pkgScore ? pkgScore.riskLevel : getRiskLevel(100);
        const trustScore = pkgScore ? pkgScore.score : 100;

        // Skip LOW-risk signals in CI mode for noise reduction
        // (Users can configure this via sarifLevel config)
        if (riskLevel === 'LOW' && options.skipLow !== false) {
            continue;
        }

        const sarifLevel = riskLevelToSarifLevel(riskLevel);
        const location = extractLocation(signal);
        const message = buildSignalMessage(signal, riskLevel);

        const result = {
            ruleId: signal.type,
            level: sarifLevel,
            message: { text: message },
            properties: {
                'bheeshma.package': signal.package,
                'bheeshma.version': signal.version,
                'bheeshma.trustScore': trustScore,
                'bheeshma.riskLevel': riskLevel,
                'bheeshma.occurrences': entry.count
            }
        };

        // Add location if we can extract one
        if (location) {
            result.locations = [{
                physicalLocation: {
                    artifactLocation: {
                        uri: sanitizePath(location)
                    }
                }
            }];
        }

        results.push(result);
    }

    // Add pattern analysis findings as additional results
    if (patternResults && patternResults.summary && patternResults.summary.totalThreats > 0) {
        const threatCategories = [
            { key: 'cryptoMining', ruleId: 'PATTERN_CRYPTO_MINING', level: 'error' },
            { key: 'dataExfiltration', ruleId: 'PATTERN_DATA_EXFILTRATION', level: 'error' },
            { key: 'backdoors', ruleId: 'PATTERN_BACKDOOR', level: 'error' },
            { key: 'credentialTheft', ruleId: 'PATTERN_CREDENTIAL_THEFT', level: 'warning' },
            { key: 'typosquats', ruleId: 'PATTERN_TYPOSQUAT', level: 'warning' }
        ];

        for (const cat of threatCategories) {
            const findings = patternResults[cat.key];
            if (!findings || findings.length === 0) continue;

            for (const finding of findings) {
                results.push({
                    ruleId: cat.ruleId,
                    level: cat.level,
                    message: {
                        text: `**[${finding.package}]** ${cat.ruleId}: ${finding.indicator}`
                    },
                    properties: {
                        'bheeshma.package': finding.package,
                        'bheeshma.patternSeverity': finding.severity,
                        'bheeshma.patternType': finding.type
                    }
                });
            }
        }
    }

    // Build the SARIF document
    const sarif = {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [{
            tool: {
                driver: {
                    name: 'bheeshma',
                    version: toolVersion,
                    informationUri: repoUri,
                    rules: SARIF_RULES
                }
            },
            results: results
        }]
    };

    // Add invocation info for CI debugging
    sarif.runs[0].invocations = [{
        executionSuccessful: true,
        startTimeUtc: new Date().toISOString()
    }];

    // Add summary counts in run properties
    if (scores && scores.size > 0) {
        const riskDist = { critical: 0, high: 0, medium: 0, low: 0 };
        for (const [, data] of scores) {
            const r = (data.riskLevel || 'LOW').toLowerCase();
            if (riskDist[r] !== undefined) riskDist[r]++;
        }
        sarif.runs[0].properties = {
            'bheeshma.totalPackages': scores.size,
            'bheeshma.totalResults': results.length,
            'bheeshma.riskDistribution': riskDist
        };
    }

    return JSON.stringify(sarif, null, 2);
}

module.exports = { formatReport };
