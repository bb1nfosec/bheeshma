/**
 * BHEESHMA Pattern Matcher
 * 
 * Advanced pattern detection for identifying known malicious behaviors
 * and supply chain attack indicators.
 */

'use strict';

const { SignalType } = require('../signals/signalTypes');
const {
    CRYPTO_MINER_PATTERNS,
    DATA_EXFILTRATION_PATTERNS,
    BACKDOOR_PATTERNS,
    CREDENTIAL_THEFT_PATTERNS,
    TYPOSQUAT_PATTERNS,
    KNOWN_SAFE_CONTEXTS
} = require('./malwareSignatures');

/**
 * Analyze all signals for malicious patterns
 * 
 * @param {Array} signals - All collected signals
 * @param {object} config - Pattern detection configuration
 * @returns {object} Pattern detection results
 */
function analyzePatterns(signals, config = {}) {
    const results = {
        cryptoMining: [],
        dataExfiltration: [],
        backdoors: [],
        credentialTheft: [],
        typosquats: [],
        summary: {
            totalThreats: 0,
            highestSeverity: 'NONE'
        }
    };

    if (!config.enabled) {
        return results;
    }

    // Detect cryptocurrency mining
    if (config.detectCryptoMiners) {
        results.cryptoMining = detectCryptoMiners(signals);
    }

    // Detect data exfiltration
    if (config.detectDataExfiltration) {
        results.dataExfiltration = detectDataExfiltration(signals);
    }

    // Detect backdoors
    if (config.detectBackdoors) {
        results.backdoors = detectBackdoors(signals);
    }

    // Detect credential theft (always runs)
    results.credentialTheft = detectCredentialTheft(signals);

    // Detect typosquat packages (check all observed package names)
    results.typosquats = detectTyposquats(signals);

    // Calculate summary
    results.summary.totalThreats =
        results.cryptoMining.length +
        results.dataExfiltration.length +
        results.backdoors.length +
        results.credentialTheft.length +
        results.typosquats.length;

    // Determine highest severity
    if (results.backdoors.length > 0 || results.cryptoMining.length > 0) {
        results.summary.highestSeverity = 'CRITICAL';
    } else if (results.dataExfiltration.length > 0 || results.credentialTheft.length > 0) {
        results.summary.highestSeverity = 'HIGH';
    } else if (results.typosquats.length > 0) {
        results.summary.highestSeverity = 'MEDIUM';
    } else if (results.summary.totalThreats > 0) {
        results.summary.highestSeverity = 'LOW';
    }

    return results;
}

/**
 * Detect cryptocurrency mining patterns
 * 
 * @param {Array} signals - Signals to analyze
 * @returns {Array} Detected mining indicators
 */
function detectCryptoMiners(signals) {
    const indicators = [];

    for (const signal of signals) {
        // Check for miner processes
        if (signal.type === SignalType.SHELL_EXEC) {
            const command = signal.metadata.command?.toLowerCase() || '';
            const safeShell = isKnownSafeContext(signal.package, 'shellExec');

            for (const minerProcess of CRYPTO_MINER_PATTERNS.processes) {
                if (command.includes(minerProcess.toLowerCase())) {
                    indicators.push({
                        type: 'CRYPTO_MINER_PROCESS',
                        severity: safeShell ? 'MEDIUM' : 'CRITICAL',
                        package: signal.package,
                        indicator: minerProcess,
                        signal
                    });
                }
            }
        }

        // Check for mining pool connections
        if (signal.type === SignalType.HTTP_REQUEST || signal.type === SignalType.HTTPS_REQUEST) {
            const url = signal.metadata.url?.toLowerCase() || '';

            for (const poolDomain of CRYPTO_MINER_PATTERNS.domains) {
                if (url.includes(poolDomain)) {
                    indicators.push({
                        type: 'MINING_POOL_CONNECTION',
                        severity: 'CRITICAL',
                        package: signal.package,
                        indicator: poolDomain,
                        signal
                    });
                }
            }
        }

        // Check for mining-related environment variables
        if (signal.type === SignalType.ENV_ACCESS) {
            const variable = signal.metadata.variable || '';

            for (const envVar of CRYPTO_MINER_PATTERNS.envVars) {
                if (variable === envVar) {
                    indicators.push({
                        type: 'MINING_ENV_VAR',
                        severity: 'HIGH',
                        package: signal.package,
                        indicator: envVar,
                        signal
                    });
                }
            }
        }
    }

    return indicators;
}

/**
 * Check whether a package is a known-safe context for a given behavior category.
 *
 * @param {string} packageName
 * @param {'shellExec'|'fsRead'|'credentialFiles'|'httpRequest'} category
 * @returns {boolean}
 */
function isKnownSafeContext(packageName, category) {
    if (!packageName) return false;
    const list = KNOWN_SAFE_CONTEXTS[category] || [];
    const nameLower = packageName.toLowerCase();
    return list.some(safe => {
        if (safe.endsWith('/*')) return nameLower.startsWith(safe.slice(0, -2));
        return nameLower === safe || nameLower.startsWith(safe + '/');
    });
}

/**
 * Detect data exfiltration patterns with temporal correlation.
 *
 * Temporal analysis: if a package reads a sensitive file AND makes an HTTP
 * request within a short window, confidence in exfiltration is very high.
 *   ≤ 2 000 ms apart → CRITICAL (near-simultaneous = intentional exfil)
 *   ≤ 30 000 ms apart → HIGH
 *   > 30 000 ms or no timing data → MEDIUM (correlation exists but timing unclear)
 *
 * @param {Array} signals
 * @returns {Array} Detected indicators
 */
function detectDataExfiltration(signals) {
    const indicators = [];

    // Track sensitive file reads per package: { file, signal, tsMs }
    const sensitiveFileReads = new Map();

    for (const signal of signals) {
        if (signal.type === SignalType.FS_READ) {
            const filePath = signal.metadata.path || '';
            for (const sensitiveFile of DATA_EXFILTRATION_PATTERNS.sensitiveFiles) {
                if (filePath.includes(sensitiveFile)) {
                    if (!sensitiveFileReads.has(signal.package)) sensitiveFileReads.set(signal.package, []);
                    sensitiveFileReads.get(signal.package).push({
                        file: sensitiveFile,
                        signal,
                        tsMs: signal.timestamp ? new Date(signal.timestamp).getTime() : null
                    });
                }
            }
        }

        // Direct exfiltration service detection (always CRITICAL)
        if (signal.type === SignalType.HTTP_REQUEST || signal.type === SignalType.HTTPS_REQUEST) {
            const url = (signal.metadata.url || '').toLowerCase();
            for (const service of DATA_EXFILTRATION_PATTERNS.exfiltrationServices) {
                if (url.includes(service)) {
                    indicators.push({
                        type: 'EXFILTRATION_SERVICE',
                        severity: 'CRITICAL',
                        package: signal.package,
                        indicator: service,
                        signal
                    });
                }
            }
        }
    }

    // Temporal correlation: sensitive read + HTTP request from the same package
    for (const [packageName, fileReads] of sensitiveFileReads.entries()) {
        const httpSignals = signals.filter(s =>
            s.package === packageName &&
            (s.type === SignalType.HTTP_REQUEST || s.type === SignalType.HTTPS_REQUEST)
        );
        if (httpSignals.length === 0) continue;

        // Find the minimum time gap between any sensitive read and any HTTP request
        let minGapMs = Infinity;
        for (const read of fileReads) {
            if (read.tsMs === null) continue;
            for (const httpSig of httpSignals) {
                if (!httpSig.timestamp) continue;
                const gap = Math.abs(new Date(httpSig.timestamp).getTime() - read.tsMs);
                if (gap < minGapMs) minGapMs = gap;
            }
        }

        let severity = 'MEDIUM';
        let temporalNote = '';
        if (minGapMs <= 2000)       { severity = 'CRITICAL'; temporalNote = ` within ${minGapMs}ms`; }
        else if (minGapMs <= 30000) { severity = 'HIGH';     temporalNote = ` within ${Math.round(minGapMs / 1000)}s`; }
        else if (minGapMs === Infinity) { severity = 'MEDIUM'; temporalNote = ''; }
        else { severity = 'MEDIUM'; temporalNote = ' (>30s gap)'; }

        indicators.push({
            type: 'SENSITIVE_FILE_PLUS_HTTP',
            severity,
            package: packageName,
            indicator: `Read ${fileReads.length} sensitive file(s) and made HTTP request${temporalNote}`,
            details: fileReads.map(r => r.file),
            minGapMs: minGapMs === Infinity ? null : minGapMs
        });
    }

    return indicators;
}

/**
 * Detect backdoor patterns
 * 
 * @param {Array} signals - Signals to analyze
 * @returns {Array} Detected backdoor indicators
 */
function detectBackdoors(signals) {
    const indicators = [];

    for (const signal of signals) {
        if (signal.type === SignalType.SHELL_EXEC) {
            const command = signal.metadata.command || '';
            const safeShell = isKnownSafeContext(signal.package, 'shellExec');

            for (const shellPattern of BACKDOOR_PATTERNS.reverseShellCommands) {
                if (command.includes(shellPattern)) {
                    // Reverse shell is always CRITICAL — no safe context override
                    indicators.push({
                        type: 'REVERSE_SHELL',
                        severity: 'CRITICAL',
                        package: signal.package,
                        indicator: shellPattern,
                        signal
                    });
                }
            }

            for (const ratTool of BACKDOOR_PATTERNS.ratTools) {
                if (command.toLowerCase().includes(ratTool)) {
                    indicators.push({
                        type: 'REMOTE_ACCESS_TOOL',
                        severity: safeShell ? 'LOW' : 'HIGH',
                        package: signal.package,
                        indicator: ratTool,
                        signal
                    });
                }
            }
        }

        if (signal.type === SignalType.NET_CONNECT) {
            const port = signal.metadata.port;
            if (BACKDOOR_PATTERNS.suspiciousPorts.includes(port)) {
                indicators.push({
                    type: 'SUSPICIOUS_PORT',
                    severity: 'HIGH',
                    package: signal.package,
                    indicator: `Port ${port}`,
                    signal
                });
            }
        }
    }

    return indicators;
}

/**
 * Detect credential theft patterns
 * 
 * Context-aware: Known config-loading packages (dotenv, convict, etc.)
 * reading .env or config.json is EXPECTED behavior, not credential theft.
 * For these packages, credential file reads are downgraded to LOW severity.
 * 
 * @param {Array} signals - Signals to analyze
 * @returns {Array} Detected credential theft indicators
 */
function detectCredentialTheft(signals) {
    const indicators = [];

    for (const signal of signals) {
        // Check for secret environment variable access
        if (signal.type === SignalType.ENV_ACCESS) {
            const variable = signal.metadata.variable || '';

            for (const secretVar of CREDENTIAL_THEFT_PATTERNS.secretEnvVars) {
                if (variable === secretVar) {
                    indicators.push({
                        type: 'SECRET_ENV_ACCESS',
                        severity: 'HIGH',
                        package: signal.package,
                        indicator: secretVar,
                        signal
                    });
                }
            }
        }

        // Check for credential file reads — context-aware
        if (signal.type === SignalType.FS_READ) {
            const filePath = signal.metadata.path || '';
            const pkgName = (signal.package || '').toLowerCase();

            for (const credFile of CREDENTIAL_THEFT_PATTERNS.credentialFiles) {
                if (filePath.includes(credFile)) {
                    // Check if this is a known config loader doing its job
                    const isConfigLoader = CREDENTIAL_THEFT_PATTERNS.knownConfigLoaders
                        .some(loader => pkgName === loader || pkgName.startsWith(loader + '/'));

                    indicators.push({
                        type: 'CREDENTIAL_FILE_READ',
                        severity: isConfigLoader ? 'LOW' : 'HIGH',
                        package: signal.package,
                        indicator: credFile,
                        context: isConfigLoader
                            ? `${signal.package} is a known config loader — reading ${credFile} is expected behavior`
                            : undefined,
                        signal
                    });
                }
            }
        }
    }

    return indicators;
}

/**
 * Detect typosquat packages by comparing observed package names against
 * a list of popular packages using Levenshtein distance and character swaps.
 *
 * @param {Array} signals - Signals to analyze
 * @returns {Array} Detected typosquat indicators
 */
function detectTyposquats(signals) {
    const indicators = [];
    const seen = new Set(); // Avoid duplicate detections per package

    for (const signal of signals) {
        if (!signal.package || seen.has(signal.package)) continue;

        const pkgName = signal.package.toLowerCase();

        for (const popular of TYPOSQUAT_PATTERNS.popularPackages) {
            const popularLower = popular.toLowerCase();

            // Levenshtein distance check
            if (levenshteinDistance(pkgName, popularLower) === 1) {
                seen.add(signal.package);
                indicators.push({
                    type: 'TYPOSQUAT_LEVENSHTEIN',
                    severity: 'MEDIUM',
                    package: signal.package,
                    indicator: `"${signal.package}" is 1 edit away from "${popular}"`,
                    signal
                });
                break; // One match per package is enough
            }

            // Character swap check (o→0, i→l, e→3)
            for (const [original, replacement] of Object.entries(TYPOSQUAT_PATTERNS.techniques.swaps)) {
                const swapped = popularLower.split(original).join(replacement);
                if (pkgName === swapped) {
                    seen.add(signal.package);
                    indicators.push({
                        type: 'TYPOSQUAT_SWAP',
                        severity: 'MEDIUM',
                        package: signal.package,
                        indicator: `"${signal.package}" looks like "${popular}" with ${original}→${replacement} swap`,
                        signal
                    });
                    break;
                }
            }

            if (seen.has(signal.package)) break;
        }
    }

    return indicators;
}

/**
 * Calculate Levenshtein edit distance between two strings.
 * Returns the minimum number of single-character edits (insertions,
 * deletions, substitutions) to transform a into b.
 *
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {number} Edit distance
 */
function levenshteinDistance(a, b) {
    if (a === b) return 0;
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;

    const matrix = [];
    for (let i = 0; i <= b.length; i++) {
        matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
        matrix[0][j] = j;
    }

    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            const cost = a[j - 1] === b[i - 1] ? 0 : 1;
            matrix[i][j] = Math.min(
                matrix[i - 1][j] + 1,      // deletion
                matrix[i][j - 1] + 1,      // insertion
                matrix[i - 1][j - 1] + cost // substitution
            );
        }
    }

    return matrix[b.length][a.length];
}

module.exports = {
    analyzePatterns,
    detectCryptoMiners,
    detectDataExfiltration,
    detectBackdoors,
    detectCredentialTheft,
    detectTyposquats
};
