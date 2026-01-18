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
    CREDENTIAL_THEFT_PATTERNS
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

    // Detect credential theft
    results.credentialTheft = detectCredentialTheft(signals);

    // Calculate summary
    results.summary.totalThreats =
        results.cryptoMining.length +
        results.dataExfiltration.length +
        results.backdoors.length +
        results.credentialTheft.length;

    // Determine highest severity
    if (results.backdoors.length > 0 || results.cryptoMining.length > 0) {
        results.summary.highestSeverity = 'CRITICAL';
    } else if (results.dataExfiltration.length > 0 || results.credentialTheft.length > 0) {
        results.summary.highestSeverity = 'HIGH';
    } else if (results.summary.totalThreats > 0) {
        results.summary.highestSeverity = 'MEDIUM';
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

            for (const minerProcess of CRYPTO_MINER_PATTERNS.processes) {
                if (command.includes(minerProcess.toLowerCase())) {
                    indicators.push({
                        type: 'CRYPTO_MINER_PROCESS',
                        severity: 'CRITICAL',
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
 * Detect data exfiltration patterns
 * 
 * @param {Array} signals - Signals to analyze
 * @returns {Array} Detected exfiltration indicators
 */
function detectDataExfiltration(signals) {
    const indicators = [];

    // Track which packages read sensitive files
    const sensitiveFileReads = new Map();

    for (const signal of signals) {
        // Detect sensitive file reads
        if (signal.type === SignalType.FS_READ) {
            const path = signal.metadata.path || '';

            for (const sensitiveFile of DATA_EXFILTRATION_PATTERNS.sensitiveFiles) {
                if (path.includes(sensitiveFile)) {
                    if (!sensitiveFileReads.has(signal.package)) {
                        sensitiveFileReads.set(signal.package, []);
                    }
                    sensitiveFileReads.get(signal.package).push({ file: sensitiveFile, signal });
                }
            }
        }

        // Detect exfiltration to known services
        if (signal.type === SignalType.HTTP_REQUEST || signal.type === SignalType.HTTPS_REQUEST) {
            const url = signal.metadata.url?.toLowerCase() || '';

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

    // If a package read sensitive files AND made HTTP requests, that's highly suspicious
    for (const [packageName, fileReads] of sensitiveFileReads.entries()) {
        const packageHasHttpRequest = signals.some(s =>
            s.package === packageName &&
            (s.type === SignalType.HTTP_REQUEST || s.type === SignalType.HTTPS_REQUEST)
        );

        if (packageHasHttpRequest) {
            indicators.push({
                type: 'SENSITIVE_FILE_PLUS_HTTP',
                severity: 'CRITICAL',
                package: packageName,
                indicator: `Read ${fileReads.length} sensitive file(s) and made HTTP request`,
                details: fileReads.map(fr => fr.file)
            });
        }
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
        // Check for reverse shell commands
        if (signal.type === SignalType.SHELL_EXEC) {
            const command = signal.metadata.command || '';

            for (const shellPattern of BACKDOOR_PATTERNS.reverseShellCommands) {
                if (command.includes(shellPattern)) {
                    indicators.push({
                        type: 'REVERSE_SHELL',
                        severity: 'CRITICAL',
                        package: signal.package,
                        indicator: shellPattern,
                        signal
                    });
                }
            }

            // Check for remote access tools
            for (const ratTool of BACKDOOR_PATTERNS.ratTools) {
                if (command.toLowerCase().includes(ratTool)) {
                    indicators.push({
                        type: 'REMOTE_ACCESS_TOOL',
                        severity: 'HIGH',
                        package: signal.package,
                        indicator: ratTool,
                        signal
                    });
                }
            }
        }

        // Check for suspicious listening ports
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

        // Check for credential file reads
        if (signal.type === SignalType.FS_READ) {
            const path = signal.metadata.path || '';

            for (const credFile of CREDENTIAL_THEFT_PATTERNS.credentialFiles) {
                if (path.includes(credFile)) {
                    indicators.push({
                        type: 'CREDENTIAL_FILE_READ',
                        severity: 'HIGH',
                        package: signal.package,
                        indicator: credFile,
                        signal
                    });
                }
            }
        }
    }

    return indicators;
}

module.exports = {
    analyzePatterns,
    detectCryptoMiners,
    detectDataExfiltration,
    detectBackdoors,
    detectCredentialTheft
};
