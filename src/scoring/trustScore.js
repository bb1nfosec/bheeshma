/**
 * BHEESHMA Trust Scoring Engine
 * 
 * Security: Transparent, deterministic trust scoring (no ML, no opacity)
 * Follows principle: "Security through clarity, not obscurity"
 * 
 * Purpose: Calculate a trust score [0-100] for each package based on
 * observed runtime behaviors. Lower scores indicate higher risk.
 * 
 * Scoring is deterministic: Same signals always produce same score.
 */

'use strict';

const { SignalType } = require('../signals/signalTypes');

/**
 * Risk weights for different signal types
 * Higher weight = greater risk deduction
 */
const RISK_WEIGHTS = Object.freeze({
    [SignalType.SHELL_EXEC]:           20,
    [SignalType.FS_WRITE]:             10,
    [SignalType.NET_CONNECT]:           8,
    [SignalType.ENV_ACCESS]:            5,
    [SignalType.FS_READ]:               3,
    [SignalType.HTTP_REQUEST]:         10,
    [SignalType.HTTPS_REQUEST]:         8,
    [SignalType.DNS_QUERY]:             4,
    [SignalType.OBFUSCATION_DETECTED]: 25,
    [SignalType.VM_EXEC]:              20,   // code execution — same weight as SHELL_EXEC
    [SignalType.CRYPTO_OP]:             8,   // decrypt/cipher ops — suspicious but may be legit
    [SignalType.HOOK_TAMPER]:         100,   // evasion — guaranteed CRITICAL
    [SignalType.PROTO_POLLUTION]:      30,   // injection attack
    'BLACKLISTED_PACKAGE':            100
});

/**
 * Calculate trust score for a single package
 * 
 * Algorithm:
 * 1. Start at 100 (full trust)
 * 2. For each signal attributed to the package, deduct risk weight
 * 3. Floor at 0 (no negative scores)
 * 
 * @param {Array<object>} signals - Array of signals for this package
 * @returns {number} Trust score [0-100]
 */
function calculateTrustScore(signals) {
    if (!Array.isArray(signals) || signals.length === 0) {
        return 100;
    }

    let score = 100;

    for (const signal of signals) {
        const weight = RISK_WEIGHTS[signal.type] || 0;
        score -= weight;

        if (score < 0) {
            score = 0;
            break;
        }
    }

    return score;
}

/**
 * Deduplicate signals to collapse identical repeated behaviors.
 * 
 * Key: ${pkg}:${type}:${destination}
 * For each unique key, keeps count, firstSeen, lastSeen, and one sample signal.
 * This makes reports readable — a package that makes 300 identical HTTP requests
 * to the same host shows as 1 entry with count=300, not 300 noisy rows.
 * 
 * @param {Array<object>} signals - Raw signals array
 * @returns {Array<object>} Deduplicated signals
 */
function deduplicateSignals(signals) {
    const dedupMap = new Map();

    for (const signal of signals) {
        // Build a dedup key based on signal type + destination
        const key = buildDedupKey(signal);

        if (dedupMap.has(key)) {
            const entry = dedupMap.get(key);
            entry.count++;
            entry.lastSeen = signal.timestamp;
            // Keep the signal with the most metadata
            if (Object.keys(signal.metadata).length > Object.keys(entry.sample.metadata).length) {
                entry.sample = signal;
            }
        } else {
            dedupMap.set(key, {
                count: 1,
                firstSeen: signal.timestamp,
                lastSeen: signal.timestamp,
                sample: signal
            });
        }
    }

    // Reconstruct signal array with dedup metadata
    const result = [];
    for (const [, entry] of dedupMap) {
        const signal = { ...entry.sample };
        signal._dedup = {
            count: entry.count,
            firstSeen: entry.firstSeen,
            lastSeen: entry.lastSeen
        };
        result.push(Object.freeze(signal));
    }

    return result;
}

/**
 * Build a deduplication key for a signal
 * 
 * @param {object} signal - Signal object
 * @returns {string} Dedup key
 */
function buildDedupKey(signal) {
    const pkg = signal.package || 'unknown';
    const type = signal.type;
    let destination = '';

    switch (signal.type) {
        case SignalType.ENV_ACCESS:
            destination = signal.metadata.variable || '';
            break;
        case SignalType.FS_READ:
        case SignalType.FS_WRITE:
            destination = signal.metadata.path || '';
            break;
        case SignalType.SHELL_EXEC:
            // Normalize command to reduce noise from dynamic args
            destination = (signal.metadata.command || '').split(/\s+/).slice(0, 3).join(' ');
            break;
        case SignalType.NET_CONNECT:
            destination = `${signal.metadata.host}:${signal.metadata.port}`;
            break;
        case SignalType.HTTP_REQUEST:
        case SignalType.HTTPS_REQUEST:
            // Key on host + method to group repeated requests to same endpoint
            destination = `${signal.metadata.host}:${signal.metadata.method}`;
            break;
        case SignalType.DNS_QUERY:
            destination = signal.metadata.hostname || '';
            break;
        case SignalType.OBFUSCATION_DETECTED:
            destination = JSON.stringify(signal.metadata.indicators || []);
            break;
        default:
            destination = JSON.stringify(signal.metadata || {});
    }

    return `${pkg}:${type}:${destination}`;
}

/**
 * Calculate trust scores for all packages from signal collection
 * 
 * Groups signals by package, deduplicates them, then calculates scores.
 * 
 * @param {Array<object>} allSignals - All captured signals
 * @param {object} options - { deduplicate: boolean, packageThresholds: object, configThresholds: object }
 * @returns {Map<string, object>} Map of packageName -> { score, signals, stats, riskLevel }
 */
function calculateAllScores(allSignals, options = {}) {
    const { deduplicate = true, packageThresholds = {}, configThresholds = {} } = options;
    const packageMap = new Map();

    // Group signals by package
    for (const signal of allSignals) {
        if (!signal.package) continue;

        const key = `${signal.package}@${signal.version}`;

        if (!packageMap.has(key)) {
            packageMap.set(key, {
                name: signal.package,
                version: signal.version,
                signals: [],
                stats: initializeStats()
            });
        }

        const packageData = packageMap.get(key);
        packageData.signals.push(signal);
        updateStats(packageData.stats, signal);
    }

    // Deduplicate signals per package
    const scores = new Map();
    for (const [key, data] of packageMap.entries()) {
        const effectiveSignals = deduplicate ? deduplicateSignals(data.signals) : data.signals;
        let score = calculateTrustScore(effectiveSignals);

        // Apply per-package threshold override
        const customThreshold = packageThresholds[data.name];
        if (customThreshold !== undefined && typeof customThreshold === 'number') {
            // If the score is below the custom threshold, override risk level
            // The score stays the same, but enforcement uses the custom threshold
        }

        const riskLevel = getRiskLevel(score, customThreshold);

        scores.set(key, {
            name: data.name,
            version: data.version,
            score,
            riskLevel,
            signalCount: data.signals.length,
            uniqueSignalCount: effectiveSignals.length,
            stats: data.stats,
            effectiveSignals
        });
    }

    return scores;
}

/**
 * Initialize statistics object for a package
 */
function initializeStats() {
    const stats = {};
    for (const type of Object.values(SignalType)) {
        stats[type] = 0;
    }
    return stats;
}

/**
 * Update statistics with a new signal
 */
function updateStats(stats, signal) {
    if (stats[signal.type] !== undefined) {
        stats[signal.type]++;
    }
}

/**
 * Get risk level category based on trust score.
 * Supports optional per-package threshold override.
 * 
 * @param {number} score - Trust score [0-100]
 * @param {number} customThreshold - Optional per-package threshold override
 * @returns {string} Risk level: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
 */
function getRiskLevel(score, customThreshold) {
    const critical = customThreshold !== undefined ? customThreshold : 30;
    const high = customThreshold !== undefined ? Math.min(critical + 30, 100) : 60;
    const medium = customThreshold !== undefined ? Math.min(high + 20, 100) : 80;

    if (score < critical) return 'CRITICAL';
    if (score < high) return 'HIGH';
    if (score < medium) return 'MEDIUM';
    return 'LOW';
}

/**
 * Risk level numeric priority — higher = more severe.
 */
const RISK_PRIORITY = Object.freeze({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 });

/**
 * Check if any package has CRITICAL risk level (for enforcement mode).
 * Kept for backwards compatibility — use findViolatingPackages for configurable levels.
 *
 * @param {Map} scores - Trust scores map
 * @param {object} config - Configuration with thresholds
 * @returns {Array} CRITICAL packages
 */
function findCriticalPackages(scores, config = {}) {
    return findViolatingPackages(scores, 'critical');
}

/**
 * Find packages that violate the configured fail level.
 * Returns packages whose riskLevel meets or exceeds the threshold.
 *
 * @param {Map} scores - Trust scores map from calculateAllScores
 * @param {string} failLevel - 'critical' | 'high' | 'medium' | 'low'
 * @returns {Array} Violating packages: [{ name, version, score, riskLevel }]
 */
function findViolatingPackages(scores, failLevel = 'critical') {
    const minPriority = RISK_PRIORITY[(failLevel || 'critical').toUpperCase()] || RISK_PRIORITY.CRITICAL;
    const violations = [];

    for (const [, data] of scores) {
        const pkgPriority = RISK_PRIORITY[data.riskLevel] || 0;
        if (pkgPriority >= minPriority) {
            violations.push({
                name: data.name,
                version: data.version,
                score: data.score,
                riskLevel: data.riskLevel,
                signalCount: data.signalCount
            });
        }
    }

    return violations;
}

module.exports = {
    calculateTrustScore,
    calculateAllScores,
    getRiskLevel,
    findCriticalPackages,
    findViolatingPackages,
    deduplicateSignals,
    RISK_WEIGHTS,
    RISK_PRIORITY
};
