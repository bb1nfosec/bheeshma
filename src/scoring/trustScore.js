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
 * 
 * Rationale:
 * - SHELL_EXEC: Highest risk (arbitrary code execution)
 * - FS_WRITE: High risk (data exfiltration, persistence)
 * - NET_CONNECT: Medium-high risk (data exfiltration)
 * - ENV_ACCESS: Medium risk (credential theft)
 * - FS_READ: Lower risk (reconnaissance)
 * 
 * These weights are intentionally conservative and can be tuned.
 */
const RISK_WEIGHTS = Object.freeze({
    [SignalType.SHELL_EXEC]: 20,
    [SignalType.FS_WRITE]: 10,
    [SignalType.NET_CONNECT]: 8,
    [SignalType.ENV_ACCESS]: 5,
    [SignalType.FS_READ]: 3
});

/**
 * Calculate trust score for a single package
 * 
 * Algorithm:
 * 1. Start at 100 (full trust)
 * 2. For each signal attributed to the package, deduct risk weight
 * 3. Floor at 0 (no negative scores)
 * 
 * Security:
 * - Pure function: No side effects
 * - Deterministic: Same input always produces same output
 * - Auditable: All logic is transparent
 * 
 * @param {Array<object>} signals - Array of signals for this package
 * @returns {number} Trust score [0-100]
 */
function calculateTrustScore(signals) {
    if (!Array.isArray(signals) || signals.length === 0) {
        // No signals = full trust (package didn't do anything observable)
        return 100;
    }

    let score = 100;

    for (const signal of signals) {
        const weight = RISK_WEIGHTS[signal.type] || 0;
        score -= weight;

        // Floor at 0
        if (score < 0) {
            score = 0;
            break;
        }
    }

    return score;
}

/**
 * Calculate trust scores for all packages from signal collection
 * 
 * Groups signals by package and calculates individual scores.
 * 
 * @param {Array<object>} allSignals - All captured signals
 * @returns {Map<string, object>} Map of packageName -> { score, signals, stats }
 */
function calculateAllScores(allSignals) {
    const packageMap = new Map();

    // Group signals by package
    for (const signal of allSignals) {
        // Skip signals from first-party code
        if (!signal.package) {
            continue;
        }

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

        // Update statistics
        updateStats(packageData.stats, signal);
    }

    // Calculate scores for each package
    const scores = new Map();
    for (const [key, data] of packageMap.entries()) {
        scores.set(key, {
            name: data.name,
            version: data.version,
            score: calculateTrustScore(data.signals),
            signalCount: data.signals.length,
            stats: data.stats
        });
    }

    return scores;
}

/**
 * Initialize statistics object for a package
 * 
 * @returns {object} Stats object
 */
function initializeStats() {
    return {
        [SignalType.ENV_ACCESS]: 0,
        [SignalType.FS_READ]: 0,
        [SignalType.FS_WRITE]: 0,
        [SignalType.SHELL_EXEC]: 0,
        [SignalType.NET_CONNECT]: 0
    };
}

/**
 * Update statistics with a new signal
 * 
 * @param {object} stats - Statistics object
 * @param {object} signal - Signal to count
 * @returns {void}
 */
function updateStats(stats, signal) {
    if (stats[signal.type] !== undefined) {
        stats[signal.type]++;
    }
}

/**
 * Get risk level category based on trust score
 * 
 * @param {number} score - Trust score [0-100]
 * @returns {string} Risk level: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
 */
function getRiskLevel(score) {
    if (score >= 80) return 'LOW';
    if (score >= 60) return 'MEDIUM';
    if (score >= 30) return 'HIGH';
    return 'CRITICAL';
}

module.exports = {
    calculateTrustScore,
    calculateAllScores,
    getRiskLevel,
    RISK_WEIGHTS
};
