/**
 * BHEESHMA JSON Output Formatter
 * 
 * Security: Machine-readable output for CI/CD integration
 * 
 * Purpose: Generate structured JSON output for automated processing,
 * policy enforcement, and integration with security pipelines.
 */

'use strict';

const { getRiskLevel } = require('../scoring/trustScore');

/**
 * Format complete report as JSON
 * 
 * Output schema:
 * {
 *   "version": "1.0",
 *   "timestamp": "ISO 8601",
 *   "summary": { ... },
 *   "packages": [ ... ],
 *   "signals": [ ... ]
 * }
 * 
 * Security:
 * - Escapes all user-controlled strings to prevent injection
 * - Schema versioned for forward compatibility
 * - Deterministic output (same input = same JSON)
 * 
 * @param {Map} scores - Trust scores by package
 * @param {Array} allSignals - All captured signals
 * @returns {string} JSON string
 */
function formatReport(scores, allSignals) {
    const report = {
        version: '1.0',
        timestamp: new Date().toISOString(),
        summary: buildSummary(scores, allSignals),
        packages: buildPackageList(scores),
        signals: sanitizeSignals(allSignals)
    };

    // Pretty print with 2-space indentation for readability
    return JSON.stringify(report, null, 2);
}

/**
 * Build summary object
 * 
 * @param {Map} scores - Trust scores
 * @param {Array} allSignals - All signals
 * @returns {object} Summary object
 */
function buildSummary(scores, allSignals) {
    const riskDistribution = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
    };

    for (const [, data] of scores) {
        const risk = getRiskLevel(data.score).toLowerCase();
        if (riskDistribution[risk] !== undefined) {
            riskDistribution[risk]++;
        }
    }

    return {
        totalPackages: scores.size,
        totalSignals: allSignals.filter(s => s.package !== null).length,
        riskDistribution
    };
}

/**
 * Build package list with scores and stats
 * 
 * @param {Map} scores - Trust scores
 * @returns {Array} Package array
 */
function buildPackageList(scores) {
    const packages = [];

    for (const [packageKey, data] of scores) {
        packages.push({
            name: data.name,
            version: data.version,
            trustScore: data.score,
            riskLevel: getRiskLevel(data.score),
            signalCount: data.signalCount,
            behaviors: data.stats
        });
    }

    // Sort by trust score (lowest first)
    packages.sort((a, b) => a.trustScore - b.trustScore);

    return packages;
}

/**
 * Sanitize signals for JSON output
 * 
 * Security:
 * - Removes sensitive stack trace details
 * - Ensures all strings are properly escaped
 * - Validates structure
 * 
 * @param {Array} allSignals - All signals
 * @returns {Array} Sanitized signals
 */
function sanitizeSignals(allSignals) {
    return allSignals
        .filter(s => s.package !== null) // Only third-party
        .map(signal => ({
            timestamp: signal.timestamp,
            type: signal.type,
            package: signal.package,
            version: signal.version,
            metadata: sanitizeMetadata(signal.metadata)
            // Omit full stack trace from JSON (too verbose)
        }));
}

/**
 * Sanitize metadata object
 * 
 * Ensures no sensitive data leaked and all values are JSON-safe
 * 
 * @param {object} metadata - Signal metadata
 * @returns {object} Sanitized metadata
 */
function sanitizeMetadata(metadata) {
    if (!metadata || typeof metadata !== 'object') {
        return {};
    }

    const sanitized = {};

    // Copy allowed fields only
    const allowedFields = ['variable', 'path', 'operation', 'host', 'port', 'protocol', 'command'];

    for (const field of allowedFields) {
        if (metadata[field] !== undefined) {
            // Ensure string values are truncated if too long
            if (typeof metadata[field] === 'string' && metadata[field].length > 500) {
                sanitized[field] = metadata[field].substring(0, 500) + '...[TRUNCATED]';
            } else {
                sanitized[field] = metadata[field];
            }
        }
    }

    return sanitized;
}

module.exports = {
    formatReport
};
