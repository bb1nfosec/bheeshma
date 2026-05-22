'use strict';

/**
 * BHEESHMA Behavioral Baseline Manager
 *
 * Supports two modes:
 *
 *  --learn   Run the app and record all signals to a baseline JSON file.
 *            On subsequent runs, signals that match the baseline are considered
 *            "known good" and suppressed before scoring/reporting.
 *
 *  --baseline <file>   Load baseline and filter matching signals.
 *            Only NEW behaviors (not in baseline) are scored and reported.
 *            This eliminates false-positive fatigue for apps with many
 *            dependencies that legitimately make network calls.
 *
 * Baseline format: JSON object mapping dedup keys → signal metadata snapshots.
 * The key is the same dedup key used by trustScore.deduplicateSignals so the
 * two systems stay consistent.
 */

const fs = require('fs');
const path = require('path');

/**
 * Build a stable dedup key for a signal (mirrors trustScore.buildDedupKey).
 *
 * @param {object} signal
 * @returns {string}
 */
function buildBaselineKey(signal) {
    const pkg  = signal.package || 'unknown';
    const type = signal.type;
    let dest = '';

    switch (type) {
        case 'ENV_ACCESS':    dest = signal.metadata.variable || ''; break;
        case 'FS_READ':
        case 'FS_WRITE':      dest = signal.metadata.path || ''; break;
        case 'SHELL_EXEC':    dest = (signal.metadata.command || '').split(/\s+/).slice(0, 3).join(' '); break;
        case 'NET_CONNECT':   dest = `${signal.metadata.host}:${signal.metadata.port}`; break;
        case 'HTTP_REQUEST':
        case 'HTTPS_REQUEST': dest = `${signal.metadata.host || ''}:${signal.metadata.method || ''}`; break;
        case 'DNS_QUERY':     dest = signal.metadata.hostname || ''; break;
        case 'VM_EXEC':       dest = signal.metadata.method || ''; break;
        case 'CRYPTO_OP':     dest = `${signal.metadata.operation || ''}:${signal.metadata.algorithm || ''}`; break;
        default:              dest = JSON.stringify(signal.metadata || {});
    }

    return `${pkg}:${type}:${dest}`;
}

/**
 * Capture a baseline from a set of signals and write it to disk.
 *
 * @param {Array}  signals    - All collected signals
 * @param {string} outputPath - File path for the baseline JSON
 * @returns {object} { saved: number, path: string }
 */
function captureBaseline(signals, outputPath) {
    const baseline = {
        version: 1,
        capturedAt: new Date().toISOString(),
        entries: {}
    };

    for (const signal of signals) {
        if (!signal.package) continue;
        const key = buildBaselineKey(signal);
        if (!baseline.entries[key]) {
            baseline.entries[key] = {
                package: signal.package,
                version: signal.version,
                type:    signal.type,
                count:   0
            };
        }
        baseline.entries[key].count++;
    }

    const absPath = path.resolve(outputPath);
    fs.writeFileSync(absPath, JSON.stringify(baseline, null, 2), 'utf8');

    return { saved: Object.keys(baseline.entries).length, path: absPath };
}

/**
 * Load a baseline file from disk.
 *
 * @param {string} baselinePath
 * @returns {object|null} Baseline object or null on failure
 */
function loadBaseline(baselinePath) {
    try {
        const content = fs.readFileSync(path.resolve(baselinePath), 'utf8');
        const parsed = JSON.parse(content);
        if (!parsed || !parsed.entries || typeof parsed.entries !== 'object') return null;
        return parsed;
    } catch (err) {
        console.warn(`[BHEESHMA] Could not load baseline: ${err.message}`);
        return null;
    }
}

/**
 * Filter signals, keeping only those NOT present in the baseline.
 * Signals without a package (first-party) are always kept.
 *
 * @param {Array}  signals  - Raw signals array
 * @param {object} baseline - Loaded baseline object (from loadBaseline)
 * @returns {Array} Filtered signals — only new behaviors
 */
function filterBaselineSignals(signals, baseline) {
    if (!baseline || !baseline.entries) return signals;

    return signals.filter(signal => {
        if (!signal.package) return true;
        const key = buildBaselineKey(signal);
        return !Object.prototype.hasOwnProperty.call(baseline.entries, key);
    });
}

/**
 * Summarize what's new vs the baseline (for CLI output).
 *
 * @param {Array}  signals  - All captured signals
 * @param {object} baseline - Loaded baseline
 * @returns {{ newCount: number, baselineCount: number, newSignals: Array }}
 */
function diffBaseline(signals, baseline) {
    const newSignals = filterBaselineSignals(signals, baseline);
    return {
        newCount:      newSignals.length,
        baselineCount: signals.length - newSignals.length,
        newSignals
    };
}

module.exports = { captureBaseline, loadBaseline, filterBaselineSignals, diffBaseline, buildBaselineKey };
