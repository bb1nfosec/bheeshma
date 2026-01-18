/**
 * BHEESHMA Main Entry Point
 * 
 * Security: Orchestrates safe hook installation and signal collection
 * Follows OWASP principle: "Establish secure defaults"
 * 
 * Purpose: Main API for programmatic use of BHEESHMA monitoring.
 */

'use strict';

const envHook = require('./hooks/envHook');
const fsHook = require('./hooks/fsHook');
const netHook = require('./hooks/netHook');
const childProcHook = require('./hooks/childProcHook');
const { calculateAllScores } = require('./scoring/trustScore');
const cliFormatter = require('./output/cliFormatter');
const jsonFormatter = require('./output/jsonFormatter');

/**
 * Global signal collector
 * Security: Single source of truth for all captured signals
 */
const signals = [];

/**
 * Hook installation state
 */
let hooksInstalled = false;

/**
 * Initialize BHEESHMA monitoring
 * 
 * Installs all hooks and begins signal collection.
 * This should be called as early as possible in the application lifecycle,
 * ideally before any third-party dependencies are loaded.
 * 
 * Security:
 * - Fail-safe: Partial hook failure doesn't prevent app from running
 * - Idempotent: Safe to call multiple times
 * - Returns success status for verification
 * 
 * @param {object} options - Configuration options (reserved for future use)
 * @returns {object} { success: boolean, installed: string[] }
 */
function init(options = {}) {
    if (hooksInstalled) {
        return { success: true, installed: [], message: 'Already initialized' };
    }

    const installed = [];
    const failed = [];

    // Install hooks sequentially
    // If one fails, others can still succeed (defense in depth)

    if (envHook.install(signals)) {
        installed.push('envHook');
    } else {
        failed.push('envHook');
    }

    if (fsHook.install(signals)) {
        installed.push('fsHook');
    } else {
        failed.push('fsHook');
    }

    if (netHook.install(signals)) {
        installed.push('netHook');
    } else {
        failed.push('netHook');
    }

    if (childProcHook.install(signals)) {
        installed.push('childProcHook');
    } else {
        failed.push('childProcHook');
    }

    hooksInstalled = installed.length > 0;

    return {
        success: hooksInstalled,
        installed,
        failed: failed.length > 0 ? failed : undefined
    };
}

/**
 * Get all collected signals
 * 
 * Security: Returns a copy to prevent external mutation
 * 
 * @returns {Array} Copy of signals array
 */
function getSignals() {
    return [...signals];
}

/**
 * Get calculated trust scores for all packages
 * 
 * @returns {Map} Trust scores by package
 */
function getTrustScores() {
    return calculateAllScores(signals);
}

/**
 * Generate formatted report
 * 
 * @param {string} format - 'cli' or 'json'
 * @returns {string} Formatted report
 */
function generateReport(format = 'cli') {
    const scores = getTrustScores();

    if (format === 'json') {
        return jsonFormatter.formatReport(scores, signals);
    } else {
        return cliFormatter.formatReport(scores, signals);
    }
}

/**
 * Teardown BHEESHMA (remove all hooks)
 * 
 * Useful for testing and cleanup.
 * In production, hooks typically remain installed for the process lifetime.
 * 
 * Security: Clean restoration of original behavior
 * 
 * @returns {object} { success: boolean, uninstalled: string[] }
 */
function teardown() {
    const uninstalled = [];
    const failed = [];

    if (envHook.uninstall()) {
        uninstalled.push('envHook');
    } else {
        failed.push('envHook');
    }

    if (fsHook.uninstall()) {
        uninstalled.push('fsHook');
    } else {
        failed.push('fsHook');
    }

    if (netHook.uninstall()) {
        uninstalled.push('netHook');
    } else {
        failed.push('netHook');
    }

    if (childProcHook.uninstall()) {
        uninstalled.push('childProcHook');
    } else {
        failed.push('childProcHook');
    }

    hooksInstalled = false;
    signals.length = 0; // Clear signals

    return {
        success: true,
        uninstalled,
        failed: failed.length > 0 ? failed : undefined
    };
}

/**
 * Monitor a function execution
 * 
 * Convenience wrapper that:
 * 1. Initializes hooks
 * 2. Executes function
 * 3. Generates report
 * 
 * @param {Function} fn - Function to monitor
 * @param {object} options - { format: 'cli'|'json' }
 * @returns {Promise<object>} { result, report }
 */
async function monitor(fn, options = {}) {
    // Initialize
    const initResult = init();

    if (!initResult.success) {
        throw new Error('Failed to initialize BHEESHMA hooks');
    }

    // Execute function
    let result;
    let error;

    try {
        result = await Promise.resolve(fn());
    } catch (err) {
        error = err;
    }

    // Generate report
    const report = generateReport(options.format || 'cli');

    // Re-throw if function failed
    if (error) {
        throw error;
    }

    return {
        result,
        report
    };
}

module.exports = {
    init,
    getSignals,
    getTrustScores,
    generateReport,
    teardown,
    monitor
};
