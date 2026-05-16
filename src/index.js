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
const httpHook = require('./hooks/httpHook');
const dnsHook = require('./hooks/dnsHook');
const { calculateAllScores, findCriticalPackages, getRiskLevel } = require('./scoring/trustScore');
const cliFormatter = require('./output/cliFormatter');
const jsonFormatter = require('./output/jsonFormatter');
const htmlFormatter = require('./output/htmlFormatter');
const { loadConfig, getDefaultConfig } = require('./config/configLoader');
const { analyzePatterns } = require('./patterns/patternMatcher');
const { isWhitelisted } = require('./attribution/resolver');
const { mergeConfig, validateConfig } = require('./config/schema');

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
 * Current configuration
 */
let currentConfig = null;

/**
 * Worker thread signal collector
 * Merges signals from worker threads into the main store
 */
let workerSignalHandler = null;

/**
 * Initialize BHEESHMA monitoring
 * 
 * Installs all hooks and begins signal collection.
 * This should be called as early as possible in the application lifecycle.
 * 
 * @param {object} options - Configuration options
 * @returns {object} { success: boolean, installed: string[] }
 */
function init(options = {}) {
    if (hooksInstalled) {
        return { success: true, installed: [], message: 'Already initialized' };
    }

    // Load configuration
    if (options.config) {
        // Merge user-provided config with defaults to ensure all fields exist
        const validation = validateConfig(options.config);
        currentConfig = validation.valid ? mergeConfig(options.config) : getDefaultConfig();
    } else if (options.configPath) {
        currentConfig = loadConfig(options.configPath);
    } else {
        currentConfig = loadConfig();
    }

    if (!currentConfig) {
        currentConfig = getDefaultConfig();
    }

    const installed = [];
    const failed = [];

    // Install hooks sequentially based on configuration
    if (currentConfig.hooks.env && envHook.install(signals, currentConfig)) {
        installed.push('envHook');
    } else if (currentConfig.hooks.env) {
        failed.push('envHook');
    }

    if (currentConfig.hooks.fs && fsHook.install(signals, currentConfig)) {
        installed.push('fsHook');
    } else if (currentConfig.hooks.fs) {
        failed.push('fsHook');
    }

    if (currentConfig.hooks.net && netHook.install(signals, currentConfig)) {
        installed.push('netHook');
    } else if (currentConfig.hooks.net) {
        failed.push('netHook');
    }

    if (currentConfig.hooks.childProcess && childProcHook.install(signals, currentConfig)) {
        installed.push('childProcHook');
    } else if (currentConfig.hooks.childProcess) {
        failed.push('childProcHook');
    }

    if (currentConfig.hooks.http && httpHook.install(signals, currentConfig)) {
        installed.push('httpHook');
    } else if (currentConfig.hooks.http) {
        failed.push('httpHook');
    }

    if (currentConfig.hooks.dns && dnsHook.install(signals, currentConfig)) {
        installed.push('dnsHook');
    } else if (currentConfig.hooks.dns) {
        failed.push('dnsHook');
    }

    // Set up worker thread signal collection if available
    setupWorkerSignalCollection();

    hooksInstalled = installed.length > 0;

    return {
        success: hooksInstalled,
        installed,
        failed: failed.length > 0 ? failed : undefined,
        config: currentConfig
    };
}

/**
 * Set up worker thread signal collection.
 * When a worker thread posts signals via parentPort, merge them into
 * the main process signal store.
 */
function setupWorkerSignalCollection() {
    try {
        const { isMainThread, parentPort } = require('worker_threads');

        if (!isMainThread && parentPort) {
            // This IS a worker thread — we should be using worker-bootstrap.js
            // which sends signals to the main thread. Nothing to do here.
        }

        if (isMainThread) {
            // Main thread: set up to receive signals from workers
            process.on('message', (msg) => {
                if (msg && msg.type === 'BHEESHMA_SIGNAL' && msg.signal) {
                    signals.push(msg.signal);
                }
            });
        }
    } catch (err) {
        // worker_threads not available (Node < 11.7)
    }
}

/**
 * Add a signal to the collector, respecting whitelist.
 * This is the centralized push point — all hooks should use this.
 * 
 * @param {object} signal - Signal object
 * @returns {boolean} True if signal was recorded (not whitelisted)
 */
function recordSignal(signal) {
    if (!signal) return false;

    // Respect maxSignals limit
    if (currentConfig && currentConfig.performance.maxSignals) {
        if (signals.length >= currentConfig.performance.maxSignals) {
            return false;
        }
    }

    // Check whitelist — suppress signals from whitelisted packages at collection time
    if (signal.package && currentConfig && currentConfig.whitelist) {
        if (isWhitelisted(signal.package, signal.version, currentConfig.whitelist)) {
            return false;
        }
    }

    signals.push(signal);
    return true;
}

/**
 * Get all collected signals
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
    return calculateAllScores(signals, {
        deduplicate: currentConfig ? currentConfig.performance.deduplicateSignals !== false : true,
        packageThresholds: currentConfig ? currentConfig.packageThresholds : {},
        configThresholds: currentConfig ? currentConfig.thresholds : {}
    });
}

/**
 * Get current configuration
 * 
 * @returns {object} Current config
 */
function getConfig() {
    return currentConfig;
}

/**
 * Generate formatted report
 * 
 * @param {string} format - 'cli', 'json', or 'html'
 * @returns {string} Formatted report
 */
function generateReport(format = 'cli') {
    const scores = getTrustScores();

    if (format === 'json') {
        return jsonFormatter.formatReport(scores, signals);
    } else if (format === 'html') {
        return htmlFormatter.formatReport(scores, signals);
    } else {
        return cliFormatter.formatReport(scores, signals);
    }
}

/**
 * Enforce policy — check if any package exceeds risk thresholds.
 * Returns an object with enforcement results suitable for CI.
 * 
 * @returns {object} { passed: boolean, criticalPackages: [], message: string }
 */
function enforcePolicy() {
    const scores = getTrustScores();
    const critical = findCriticalPackages(scores, currentConfig);

    if (critical.length === 0) {
        return {
            passed: true,
            criticalPackages: [],
            message: 'All packages within acceptable risk thresholds'
        };
    }

    const pkgList = critical.map(p => `${p.name}@${p.version} (score: ${p.score})`).join(', ');
    return {
        passed: false,
        criticalPackages: critical,
        message: `POLICY VIOLATION: ${critical.length} package(s) exceed risk threshold: ${pkgList}`
    };
}

/**
 * Send alert webhook if critical packages found.
 * Uses raw https.request — zero external dependencies.
 * 
 * @param {string} url - Webhook URL
 * @param {Array} criticalPackages - Array of critical package results
 */
function sendAlertWebhook(url, criticalPackages) {
    if (!url) return;

    try {
        const https = require('https');
        const urlObj = new URL(url);

        const payload = JSON.stringify({
            source: 'bheeshma',
            severity: 'CRITICAL',
            timestamp: new Date().toISOString(),
            packages: criticalPackages.map(p => ({
                name: p.name,
                version: p.version,
                trustScore: p.score,
                riskLevel: p.riskLevel,
                signalCount: p.signalCount
            }))
        });

        const req = https.request({
            hostname: urlObj.hostname,
            port: urlObj.port || 443,
            path: urlObj.pathname + urlObj.search,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload)
            },
            timeout: 5000
        }, () => {
            // Best effort — don't block on response
        });

        req.on('error', () => {
            // Silently fail — webhook is best-effort
        });

        req.on('timeout', () => {
            req.destroy();
        });

        req.write(payload);
        req.end();
    } catch (err) {
        // Silently fail
    }
}

/**
 * Teardown BHEESHMA (remove all hooks)
 * 
 * @returns {object} { success: boolean, uninstalled: string[] }
 */
function teardown() {
    const uninstalled = [];
    const failed = [];

    if (envHook.uninstall()) uninstalled.push('envHook');
    else failed.push('envHook');

    if (fsHook.uninstall()) uninstalled.push('fsHook');
    else failed.push('fsHook');

    if (netHook.uninstall()) uninstalled.push('netHook');
    else failed.push('netHook');

    if (childProcHook.uninstall()) uninstalled.push('childProcHook');
    else failed.push('childProcHook');

    if (httpHook.uninstall()) uninstalled.push('httpHook');
    else failed.push('httpHook');

    if (dnsHook.uninstall()) uninstalled.push('dnsHook');
    else failed.push('dnsHook');

    hooksInstalled = false;
    signals.length = 0;

    return {
        success: true,
        uninstalled,
        failed: failed.length > 0 ? failed : undefined
    };
}

/**
 * Monitor a function execution
 * 
 * @param {Function} fn - Function to monitor
 * @param {object} options - { format: 'cli'|'json'|'html' }
 * @returns {Promise<object>} { result, report }
 */
async function monitor(fn, options = {}) {
    const initResult = init();

    if (!initResult.success) {
        throw new Error('Failed to initialize BHEESHMA hooks');
    }

    let result;
    let error;

    try {
        result = await Promise.resolve(fn());
    } catch (err) {
        error = err;
    }

    const report = generateReport(options.format || 'cli');

    if (error) throw error;

    return { result, report };
}

module.exports = {
    init,
    getSignals,
    getTrustScores,
    getConfig,
    generateReport,
    enforcePolicy,
    sendAlertWebhook,
    teardown,
    monitor,
    recordSignal
};
