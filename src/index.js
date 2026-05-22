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
const vmHook = require('./hooks/vmHook');
const cryptoHook = require('./hooks/cryptoHook');
const { calculateAllScores, findCriticalPackages, findViolatingPackages, getRiskLevel } = require('./scoring/trustScore');
const cliFormatter = require('./output/cliFormatter');
const jsonFormatter = require('./output/jsonFormatter');
const htmlFormatter = require('./output/htmlFormatter');
const sarifFormatter = require('./output/sarifFormatter');
const { loadConfig, getDefaultConfig } = require('./config/configLoader');
const { analyzePatterns } = require('./patterns/patternMatcher');
const resolver = require('./attribution/resolver');
const isWhitelisted = resolver.isWhitelisted;
const getPackageFromStack = resolver.getPackageFromStack;
const clearResolverCache = resolver.clearCache;
const { mergeConfig, validateConfig } = require('./config/schema');
const detector = require('./obfuscation/detector');
const scanPackage = detector.scanPackage;
const clearScanCache = detector.clearScanCache;
const { loadBaseline, filterBaselineSignals } = require('./baseline/baselineManager');

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
 * Loaded behavioral baseline (from baselineManager.loadBaseline).
 * When non-null, matching signals are suppressed before scoring.
 */
let currentBaseline = null;

/**
 * Persistent log write stream (fs.WriteStream for NDJSON append).
 * null = disabled.
 */
let logStream = null;

/**
 * Dedup key → seen count, for sampling support.
 * Tracks how many times each unique behavior was seen so we can sample
 * duplicate signals when performance.sampleRate < 1.
 */
const seenDedupKeys = new Map();

/**
 * Snapshot of wrapped hook functions for tamper detection.
 * Maps 'module.method' → reference to our wrapper at install time.
 * If the reference no longer matches at report time, a HOOK_TAMPER
 * signal is injected.
 */
const hookSnapshots = new Map();

/**
 * Signal recorder proxy — passed to hooks instead of the raw array.
 * Intercepts .push() to enforce whitelist suppression and maxSignals limit
 * at the hook layer (not just at report time).
 *
 * Hooks call recorder.push(signal) just like they would on an array,
 * but the whitelist and maxSignals checks run BEFORE the signal is stored.
 * This makes the README claim true: "whitelisted packages are suppressed
 * at the hook layer — signals are never even recorded."
 */
function createSignalRecorder() {
    return {
        push(signal) {
            return recordSignal(signal);
        },
        get length() {
            return signals.length;
        }
    };
}

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

    // Create recorder proxy — hooks use this instead of raw signals array
    // so whitelist and maxSignals are enforced at push time
    const recorder = createSignalRecorder();

    // Install hooks sequentially based on configuration
    if (currentConfig.hooks.env && envHook.install(recorder, currentConfig)) {
        installed.push('envHook');
    } else if (currentConfig.hooks.env) {
        failed.push('envHook');
    }

    if (currentConfig.hooks.fs && fsHook.install(recorder, currentConfig)) {
        installed.push('fsHook');
    } else if (currentConfig.hooks.fs) {
        failed.push('fsHook');
    }

    if (currentConfig.hooks.net && netHook.install(recorder, currentConfig)) {
        installed.push('netHook');
    } else if (currentConfig.hooks.net) {
        failed.push('netHook');
    }

    if (currentConfig.hooks.childProcess && childProcHook.install(recorder, currentConfig)) {
        installed.push('childProcHook');
    } else if (currentConfig.hooks.childProcess) {
        failed.push('childProcHook');
    }

    if (currentConfig.hooks.http && httpHook.install(recorder, currentConfig)) {
        installed.push('httpHook');
    } else if (currentConfig.hooks.http) {
        failed.push('httpHook');
    }

    if (currentConfig.hooks.dns && dnsHook.install(recorder, currentConfig)) {
        installed.push('dnsHook');
    } else if (currentConfig.hooks.dns) {
        failed.push('dnsHook');
    }

    if (currentConfig.hooks.vm && vmHook.install(recorder, currentConfig)) {
        installed.push('vmHook');
    } else if (currentConfig.hooks.vm) {
        failed.push('vmHook');
    }

    if (currentConfig.hooks.crypto && cryptoHook.install(recorder, currentConfig)) {
        installed.push('cryptoHook');
    } else if (currentConfig.hooks.crypto) {
        failed.push('cryptoHook');
    }

    // Snapshot hook references for tamper detection
    snapshotHooks();

    // Load behavioral baseline if configured
    if (currentConfig.baselineFile) {
        currentBaseline = loadBaseline(currentConfig.baselineFile);
        if (currentBaseline) {
            console.error(`[BHEESHMA] Baseline loaded: ${Object.keys(currentBaseline.entries).length} known behaviors`);
        }
    }

    // Open persistent log file if configured
    if (currentConfig.logging && currentConfig.logging.logFile) {
        try {
            const fs = require('fs');
            logStream = fs.createWriteStream(currentConfig.logging.logFile, { flags: 'a', encoding: 'utf8' });
            logStream.on('error', () => { logStream = null; });
        } catch (err) {
            console.warn(`[BHEESHMA] Could not open log file: ${err.message}`);
        }
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
 * Snapshot key hook wrappers immediately after installation.
 * Called once by init() after all hooks are installed.
 */
function snapshotHooks() {
    try {
        hookSnapshots.clear();
        hookSnapshots.set('fs.readFile',     require('fs').readFile);
        hookSnapshots.set('fs.writeFile',    require('fs').writeFile);
        hookSnapshots.set('net.connect',     require('net').connect);
        hookSnapshots.set('http.request',    require('http').request);
        hookSnapshots.set('https.request',   require('https').request);
        hookSnapshots.set('dns.lookup',      require('dns').lookup);
    } catch (_) {}
}

/**
 * Check if any hooked functions have been replaced since installation.
 * Injects HOOK_TAMPER signals for each detected replacement.
 *
 * @param {Array} targetSignals - Signal array to push tamper signals into
 */
function checkHookTamper(targetSignals) {
    if (hookSnapshots.size === 0) return;

    const { createSignal, SignalType } = require('./signals/signalTypes');

    for (const [key, snapshot] of hookSnapshots.entries()) {
        try {
            const [moduleName, fnName] = key.split('.');
            const current = require(moduleName)[fnName];
            if (current !== snapshot) {
                targetSignals.push(createSignal(
                    SignalType.HOOK_TAMPER,
                    { hook: key, description: `Hook ${key} was replaced after bheeshma installation` },
                    'unknown',
                    'unknown',
                    new Error().stack
                ));
            }
        } catch (_) {}
    }
}

/**
 * Set up worker thread signal collection.
 *
 * Strategy: Intercept the Worker constructor so that every new worker gets
 * a message listener. Workers use parentPort.postMessage() to send signals;
 * the main thread receives them on worker.on('message').
 *
 * Note: process.on('message') only works when the main process itself was
 * spawned as a child. Worker threads communicate via the Worker object's
 * message event, not process.on('message').
 */
function setupWorkerSignalCollection() {
    try {
        const { Worker, isMainThread } = require('worker_threads');

        if (!isMainThread) {
            // This IS a worker thread — worker-bootstrap.js handles relay
            return;
        }

        // Intercept Worker constructor to attach message listeners
        const OriginalWorker = Worker;
        // eslint-disable-next-line no-global-assign
        const worker_threads = require('worker_threads');
        worker_threads.Worker = class BheeshmaWorker extends OriginalWorker {
            constructor(filename, options) {
                // Inject worker-bootstrap.js so hooks are reinstalled in the worker
                const execArgv = options && options.execArgv
                    ? [...options.execArgv]
                    : process.execArgv || [];
                const bootstrapPath = require('path').resolve(__dirname, 'worker-bootstrap.js');
                if (!execArgv.some(arg => arg.includes('worker-bootstrap'))) {
                    execArgv.push('--require', bootstrapPath);
                }

                super(filename, { ...options, execArgv });

                // Listen for signals from this worker
                this.on('message', (msg) => {
                    if (msg && msg.type === 'BHEESHMA_SIGNAL') {
                        if (msg.signal) {
                            // Single signal
                            signals.push(msg.signal);
                        } else if (msg.signals && Array.isArray(msg.signals)) {
                            // Batch of signals
                            for (const sig of msg.signals) {
                                signals.push(sig);
                            }
                        }
                    }
                });
            }
        };
    } catch (err) {
        // worker_threads not available (Node < 11.7)
    }
}

/**
 * Track which packages have been scanned for obfuscation.
 * Maps package name → boolean (true = scanned).
 * Scanning happens once per package, on first signal.
 */
const obfuscationScannedPackages = new Set();

/**
 * Add a signal to the collector, respecting whitelist and blacklist.
 * This is the centralized push point — all hooks should use this.
 *
 * Side effects:
 * - Whitelisted packages: signals are silently dropped
 * - Blacklisted packages: signal is recorded + a synthetic CRITICAL
 *   BLACKLISTED_PACKAGE signal is injected to guarantee maximum penalty
 * - First signal from a package triggers obfuscation scan (via setImmediate)
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

    // Sampling: probabilistically drop duplicate signals to reduce memory pressure.
    // First occurrence of any dedup key is always recorded regardless of sampleRate.
    const sampleRate = currentConfig && currentConfig.performance && currentConfig.performance.sampleRate != null
        ? currentConfig.performance.sampleRate : 1.0;
    if (sampleRate < 1.0 && signal.package) {
        const dedupKey = `${signal.package}:${signal.type}:${signal.metadata ? JSON.stringify(signal.metadata).slice(0, 64) : ''}`;
        const seen = seenDedupKeys.get(dedupKey) || 0;
        if (seen > 0 && Math.random() > sampleRate) {
            seenDedupKeys.set(dedupKey, seen + 1);
            return false;
        }
        seenDedupKeys.set(dedupKey, seen + 1);
    }

    signals.push(signal);

    // Append to persistent log file (NDJSON format)
    if (logStream) {
        try {
            logStream.write(JSON.stringify(signal) + '\n');
        } catch (_) {}
    }

    // Blacklist enforcement: blacklisted packages get a forced CRITICAL signal
    // This guarantees they hit trust score 0 regardless of actual behavior
    if (signal.package && currentConfig && currentConfig.blacklist) {
        if (currentConfig.blacklist.includes(signal.package)) {
            // Only inject once per blacklisted package
            const alreadyFlagged = signals.some(
                s => s.type === 'BLACKLISTED_PACKAGE' && s.package === signal.package
            );
            if (!alreadyFlagged) {
                signals.push({
                    type: 'BLACKLISTED_PACKAGE',
                    timestamp: signal.timestamp,
                    package: signal.package,
                    version: signal.version,
                    metadata: {
                        reason: `Package "${signal.package}" is on the blacklist`
                    }
                });
            }
        }
    }

    // Trigger obfuscation scan for new packages (once per package)
    if (signal.package && !obfuscationScannedPackages.has(signal.package)) {
        obfuscationScannedPackages.add(signal.package);
        // Run scan asynchronously (non-blocking) to avoid slowing the hooked call
        // Use setImmediate so the current hook call completes first
        setImmediate(() => {
            try {
                if (signal.stackTrace) {
                    const pkgAttribution = getPackageFromStack(signal.stackTrace);
                    if (pkgAttribution && pkgAttribution.path) {
                        // Pass the raw signals array directly (not the recorder)
                        // to avoid infinite recursion through recordSignal
                        scanPackage(signal.package, pkgAttribution.path, signals, currentConfig);
                    }
                }
            } catch (err) {
                // Obfuscation scan failure should never break anything
            }
        });
    }

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
 * When a baseline is loaded, signals matching known-good behaviors are
 * filtered out before scoring so only NEW behaviors affect the score.
 *
 * @returns {Map} Trust scores by package
 */
function getTrustScores() {
    const scoredSignals = currentBaseline
        ? filterBaselineSignals(signals, currentBaseline)
        : signals;

    return calculateAllScores(scoredSignals, {
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
 * Runs pattern analysis on all collected signals and includes results.
 * 
 * @param {string} format - 'cli', 'json', 'html', or 'sarif'
 * @returns {string} Formatted report
 */
function generateReport(format = 'cli') {
    // Check for hook tampering before scoring — injects HOOK_TAMPER signals if needed
    checkHookTamper(signals);

    const scores = getTrustScores();

    // Run pattern analysis on collected signals
    const patternConfig = currentConfig ? currentConfig.patterns : {};
    const patternResults = analyzePatterns(signals, patternConfig);

    if (format === 'json') {
        return jsonFormatter.formatReport(scores, signals, patternResults);
    } else if (format === 'html') {
        return htmlFormatter.formatReport(scores, signals, patternResults);
    } else if (format === 'sarif') {
        let toolVersion = '1.0.0';
        try {
            const pkgJson = require('../package.json');
            toolVersion = pkgJson.version;
        } catch (e) { /* use default */ }
        return sarifFormatter.formatReport(scores, signals, patternResults, { toolVersion });
    } else {
        return cliFormatter.formatReport(scores, signals, patternResults);
    }
}

/**
 * Enforce policy — check if any package exceeds risk thresholds.
 * Returns an object with enforcement results suitable for CI.
 *
 * @param {object} options - { failLevel: 'critical'|'high'|'medium'|'low' }
 * @returns {object} { passed: boolean, criticalPackages: [], message: string }
 */
function enforcePolicy(options = {}) {
    const failLevel = options.failLevel ||
        (currentConfig && currentConfig.enforce && currentConfig.failLevel) ||
        'critical';

    const scores = getTrustScores();
    const violating = findViolatingPackages(scores, failLevel);

    if (violating.length === 0) {
        return {
            passed: true,
            criticalPackages: [],
            message: 'All packages within acceptable risk thresholds'
        };
    }

    const pkgList = violating.map(p => `${p.name}@${p.version} (score: ${p.score})`).join(', ');
    return {
        passed: false,
        criticalPackages: violating,
        message: `POLICY VIOLATION: ${violating.length} package(s) exceed risk threshold [${failLevel}]: ${pkgList}`
    };
}

/**
 * Build a webhook payload in the requested format.
 *
 * Supported formats:
 *   generic   — { source, severity, timestamp, packages[] }
 *   slack     — Slack Block Kit message
 *   pagerduty — PagerDuty Events API v2
 *   teams     — Microsoft Teams Adaptive Card
 *
 * @param {string} format
 * @param {Array}  packages
 * @returns {object}
 */
function buildWebhookPayload(format, packages) {
    const ts = new Date().toISOString();
    const pkgLines = packages.map(p => `${p.name}@${p.version} score=${p.score} (${p.riskLevel})`);

    if (format === 'slack') {
        return {
            text: `*BHEESHMA ALERT* — ${packages.length} package(s) flagged`,
            blocks: [
                {
                    type: 'header',
                    text: { type: 'plain_text', text: `⚠️ BHEESHMA Supply-Chain Alert` }
                },
                {
                    type: 'section',
                    text: {
                        type: 'mrkdwn',
                        text: `*${packages.length} package(s) flagged at ${packages[0]?.riskLevel || 'HIGH'} or above:*\n` +
                              pkgLines.map(l => `• ${l}`).join('\n')
                    }
                },
                {
                    type: 'context',
                    elements: [{ type: 'mrkdwn', text: `Detected at ${ts}` }]
                }
            ]
        };
    }

    if (format === 'pagerduty') {
        return {
            routing_key: '',
            event_action: 'trigger',
            payload: {
                summary: `BHEESHMA: ${packages.length} supply-chain threat(s) detected`,
                severity: 'critical',
                timestamp: ts,
                custom_details: {
                    packages: packages.map(p => ({
                        name: p.name,
                        version: p.version,
                        trustScore: p.score,
                        riskLevel: p.riskLevel
                    }))
                }
            }
        };
    }

    if (format === 'teams') {
        return {
            '@type': 'MessageCard',
            '@context': 'http://schema.org/extensions',
            themeColor: 'FF0000',
            summary: `BHEESHMA: ${packages.length} supply-chain threat(s)`,
            sections: [{
                activityTitle: `⚠ BHEESHMA Supply-Chain Alert`,
                activitySubtitle: `${packages.length} package(s) flagged — ${ts}`,
                facts: packages.map(p => ({
                    name: `${p.name}@${p.version}`,
                    value: `Score: ${p.score} | Risk: ${p.riskLevel}`
                }))
            }]
        };
    }

    // generic (default)
    return {
        source: 'bheeshma',
        severity: packages[0]?.riskLevel || 'CRITICAL',
        timestamp: ts,
        packages: packages.map(p => ({
            name: p.name,
            version: p.version,
            trustScore: p.score,
            riskLevel: p.riskLevel,
            signalCount: p.signalCount
        }))
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
        const format = currentConfig && currentConfig.webhookFormat || 'generic';

        const payload = JSON.stringify(buildWebhookPayload(format, criticalPackages));

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

    if (vmHook.uninstall()) uninstalled.push('vmHook');
    else failed.push('vmHook');

    if (cryptoHook.uninstall()) uninstalled.push('cryptoHook');
    else failed.push('cryptoHook');

    if (logStream) {
        try { logStream.end(); } catch (_) {}
        logStream = null;
    }

    hooksInstalled = false;
    signals.length = 0;
    currentConfig = null;
    currentBaseline = null;
    seenDedupKeys.clear();
    hookSnapshots.clear();
    obfuscationScannedPackages.clear();
    clearResolverCache();
    clearScanCache();

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
    recordSignal,
    buildWebhookPayload
};
