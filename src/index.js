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

    // Seed the async attribution context at module-load time so behavior
    // deferred across async boundaries is still attributed to the right package.
    installModuleContextHook();

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
 * Original Module._load, saved so teardown() can restore it.
 */
let originalModuleLoad = null;

/**
 * Seed the async attribution context by wrapping Module._load.
 *
 * When a file inside node_modules is loaded, we resolve which package owns it
 * and run the load within that package's async context (resolver context store).
 * Because AsyncLocalStorage propagates across timers, promises, and I/O
 * callbacks, any work the module schedules during initialization stays
 * attributed to it — even when the synchronous stack has unwound. Hooks still
 * prefer live-stack attribution; this only fills the gap when the stack can't.
 *
 * Heavily guarded: resolution failures fall through to the original loader,
 * and core/builtin requires (no node_modules in the path) take the fast path.
 */
function installModuleContextHook() {
    try {
        if (originalModuleLoad) return;
        const Module = require('module');
        originalModuleLoad = Module._load;

        Module._load = function (request, parent, isMain) {
            let pkg = null;
            try {
                const filename = Module._resolveFilename(request, parent, isMain);
                if (typeof filename === 'string' && filename.indexOf('node_modules') !== -1) {
                    pkg = resolver.getPackageFromPath(filename);
                }
            } catch (err) {
                // Resolution can throw for unresolvable specifiers — fall through.
            }

            if (pkg) {
                return resolver.runWithPackageContext(
                    pkg,
                    () => originalModuleLoad.call(this, request, parent, isMain)
                );
            }
            return originalModuleLoad.call(this, request, parent, isMain);
        };
    } catch (err) {
        // Never let context seeding break module loading.
        originalModuleLoad = null;
    }
}

/**
 * Restore the original Module._load (used by teardown).
 */
function uninstallModuleContextHook() {
    try {
        if (originalModuleLoad) {
            require('module')._load = originalModuleLoad;
            originalModuleLoad = null;
        }
    } catch (err) {
        // Best effort.
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

    signals.push(signal);

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
 * @returns {Map} Trust scores by package
 */
function getTrustScores() {
    // Run correlated-pattern analysis so trust scores (and therefore policy
    // enforcement, not just the report) reflect exfil/backdoor/crypto/etc.
    const patternResults = analyzePatterns(signals, currentConfig ? currentConfig.patterns : {});
    return calculateAllScores(signals, {
        deduplicate: currentConfig ? currentConfig.performance.deduplicateSignals !== false : true,
        packageThresholds: currentConfig ? currentConfig.packageThresholds : {},
        configThresholds: currentConfig ? currentConfig.thresholds : {},
        patternResults
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

    uninstallModuleContextHook();

    hooksInstalled = false;
    signals.length = 0;
    currentConfig = null;
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
    recordSignal
};
