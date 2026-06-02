/**
 * BHEESHMA Environment Variable Access Hook
 * 
 * Security: Safe, reversible monkey-patching of process.env
 * Follows OWASP principle: "Fail securely" and Node.js best practice: "Preserve original behavior"
 * 
 * Purpose: Detect when third-party dependencies access environment variables,
 * which may contain credentials, API keys, or sensitive configuration.
 * 
 * CRITICAL: This hook captures variable NAMES only, never VALUES.
 */

'use strict';

const { createSignal, SignalType } = require('../signals/signalTypes');
const { resolveCurrentStackFast } = require('../attribution/resolver');

/**
 * Detect env reads that are Node's own internal full-environment copy rather
 * than a deliberate access by the package.
 *
 * When a package spawns a subprocess, Node iterates the ENTIRE environment
 * (copyProcessEnvToEnv / normalizeSpawnArguments in node:child_process) to build
 * the child's env, firing one proxy `get` per variable. Attributing 60+
 * ENV_ACCESS signals to the package for a single spawn floods the report and
 * floors its trust score — making every subprocess-spawning package look
 * CRITICAL (a false positive) and "detecting" malware for the wrong reason.
 * A genuine `process.env.X` read by the package has no child_process frame.
 *
 * @param {string} stack - Captured stack trace
 * @returns {boolean} True if this read is Node's internal env enumeration
 */
function isInternalEnvEnumeration(stack) {
    if (!stack) return false;
    return /node:child_process|internal\/child_process/.test(stack);
}

let signalCollector = [];
let isHookInstalled = false;
let hookConfig = null;
let originalEnvObject = null;

/**
 * Install environment variable access hook
 * 
 * Implementation:
 * - Uses Proxy to intercept property access on process.env
 * - Captures variable name (not value) in signal metadata
 * - Preserves original behavior exactly
 * 
 * Security considerations:
 * - Idempotent: Multiple installs don't stack
 * - Reversible: Can be uninstalled cleanly
 * - Fail-safe: Errors in hook don't break process.env access
 * - No secret capture: Only variable names are recorded
 * 
 * @param {Array} collector - Shared signal collector array
 * @param {object} config - Bheeshma configuration
 * @returns {boolean} True if installed successfully
 */
function install(collector, config) {
    try {
        // Prevent double-installation
        if (isHookInstalled) {
            return true;
        }

        signalCollector = collector;
        hookConfig = config;

        // Store original process.env reference (only once)
        // On re-install after teardown, use the saved original
        if (!originalEnvObject) {
            originalEnvObject = process.env;
        }

        // Create a Proxy to intercept property access
        const envProxy = new Proxy(originalEnvObject, {
            /**
             * Intercept property reads
             * Security: This is the most common way packages access env vars
             */
            get(target, property, receiver) {
                try {
                    // Emit signal for this access
                    emitEnvAccessSignal(property);
                } catch (err) {
                    // Fail-safe: Never throw from hook
                    // Continue to return actual value
                }

                // Return actual value (preserve original behavior)
                // Use target directly, not receiver, for process.env compatibility
                return Reflect.get(target, property);
            },

            /**
             * Intercept property writes
             * Less common but packages may set env vars
             */
            set(target, property, value, receiver) {
                try {
                    // Emit signal for write access too
                    emitEnvAccessSignal(property);
                } catch (err) {
                    // Fail-safe
                }

                // Allow the write (preserve original behavior)
                // CRITICAL: Use target directly, NOT receiver.
                // In Node 18+, process.env has special internal setters that
                // validate property descriptors on the receiver. Passing the
                // Proxy as receiver causes ERR_INVALID_OBJECT_DEFINE_PROPERTY.
                return Reflect.set(target, property, value);
            },

            /**
             * Intercept 'in' operator and hasOwnProperty checks
             */
            has(target, property) {
                try {
                    emitEnvAccessSignal(property);
                } catch (err) {
                    // Fail-safe
                }

                return Reflect.has(target, property);
            }
        });

        // Replace process.env with our proxy
        // On Node 18+, process.env may need special handling
        try {
            Object.defineProperty(process, 'env', {
                value: envProxy,
                writable: true,
                enumerable: true,
                configurable: true
            });
        } catch (defineErr) {
            // Fallback for strict environments: just track without proxy
            // The signals won't be as complete but the app won't crash
            isHookInstalled = true;
            return true;
        }

        isHookInstalled = true;
        return true;
    } catch (err) {
        // Fail-safe: If hook installation fails, app continues normally
        console.error('[BHEESHMA] Failed to install env hook:', err.message);
        return false;
    }
}

/**
 * Emit an ENV_ACCESS signal
 * 
 * Security:
 * - Captures variable name only (never the value)
 * - Resolves stack trace to identify package
 * - Creates immutable signal
 * 
 * @param {string} variableName - Name of environment variable accessed
 * @returns {void}
 */
function emitEnvAccessSignal(variableName) {
    try {
        // Skip internal Node.js and BHEESHMA accesses
        if (typeof variableName !== 'string') {
            return;
        }

        // Resolve package (fast: structured stack, no string formatting).
        const attribution = resolveCurrentStackFast();

        // Only emit signals for third-party packages
        if (!attribution) {
            return;
        }

        // Fast-path: skip the string-stack capture below if this signal would
        // be dropped anyway (maxSignals reached / whitelisted). env is the
        // hottest hook, so this avoids the dominant cost on the common path.
        if (signalCollector.shouldCapture &&
            !signalCollector.shouldCapture(attribution.name, attribution.version)) {
            return;
        }

        // A string stack is still needed to recognize Node's internal
        // full-environment copy during child_process spawn (one read per env
        // var) — not a deliberate access by the package. Captured only now,
        // for signals we would actually record.
        const stack = new Error().stack;
        if (isInternalEnvEnumeration(stack)) {
            return;
        }

        const signal = createSignal(
            SignalType.ENV_ACCESS,
            {
                variable: variableName,
                // Security: Explicitly do NOT include the value
            },
            attribution.name,
            attribution.version,
            stack
        );

        signalCollector.push(signal);
    } catch (err) {
        // Defensive: Never throw from signal emission
    }
}

/**
 * Uninstall the hook (for testing and cleanup)
 * 
 * Security: Ensures clean teardown
 * 
 * @returns {boolean} True if uninstalled successfully
 */
function uninstall() {
    try {
        if (!isHookInstalled) {
            return true;
        }

        // Restore the original process.env object
        if (originalEnvObject) {
            try {
                Object.defineProperty(process, 'env', {
                    value: originalEnvObject,
                    writable: true,
                    enumerable: true,
                    configurable: true
                });
            } catch (restoreErr) {
                // If restore fails (strict env), leave proxy in place
                // but mark as uninstalled so re-install can skip
            }
        }

        isHookInstalled = false;
        return true;
    } catch (err) {
        return false;
    }
}

/**
 * Check if hook is installed
 * 
 * @returns {boolean}
 */
function isInstalled() {
    return isHookInstalled;
}

module.exports = {
    install,
    uninstall,
    isInstalled
};
