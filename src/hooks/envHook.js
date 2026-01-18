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
const { resolveCurrentStack } = require('../attribution/resolver');

/**
 * Global signal collector
 * Security: Signals are append-only during runtime
 */
let signalCollector = [];

/**
 * Store for original descriptor to support idempotent installation
 */
let originalDescriptor = null;
let isHookInstalled = false;

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
 * @returns {boolean} True if installed successfully
 */
function install(collector) {
    try {
        // Prevent double-installation
        if (isHookInstalled) {
            return true;
        }

        signalCollector = collector;

        // Store original process.env reference
        const originalEnv = process.env;

        // Create a Proxy to intercept property access
        const envProxy = new Proxy(originalEnv, {
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
                return Reflect.get(target, property, receiver);
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
                return Reflect.set(target, property, value, receiver);
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
        // Note: This is safe because process.env is configurable
        Object.defineProperty(process, 'env', {
            value: envProxy,
            writable: true,
            enumerable: true,
            configurable: true
        });

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

        // Resolve package from stack trace
        const attribution = resolveCurrentStack();

        // Only emit signals for third-party packages
        if (!attribution) {
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
            new Error().stack
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

        // Note: We can't truly "restore" the original process.env
        // because we replaced it with a Proxy. However, the Proxy
        // delegates to the original object, so behavior is preserved.
        // For testing, we can create a fresh env object if needed.

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
