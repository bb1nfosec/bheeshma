/**
 * BHEESHMA ESM Loader Hook
 *
 * Intercepts ES module imports via Node.js --loader API.
 * Records every third-party ESM import and resolves package attribution.
 *
 * Usage: node --loader bheeshma/src/esm-loader.mjs app.mjs
 *
 * Supports ESM-only packages invisible to the require() hooks:
 * got v12+, node-fetch v3+, chalk v5+, execa v6+, p-limit v4+, etc.
 *
 * Implementation notes:
 * - Must use createRequire to load CJS modules from ESM context
 * - process.bheeshmaSignals / process.bheeshmaConfig are set by the CLI
 *   before the child process launches, giving this loader a shared channel
 */

import { createRequire } from 'module';
import { fileURLToPath } from 'url';

const require = createRequire(import.meta.url);

// Lazy-load CJS signal infrastructure to avoid circular init issues
let _infra = null;
function infra() {
    if (_infra) return _infra;
    const { createSignal, SignalType } = require('./signals/signalTypes.js');
    const { getPackageFromStack, isWhitelisted } = require('./attribution/resolver.js');
    _infra = { createSignal, SignalType, getPackageFromStack, isWhitelisted };
    return _infra;
}

function getSignalCollector() {
    if (!process.bheeshmaSignals) process.bheeshmaSignals = [];
    return process.bheeshmaSignals;
}

function getConfig() {
    return process.bheeshmaConfig || null;
}

/**
 * resolve hook — intercepts every import specifier.
 * Fires before the module is loaded, letting us record the import attempt.
 */
export async function resolve(specifier, context, nextResolve) {
    try {
        const result = await nextResolve(specifier, context);

        if (result && result.url && result.url.includes('node_modules')) {
            const stack = new Error().stack;
            const { getPackageFromStack, isWhitelisted, createSignal, SignalType } = infra();
            const attribution = getPackageFromStack(stack);

            if (attribution) {
                const config = getConfig();

                // Respect whitelist — same as CJS hooks
                if (config && config.whitelist &&
                    isWhitelisted(attribution.name, attribution.version, config.whitelist)) {
                    return result;
                }

                const filePath = result.url.startsWith('file://')
                    ? fileURLToPath(result.url)
                    : result.url;

                const signal = createSignal(
                    SignalType.FS_READ,
                    {
                        path: filePath,
                        operation: 'esm_import',
                        specifier,
                        format: result.format || 'unknown'
                    },
                    attribution.name,
                    attribution.version,
                    stack
                );

                getSignalCollector().push(signal);
            }
        }

        return result;
    } catch (_err) {
        // Fail-safe: never block the import
        return nextResolve(specifier, context);
    }
}

/**
 * load hook — pass-through.
 * All interception is done in resolve; we don't need to modify source.
 */
export async function load(url, context, nextLoad) {
    return nextLoad(url, context);
}
