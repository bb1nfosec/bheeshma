/**
 * BHEESHMA ESM Loader Hook
 * 
 * Intercepts ES module imports via Node.js --loader API.
 * Records every ESM import and resolves package attribution
 * before calling the original loader.
 * 
 * Usage: node --loader bheeshma/src/esm-loader.mjs app.js
 * 
 * This makes Bheeshma compatible with pure ESM packages
 * (got, node-fetch v3+, chalk v5+, execa v6+, etc.)
 * which are invisible to the require() hook approach.
 */

'use strict';

// ESM loader API — this file must be .mjs
const { resolve, load, getFormat } = require('module');

// Import the signal infrastructure from CJS
const { createSignal, SignalType } = require('./signals/signalTypes');
const { getPackageFromStack, isWhitelisted } = require('./attribution/resolver');

// Global signal store — shared with CJS hooks
// We access the main module's signals array via process.bheeshmaSignals
function getSignalCollector() {
    if (process.bheeshmaSignals) {
        return process.bheeshmaSignals;
    }
    // Initialize if not set
    process.bheeshmaSignals = [];
    return process.bheeshmaSignals;
}

function getConfig() {
    return process.bheeshmaConfig || null;
}

/**
 * Resolve hook — intercepts every import URL
 */
export async function resolve(specifier, context, nextResolve) {
    try {
        const url = await nextResolve(specifier, context);

        // Check if the resolved URL is inside node_modules
        if (url && url.url && url.url.includes('node_modules')) {
            const stack = new Error().stack;
            const attribution = getPackageFromStack(stack);

            if (attribution) {
                const config = getConfig();
                // Check whitelist
                if (config && config.whitelist) {
                    const { isWhitelisted } = require('./attribution/resolver');
                    if (isWhitelisted(attribution.name, attribution.version, config.whitelist)) {
                        return url;
                    }
                }

                const signals = getSignalCollector();

                // Create an ESM_IMPORT signal — we use FS_READ as the closest analog
                // since ESM loading is a form of file system access
                const signal = createSignal(
                    SignalType.FS_READ,
                    {
                        path: url.url.replace('file://', ''),
                        operation: 'esm_import',
                        specifier: specifier,
                        format: url.format || 'unknown'
                    },
                    attribution.name,
                    attribution.version,
                    stack
                );

                signals.push(signal);
            }
        }

        return url;
    } catch (err) {
        // Fail-safe: pass through to original loader
        return nextResolve(specifier, context);
    }
}

/**
 * Load hook — intercepts module loading
 */
export async function load(url, context, nextLoad) {
    // Just pass through to original loader
    // All interception happens in resolve
    return nextLoad(url, context);
}
