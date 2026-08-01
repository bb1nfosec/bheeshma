/**
 * BHEESHMA HTTP/HTTPS Hook
 * 
 * Monitors outbound HTTP/HTTPS requests to detect data exfiltration
 * and suspicious network activity.
 * 
 * Security: This is CRITICAL for detecting supply chain attacks
 * as most malicious packages exfiltrate data via HTTP(S).
 */

'use strict';

const http = require('http');
const https = require('https');
const { createSignal, SignalType } = require('../signals/signalTypes');
const { resolveCurrentStackFast } = require('../attribution/resolver');
const { sanitizeHeaders, analyzeSuspiciousness } = require('../analysis/httpAnalysis');

let originalHttpRequest = null;
let originalHttpsRequest = null;
let originalHttpGet = null;
let originalHttpsGet = null;
let signalsArray = null;
let hookConfig = null;

/**
 * Install HTTP/HTTPS monitoring hook
 * 
 * Intercepts http.request() and https.request() to capture outbound requests
 * 
 * @param {Array} signals - Global signals array
 * @returns {boolean} Success
 */
function install(signals, config) {
    if (!signals || (typeof signals !== 'object')) {
        return false;
    }

    signalsArray = signals;
    hookConfig = config;

    try {
        // Hook http.request
        if (!originalHttpRequest) {
            originalHttpRequest = http.request;
            http.request = createHttpRequestHook(originalHttpRequest, false);
        }

        // Hook https.request
        if (!originalHttpsRequest) {
            originalHttpsRequest = https.request;
            https.request = createHttpRequestHook(originalHttpsRequest, true);
        }

        // Hook http.get / https.get separately.
        // CRITICAL: in Node core, http.get() calls the *internal* request
        // function, not the exported http.request we patched above — so
        // patching request alone leaves every .get() call (a huge share of
        // real-world traffic and a common exfil/beacon path) completely
        // unmonitored. We wrap get() directly. No double-counting: the
        // original get() does not route back through our patched request.
        if (!originalHttpGet) {
            originalHttpGet = http.get;
            http.get = createHttpRequestHook(originalHttpGet, false);
        }
        if (!originalHttpsGet) {
            originalHttpsGet = https.get;
            https.get = createHttpRequestHook(originalHttpsGet, true);
        }

        return true;
    } catch (err) {
        console.error('[BHEESHMA] HTTP hook installation failed:', err.message);
        return false;
    }
}

/**
 * Create a request hook for HTTP or HTTPS
 * 
 * @param {Function} original - Original request function
 * @param {boolean} isHttps - Whether this is HTTPS
 * @returns {Function} Hooked request function
 */
function createHttpRequestHook(original, isHttps) {
    return function (...args) {
        // Parse request arguments
        const requestInfo = parseRequestArgs(args, isHttps);

        if (requestInfo) {
            // Resolve attribution (fast: structured stack, no string formatting;
            // async-aware fallback to the async context when frames have unwound).
            const attribution = resolveCurrentStackFast();

            // Only record signals for third-party packages, and only when the
            // signal would actually be kept (skip stack capture + analysis on
            // the dropped path).
            if (attribution &&
                (!signalsArray.shouldCapture ||
                 signalsArray.shouldCapture(attribution.name, attribution.version))) {
                const stack = new Error().stack;
                const signal = createSignal(
                    isHttps ? SignalType.HTTPS_REQUEST : SignalType.HTTP_REQUEST,
                    {
                        url: requestInfo.url,
                        method: requestInfo.method,
                        host: requestInfo.host,
                        port: requestInfo.port,
                        path: requestInfo.path,
                        headers: sanitizeHeaders(requestInfo.headers),
                        via: 'http-module',
                        suspicious: analyzeSuspiciousness(requestInfo)
                    },
                    attribution.name,
                    attribution.version,
                    stack
                );

                signalsArray.push(signal);
            }
        }

        // Call original function
        return original.apply(this, args);
    };
}

/**
 * Parse request arguments into normalized format
 * 
 * @param {Array} args - Arguments passed to request()
 * @param {boolean} isHttps - Whether this is HTTPS
 * @returns {object} Parsed request info
 */
function parseRequestArgs(args, isHttps) {
    let url, options;

    // http.request() can be called with various signatures
    if (typeof args[0] === 'string') {
        url = args[0];
        options = args[1] || {};
    } else if (args[0] instanceof URL) {
        url = args[0].href;
        options = args[1] || {};
    } else if (typeof args[0] === 'object') {
        options = args[0];
        url = buildUrlFromOptions(options, isHttps);
    } else {
        return null;
    }

    return {
        url,
        method: (options.method || 'GET').toUpperCase(),
        host: options.host || options.hostname,
        port: options.port || (isHttps ? 443 : 80),
        path: options.path || '/',
        headers: options.headers || {}
    };
}

/**
 * Build URL from options object
 * 
 * @param {object} options - Request options
 * @param {boolean} isHttps - Whether this is HTTPS
 * @returns {string} Full URL
 */
function buildUrlFromOptions(options, isHttps) {
    const protocol = isHttps ? 'https:' : 'http:';
    const host = options.host || options.hostname || 'localhost';
    const port = options.port || (isHttps ? 443 : 80);
    const path = options.path || '/';

    const defaultPort = isHttps ? 443 : 80;
    const portPart = (port === defaultPort) ? '' : `:${port}`;

    return `${protocol}//${host}${portPart}${path}`;
}

/**
 * Uninstall HTTP/HTTPS hook
 * 
 * @returns {boolean} Success
 */
function uninstall() {
    try {
        if (originalHttpRequest) {
            http.request = originalHttpRequest;
            originalHttpRequest = null;
        }

        if (originalHttpsRequest) {
            https.request = originalHttpsRequest;
            originalHttpsRequest = null;
        }

        if (originalHttpGet) {
            http.get = originalHttpGet;
            originalHttpGet = null;
        }

        if (originalHttpsGet) {
            https.get = originalHttpsGet;
            originalHttpsGet = null;
        }

        signalsArray = null;
        return true;
    } catch (err) {
        return false;
    }
}

module.exports = {
    install,
    uninstall
};
