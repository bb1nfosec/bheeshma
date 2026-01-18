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
const { getPackageFromStack } = require('../attribution/resolver');

let originalHttpRequest = null;
let originalHttpsRequest = null;
let signalsArray = null;

/**
 * Install HTTP/HTTPS monitoring hook
 * 
 * Intercepts http.request() and https.request() to capture outbound requests
 * 
 * @param {Array} signals - Global signals array
 * @returns {boolean} Success
 */
function install(signals) {
    if (!signals || !Array.isArray(signals)) {
        return false;
    }

    signalsArray = signals;

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
            // Capture stack trace for attribution
            const stack = new Error().stack;
            const attribution = getPackageFromStack(stack);

            // Create signal
            const signal = createSignal(
                isHttps ? SignalType.HTTPS_REQUEST : SignalType.HTTP_REQUEST,
                {
                    url: requestInfo.url,
                    method: requestInfo.method,
                    host: requestInfo.host,
                    port: requestInfo.port,
                    path: requestInfo.path,
                    headers: sanitizeHeaders(requestInfo.headers),
                    suspicious: analyzeSuspiciousness(requestInfo)
                },
                attribution.package,
                attribution.version,
                stack
            );

            signalsArray.push(signal);
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
 * Sanitize headers to remove sensitive information
 * 
 * @param {object} headers - Request headers
 * @returns {object} Sanitized headers (keys only, no values)
 */
function sanitizeHeaders(headers) {
    if (!headers || typeof headers !== 'object') {
        return {};
    }

    // Only return header names, not values (to avoid leaking auth tokens)
    const sanitized = {};
    for (const key of Object.keys(headers)) {
        const lowerKey = key.toLowerCase();
        if (lowerKey.includes('auth') || lowerKey.includes('token') || lowerKey.includes('key')) {
            sanitized[key] = '[REDACTED]';
        } else {
            sanitized[key] = '[PRESENT]';
        }
    }
    return sanitized;
}

/**
 * Analyze request for suspicious patterns
 * 
 * @param {object} requestInfo - Parsed request info
 * @returns {object} Suspiciousness analysis
 */
function analyzeSuspiciousness(requestInfo) {
    const suspicious = {
        isIpAddress: false,
        suspiciousTld: false,
        nonStandardPort: false,
        pastebinLike: false,
        indicators: []
    };

    // Check if host is an IP address
    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    if (ipPattern.test(requestInfo.host)) {
        suspicious.isIpAddress = true;
        suspicious.indicators.push('Direct IP request');
    }

    // Check for suspicious TLDs
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz'];
    if (suspiciousTlds.some(tld => requestInfo.host?.endsWith(tld))) {
        suspicious.suspiciousTld = true;
        suspicious.indicators.push('Suspicious TLD');
    }

    // Check for non-standard ports
    if (requestInfo.port !== 80 && requestInfo.port !== 443 && requestInfo.port !== 8080) {
        suspicious.nonStandardPort = true;
        suspicious.indicators.push(`Non-standard port: ${requestInfo.port}`);
    }

    // Check for pastebin-like services
    const pastebinHosts = ['pastebin.com', 'paste.ee', 'hastebin.com', 'dpaste.com'];
    if (pastebinHosts.some(host => requestInfo.host?.includes(host))) {
        suspicious.pastebinLike = true;
        suspicious.indicators.push('Pastebin-like service');
    }

    return suspicious;
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
