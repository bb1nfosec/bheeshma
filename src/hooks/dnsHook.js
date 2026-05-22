/**
 * BHEESHMA DNS Monitoring Hook
 *
 * Monitors DNS resolution to detect DNS tunneling and data exfiltration.
 * DNS tunneling encodes data in subdomains (e.g. c2-payload.evil.io) and
 * bypasses HTTP-level monitoring because it occurs at the resolver level.
 *
 * Covers both callback-based dns.* API and the promises-based dns.promises.*
 * API (Node 10+), which are separate JS implementations over the same C++ bindings.
 *
 * Wrapped functions:
 *   Callback: lookup, resolve, resolve4, resolve6, resolveTxt, resolveMx,
 *             resolveCname, resolveNs, resolveSrv, resolveCaa, resolveNaptr,
 *             resolvePtr, reverse
 *   Promises: same set via dns.promises.*
 */

'use strict';

const dns = require('dns');
const { createSignal, SignalType } = require('../signals/signalTypes');
const { resolveCurrentStack } = require('../attribution/resolver');

let signalCollector = [];
let hookConfig = null;
let isHookInstalled = false;

const originalCallbacks = {};
const originalPromises = {};

/**
 * Known exfiltration DNS services.
 * ngrok.io, localtunnel.me, canarytokens.com excluded — legitimate dev/defensive tools.
 */
const KNOWN_EXFIL_DOMAINS = [
    'dnshook.site',
    'requestbin.com',
    'webhook.site',
    'pipedream.com'
];

/**
 * Callback-based DNS functions to hook.
 * 'reverse' takes an IP address as first arg — still worth monitoring.
 */
const CALLBACK_FUNCTIONS = [
    'lookup',
    'resolve',
    'resolve4',
    'resolve6',
    'resolveTxt',
    'resolveMx',
    'resolveCname',
    'resolveNs',
    'resolveSrv',
    'resolveCaa',
    'resolveNaptr',
    'resolvePtr',
    'reverse'
];

/**
 * Install DNS monitoring hooks (callback + promises API).
 *
 * @param {object} collector - Signal recorder (has .push())
 * @param {object} config - Bheeshma configuration
 * @returns {boolean} True if installed successfully
 */
function install(collector, config) {
    try {
        if (isHookInstalled) return true;

        signalCollector = collector;
        hookConfig = config;

        // Hook callback-based API
        for (const fnName of CALLBACK_FUNCTIONS) {
            hookCallbackFunction(fnName);
        }

        // Hook dns.promises API (Node 10+)
        if (dns.promises && typeof dns.promises === 'object') {
            for (const fnName of CALLBACK_FUNCTIONS) {
                hookPromiseFunction(fnName);
            }
        }

        isHookInstalled = true;
        return true;
    } catch (err) {
        console.error('[BHEESHMA] Failed to install DNS hook:', err.message);
        return false;
    }
}

/**
 * Hook one callback-based dns.* function.
 */
function hookCallbackFunction(fnName) {
    if (typeof dns[fnName] !== 'function') return;
    if (originalCallbacks[fnName]) return;

    originalCallbacks[fnName] = dns[fnName];

    dns[fnName] = function (...args) {
        try {
            const hostname = args[0];
            if (typeof hostname === 'string' && hostname.length > 0) {
                emitDnsSignal(hostname, fnName);
            }
        } catch (_err) {
            // Fail-safe
        }
        return originalCallbacks[fnName].apply(this, args);
    };

    Object.defineProperty(dns[fnName], 'name', { value: fnName, configurable: true });
}

/**
 * Hook one dns.promises.* function.
 */
function hookPromiseFunction(fnName) {
    if (!dns.promises || typeof dns.promises[fnName] !== 'function') return;
    if (originalPromises[fnName]) return;

    originalPromises[fnName] = dns.promises[fnName];

    dns.promises[fnName] = async function (...args) {
        try {
            const hostname = args[0];
            if (typeof hostname === 'string' && hostname.length > 0) {
                emitDnsSignal(hostname, `promises.${fnName}`);
            }
        } catch (_err) {
            // Fail-safe
        }
        return originalPromises[fnName].apply(this, args);
    };

    Object.defineProperty(dns.promises[fnName], 'name', {
        value: fnName,
        configurable: true
    });
}

/**
 * Emit a DNS_QUERY signal with tunneling/exfil analysis.
 */
function emitDnsSignal(hostname, calledFunction) {
    try {
        const attribution = resolveCurrentStack();
        if (!attribution) return;

        const analysis = analyzeHostname(hostname);

        const signal = createSignal(
            SignalType.DNS_QUERY,
            {
                hostname,
                function: calledFunction,
                isIpAddress: analysis.isIpAddress,
                suspiciousSubdomainLength: analysis.suspiciousSubdomainLength,
                highEntropySubdomain: analysis.highEntropySubdomain,
                knownExfilService: analysis.knownExfilService,
                base64InSubdomain: analysis.base64InSubdomain,
                hexInSubdomain: analysis.hexInSubdomain,
                indicators: analysis.indicators
            },
            attribution.name,
            attribution.version,
            new Error().stack
        );

        signalCollector.push(signal);
    } catch (_err) {
        // Defensive
    }
}

/**
 * Analyze a hostname for DNS tunneling and exfiltration patterns.
 *
 * Checks:
 * 1. IP address (not useful for tunneling detection — return early)
 * 2. Known exfil services (exact match or *.service)
 * 3. Abnormally long subdomain labels (>50 chars = likely encoded data)
 * 4. High Shannon entropy (>4.0 bits = likely Base64/hex encoded payload)
 * 5. Base64 character set in subdomain label (length >16)
 * 6. Hex-encoded subdomain label (length >20)
 *
 * @param {string} hostname - Hostname to analyze
 * @returns {object} Analysis result with indicators array
 */
function analyzeHostname(hostname) {
    const analysis = {
        isIpAddress: false,
        suspiciousSubdomainLength: false,
        highEntropySubdomain: false,
        knownExfilService: false,
        base64InSubdomain: false,
        hexInSubdomain: false,
        indicators: []
    };

    // IPv4 — skip tunneling analysis
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
        analysis.isIpAddress = true;
        return analysis;
    }

    // Known exfil services (full-domain or subdomain match)
    for (const exfilDomain of KNOWN_EXFIL_DOMAINS) {
        if (hostname === exfilDomain || hostname.endsWith('.' + exfilDomain)) {
            analysis.knownExfilService = true;
            analysis.indicators.push(`Known exfil service: ${exfilDomain}`);
        }
    }

    const parts = hostname.split('.');

    // Analyze each label except the TLD
    for (let i = 0; i < parts.length - 1; i++) {
        const label = parts[i];

        if (label.length > 50) {
            analysis.suspiciousSubdomainLength = true;
            analysis.indicators.push(`Abnormally long subdomain label: ${label.length} chars`);
        }

        if (label.length > 10) {
            const entropy = shannonEntropy(label);
            if (entropy > 4.0) {
                analysis.highEntropySubdomain = true;
                analysis.indicators.push(`High-entropy subdomain (${entropy.toFixed(2)} bits)`);
            }
        }

        if (label.length > 16 && /^[A-Za-z0-9+/=]+$/.test(label)) {
            analysis.base64InSubdomain = true;
            analysis.indicators.push('Base64-like characters in subdomain label');
        }

        if (label.length > 20 && /^[0-9a-fA-F]+$/.test(label)) {
            analysis.hexInSubdomain = true;
            analysis.indicators.push('Hex-encoded subdomain label');
        }
    }

    return analysis;
}

/**
 * Calculate Shannon entropy (bits) of a string.
 * Higher entropy → more random → more likely encoded data.
 *
 * @param {string} str
 * @returns {number}
 */
function shannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    let entropy = 0;
    const len = str.length;
    for (const count of Object.values(freq)) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

/**
 * Uninstall DNS hooks (both callback and promises API).
 *
 * @returns {boolean} Success
 */
function uninstall() {
    try {
        if (!isHookInstalled) return true;

        for (const [fnName, originalFn] of Object.entries(originalCallbacks)) {
            if (originalFn) dns[fnName] = originalFn;
        }

        if (dns.promises) {
            for (const [fnName, originalFn] of Object.entries(originalPromises)) {
                if (originalFn) dns.promises[fnName] = originalFn;
            }
        }

        isHookInstalled = false;
        signalCollector = null;
        hookConfig = null;
        return true;
    } catch (_err) {
        return false;
    }
}

module.exports = { install, uninstall };
