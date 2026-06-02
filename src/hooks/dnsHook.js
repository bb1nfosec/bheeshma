/**
 * BHEESHMA DNS Monitoring Hook
 * 
 * Security: Monitors DNS resolution to detect DNS tunneling and data exfiltration.
 * DNS tunneling encodes data in subdomains (e.g., c2-payload.evil.io) and bypasses
 * HTTP-level monitoring because it happens at the resolver level before TCP.
 * 
 * Wraps: dns.lookup, dns.resolve, dns.resolve4, dns.resolve6, dns.resolveTxt
 */

'use strict';

const dns = require('dns');
const { createSignal, SignalType } = require('../signals/signalTypes');
const { resolveCurrentStack } = require('../attribution/resolver');

let signalCollector = [];
let hookConfig = null;
let isHookInstalled = false;

const originalFunctions = {
    lookup: null,
    resolve: null,
    resolve4: null,
    resolve6: null,
    resolveTxt: null
};

/**
 * Known exfiltration DNS services
 * NOTE: ngrok.io and localtunnel.me are EXCLUDED — they are legitimate
 * dev tools, not exfil services. canarytokens.com is EXCLUDED — it's a
 * DEFENSIVE tool, not an attack tool.
 */
const KNOWN_EXFIL_DOMAINS = [
    'dnshook.site',
    'requestbin.com',
    'webhook.site',
    'pipedream.com'
];

/**
 * Install DNS monitoring hook
 * 
 * @param {Array} collector - Shared signal collector
 * @param {object} config - Bheeshma configuration
 * @returns {boolean} True if installed successfully
 */
function install(collector, config) {
    try {
        if (isHookInstalled) return true;

        signalCollector = collector;
        hookConfig = config;

        // Hook each DNS function
        hookDnsFunction('lookup');
        hookDnsFunction('resolve');
        hookDnsFunction('resolve4');
        hookDnsFunction('resolve6');
        hookDnsFunction('resolveTxt');

        isHookInstalled = true;
        return true;
    } catch (err) {
        console.error('[BHEESHMA] Failed to install DNS hook:', err.message);
        return false;
    }
}

/**
 * Hook a single DNS function
 * 
 * @param {string} fnName - DNS function name
 */
function hookDnsFunction(fnName) {
    if (typeof dns[fnName] !== 'function') return;
    if (originalFunctions[fnName]) return; // Already hooked

    originalFunctions[fnName] = dns[fnName];

    dns[fnName] = function (...args) {
        try {
            const hostname = args[0];
            if (typeof hostname === 'string' && hostname.length > 0) {
                emitDnsSignal(hostname, fnName);
            }
        } catch (err) {
            // Fail-safe
        }

        return originalFunctions[fnName].apply(this, args);
    };

    Object.defineProperty(dns[fnName], 'name', {
        value: fnName,
        configurable: true
    });
}

/**
 * Emit a DNS query signal with tunneling/exfil analysis
 * 
 * @param {string} hostname - Queried hostname
 * @param {string} function_ - DNS function that was called
 */
function emitDnsSignal(hostname, function_) {
    try {
        const attribution = resolveCurrentStack();
        if (!attribution) return;

        // Note: Whitelist checking is handled centrally by the signal recorder
        // in index.js (createSignalRecorder) — no need to check here.

        const analysis = analyzeHostname(hostname);

        const signal = createSignal(
            SignalType.DNS_QUERY,
            {
                hostname: hostname,
                function: function_,
                // Analysis results
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
    } catch (err) {
        // Defensive
    }
}

/**
 * Analyze a hostname for DNS tunneling and exfiltration patterns
 * 
 * Checks:
 * 1. Abnormally long subdomains (>50 chars, indicating encoded data)
 * 2. High-entropy subdomains (Base64/hex encoded data)
 * 3. Known exfiltration services
 * 4. Base64 character patterns in domain labels
 * 5. Hex-encoded subdomains
 * 
 * @param {string} hostname - Hostname to analyze
 * @returns {object} Analysis results
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

    // Check if it's an IP address (not useful for DNS tunneling detection)
    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    if (ipPattern.test(hostname)) {
        analysis.isIpAddress = true;
        return analysis;
    }

    // Extract subdomain parts
    const parts = hostname.split('.');

    // Check known exfil services (match against domain end, not substring)
    for (const exfilDomain of KNOWN_EXFIL_DOMAINS) {
        if (hostname === exfilDomain || hostname.endsWith('.' + exfilDomain)) {
            analysis.knownExfilService = true;
            analysis.indicators.push(`Known exfil service: ${exfilDomain}`);
        }
    }

    // Analyze each subdomain label
    for (let i = 0; i < parts.length - 1; i++) { // Skip TLD
        const label = parts[i];

        // Check for abnormally long subdomains (>50 chars = likely encoded data)
        if (label.length > 50) {
            analysis.suspiciousSubdomainLength = true;
            analysis.indicators.push(`Abnormally long subdomain: ${label.length} chars`);
        }

        // Check for high entropy (likely encoded data)
        if (label.length > 10) {
            const entropy = calculateShannonEntropy(label);
            if (entropy > 4.0) {
                analysis.highEntropySubdomain = true;
                analysis.indicators.push(`High-entropy subdomain (${entropy.toFixed(2)} bits)`);
            }
        }

        // Check for Base64 patterns in subdomains
        if (label.length > 16 && /^[A-Za-z0-9+/=]+$/.test(label)) {
            analysis.base64InSubdomain = true;
            analysis.indicators.push('Base64-like characters in subdomain');
        }

        // Check for hex-encoded subdomains (long hex strings)
        if (label.length > 20 && /^[0-9a-fA-F]+$/.test(label)) {
            analysis.hexInSubdomain = true;
            analysis.indicators.push('Hex-encoded subdomain');
        }
    }

    return analysis;
}

/**
 * Calculate Shannon entropy of a string
 * Higher entropy = more random/encoded = more suspicious
 * 
 * @param {string} str - Input string
 * @returns {number} Shannon entropy in bits
 */
function calculateShannonEntropy(str) {
    if (!str || str.length === 0) return 0;

    const freq = {};
    for (const char of str) {
        freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;
    for (const count of Object.values(freq)) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }

    return entropy;
}

/**
 * Uninstall DNS hook
 * 
 * @returns {boolean} Success
 */
function uninstall() {
    try {
        if (!isHookInstalled) return true;

        for (const [fnName, originalFn] of Object.entries(originalFunctions)) {
            if (originalFn) {
                dns[fnName] = originalFn;
                // Clear the saved reference. hookDnsFunction() guards re-wrapping
                // with `if (originalFunctions[fnName]) return`; leaving these set
                // makes a subsequent init() short-circuit, silently killing DNS
                // hooking for the rest of the process (breaks repeated
                // init/teardown — tests, benchmarks, programmatic reuse).
                originalFunctions[fnName] = null;
            }
        }

        isHookInstalled = false;
        signalCollector = null;
        hookConfig = null;
        return true;
    } catch (err) {
        return false;
    }
}

module.exports = {
    install,
    uninstall
};
