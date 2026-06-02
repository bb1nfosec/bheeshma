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
const { resolveCurrentStackFast } = require('../attribution/resolver');
const { analyzeHostname } = require('../analysis/dnsAnalysis');

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
        const attribution = resolveCurrentStackFast();
        if (!attribution) return;

        // Fast-path: skip stack capture + analysis if this signal would be
        // dropped anyway (maxSignals reached / whitelisted).
        if (signalCollector.shouldCapture &&
            !signalCollector.shouldCapture(attribution.name, attribution.version)) {
            return;
        }

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

// Hostname analysis (entropy, known-exfil, subdomain heuristics) lives in
// ../analysis/dnsAnalysis so the in-process and out-of-process engines agree.

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
