/**
 * BHEESHMA DNS hostname analysis (shared)
 *
 * Detects DNS tunneling / exfiltration indicators in a queried hostname. Used by
 * BOTH engines: the in-process dnsHook (which gets the hostname from the wrapped
 * dns.* call) and the out-of-process strace engine (which recovers it from the
 * DNS query payload). Keeping it in one place keeps their verdicts identical.
 */

'use strict';

/**
 * Known exfiltration / request-capture DNS services.
 * NOTE: ngrok.io / localtunnel.me are EXCLUDED (legitimate dev tunnels) and
 * canarytokens.com is EXCLUDED (a defensive tool), to avoid false positives.
 */
const KNOWN_EXFIL_DOMAINS = [
    'dnshook.site',
    'requestbin.com',
    'webhook.site',
    'pipedream.com'
];

/**
 * Shannon entropy of a string (bits). Higher = more random/encoded.
 * @param {string} str
 * @returns {number}
 */
function calculateShannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = {};
    for (const char of str) freq[char] = (freq[char] || 0) + 1;
    let entropy = 0;
    const len = str.length;
    for (const count of Object.values(freq)) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

/**
 * Analyze a hostname for DNS tunneling / exfiltration patterns.
 *
 * @param {string} hostname
 * @returns {object} analysis with boolean flags + indicators[]
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

    if (!hostname || typeof hostname !== 'string') return analysis;

    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    if (ipPattern.test(hostname)) {
        analysis.isIpAddress = true;
        return analysis;
    }

    const parts = hostname.split('.');

    for (const exfilDomain of KNOWN_EXFIL_DOMAINS) {
        if (hostname === exfilDomain || hostname.endsWith('.' + exfilDomain)) {
            analysis.knownExfilService = true;
            analysis.indicators.push(`Known exfil service: ${exfilDomain}`);
        }
    }

    for (let i = 0; i < parts.length - 1; i++) { // skip TLD
        const label = parts[i];

        if (label.length > 50) {
            analysis.suspiciousSubdomainLength = true;
            analysis.indicators.push(`Abnormally long subdomain: ${label.length} chars`);
        }
        if (label.length > 10) {
            const entropy = calculateShannonEntropy(label);
            if (entropy > 4.0) {
                analysis.highEntropySubdomain = true;
                analysis.indicators.push(`High-entropy subdomain (${entropy.toFixed(2)} bits)`);
            }
        }
        if (label.length > 16 && /^[A-Za-z0-9+/=]+$/.test(label)) {
            analysis.base64InSubdomain = true;
            analysis.indicators.push('Base64-like characters in subdomain');
        }
        if (label.length > 20 && /^[0-9a-fA-F]+$/.test(label)) {
            analysis.hexInSubdomain = true;
            analysis.indicators.push('Hex-encoded subdomain');
        }
    }

    return analysis;
}

module.exports = { analyzeHostname, calculateShannonEntropy, KNOWN_EXFIL_DOMAINS };
