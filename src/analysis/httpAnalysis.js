/**
 * BHEESHMA Shared HTTP Request Analysis
 *
 * Header sanitization and destination-suspiciousness analysis, shared by
 * every hook that observes an outbound HTTP(S) request: the core
 * `http`/`https` module hook and the global `fetch` hook.
 *
 * Kept in one place so both entry points produce identical signal metadata —
 * a fetch-based exfil and an https.request-based exfil must look the same to
 * the scoring and pattern layers, or the correlation engine sees two shapes
 * of the same behavior.
 */

'use strict';

/**
 * Sanitize headers to remove sensitive information.
 *
 * Only header *names* are retained. Values are never captured: an
 * Authorization or Cookie value is exactly the secret we are trying to
 * detect being stolen, and a monitor must not become a second copy of it.
 *
 * @param {object} headers - Request headers
 * @returns {object} Sanitized headers (names only, no values)
 */
function sanitizeHeaders(headers) {
    if (!headers || typeof headers !== 'object') {
        return {};
    }

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
 * Analyze a request destination for suspicious patterns.
 *
 * @param {object} requestInfo - Parsed request info ({ host, port, ... })
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

module.exports = {
    sanitizeHeaders,
    analyzeSuspiciousness
};
