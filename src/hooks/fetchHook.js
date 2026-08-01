/**
 * BHEESHMA fetch() Hook
 *
 * Monitors outbound requests made through the global `fetch` (undici),
 * which is the DEFAULT HTTP path in Node 18+ and completely bypasses the
 * `http`/`https` module hook.
 *
 * Why this exists: undici does not route through `http.request` — it drives
 * its own client over a socket. Patching the `http`/`https` modules therefore
 * leaves `fetch()` unmonitored, and the connection undici eventually opens is
 * made from internal code after the caller's stack has unwound, so it cannot
 * be attributed to a package either. The result was a total blind spot for
 * fetch-based exfiltration — the shape used by current npm worm families.
 *
 * Design notes:
 * - Emits HTTP_REQUEST / HTTPS_REQUEST, the same signal types as the module
 *   hook, so existing correlation (SECRET_ENV_EXFIL, data exfiltration, worm
 *   propagation) and scoring apply with no changes. `metadata.via` records
 *   which entry point produced the signal.
 * - Attribution is resolved at the synchronous call site, before the request
 *   goes async — the only point where the calling package is still knowable.
 * - Gated by `hooks.http`: a fetch call *is* an HTTP request, so disabling
 *   HTTP monitoring disables both entry points together.
 * - Request bodies are never read. Only destination metadata and header
 *   names are captured.
 *
 * Known limits (documented, not silently accepted): this patches the global
 * `fetch` binding. A package that imports `undici` directly and calls its
 * exported `fetch`, or that captured a reference to the global before
 * bheeshma initialized, is not covered.
 */

'use strict';

const { createSignal, SignalType } = require('../signals/signalTypes');
const { resolveCurrentStackFast } = require('../attribution/resolver');
const { sanitizeHeaders, analyzeSuspiciousness } = require('../analysis/httpAnalysis');

let originalFetch = null;
let signalsArray = null;
let hookConfig = null;

/**
 * Install the global fetch monitoring hook.
 *
 * @param {Array} signals - Global signals recorder
 * @param {object} config - Active configuration
 * @returns {boolean} Success (false when the runtime has no global fetch)
 */
function install(signals, config) {
    if (!signals || (typeof signals !== 'object')) {
        return false;
    }

    // Node < 18 has no global fetch. Nothing to hook, and that is not a
    // failure — the blind spot does not exist on those runtimes.
    if (typeof globalThis.fetch !== 'function') {
        return false;
    }

    signalsArray = signals;
    hookConfig = config;

    try {
        if (!originalFetch) {
            originalFetch = globalThis.fetch;
            globalThis.fetch = createFetchHook(originalFetch);
        }
        return true;
    } catch (err) {
        console.error('[BHEESHMA] fetch hook installation failed:', err.message);
        return false;
    }
}

/**
 * Wrap fetch so every call is observed before it is forwarded.
 *
 * @param {Function} original - The original global fetch
 * @returns {Function} Hooked fetch
 */
function createFetchHook(original) {
    return function fetch(...args) {
        // Never let monitoring break the monitored program: any failure in
        // signal capture falls through to the original call untouched.
        try {
            const requestInfo = parseFetchArgs(args);

            if (requestInfo) {
                // Resolve attribution synchronously — once the request goes
                // async into undici, the calling package is unrecoverable.
                const attribution = resolveCurrentStackFast();

                if (attribution &&
                    (!signalsArray.shouldCapture ||
                     signalsArray.shouldCapture(attribution.name, attribution.version))) {
                    const stack = new Error().stack;
                    const signal = createSignal(
                        requestInfo.isHttps ? SignalType.HTTPS_REQUEST : SignalType.HTTP_REQUEST,
                        {
                            url: requestInfo.url,
                            method: requestInfo.method,
                            host: requestInfo.host,
                            port: requestInfo.port,
                            path: requestInfo.path,
                            headers: sanitizeHeaders(requestInfo.headers),
                            via: 'fetch',
                            suspicious: analyzeSuspiciousness(requestInfo)
                        },
                        attribution.name,
                        attribution.version,
                        stack
                    );

                    signalsArray.push(signal);
                }
            }
        } catch (err) {
            // Swallow — monitoring must not change program behavior.
        }

        return original.apply(this, args);
    };
}

/**
 * Normalize fetch(input, init) arguments into the same shape the HTTP hook
 * produces.
 *
 * `input` may be a string, a URL, or a Request-like object; `init` may carry
 * method and headers that override it.
 *
 * @param {Array} args - Arguments passed to fetch()
 * @returns {object|null} Parsed request info, or null if unparseable
 */
function parseFetchArgs(args) {
    const input = args[0];
    const init = args[1] || {};

    let rawUrl = null;
    let method = init.method;
    let headers = init.headers;

    if (typeof input === 'string') {
        rawUrl = input;
    } else if (input instanceof URL) {
        rawUrl = input.href;
    } else if (input && typeof input === 'object') {
        // Request-like: carries its own url/method/headers, which init overrides.
        rawUrl = typeof input.url === 'string' ? input.url : null;
        method = method || input.method;
        headers = headers || input.headers;
    }

    if (!rawUrl) {
        return null;
    }

    let parsed;
    try {
        parsed = new URL(rawUrl);
    } catch (err) {
        // Relative or malformed URL — fetch itself will reject it.
        return null;
    }

    const isHttps = parsed.protocol === 'https:';
    const defaultPort = isHttps ? 443 : 80;

    return {
        url: parsed.href,
        method: (method || 'GET').toUpperCase(),
        host: parsed.hostname,
        port: parsed.port ? Number(parsed.port) : defaultPort,
        path: `${parsed.pathname}${parsed.search}`,
        headers: normalizeHeaders(headers),
        isHttps
    };
}

/**
 * Convert the several shapes fetch accepts for headers (Headers instance,
 * array of pairs, plain object) into a plain object of names.
 *
 * Values are passed through to sanitizeHeaders, which discards them.
 *
 * @param {*} headers - Headers in any accepted form
 * @returns {object} Plain header object
 */
function normalizeHeaders(headers) {
    if (!headers) {
        return {};
    }

    try {
        // Headers instance (or anything else iterable as name/value pairs)
        if (typeof headers.forEach === 'function' && typeof headers.get === 'function') {
            const plain = {};
            headers.forEach((value, name) => { plain[name] = value; });
            return plain;
        }

        if (Array.isArray(headers)) {
            const plain = {};
            for (const entry of headers) {
                if (Array.isArray(entry) && entry.length >= 1) {
                    plain[entry[0]] = entry[1];
                }
            }
            return plain;
        }

        if (typeof headers === 'object') {
            return headers;
        }
    } catch (err) {
        // Fall through to empty on any exotic header implementation.
    }

    return {};
}

/**
 * Uninstall the fetch hook.
 *
 * @returns {boolean} Success
 */
function uninstall() {
    try {
        if (originalFetch) {
            globalThis.fetch = originalFetch;
            originalFetch = null;
        }

        signalsArray = null;
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
