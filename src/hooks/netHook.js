/**
 * BHEESHMA Network Hook
 * 
 * Security: Non-blocking observation of outbound network connections
 * Follows OWASP principle: "Monitor security-relevant events"
 * 
 * Purpose: Detect when third-party dependencies make outbound network calls.
 * This can identify data exfiltration, command-and-control communication,
 * or unauthorized external API calls.
 * 
 * CRITICAL: Hooks observe connection metadata only, never request/response bodies.
 */

'use strict';

const net = require('net');
const http = require('http');
const https = require('https');
const { createSignal, SignalType } = require('../signals/signalTypes');
const { resolveCurrentStack } = require('../attribution/resolver');

/**
 * Global signal collector
 */
let signalCollector = [];

/**
 * Store original functions for restoration
 */
const originalFunctions = {
    netConnect: null,
    httpRequest: null,
    httpsRequest: null
};

let isHookInstalled = false;

/**
 * Install network hooks
 * 
 * Hooks:
 * - net.connect (low-level TCP/socket connections)
 * - http.request (HTTP requests)
 * - https.request (HTTPS requests)
 * 
 * Security:
 * - Non-blocking: Doesn't delay actual connection
 * - No body inspection: Never captures request/response data
 * - No header inspection: Prevents capturing Authorization headers
 * - Preserves all original behavior and event emitters
 * 
 * @param {Array} collector - Shared signal collector
 * @returns {boolean} True if installed successfully
 */
function install(collector) {
    try {
        if (isHookInstalled) {
            return true;
        }

        signalCollector = collector;

        // Hook net.connect
        hookNetConnect();

        // Hook http.request and http.get
        hookHttpRequest();

        // Hook https.request and https.get
        hookHttpsRequest();

        isHookInstalled = true;
        return true;
    } catch (err) {
        console.error('[BHEESHMA] Failed to install network hook:', err.message);
        return false;
    }
}

/**
 * Hook net.connect (low-level socket connections)
 * 
 * @returns {void}
 */
function hookNetConnect() {
    originalFunctions.netConnect = net.connect;

    net.connect = function (...args) {
        try {
            // Extract connection info from arguments
            // net.connect can be called as:
            // - net.connect(port, host)
            // - net.connect(options)
            // - net.connect(path) for IPC
            const connInfo = parseNetConnectArgs(args);
            if (connInfo) {
                emitNetSignal(connInfo.host, connInfo.port, 'tcp');
            }
        } catch (err) {
            // Fail-safe
        }

        // Call original function
        return originalFunctions.netConnect.apply(this, args);
    };
}

/**
 * Hook http.request and http.get
 * 
 * @returns {void}
 */
function hookHttpRequest() {
    originalFunctions.httpRequest = http.request;

    http.request = function (...args) {
        try {
            const connInfo = parseHttpArgs(args);
            if (connInfo) {
                emitNetSignal(connInfo.host, connInfo.port, 'http');
            }
        } catch (err) {
            // Fail-safe
        }

        return originalFunctions.httpRequest.apply(this, args);
    };

    // http.get calls http.request internally, so we only need to hook request
}

/**
 * Hook https.request and https.get
 * 
 * @returns {void}
 */
function hookHttpsRequest() {
    originalFunctions.httpsRequest = https.request;

    https.request = function (...args) {
        try {
            const connInfo = parseHttpArgs(args);
            if (connInfo) {
                emitNetSignal(connInfo.host, connInfo.port, 'https');
            }
        } catch (err) {
            // Fail-safe
        }

        return originalFunctions.httpsRequest.apply(this, args);
    };

    // https.get calls https.request internally
}

/**
 * Parse net.connect arguments to extract host and port
 * 
 * @param {Array} args - Arguments to net.connect
 * @returns {object|null} { host, port } or null
 */
function parseNetConnectArgs(args) {
    try {
        if (args.length === 0) {
            return null;
        }

        // Check if first arg is an options object
        if (typeof args[0] === 'object' && args[0] !== null) {
            const options = args[0];
            return {
                host: options.host || 'localhost',
                port: options.port || 0
            };
        }

        // Check if called as (port, host)
        if (typeof args[0] === 'number') {
            return {
                port: args[0],
                host: args[1] || 'localhost'
            };
        }

        return null;
    } catch (err) {
        return null;
    }
}

/**
 * Parse http/https request arguments to extract URL info
 * 
 * http.request can be called as:
 * - http.request(url)
 * - http.request(options)
 * - http.request(url, options)
 * 
 * @param {Array} args - Arguments to http.request
 * @returns {object|null} { host, port } or null
 */
function parseHttpArgs(args) {
    try {
        if (args.length === 0) {
            return null;
        }

        const firstArg = args[0];

        // Parse URL string
        if (typeof firstArg === 'string') {
            const url = new URL(firstArg);
            return {
                host: url.hostname,
                port: url.port ? parseInt(url.port, 10) : (url.protocol === 'https:' ? 443 : 80)
            };
        }

        // Parse URL object
        if (firstArg instanceof URL) {
            return {
                host: firstArg.hostname,
                port: firstArg.port ? parseInt(firstArg.port, 10) : 80
            };
        }

        // Parse options object
        if (typeof firstArg === 'object' && firstArg !== null) {
            return {
                host: firstArg.hostname || firstArg.host || 'localhost',
                port: firstArg.port || 80
            };
        }

        return null;
    } catch (err) {
        return null;
    }
}

/**
 * Emit a network connection signal
 * 
 * Security:
 * - Captures host and port only (metadata)
 * - Never captures request headers (may contain auth tokens)
 * - Never captures request/response bodies
 * - Never captures query parameters (may contain sensitive data)
 * 
 * @param {string} host - Hostname or IP
 * @param {number} port - Port number
 * @param {string} protocol - 'tcp', 'http', or 'https'
 * @returns {void}
 */
function emitNetSignal(host, port, protocol) {
    try {
        // Resolve attribution
        const attribution = resolveCurrentStack();

        // Only emit for third-party packages
        if (!attribution) {
            return;
        }

        const signal = createSignal(
            SignalType.NET_CONNECT,
            {
                host: host,
                port: port,
                protocol: protocol
                // Security: Explicitly do NOT include:
                // - Headers (Authorization, cookies, etc.)
                // - Request body
                // - Query parameters
                // - Response data
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
 * Uninstall network hooks
 * 
 * @returns {boolean} True if uninstalled successfully
 */
function uninstall() {
    try {
        if (!isHookInstalled) {
            return true;
        }

        // Restore original functions
        if (originalFunctions.netConnect) {
            net.connect = originalFunctions.netConnect;
        }
        if (originalFunctions.httpRequest) {
            http.request = originalFunctions.httpRequest;
        }
        if (originalFunctions.httpsRequest) {
            https.request = originalFunctions.httpsRequest;
        }

        isHookInstalled = false;
        return true;
    } catch (err) {
        return false;
    }
}

/**
 * Check if hook is installed
 * 
 * @returns {boolean}
 */
function isInstalled() {
    return isHookInstalled;
}

module.exports = {
    install,
    uninstall,
    isInstalled
};
