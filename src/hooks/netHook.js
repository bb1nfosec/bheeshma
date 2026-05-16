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
    netConnect: null
};

let isHookInstalled = false;
let hookConfig = null;

/**
 * Install network hooks
 * 
 * @param {Array} collector - Shared signal collector
 * @param {object} config - Bheeshma configuration
 * @returns {boolean} True if installed successfully
 */
function install(collector, config) {
    try {
        if (isHookInstalled) {
            return true;
        }

        signalCollector = collector;
        hookConfig = config;

        // Hook net.connect (low-level TCP connections)
        // Note: HTTP/HTTPS is handled separately by httpHook.js which provides
        // richer analysis (headers, suspiciousness scoring). We intentionally
        // do NOT wrap http.request/https.request here to avoid conflicts.
        hookNetConnect();

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
