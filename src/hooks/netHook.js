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
const { resolveCurrentStackFast } = require('../attribution/resolver');

/**
 * Global signal collector
 */
let signalCollector = [];

/**
 * Store original functions for restoration
 */
const originalFunctions = {
    netConnect: null,
    netCreateConnection: null
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

        // Hook net.connect AND net.createConnection (low-level TCP).
        // They are separate exported references — patching one does NOT patch
        // the other, so raw TCP opened via net.createConnection (reverse
        // shells, custom C2) would otherwise slip through unmonitored.
        // Node's own HTTP/HTTPS stack uses an internal socket path, not these
        // public exports, so this never double-counts httpHook traffic.
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
    // net.connect and net.createConnection are distinct exported references.
    // Wrap each so neither raw-TCP entry point is missed.
    originalFunctions.netConnect = net.connect;
    net.connect = makeConnectWrapper('netConnect');

    if (typeof net.createConnection === 'function') {
        originalFunctions.netCreateConnection = net.createConnection;
        net.createConnection = makeConnectWrapper('netCreateConnection');
    }
}

/**
 * Build a connect-style wrapper that emits a NET_CONNECT signal then delegates
 * to the saved original. Shared by net.connect and net.createConnection.
 *
 * @param {string} originalKey - Key into originalFunctions for the real fn
 * @returns {Function} Wrapped connect function
 */
function makeConnectWrapper(originalKey) {
    return function (...args) {
        try {
            // net.connect / net.createConnection can be called as:
            // - (port, host)
            // - (options)
            // - (path) for IPC
            const connInfo = parseNetConnectArgs(args);
            if (connInfo) {
                emitNetSignal(connInfo.host, connInfo.port, 'tcp');
            }
        } catch (err) {
            // Fail-safe
        }

        return originalFunctions[originalKey].apply(this, args);
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
        // Resolve attribution (fast: structured stack, no string formatting)
        const attribution = resolveCurrentStackFast();

        // Only emit for third-party packages
        if (!attribution) {
            return;
        }

        // Fast-path: skip stack capture + signal build if it would be dropped.
        if (signalCollector.shouldCapture &&
            !signalCollector.shouldCapture(attribution.name, attribution.version)) {
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
            originalFunctions.netConnect = null;
        }
        if (originalFunctions.netCreateConnection) {
            net.createConnection = originalFunctions.netCreateConnection;
            originalFunctions.netCreateConnection = null;
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
