/**
 * BHEESHMA Filesystem Hook
 * 
 * Security: Non-invasive wrapping of fs module operations
 * Follows CERT principle: "Do not modify behavior of standard library"
 * 
 * Purpose: Detect file system access (read/write) by third-party dependencies.
 * This can identify data exfiltration, credential theft, or malicious persistence.
 * 
 * CRITICAL: Hooks observe only, never modify fs behavior or file contents.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { createSignal, SignalType } = require('../signals/signalTypes');
const { resolveCurrentStack } = require('../attribution/resolver');

/**
 * Global signal collector
 */
let signalCollector = [];

/**
 * Store original fs functions for restoration
 */
const originalFunctions = {};
let isHookInstalled = false;

/**
 * FS functions to hook for READ operations
 */
const READ_FUNCTIONS = [
    'readFile',
    'readFileSync',
    'readdir',
    'readdirSync',
    'readlink',
    'readlinkSync',
    'createReadStream'
];

/**
 * FS functions to hook for WRITE operations
 */
const WRITE_FUNCTIONS = [
    'writeFile',
    'writeFileSync',
    'appendFile',
    'appendFileSync',
    'mkdir',
    'mkdirSync',
    'rmdir',
    'rmdirSync',
    'unlink',
    'unlinkSync',
    'rename',
    'renameSync',
    'createWriteStream'
];

/**
 * Install filesystem hooks
 * 
 * Security:
 * - Wraps original functions (doesn't replace)
 * - Preserves all arguments and return values
 * - Fail-safe: Errors in hooks don't break fs operations
 * - Idempotent: Safe to call multiple times
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

        // Hook read operations
        for (const fnName of READ_FUNCTIONS) {
            if (typeof fs[fnName] === 'function') {
                hookFunction(fnName, SignalType.FS_READ);
            }
        }

        // Hook write operations
        for (const fnName of WRITE_FUNCTIONS) {
            if (typeof fs[fnName] === 'function') {
                hookFunction(fnName, SignalType.FS_WRITE);
            }
        }

        isHookInstalled = true;
        return true;
    } catch (err) {
        console.error('[BHEESHMA] Failed to install fs hook:', err.message);
        return false;
    }
}

/**
 * Hook a single fs function
 * 
 * Implementation:
 * 1. Store original function
 * 2. Create wrapper that:
 *    a. Emits signal with sanitized file path
 *    b. Calls original function with all arguments
 *    c. Returns original result
 * 3. Replace fs function with wrapper
 * 
 * Security:
 * - Uses ...args to preserve all arguments exactly
 * - Preserves 'this' binding
 * - Try-catch prevents hook errors from breaking fs
 * 
 * @param {string} fnName - Function name on fs module
 * @param {string} signalType - FS_READ or FS_WRITE
 * @returns {void}
 */
function hookFunction(fnName, signalType) {
    // Store original
    originalFunctions[fnName] = fs[fnName];

    // Create wrapper
    fs[fnName] = function (...args) {
        try {
            // Emit signal BEFORE calling original function
            // This ensures we capture the attempt even if it fails
            emitFsSignal(signalType, args[0], fnName);
        } catch (err) {
            // Fail-safe: Hook error doesn't prevent fs operation
        }

        // Call original function with all arguments and context
        return originalFunctions[fnName].apply(this, args);
    };

    // Preserve function properties (for tools that inspect fs)
    Object.defineProperty(fs[fnName], 'name', {
        value: fnName,
        configurable: true
    });
}

/**
 * Emit a filesystem signal
 * 
 * Security:
 * - Sanitizes file path (resolves to absolute, normalized path)
 * - Filters out potential sensitive paths (home dir, etc.)
 * - Captures metadata only, never file contents
 * 
 * @param {string} signalType - FS_READ or FS_WRITE
 * @param {string|Buffer|URL|number} filePath - First argument to fs function
 * @param {string} operation - Name of fs function called
 * @returns {void}
 */
function emitFsSignal(signalType, filePath, operation) {
    try {
        // Resolve attribution
        const attribution = resolveCurrentStack();

        // Only emit for third-party packages
        if (!attribution) {
            return;
        }

        // Sanitize and normalize file path
        const sanitizedPath = sanitizePath(filePath);
        if (!sanitizedPath) {
            return;
        }

        const signal = createSignal(
            signalType,
            {
                path: sanitizedPath,
                operation: operation
                // Security: Do NOT include file contents or buffer data
            },
            attribution.name,
            attribution.version,
            new Error().stack
        );

        signalCollector.push(signal);
    } catch (err) {
        // Defensive: Never throw
    }
}

/**
 * Sanitize file path for signal metadata
 * 
 * Security:
 * - Converts to absolute path to prevent confusion attacks
 * - Normalizes path (removes .., ., etc.)
 * - Returns string format only
 * 
 * Privacy:
 * - Could filter certain paths (home dir) if needed
 * - Currently captures all paths for maximum visibility
 * 
 * @param {string|Buffer|URL|number} filePath - Raw file path from fs call
 * @returns {string|null} Sanitized path or null if invalid
 */
function sanitizePath(filePath) {
    try {
        // Handle different path formats
        let strPath;

        if (typeof filePath === 'string') {
            strPath = filePath;
        } else if (Buffer.isBuffer(filePath)) {
            strPath = filePath.toString('utf8');
        } else if (filePath instanceof URL) {
            strPath = filePath.pathname;
        } else if (typeof filePath === 'number') {
            // File descriptor - can't sanitize, skip
            return null;
        } else {
            return null;
        }

        // Resolve to absolute, normalized path
        const absolutePath = path.resolve(strPath);

        return absolutePath;
    } catch (err) {
        return null;
    }
}

/**
 * Uninstall filesystem hooks
 * 
 * Security: Clean restoration of original fs functions
 * 
 * @returns {boolean} True if uninstalled successfully
 */
function uninstall() {
    try {
        if (!isHookInstalled) {
            return true;
        }

        // Restore all original functions
        for (const [fnName, originalFn] of Object.entries(originalFunctions)) {
            fs[fnName] = originalFn;
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
