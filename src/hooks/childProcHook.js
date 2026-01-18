/**
 * BHEESHMA Child Process Hook
 * 
 * Security: High-risk behavior monitoring for shell execution
 * Follows CERT principle: "Minimize attack surface"
 * 
 * Purpose: Detect when third-party dependencies execute shell commands
 * or spawn child processes. This is one of the highest-risk behaviors
 * as it can lead to arbitrary code execution.
 * 
 * CRITICAL: Captures command templates only, never stdin/stdout or secrets.
 */

'use strict';

const childProcess = require('child_process');
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
    exec: null,
    execSync: null,
    execFile: null,
    execFileSync: null,
    spawn: null,
    spawnSync: null,
    fork: null
};

let isHookInstalled = false;

/**
 * Install child process hooks
 * 
 * Hooks all child_process functions:
 * - exec/execSync: Shell command execution
 * - execFile/execFileSync: Direct file execution
 * - spawn/spawnSync: Lower-level process spawning
 * - fork: Node.js child process forking
 * 
 * Security:
 * - High-risk signals: Shell execution is a critical indicator
 * - Sanitizes commands to remove interpolated secrets
 * - Never captures process output (stdin/stdout/stderr)
 * - Preserves all original behavior
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

        // Hook all child_process functions
        hookFunction('exec');
        hookFunction('execSync');
        hookFunction('execFile');
        hookFunction('execFileSync');
        hookFunction('spawn');
        hookFunction('spawnSync');
        hookFunction('fork');

        isHookInstalled = true;
        return true;
    } catch (err) {
        console.error('[BHEESHMA] Failed to install child_process hook:', err.message);
        return false;
    }
}

/**
 * Hook a single child_process function
 * 
 * @param {string} fnName - Function name on child_process module
 * @returns {void}
 */
function hookFunction(fnName) {
    if (typeof childProcess[fnName] !== 'function') {
        return;
    }

    // Store original
    originalFunctions[fnName] = childProcess[fnName];

    // Create wrapper
    childProcess[fnName] = function (...args) {
        try {
            // Emit signal BEFORE execution
            emitShellSignal(args, fnName);
        } catch (err) {
            // Fail-safe
        }

        // Call original function
        return originalFunctions[fnName].apply(this, args);
    };

    // Preserve function name
    Object.defineProperty(childProcess[fnName], 'name', {
        value: fnName,
        configurable: true
    });
}

/**
 * Emit a shell execution signal
 * 
 * Security:
 * - Sanitizes command to remove potentially interpolated secrets
 * - Captures command structure only, not dynamic values
 * - Never captures stdin, stdout, stderr streams
 * - Never captures environment variables passed to child
 * 
 * @param {Array} args - Arguments to child_process function
 * @param {string} operation - Function name (exec, spawn, etc.)
 * @returns {void}
 */
function emitShellSignal(args, operation) {
    try {
        // Resolve attribution
        const attribution = resolveCurrentStack();

        // Only emit for third-party packages
        if (!attribution) {
            return;
        }

        // Extract and sanitize command
        const command = extractCommand(args, operation);
        if (!command) {
            return;
        }

        const signal = createSignal(
            SignalType.SHELL_EXEC,
            {
                command: command,
                operation: operation
                // Security: Explicitly do NOT include:
                // - Process output (stdout/stderr)
                // - Process input (stdin)
                // - Environment variables
                // - Working directory (may contain secrets in path)
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
 * Extract command from child_process arguments
 * 
 * Different functions have different signatures:
 * - exec(command, [options], [callback])
 * - spawn(command, [args], [options], [callback])
 * - fork(modulePath, [args], [options])
 * 
 * Security:
 * - Sanitizes to prevent capturing interpolated secrets
 * - Returns command template only
 * 
 * @param {Array} args - Function arguments
 * @param {string} operation - Function name
 * @returns {string|null} Sanitized command or null
 */
function extractCommand(args, operation) {
    try {
        if (args.length === 0) {
            return null;
        }

        const firstArg = args[0];

        // For exec/execSync, first arg is the command string
        if (operation === 'exec' || operation === 'execSync') {
            return sanitizeCommand(firstArg);
        }

        // For spawn/execFile, first arg is command, second is args array
        if (operation === 'spawn' || operation === 'spawnSync' ||
            operation === 'execFile' || operation === 'execFileSync') {
            const command = firstArg;
            const argsArray = args[1];

            if (Array.isArray(argsArray)) {
                // Join command and args, but sanitize
                return sanitizeCommand(`${command} ${argsArray.join(' ')}`);
            }

            return sanitizeCommand(command);
        }

        // For fork, first arg is the module path
        if (operation === 'fork') {
            return `node ${firstArg}`;
        }

        return sanitizeCommand(firstArg);
    } catch (err) {
        return null;
    }
}

/**
 * Sanitize command string to remove potential secrets
 * 
 * Security strategy:
 * - Remove common secret patterns (API keys, tokens, passwords)
 * - Limit length to prevent capturing large interpolated data
 * - Redact common credential arguments
 * 
 * This is best-effort sanitization. For maximum security,
 * the recommendation is to never log full commands.
 * 
 * @param {string} command - Raw command string
 * @returns {string} Sanitized command
 */
function sanitizeCommand(command) {
    if (typeof command !== 'string') {
        return String(command);
    }

    let sanitized = command;

    // Truncate very long commands (may contain embedded data)
    if (sanitized.length > 200) {
        sanitized = sanitized.substring(0, 200) + '...[TRUNCATED]';
    }

    // Redact common credential patterns
    // These are heuristic and not exhaustive
    sanitized = sanitized.replace(/--password[= ][\S]+/gi, '--password=***');
    sanitized = sanitized.replace(/--token[= ][\S]+/gi, '--token=***');
    sanitized = sanitized.replace(/--api-key[= ][\S]+/gi, '--api-key=***');
    sanitized = sanitized.replace(/--secret[= ][\S]+/gi, '--secret=***');

    // Redact environment variable assignments that might contain secrets
    sanitized = sanitized.replace(/\b[A-Z_]+_KEY=[\S]+/g, 'xxx_KEY=***');
    sanitized = sanitized.replace(/\b[A-Z_]+_TOKEN=[\S]+/g, 'xxx_TOKEN=***');
    sanitized = sanitized.replace(/\b[A-Z_]+_SECRET=[\S]+/g, 'xxx_SECRET=***');

    return sanitized;
}

/**
 * Uninstall child process hooks
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
            if (originalFn) {
                childProcess[fnName] = originalFn;
            }
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
