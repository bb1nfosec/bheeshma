/**
 * BHEESHMA Attribution Resolver
 * 
 * Security: Read-only stack trace analysis for package identification.
 * Follows CERT principle: "Defensive programming"
 * 
 * Purpose: Determine which npm package is responsible for a runtime behavior
 * by analyzing stack traces and finding node_modules boundaries.
 * 
 * This module NEVER executes code, only analyzes file paths.
 */

'use strict';

const fs = require('fs');
const path = require('path');

/**
 * In-memory cache for package.json lookups
 * Security: Reduces filesystem I/O and prevents TOCTOU issues
 * @type {Map<string, object>}
 */
const packageCache = new Map();

/**
 * Extract npm package attribution from a stack trace
 * 
 * Algorithm:
 * 1. Parse stack trace into frames
 * 2. Find frames containing 'node_modules'
 * 3. Extract package directory and read package.json
 * 4. Return package name and version
 * 
 * Security considerations:
 * - Read-only operations (never writes to filesystem)
 * - Defensive error handling for malformed stack traces
 * - No eval() or code execution
 * - Returns null for first-party code (not in node_modules)
 * 
 * @param {Error} error - Error object with stack trace (or new Error())
 * @returns {object|null} { name, version, path } or null if first-party
 */
function resolvePackageFromStack(error) {
    try {
        // Security: Ensure we have a valid stack
        if (!error || !error.stack) {
            return null;
        }

        const stackLines = error.stack.split('\n');

        for (const line of stackLines) {
            // Extract file path from stack frame
            // Format: "    at Function.name (path:line:col)"
            const match = line.match(/\((.+?):\d+:\d+\)/);
            if (!match) continue;

            const filePath = match[1];

            // Look for node_modules in the path
            const nodeModulesIndex = filePath.indexOf('node_modules');
            if (nodeModulesIndex === -1) {
                // First-party application code - not a dependency
                continue;
            }

            // Extract package path from node_modules
            const packageInfo = extractPackageInfo(filePath, nodeModulesIndex);
            if (packageInfo) {
                return packageInfo;
            }
        }

        // No third-party package found in stack trace
        return null;
    } catch (err) {
        // Defensive: Never throw from attribution logic
        // Fail-safe: Return null if we can't determine attribution
        return null;
    }
}

/**
 * Extract package information from a file path containing node_modules
 * 
 * Handles both regular and scoped packages:
 * - Regular: node_modules/package-name
 * - Scoped: node_modules/@scope/package-name
 * 
 * @param {string} filePath - Absolute file path
 * @param {number} nodeModulesIndex - Index where 'node_modules' starts
 * @returns {object|null} Package info or null
 */
function extractPackageInfo(filePath, nodeModulesIndex) {
    try {
        const afterNodeModules = filePath.slice(nodeModulesIndex + 'node_modules'.length + 1);
        const parts = afterNodeModules.split(path.sep);

        let packageName;
        let packageDir;

        // Handle scoped packages (@scope/package)
        if (parts[0] && parts[0].startsWith('@')) {
            packageName = `${parts[0]}/${parts[1]}`;
            packageDir = path.join(
                filePath.slice(0, nodeModulesIndex),
                'node_modules',
                parts[0],
                parts[1]
            );
        } else {
            packageName = parts[0];
            packageDir = path.join(
                filePath.slice(0, nodeModulesIndex),
                'node_modules',
                parts[0]
            );
        }

        // Read package.json to get version
        const packageJson = readPackageJson(packageDir);
        if (!packageJson) {
            return null;
        }

        return {
            name: packageName,
            version: packageJson.version || 'unknown',
            path: packageDir
        };
    } catch (err) {
        // Defensive: Malformed path or package structure
        return null;
    }
}

/**
 * Read and parse package.json with caching
 * 
 * Security:
 * - Read-only operation
 * - Cached to prevent repeated I/O
 * - Defensive parsing (handles malformed JSON)
 * 
 * @param {string} packageDir - Absolute path to package directory
 * @returns {object|null} Parsed package.json or null
 */
function readPackageJson(packageDir) {
    try {
        // Check cache first
        if (packageCache.has(packageDir)) {
            return packageCache.get(packageDir);
        }

        const packageJsonPath = path.join(packageDir, 'package.json');

        // Security: Check file exists before reading to prevent errors
        if (!fs.existsSync(packageJsonPath)) {
            return null;
        }

        const content = fs.readFileSync(packageJsonPath, 'utf8');
        const packageJson = JSON.parse(content);

        // Cache the result
        packageCache.set(packageDir, packageJson);

        return packageJson;
    } catch (err) {
        // Defensive: Malformed JSON or read error
        return null;
    }
}

/**
 * Clear the package cache (useful for testing)
 * 
 * @returns {void}
 */
function clearCache() {
    packageCache.clear();
}

/**
 * Create a new Error and resolve its stack immediately
 * Utility function for hooks to use
 * 
 * @returns {object|null} Package attribution
 */
function resolveCurrentStack() {
    const error = new Error();
    Error.captureStackTrace(error, resolveCurrentStack);
    return resolvePackageFromStack(error);
}

module.exports = {
    resolvePackageFromStack,
    resolveCurrentStack,
    clearCache
};
