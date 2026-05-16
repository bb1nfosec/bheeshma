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
 * Extract npm package attribution from a stack trace string.
 * 
 * Attribution strategy: Walk the ENTIRE call stack and find the OUTERMOST
 * node_modules entry (closest to user code), not the first one. This prevents
 * mislabeling transitive dependency calls — if lodash calls something-evil,
 * the signal gets attributed to something-evil (the user-installed dep), not
 * lodash (the intermediary).
 * 
 * @param {string} stack - Raw stack trace string (from new Error().stack)
 * @returns {object|null} { name, version, path } or null if first-party
 */
function getPackageFromStack(stack) {
    try {
        if (!stack || typeof stack !== 'string') {
            return null;
        }

        const stackLines = stack.split('\n');
        let lastAttribution = null;

        // Walk ALL frames and find the LAST node_modules entry
        // (closest to user code, outermost in the dependency tree)
        for (const line of stackLines) {
            const match = line.match(/\((.+?):\d+:\d+\)/);
            if (!match) continue;

            const filePath = match[1];
            const nodeModulesIndex = filePath.indexOf('node_modules');
            if (nodeModulesIndex === -1) continue;

            const packageInfo = extractPackageInfo(filePath, nodeModulesIndex);
            if (packageInfo) {
                lastAttribution = packageInfo;
            }
        }

        return lastAttribution;
    } catch (err) {
        return null;
    }
}

/**
 * Extract npm package attribution from an Error object.
 * 
 * @param {Error} error - Error object with stack trace (or new Error())
 * @returns {object|null} { name, version, path } or null if first-party
 */
function resolvePackageFromStack(error) {
    if (!error || !error.stack) {
        return null;
    }
    return getPackageFromStack(error.stack);
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
            if (!parts[1]) return null;
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
        return null;
    }
}

/**
 * Read and parse package.json with caching
 * 
 * @param {string} packageDir - Absolute path to package directory
 * @returns {object|null} Parsed package.json or null
 */
function readPackageJson(packageDir) {
    try {
        if (packageCache.has(packageDir)) {
            return packageCache.get(packageDir);
        }

        const packageJsonPath = path.join(packageDir, 'package.json');
        if (!fs.existsSync(packageJsonPath)) {
            return null;
        }

        const content = fs.readFileSync(packageJsonPath, 'utf8');
        const packageJson = JSON.parse(content);
        packageCache.set(packageDir, packageJson);
        return packageJson;
    } catch (err) {
        return null;
    }
}

/**
 * Clear the package cache (useful for testing)
 */
function clearCache() {
    packageCache.clear();
}

/**
 * Create a new Error and resolve its stack immediately.
 * Utility function for hooks to use.
 * 
 * @returns {object|null} Package attribution { name, version, path }
 */
function resolveCurrentStack() {
    const error = new Error();
    Error.captureStackTrace(error, resolveCurrentStack);
    return resolvePackageFromStack(error);
}

/**
 * Check if a package name matches a whitelist pattern.
 * Supports: exact match ("express"), wildcard ("express@*"), scoped ("@types/*")
 * 
 * @param {string} packageName - Package name to check (e.g., "express")
 * @param {string} pattern - Whitelist pattern (e.g., "express@*" or "@types/*")
 * @returns {boolean} True if the package matches the pattern
 */
function matchesWhitelist(packageName, pattern) {
    if (!packageName || !pattern) return false;

    // Handle @scope/* patterns
    if (pattern.endsWith('/*')) {
        const scope = pattern.slice(0, -2);
        return packageName === scope || packageName.startsWith(scope + '/');
    }

    // Handle pkg@* patterns (any version)
    if (pattern.includes('@') && pattern.endsWith('*')) {
        const namePart = pattern.slice(0, pattern.lastIndexOf('@'));
        return packageName === namePart;
    }

    // Handle pkg@version patterns (exact)
    if (pattern.includes('@')) {
        return packageName === pattern;
    }

    // Plain name match
    return packageName === pattern;
}

/**
 * Check if a package is whitelisted based on its name and version.
 * 
 * @param {string} packageName - Package name
 * @param {string} packageVersion - Package version
 * @param {Array<string>} whitelist - Whitelist patterns array
 * @returns {boolean} True if the package should be suppressed
 */
function isWhitelisted(packageName, packageVersion, whitelist) {
    if (!whitelist || !Array.isArray(whitelist) || whitelist.length === 0) {
        return false;
    }

    for (const pattern of whitelist) {
        // Check with name@version
        if (packageVersion && matchesWhitelist(`${packageName}@${packageVersion}`, pattern)) {
            return true;
        }
        // Check with name only
        if (matchesWhitelist(packageName, pattern)) {
            return true;
        }
    }

    return false;
}

module.exports = {
    resolvePackageFromStack,
    resolveCurrentStack,
    getPackageFromStack,
    clearCache,
    matchesWhitelist,
    isWhitelisted
};
