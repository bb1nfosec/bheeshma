/**
 * BHEESHMA Obfuscation Detection
 * 
 * Security: Static analysis of package source code at load time to detect
 * obfuscated code patterns before execution. Flags suspicious packages
 * with OBFUSCATION_DETECTED signals at severity HIGH.
 * 
 * This runs as a one-time check per package when it first triggers a signal.
 * It reads the package's entry point source and pattern-matches for common
 * obfuscation techniques.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { createSignal, SignalType } = require('../signals/signalTypes');
const { isWhitelisted } = require('../attribution/resolver');

/**
 * Cache of packages already scanned (avoid repeated file I/O)
 */
const scannedPackages = new Map();

/**
 * Scan a package for obfuscation patterns.
 * Called lazily — only when the package first emits a signal.
 * 
 * Detection patterns:
 * 1. eval( and Function( — dynamic code execution
 * 2. Buffer.from(...).toString() — Base64 decode
 * 3. Hex string literals > 100 chars
 * 4. \x escape density > 10% of source characters
 * 5. String concatenation chains
 * 6. Excessive use of String.fromCharCode
 * 
 * @param {string} packageName - Package name
 * @param {string} packageDir - Package directory path
 * @param {Array} signalCollector - Signal array to push to
 * @param {object} config - Bheeshma config
 * @returns {object|null} Detection result or null
 */
function scanPackage(packageName, packageDir, signalCollector, config) {
    if (scannedPackages.has(packageName)) {
        return scannedPackages.get(packageName);
    }

    try {
        const pkgJsonPath = path.join(packageDir, 'package.json');
        if (!fs.existsSync(pkgJsonPath)) {
            scannedPackages.set(packageName, null);
            return null;
        }

        // Check whitelist
        if (config && config.whitelist) {
            if (isWhitelisted(packageName, null, config.whitelist)) {
                scannedPackages.set(packageName, null);
                return null;
            }
        }

        const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
        const entryPoint = pkgJson.main || 'index.js';
        const entryPath = path.join(packageDir, entryPoint);

        if (!fs.existsSync(entryPath)) {
            scannedPackages.set(packageName, null);
            return null;
        }

        const source = fs.readFileSync(entryPath, 'utf8');
        const indicators = detectObfuscationPatterns(source);

        const result = indicators.length > 0 ? { indicators, packageName } : null;

        if (result && signalCollector) {
            const pkgVersion = pkgJson.version || 'unknown';
            const stack = new Error().stack;

            const signal = createSignal(
                SignalType.OBFUSCATION_DETECTED,
                {
                    entryPoint: entryPath,
                    indicators: indicators,
                    sourceLength: source.length,
                    packageDir: packageDir
                },
                packageName,
                pkgVersion,
                stack
            );

            signalCollector.push(signal);
        }

        scannedPackages.set(packageName, result);
        return result;
    } catch (err) {
        scannedPackages.set(packageName, null);
        return null;
    }
}

/**
 * Detect obfuscation patterns in source code
 * 
 * @param {string} source - Source code string
 * @returns {Array} Array of indicator objects
 */
function detectObfuscationPatterns(source) {
    const indicators = [];

    // 1. eval() usage
    const evalMatches = source.match(/eval\s*\(/g);
    if (evalMatches && evalMatches.length > 0) {
        indicators.push({
            type: 'EVAL_USAGE',
            severity: 'HIGH',
            count: evalMatches.length,
            description: `eval() found ${evalMatches.length} time(s) — dynamic code execution`
        });
    }

    // 2. Function() constructor usage
    const functionMatches = source.match(/(?:new\s+)?Function\s*\(/g);
    if (functionMatches && functionMatches.length > 0) {
        indicators.push({
            type: 'FUNCTION_CONSTRUCTOR',
            severity: 'HIGH',
            count: functionMatches.length,
            description: `Function() constructor found ${functionMatches.length} time(s)`
        });
    }

    // 3. Buffer.from(...).toString() — common decode pattern
    const bufferDecodeMatches = source.match(/Buffer\.from\s*\([^)]+\)\s*\.toString/g);
    if (bufferDecodeMatches && bufferDecodeMatches.length > 2) {
        indicators.push({
            type: 'BUFFER_DECODE',
            severity: 'MEDIUM',
            count: bufferDecodeMatches.length,
            description: `Buffer.from().toString() found ${bufferDecodeMatches.length} times — possible encoded payload`
        });
    }

    // 4. Hex string literals > 100 chars
    const hexStringMatches = source.match(/['"][0-9a-fA-F]{100,}['"]/g);
    if (hexStringMatches) {
        indicators.push({
            type: 'HEX_STRING_LITERAL',
            severity: 'HIGH',
            count: hexStringMatches.length,
            description: `Long hex string literal(s) found (${hexStringMatches.length})`
        });
    }

    // 5. \x escape density > 10%
    const xEscapeMatches = source.match(/\\x[0-9a-fA-F]{2}/g);
    if (xEscapeMatches && source.length > 0) {
        const xEscapeDensity = (xEscapeMatches.length * 4) / source.length;
        if (xEscapeDensity > 0.10) {
            indicators.push({
                type: 'HIGH_HEX_ESCAPE_DENSITY',
                severity: 'HIGH',
                density: xEscapeDensity.toFixed(4),
                description: `\\x escape density ${((xEscapeDensity) * 100).toFixed(1)}% — heavily obfuscated source`
            });
        }
    }

    // 6. String.fromCharCode chains
    const fromCharCodeMatches = source.match(/String\.fromCharCode/g);
    if (fromCharCodeMatches && fromCharCodeMatches.length > 3) {
        indicators.push({
            type: 'FROM_CHAR_CODE_CHAIN',
            severity: 'HIGH',
            count: fromCharCodeMatches.length,
            description: `String.fromCharCode() found ${fromCharCodeMatches.length} times — string obfuscation`
        });
    }

    // 7. atob() — Base64 decode
    const atobMatches = source.match(/atob\s*\(/g);
    if (atobMatches && atobMatches.length > 0) {
        indicators.push({
            type: 'ATOB_USAGE',
            severity: 'MEDIUM',
            count: atobMatches.length,
            description: `atob() found ${atobMatches.length} time(s) — Base64 decoding`
        });
    }

    // 8. Excessive string concatenation (obfuscation technique)
    const concatMatches = source.match(/['"][^'"]{1,5}['"]\s*\+\s*['"][^'"]{1,5}['"]\s*\+\s*['"][^'"]{1,5}['"]/g);
    if (concatMatches && concatMatches.length > 5) {
        indicators.push({
            type: 'EXCESSIVE_CONCATENATION',
            severity: 'MEDIUM',
            count: concatMatches.length,
            description: `Suspicious string concatenation chains (${concatMatches.length}) — possible obfuscation`
        });
    }

    return indicators;
}

/**
 * Clear scan cache (for testing)
 */
function clearScanCache() {
    scannedPackages.clear();
}

module.exports = {
    scanPackage,
    detectObfuscationPatterns,
    clearScanCache
};
