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
 * Detect obfuscation patterns in source code.
 *
 * Patterns:
 *  1.  eval()                      — dynamic code execution          HIGH
 *  2.  Function() constructor      — dynamic code execution          HIGH
 *  3.  Buffer.from().toString() ×3+— common base64 decode idiom      MEDIUM
 *  4.  Hex string literal >100 ch  — encoded payload                 HIGH
 *  5.  \\x escape density >10%     — heavily hex-escaped source      HIGH
 *  6.  String.fromCharCode ×4+     — character-code string building  HIGH
 *  7.  atob()                      — base64 decoding                 MEDIUM
 *  8.  Excessive concat ×6+        — split-string obfuscation        MEDIUM
 *  9.  process.binding()           — direct Node.js internal access  HIGH
 * 10.  Long charCode array >8 elem — payload encoded as int array    HIGH
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

    // 2. Function() constructor
    const functionMatches = source.match(/(?:new\s+)?Function\s*\(/g);
    if (functionMatches && functionMatches.length > 0) {
        indicators.push({
            type: 'FUNCTION_CONSTRUCTOR',
            severity: 'HIGH',
            count: functionMatches.length,
            description: `Function() constructor found ${functionMatches.length} time(s)`
        });
    }

    // 3. Buffer.from(...).toString() — common base64 decode pattern (threshold: >2)
    const bufferDecodeMatches = source.match(/Buffer\.from\s*\([^)]+\)\s*\.toString/g);
    if (bufferDecodeMatches && bufferDecodeMatches.length > 2) {
        indicators.push({
            type: 'BUFFER_DECODE',
            severity: 'MEDIUM',
            count: bufferDecodeMatches.length,
            description: `Buffer.from().toString() found ${bufferDecodeMatches.length} times — possible encoded payload`
        });
    }

    // 4. Long hex string literals (>100 chars)
    const hexStringMatches = source.match(/['"][0-9a-fA-F]{100,}['"]/g);
    if (hexStringMatches) {
        indicators.push({
            type: 'HEX_STRING_LITERAL',
            severity: 'HIGH',
            count: hexStringMatches.length,
            description: `Long hex string literal(s) found (${hexStringMatches.length})`
        });
    }

    // 5. \\x escape density >10%
    const xEscapeMatches = source.match(/\\x[0-9a-fA-F]{2}/g);
    if (xEscapeMatches && source.length > 0) {
        const density = (xEscapeMatches.length * 4) / source.length;
        if (density > 0.10) {
            indicators.push({
                type: 'HIGH_HEX_ESCAPE_DENSITY',
                severity: 'HIGH',
                density: density.toFixed(4),
                description: `\\x escape density ${(density * 100).toFixed(1)}% — heavily obfuscated source`
            });
        }
    }

    // 6. String.fromCharCode chains (threshold: >3)
    const fromCharCodeMatches = source.match(/String\.fromCharCode/g);
    if (fromCharCodeMatches && fromCharCodeMatches.length > 3) {
        indicators.push({
            type: 'FROM_CHAR_CODE_CHAIN',
            severity: 'HIGH',
            count: fromCharCodeMatches.length,
            description: `String.fromCharCode() found ${fromCharCodeMatches.length} times — character-code string obfuscation`
        });
    }

    // 7. atob() — browser-style base64 decode (present in some Node environments)
    const atobMatches = source.match(/atob\s*\(/g);
    if (atobMatches && atobMatches.length > 0) {
        indicators.push({
            type: 'ATOB_USAGE',
            severity: 'MEDIUM',
            count: atobMatches.length,
            description: `atob() found ${atobMatches.length} time(s) — Base64 decoding`
        });
    }

    // 8. Excessive short-string concatenation (threshold: >5 chains)
    const concatMatches = source.match(/['"][^'"]{1,5}['"]\s*\+\s*['"][^'"]{1,5}['"]\s*\+\s*['"][^'"]{1,5}['"]/g);
    if (concatMatches && concatMatches.length > 5) {
        indicators.push({
            type: 'EXCESSIVE_CONCATENATION',
            severity: 'MEDIUM',
            count: concatMatches.length,
            description: `Suspicious string concatenation chains (${concatMatches.length}) — possible split-string obfuscation`
        });
    }

    // 9. process.binding() — direct access to Node.js C++ internals
    //    Legitimate use is vanishingly rare outside Node.js core itself.
    const bindingMatches = source.match(/process\.binding\s*\(/g);
    if (bindingMatches && bindingMatches.length > 0) {
        indicators.push({
            type: 'PROCESS_BINDING',
            severity: 'HIGH',
            count: bindingMatches.length,
            description: `process.binding() found ${bindingMatches.length} time(s) — direct Node.js internal access`
        });
    }

    // 10. Long integer array (charCode payload) — e.g. [72,101,108,108,111,...] >8 elements
    const charCodeArrayMatches = source.match(/\[(?:\d{1,3},\s*){8,}\d{1,3}\]/g);
    if (charCodeArrayMatches && charCodeArrayMatches.length > 0) {
        indicators.push({
            type: 'CHAR_CODE_ARRAY',
            severity: 'HIGH',
            count: charCodeArrayMatches.length,
            description: `Long integer array(s) found (${charCodeArrayMatches.length}) — possible payload encoded as charCode sequence`
        });
    }

    // 11. Prototype pollution patterns
    //     Object.prototype assignment, __proto__ mutation, constructor.prototype manipulation
    const protoPatterns = [
        { re: /Object\.prototype\.\w+\s*=/, label: 'Object.prototype property assignment' },
        { re: /__proto__\s*[=[]/, label: '__proto__ mutation' },
        { re: /\[['"]__proto__['"]\]/, label: '__proto__ bracket access' },
        { re: /constructor\s*\.\s*prototype\s*\.\w+\s*=/, label: 'constructor.prototype mutation' }
    ];
    for (const { re, label } of protoPatterns) {
        if (re.test(source)) {
            indicators.push({
                type: 'PROTO_POLLUTION',
                severity: 'HIGH',
                description: `Prototype pollution pattern: ${label}`
            });
        }
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
