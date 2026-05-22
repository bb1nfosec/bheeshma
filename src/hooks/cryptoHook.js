'use strict';

/**
 * BHEESHMA Crypto API Hook
 *
 * Monitors use of Node.js `crypto` module functions that indicate:
 * - Payload unpacking: createDecipheriv() called by a package with no obvious
 *   reason to decrypt things (string utils, date formatters, HTTP clients)
 * - C2 authentication: createHmac() used to sign requests to a remote server
 * - Key derivation: pbkdf2() / scrypt() used to derive keys from embedded seeds
 * - Embedded ciphers: createCipheriv() used to encrypt harvested credentials
 *
 * Low-signal operations like createHash('sha256') for integrity checks are
 * captured with lower weight. Decipher/cipher ops get higher weight since
 * they imply an embedded encrypted payload.
 *
 * Wrapped: createCipheriv, createDecipheriv, createHash, createHmac,
 *          randomBytes, pbkdf2, pbkdf2Sync, scrypt, scryptSync
 */

const crypto = require('crypto');
const { createSignal, SignalType } = require('../signals/signalTypes');
const { resolveCurrentStack } = require('../attribution/resolver');

let signalCollector = null;
let hookConfig = null;
let isHookInstalled = false;

// Higher suspicion level for encrypt/decrypt ops vs hashing
const HIGH_SUSPICION_OPS = new Set([
    'createCipheriv', 'createDecipheriv', 'createDiffieHellman',
    'createECDH', 'pbkdf2', 'pbkdf2Sync', 'scrypt', 'scryptSync'
]);

const WRAPPED_FUNCTIONS = [
    'createCipheriv',
    'createDecipheriv',
    'createHash',
    'createHmac',
    'randomBytes',
    'randomFill',
    'pbkdf2',
    'pbkdf2Sync',
    'scrypt',
    'scryptSync'
];

const originalFunctions = {};

function install(collector, config) {
    try {
        if (isHookInstalled) return true;
        signalCollector = collector;
        hookConfig = config;

        for (const fnName of WRAPPED_FUNCTIONS) {
            if (typeof crypto[fnName] === 'function') hookCryptoFunction(fnName);
        }

        isHookInstalled = true;
        return true;
    } catch (err) {
        console.error('[BHEESHMA] Failed to install crypto hook:', err.message);
        return false;
    }
}

function hookCryptoFunction(fnName) {
    originalFunctions[fnName] = crypto[fnName];

    crypto[fnName] = function (...args) {
        try { emitCryptoSignal(fnName, args); } catch (_) {}
        return originalFunctions[fnName].apply(this, args);
    };

    Object.defineProperty(crypto[fnName], 'name', { value: fnName, configurable: true });
}

function emitCryptoSignal(operation, args) {
    const attribution = resolveCurrentStack();
    if (!attribution) return;

    const metadata = {
        operation,
        isHighSuspicion: HIGH_SUSPICION_OPS.has(operation)
    };

    // Capture algorithm name (first arg for createHash/createCipheriv etc) — not a secret
    if (typeof args[0] === 'string') {
        metadata.algorithm = args[0];
    }

    const signal = createSignal(
        SignalType.CRYPTO_OP,
        metadata,
        attribution.name,
        attribution.version,
        new Error().stack
    );
    signalCollector.push(signal);
}

function uninstall() {
    try {
        if (!isHookInstalled) return true;
        for (const [fnName, orig] of Object.entries(originalFunctions)) {
            if (orig) crypto[fnName] = orig;
        }
        isHookInstalled = false;
        signalCollector = null;
        hookConfig = null;
        return true;
    } catch (_) {
        return false;
    }
}

module.exports = { install, uninstall };
