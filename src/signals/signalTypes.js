'use strict';

/**
 * Signal Types — enumeration of all observable runtime behaviors.
 * @readonly
 * @enum {string}
 */
const SignalType = Object.freeze({
    ENV_ACCESS:           'ENV_ACCESS',           // process.env property access
    FS_READ:              'FS_READ',              // fs read operation
    FS_WRITE:             'FS_WRITE',             // fs write operation
    SHELL_EXEC:           'SHELL_EXEC',           // child_process exec/spawn/fork
    NET_CONNECT:          'NET_CONNECT',          // raw TCP or IPC socket connect
    HTTP_REQUEST:         'HTTP_REQUEST',         // http.request
    HTTPS_REQUEST:        'HTTPS_REQUEST',        // https.request
    DNS_QUERY:            'DNS_QUERY',            // dns.lookup/resolve/*
    OBFUSCATION_DETECTED: 'OBFUSCATION_DETECTED', // static obfuscation scan hit
    VM_EXEC:              'VM_EXEC',              // vm.runInNewContext / vm.Script
    CRYPTO_OP:            'CRYPTO_OP',            // crypto cipher/decipher/hash
    HOOK_TAMPER:          'HOOK_TAMPER',          // bheeshma hook was overwritten
    PROTO_POLLUTION:      'PROTO_POLLUTION',      // prototype pollution attempt
});

/**
 * Create an immutable signal object.
 * All fields are frozen to prevent post-creation tampering.
 *
 * @param {string} type          - SignalType value
 * @param {object} metadata      - Type-specific metadata (never contains secrets)
 * @param {string} packageName   - Attributed npm package name (null = first-party)
 * @param {string} packageVersion
 * @param {string} stackTrace    - Raw stack trace string
 * @returns {object} Frozen signal
 */
function createSignal(type, metadata, packageName, packageVersion, stackTrace) {
    if (!Object.values(SignalType).includes(type)) {
        throw new TypeError(`Invalid signal type: ${type}`);
    }
    return Object.freeze({
        timestamp:  new Date().toISOString(),
        type,
        package:    packageName  || null,
        version:    packageVersion || null,
        metadata:   metadata    || {},
        stackTrace: stackTrace  || null
    });
}

/**
 * Validate signal metadata fields for a given type.
 *
 * @param {string} type
 * @param {object} metadata
 * @returns {boolean}
 */
function validateSignalMetadata(type, metadata) {
    if (!metadata || typeof metadata !== 'object') return false;

    switch (type) {
        case SignalType.ENV_ACCESS:
            return typeof metadata.variable === 'string';
        case SignalType.FS_READ:
        case SignalType.FS_WRITE:
            return typeof metadata.path === 'string';
        case SignalType.SHELL_EXEC:
            return typeof metadata.command === 'string';
        case SignalType.NET_CONNECT:
            return typeof metadata.host === 'string';
        case SignalType.HTTP_REQUEST:
        case SignalType.HTTPS_REQUEST:
            return typeof metadata.url === 'string' && typeof metadata.method === 'string';
        case SignalType.DNS_QUERY:
            return typeof metadata.hostname === 'string';
        case SignalType.OBFUSCATION_DETECTED:
            return typeof metadata.indicators === 'object';
        case SignalType.VM_EXEC:
            return typeof metadata.method === 'string';
        case SignalType.CRYPTO_OP:
            return typeof metadata.operation === 'string';
        case SignalType.HOOK_TAMPER:
            return typeof metadata.hook === 'string';
        case SignalType.PROTO_POLLUTION:
            return typeof metadata.pattern === 'string';
        default:
            return false;
    }
}

module.exports = { SignalType, createSignal, validateSignalMetadata };
