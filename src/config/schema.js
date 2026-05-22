'use strict';

const { SignalType } = require('../signals/signalTypes');

const DEFAULT_CONFIG = Object.freeze({
    hooks: {
        env:          true,
        fs:           true,
        net:          true,
        childProcess: true,
        http:         true,
        dns:          true,
        vm:           true,   // vm module code execution
        crypto:       true    // crypto cipher/decipher/hash operations
    },
    riskWeights: {
        [SignalType.SHELL_EXEC]:           20,
        [SignalType.FS_WRITE]:             10,
        [SignalType.NET_CONNECT]:           8,
        [SignalType.HTTP_REQUEST]:         10,
        [SignalType.HTTPS_REQUEST]:         8,
        [SignalType.ENV_ACCESS]:            5,
        [SignalType.FS_READ]:               3,
        [SignalType.DNS_QUERY]:             4,
        [SignalType.OBFUSCATION_DETECTED]: 25,
        [SignalType.VM_EXEC]:              20,
        [SignalType.CRYPTO_OP]:             8,
        [SignalType.HOOK_TAMPER]:         100,
        [SignalType.PROTO_POLLUTION]:      30
    },
    thresholds: {
        critical: 30,
        high:     60,
        medium:   80
    },
    packageThresholds: {},
    whitelist: [],
    blacklist: [],
    patterns: {
        enabled:               true,
        detectCryptoMiners:    true,
        detectDataExfiltration:true,
        detectBackdoors:       true,
        detectObfuscation:     true
    },
    performance: {
        track:              false,
        maxSignals:         10000,
        deduplicateSignals: true,
        // Sampling rate for duplicate signals (1.0 = record all, 0.01 = 1%).
        // First occurrence of any dedup key is always recorded regardless of rate.
        sampleRate:         1.0
    },
    output: {
        formats:            ['cli'],
        verbosity:          'normal',
        includeStackTraces: true
    },
    // Persistent signal log — append NDJSON to this file as signals arrive.
    // null = disabled (in-memory only).
    logging: {
        logFile: null
    },
    // Behavioral baseline file path. When set, signals matching the baseline
    // are suppressed before scoring (--baseline mode).
    baselineFile: null,
    enforce:      false,
    alertWebhook: null,
    // Webhook output format: 'generic' | 'slack' | 'pagerduty' | 'teams'
    webhookFormat: 'generic'
});

/**
 * Deep-validate a user-supplied config object.
 *
 * @param {object} config
 * @returns {{ valid: boolean, errors: string[] }}
 */
function validateConfig(config) {
    const errors = [];

    if (!config || typeof config !== 'object') {
        return { valid: false, errors: ['Configuration must be an object'] };
    }

    if (config.hooks) {
        if (typeof config.hooks !== 'object') {
            errors.push('hooks must be an object');
        } else {
            const validHooks = ['env', 'fs', 'net', 'childProcess', 'http', 'dns', 'vm', 'crypto'];
            for (const [key, value] of Object.entries(config.hooks)) {
                if (!validHooks.includes(key)) errors.push(`Invalid hook: ${key}`);
                if (typeof value !== 'boolean') errors.push(`Hook ${key} must be a boolean`);
            }
        }
    }

    if (config.riskWeights) {
        if (typeof config.riskWeights !== 'object') {
            errors.push('riskWeights must be an object');
        } else {
            for (const [key, value] of Object.entries(config.riskWeights)) {
                if (!Object.values(SignalType).includes(key)) errors.push(`Invalid signal type in riskWeights: ${key}`);
                if (typeof value !== 'number' || value < 0 || value > 100) errors.push(`Risk weight for ${key} must be 0-100`);
            }
        }
    }

    if (config.thresholds) {
        if (typeof config.thresholds !== 'object') {
            errors.push('thresholds must be an object');
        } else {
            const { critical, high, medium } = config.thresholds;
            if (critical !== undefined && (typeof critical !== 'number' || critical < 0 || critical > 100)) errors.push('critical threshold must be 0-100');
            if (high     !== undefined && (typeof high     !== 'number' || high     < 0 || high     > 100)) errors.push('high threshold must be 0-100');
            if (medium   !== undefined && (typeof medium   !== 'number' || medium   < 0 || medium   > 100)) errors.push('medium threshold must be 0-100');
            if (critical !== undefined && high !== undefined && critical >= high) errors.push('critical must be < high');
            if (high     !== undefined && medium !== undefined && high >= medium) errors.push('high must be < medium');
        }
    }

    if (config.packageThresholds) {
        if (typeof config.packageThresholds !== 'object' || Array.isArray(config.packageThresholds)) {
            errors.push('packageThresholds must be an object');
        } else {
            for (const [k, v] of Object.entries(config.packageThresholds)) {
                if (typeof v !== 'number' || v < 0 || v > 100) errors.push(`packageThresholds["${k}"] must be 0-100`);
            }
        }
    }

    if (config.whitelist && !Array.isArray(config.whitelist)) errors.push('whitelist must be an array');
    if (config.blacklist && !Array.isArray(config.blacklist)) errors.push('blacklist must be an array');

    if (config.performance) {
        if (typeof config.performance !== 'object') {
            errors.push('performance must be an object');
        } else {
            if (config.performance.maxSignals !== undefined &&
                (typeof config.performance.maxSignals !== 'number' || config.performance.maxSignals < 1)) {
                errors.push('maxSignals must be a positive number');
            }
            if (config.performance.sampleRate !== undefined) {
                const sr = config.performance.sampleRate;
                if (typeof sr !== 'number' || sr <= 0 || sr > 1) errors.push('sampleRate must be > 0 and ≤ 1');
            }
        }
    }

    if (config.logging) {
        if (typeof config.logging !== 'object') {
            errors.push('logging must be an object');
        } else if (config.logging.logFile !== undefined && config.logging.logFile !== null &&
                   typeof config.logging.logFile !== 'string') {
            errors.push('logging.logFile must be a string path or null');
        }
    }

    if (config.baselineFile !== undefined && config.baselineFile !== null &&
        typeof config.baselineFile !== 'string') {
        errors.push('baselineFile must be a string path or null');
    }

    if (config.enforce !== undefined && typeof config.enforce !== 'boolean') errors.push('enforce must be a boolean');

    if (config.alertWebhook !== undefined && config.alertWebhook !== null &&
        typeof config.alertWebhook !== 'string') {
        errors.push('alertWebhook must be a string URL or null');
    }

    const validWebhookFormats = ['generic', 'slack', 'pagerduty', 'teams'];
    if (config.webhookFormat !== undefined && !validWebhookFormats.includes(config.webhookFormat)) {
        errors.push(`webhookFormat must be one of: ${validWebhookFormats.join(', ')}`);
    }

    return { valid: errors.length === 0, errors };
}

/**
 * Deep-merge user config with defaults.
 *
 * @param {object} userConfig
 * @returns {object} Merged config
 */
function mergeConfig(userConfig) {
    return {
        hooks:            { ...DEFAULT_CONFIG.hooks,             ...userConfig.hooks },
        riskWeights:      { ...DEFAULT_CONFIG.riskWeights,       ...userConfig.riskWeights },
        thresholds:       { ...DEFAULT_CONFIG.thresholds,        ...userConfig.thresholds },
        packageThresholds: userConfig.packageThresholds || DEFAULT_CONFIG.packageThresholds,
        whitelist:        userConfig.whitelist        || DEFAULT_CONFIG.whitelist,
        blacklist:        userConfig.blacklist        || DEFAULT_CONFIG.blacklist,
        patterns:         { ...DEFAULT_CONFIG.patterns,          ...userConfig.patterns },
        performance:      { ...DEFAULT_CONFIG.performance,       ...userConfig.performance },
        output:           { ...DEFAULT_CONFIG.output,            ...userConfig.output },
        logging:          { ...DEFAULT_CONFIG.logging,           ...(userConfig.logging || {}) },
        baselineFile:     userConfig.baselineFile  !== undefined ? userConfig.baselineFile  : DEFAULT_CONFIG.baselineFile,
        enforce:          userConfig.enforce       !== undefined ? userConfig.enforce       : DEFAULT_CONFIG.enforce,
        alertWebhook:     userConfig.alertWebhook  !== undefined ? userConfig.alertWebhook  : DEFAULT_CONFIG.alertWebhook,
        webhookFormat:    userConfig.webhookFormat !== undefined ? userConfig.webhookFormat : DEFAULT_CONFIG.webhookFormat
    };
}

module.exports = { DEFAULT_CONFIG, validateConfig, mergeConfig };
