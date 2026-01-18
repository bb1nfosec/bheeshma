/**
 * BHEESHMA Configuration Schema
 * 
 * Defines the structure and validation rules for configuration files.
 * Security: Validates all config to prevent injection attacks
 */

'use strict';

const { SignalType } = require('../signals/signalTypes');

/**
 * Default configuration
 * These are the fallback values if no config file is provided
 */
const DEFAULT_CONFIG = Object.freeze({
    hooks: {
        env: true,
        fs: true,
        net: true,
        childProcess: true,
        http: true
    },
    riskWeights: {
        [SignalType.SHELL_EXEC]: 20,
        [SignalType.FS_WRITE]: 10,
        [SignalType.NET_CONNECT]: 8,
        [SignalType.HTTP_REQUEST]: 10,
        [SignalType.HTTPS_REQUEST]: 8,
        [SignalType.ENV_ACCESS]: 5,
        [SignalType.FS_READ]: 3
    },
    thresholds: {
        critical: 30,
        high: 60,
        medium: 80
    },
    whitelist: [],
    blacklist: [],
    patterns: {
        enabled: true,
        detectCryptoMiners: true,
        detectDataExfiltration: true,
        detectBackdoors: true,
        detectObfuscation: true
    },
    performance: {
        track: false,
        maxSignals: 10000
    },
    output: {
        formats: ['cli'],
        verbosity: 'normal',
        includeStackTraces: true
    }
});

/**
 * Validate configuration object
 * 
 * @param {object} config - Configuration to validate
 * @returns {object} { valid: boolean, errors: string[] }
 */
function validateConfig(config) {
    const errors = [];

    if (!config || typeof config !== 'object') {
        return { valid: false, errors: ['Configuration must be an object'] };
    }

    // Validate hooks section
    if (config.hooks) {
        if (typeof config.hooks !== 'object') {
            errors.push('hooks must be an object');
        } else {
            const validHooks = ['env', 'fs', 'net', 'childProcess', 'http'];
            for (const [key, value] of Object.entries(config.hooks)) {
                if (!validHooks.includes(key)) {
                    errors.push(`Invalid hook: ${key}`);
                }
                if (typeof value !== 'boolean') {
                    errors.push(`Hook ${key} must be a boolean`);
                }
            }
        }
    }

    // Validate risk weights
    if (config.riskWeights) {
        if (typeof config.riskWeights !== 'object') {
            errors.push('riskWeights must be an object');
        } else {
            for (const [key, value] of Object.entries(config.riskWeights)) {
                if (!Object.values(SignalType).includes(key)) {
                    errors.push(`Invalid signal type in riskWeights: ${key}`);
                }
                if (typeof value !== 'number' || value < 0 || value > 100) {
                    errors.push(`Risk weight for ${key} must be a number between 0-100`);
                }
            }
        }
    }

    // Validate thresholds
    if (config.thresholds) {
        if (typeof config.thresholds !== 'object') {
            errors.push('thresholds must be an object');
        } else {
            const { critical, high, medium } = config.thresholds;
            if (critical !== undefined && (typeof critical !== 'number' || critical < 0 || critical > 100)) {
                errors.push('critical threshold must be 0-100');
            }
            if (high !== undefined && (typeof high !== 'number' || high < 0 || high > 100)) {
                errors.push('high threshold must be 0-100');
            }
            if (medium !== undefined && (typeof medium !== 'number' || medium < 0 || medium > 100)) {
                errors.push('medium threshold must be 0-100');
            }
            if (critical !== undefined && high !== undefined && critical >= high) {
                errors.push('critical threshold must be less than high threshold');
            }
            if (high !== undefined && medium !== undefined && high >= medium) {
                errors.push('high threshold must be less than medium threshold');
            }
        }
    }

    // Validate whitelist/blacklist
    if (config.whitelist && !Array.isArray(config.whitelist)) {
        errors.push('whitelist must be an array');
    }
    if (config.blacklist && !Array.isArray(config.blacklist)) {
        errors.push('blacklist must be an array');
    }

    // Validate patterns
    if (config.patterns) {
        if (typeof config.patterns !== 'object') {
            errors.push('patterns must be an object');
        }
    }

    // Validate performance
    if (config.performance) {
        if (typeof config.performance !== 'object') {
            errors.push('performance must be an object');
        } else {
            if (config.performance.maxSignals !== undefined) {
                if (typeof config.performance.maxSignals !== 'number' || config.performance.maxSignals < 1) {
                    errors.push('maxSignals must be a positive number');
                }
            }
        }
    }

    return {
        valid: errors.length === 0,
        errors
    };
}

/**
 * Merge user config with defaults
 * 
 * @param {object} userConfig - User-provided configuration
 * @returns {object} Merged configuration
 */
function mergeConfig(userConfig) {
    // Deep merge user config with defaults
    return {
        hooks: { ...DEFAULT_CONFIG.hooks, ...userConfig.hooks },
        riskWeights: { ...DEFAULT_CONFIG.riskWeights, ...userConfig.riskWeights },
        thresholds: { ...DEFAULT_CONFIG.thresholds, ...userConfig.thresholds },
        whitelist: userConfig.whitelist || DEFAULT_CONFIG.whitelist,
        blacklist: userConfig.blacklist || DEFAULT_CONFIG.blacklist,
        patterns: { ...DEFAULT_CONFIG.patterns, ...userConfig.patterns },
        performance: { ...DEFAULT_CONFIG.performance, ...userConfig.performance },
        output: { ...DEFAULT_CONFIG.output, ...userConfig.output }
    };
}

module.exports = {
    DEFAULT_CONFIG,
    validateConfig,
    mergeConfig
};
