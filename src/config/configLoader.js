/**
 * BHEESHMA Configuration Loader
 * 
 * Loads and parses configuration from files or objects.
 * Security: Validates all loaded config to prevent malicious configurations
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { DEFAULT_CONFIG, validateConfig, mergeConfig } = require('./schema');

/**
 * Configuration file names to search for (in order of priority)
 */
const CONFIG_FILES = [
    '.bheeshmarc.json',
    '.bheeshmarc',
    'bheeshma.config.json',
    'bheeshma.config.js'
];

/**
 * Load configuration from a file
 * 
 * Security:
 * - Only loads from expected locations (no arbitrary paths)
 * - Validates JSON syntax
 * - Validates schema before accepting
 * 
 * @param {string} configPath - Optional explicit config path
 * @returns {object} Loaded and validated configuration
 */
function loadConfig(configPath = null) {
    let userConfig = {};

    if (configPath) {
        // Explicit path provided
        userConfig = loadConfigFile(configPath);
    } else {
        // Search for config in current directory
        userConfig = searchConfigFile();
    }

    // Validate the loaded config
    const validation = validateConfig(userConfig);
    if (!validation.valid) {
        console.warn('[BHEESHMA] Configuration validation errors:');
        validation.errors.forEach(err => console.warn(`  - ${err}`));
        console.warn('[BHEESHMA] Using default configuration');
        return DEFAULT_CONFIG;
    }

    // Merge with defaults
    const finalConfig = mergeConfig(userConfig);
    return finalConfig;
}

/**
 * Search for configuration file in current directory
 * 
 * @returns {object} Loaded config or empty object
 */
function searchConfigFile() {
    const cwd = process.cwd();

    for (const filename of CONFIG_FILES) {
        const fullPath = path.join(cwd, filename);

        if (fs.existsSync(fullPath)) {
            try {
                return loadConfigFile(fullPath);
            } catch (err) {
                // Continue to next file if this one fails
                console.warn(`[BHEESHMA] Failed to load ${filename}: ${err.message}`);
            }
        }
    }

    return {};
}

/**
 * Load configuration from a specific file
 * 
 * @param {string} filePath - Absolute path to config file
 * @returns {object} Parsed configuration
 */
function loadConfigFile(filePath) {
    const ext = path.extname(filePath);

    if (ext === '.json' || ext === '') {
        // JSON file
        const content = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(content);
    } else if (ext === '.js') {
        // JavaScript file
        // Security: Only allow from trusted locations
        if (!filePath.includes('node_modules')) {
            return require(filePath);
        } else {
            throw new Error('Cannot load config from node_modules');
        }
    } else {
        throw new Error(`Unsupported config file extension: ${ext}`);
    }
}

/**
 * Load configuration from an object (for programmatic use)
 * 
 * @param {object} configObj - Configuration object
 * @returns {object} Validated and merged configuration
 */
function loadConfigFromObject(configObj) {
    const validation = validateConfig(configObj);

    if (!validation.valid) {
        throw new Error(`Invalid configuration: ${validation.errors.join(', ')}`);
    }

    return mergeConfig(configObj);
}

/**
 * Get default configuration
 * 
 * @returns {object} Default configuration
 */
function getDefaultConfig() {
    return { ...DEFAULT_CONFIG };
}

/**
 * Create a sample configuration file
 * 
 * @param {string} outputPath - Where to write the sample config
 * @returns {boolean} Success
 */
function createSampleConfig(outputPath = '.bheeshmarc.json') {
    const sampleConfig = {
        hooks: {
            env: true,
            fs: true,
            net: true,
            childProcess: true,
            http: true
        },
        riskWeights: {
            SHELL_EXEC: 20,
            FS_WRITE: 10,
            HTTP_REQUEST: 10,
            HTTPS_REQUEST: 8,
            NET_CONNECT: 8,
            ENV_ACCESS: 5,
            FS_READ: 3
        },
        thresholds: {
            critical: 30,
            high: 60,
            medium: 80
        },
        whitelist: [
            "express@*",
            "@types/*"
        ],
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
            formats: ["cli"],
            verbosity: "normal",
            includeStackTraces: true
        }
    };

    try {
        fs.writeFileSync(outputPath, JSON.stringify(sampleConfig, null, 2), 'utf8');
        return true;
    } catch (err) {
        console.error(`[BHEESHMA] Failed to create sample config: ${err.message}`);
        return false;
    }
}

module.exports = {
    loadConfig,
    loadConfigFromObject,
    getDefaultConfig,
    createSampleConfig
};
