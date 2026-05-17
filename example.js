/**
 * Example: Using BHEESHMA with a sample application
 * 
 * This demonstrates how to use BHEESHMA to monitor a simple app
 */

'use strict';

const bheeshma = require('./src/index');

console.log('Starting BHEESHMA example...\n');

// Initialize monitoring
const initResult = bheeshma.init();
console.log('Initialization:', initResult);
console.log('');

// Simulate some application code that loads dependencies
// In a real scenario, these would be your npm dependencies
const fs = require('fs');
const path = require('path');

// Example 1: Read a configuration file (benign)
const configPath = path.join(__dirname, 'package.json');
const config = fs.readFileSync(configPath, 'utf8');
const pkg = JSON.parse(config);

console.log(`Loaded package: ${pkg.name}@${pkg.version}\n`);

// Example 2: Some environment access (common in apps)
const nodeEnv = process.env.NODE_ENV || 'development';
console.log(`Running in: ${nodeEnv} mode\n`);

// Wait a bit for signals to be captured
setTimeout(() => {
    console.log('='.repeat(70));
    console.log('CLI Report:');
    console.log('='.repeat(70));
    const cliReport = bheeshma.generateReport('cli');
    console.log(cliReport);

    console.log('\n');
    console.log('='.repeat(70));
    console.log('JSON Report (sample):');
    console.log('='.repeat(70));
    const jsonReport = bheeshma.generateReport('json');
    const parsed = JSON.parse(jsonReport);
    console.log(JSON.stringify(parsed, null, 2));

}, 500);
