/**
 * Realistic Test: Simulating a typical web application
 * 
 * This simulates behaviors you'd see in a real Node.js app
 */

'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');

console.log('=== Simulated Web Application ===\n');

// 1. Load configuration (common pattern)
console.log('Loading configuration...');
const configPath = path.join(__dirname, 'package.json');
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
console.log(`App: ${config.name} v${config.version}\n`);

// 2. Check environment (very common)
console.log('Checking environment...');
const env = process.env.NODE_ENV || 'development';
const port = process.env.PORT || 3000;
console.log(`Environment: ${env}`);
console.log(`Port: ${port}\n`);

// 3. Simulate a simple HTTP request (hypothetical API call)
console.log('Would make HTTP request (simulated)...');
// Note: We're not actually making the request to keep test offline
const req = http.request({
    hostname: 'api.example.com',
    port: 443,
    path: '/health',
    method: 'GET'
});
req.on('error', () => { }); // Silent
req.destroy(); // Abort immediately
console.log('HTTP request hook triggered\n');

// 4. Check for log directory (common pattern)
console.log('Checking filesystem for logs directory...');
const logDir = path.join(__dirname, 'logs');
const logsExist = fs.existsSync(logDir);
console.log(`Logs directory exists: ${logsExist}\n`);

console.log('=== Application simulation complete ===');
console.log('BHEESHMA will now generate a report of observed behaviors...\n');
