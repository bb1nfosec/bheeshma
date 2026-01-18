/**
 * Suspicious Dependency Simulation
 * 
 * Purpose: Simulates a malicious npm package with multiple risky behaviors.
 * Expected: Low trust score (< 50)
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');
const { exec } = require('child_process');

/**
 * Simulate malicious behaviors that BHEESHMA should detect
 */
function maliciousBehaviors() {
    try {
        // 1. Access environment variables (potential credential theft)
        const nodeEnv = process.env.NODE_ENV;
        const home = process.env.HOME || process.env.USERPROFILE;
        const path = process.env.PATH;
        const apiKey = process.env.API_KEY; // Common secret name
        const token = process.env.TOKEN;

        // 2. Write to filesystem (persistence mechanism)
        const tempDir = os.tmpdir();
        const maliciousFile = path.join(tempDir, 'suspicious-file.txt');

        try {
            fs.writeFileSync(maliciousFile, 'suspicious content', 'utf8');

            // Clean up (so test doesn't pollute system)
            fs.unlinkSync(maliciousFile);
        } catch (err) {
            // Ignore write errors (may not have permissions)
        }

        // 3. Attempt outbound network connection (data exfiltration)
        const req = http.request({
            hostname: 'example.com',
            port: 80,
            path: '/',
            method: 'GET'
        });

        // Don't actually complete the request (offline test)
        req.on('error', () => {
            // Expected - we don't want to actually make the connection
        });

        // Immediately abort
        req.destroy();

        // 4. Execute shell command (arbitrary code execution)
        // Use a harmless command that won't damage system
        try {
            exec('echo "suspicious command"', (error, stdout, stderr) => {
                // Silent execution
            });
        } catch (err) {
            // Ignore exec errors
        }

        // 5. Additional filesystem writes
        const homeConfigPath = path.join(tempDir, '.suspiciousrc');
        try {
            fs.writeFileSync(homeConfigPath, '{}', 'utf8');
            fs.unlinkSync(homeConfigPath);
        } catch (err) {
            // Ignore
        }

        return { executed: true };
    } catch (err) {
        return { executed: false, error: err.message };
    }
}

// Execute suspicious behaviors
const result = maliciousBehaviors();

module.exports = { maliciousBehaviors, result };
