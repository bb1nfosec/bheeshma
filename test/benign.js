/**
 * Benign Dependency Simulation
 * 
 * Purpose: Simulates a well-behaved npm package with minimal risky behavior.
 * Expected: High trust score (>= 80)
 */

'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Simulate a utility package that reads its own package.json
 * This is common and benign behavior.
 */
function init() {
    try {
        // Read package.json (common benign operation)
        const packagePath = path.join(__dirname, '../package.json');

        if (fs.existsSync(packagePath)) {
            const content = fs.readFileSync(packagePath, 'utf8');
            const pkg = JSON.parse(content);

            // Use the data in a benign way
            const name = pkg.name || 'unknown';

            // Return some harmless result
            return { initialized: true, name };
        }
    } catch (err) {
        // Silent failure is fine for test
    }

    return { initialized: false };
}

// Execute benign behavior
const result = init();

module.exports = { init, result };
