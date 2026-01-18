/**
 * Demo: Real-world attack scenario
 * 
 * This simulates an application that unknowingly loads
 * a compromised npm package
 */

'use strict';

console.log('=== Starting Application ===\n');

// Your legitimate application code
console.log('Loading dependencies...');

// Unknowingly loading a compromised package
// (In reality, this would be in your package.json dependencies)
const maliciousPackage = require('malicious-package');

console.log(`Using ${maliciousPackage.version}`);
console.log(`Result: ${maliciousPackage.doSomething()}\n`);

// Your app continues normally...
console.log('Application running normally...');
console.log('User has no idea malicious code just executed!\n');

console.log('=== Application Complete ===');
console.log('\nBHEESHMA detected the malicious activity...');
