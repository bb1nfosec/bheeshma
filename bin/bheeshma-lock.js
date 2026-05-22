#!/usr/bin/env node

/**
 * bheeshma lock — lockfile integrity checker.
 *
 * Computes a SHA-256 hash of package-lock.json / yarn.lock / pnpm-lock.yaml
 * and either records it (--save) or verifies it hasn't changed (--verify).
 *
 * Usage:
 *   bheeshma-lock --save                        # Hash all lockfiles, write .bheeshma-lock.json
 *   bheeshma-lock --verify                       # Compare current hashes against saved
 *   bheeshma-lock --save --lock-file yarn.lock   # Hash a specific lockfile
 *
 * Exit codes:
 *   0 — integrity verified (or save succeeded)
 *   1 — integrity violation detected
 *   2 — usage error / no lockfile found
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

const LOCKFILE_NAMES = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json'];
const DEFAULT_HASH_FILE = '.bheeshma-lock.json';

function printHelp() {
    console.log(`
bheeshma lock — lockfile integrity checker

Usage:
  bheeshma-lock --save [options]     Hash lockfiles, write integrity record
  bheeshma-lock --verify [options]   Verify lockfiles match saved hashes

Options:
  --lock-file <path>   Target a specific lockfile (default: auto-detect)
  --hash-file <path>   Path to integrity record (default: .bheeshma-lock.json)
  --help, -h           Show this help

Exit codes:
  0 — integrity verified / save succeeded
  1 — integrity violation (hash mismatch or missing lockfile)
  2 — usage error
`);
}

function parseArgs() {
    const args = process.argv.slice(2);
    const opts = { mode: null, lockFile: null, hashFile: DEFAULT_HASH_FILE };
    let i = 0;
    while (i < args.length) {
        const arg = args[i];
        if (arg === '--save')    { opts.mode = 'save'; i++; }
        else if (arg === '--verify') { opts.mode = 'verify'; i++; }
        else if (arg === '--lock-file') { opts.lockFile = args[++i]; i++; }
        else if (arg === '--hash-file') { opts.hashFile = args[++i]; i++; }
        else if (arg === '--help' || arg === '-h') { printHelp(); process.exit(0); }
        else { i++; }
    }
    return opts;
}

function hashFile(filePath) {
    const content = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(content).digest('hex');
}

function discoverLockfiles(cwd) {
    return LOCKFILE_NAMES
        .map(name => path.join(cwd, name))
        .filter(p => fs.existsSync(p));
}

function save(opts) {
    const cwd = process.cwd();
    const targets = opts.lockFile
        ? [path.resolve(opts.lockFile)]
        : discoverLockfiles(cwd);

    if (targets.length === 0) {
        console.error('[bheeshma-lock] No lockfiles found. Run npm install first.');
        process.exit(2);
    }

    const record = {
        version: 1,
        savedAt: new Date().toISOString(),
        hashes: {}
    };

    for (const filePath of targets) {
        const rel = path.relative(cwd, filePath);
        const hash = hashFile(filePath);
        record.hashes[rel] = { sha256: hash, size: fs.statSync(filePath).size };
        console.log(`  hashed: ${rel}  sha256=${hash.slice(0, 16)}...`);
    }

    const hashFilePath = path.resolve(opts.hashFile);
    fs.writeFileSync(hashFilePath, JSON.stringify(record, null, 2), 'utf8');
    console.log(`[bheeshma-lock] Integrity record saved to: ${opts.hashFile}`);
    process.exit(0);
}

function verify(opts) {
    const hashFilePath = path.resolve(opts.hashFile);
    if (!fs.existsSync(hashFilePath)) {
        console.error(`[bheeshma-lock] No integrity record found at ${opts.hashFile}. Run --save first.`);
        process.exit(1);
    }

    let record;
    try {
        record = JSON.parse(fs.readFileSync(hashFilePath, 'utf8'));
    } catch (err) {
        console.error(`[bheeshma-lock] Could not parse integrity record: ${err.message}`);
        process.exit(2);
    }

    const cwd = process.cwd();
    let violations = 0;

    for (const [rel, expected] of Object.entries(record.hashes)) {
        const filePath = path.join(cwd, rel);

        if (!fs.existsSync(filePath)) {
            console.error(`  MISSING: ${rel} — lockfile removed`);
            violations++;
            continue;
        }

        const actual = hashFile(filePath);
        if (actual !== expected.sha256) {
            console.error(`  TAMPERED: ${rel}`);
            console.error(`    expected: ${expected.sha256}`);
            console.error(`    actual:   ${actual}`);
            violations++;
        } else {
            console.log(`  OK: ${rel}`);
        }
    }

    if (violations === 0) {
        console.log('[bheeshma-lock] All lockfiles intact.');
        process.exit(0);
    } else {
        console.error(`\n[bheeshma-lock] INTEGRITY VIOLATION: ${violations} lockfile(s) modified.`);
        console.error('  This may indicate a supply-chain attack or unexpected dependency update.');
        process.exit(1);
    }
}

function main() {
    const opts = parseArgs();

    if (!opts.mode) {
        console.error('[bheeshma-lock] Specify --save or --verify.\n');
        printHelp();
        process.exit(2);
    }

    if (opts.mode === 'save')   save(opts);
    if (opts.mode === 'verify') verify(opts);
}

main();
