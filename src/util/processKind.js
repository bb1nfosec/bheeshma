'use strict';

/**
 * Process-kind detection helpers (pure, dependency-free, unit-testable).
 */

const path = require('path');

/**
 * Is the given process entry point a package-manager launcher (npm/npx/yarn/
 * pnpm/corepack) rather than user/dependency code?
 *
 * NODE_OPTIONS is inherited across the whole process tree during `npm install`
 * / `npm test`, so bheeshma's CI preload also loads into the package-manager
 * process itself. The manager's own code lives under node_modules (npm, its
 * bundled semver/tar/pacote/sigstore, ...), so monitoring it would attribute
 * hundreds of the manager's own file reads to "packages" of those names and
 * bury the real install/lifecycle behavior. The manager runs each dependency
 * lifecycle script and `npm test` etc. as SEPARATE child processes whose entry
 * is NOT the manager binary — those we still monitor.
 *
 * Matches both the launcher binary (e.g. `/usr/bin/npm`, no extension) and the
 * CLI entry (`npm-cli.js`), and the manager's location under node_modules.
 *
 * @param {string} entry - process.argv[1] (the script being run)
 * @returns {boolean}
 */
function isPackageManagerEntry(entry) {
    if (!entry || typeof entry !== 'string') return false;
    const base = path.basename(entry);
    if (/^(npm|npx|yarn|pnpm|corepack)(-cli)?(\.js|\.cjs)?$/.test(base)) {
        return true;
    }
    const nm = `${path.sep}node_modules${path.sep}`;
    return (
        entry.includes(`${nm}npm${path.sep}`) ||
        entry.includes(`${nm}pnpm${path.sep}`) ||
        entry.includes(`${nm}yarn${path.sep}`) ||
        entry.includes(`${nm}corepack${path.sep}`)
    );
}

module.exports = { isPackageManagerEntry };
