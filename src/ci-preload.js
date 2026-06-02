'use strict';

/**
 * BHEESHMA CI child preload.
 *
 * Preloaded via `node --require` into the process that actually runs the
 * monitored command (e.g. `node app.js`, or each `node` process spawned by
 * `npm test`). This is where the app's real runtime behavior happens, so this
 * is where monitoring must live — the parent `bheeshma-ci`/`bheeshma` process
 * only orchestrates and never executes the dependency code itself.
 *
 * Each preloaded process installs the hooks, then on exit serializes the
 * signals it collected to a per-PID file under BHEESHMA_SIGNAL_DIR. The parent
 * reads every file in that directory after the process tree exits and ingests
 * the signals to produce the report and enforce policy. NODE_OPTIONS is
 * inherited by grandchildren, so a whole `npm`/`node` tree is covered, and the
 * per-PID filename avoids one process clobbering another's signals.
 *
 * (Workers spawned inside a monitored process are still handled by init()'s
 * Worker-constructor interception, which relays their signals to that
 * process's own store before it flushes here.)
 */

const path = require('path');
const bheeshma = require('./index');

/**
 * Is THIS process the package manager itself (npm/npx/yarn/pnpm) rather than
 * the user/dependency code we care about?
 *
 * NODE_OPTIONS is inherited by the whole process tree, so this preload also
 * loads into the package-manager process during `npm install` / `npm test`.
 * The package manager's own code lives under node_modules (e.g.
 * node_modules/npm/**, its bundled semver, etc.), so monitoring it would
 * attribute hundreds of the manager's own file reads to "packages" named
 * npm/semver/... — drowning the actual install/lifecycle behavior in noise.
 *
 * The package manager runs each dependency lifecycle script (preinstall/
 * install/postinstall) and `npm test` etc. as SEPARATE child node processes,
 * which are NOT the manager binary — those we still monitor. We only skip the
 * manager's own process.
 */
function isPackageManagerProcess() {
    try {
        const entry = process.argv[1] || '';
        const base = path.basename(entry);
        // Match the launcher binary (e.g. .../bin/npm — no extension) and the
        // CLI entry (npm-cli.js), for npm/npx/yarn/pnpm/corepack.
        if (/^(npm|npx|yarn|pnpm|corepack)(-cli)?(\.js)?$/.test(base)) {
            return true;
        }
        const nm = `${path.sep}node_modules${path.sep}`;
        if (entry.includes(`${nm}npm${path.sep}`) ||
            entry.includes(`${nm}pnpm${path.sep}`) ||
            entry.includes(`${nm}yarn${path.sep}`)) {
            return true;
        }
        return false;
    } catch (err) {
        return false;
    }
}

if (isPackageManagerProcess()) {
    // Don't monitor the package manager's own internals.
    module.exports = {};
    return;
}

try {
    const configPath = process.env.BHEESHMA_CONFIG_PATH;
    bheeshma.init(configPath ? { configPath } : undefined);
} catch (err) {
    // Never let monitoring setup break the monitored command.
}

const signalDir = process.env.BHEESHMA_SIGNAL_DIR;
if (signalDir) {
    // Capture a pristine fs.writeFileSync now, before nothing — at this point
    // fs.writeFileSync may already be hooked, but writing to our own temp dir
    // produces no package-attributed signal, so the hooked version is harmless.
    const flush = () => {
        try {
            const fs = require('fs');
            const signals = bheeshma.getSignals();
            if (signals && signals.length) {
                fs.writeFileSync(
                    path.join(signalDir, `${process.pid}.json`),
                    JSON.stringify(signals)
                );
            }
        } catch (err) {
            // Best effort — a missing flush just means fewer signals reported.
        }
    };
    process.on('exit', flush);
}
