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
