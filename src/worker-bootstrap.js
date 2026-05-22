/**
 * BHEESHMA Worker Thread Bootstrap
 *
 * Injected into worker threads via --require (or injected by the intercepted
 * Worker constructor in index.js) to reinstall all hooks and relay signals
 * back to the main thread via parentPort.postMessage().
 *
 * How it works:
 * 1. Reinstalls all BHEESHMA hooks inside the worker thread
 * 2. Periodically flushes new signals (since last flush) to the main thread
 * 3. Sends a final flush on worker exit
 *
 * Message format: { type: 'BHEESHMA_SIGNAL', signals: [...] }
 * The main thread listens for this on worker.on('message') (set up by
 * setupWorkerSignalCollection in index.js).
 */

'use strict';

const { isMainThread, parentPort, workerData } = require('worker_threads');

if (isMainThread) {
    // This file should only run in worker threads
    module.exports = {};
} else {
    /**
     * Track how many signals we've already sent to avoid duplicates.
     * getSignals() returns a copy of the array, so without tracking we'd
     * re-send the entire history every flush interval.
     */
    let lastSentCount = 0;

    /**
     * Install worker-side signal relay.
     *
     * @returns {boolean} True if relay installed successfully
     */
    function installWorkerRelay() {
        if (!parentPort) {
            // No parentPort available — can't relay to main thread
            return false;
        }

        try {
            const bheeshma = require('./index');
            const config = workerData && workerData.bheeshmaConfig
                ? workerData.bheeshmaConfig
                : undefined;

            // Initialize hooks in the worker thread
            const initResult = bheeshma.init(config ? { config } : undefined);

            if (!initResult.success) {
                return false;
            }

            /**
             * Flush NEW signals (those collected since the last flush)
             * to the main thread via parentPort.
             */
            function flushSignals() {
                const currentSignals = bheeshma.getSignals();
                const newSignals = currentSignals.slice(lastSentCount);

                if (newSignals.length > 0) {
                    lastSentCount = currentSignals.length;
                    try {
                        parentPort.postMessage({
                            type: 'BHEESHMA_SIGNAL',
                            signals: newSignals
                        });
                    } catch (err) {
                        // Parent may have already exited
                    }
                }
            }

            // Periodic flush every second
            const flushInterval = setInterval(flushSignals, 1000);

            // Final flush on worker exit
            process.on('exit', () => {
                clearInterval(flushInterval);
                flushSignals();
            });

            // Also flush on beforeExit for graceful shutdown
            process.on('beforeExit', () => {
                flushSignals();
            });

            return true;
        } catch (err) {
            return false;
        }
    }

    // Auto-install when required in a worker thread
    installWorkerRelay();

    module.exports = { installWorkerRelay };
}
