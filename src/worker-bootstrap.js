/**
 * BHEESHMA Worker Thread Bootstrap
 * 
 * Injected into worker threads via --require to reinstall all hooks
 * and relay signals back to the main thread via parentPort.postMessage().
 * 
 * Usage: Automatically injected by the childProcHook when it detects
 * a new Worker() spawn. The bootstrap:
 * 
 * 1. Reinstalls all BHEESHMA hooks inside the worker
 * 2. Intercepts signal pushes to instead send via parentPort
 * 3. Main thread collector merges incoming worker signals
 */

'use strict';

const { isMainThread, parentPort, workerData } = require('worker_threads');

if (isMainThread) {
    // This file should only run in worker threads
    module.exports = {};
} else {
    /**
     * Worker-side signal relay.
     * Replaces the signal array push to forward signals to main thread.
     */
    function installWorkerRelay() {
        if (!parentPort) {
            // No parentPort available — can't relay
            return false;
        }

        try {
            const bheeshma = require('../index');
            const config = workerData && workerData.bheeshmaConfig
                ? workerData.bheeshmaConfig
                : undefined;

            // Initialize hooks in the worker
            const initResult = bheeshma.init(config ? { config } : undefined);

            if (!initResult.success) {
                return false;
            }

            // Get the signals array and monkey-patch push to relay
            const signals = bheeshma.getSignals();

            // Override the push method to relay to main thread
            const originalPush = Array.prototype.push;

            // We need a proxy that intercepts all signal additions
            // The simplest approach: periodically flush signals to main thread
            const flushInterval = setInterval(() => {
                const currentSignals = bheeshma.getSignals();
                if (currentSignals.length > 0) {
                    parentPort.postMessage({
                        type: 'BHEESHMA_WORKER_SIGNALS',
                        signals: currentSignals
                    });
                }
            }, 1000);

            // Send on exit too
            process.on('exit', () => {
                clearInterval(flushInterval);
                const currentSignals = bheeshma.getSignals();
                if (currentSignals.length > 0) {
                    try {
                        parentPort.postMessage({
                            type: 'BHEESHMA_WORKER_SIGNALS',
                            signals: currentSignals
                        });
                    } catch (err) {
                        // Parent may have already exited
                    }
                }
            });

            return true;
        } catch (err) {
            return false;
        }
    }

    // Auto-install on require
    installWorkerRelay();

    module.exports = { installWorkerRelay };
}
