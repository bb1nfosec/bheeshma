'use strict';

/**
 * BHEESHMA VM Module Hook
 *
 * Detects attempts to execute code via Node.js `vm` module, which creates a
 * fresh V8 context where bheeshma's monkey-patches are NOT installed.
 * Malicious packages use vm.runInNewContext() as a hook-evasion technique:
 * any net/fs/child_process calls inside the vm context are invisible to other
 * hooks. Flagging the vm call itself closes this evasion path.
 *
 * Wrapped:
 *   vm.runInNewContext()   — executes code string in a new sandbox
 *   vm.runInThisContext()  — executes code string in the current context
 *   vm.runInContext()      — executes code string in an existing context
 *   vm.compileFunction()   — compiles code into a function (Node 10.10+)
 *   new vm.Script()        — compiles a script for later execution
 */

const vm = require('vm');
const { createSignal, SignalType } = require('../signals/signalTypes');
const { resolveCurrentStack } = require('../attribution/resolver');

let signalCollector = null;
let hookConfig = null;
let isHookInstalled = false;

const originalFunctions = {
    runInNewContext:  null,
    runInThisContext: null,
    runInContext:     null,
    compileFunction:  null,
    Script:           null
};

function install(collector, config) {
    try {
        if (isHookInstalled) return true;
        signalCollector = collector;
        hookConfig = config;

        hookVmMethod('runInNewContext');
        hookVmMethod('runInThisContext');
        hookVmMethod('runInContext');
        if (typeof vm.compileFunction === 'function') hookVmMethod('compileFunction');

        // Hook vm.Script constructor
        const OriginalScript = vm.Script;
        originalFunctions.Script = OriginalScript;
        vm.Script = function BheeshmaScript(code, options) {
            try { emitVmSignal('new vm.Script', code); } catch (_) {}
            return new OriginalScript(code, options);
        };
        // Preserve static members
        Object.assign(vm.Script, OriginalScript);
        vm.Script.prototype = OriginalScript.prototype;

        isHookInstalled = true;
        return true;
    } catch (err) {
        console.error('[BHEESHMA] Failed to install VM hook:', err.message);
        return false;
    }
}

function hookVmMethod(fnName) {
    if (typeof vm[fnName] !== 'function') return;
    originalFunctions[fnName] = vm[fnName];

    vm[fnName] = function (...args) {
        try { emitVmSignal(fnName, args[0]); } catch (_) {}
        return originalFunctions[fnName].apply(this, args);
    };

    Object.defineProperty(vm[fnName], 'name', { value: fnName, configurable: true });
}

function emitVmSignal(method, codeArg) {
    const attribution = resolveCurrentStack();
    if (!attribution) return;

    // Capture a safe preview of the code (truncated, no secrets)
    let codePreview = null;
    if (typeof codeArg === 'string') {
        codePreview = codeArg.length > 120
            ? codeArg.slice(0, 120) + '...[truncated]'
            : codeArg;
    }

    const signal = createSignal(
        SignalType.VM_EXEC,
        { method, codePreview, hasStringCode: typeof codeArg === 'string' },
        attribution.name,
        attribution.version,
        new Error().stack
    );
    signalCollector.push(signal);
}

function uninstall() {
    try {
        if (!isHookInstalled) return true;

        for (const [fnName, orig] of Object.entries(originalFunctions)) {
            if (orig && fnName !== 'Script') vm[fnName] = orig;
        }
        if (originalFunctions.Script) vm.Script = originalFunctions.Script;

        isHookInstalled = false;
        signalCollector = null;
        hookConfig = null;
        return true;
    } catch (_) {
        return false;
    }
}

module.exports = { install, uninstall };
