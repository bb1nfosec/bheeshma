/**
 * BHEESHMA Out-of-Process Engine (experimental)
 *
 * The in-process engine (src/index.js) monkey-patches Node APIs and therefore
 * shares the monitored code's privileges — it is evadable, misses native/WASM
 * code, and cannot see syscalls made by child processes like `curl`. This
 * module observes from OUTSIDE the process via the kernel (ptrace, through
 * `strace`), giving a real trust boundary: the monitored code cannot tamper
 * with the observer, and behavior is captured regardless of language/runtime.
 *
 * Attribution is done by process lineage, which out-of-process is cleaner than
 * stack traces: when a dependency's lifecycle script is exec'd, its argv
 * contains node_modules/<pkg>, so we map that pid (and its descendants) to the
 * package. Package-manager processes (npm/yarn/…) are not attributed, so their
 * own internals don't pollute the report.
 *
 * Requirements: Linux + strace. This is a proof-of-concept parser focused on the
 * security-relevant syscalls (network connects, process execs, sensitive-file
 * reads); it is intentionally conservative about what it records.
 */

'use strict';

const { spawn } = require('child_process');
const path = require('path');
const { createSignal, SignalType } = require('../signals/signalTypes');
const { isPackageManagerEntry } = require('../util/processKind');
const { analyzeHostname } = require('../analysis/dnsAnalysis');

// Syscalls we trace. Kept tight: the behaviors that matter for supply-chain
// detection, plus process-lineage syscalls for attribution.
const TRACED = 'execve,connect,socket,sendto,sendmmsg,openat,clone,clone3,fork,vfork';

// DNS query names are recovered by un-escaping strace's printed payload back to
// raw bytes and parsing the DNS wire format (length-prefixed labels from the
// 12-byte header). This is exact — unlike text heuristics it doesn't fail when a
// label's length byte happens to be a printable character (e.g. a 43-char
// exfil label whose length byte is '+'), which is precisely the long,
// high-entropy label DNS tunneling uses.
const NAMED_ESCAPE = { n: 10, t: 9, r: 13, v: 11, f: 12, b: 8, a: 7, '\\': 92, '"': 34 };

function unescapeStraceString(s) {
    const out = [];
    for (let i = 0; i < s.length; i++) {
        const c = s[i];
        if (c !== '\\') { out.push(s.charCodeAt(i) & 0xff); continue; }
        const n = s[i + 1];
        if (n === 'x') { out.push(parseInt(s.substr(i + 2, 2), 16) & 0xff); i += 3; }
        else if (n >= '0' && n <= '7') {
            let j = i + 1, oct = '';
            while (j < s.length && oct.length < 3 && s[j] >= '0' && s[j] <= '7') { oct += s[j]; j++; }
            out.push(parseInt(oct, 8) & 0xff); i = j - 1;
        } else { out.push(NAMED_ESCAPE[n] !== undefined ? NAMED_ESCAPE[n] : s.charCodeAt(i + 1) & 0xff); i++; }
    }
    return Buffer.from(out);
}

function parseQName(buf) {
    if (!buf || buf.length < 13) return null;
    let off = 12; // skip DNS header
    const labels = [];
    while (off < buf.length) {
        const len = buf[off];
        if (len === 0) break;
        if (len > 63) return null; // compression pointer / not a plain query
        if (off + 1 + len > buf.length) break;
        labels.push(buf.toString('latin1', off + 1, off + 1 + len));
        off += len + 1;
        if (labels.length > 25) break;
    }
    if (labels.length < 2) return null;
    const name = labels.join('.');
    if (!/^[A-Za-z0-9._+/=-]+$/.test(name)) return null;
    return name;
}

function parseDnsNames(line) {
    const quoted = line.match(/"(?:[^"\\]|\\.)*"/g);
    if (!quoted) return [];
    const names = [];
    for (const q of quoted) {
        const name = parseQName(unescapeStraceString(q.slice(1, -1)));
        if (name) names.push(name);
    }
    return [...new Set(names)];
}

// Credential / secret files worth flagging on read (others are loader/noise).
const SENSITIVE_FILE = /(^|\/)(\.npmrc|\.env|\.netrc|\.git-credentials|id_rsa|id_ed25519|credentials|\.aws\/|\.ssh\/)/;

const SHELLS = /\/(sh|bash|dash|zsh|ksh)$/;

function extractPackageFromPath(p) {
    const idx = p.lastIndexOf('node_modules');
    if (idx === -1) return null;
    const rest = p.slice(idx + 'node_modules'.length + 1).split('/');
    if (!rest[0]) return null;
    if (rest[0].startsWith('@')) return rest[1] ? `${rest[0]}/${rest[1]}` : null;
    return rest[0];
}

/**
 * Run a command under strace and collect attributed signals.
 *
 * @param {string} command
 * @param {string[]} args
 * @param {object} [opts] - { onLine?: fn, env?, cwd? }
 * @returns {Promise<{ signals: object[], straceAvailable: boolean, exitCode: number }>}
 */
function run(command, args, opts = {}) {
    return new Promise((resolve) => {
        const signals = [];
        const pidPackage = new Map(); // pid -> package name
        const pidParent = new Map();  // pid -> parent pid
        // The root process's execve is printed WITHOUT a [pid] prefix, but its
        // real pid shows up in later lines, so descendants can't chain back to
        // it by pid. We remember the root's package and use it as the fallback:
        // every traced process descends from root, so if root is a dependency's
        // lifecycle script, its children (sh, curl, …) inherit that package.
        // If root is the package manager (npm/…), rootPackage stays null and
        // only explicitly-attributed lifecycle scripts are recorded.
        let rootPackage = null;
        let rootResolved = false;

        const attributionFor = (pid) => {
            let cur = pid;
            const seen = new Set();
            while (cur != null && !seen.has(cur)) {
                seen.add(cur);
                if (pidPackage.has(cur)) return pidPackage.get(cur);
                cur = pidParent.get(cur);
            }
            return rootPackage;
        };

        // -v expands the execve environment array, which carries
        // `npm_package_name=<pkg>` for dependency lifecycle scripts — the most
        // reliable way to attribute an `npm install` postinstall to its package
        // (npm runs the script with a relative argv, so the path alone won't do).
        const straceArgs = ['-v', '-f', '-qq', '-y', '-s', '256', '-e', `trace=${TRACED}`, command, ...args];
        let child;
        try {
            child = spawn('strace', straceArgs, {
                env: opts.env || process.env,
                cwd: opts.cwd || process.cwd(),
                stdio: ['inherit', 'inherit', 'pipe'] // strace writes its trace to stderr
            });
        } catch (err) {
            return resolve({ signals, straceAvailable: false, exitCode: 1 });
        }

        let straceAvailable = true;
        let buf = '';

        child.stderr.on('data', (chunk) => {
            buf += chunk.toString();
            let nl;
            while ((nl = buf.indexOf('\n')) !== -1) {
                const line = buf.slice(0, nl);
                buf = buf.slice(nl + 1);
                parseLine(line);
            }
        });

        function parseLine(line) {
            if (/strace: (Can't|command not found|exec)/i.test(line)) straceAvailable = false;

            // pid prefix; strace omits it for the root pid until it forks.
            const pidMatch = line.match(/^\[pid\s+(\d+)\]\s*/);
            const pid = pidMatch ? Number(pidMatch[1]) : 0;
            const body = pidMatch ? line.slice(pidMatch[0].length) : line;

            // Process lineage: clone/fork return the child pid.
            const cloneMatch = body.match(/^(?:clone|clone3|fork|vfork)\(.*\)\s*=\s*(\d+)/);
            if (cloneMatch) {
                pidParent.set(Number(cloneMatch[1]), pid);
                return;
            }

            // execve: attribution + shell-exec signal.
            const exec = body.match(/^execve\("([^"]+)",\s*\[([^\]]*)\]/);
            if (exec) {
                const exePath = exec[1];
                const argv = exec[2];
                // Attribute this pid to the package whose lifecycle script it runs.
                // Prefer npm's own `npm_package_name` env var (set for lifecycle
                // scripts and present in the -v execve env), then fall back to a
                // node_modules/<pkg> path in argv/exe for non-npm invocations.
                const npmName = body.match(/"npm_package_name=([^"]+)"/);
                const fromArgs = (npmName && npmName[1]) ||
                    extractPackageFromPath(argv) || extractPackageFromPath(exePath);
                const attributable = fromArgs && !isPackageManagerEntry(exePath);
                // The first execve is the root process; seed the fallback package.
                if (!rootResolved) {
                    rootResolved = true;
                    rootPackage = attributable ? fromArgs : null;
                }
                if (attributable) {
                    pidPackage.set(pid, fromArgs);
                }
                const owner = attributionFor(pid);
                if (owner && SHELLS.test(exePath)) {
                    push(SignalType.SHELL_EXEC, { command: unquoteArgv(argv), exe: exePath }, owner, pid);
                }
                return;
            }

            // connect: outbound network (the egress the in-process hooks miss).
            const conn = body.match(/^connect\([^,]+,\s*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\).*?inet6?_addr\("([^"]+)"\)/);
            if (conn) {
                const owner = attributionFor(pid);
                if (owner) push(SignalType.NET_CONNECT, { host: conn[2], port: Number(conn[1]), protocol: 'tcp' }, owner, pid);
                return;
            }

            // sendto/sendmmsg: recover DNS query names from UDP payloads so the
            // out-of-process engine catches DNS tunneling/exfil too.
            if (/^(?:sendto|sendmmsg)\(/.test(body)) {
                const owner = attributionFor(pid);
                if (owner) {
                    for (const host of parseDnsNames(body)) {
                        const a = analyzeHostname(host);
                        push(SignalType.DNS_QUERY, {
                            hostname: host,
                            isIpAddress: a.isIpAddress,
                            suspiciousSubdomainLength: a.suspiciousSubdomainLength,
                            highEntropySubdomain: a.highEntropySubdomain,
                            knownExfilService: a.knownExfilService,
                            base64InSubdomain: a.base64InSubdomain,
                            hexInSubdomain: a.hexInSubdomain,
                            indicators: a.indicators
                        }, owner, pid);
                    }
                }
                return;
            }

            // socket(): flag RAW sockets — packet crafting / covert channels,
            // not something a benign install/build does.
            const sock = body.match(/^socket\(([^,]+),\s*([^,]+),/);
            if (sock && /SOCK_RAW/.test(sock[2])) {
                const owner = attributionFor(pid);
                if (owner) push(SignalType.NET_CONNECT, { host: 'raw-socket', port: 0, protocol: 'raw', family: sock[1].trim() }, owner, pid);
                return;
            }

            // openat: only flag sensitive/credential file reads (others are noise).
            const open = body.match(/^openat\([^,]+,\s*"([^"]+)"/);
            if (open) {
                const p = open[1];
                if (SENSITIVE_FILE.test(p)) {
                    const owner = attributionFor(pid);
                    if (owner) push(SignalType.FS_READ, { path: p, operation: 'openat' }, owner, pid);
                }
            }
        }

        function push(type, metadata, pkg, pid) {
            const sig = createSignal(type, { ...metadata, pid, source: 'strace' }, pkg, 'unknown', null);
            signals.push(sig);
            if (opts.onLine) opts.onLine(sig);
        }

        child.on('error', () => resolve({ signals, straceAvailable: false, exitCode: 1 }));
        child.on('exit', (code) => {
            if (buf) parseLine(buf);
            resolve({ signals, straceAvailable, exitCode: code == null ? 0 : code });
        });
    });
}

function unquoteArgv(argvStr) {
    // "curl", "-s", "http://…"  ->  curl -s http://…
    return argvStr.split(/",\s*"/).map(s => s.replace(/^"|"$/g, '')).join(' ').slice(0, 256);
}

module.exports = { run, parseDnsNames, parseQName, unescapeStraceString };
