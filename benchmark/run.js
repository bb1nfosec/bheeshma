#!/usr/bin/env node
/**
 * BHEESHMA Efficacy Benchmark Runner
 *
 * Runs each labeled fixture (benchmark/fixtures.js) in isolation under bheeshma,
 * then reports how well bheeshma separates malicious from benign behavior.
 *
 * Because the "right" operating point depends on how a build is gated, we
 * evaluate detection AND false positives at every enforcement threshold:
 *   - critical-only (score < 30)  ← bheeshma's DEFAULT CI gate (fail-level critical)
 *   - high+         (score < 60)
 *   - medium+       (score < 80)
 *   - pattern-based (any correlated pattern hit, independent of score)
 *
 * Output: a confusion matrix + precision/recall/FP-rate per threshold, and a
 * machine-readable JSON summary written to benchmark/results.json.
 *
 * Fully offline and deterministic. Usage: node benchmark/run.js
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const bheeshma = require('../src/index');
const { ALL } = require('./fixtures');

const THRESHOLDS = [
    { key: 'criticalOnly', label: 'critical-only (<30)  [DEFAULT GATE]', cutoff: 30 },
    { key: 'highPlus', label: 'high+ (<60)', cutoff: 60 },
    { key: 'mediumPlus', label: 'medium+ (<80)', cutoff: 80 }
];

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function setupCorpus() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bheeshma-bench-'));
    const nm = path.join(root, 'node_modules');
    for (const fx of ALL) {
        const dir = path.join(nm, fx.name);
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, 'package.json'),
            JSON.stringify({ name: fx.name, version: fx.version, main: 'index.js' }));
        fs.writeFileSync(path.join(dir, 'index.js'), fx.code);
    }
    return { root, nm };
}

function clearRequireCache(nm) {
    for (const key of Object.keys(require.cache)) {
        if (key.startsWith(nm)) delete require.cache[key];
    }
}

function patternFlagged(report) {
    const pa = report.patternAnalysis;
    if (!pa) return false;
    const counts = [
        pa.cryptoMining, pa.dataExfiltration, pa.backdoors,
        pa.credentialTheft, pa.typosquats
    ];
    // A LOW-severity credential read (e.g. dotenv) should not count as a hit;
    // we treat any non-zero correlated pattern as a flag but let scoring handle
    // the dotenv FP case (it is context-aware downstream).
    return counts.some(c => typeof c === 'number' && c > 0);
}

async function evaluateFixture(fx, nm) {
    bheeshma.teardown();
    clearRequireCache(nm);
    bheeshma.init();

    require(path.join(nm, fx.name, 'index.js'));
    // Generous wait so deferred (setImmediate) behavior and the obfuscation
    // scan complete before we read results.
    await sleep(350);

    const scores = bheeshma.getTrustScores();
    let pkg = null;
    for (const v of scores.values()) {
        if (v.name === fx.name) { pkg = v; break; }
    }

    const report = JSON.parse(bheeshma.generateReport('json'));
    const score = pkg ? pkg.score : 100;
    const riskLevel = pkg ? pkg.riskLevel : 'LOW';
    const signalTypes = pkg ? Object.entries(pkg.stats).filter(([, n]) => n > 0).map(([t]) => t) : [];

    return {
        name: fx.name,
        label: fx.label,
        attack: fx.attack,
        score,
        riskLevel,
        signalTypes,
        patternFlagged: patternFlagged(report)
    };
}

function confusion(results, predictFn) {
    let tp = 0, fp = 0, tn = 0, fn = 0;
    for (const r of results) {
        const predictedMalicious = predictFn(r);
        if (r.label === 'malicious') {
            if (predictedMalicious) tp++; else fn++;
        } else {
            if (predictedMalicious) fp++; else tn++;
        }
    }
    const recall = tp + fn === 0 ? 0 : tp / (tp + fn);
    const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
    const fpRate = fp + tn === 0 ? 0 : fp / (fp + tn);
    const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
    return { tp, fp, tn, fn, recall, precision, fpRate, f1 };
}

function pct(x) { return (x * 100).toFixed(0) + '%'; }

async function main() {
    const { root, nm } = setupCorpus();
    const results = [];

    console.log('='.repeat(74));
    console.log('BHEESHMA EFFICACY BENCHMARK');
    console.log('='.repeat(74));
    console.log(`Corpus: ${ALL.filter(f => f.label === 'malicious').length} malicious, ` +
        `${ALL.filter(f => f.label === 'benign').length} benign fixtures\n`);

    for (const fx of ALL) {
        const r = await evaluateFixture(fx, nm);
        results.push(r);
        const tag = r.label === 'malicious' ? 'MAL ' : 'BEN ';
        console.log(`  [${tag}] ${r.name.padEnd(26)} score=${String(r.score).padStart(3)} ` +
            `${r.riskLevel.padEnd(8)} pattern=${r.patternFlagged ? 'Y' : 'n'}  ${r.signalTypes.join(',')}`);
    }

    bheeshma.teardown();
    fs.rmSync(root, { recursive: true, force: true });

    // Build evaluation matrices
    const matrices = {};
    for (const t of THRESHOLDS) {
        matrices[t.key] = { label: t.label, ...confusion(results, r => r.score < t.cutoff) };
    }
    // Score OR pattern (the realistic "best" detection bheeshma can offer today)
    matrices.scoreOrPattern = {
        label: 'medium+ OR pattern hit (best available today)',
        ...confusion(results, r => r.score < 80 || r.patternFlagged)
    };

    console.log('\n' + '-'.repeat(74));
    console.log('DETECTION vs FALSE POSITIVES by enforcement threshold');
    console.log('-'.repeat(74));
    console.log('  threshold'.padEnd(46) + 'recall  precision  FP-rate  F1');
    for (const key of ['criticalOnly', 'highPlus', 'mediumPlus', 'scoreOrPattern']) {
        const m = matrices[key];
        console.log('  ' + m.label.padEnd(44) +
            pct(m.recall).padEnd(8) + pct(m.precision).padEnd(11) +
            pct(m.fpRate).padEnd(9) + m.f1.toFixed(2));
    }

    // Highlight the headline finding: what the DEFAULT gate catches.
    const def = matrices.criticalOnly;
    console.log('\n' + '-'.repeat(74));
    console.log('HEADLINE');
    console.log('-'.repeat(74));
    console.log(`  Default CI gate (fail-level=critical) detects ${pct(def.recall)} of malicious ` +
        `fixtures (${def.tp}/${def.tp + def.fn}).`);
    const missed = results.filter(r => r.label === 'malicious' && r.score >= 30);
    if (missed.length) {
        console.log('  Malicious fixtures the DEFAULT gate would NOT block:');
        for (const r of missed) {
            console.log(`    - ${r.name} (score=${r.score}, ${r.riskLevel}) — ${r.attack}`);
        }
    }
    const benignFlaggedMed = results.filter(r => r.label === 'benign' && r.score < 80);
    console.log(`  Benign fixtures flagged at medium+ (potential false positives): ` +
        `${benignFlaggedMed.length}` +
        (benignFlaggedMed.length ? ' — ' + benignFlaggedMed.map(r => r.name).join(', ') : ''));

    const summary = {
        generatedAt: new Date().toISOString(),
        corpus: { malicious: ALL.filter(f => f.label === 'malicious').length, benign: ALL.filter(f => f.label === 'benign').length },
        results,
        matrices
    };
    fs.writeFileSync(path.join(__dirname, 'results.json'), JSON.stringify(summary, null, 2));
    console.log('\n  Machine-readable summary: benchmark/results.json');
    console.log('='.repeat(74));
}

main().catch(err => { console.error('Benchmark error:', err); process.exit(1); });
