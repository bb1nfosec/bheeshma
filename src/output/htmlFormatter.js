/**
 * BHEESHMA HTML Report Formatter
 * 
 * Generates a self-contained HTML report with inline JavaScript.
 * No external dependencies, no server — one file anyone can open and forward.
 * 
 * Security: All data is embedded as JSON; no external resources loaded.
 */

'use strict';

const { getRiskLevel } = require('../scoring/trustScore');

/**
 * Format complete report as self-contained HTML
 * 
 * @param {Map} scores - Trust scores by package
 * @param {Array} allSignals - All captured signals
 * @returns {string} HTML string
 */
function formatReport(scores, allSignals) {
    const summary = buildSummary(scores, allSignals);
    const packages = buildPackageList(scores);
    const signals = buildSignalList(allSignals);

    const reportData = JSON.stringify({ summary, packages, signals });

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BHEESHMA Runtime Security Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; }
  .container { max-width: 1200px; margin: 0 auto; }
  h1 { font-size: 24px; margin-bottom: 8px; color: #58a6ff; }
  .timestamp { color: #8b949e; font-size: 13px; margin-bottom: 24px; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .summary-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }
  .summary-card .value { font-size: 28px; font-weight: 700; }
  .summary-card .label { font-size: 12px; color: #8b949e; text-transform: uppercase; margin-top: 4px; }
  .critical { color: #f85149; } .high { color: #d29922; } .medium { color: #58a6ff; } .low { color: #3fb950; }
  .critical-bg { background: #f8514920; border-color: #f8514950; } .high-bg { background: #d2992220; border-color: #d2992250; }
  .medium-bg { background: #58a6ff20; border-color: #58a6ff50; } .low-bg { background: #3fb95020; border-color: #3fb95050; }

  .packages-section { margin-bottom: 24px; }
  .packages-section h2 { font-size: 18px; margin-bottom: 12px; color: #c9d1d9; }
  .package-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 8px; }
  .package-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .package-name { font-weight: 600; font-size: 15px; }
  .score-badge { padding: 4px 12px; border-radius: 12px; font-size: 13px; font-weight: 600; }
  .behaviors { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
  .behavior-tag { background: #21262d; border: 1px solid #30363d; border-radius: 4px; padding: 2px 8px; font-size: 12px; color: #8b949e; }
  .behavior-tag .count { color: #c9d1d9; font-weight: 600; }

  .signals-section h2 { font-size: 18px; margin-bottom: 12px; color: #c9d1d9; }
  .signals-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .signals-table th { background: #161b22; padding: 8px 12px; text-align: left; border-bottom: 1px solid #30363d; color: #8b949e; text-transform: uppercase; font-size: 11px; }
  .signals-table td { padding: 6px 12px; border-bottom: 1px solid #21262d; }
  .signals-table tr:hover { background: #161b22; }

  .controls { margin-bottom: 16px; display: flex; gap: 8px; }
  .controls select, .controls input { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 6px 12px; border-radius: 6px; font-size: 13px; }
  .controls button { background: #238636; border: none; color: white; padding: 6px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; }
  .controls button:hover { background: #2ea043; }

  .footer { margin-top: 24px; padding-top: 16px; border-top: 1px solid #21262d; color: #484f58; font-size: 12px; text-align: center; }
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ BHEESHMA Runtime Security Report</h1>
  <div class="timestamp" id="timestamp"></div>

  <div class="summary-grid" id="summary-grid"></div>

  <div class="controls">
    <select id="risk-filter">
      <option value="all">All Risk Levels</option>
      <option value="CRITICAL">CRITICAL</option>
      <option value="HIGH">HIGH</option>
      <option value="MEDIUM">MEDIUM</option>
      <option value="LOW">LOW</option>
    </select>
    <input type="text" id="search" placeholder="Search packages...">
    <button onclick="exportJSON()">Export JSON</button>
  </div>

  <div class="packages-section">
    <h2>Packages</h2>
    <div id="packages-list"></div>
  </div>

  <div class="signals-section">
    <h2>Signals <span id="signal-count" style="color:#8b949e;font-size:14px;"></span></h2>
    <table class="signals-table">
      <thead><tr><th>Time</th><th>Package</th><th>Type</th><th>Details</th></tr></thead>
      <tbody id="signals-tbody"></tbody>
    </table>
  </div>

  <div class="footer">
    Generated by <strong>BHEESHMA</strong> — Runtime Dependency Behavior Monitor<br>
    Zero telemetry. Local-only. No cloud services.
  </div>
</div>

<script>
const DATA = ${reportData};

function init() {
  document.getElementById('timestamp').textContent = new Date(DATA.summary.timestamp).toLocaleString();
  renderSummary();
  renderPackages();
  renderSignals();
  document.getElementById('risk-filter').addEventListener('change', renderPackages);
  document.getElementById('search').addEventListener('input', renderPackages);
}

function renderSummary() {
  const s = DATA.summary;
  document.getElementById('summary-grid').innerHTML = \`
    <div class="summary-card"><div class="value">\${s.totalPackages}</div><div class="label">Packages</div></div>
    <div class="summary-card"><div class="value">\${s.totalSignals}</div><div class="label">Signals</div></div>
    <div class="summary-card \${s.riskDistribution.critical > 0 ? 'critical-bg' : ''}"><div class="value critical">\${s.riskDistribution.critical}</div><div class="label">Critical</div></div>
    <div class="summary-card \${s.riskDistribution.high > 0 ? 'high-bg' : ''}"><div class="value high">\${s.riskDistribution.high}</div><div class="label">High</div></div>
    <div class="summary-card \${s.riskDistribution.medium > 0 ? 'medium-bg' : ''}"><div class="value medium">\${s.riskDistribution.medium}</div><div class="label">Medium</div></div>
    <div class="summary-card"><div class="value low">\${s.riskDistribution.low}</div><div class="label">Low</div></div>
  \`;
}

function renderPackages() {
  const filter = document.getElementById('risk-filter').value;
  const search = document.getElementById('search').value.toLowerCase();
  const container = document.getElementById('packages-list');

  const filtered = DATA.packages.filter(p => {
    if (filter !== 'all' && p.riskLevel !== filter) return false;
    if (search && !p.name.toLowerCase().includes(search)) return false;
    return true;
  });

  container.innerHTML = filtered.map(p => {
    const cls = p.riskLevel.toLowerCase();
    const behaviors = Object.entries(p.behaviors || {})
      .filter(([,c]) => c > 0)
      .map(([t,c]) => '<span class="behavior-tag">' + t.replace(/_/g,' ') + ' <span class="count">' + c + '</span></span>')
      .join('');

    return \`<div class="package-card \${cls}-bg">
      <div class="package-header">
        <span class="package-name">\${p.name}@\${p.version}</span>
        <span class="score-badge \${cls}">\${p.trustScore}/100 [\${p.riskLevel}]</span>
      </div>
      <div style="color:#8b949e;font-size:13px;">\${p.signalCount} signals\${p.uniqueSignalCount ? ' (' + p.uniqueSignalCount + ' unique)' : ''}</div>
      <div class="behaviors">\${behaviors}</div>
    </div>\`;
  }).join('');
}

function renderSignals() {
  const tbody = document.getElementById('signals-tbody');
  document.getElementById('signal-count').textContent = '(' + DATA.signals.length + ')';
  const rows = DATA.signals.slice(0, 500).map(s => {
    const time = new Date(s.timestamp).toLocaleTimeString();
    const details = Object.entries(s.metadata || {}).map(([k,v]) => k + ': ' + v).join(', ');
    return '<tr><td>' + time + '</td><td>' + (s.package || '-') + '</td><td>' + s.type + '</td><td>' + (details || '-') + '</td></tr>';
  });
  tbody.innerHTML = rows.join('');
  if (DATA.signals.length > 500) {
    tbody.innerHTML += '<tr><td colspan="4" style="text-align:center;color:#8b949e;">Showing 500 of ' + DATA.signals.length + ' signals</td></tr>';
  }
}

function exportJSON() {
  const blob = new Blob([JSON.stringify(DATA, null, 2)], {type: 'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'bheeshma-report.json'; a.click();
  URL.revokeObjectURL(url);
}

init();
</script>
</body>
</html>`;
}

function buildSummary(scores, allSignals) {
    const riskDistribution = { critical: 0, high: 0, medium: 0, low: 0 };

    for (const [, data] of scores) {
        const risk = (data.riskLevel || getRiskLevel(data.score)).toLowerCase();
        if (riskDistribution[risk] !== undefined) riskDistribution[risk]++;
    }

    return {
        timestamp: new Date().toISOString(),
        totalPackages: scores.size,
        totalSignals: allSignals.filter(s => s.package !== null).length,
        riskDistribution
    };
}

function buildPackageList(scores) {
    const packages = [];
    for (const [packageKey, data] of scores) {
        packages.push({
            name: data.name,
            version: data.version,
            trustScore: data.score,
            riskLevel: data.riskLevel || getRiskLevel(data.score),
            signalCount: data.signalCount,
            uniqueSignalCount: data.uniqueSignalCount || data.signalCount,
            behaviors: data.stats
        });
    }
    packages.sort((a, b) => a.trustScore - b.trustScore);
    return packages;
}

function buildSignalList(allSignals) {
    return allSignals
        .filter(s => s.package !== null)
        .map(s => ({
            timestamp: s.timestamp,
            type: s.type,
            package: s.package,
            version: s.version,
            metadata: s._dedup
                ? { ...s.metadata, _count: s._dedup.count, _first: s._dedup.firstSeen, _last: s._dedup.lastSeen }
                : s.metadata
        }));
}

module.exports = { formatReport };
