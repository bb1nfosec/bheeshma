/**
 * BHEESHMA CLI Output Formatter
 * 
 * Security: Human-readable terminal output with no code execution
 * 
 * Purpose: Format signal data and trust scores for terminal display.
 * Designed for security engineers reviewing dependency behavior.
 */

'use strict';

const { getRiskLevel } = require('../scoring/trustScore');
const { SignalType } = require('../signals/signalTypes');

/**
 * ANSI color codes for terminal output
 * Only used if terminal supports color
 */
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    dim: '\x1b[2m',

    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m'
};

/**
 * Emoji indicators for signal types
 */
const signalEmoji = {
    [SignalType.ENV_ACCESS]: '🔐',
    [SignalType.FS_READ]: '📖',
    [SignalType.FS_WRITE]: '📝',
    [SignalType.SHELL_EXEC]: '⚡',
    [SignalType.NET_CONNECT]: '🌐'
};

/**
 * Format complete report for CLI output
 * 
 * @param {Map} scores - Trust scores by package
 * @param {Array} allSignals - All captured signals
 * @returns {string} Formatted CLI output
 */
function formatReport(scores, allSignals) {
    const lines = [];

    // Header
    lines.push('');
    lines.push(colorize('='.repeat(70), 'bright'));
    lines.push(colorize('  BHEESHMA Runtime Dependency Behavior Report', 'bright'));
    lines.push(colorize('='.repeat(70), 'bright'));
    lines.push('');

    // Summary statistics
    lines.push(formatSummary(scores, allSignals));
    lines.push('');

    // Per-package details
    if (scores.size === 0) {
        lines.push(colorize('No third-party dependency activity detected.', 'green'));
        lines.push('');
    } else {
        // Sort packages by trust score (lowest first = highest risk)
        const sortedPackages = Array.from(scores.entries())
            .sort((a, b) => a[1].score - b[1].score);

        for (const [packageKey, data] of sortedPackages) {
            lines.push(formatPackage(packageKey, data));
            lines.push('');
        }
    }

    // Footer
    lines.push(colorize('-'.repeat(70), 'dim'));
    lines.push(colorize('Legend: 🔐 ENV  📖 FS_READ  📝 FS_WRITE  ⚡ SHELL  🌐 NETWORK', 'dim'));
    lines.push(colorize('-'.repeat(70), 'dim'));
    lines.push('');

    return lines.join('\n');
}

/**
 * Format summary statistics
 * 
 * @param {Map} scores - Trust scores
 * @param {Array} allSignals - All signals
 * @returns {string} Formatted summary
 */
function formatSummary(scores, allSignals) {
    const totalPackages = scores.size;
    const totalSignals = allSignals.filter(s => s.package !== null).length;

    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    for (const [, data] of scores) {
        const risk = getRiskLevel(data.score);
        if (risk === 'CRITICAL') criticalCount++;
        else if (risk === 'HIGH') highCount++;
        else if (risk === 'MEDIUM') mediumCount++;
        else lowCount++;
    }

    const lines = [];
    lines.push(colorize('Summary:', 'bright'));
    lines.push(`  Total Packages Monitored: ${totalPackages}`);
    lines.push(`  Total Signals Captured: ${totalSignals}`);
    lines.push('');
    lines.push('  Risk Distribution:');
    if (criticalCount > 0) {
        lines.push(colorize(`    CRITICAL: ${criticalCount}`, 'red'));
    }
    if (highCount > 0) {
        lines.push(colorize(`    HIGH: ${highCount}`, 'yellow'));
    }
    if (mediumCount > 0) {
        lines.push(colorize(`    MEDIUM: ${mediumCount}`, 'cyan'));
    }
    if (lowCount > 0) {
        lines.push(colorize(`    LOW: ${lowCount}`, 'green'));
    }

    return lines.join('\n');
}

/**
 * Format individual package report
 * 
 * @param {string} packageKey - Package identifier (name@version)
 * @param {object} data - Package data with score and stats
 * @returns {string} Formatted package section
 */
function formatPackage(packageKey, data) {
    const lines = [];

    const riskLevel = getRiskLevel(data.score);
    const riskColor = getRiskColor(riskLevel);

    // Package header with trust score
    lines.push(colorize(`📦 ${packageKey}`, 'bright'));
    lines.push(colorize(`   Trust Score: ${data.score}/100 [${riskLevel}]`, riskColor));
    lines.push('');

    // Behavior breakdown
    lines.push('   Observed Behaviors:');

    for (const [signalType, count] of Object.entries(data.stats)) {
        if (count > 0) {
            const emoji = signalEmoji[signalType] || '•';
            const label = signalType.replace('_', ' ');
            lines.push(`     ${emoji}  ${label}: ${count} occurrence${count > 1 ? 's' : ''}`);
        }
    }

    return lines.join('\n');
}

/**
 * Get color for risk level
 * 
 * @param {string} riskLevel - Risk level string
 * @returns {string} Color name
 */
function getRiskColor(riskLevel) {
    switch (riskLevel) {
        case 'CRITICAL': return 'red';
        case 'HIGH': return 'yellow';
        case 'MEDIUM': return 'cyan';
        case 'LOW': return 'green';
        default: return 'white';
    }
}

/**
 * Colorize text for terminal output
 * 
 * Security: No code execution, simple string concatenation
 * 
 * @param {string} text - Text to colorize
 * @param {string} color - Color name
 * @returns {string} Colorized text with ANSI codes
 */
function colorize(text, color) {
    // Check if stdout is a TTY (supports color)
    if (!process.stdout.isTTY) {
        return text;
    }

    const colorCode = colors[color] || '';
    return `${colorCode}${text}${colors.reset}`;
}

module.exports = {
    formatReport
};
