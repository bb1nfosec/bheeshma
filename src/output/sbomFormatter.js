'use strict';

/**
 * BHEESHMA SBOM Formatter — CycloneDX 1.4 JSON
 *
 * Generates a Software Bill of Materials from the set of observed packages.
 * Every package bheeshma attributed at least one signal to is included.
 *
 * Format: CycloneDX 1.4 JSON (https://cyclonedx.org/specification/overview/)
 * This is the format required by US EO 14028 and the EU Cyber Resilience Act.
 *
 * Each component includes:
 *   - type: "library"
 *   - name, version
 *   - purl: package URL (pkg:npm/name@version)
 *   - bom-ref: unique identifier
 *   - properties: bheeshma trust score, risk level, signal count
 */

const { randomBytes } = require('crypto');

/**
 * Generate a deterministic bom-ref for a package.
 *
 * @param {string} name
 * @param {string} version
 * @returns {string}
 */
function bomRef(name, version) {
    return `pkg:npm/${encodeURIComponent(name)}@${encodeURIComponent(version || 'unknown')}`;
}

/**
 * Build a package URL (purl) per the purl-spec for npm packages.
 * https://github.com/package-url/purl-spec
 *
 * @param {string} name
 * @param {string} version
 * @returns {string}
 */
function purl(name, version) {
    // Handle scoped packages: @scope/name → pkg:npm/%40scope%2Fname@version
    const encodedName = name.startsWith('@')
        ? encodeURIComponent(name)
        : name;
    return `pkg:npm/${encodedName}@${version || 'unknown'}`;
}

/**
 * Map bheeshma risk level to CycloneDX vulnerability severity classification.
 *
 * @param {string} riskLevel
 * @returns {string}
 */
function riskToSeverity(riskLevel) {
    switch (riskLevel) {
        case 'CRITICAL': return 'critical';
        case 'HIGH':     return 'high';
        case 'MEDIUM':   return 'medium';
        case 'LOW':      return 'low';
        default:         return 'none';
    }
}

/**
 * Format a CycloneDX 1.4 SBOM from bheeshma scan results.
 *
 * @param {Map}    scores      - Trust scores map from calculateAllScores
 * @param {Array}  allSignals  - All captured signals
 * @param {object} options     - { toolVersion, projectName, projectVersion }
 * @returns {string} CycloneDX JSON string
 */
function formatSbom(scores, allSignals, options = {}) {
    const toolVersion   = options.toolVersion   || '1.0.0';
    const projectName   = options.projectName   || 'unknown-project';
    const projectVersion = options.projectVersion || '0.0.0';

    // Use a short random serial for this BOM instance
    const serialNumber = `urn:uuid:${randomBytes(16).toString('hex').replace(
        /^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5'
    )}`;

    const components = [];

    for (const [, data] of scores) {
        const { name, version, score, riskLevel, signalCount, uniqueSignalCount } = data;

        const component = {
            type:    'library',
            'bom-ref': bomRef(name, version),
            name,
            version: version || 'unknown',
            purl:    purl(name, version),
            properties: [
                { name: 'bheeshma:trustScore',        value: String(score) },
                { name: 'bheeshma:riskLevel',         value: riskLevel },
                { name: 'bheeshma:signalCount',       value: String(signalCount) },
                { name: 'bheeshma:uniqueSignalCount',  value: String(uniqueSignalCount) },
                { name: 'bheeshma:severity',          value: riskToSeverity(riskLevel) }
            ]
        };

        // Add signal type breakdown as properties
        const sigTypes = {};
        for (const sig of allSignals.filter(s => s.package === name)) {
            sigTypes[sig.type] = (sigTypes[sig.type] || 0) + 1;
        }
        for (const [sigType, count] of Object.entries(sigTypes)) {
            component.properties.push({
                name:  `bheeshma:signal:${sigType}`,
                value: String(count)
            });
        }

        components.push(component);
    }

    // Sort by trust score ascending (most risky first)
    components.sort((a, b) => {
        const scoreA = parseInt(a.properties.find(p => p.name === 'bheeshma:trustScore')?.value || '100', 10);
        const scoreB = parseInt(b.properties.find(p => p.name === 'bheeshma:trustScore')?.value || '100', 10);
        return scoreA - scoreB;
    });

    const sbom = {
        bomFormat:   'CycloneDX',
        specVersion: '1.4',
        serialNumber,
        version:     1,
        metadata: {
            timestamp: new Date().toISOString(),
            tools: [{
                vendor:  'bheeshma',
                name:    'bheeshma',
                version: toolVersion
            }],
            component: {
                type:    'application',
                name:    projectName,
                version: projectVersion
            }
        },
        components
    };

    return JSON.stringify(sbom, null, 2);
}

module.exports = { formatSbom };
