/**
 * BHEESHMA — Runtime Dependency Behavior Monitor for Node.js
 * TypeScript declaration file
 */

/**
 * Signal types that bheeshma monitors
 */
export type SignalType =
  | 'ENV_ACCESS'
  | 'FS_READ'
  | 'FS_WRITE'
  | 'NET_CONNECT'
  | 'HTTP_REQUEST'
  | 'HTTPS_REQUEST'
  | 'DNS_QUERY'
  | 'SHELL_EXEC'
  | 'OBFUSCATION_DETECTED'
  | 'BLACKLISTED_PACKAGE';

/**
 * Risk levels for packages
 */
export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

/**
 * A single captured behavioral signal
 */
export interface Signal {
  /** Signal type (e.g., SHELL_EXEC, HTTP_REQUEST) */
  type: SignalType;
  /** Name of the package that triggered the signal */
  package?: string;
  /** Version of the package */
  version?: string;
  /** Timestamp of signal capture */
  timestamp: number;
  /** Signal-specific metadata */
  metadata: Record<string, any>;
  /** Raw stack trace for attribution */
  stackTrace?: string;
}

/**
 * Trust score result for a package
 */
export interface TrustScoreResult {
  /** Package name */
  package: string;
  /** Package version */
  version: string;
  /** Trust score (0-100, higher = safer) */
  trustScore: number;
  /** Risk level derived from trust score */
  riskLevel: RiskLevel;
  /** Number of signals captured */
  signalCount: number;
  /** Breakdown of signals by type */
  behaviors: Partial<Record<SignalType, number>>;
}

/**
 * Report summary
 */
export interface ReportSummary {
  /** Total packages monitored */
  totalPackages: number;
  /** Total signals captured */
  totalSignals: number;
  /** Risk distribution */
  riskDistribution: Record<RiskLevel, number>;
}

/**
 * Full report with per-package analysis
 */
export interface Report {
  /** Report format version */
  version: string;
  /** Summary statistics */
  summary: ReportSummary;
  /** Per-package trust scores and signals */
  packages: TrustScoreResult[];
  /** Pattern analysis results */
  patterns?: PatternResults;
}

/**
 * Pattern analysis results
 */
export interface PatternResults {
  summary: {
    totalThreats: number;
  };
  cryptoMining?: PatternFinding[];
  dataExfiltration?: PatternFinding[];
  backdoors?: PatternFinding[];
  credentialTheft?: PatternFinding[];
  typosquats?: PatternFinding[];
}

/**
 * A single pattern finding
 */
export interface PatternFinding {
  /** Package name */
  package: string;
  /** Indicator description */
  indicator: string;
  /** Severity level */
  severity: RiskLevel;
  /** Pattern type */
  type: string;
}

/**
 * Policy enforcement result
 */
export interface EnforcementResult {
  /** Whether the policy passed */
  passed: boolean;
  /** Failure message if policy failed */
  message?: string;
  /** Packages that violated the policy */
  criticalPackages?: Array<{
    package: string;
    version: string;
    trustScore: number;
    riskLevel: RiskLevel;
  }>;
}

/**
 * Configuration schema for .bheeshmarc.json
 */
export interface BheeshmaConfig {
  thresholds?: {
    critical?: number;
    high?: number;
    medium?: number;
  };
  packageThresholds?: Record<string, number>;
  whitelist?: string[];
  blacklist?: string[];
  patterns?: {
    enabled?: boolean;
    detectCryptoMiners?: boolean;
    detectDataExfiltration?: boolean;
    detectBackdoors?: boolean;
  };
  performance?: {
    maxSignals?: number;
    deduplicateSignals?: boolean;
  };
}

/**
 * Output format options
 */
export type OutputFormat = 'cli' | 'json' | 'html' | 'sarif';

/**
 * Initialize bheeshma monitoring hooks.
 * Call this before requiring any third-party packages.
 */
export function init(): void;

/**
 * Generate a report in the specified format.
 * @param format - Output format: 'cli', 'json', 'html', or 'sarif'
 * @returns Formatted report string
 */
export function generateReport(format: OutputFormat): string;

/**
 * Generate a structured JSON report object.
 * @returns Parsed report with summary, packages, and patterns
 */
export function generateReport(format: 'json'): string;

/**
 * Check enforcement policy against current signals.
 * @returns Enforcement result with pass/fail and critical packages
 */
export function enforcePolicy(): EnforcementResult;

/**
 * Clean up all monitoring hooks and restore original functions.
 */
export function teardown(): void;
