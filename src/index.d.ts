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
export interface ViolatingPackage {
  name: string;
  version: string;
  score: number;
  riskLevel: RiskLevel;
}

export interface EnforcementResult {
  /** Whether the policy passed */
  passed: boolean;
  /** The fail level the check was run at */
  failLevel: FailLevel;
  /** Packages at or above the fail level */
  violatingPackages: ViolatingPackage[];
  /** Alias of violatingPackages, kept for backward compatibility */
  criticalPackages: ViolatingPackage[];
  /** Human-readable result message */
  message: string;
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

/** Enforcement fail levels, lowest to highest strictness. */
export type FailLevel = 'low' | 'medium' | 'high' | 'critical';

/** Options accepted by init(). */
export interface InitOptions {
  /** An inline config object (merged over defaults). */
  config?: BheeshmaConfig;
  /** Path to a .bheeshmarc.json file to load. */
  configPath?: string;
}

/** Result returned by init(). */
export interface InitResult {
  success: boolean;
  installed: string[];
  failed?: string[];
  config?: BheeshmaConfig;
  message?: string;
}

/** Result returned by teardown(). */
export interface TeardownResult {
  success: boolean;
  uninstalled: string[];
  failed?: string[];
}

/** Per-package score entry returned by getTrustScores(). */
export interface PackageScore {
  name: string;
  version: string;
  score: number;
  riskLevel: RiskLevel;
  signalCount: number;
  uniqueSignalCount: number;
  stats: Partial<Record<SignalType, number>>;
  effectiveSignals: Signal[];
}

/**
 * Initialize bheeshma monitoring hooks. Call as early as possible, before
 * requiring third-party packages.
 */
export function init(options?: InitOptions): InitResult;

/** Get a copy of all collected signals. */
export function getSignals(): Signal[];

/** Get calculated, pattern-aware trust scores keyed by `name@version`. */
export function getTrustScores(): Map<string, PackageScore>;

/** Get the active configuration (or null if not initialized). */
export function getConfig(): BheeshmaConfig | null;

/**
 * Generate a report. 'json'/'sarif' return serialized strings; 'cli'/'html'
 * return formatted text. Defaults to 'cli'.
 */
export function generateReport(format?: OutputFormat): string;

/**
 * Check enforcement policy against current signals.
 * @param options - Optional fail level (defaults to 'critical').
 */
export function enforcePolicy(options?: { failLevel?: FailLevel }): EnforcementResult;

/** Best-effort POST of a critical-findings alert to a webhook URL. */
export function sendAlertWebhook(url: string, criticalPackages: ViolatingPackage[]): void;

/** Remove all hooks, restore originals, and clear collected state. */
export function teardown(): TeardownResult;

/** Run `fn` under monitoring and return its result plus a report. */
export function monitor(
  fn: () => any,
  options?: { format?: OutputFormat }
): Promise<{ result: any; report: string }>;

/** Record a single signal (respects whitelist/blacklist/maxSignals). */
export function recordSignal(signal: Signal): boolean;

/**
 * Ingest signals collected by another process (used by the CI child preload).
 * @returns the number of signals ingested.
 */
export function ingestSignals(signals: Signal[]): number;
