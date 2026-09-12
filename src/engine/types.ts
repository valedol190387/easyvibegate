export type Severity = 'critical' | 'warning' | 'info' | 'advisory';
export type Level = 0 | 1 | 2;

export const SEVERITY_ORDER: Severity[] = ['critical', 'warning', 'info', 'advisory'];

/**
 * Whether a check actually ran and produced a trustworthy result. This is kept
 * separate from findings so "checked and clean", "could not check", "nothing to
 * check", and "not run" are never conflated into a green PASS.
 */
export type CheckStatus = 'completed' | 'partial' | 'failed' | 'skipped' | 'unsupported';

export interface CheckRun {
  /** Human id of the check, e.g. "static:secrets", "supabase-probe", "deps". */
  id: string;
  level: Level;
  status: CheckStatus;
  /** Short reason, shown to the user (e.g. "network error", "no lockfile"). */
  note?: string;
}

export interface Finding {
  /** Machine-readable id, e.g. "openai_key", "supabase_anon_read". */
  id: string;
  severity: Severity;
  title: string;
  /** One-line explanation of what was found. */
  detail: string;
  /** Copy-paste remediation guidance. */
  fix: string;
  /** Which checker produced it. */
  checker: string;
  level: Level;
  /** Project-relative file path, if the finding is code-based. */
  file?: string;
  /** 1-based line number inside `file`, if known. */
  line?: number;
  /** Endpoint reference for live findings, e.g. "GET /api/orders/1". */
  endpoint?: string;
  /** Redacted evidence (never a raw secret): a masked value or a curl. */
  evidence?: string;
}

export interface ScanFile {
  /** Absolute path on disk. */
  abs: string;
  /** Path relative to the scanned root, using "/" separators. */
  rel: string;
  content: string;
  /** Lowercased extension including the dot, e.g. ".ts". Empty if none. */
  ext: string;
  size: number;
}

export interface Detection {
  frameworks: string[];
  backends: string[];
  languages: string[];
  packageManagers: string[];
  hasEnv: boolean;
  hasGitignore: boolean;
}

export interface CheckerContext {
  root: string;
  files: ScanFile[];
  detection: Detection;
}

/**
 * A checker may report that it could not interpret part of its input. That is
 * missing coverage, not a clean result: the run is recorded as `partial`, which
 * makes the gate `incomplete`. Unknown must never read as clean.
 */
export interface CheckerResult {
  findings: Finding[];
  /** Why coverage is partial (shown to the user). Omit when complete. */
  partial?: string;
}

export interface Checker {
  id: string;
  title: string;
  level: Level;
  run(ctx: CheckerContext): Finding[] | CheckerResult | Promise<Finding[] | CheckerResult>;
}
