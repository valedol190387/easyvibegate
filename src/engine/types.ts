export type Severity = 'critical' | 'warning' | 'info' | 'advisory';
export type Level = 0 | 1 | 2;

export const SEVERITY_ORDER: Severity[] = ['critical', 'warning', 'info', 'advisory'];

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

export interface Checker {
  id: string;
  title: string;
  level: Level;
  run(ctx: CheckerContext): Finding[] | Promise<Finding[]>;
}
