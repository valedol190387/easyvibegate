import { execFile } from 'node:child_process';
import type { CheckRun, Finding, Severity } from '../../types.js';

interface AuditCounts {
  critical: number;
  high: number;
  moderate: number;
  low: number;
  info: number;
  total?: number;
}

export interface DepsResult {
  findings: Finding[];
  run: CheckRun;
}

interface RunResult {
  stdout: string;
  /** Exit code; null when the process died from a signal (or never ran). */
  code: number | null;
  failedToSpawn: boolean;
}

type Manager = 'npm' | 'pnpm' | 'yarn' | 'bun';
const MANAGERS = new Set<string>(['npm', 'pnpm', 'yarn', 'bun']);

function run(cmd: string, args: string[], cwd: string, timeoutMs: number): Promise<RunResult> {
  return new Promise((resolve) => {
    execFile(cmd, args, { cwd, timeout: timeoutMs, maxBuffer: 20 * 1024 * 1024 }, (err, stdout) => {
      // audit tools exit non-zero when vulnerabilities are found; keep stdout.
      const e = err as (NodeJS.ErrnoException & { code?: number | string }) | null;
      const failedToSpawn = !!e && (e.code === 'ENOENT' || (e as { killed?: boolean }).killed === true);
      const code = e ? (typeof e.code === 'number' ? e.code : null) : 0;
      resolve({ stdout: stdout || '', code, failedToSpawn });
    });
  });
}

/**
 * Exit codes that mean "the audit ran and found something", per tool docs:
 * npm/pnpm exit 1 when vulnerabilities exist; yarn v1 exits with a bitmask of
 * the severities found (1 info … 16 critical, max 31). Anything else is a tool
 * or registry error — a fake pnpm exiting 7 with an empty report once counted
 * as a clean `completed` run.
 */
function isVulnsFoundExit(pm: Manager, code: number): boolean {
  if (pm === 'yarn') return code >= 1 && code <= 31;
  return code === 1;
}

const SEVERITY_FIELDS = ['info', 'low', 'moderate', 'high', 'critical'] as const;

/**
 * Accept only a report whose severity counters are all present and numeric,
 * with `total` (when present) equal to their sum. `{}` or a missing field is
 * an unparseable report, never "0 vulnerabilities".
 */
function validCounts(v: unknown): AuditCounts | null {
  if (typeof v !== 'object' || v === null) return null;
  const o = v as Record<string, unknown>;
  const out: Record<string, number> = {};
  for (const k of SEVERITY_FIELDS) {
    const n = o[k];
    if (typeof n !== 'number' || !Number.isInteger(n) || n < 0) return null;
    out[k] = n;
  }
  const sum = SEVERITY_FIELDS.reduce((a, k) => a + (out[k] ?? 0), 0);
  if (o['total'] !== undefined) {
    if (typeof o['total'] !== 'number' || o['total'] !== sum) return null;
    out['total'] = o['total'];
  }
  return out as unknown as AuditCounts;
}

/**
 * Level 1: dependency vulnerability audit via the project's package manager.
 * Returns a status so an audit that could not run (offline, missing tool,
 * registry error, garbage output) is never reported as "no vulnerabilities".
 *
 * `packageManagers` comes from detect(): the declared `packageManager` field
 * first, then lockfile-detected managers in preference order — so [0] decides.
 */
export async function auditDeps(
  root: string,
  packageManagers: string[],
  timeoutMs = 60000,
): Promise<DepsResult> {
  const known = packageManagers.filter((m): m is Manager => MANAGERS.has(m));
  const pm: Manager = known[0] ?? 'npm';
  const others = [...new Set(known.slice(1))];

  if (pm === 'bun') {
    return {
      findings: [],
      run: { id: 'deps', level: 1, status: 'unsupported', note: 'bun audit is not yet supported — run `bun audit` manually' },
    };
  }

  // Several managers detected (a stale lockfile beside `packageManager`, or
  // two lockfiles): the audit only covers the one we ran. Say so, visibly but
  // not fatally — the audit itself did complete.
  const conflict = others.length
    ? `audited with ${pm}; ${others.join(', ')} lockfile(s)/declaration also present — remove the stale one so the audit covers what is actually installed`
    : undefined;
  const conflictFindings: Finding[] = conflict
    ? [{
        id: 'deps_manager_conflict',
        severity: 'advisory',
        title: 'Several package managers detected',
        detail: `Dependency audit ran with ${pm}, but ${others.join(', ')} is also detected (lockfile or packageManager field).`,
        fix: `Keep one package manager: delete the stale lockfile(s) or fix the \`packageManager\` field, so \`${pm} audit\` reflects the real dependency tree.`,
        checker: 'deps',
        level: 1,
      }]
    : [];
  const withNote = (r: CheckRun): CheckRun => (conflict ? { ...r, note: r.note ? `${r.note}; ${conflict}` : conflict } : r);

  const failed = (note: string): DepsResult => ({
    findings: conflictFindings,
    run: withNote({ id: 'deps', level: 1, status: 'failed', note }),
  });

  const res = await run(pm, ['audit', '--json'], root, timeoutMs);
  if (res.failedToSpawn) return failed(`${pm} not found or timed out`);
  if (res.code === null) return failed(`${pm} audit was terminated by a signal`);
  // A non-zero exit that is not the documented "vulnerabilities found" code is
  // a tool error, whatever stdout says.
  if (res.code !== 0 && !isVulnsFoundExit(pm, res.code)) return failed(`${pm} audit exited with code ${res.code}`);
  if (!res.stdout.trim()) return failed(`${pm} audit produced no output (offline or no lockfile?)`);

  let counts: AuditCounts | null = null;
  let vulnMap: Record<string, { severity?: string; name?: string }> = {};

  if (pm === 'yarn') {
    for (const line of res.stdout.split('\n')) {
      const s = line.trim();
      if (!s.startsWith('{')) continue;
      try {
        const obj = JSON.parse(s) as { type?: string; data?: { vulnerabilities?: unknown } };
        if (obj.type === 'auditSummary') counts = validCounts(obj.data?.vulnerabilities);
      } catch { /* skip */ }
    }
    if (!counts) return failed('unparseable audit output (no valid yarn auditSummary)');
  } else {
    let parsed: {
      error?: unknown;
      metadata?: { vulnerabilities?: unknown };
      vulnerabilities?: Record<string, { severity?: string; name?: string }>;
    };
    try {
      parsed = JSON.parse(res.stdout);
    } catch {
      const line = res.stdout.trim().split('\n').filter(Boolean).pop() ?? '';
      try {
        parsed = JSON.parse(line);
      } catch {
        return failed('unparseable audit output (not JSON)');
      }
    }
    // A valid JSON error envelope (e.g. registry unavailable) is NOT "clean".
    if (typeof parsed !== 'object' || parsed === null || parsed.error !== undefined) {
      return failed('audit returned an error envelope');
    }
    counts = validCounts(parsed.metadata?.vulnerabilities);
    if (!counts) return failed('unparseable audit output (metadata.vulnerabilities missing or malformed)');
    vulnMap = parsed.vulnerabilities ?? {};
  }

  const { critical, high, moderate, low } = counts;
  const total = counts.total ?? critical + high + moderate + low + counts.info;

  const findings: Finding[] = [...conflictFindings];
  if (total > 0) {
    const severity: Severity = critical + high > 0 ? 'critical' : moderate > 0 ? 'warning' : 'info';
    findings.push({
      id: 'deps_vulnerabilities',
      severity,
      title: `${total} vulnerable dependenc${total === 1 ? 'y' : 'ies'}`,
      detail: `${pm} audit: ${critical} critical, ${high} high, ${moderate} moderate, ${low} low.`,
      fix: `Run \`${pm} audit${pm === 'npm' ? ' fix' : ''}\` and upgrade the flagged packages; check breaking changes.`,
      checker: 'deps',
      level: 1,
    });
    const named = Object.values(vulnMap)
      .filter((v) => v.severity === 'critical' || v.severity === 'high')
      .map((v) => v.name)
      .filter(Boolean)
      .slice(0, 8);
    if (named.length) {
      findings.push({
        id: 'deps_top_packages',
        severity: 'info',
        title: 'High/critical packages to upgrade',
        detail: named.join(', '),
        fix: 'Upgrade these first; they carry the most severe advisories.',
        checker: 'deps',
        level: 1,
      });
    }
  }

  // "completed" with zero findings means genuinely no known vulns — the status,
  // not an info finding, records that the check ran cleanly.
  return { findings, run: withNote({ id: 'deps', level: 1, status: 'completed' }) };
}
