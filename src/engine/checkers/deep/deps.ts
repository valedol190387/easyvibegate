import { execFile } from 'node:child_process';
import type { CheckRun, Finding, Severity } from '../../types.js';

interface AuditCounts {
  critical?: number;
  high?: number;
  moderate?: number;
  low?: number;
  info?: number;
  total?: number;
}

export interface DepsResult {
  findings: Finding[];
  run: CheckRun;
}

interface RunResult {
  stdout: string;
  code: number | null;
  failedToSpawn: boolean;
}

function run(cmd: string, args: string[], cwd: string, timeoutMs: number): Promise<RunResult> {
  return new Promise((resolve) => {
    execFile(cmd, args, { cwd, timeout: timeoutMs, maxBuffer: 20 * 1024 * 1024 }, (err, stdout) => {
      // audit tools exit non-zero when vulnerabilities are found; keep stdout.
      const e = err as (NodeJS.ErrnoException & { code?: number | string }) | null;
      const failedToSpawn = !!e && (e.code === 'ENOENT' || (e as { killed?: boolean }).killed === true);
      const code = e && typeof e.code === 'number' ? e.code : e ? 1 : 0;
      resolve({ stdout: stdout || '', code, failedToSpawn });
    });
  });
}

/**
 * Level 1: dependency vulnerability audit via the project's package manager.
 * Returns a status so an audit that could not run (offline, missing tool,
 * registry error) is never reported as "no vulnerabilities".
 */
export async function auditDeps(
  root: string,
  packageManagers: string[],
  timeoutMs = 60000,
): Promise<DepsResult> {
  const pm = packageManagers.includes('pnpm')
    ? 'pnpm'
    : packageManagers.includes('yarn')
      ? 'yarn'
      : packageManagers.includes('bun')
        ? 'bun'
        : 'npm';

  if (pm === 'bun') {
    return {
      findings: [],
      run: { id: 'deps', level: 1, status: 'unsupported', note: 'bun audit is not yet supported — run `bun audit` manually' },
    };
  }

  const failed = (note: string): DepsResult => ({
    findings: [],
    run: { id: 'deps', level: 1, status: 'failed', note },
  });

  const res = await run(pm, ['audit', '--json'], root, timeoutMs);
  if (res.failedToSpawn) return failed(`${pm} not found or timed out`);
  if (!res.stdout.trim()) return failed(`${pm} audit produced no output (offline or no lockfile?)`);

  let counts: AuditCounts;
  let vulnMap: Record<string, { severity?: string; name?: string }> = {};

  if (pm === 'yarn') {
    let summary: AuditCounts | undefined;
    for (const line of res.stdout.split('\n')) {
      const s = line.trim();
      if (!s.startsWith('{')) continue;
      try {
        const obj = JSON.parse(s) as { type?: string; data?: { vulnerabilities?: AuditCounts } };
        if (obj.type === 'auditSummary' && obj.data?.vulnerabilities) summary = obj.data.vulnerabilities;
      } catch { /* skip */ }
    }
    if (!summary) return failed('could not parse yarn audit output');
    counts = summary;
  } else {
    let parsed: {
      error?: unknown;
      metadata?: { vulnerabilities?: AuditCounts };
      vulnerabilities?: Record<string, { severity?: string; name?: string }>;
    };
    try {
      parsed = JSON.parse(res.stdout);
    } catch {
      const line = res.stdout.trim().split('\n').filter(Boolean).pop() ?? '';
      try {
        parsed = JSON.parse(line);
      } catch {
        return failed('could not parse audit output');
      }
    }
    // A valid JSON error envelope (e.g. registry unavailable) is NOT "clean".
    if (parsed.error !== undefined || !parsed.metadata?.vulnerabilities) {
      return failed('audit returned an error or an unrecognized shape');
    }
    counts = parsed.metadata.vulnerabilities;
    vulnMap = parsed.vulnerabilities ?? {};
  }

  const critical = counts.critical ?? 0;
  const high = counts.high ?? 0;
  const moderate = counts.moderate ?? 0;
  const low = counts.low ?? 0;
  const total = counts.total ?? critical + high + moderate + low;

  const findings: Finding[] = [];
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
  return { findings, run: { id: 'deps', level: 1, status: 'completed' } };
}
