import { execFile } from 'node:child_process';
import type { Finding, Severity } from '../../types.js';

interface AuditCounts {
  critical?: number;
  high?: number;
  moderate?: number;
  low?: number;
  info?: number;
  total?: number;
}

function run(cmd: string, args: string[], cwd: string, timeoutMs: number): Promise<string> {
  return new Promise((resolve) => {
    execFile(cmd, args, { cwd, timeout: timeoutMs, maxBuffer: 20 * 1024 * 1024 }, (_err, stdout) => {
      // audit tools exit non-zero when vulnerabilities are found; we still want stdout.
      resolve(stdout || '');
    });
  });
}

/**
 * Level 1: dependency vulnerability audit via the project's package manager.
 * Best-effort across npm and pnpm; degrades to an info note if it can't parse.
 */
export async function auditDeps(
  root: string,
  packageManagers: string[],
  timeoutMs = 60000,
): Promise<Finding[]> {
  const pm = packageManagers.includes('pnpm')
    ? 'pnpm'
    : packageManagers.includes('yarn')
      ? 'yarn'
      : 'npm';

  // npm & pnpm: `<pm> audit --json` → one JSON object with metadata.vulnerabilities.
  // yarn (classic): `yarn audit --json` → NDJSON, summary line type "auditSummary".
  let raw = '';
  try {
    raw = await run(pm, ['audit', '--json'], root, timeoutMs);
  } catch {
    /* handled below */
  }

  const unavailable = (): Finding[] => [{
    id: 'deps_audit_unavailable',
    severity: 'info',
    title: 'Dependency audit could not run',
    detail: `Could not get audit output from ${pm}. It may be offline, the lockfile may be missing, or this ${pm} version differs.`,
    fix: `Run \`${pm} audit\` manually and address high/critical advisories.`,
    checker: 'deps',
    level: 1,
  }];

  if (!raw.trim()) return unavailable();

  let counts: AuditCounts;
  let vulnMap: Record<string, { severity?: string; name?: string }> = {};

  if (pm === 'yarn') {
    // Find the auditSummary NDJSON line: { type: "auditSummary", data: { vulnerabilities: {...} } }.
    let summary: AuditCounts | undefined;
    for (const line of raw.split('\n')) {
      const s = line.trim();
      if (!s.startsWith('{')) continue;
      try {
        const obj = JSON.parse(s) as { type?: string; data?: { vulnerabilities?: AuditCounts } };
        if (obj.type === 'auditSummary' && obj.data?.vulnerabilities) summary = obj.data.vulnerabilities;
      } catch {
        /* skip non-JSON lines */
      }
    }
    if (!summary) return unavailable();
    counts = summary;
  } else {
    let parsed: { metadata?: { vulnerabilities?: AuditCounts }; vulnerabilities?: Record<string, { severity?: string; name?: string }> };
    try {
      parsed = JSON.parse(raw);
    } catch {
      const line = raw.trim().split('\n').filter(Boolean).pop() ?? '';
      try {
        parsed = JSON.parse(line);
      } catch {
        return unavailable();
      }
    }
    counts = parsed.metadata?.vulnerabilities ?? {};
    vulnMap = parsed.vulnerabilities ?? {};
  }

  const critical = counts.critical ?? 0;
  const high = counts.high ?? 0;
  const moderate = counts.moderate ?? 0;
  const low = counts.low ?? 0;
  const total = counts.total ?? critical + high + moderate + low;

  const findings: Finding[] = [];

  if (total === 0) {
    return [{
      id: 'deps_clean',
      severity: 'info',
      title: 'No known-vulnerable dependencies',
      detail: `${pm} audit reported no advisories.`,
      fix: 'Keep dependencies updated and re-run audits in CI.',
      checker: 'deps',
      level: 1,
    }];
  }

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

  // Name a few high/critical packages when the detailed map is present (npm/pnpm).
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

  return findings;
}
