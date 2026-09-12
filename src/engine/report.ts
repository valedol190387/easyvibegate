import type { CheckRun, Finding, Severity } from './types.js';
import { SEVERITY_ORDER } from './types.js';
import type { ScanResult } from './scan.js';
import { color } from './util/color.js';
import { t, type Lang } from './i18n.js';
import { VERSION } from './version.js';

const WEIGHTS: Record<Severity, number> = { critical: 25, warning: 8, info: 2, advisory: 0 };
/**
 * How many findings of a severity may move the score. Beyond the cap the count
 * still shows in the report, but the grade stops falling: 562 warnings once
 * produced 0/100 next to a project with real critical leaks at the same 0/100,
 * which told the reader nothing. Criticals can still zero the score.
 */
const SCORE_CAP: Record<Severity, number> = { critical: 4, warning: 5, info: 5, advisory: 0 };
const EMOJI: Record<Severity, string> = { critical: '🔴', warning: '🟡', info: '🔵', advisory: '⚪' };

export interface Coverage {
  completed: number;
  partial: number;
  failed: number;
  skipped: number;
  unsupported: number;
  total: number;
  /** A requested check was attempted but could not finish, or is unsupported. */
  incomplete: boolean;
  /** No check actually produced a trustworthy result. */
  nothingVerified: boolean;
}

export function coverage(runs: CheckRun[]): Coverage {
  const c = { completed: 0, partial: 0, failed: 0, skipped: 0, unsupported: 0 };
  for (const r of runs) c[r.status]++;
  return {
    ...c,
    total: runs.length,
    incomplete: c.failed > 0 || c.partial > 0 || c.unsupported > 0,
    nothingVerified: c.completed + c.partial === 0,
  };
}

/**
 * The single verdict every surface (CI exit, JSON, badge, console, next steps)
 * derives from. `incomplete` means: no critical finding, but the result cannot
 * be called clean because a check failed/partially ran/is unsupported, or
 * nothing was verified at all.
 */
export type Gate = 'pass' | 'warn' | 'fail' | 'incomplete';

export interface Summary {
  score: number;
  gate: Gate;
  counts: Record<Severity, number>;
  coverage: Coverage;
}

export function summarize(findings: Finding[], runs: CheckRun[] = []): Summary {
  const counts: Record<Severity, number> = { critical: 0, warning: 0, info: 0, advisory: 0 };
  let score = 100;
  const counted: Record<Severity, number> = { critical: 0, warning: 0, info: 0, advisory: 0 };
  for (const f of findings) {
    counts[f.severity]++;
    if (counted[f.severity] < SCORE_CAP[f.severity]) score -= WEIGHTS[f.severity];
    counted[f.severity]++;
  }
  const cov = coverage(runs);
  const gate: Gate =
    counts.critical > 0 ? 'fail'
      : cov.incomplete || cov.nothingVerified ? 'incomplete'
        : counts.warning > 0 ? 'warn'
          : 'pass';
  return { score: Math.max(0, score), gate, counts, coverage: cov };
}

/** CI exit code from the same policy: 2 critical, 1 warning, 3 incomplete, 0 clean. */
export function exitCodeFor(summary: Summary): number {
  switch (summary.gate) {
    case 'fail': return 2;
    case 'incomplete': return 3;
    case 'warn': return 1;
    default: return 0;
  }
}

export function whereOf(f: Finding): string {
  if (f.endpoint) return f.endpoint;
  if (f.file && f.line) return `${f.file}:${f.line}`;
  if (f.file) return f.file;
  return '—';
}

export function sortFindings(findings: Finding[]): Finding[] {
  const rank = (s: Severity) => SEVERITY_ORDER.indexOf(s);
  return [...findings].sort(
    (a, b) =>
      rank(a.severity) - rank(b.severity) ||
      (a.file ?? '').localeCompare(b.file ?? '') ||
      (a.line ?? 0) - (b.line ?? 0),
  );
}

/** Badge reflects the gate, never a bare score: an incomplete run is never green. */
export function badgeMarkdown(summary: Summary): string {
  if (summary.gate === 'fail') return `![EasyVibeGate](https://img.shields.io/badge/EasyVibeGate-${summary.score}%2F100-red)`;
  if (summary.gate === 'incomplete') return '![EasyVibeGate](https://img.shields.io/badge/EasyVibeGate-incomplete-yellow)';
  if (summary.gate === 'warn') return `![EasyVibeGate](https://img.shields.io/badge/EasyVibeGate-${summary.score}%2F100-yellow)`;
  const c = summary.score >= 90 ? 'brightgreen' : summary.score >= 60 ? 'yellow' : 'orange';
  return `![EasyVibeGate](https://img.shields.io/badge/EasyVibeGate-${summary.score}%2F100-${c})`;
}

function stackLine(result: ScanResult): string {
  const d = result.detection;
  const parts: string[] = [];
  if (d.frameworks.length) parts.push(d.frameworks.join(', '));
  if (d.backends.length) parts.push(`backend: ${d.backends.join(', ')}`);
  if (d.languages.length) parts.push(d.languages.join(', '));
  return parts.join(' · ') || 'unknown stack';
}

function gateLabel(summary: Summary): string {
  if (summary.gate === 'fail') return color.red(color.bold('FAIL'));
  if (summary.gate === 'incomplete') return color.yellow(color.bold('INCOMPLETE'));
  if (summary.gate === 'warn') return color.yellow(color.bold('WARN'));
  return color.green(color.bold('PASS'));
}

export function renderConsole(result: ScanResult, summary: Summary, lang: Lang = 'en'): string {
  const lines: string[] = [];
  lines.push('');
  lines.push(`${color.bold('🛡  EasyVibeGate')} ${color.gray(`· ${t(lang, 'console.filesLine', { n: result.fileCount })} · ${stackLine(result)}`)}`);
  lines.push('');

  const shown = sortFindings(result.findings);
  if (shown.length === 0) lines.push(color.green(`  ${t(lang, 'console.none')}`));
  for (const f of shown) {
    lines.push(`  ${EMOJI[f.severity]} ${color.bold(f.title)} ${color.gray(whereOf(f))}`);
    lines.push(`     ${color.dim(f.detail)}`);
    if (f.evidence) lines.push(`     ${color.gray(`${t(lang, 'console.evidence')}: ${f.evidence}`)}`);
    lines.push(`     ${color.cyan(`${t(lang, 'console.fix')}: ${f.fix}`)}`);
  }

  lines.push('');
  const c = summary.counts;
  lines.push(`  ${color.bold(t(lang, 'console.score'))} ${scoreColor(summary)} ${color.gray('/100')}   ${color.bold(t(lang, 'console.gate'))} ${gateLabel(summary)}`);
  lines.push(`  ${EMOJI.critical} ${c.critical}  ${EMOJI.warning} ${c.warning}  ${EMOJI.info} ${c.info}  ${EMOJI.advisory} ${c.advisory}`);
  const cov = summary.coverage;
  const covLine = t(lang, 'cov.line', { ok: cov.completed, failed: cov.failed + cov.partial + cov.unsupported, skipped: cov.skipped });
  lines.push(`  ${cov.incomplete ? color.yellow(covLine) : color.gray(covLine)}`);
  lines.push('');
  return lines.join('\n');
}

function scoreColor(summary: Summary): string {
  const s = String(summary.score);
  if (summary.gate === 'fail') return color.red(s);
  if (summary.gate === 'incomplete' || summary.gate === 'warn') return color.yellow(s);
  return color.green(s);
}

/** One plain-language line a non-technical user understands. */
export function renderVerdict(summary: Summary, lang: Lang = 'en'): string {
  const c = summary.counts;
  if (summary.gate === 'fail') return color.red(color.bold(`  ${t(lang, 'verdict.fail', { crit: c.critical })}`));
  if (summary.gate === 'incomplete') {
    const key = summary.coverage.nothingVerified ? 'verdict.nocov' : 'verdict.incompleteGate';
    return color.yellow(color.bold(`  ${t(lang, key, { n: summary.coverage.failed + summary.coverage.partial + summary.coverage.unsupported })}`));
  }
  if (c.warning > 0) return color.yellow(color.bold(`  ${t(lang, 'verdict.warn', { warn: c.warning })}`));
  return color.green(color.bold(`  ${t(lang, 'verdict.clean')}`));
}

/** The beginner-facing "what do I do now" block, with an AI-agent handoff. */
export function renderNextSteps(summary: Summary, reportDir: string, lang: Lang = 'en'): string {
  const lines: string[] = [];
  lines.push(color.bold(`  ${t(lang, 'next.title')}`));
  if (summary.counts.critical === 0 && summary.counts.warning === 0) {
    lines.push(`  ${summary.gate === 'incomplete' ? color.yellow(t(lang, 'next.incompleteClean')) : t(lang, 'next.clean')}`);
    lines.push('');
    return lines.join('\n');
  }
  lines.push(`  ${t(lang, 'next.step1', { path: color.cyan(`${reportDir}/ai-fix-prompt.md`) })}`);
  lines.push(`  ${t(lang, 'next.step2a')}`);
  lines.push(`  ${t(lang, 'next.step2b')}`);
  lines.push(color.gray(`  ${t(lang, 'next.model1')}`));
  lines.push(color.gray(`  ${t(lang, 'next.model2')}`));
  let n = 3;
  if (summary.counts.critical > 0) { lines.push(`  ${t(lang, 'next.rotate', { n })}`); n++; }
  lines.push(`  ${t(lang, 'next.rerun', { n })}`);
  if (summary.gate === 'incomplete') lines.push(color.yellow(`  ${t(lang, 'next.incompleteClean')}`));
  lines.push('');
  return lines.join('\n');
}

export function renderMarkdown(result: ScanResult, summary: Summary, lang: Lang = 'en'): string {
  const lines: string[] = [];
  lines.push('# 🛡 EasyVibeGate Report');
  lines.push('');
  lines.push(t(lang, 'md.summary', { score: summary.score, gate: summary.gate.toUpperCase(), files: result.fileCount }));
  lines.push('');
  lines.push(t(lang, 'md.stack', { stack: stackLine(result) }));
  lines.push('');
  lines.push(`\`${result.root}\` · EasyVibeGate ${VERSION} · ${new Date().toISOString()}`);
  lines.push('');
  lines.push(badgeMarkdown(summary));
  lines.push('');

  // Coverage — make failed/partial/skipped/unsupported checks visible.
  const notDone = result.runs.filter((r) => r.status !== 'completed');
  if (notDone.length > 0) {
    lines.push(`## ${t(lang, 'md.checks')}`);
    lines.push('');
    for (const r of notDone) lines.push(`- \`${r.id}\` — **${r.status}**${r.note ? ` (${r.note})` : ''}`);
    lines.push('');
  }

  const shown = sortFindings(result.findings);
  if (shown.length === 0) {
    lines.push(t(lang, 'md.none'));
    lines.push('');
    return lines.join('\n');
  }
  for (const sev of SEVERITY_ORDER) {
    const group = shown.filter((f) => f.severity === sev);
    if (group.length === 0) continue;
    lines.push(`## ${EMOJI[sev]} ${t(lang, `sev.${sev}`)} (${group.length})`);
    lines.push('');
    for (const f of group) {
      lines.push(`- **${f.title}** — ${f.detail}`);
      lines.push(`  - ${t(lang, 'md.where')}: \`${whereOf(f)}\``);
      if (f.evidence) lines.push(`  - ${t(lang, 'md.evidence')}: \`${f.evidence}\``);
      lines.push(`  - ${t(lang, 'md.fix')}: ${f.fix}`);
    }
    lines.push('');
  }
  lines.push('---');
  lines.push(t(lang, 'md.generated'));
  lines.push('');
  return lines.join('\n');
}

export function renderJson(result: ScanResult, summary: Summary): string {
  return JSON.stringify(
    {
      projectRoot: result.root,
      scannedAt: new Date().toISOString(),
      version: VERSION,
      score: summary.score,
      gate: summary.gate,
      counts: summary.counts,
      coverage: summary.coverage,
      fileCount: result.fileCount,
      detection: result.detection,
      runs: result.runs,
      findings: sortFindings(result.findings),
    },
    null,
    2,
  );
}
