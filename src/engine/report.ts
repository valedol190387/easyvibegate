import type { Finding, Severity } from './types.js';
import { SEVERITY_ORDER } from './types.js';
import type { ScanResult } from './scan.js';
import { color } from './util/color.js';
import { t, type Lang } from './i18n.js';

const WEIGHTS: Record<Severity, number> = { critical: 25, warning: 8, info: 2, advisory: 0 };
const EMOJI: Record<Severity, string> = { critical: '🔴', warning: '🟡', info: '🔵', advisory: '⚪' };

export interface Summary {
  score: number;
  gate: 'pass' | 'fail';
  counts: Record<Severity, number>;
}

export function summarize(findings: Finding[]): Summary {
  const counts: Record<Severity, number> = { critical: 0, warning: 0, info: 0, advisory: 0 };
  let score = 100;
  for (const f of findings) {
    counts[f.severity]++;
    score -= WEIGHTS[f.severity];
  }
  return {
    score: Math.max(0, score),
    gate: counts.critical > 0 ? 'fail' : 'pass',
    counts,
  };
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

function badgeColor(summary: Summary): string {
  if (summary.gate === 'fail') return 'red';
  if (summary.score >= 90) return 'brightgreen';
  if (summary.score >= 60) return 'yellow';
  return 'orange';
}

export function badgeMarkdown(summary: Summary): string {
  return `![EasyVibeGate](https://img.shields.io/badge/EasyVibeGate-${summary.score}%2F100-${badgeColor(summary)})`;
}

function stackLine(result: ScanResult): string {
  const d = result.detection;
  const parts: string[] = [];
  if (d.frameworks.length) parts.push(d.frameworks.join(', '));
  if (d.backends.length) parts.push(`backend: ${d.backends.join(', ')}`);
  if (d.languages.length) parts.push(d.languages.join(', '));
  return parts.join(' · ') || 'unknown stack';
}

export function renderConsole(result: ScanResult, summary: Summary, lang: Lang = 'en'): string {
  const lines: string[] = [];
  const gateText =
    summary.gate === 'fail' ? color.red(color.bold('FAIL')) : color.green(color.bold('PASS'));

  lines.push('');
  lines.push(`${color.bold('🛡  EasyVibeGate')} ${color.gray(`· ${result.fileCount} ${t(lang, 'console.files')} · ${stackLine(result)}`)}`);
  lines.push('');

  const shown = sortFindings(result.findings);
  if (shown.length === 0) {
    lines.push(color.green(`  ${t(lang, 'console.none')}`));
  }
  for (const f of shown) {
    lines.push(`  ${EMOJI[f.severity]} ${color.bold(f.title)} ${color.gray(whereOf(f))}`);
    lines.push(`     ${color.dim(f.detail)}`);
    if (f.evidence) lines.push(`     ${color.gray(`${t(lang, 'console.evidence')}: ${f.evidence}`)}`);
    lines.push(`     ${color.cyan(`${t(lang, 'console.fix')}: ${f.fix}`)}`);
  }

  lines.push('');
  const c = summary.counts;
  lines.push(`  ${color.bold(t(lang, 'console.score'))} ${scoreColor(summary)} ${color.gray('/100')}   ${color.bold(t(lang, 'console.gate'))} ${gateText}`);
  lines.push(`  ${EMOJI.critical} ${c.critical}  ${EMOJI.warning} ${c.warning}  ${EMOJI.info} ${c.info}  ${EMOJI.advisory} ${c.advisory}`);
  lines.push('');
  return lines.join('\n');
}

function scoreColor(summary: Summary): string {
  const s = String(summary.score);
  if (summary.gate === 'fail') return color.red(s);
  if (summary.score >= 90) return color.green(s);
  return color.yellow(s);
}

/** One plain-language line a non-technical user understands. */
export function renderVerdict(summary: Summary, lang: Lang = 'en'): string {
  const c = summary.counts;
  if (summary.gate === 'fail') {
    return color.red(color.bold(`  ${t(lang, 'verdict.fail', { crit: c.critical })}`));
  }
  if (c.warning > 0) {
    return color.yellow(color.bold(`  ${t(lang, 'verdict.warn', { warn: c.warning })}`));
  }
  return color.green(color.bold(`  ${t(lang, 'verdict.clean')}`));
}

/** The beginner-facing "what do I do now" block, with an AI-agent handoff. */
export function renderNextSteps(summary: Summary, reportDir: string, lang: Lang = 'en'): string {
  const lines: string[] = [];
  lines.push(color.bold(`  ${t(lang, 'next.title')}`));
  if (summary.counts.critical === 0 && summary.counts.warning === 0) {
    lines.push(`  ${t(lang, 'next.clean')}`);
    lines.push('');
    return lines.join('\n');
  }
  lines.push(`  ${t(lang, 'next.step1', { path: color.cyan(`${reportDir}/ai-fix-prompt.md`) })}`);
  lines.push(`  ${t(lang, 'next.step2a')}`);
  lines.push(`  ${t(lang, 'next.step2b')}`);
  lines.push(color.gray(`  ${t(lang, 'next.model1')}`));
  lines.push(color.gray(`  ${t(lang, 'next.model2')}`));
  let n = 3;
  if (summary.counts.critical > 0) {
    lines.push(`  ${t(lang, 'next.rotate', { n })}`);
    n++;
  }
  lines.push(`  ${t(lang, 'next.rerun', { n })}`);
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
  lines.push(badgeMarkdown(summary));
  lines.push('');

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
      score: summary.score,
      gate: summary.gate,
      counts: summary.counts,
      fileCount: result.fileCount,
      detection: result.detection,
      findings: sortFindings(result.findings),
    },
    null,
    2,
  );
}
