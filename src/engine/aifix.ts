import type { Finding, Severity } from './types.js';
import type { ScanResult } from './scan.js';
import type { Summary } from './report.js';
import { sortFindings, whereOf } from './report.js';
import { t, type Lang } from './i18n.js';

const LABEL: Record<Severity, string> = { critical: 'CRITICAL', warning: 'WARNING', info: 'INFO', advisory: 'ADVISORY' };

/**
 * Assemble a single "master fix prompt" to paste into Cursor/Claude/an AI agent.
 * Actionable findings become numbered fix tasks; advisories become a manual
 * verification checklist. Secrets are never included in raw form.
 */
export function buildAiFixPrompt(result: ScanResult, summary: Summary, lang: Lang = 'en'): string {
  const all = sortFindings(result.findings);
  const actionable = all.filter((f) => f.severity === 'critical' || f.severity === 'warning');
  const advisories = all.filter((f) => f.severity === 'advisory');
  const lines: string[] = [];

  lines.push(t(lang, 'aifix.title'));
  lines.push('');
  lines.push(t(lang, 'aifix.intro', { crit: summary.counts.critical, warn: summary.counts.warning, score: summary.score, gate: summary.gate.toUpperCase() }));
  lines.push('');
  lines.push(`## ${t(lang, 'aifix.rules')}`);
  lines.push(t(lang, 'aifix.rule1'));
  lines.push(t(lang, 'aifix.rule2'));
  lines.push(t(lang, 'aifix.rule3'));
  lines.push(t(lang, 'aifix.rule4'));
  lines.push(t(lang, 'aifix.rule5'));
  lines.push(t(lang, 'aifix.rule6'));
  lines.push('');
  lines.push(`## ${t(lang, 'aifix.issues')}`);
  lines.push('');

  if (actionable.length === 0) {
    lines.push(t(lang, 'aifix.none'));
  }
  actionable.forEach((f, i) => {
    lines.push(`### ${i + 1}. [${LABEL[f.severity]}] ${f.title}`);
    lines.push(`- ${t(lang, 'aifix.location')}: \`${whereOf(f)}\``);
    lines.push(`- ${t(lang, 'aifix.problem')}: ${f.detail}`);
    lines.push(`- ${t(lang, 'aifix.fix')}: ${f.fix}`);
    lines.push('');
  });

  if (advisories.length > 0) {
    lines.push(`## ${t(lang, 'aifix.manual')}`);
    lines.push('');
    for (const f of advisories) lines.push(`- ${f.title}: ${f.detail}`);
    lines.push('');
  }

  lines.push(`## ${t(lang, 'aifix.done')}`);
  lines.push(t(lang, 'aifix.done1'));
  lines.push(t(lang, 'aifix.done2'));
  lines.push(t(lang, 'aifix.done3'));
  lines.push('');

  return lines.join('\n');
}
