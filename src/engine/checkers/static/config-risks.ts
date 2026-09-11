import type { Checker, Finding, Severity } from '../../types.js';
import { lineAt } from '../../util/text.js';
import { looksMinified, maskCode } from '../../util/mask.js';

interface Rule {
  id: string;
  title: string;
  re: RegExp;
  severity: Severity;
  detail: string;
  fix: string;
}

const RULES: Rule[] = [
  {
    id: 'cors_star',
    title: 'CORS open to any origin',
    re: /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']|origin\s*:\s*["']\*["']/g,
    severity: 'warning',
    detail: 'The API allows any origin ("*"). If it also allows credentials this is a serious CORS hole; even without credentials it widens exposure.',
    fix: 'Set an explicit allowlist of origins instead of "*", and never combine "*" with credentials.',
  },
  {
    id: 'debug_on',
    title: 'Debug mode enabled',
    re: /\bDEBUG\s*=\s*True\b|debug\s*=\s*True\b|run\([^)]*debug\s*=\s*True/g,
    severity: 'warning',
    detail: 'Debug mode leaks stack traces and internals to visitors in production.',
    fix: 'Drive debug from an env var and keep it off in production.',
  },
  {
    id: 'eval_use',
    title: 'Use of eval / new Function',
    re: /\beval\s*\(|\bnew\s+Function\s*\(/g,
    severity: 'warning',
    detail: 'eval on any untrusted input is a code-execution risk.',
    fix: 'Replace eval with explicit parsing/logic; never eval user-supplied data.',
  },
  {
    id: 'sql_interpolation',
    title: 'SQL built by string interpolation',
    // Requires real query shape: a DML verb + a clause keyword + interpolation,
    // inside one string literal — so prose mentioning "insert" won't match.
    // Quantifiers are length-bounded ({0,200}) to prevent catastrophic
    // backtracking (ReDoS) on very long / minified lines.
    re: /`\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]{0,200}\b(?:FROM|INTO|WHERE|VALUES|SET|JOIN)\b[^`]{0,200}\$\{|f["']\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"'\n]{0,200}\b(?:FROM|INTO|WHERE|VALUES|SET|JOIN)\b[^"'\n]{0,200}\{/gi,
    severity: 'warning',
    detail: 'Interpolating values into SQL invites SQL injection.',
    fix: 'Use parameterized queries / prepared statements instead of string interpolation.',
  },
  {
    id: 'jwt_alg_none',
    title: 'JWT algorithm set to none',
    re: /(?:alg|algorithm)["']?\s*[:=]\s*["']none["']/gi,
    severity: 'critical',
    detail: 'alg:none disables signature verification — anyone can forge a valid token.',
    fix: 'Require a real signing algorithm (e.g. HS256/RS256) and reject "none".',
  },
];

export const configRisksChecker: Checker = {
  id: 'config-risks',
  title: 'Dangerous configuration',
  level: 0,
  run(ctx) {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      // Config risks in prose docs are examples, not live config — skip them.
      if (file.rel.endsWith('.md') || file.rel.endsWith('.txt')) continue;
      if (looksMinified(file.rel, file.content)) continue; // generated output, not source
      // Comments and quoted strings must not trigger rules; backticks stay so the
      // SQL-interpolation rule can still see template literals.
      const scan = maskCode(file.content, { strings: true });
      for (const rule of RULES) {
        for (const m of scan.matchAll(rule.re)) {
          findings.push({
            id: rule.id,
            severity: rule.severity,
            title: rule.title,
            detail: rule.detail,
            fix: rule.fix,
            checker: 'config-risks',
            level: 0,
            file: file.rel,
            line: lineAt(file.content, m.index ?? 0),
          });
        }
      }
    }

    return findings;
  },
};
