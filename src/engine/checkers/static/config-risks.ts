import type { Checker, CheckerResult, Finding, Severity } from '../../types.js';
import { lineAt } from '../../util/text.js';
import { looksBundledPath, maskTokens } from '../../util/mask.js';
import { langForFile, lexCode } from '../../util/code-lex.js';

interface Rule {
  id: string;
  title: string;
  re: RegExp;
  severity: Severity;
  detail: string;
  fix: string;
  /**
   * Whether quoted strings must be blanked before this rule runs.
   * Some rules look for a *literal value* (`"none"`, `"*"`, an f-string query) —
   * blanking strings deletes the very thing they match, so they must see the
   * source with only comments removed. Rules that look for *code* (eval) blank
   * strings so that the word inside a string is not reported.
   */
  maskStrings: boolean;
}

const RULES: Rule[] = [
  {
    id: 'cors_star',
    title: 'CORS open to any origin',
    re: /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']|origin\s*:\s*["']\*["']/g,
    severity: 'warning',
    detail: 'The API allows any origin ("*"). If it also allows credentials this is a serious CORS hole; even without credentials it widens exposure.',
    fix: 'Set an explicit allowlist of origins instead of "*", and never combine "*" with credentials.',
    maskStrings: false,
  },
  {
    id: 'debug_on',
    title: 'Debug mode enabled',
    re: /\bDEBUG\s*=\s*True\b|debug\s*=\s*True\b|run\([^)]*debug\s*=\s*True/g,
    severity: 'warning',
    detail: 'Debug mode leaks stack traces and internals to visitors in production.',
    fix: 'Drive debug from an env var and keep it off in production.',
    maskStrings: true,
  },
  {
    id: 'eval_use',
    title: 'Use of eval / new Function',
    // `(?<![\w.])` — `model.eval()` (PyTorch) and `obj.eval(` are methods, not the global.
    re: /(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(/g,
    severity: 'warning',
    detail: 'eval on any untrusted input is a code-execution risk.',
    fix: 'Replace eval with explicit parsing/logic; never eval user-supplied data.',
    maskStrings: true,
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
    maskStrings: false,
  },
  {
    id: 'jwt_alg_none',
    title: 'JWT algorithm set to none',
    re: /(?:alg|algorithm)["']?\s*[:=]\s*["']none["']/gi,
    severity: 'critical',
    detail: 'alg:none disables signature verification — anyone can forge a valid token.',
    fix: 'Require a real signing algorithm (e.g. HS256/RS256) and reject "none".',
    maskStrings: false,
  },
];

/**
 * Template tags that parameterize `${…}` instead of splicing it into the query
 * text (Postgres.js / slonik / drizzle `sql`, Prisma `$queryRaw` / `Prisma.sql`).
 * Matched against the code just before the backtick. `sql.unsafe` and
 * `$queryRawUnsafe` end differently and so stay reported, as do `.query(`…`)`
 * and untagged templates.
 */
const SAFE_SQL_TAG = /(?:^|[^\w$.])(?:sql|SQL|[\w$]+\.sql|(?:[\w$]+\.)?\$(?:queryRaw|executeRaw))\s*$/;

function isParameterizedTemplate(scan: string, backtickAt: number): boolean {
  if (scan[backtickAt] !== '`') return false;
  return SAFE_SQL_TAG.test(scan.slice(Math.max(0, backtickAt - 64), backtickAt));
}

/**
 * Where an interpolation sits decides what it can do. `WHERE id = ${id}` splices
 * a VALUE — injection. `FROM ${table}`, `SET ${col} = ?`, `ORDER BY ${dir}` splice
 * STRUCTURE with the values still parameterized — risky only if the names come
 * from request data, so it is reported as info, not as an injection. About half
 * of the real-world hits were structural.
 */
const VALUE_POSITION = /(=|<>|!=|<=|>=|<|>|\bLIKE|\bILIKE|\bIN\s*\(|\bVALUES\s*\([^)]*|\bBETWEEN|\bAND|\bOR|\bLIMIT|\bOFFSET|\bTHEN|\bELSE)\s*$/i;
const PLACEHOLDER_EXPR = /^\s*(?:\w+\.)?(placeholders?|params?|marks|questions|qs|values|binds?)\b/i;

function onlyStructuralInterpolation(scan: string, at: number): boolean {
  // The literal: from the opening delimiter to its close (bounded).
  const open = scan[at] === '`' ? '`' : scan[at + 1] ?? '"';
  const start = scan[at] === '`' ? at + 1 : at + 2;
  const close = scan.indexOf(open, start);
  const body = scan.slice(start, close === -1 ? Math.min(scan.length, start + 2000) : close);
  const holes = [...body.matchAll(/\$\{([^}]*)\}|(?<!\$)\{([^}]*)\}/g)];
  if (holes.length === 0) return false;
  for (const h of holes) {
    const expr = h[1] ?? h[2] ?? '';
    if (PLACEHOLDER_EXPR.test(expr)) continue;
    const before = body.slice(Math.max(0, (h.index ?? 0) - 60), h.index ?? 0);
    if (VALUE_POSITION.test(before)) return false;
  }
  return true;
}

export const configRisksChecker: Checker = {
  id: 'config-risks',
  title: 'Dangerous configuration',
  level: 0,
  run(ctx): CheckerResult {
    const findings: Finding[] = [];
    const skipped: string[] = [];

    for (const file of ctx.files) {
      // Config risks in prose docs are examples, not live config — skip them.
      if (file.rel.endsWith('.md') || file.rel.endsWith('.txt')) continue;
      // Generated output is skipped by PATH only and reported as missing
      // coverage below. A "looks minified" content heuristic used to skip a
      // file silently, so one long data line disabled every rule for it. The
      // regexes are length-bounded, so long lines are safe to scan instead.
      if (looksBundledPath(file.rel)) { skipped.push(file.rel); continue; }
      // Comments never trigger a rule. Strings are a per-rule decision: a rule
      // matching a literal value must still see it (see Rule.maskStrings).
      const tokens = lexCode(file.content, langForFile(file.rel));
      const noComments = maskTokens(file.content, tokens);
      const noStrings = maskTokens(file.content, tokens, { strings: true });
      for (const rule of RULES) {
        const scan = rule.maskStrings ? noStrings : noComments;
        for (const m of scan.matchAll(rule.re)) {
          if (rule.id === 'sql_interpolation' && isParameterizedTemplate(scan, m.index ?? 0)) continue;
          const structural = rule.id === 'sql_interpolation' && onlyStructuralInterpolation(scan, m.index ?? 0);
          findings.push({
            id: rule.id,
            severity: structural ? 'info' : rule.severity,
            title: structural ? 'SQL built with interpolated identifiers' : rule.title,
            detail: structural
              ? 'Table/column names or operators are spliced into the query while the values use placeholders. That is safe only if those names come from a fixed allowlist in code — never from request data (`Object.keys(body)` is the classic hole).'
              : rule.detail,
            fix: rule.fix,
            checker: 'config-risks',
            level: 0,
            file: file.rel,
            line: lineAt(file.content, m.index ?? 0),
          });
        }
      }
    }

    // Skipped is not clean: name what was not reviewed so the gate stays incomplete.
    if (skipped.length === 0) return { findings };
    const shown = skipped.slice(0, 5).join(', ') + (skipped.length > 5 ? `, … (+${skipped.length - 5})` : '');
    return { findings, partial: `${skipped.length} generated/minified file(s) not reviewed: ${shown}` };
  },
};
