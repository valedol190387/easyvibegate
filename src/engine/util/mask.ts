/**
 * Blank out comments (and, optionally, quoted strings) while preserving length
 * and newlines, so match offsets and line numbers stay correct. Used so that a
 * comment like `// never use eval()` is not reported as a finding.
 *
 * What counts as a comment or a string depends on the language, so pass the
 * file name (or a `lang`) — see code-lex.ts. Without either, the legacy
 * `mixed` rules apply: both `//` and `#` comments, strings atomic.
 */
import { lexCode, langForFile, type CodeLang, type CodeToken } from './code-lex.js';

export interface MaskOptions {
  /** Also blank string / template / regex literals (rules that look for *code*). */
  strings?: boolean;
  /** Project-relative path; picks the language rules by extension. */
  file?: string;
  /** Explicit language rules; wins over `file`. */
  lang?: CodeLang;
}

export function maskCode(src: string, opts: MaskOptions = {}): string {
  const lang = opts.lang ?? (opts.file ? langForFile(opts.file) : 'mixed');
  return maskTokens(src, lexCode(src, lang), opts);
}

/**
 * Same as maskCode but over tokens lexed once — a checker that needs both the
 * "no comments" and the "no strings" view of a file pays for lexing only once.
 */
export function maskTokens(src: string, tokens: CodeToken[], opts: { strings?: boolean } = {}): string {
  const out = src.split('');
  const n = src.length;
  const blank = (from: number, to: number) => {
    for (let k = from; k < to && k < n; k++) if (out[k] !== '\n') out[k] = ' ';
  };
  for (const t of tokens) {
    if (t.type === 'comment') blank(t.start, t.end);
    else if (opts.strings && (t.type === 'string' || t.type === 'template' || t.type === 'regex')) blank(t.start, t.end);
  }
  return out.join('');
}

/**
 * Paths that hold generated output, not source a human wrote: `.min.js`,
 * `dist/`, `build/`, `vendor/`, `bundle/`. A checker that skips these must
 * say so (CheckerResult.partial) — skipped is not clean.
 */
export function looksBundledPath(rel: string): boolean {
  return /\.min\.(js|css|mjs|cjs)$/i.test(rel) || /(^|\/)(dist|build|vendor|bundle)\//.test(rel);
}

/**
 * Minified/bundled output is not source a human wrote — reviewing it is noise.
 * The long-line heuristic is only a guess: one long data line in a real source
 * file also trips it, so callers must never use it to skip a file silently.
 */
export function looksMinified(rel: string, content: string): boolean {
  if (looksBundledPath(rel)) return true;
  const lines = content.split('\n');
  const longest = lines.reduce((m, l) => Math.max(m, l.length), 0);
  return longest > 800 && lines.length < content.length / 200;
}
