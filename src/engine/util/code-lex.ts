/**
 * A small per-language lexer for source code, chosen by file extension.
 *
 * Why this exists: the old masker scanned characters with no notion of which
 * language it was reading. `//` inside a URL string became a line comment and
 * erased the real code after it; a JS `#private` field or a Python `4 // 2`
 * was taken for a comment; a quoted string was not atomic, so anything inside
 * it could open a "comment" that swallowed the rest of the line. Every such
 * corner was a silently missed finding — a clean PASS on dangerous code.
 *
 * Lexing once, per language, makes that family of bugs impossible by
 * construction: a string is one token whatever it contains, a comment is one
 * token, and the rules for what starts either come from the language, not
 * from a guess. Same approach as sql-lex.ts, which SQL already relies on.
 *
 * Coverage is deliberately small: comments, strings, template literals and
 * regex literals. Everything else is `word` or `punct`. The grammars are
 * approximations for languages we only *mask* (Go/Java/Rust share the C-family
 * rules; shell/YAML/TOML share `#` rules), documented in `langForFile`.
 */
import { lexSql } from './sql-lex.js';

export type CodeLang =
  | 'js'      // C-family: `//` `/* */`, '…' "…" `…${}…`, /regex/, #private
  | 'html'    // js + `<!-- -->` (Vue/Svelte/Astro/HTML)
  | 'python'  // `#`, '…' "…" '''…''' """…""", `//` is an operator
  | 'hash'    // `#` line comments only (shell, YAML, TOML, .env, Ruby, …)
  | 'sql'     // delegated to lexSql: `--`, nested `/* */`, '…', $tag$…$tag$
  | 'markup'  // `<!-- -->` only, quotes are prose (XML, SVG, plist)
  | 'mixed'   // unknown text / prose: `//` `/* */` AND `#` — the legacy behaviour, strings atomic
  | 'none';   // no comments at all (JSON, keys, certificates); strings still atomic

export type CodeTokenType =
  | 'word'      // identifier, keyword or number
  | 'string'    // quoted literal — its contents are never code
  | 'template'  // a literal chunk of a JS template (`…${` / `}…${` / `}…`)
  | 'regex'     // JS /…/ literal — a literal, never code
  | 'comment'   // any comment form of the language
  | 'punct';    // any single other character

export interface CodeToken {
  type: CodeTokenType;
  /** Raw text of the token, delimiters included. */
  value: string;
  /** Offset of the token's first character in the source. */
  start: number;
  /** Offset just past the token's last character. */
  end: number;
}

interface Profile {
  slash: boolean;       // `//` line and `/* */` block comments
  hash: boolean;        // `#` line comments (not when preceded by `$`, as in `${#v}`)
  html: boolean;        // `<!-- -->` comments
  quotes: boolean;      // '…' and "…" are string literals (off for prose/markup, where a quote is just a quote)
  triple: boolean;      // '''…''' / """…""" strings
  template: boolean;    // `…${expr}…` template literals
  regex: boolean;       // /…/ literals, decided by the previous token
  privateName: boolean; // `#name` is an identifier
}

const NONE: Profile = { slash: false, hash: false, html: false, quotes: true, triple: false, template: false, regex: false, privateName: false };
const JS: Profile = { ...NONE, slash: true, template: true, regex: true, privateName: true };
const PROFILES: Record<Exclude<CodeLang, 'sql'>, Profile> = {
  js: JS,
  html: { ...JS, html: true },
  python: { ...NONE, hash: true, triple: true },
  hash: { ...NONE, hash: true },
  markup: { ...NONE, html: true, quotes: false },
  mixed: { ...NONE, slash: true, hash: true },
  none: NONE,
};

const EXT_LANG: Record<string, CodeLang> = {
  '.js': 'js', '.jsx': 'js', '.ts': 'js', '.tsx': 'js', '.mjs': 'js', '.cjs': 'js', '.mts': 'js', '.cts': 'js',
  // C-family languages share the comment/string shapes we care about.
  '.go': 'js', '.java': 'js', '.kt': 'js', '.kts': 'js', '.rs': 'js', '.cs': 'js', '.swift': 'js', '.dart': 'js',
  '.scala': 'js', '.groovy': 'js', '.gradle': 'js', '.php': 'js', '.c': 'js', '.h': 'js', '.cc': 'js', '.cpp': 'js',
  '.hpp': 'js', '.css': 'js', '.scss': 'js', '.less': 'js', '.jsonc': 'js', '.json5': 'js',
  '.vue': 'html', '.svelte': 'html', '.astro': 'html', '.html': 'html', '.htm': 'html',
  '.py': 'python', '.pyi': 'python', '.pyw': 'python',
  '.rb': 'hash', '.sh': 'hash', '.bash': 'hash', '.zsh': 'hash', '.fish': 'hash', '.yml': 'hash', '.yaml': 'hash',
  '.toml': 'hash', '.ini': 'hash', '.cfg': 'hash', '.conf': 'hash', '.env': 'hash', '.properties': 'hash',
  '.pl': 'hash', '.pm': 'hash', '.r': 'hash', '.ex': 'hash', '.exs': 'hash', '.nix': 'hash', '.tfvars': 'hash',
  '.sql': 'sql', '.psql': 'sql', '.pgsql': 'sql',
  '.xml': 'markup', '.plist': 'markup', '.svg': 'markup',
  // Prose keeps the legacy rules so `// easyvibegate-ignore` in a README still counts as a comment.
  '.md': 'mixed', '.mdx': 'mixed', '.txt': 'mixed',
  '.json': 'none', '.ipynb': 'none', '.csv': 'none', '.lock': 'none',
  '.pem': 'none', '.key': 'none', '.crt': 'none', '.cert': 'none', '.pkcs8': 'none',
};

const HASH_NAMES = new Set(['Dockerfile', 'Makefile', 'Gemfile', 'Procfile', '.gitignore', '.dockerignore', '.npmrc', '.yarnrc']);

/** Pick the lexing rules for a path. Unknown extensions get the legacy `mixed` rules. */
export function langForFile(rel: string): CodeLang {
  const base = rel.slice(Math.max(rel.lastIndexOf('/'), rel.lastIndexOf('\\')) + 1);
  if (base.startsWith('.env') || base.startsWith('docker-compose') || HASH_NAMES.has(base)) return 'hash';
  const dot = base.lastIndexOf('.');
  const ext = dot <= 0 ? '' : base.slice(dot).toLowerCase();
  return EXT_LANG[ext] ?? 'mixed';
}

const isIdentStart = (c: string) => /[A-Za-z_$-￿]/.test(c);
const isIdentPart = (c: string) => /[A-Za-z0-9_$-￿]/.test(c);
const isSpace = (c: string) => c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v';

/** After these words a `/` starts a regex literal, not a division. */
const REGEX_AFTER_WORD = new Set([
  'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'throw', 'case', 'do', 'else', 'yield', 'await',
]);

/** Tokenize `src` with the rules of `lang`. Offsets are absolute into `src`. */
export function lexCode(src: string, lang: CodeLang = 'mixed'): CodeToken[] {
  if (lang === 'sql') {
    // SQL already has a real lexer; only the token vocabulary differs.
    return lexSql(src).map((t) => ({
      type: t.type === 'comment' ? 'comment' : t.type === 'word' || t.type === 'punct' ? t.type : 'string',
      value: src.slice(t.start, t.end),
      start: t.start,
      end: t.end,
    }));
  }
  const out: CodeToken[] = [];
  lexInto(src, 0, PROFILES[lang], out, false);
  return out;
}

/**
 * Lex from `from` to the end, or — inside a template `${…}` — up to the `}`
 * that closes it, whose index is returned. Nested braces, strings, comments
 * and templates inside the expression are all handled by the same loop.
 */
function lexInto(src: string, from: number, p: Profile, out: CodeToken[], inTemplateExpr: boolean): number {
  const n = src.length;
  const push = (type: CodeTokenType, start: number, end: number) =>
    out.push({ type, value: src.slice(start, end), start, end });
  let depth = 0;
  let i = from;

  while (i < n) {
    const ch = src[i] as string;
    const next = src[i + 1];

    if (isSpace(ch)) { i++; continue; }

    if (inTemplateExpr) {
      if (ch === '{') depth++;
      else if (ch === '}') { if (depth === 0) return i; depth--; }
    }

    if (p.slash && ch === '/' && next === '/') {
      let j = i;
      while (j < n && src[j] !== '\n') j++;
      push('comment', i, j); i = j; continue;
    }
    if (p.slash && ch === '/' && next === '*') {
      const c = src.indexOf('*/', i + 2);
      const end = c === -1 ? n : c + 2;
      push('comment', i, end); i = end; continue;
    }
    if (p.hash && ch === '#' && src[i - 1] !== '$') {
      let j = i;
      while (j < n && src[j] !== '\n') j++;
      push('comment', i, j); i = j; continue;
    }
    if (p.html && ch === '<' && src.startsWith('<!--', i)) {
      const c = src.indexOf('-->', i + 4);
      const end = c === -1 ? n : c + 3;
      push('comment', i, end); i = end; continue;
    }

    if (p.quotes && (ch === '"' || ch === "'")) {
      if (p.triple && next === ch && src[i + 2] === ch) {
        // '''…''' spans lines; a backslash still escapes the next character.
        const q = ch + ch + ch;
        let j = i + 3;
        while (j < n && !src.startsWith(q, j)) j += src[j] === '\\' ? 2 : 1;
        const end = Math.min(j + 3, n);
        push('string', i, end); i = end; continue;
      }
      // One-line string. An unterminated one ends at the newline so damage from
      // a stray quote (JSX text, prose) never spreads past its own line.
      let j = i + 1;
      while (j < n && src[j] !== ch && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
      const end = Math.min(src[j] === ch ? j + 1 : j, n);
      push('string', i, end); i = end; continue;
    }

    if (p.template && ch === '`') {
      let chunk = i;
      let j = i + 1;
      while (j < n) {
        const c = src[j] as string;
        if (c === '\\') { j += 2; continue; }
        if (c === '`') { j++; break; }
        if (c === '$' && src[j + 1] === '{') {
          push('template', chunk, j + 2);
          // The expression is code again: lex it in place, resume after its `}`.
          const close = lexInto(src, j + 2, p, out, true);
          chunk = close;
          j = close + 1;
          continue;
        }
        j++;
      }
      const end = Math.min(j, n);
      if (end > chunk) push('template', chunk, end);
      i = end; continue;
    }

    if (p.regex && ch === '/' && regexAllowed(out)) {
      const end = scanRegex(src, i);
      if (end !== -1) { push('regex', i, end); i = end; continue; }
    }

    if (isIdentStart(ch) || (p.privateName && ch === '#' && next !== undefined && isIdentStart(next))) {
      let j = i + 1;
      while (j < n && isIdentPart(src[j] as string)) j++;
      push('word', i, j); i = j; continue;
    }
    if (ch >= '0' && ch <= '9') {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_.]/.test(src[j] as string)) j++;
      push('word', i, j); i = j; continue;
    }

    push('punct', i, i + 1);
    i++;
  }
  return n;
}

/** A `/` after a value (identifier, number, `)`, `]`, `}`) divides; elsewhere it opens a regex. */
function regexAllowed(out: CodeToken[]): boolean {
  let k = out.length - 1;
  while (k >= 0 && out[k]?.type === 'comment') k--;
  const prev = out[k];
  if (!prev) return true;
  if (prev.type === 'punct') return !')]}'.includes(prev.value);
  if (prev.type === 'word') return REGEX_AFTER_WORD.has(prev.value);
  return false;
}

/** End offset of a regex literal starting at `i`, or -1 if the line ends first (so it was a division). */
function scanRegex(src: string, i: number): number {
  let j = i + 1;
  let inClass = false;
  while (j < src.length) {
    const c = src[j] as string;
    if (c === '\n') return -1;
    if (c === '\\') { j += 2; continue; }
    if (inClass) { if (c === ']') inClass = false; }
    else if (c === '[') inClass = true;
    else if (c === '/') {
      j++;
      while (j < src.length && /[a-z]/i.test(src[j] as string)) j++;
      return j;
    }
    j++;
  }
  return -1;
}
