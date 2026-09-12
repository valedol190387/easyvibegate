/**
 * A small SQL lexer.
 *
 * Why this exists: the RLS checker used to look for statements with regexes run
 * over a "masked" copy of the file, where comments and strings had been blanked
 * out by a second, separate scanner. Every syntax corner that the masker got
 * wrong became a silently missed (or invented) statement — `E'it\'s'`, nested
 * block comments, `$tag$` bodies, a column alias in double quotes that happens
 * to contain SQL keywords. Approximating a real grammar with regexes has no end.
 *
 * Lexing once, here, makes that whole family of bugs impossible by construction:
 * a string is a token, a comment is a token, a quoted identifier is a token, and
 * none of them can ever be read as executable keywords.
 */

export type SqlTokenType =
  | 'word'          // keyword or unquoted identifier
  | 'quotedIdent'   // "..."  — a name, never executable text
  | 'string'        // '...' or E'...'
  | 'dollarString'  // $$...$$ / $tag$...$tag$ (value is the BODY, without tags)
  | 'comment'       // -- ... or /* ... */ (nesting aware)
  | 'punct';        // any single other character

export interface SqlToken {
  type: SqlTokenType;
  /** For quotedIdent/string/dollarString: the contents, unquoted. Else the raw text. */
  value: string;
  /** Offset of the token's first character in the original SQL. */
  start: number;
  /** Offset just past the token's last character. */
  end: number;
  /**
   * string / dollarString: where the contents start, for re-lexing a DO block
   * in place. `DO 'BEGIN … END'` is as executable as `DO $$ … $$`.
   */
  bodyStart?: number;
}

const isIdentStart = (c: string) => /[A-Za-z_-￿]/.test(c);
const isIdentPart = (c: string) => /[A-Za-z0-9_$-￿]/.test(c);

/** Read a `$tag$` opener at `i`, or null if this `$` is not a dollar-quote. */
function dollarTagAt(sql: string, i: number): string | null {
  if (sql[i] !== '$') return null;
  let j = i + 1;
  while (j < sql.length && sql[j] !== '$') {
    const c = sql[j] as string;
    // A tag is an identifier; `$1` (a bind parameter) is not a dollar-quote.
    if (!(j === i + 1 ? isIdentStart(c) : isIdentPart(c))) return null;
    j++;
  }
  return j < sql.length ? sql.slice(i, j + 1) : null;
}

/** Tokenize `sql`. Offsets are absolute; add `offset` when lexing a fragment. */
export function lexSql(sql: string, offset = 0): SqlToken[] {
  const out: SqlToken[] = [];
  const n = sql.length;
  let i = 0;

  while (i < n) {
    const ch = sql[i] as string;

    if (/\s/.test(ch)) { i++; continue; }

    // -- line comment
    if (ch === '-' && sql[i + 1] === '-') {
      let j = i;
      while (j < n && sql[j] !== '\n') j++;
      out.push({ type: 'comment', value: sql.slice(i, j), start: offset + i, end: offset + j });
      i = j; continue;
    }

    // /* block comment */ — PostgreSQL nests these.
    if (ch === '/' && sql[i + 1] === '*') {
      let depth = 0;
      let j = i;
      while (j < n) {
        if (sql[j] === '/' && sql[j + 1] === '*') { depth++; j += 2; continue; }
        if (sql[j] === '*' && sql[j + 1] === '/') { depth--; j += 2; if (depth === 0) break; continue; }
        j++;
      }
      const end = depth === 0 ? j : n;
      out.push({ type: 'comment', value: sql.slice(i, end), start: offset + i, end: offset + end });
      i = end; continue;
    }

    // '...' string. Doubling ('') always escapes; a backslash escapes only in an
    // E'' string, where PostgreSQL enables C-style escapes.
    if (ch === "'") {
      const prev = out[out.length - 1];
      const eString =
        !!prev && prev.type === 'word' && /^e$/i.test(prev.value) && prev.end === offset + i;
      let j = i + 1;
      while (j < n) {
        if (eString && sql[j] === '\\') { j += 2; continue; }
        if (sql[j] === "'") {
          if (sql[j + 1] === "'") { j += 2; continue; }
          break;
        }
        j++;
      }
      const end = Math.min(j + 1, n);
      out.push({
        type: 'string',
        value: sql.slice(i + 1, Math.max(i + 1, j)),
        start: offset + i,
        end: offset + end,
        bodyStart: offset + i + 1,
      });
      i = end; continue;
    }

    // "..." quoted identifier. Its contents are a NAME, never statements.
    if (ch === '"') {
      let j = i + 1;
      while (j < n) {
        if (sql[j] === '"') {
          if (sql[j + 1] === '"') { j += 2; continue; }
          break;
        }
        j++;
      }
      const end = Math.min(j + 1, n);
      out.push({
        type: 'quotedIdent',
        value: sql.slice(i + 1, Math.max(i + 1, j)).replace(/""/g, '"'),
        start: offset + i,
        end: offset + end,
      });
      i = end; continue;
    }

    // $tag$ ... $tag$
    const tag = dollarTagAt(sql, i);
    if (tag) {
      const bodyStart = i + tag.length;
      const close = sql.indexOf(tag, bodyStart);
      const bodyEnd = close === -1 ? n : close;
      const end = close === -1 ? n : close + tag.length;
      out.push({
        type: 'dollarString',
        value: sql.slice(bodyStart, bodyEnd),
        start: offset + i,
        end: offset + end,
        bodyStart: offset + bodyStart,
      });
      i = end; continue;
    }

    // word / unquoted identifier
    if (isIdentStart(ch)) {
      let j = i + 1;
      while (j < n && isIdentPart(sql[j] as string)) j++;
      out.push({ type: 'word', value: sql.slice(i, j), start: offset + i, end: offset + j });
      i = j; continue;
    }

    // number — lexed as a word so it can never be mistaken for a keyword
    if (/[0-9]/.test(ch)) {
      let j = i + 1;
      while (j < n && /[0-9.]/.test(sql[j] as string)) j++;
      out.push({ type: 'word', value: sql.slice(i, j), start: offset + i, end: offset + j });
      i = j; continue;
    }

    out.push({ type: 'punct', value: ch, start: offset + i, end: offset + i + 1 });
    i++;
  }

  return out;
}

/** Tokens that carry executable SQL: comments and literals are dropped. */
export function codeTokens(tokens: SqlToken[]): SqlToken[] {
  return tokens.filter((t) => t.type !== 'comment');
}
