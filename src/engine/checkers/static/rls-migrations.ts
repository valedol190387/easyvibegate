import type { Checker, Finding } from '../../types.js';
import { lineAt } from '../../util/text.js';

import { lexSql, type SqlToken } from '../../util/sql-lex.js';

/** Normalize one SQL identifier: quoted keeps case, unquoted folds to lowercase. */
function normIdent(raw: string, quoted: boolean): string {
  return quoted ? raw : raw.toLowerCase();
}

interface Name { text: string; quoted: boolean }

/**
 * A table key is `schema NUL table`. Joining with `.` let `public."a.b"` and
 * `"public.a".b` collide into one string; NUL can never occur in an identifier.
 */
const SEP = '\u0000';
/**
 * Session-private namespace. PostgreSQL looks in pg_temp FIRST for an existing
 * table, so after `CREATE TEMP TABLE orders` an unqualified `DROP TABLE orders`
 * removes the temp one and leaves the permanent `public.orders` — and its RLS
 * state — untouched. Temp tables are modelled for that shadowing only; they are
 * never reported (PostgREST cannot see them).
 */
const TEMP_SCHEMA = 'pg_temp';
const keyFor = (schema: string, table: string) => `${schema}${SEP}${table}`;
const isTempKey = (key: string) => key.startsWith(TEMP_SCHEMA + SEP);

interface Event {
  kind: 'create' | 'enable' | 'disable' | 'drop' | 'rename';
  key: string;
  /** rename only: the key the table's state moves to (`RENAME TO`, `SET SCHEMA`). */
  toKey?: string;
  toDisplay?: string;
  ifNotExists: boolean;
  file: string;
  line: number;
  display: string;
  fileIdx: number;
  offset: number;
  /**
   * May never execute, or may be undone: inside IF/LOOP/CASE, in a block with
   * an EXCEPTION section, after a RETURN, inside a rolled-back transaction, or
   * aimed at a name a guarded TEMP table may shadow.
   */
  conditional: boolean;
}

/**
 * Statement extraction over TOKENS, not over text.
 *
 * Everything this used to get wrong — `E'it\'s'`, `'end if'` in a string, a
 * column alias like `"ALTER TABLE x ENABLE ROW LEVEL SECURITY"`, nested block
 * comments, `$tag$` bodies — is now impossible rather than patched: the lexer
 * has already decided what is a string, a comment and a name, and only `word`
 * tokens can ever be keywords.
 */
interface Unparsed { offset: number; why: string }
type StmtEvent = Omit<Event, 'file' | 'fileIdx' | 'line'>;
interface Stmt { events: StmtEvent[]; unparsed: Unparsed[] }

const isWord = (t: SqlToken | undefined, w: string) => !!t && t.type === 'word' && t.value.toUpperCase() === w;
const isWordIn = (t: SqlToken | undefined, ws: string[]) => !!t && t.type === 'word' && ws.includes(t.value.toUpperCase());
const isPunct = (t: SqlToken | undefined, p: string) => !!t && t.type === 'punct' && t.value === p;
const isName = (t: SqlToken | undefined) => !!t && (t.type === 'word' || t.type === 'quotedIdent');
const isLiteral = (t: SqlToken | undefined) => !!t && (t.type === 'string' || t.type === 'dollarString');
const nameOf = (t: SqlToken): Name => ({ text: t.value, quoted: t.type === 'quotedIdent' });

/** Read `[schema .] table` at `i`; returns the names and the index after them. */
function readQualified(ts: SqlToken[], i: number): { schema?: Name; table: Name; next: number } | null {
  const first = ts[i];
  if (!isName(first)) return null;
  const dot = ts[i + 1];
  const second = ts[i + 2];
  if (dot && dot.type === 'punct' && dot.value === '.' && isName(second)) {
    return { schema: nameOf(first as SqlToken), table: nameOf(second as SqlToken), next: i + 3 };
  }
  return { table: nameOf(first as SqlToken), next: i + 1 };
}

/** Skip an optional `IF EXISTS` / `IF NOT EXISTS`; returns [nextIndex, seen]. */
function skipIfExists(ts: SqlToken[], i: number): [number, boolean] {
  if (!isWord(ts[i], 'IF')) return [i, false];
  if (isWord(ts[i + 1], 'NOT') && isWord(ts[i + 2], 'EXISTS')) return [i + 3, true];
  if (isWord(ts[i + 1], 'EXISTS')) return [i + 2, true];
  return [i, false];
}

/**
 * Token spans inside a DO body whose statements are not known to take effect.
 * No interpreter is needed to know that a branch may not be taken, a loop may
 * run zero times, nothing after `RETURN` in the same block runs, and a block
 * with an `EXCEPTION` section is rolled back entirely if the handler fires.
 * Constructs nest, so they are matched with a stack. Returns index ranges.
 */
function guardedRanges(ts: SqlToken[]): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  interface Frame { kind: 'IF' | 'LOOP' | 'CASE' | 'BEGIN'; at: number; returnAt?: number; exception?: boolean }
  const stack: Frame[] = [];
  const close = (f: Frame, i: number) => {
    // A plain BEGIN block is straight-line code; only an EXCEPTION section
    // turns its whole body (and the handlers) into a maybe.
    if (f.kind !== 'BEGIN' || f.exception) ranges.push([f.at, i]);
    if (f.returnAt !== undefined) ranges.push([f.returnAt, i]);
  };
  for (let i = 0; i < ts.length; i++) {
    const t = ts[i];
    if (!t || t.type !== 'word') continue;
    const W = t.value.toUpperCase();
    if (W === 'END') {
      // `END IF` / `END LOOP` / `END CASE` name what they close; a bare END
      // closes the innermost BEGIN block or CASE expression.
      const f = stack.pop();
      if (f) close(f, i);
      if (isWordIn(ts[i + 1], ['IF', 'LOOP', 'CASE'])) i++;
      continue;
    }
    if (W === 'IF') {
      // `IF EXISTS` / `IF NOT EXISTS` is a DDL clause, not a branch — reading it
      // as one would leave a guard open to the end of the body.
      if (isWord(ts[i + 1], 'EXISTS') || (isWord(ts[i + 1], 'NOT') && isWord(ts[i + 2], 'EXISTS'))) continue;
      stack.push({ kind: 'IF', at: i });
      continue;
    }
    if (W === 'LOOP' || W === 'CASE' || W === 'BEGIN') { stack.push({ kind: W, at: i }); continue; }
    if (W === 'EXCEPTION' && !isWord(ts[i - 1], 'RAISE')) {
      // The section belongs to the innermost BEGIN block, not to an IF inside it.
      for (let d = stack.length - 1; d >= 0; d--) {
        const f = stack[d];
        if (f && f.kind === 'BEGIN') { f.exception = true; break; }
      }
      continue;
    }
    if (W === 'RETURN') {
      const f = stack[stack.length - 1];
      if (f && f.returnAt === undefined) f.returnAt = i;
    }
  }
  while (stack.length) close(stack.pop() as Frame, ts.length);
  return ranges;
}

/**
 * Flatten a file into tokens, splicing every `DO … ` body in place so its DDL
 * is analyzed as executed code while the surrounding file keeps its own order.
 * Returns the tokens plus the guarded index ranges.
 */
function flatten(sql: string): { ts: SqlToken[]; guards: Array<[number, number]>; bodies: Array<[number, number]> } {
  const top = lexSql(sql).filter((t) => t.type !== 'comment');
  const ts: SqlToken[] = [];
  const guards: Array<[number, number]> = [];
  /** Token index ranges that came from a DO body — plpgsql, not plain SQL. */
  const bodies: Array<[number, number]> = [];
  for (let i = 0; i < top.length; i++) {
    const t = top[i] as SqlToken;
    // A DO body is executed procedural code whether it is dollar-quoted or a
    // plain `'…'` literal: lex it and inline it. `DO $$…$$`, `DO 'BEGIN … END'`,
    // `DO LANGUAGE plpgsql $$…$$` — the language clause may come first.
    const beforeBody = isWord(top[i - 2], 'LANGUAGE') && top[i - 1]?.type === 'word' ? i - 3 : i - 1;
    if (isLiteral(t) && isWord(top[beforeBody], 'DO')) {
      // In a plain literal a quote is written doubled; undo that so the body
      // lexes as the SQL PostgreSQL will actually run.
      const body = t.type === 'string' ? t.value.replace(/''/g, "'") : t.value;
      const inner = lexSql(body, t.bodyStart ?? t.start).filter((x) => x.type !== 'comment');
      const base = ts.length;
      for (const [a, b] of guardedRanges(inner)) guards.push([base + a, base + b]);
      ts.push(...inner);
      bodies.push([base, ts.length]);
      continue;
    }
    ts.push(t);
  }
  return { ts, guards, bodies };
}

/**
 * Text in a dynamic-SQL literal that can change what this checker models: a
 * table's existence, its RLS state, its name, or how unqualified names resolve.
 */
const STATE_TEXT = /row\s+level\s+security|create\s+(?:\w+\s+)*table\b|drop\s+table\b|alter\s+table\b|search_path/i;

/**
 * Extract CREATE / ENABLE / DISABLE / DROP / RENAME / SELECT INTO events from
 * one file, statement by statement. Anything that could change a table's
 * existence, name or RLS state and is NOT understood is returned in `unparsed`
 * — it must surface as partial coverage, never vanish into a `continue`.
 */
function readStatements(sql: string): Stmt {
  const { ts, guards, bodies } = flatten(sql);
  const events: StmtEvent[] = [];
  const unparsed: Unparsed[] = [];
  const guarded = (i: number) => guards.some(([a, b]) => i >= a && i < b);
  const inBody = (i: number) => bodies.some(([a, b]) => i >= a && i < b);
  // Inside plpgsql, `BEGIN ALTER TABLE …` and `IF x THEN ALTER TABLE …` are one
  // `;`-terminated run whose real statement starts after the structure word.
  // Only inside DO bodies: plain SQL uses THEN/ELSE/END in CASE expressions.
  const PLPGSQL_BOUNDARY = ['BEGIN', 'DECLARE', 'THEN', 'ELSE', 'ELSIF', 'LOOP', 'END'];
  const isBoundary = (i: number) => isPunct(ts[i], ';') || (inBody(i) && isWordIn(ts[i], PLPGSQL_BOUNDARY));
  const mentionsWord = (from: number, to: number, w: string) => {
    for (let m = from; m < to; m++) if (isWord(ts[m], w)) return true;
    return false;
  };

  // --- Name resolution ------------------------------------------------------
  // An unqualified name resolves to the first schema of search_path: `public`
  // until a `SET search_path` earlier in this file says otherwise. SET LOCAL
  // lasts to the end of the transaction. Two `orders` tables in different
  // schemas used to merge into one state because everything resolved to public.
  // An EMPTY search_path (`SET search_path = ''`, what `pg_dump` emits) is a
  // known state too: every name must then be qualified, so an unqualified one
  // cannot be resolved and is reported rather than guessed.
  let sessionSchema = 'public';
  let localSchema: string | null = null;
  const currentSchema = () => localSchema ?? sessionSchema;
  /** TEMP tables created so far in this file: normalized name → created under a guard. */
  const tempTables = new Map<string, boolean>();

  interface Resolved { key: string; schema: string; table: string; display: string; shadowed: boolean }
  const resolve = (q: { schema?: Name; table: Name }, at: number, opts: { forCreate?: boolean; temp?: boolean } = {}): Resolved => {
    const table = normIdent(q.table.text, q.table.quoted);
    if (q.schema) {
      const schema = normIdent(q.schema.text, q.schema.quoted);
      return { key: keyFor(schema, table), schema, table, display: `${q.schema.text}.${q.table.text}`, shadowed: false };
    }
    if (opts.temp) return { key: keyFor(TEMP_SCHEMA, table), schema: TEMP_SCHEMA, table, display: q.table.text, shadowed: false };
    // An existing temp table shadows the permanent one for DROP/ALTER (CREATE
    // always targets the search_path schema). If the temp CREATE itself was
    // guarded, which table this statement hits cannot be known.
    const tempGuarded = tempTables.get(table);
    if (!opts.forCreate && tempGuarded === false) {
      return { key: keyFor(TEMP_SCHEMA, table), schema: TEMP_SCHEMA, table, display: q.table.text, shadowed: false };
    }
    const schema = currentSchema();
    if (schema === '') unparsed.push({ offset: at, why: `unqualified table name "${q.table.text}" with an empty search_path cannot be resolved to a schema` });
    const display = schema === 'public' ? q.table.text : `${schema}.${q.table.text}`;
    return { key: keyFor(schema, table), schema, table, display, shadowed: tempGuarded === true };
  };
  const add = (kind: Event['kind'], r: Resolved, at: number, idx: number, extra: Partial<StmtEvent> = {}) => {
    events.push({
      kind, key: r.key, ifNotExists: false, display: r.display, offset: at,
      conditional: guarded(idx) || r.shadowed, ...extra,
    });
  };
  const noteTemp = (r: Resolved, idx: number) => { if (isTempKey(r.key)) tempTables.set(r.table, guarded(idx)); };

  // --- Transactions ---------------------------------------------------------
  // Top-level `BEGIN … ROLLBACK` undoes every statement in between; a
  // transaction still open at end of file is committed by some runners and
  // rolled back by others (psql). Either way those statements are "unconfirmed",
  // not a confident PASS and not a confident critical.
  let txStart: number | null = null; // index into `events`
  const savepoints = new Map<string, number>();
  const undoSince = (i: number) => { for (let m = i; m < events.length; m++) (events[m] as StmtEvent).conditional = true; };
  const endTx = () => { txStart = null; savepoints.clear(); localSchema = null; };

  /**
   * Adopt a new search_path given as its schema list (`''` entries are what
   * `SET search_path = ''` leaves: an empty path). `"$user"` depends on the
   * connecting role and a leading pg_temp would make every unqualified CREATE
   * a temp table — neither is decidable here, so those become partial.
   */
  const setSearchPath = (names: string[], local: boolean, at: number, why: string): void => {
    const first = names.map((n) => n.trim()).filter((n) => n !== '')[0] ?? '';
    if (first.startsWith('$') || first === TEMP_SCHEMA) { unparsed.push({ offset: at, why }); return; }
    if (local) localSchema = first; else sessionSchema = first;
  };

  /** `SET [LOCAL|SESSION] search_path {TO|=} a [, b …]`. Anything fancier → partial. */
  const applySearchPath = (from: number, to: number) => {
    const at = (ts[from] as SqlToken).start;
    const why = 'SET search_path in a form the analyzer cannot follow; unqualified table names can no longer be resolved';
    const bail = () => unparsed.push({ offset: at, why });
    let j = from + 1;
    const local = isWord(ts[j], 'LOCAL');
    if (local || isWord(ts[j], 'SESSION')) j++;
    j++; // search_path
    if (!(isWord(ts[j], 'TO') || isPunct(ts[j], '='))) return bail();
    j++;
    const names: string[] = [];
    if (isWord(ts[j], 'DEFAULT') && j + 1 === to) names.push('public');
    else {
      for (;;) {
        const t = ts[j];
        if (isName(t)) names.push(normIdent((t as SqlToken).value, (t as SqlToken).type === 'quotedIdent'));
        // `'a, b'` as one literal is a whole list PostgreSQL would split; do not guess it.
        else if (t && t.type === 'string' && !t.value.includes(',')) names.push(t.value);
        else return bail();
        j++;
        if (j >= to) break;
        if (!isPunct(ts[j], ',')) return bail();
        j++;
      }
    }
    setSearchPath(names, local, at, why);
  };

  /**
   * `[SELECT] [pg_catalog.]set_config('search_path', '<list>', is_local)` — the
   * form `pg_dump` emits. A literal list is followed like SET; any other value
   * expression is unknown → partial.
   */
  const applySetConfig = (from: number, to: number) => {
    const at = (ts[from] as SqlToken).start;
    const why = 'search_path changed via set_config(); unqualified table names can no longer be resolved';
    let m = from;
    while (m < to && !isWord(ts[m], 'SET_CONFIG')) m++;
    const [open, key, comma, val, comma2, flag, close] = ts.slice(m + 1, m + 8);
    const literal = isPunct(open, '(') && key?.type === 'string' && isPunct(comma, ',') && val?.type === 'string' && isPunct(comma2, ',')
      && isWordIn(flag, ['TRUE', 'FALSE']) && isPunct(close, ')');
    if (!literal || !val) return unparsed.push({ offset: at, why });
    // Only the list is unquoted and split; a quoted entry inside it is left as
    // written, the same way `SET search_path TO "App"` keeps case.
    const names = val.value.split(',').map((n) => n.trim()).map((n) => (n.startsWith('"') && n.endsWith('"') ? n.slice(1, -1) : n.toLowerCase()));
    setSearchPath(names, isWord(flag, 'TRUE'), at, why);
  };

  /** ENABLE|DISABLE ROW LEVEL SECURITY at `m`? Returns the verb or null. */
  const rlsVerbAt = (m: number): 'enable' | 'disable' | null => {
    const v = ts[m];
    if (!v || v.type !== 'word') return null;
    const V = v.value.toUpperCase();
    if (V !== 'ENABLE' && V !== 'DISABLE') return null;
    return isWord(ts[m + 1], 'ROW') && isWord(ts[m + 2], 'LEVEL') && isWord(ts[m + 3], 'SECURITY') ? (V === 'DISABLE' ? 'disable' : 'enable') : null;
  };
  const mentionsRls = (from: number, to: number) => {
    for (let m = from; m + 2 < to; m++) if (isWord(ts[m], 'ROW') && isWord(ts[m + 1], 'LEVEL') && isWord(ts[m + 2], 'SECURITY')) return true;
    return false;
  };
  /** `set_config('search_path', …)` anywhere in the statement. */
  const callsSetConfigSearchPath = (from: number, to: number) => {
    if (!mentionsWord(from, to, 'SET_CONFIG')) return false;
    for (let m = from; m < to; m++) {
      const t = ts[m] as SqlToken;
      if (t.type === 'string' && t.value.trim().toLowerCase() === 'search_path') return true;
    }
    return false;
  };

  const interpret = (from: number, to: number) => {
    const first = ts[from] as SqlToken;
    const w = first.type === 'word' ? first.value.toUpperCase() : '';
    const body = inBody(from);

    // From here on unqualified names resolve differently — or, inside a DO
    // block whose control flow is not followed, unknowably.
    if (callsSetConfigSearchPath(from, to)) {
      if (body) return unparsed.push({ offset: first.start, why: 'search_path changed via set_config() inside a DO block; unqualified table names can no longer be resolved' });
      return applySetConfig(from, to);
    }

    if (w === 'SET') {
      if (!mentionsWord(from, to, 'SEARCH_PATH')) return; // other GUCs do not affect the model
      if (body) return unparsed.push({ offset: first.start, why: 'SET search_path inside a DO block; unqualified table names can no longer be resolved' });
      return applySearchPath(from, to);
    }
    if (w === 'RESET' && !body) {
      if (isWordIn(ts[from + 1], ['SEARCH_PATH', 'ALL'])) { sessionSchema = 'public'; localSchema = null; }
      return;
    }

    if (!body) {
      if (w === 'BEGIN' || (w === 'START' && isWord(ts[from + 1], 'TRANSACTION'))) { if (txStart === null) txStart = events.length; return; }
      if (w === 'COMMIT' || w === 'END') { endTx(); return; } // top-level END is COMMIT
      if (w === 'SAVEPOINT' && isName(ts[from + 1])) { const n = ts[from + 1] as SqlToken; savepoints.set(normIdent(n.value, n.type === 'quotedIdent'), events.length); return; }
      if (w === 'ROLLBACK' || w === 'ABORT') {
        if (isWord(ts[from + 1], 'TO')) {
          // ROLLBACK TO [SAVEPOINT] name keeps the transaction open; only the
          // work after the savepoint is undone. Unknown savepoint → undo all.
          let j = from + 2;
          if (isWord(ts[j], 'SAVEPOINT')) j++;
          const n = ts[j];
          const at = isName(n) ? savepoints.get(normIdent((n as SqlToken).value, (n as SqlToken).type === 'quotedIdent')) : undefined;
          undoSince(at ?? txStart ?? events.length);
          return;
        }
        undoSince(txStart ?? events.length);
        endTx();
        return;
      }
    }

    if (w === 'CREATE') {
      let j = from + 1;
      let temp = false;
      while (isWordIn(ts[j], ['UNLOGGED', 'TEMP', 'TEMPORARY', 'GLOBAL', 'LOCAL'])) {
        if (/^TEMP/i.test((ts[j] as SqlToken).value)) temp = true;
        j++;
      }
      if (!isWord(ts[j], 'TABLE')) return dynamic(from, to); // CREATE INDEX/POLICY/… — not a table
      const [k, ine] = skipIfExists(ts, j + 1);
      const q = readQualified(ts, k);
      if (!q) return unparsed.push({ offset: first.start, why: 'CREATE TABLE with a table name the analyzer cannot read' });
      const r = resolve(q, first.start, { forCreate: true, temp });
      noteTemp(r, from);
      add('create', r, first.start, from, { ifNotExists: ine });
      return;
    }

    if (w === 'DROP' && isWord(ts[from + 1], 'TABLE')) {
      let [k] = skipIfExists(ts, from + 2);
      // DROP TABLE takes a list: every name in it is gone, not only the first.
      for (;;) {
        const q = readQualified(ts, k);
        if (!q) return unparsed.push({ offset: first.start, why: 'DROP TABLE with a table name the analyzer cannot read' });
        const r = resolve(q, first.start);
        add('drop', r, first.start, from);
        if (isTempKey(r.key) && !guarded(from)) tempTables.delete(r.table);
        k = q.next;
        if (!isPunct(ts[k], ',')) break;
        k++;
      }
      while (isWordIn(ts[k], ['CASCADE', 'RESTRICT'])) k++;
      if (k < to) unparsed.push({ offset: first.start, why: 'DROP TABLE has a trailing clause the analyzer cannot read' });
      return;
    }

    if (w === 'ALTER' && isWord(ts[from + 1], 'TABLE')) {
      // ALTER TABLE [IF EXISTS] [ONLY] name [*] action [, action ...]
      let [j] = skipIfExists(ts, from + 2);
      if (isWord(ts[j], 'ONLY')) j++;
      const q = readQualified(ts, j);
      if (!q) return unparsed.push({ offset: first.start, why: 'ALTER TABLE with a table name the analyzer cannot read' });
      const r = resolve(q, first.start);
      let k = q.next;
      if (isPunct(ts[k], '*')) k++;
      // RENAME TO / SET SCHEMA move the table's identity. The state must follow
      // it, or a later DISABLE under the new name is never matched to the table.
      if (isWord(ts[k], 'RENAME') && isWord(ts[k + 1], 'TO')) {
        const nq = readQualified(ts, k + 2);
        if (!nq || nq.schema || nq.next !== to) return unparsed.push({ offset: first.start, why: 'ALTER TABLE RENAME TO with a name the analyzer cannot read' });
        const table = normIdent(nq.table.text, nq.table.quoted);
        const toDisplay = r.schema === 'public' || r.schema === TEMP_SCHEMA ? nq.table.text : `${r.schema}.${nq.table.text}`;
        add('rename', r, first.start, from, { toKey: keyFor(r.schema, table), toDisplay });
        if (isTempKey(r.key) && !guarded(from)) { tempTables.delete(r.table); tempTables.set(table, false); }
        return;
      }
      if (isWord(ts[k], 'SET') && isWord(ts[k + 1], 'SCHEMA')) {
        const s = ts[k + 2];
        if (!isName(s) || k + 3 !== to) return unparsed.push({ offset: first.start, why: 'ALTER TABLE SET SCHEMA with a name the analyzer cannot read' });
        const schema = normIdent((s as SqlToken).value, (s as SqlToken).type === 'quotedIdent');
        add('rename', r, first.start, from, { toKey: keyFor(schema, r.table), toDisplay: `${(s as SqlToken).value}.${q.table.text}` });
        return;
      }
      // Actions are comma-separated; an RLS toggle may be any of them, so scan
      // the whole statement rather than only the first action.
      let handled = false;
      for (let m = k; m < to; m++) {
        const verb = rlsVerbAt(m);
        if (verb) { add(verb, r, first.start, from); handled = true; m += 3; continue; }
        // FORCE / NO FORCE ROW LEVEL SECURITY change owner bypass, not whether RLS is on.
        if (isWord(ts[m], 'FORCE') && isWord(ts[m + 1], 'ROW')) { handled = true; m += 3; }
      }
      if (!handled && mentionsRls(k, to)) {
        unparsed.push({ offset: first.start, why: 'ALTER TABLE mentions ROW LEVEL SECURITY in a form the analyzer does not understand' });
      }
      return;
    }

    // A role- or database-level default applies to every LATER session, i.e.
    // to the migrations that follow this one.
    if (w === 'ALTER' && isWordIn(ts[from + 1], ['ROLE', 'USER', 'DATABASE']) && mentionsWord(from, to, 'SEARCH_PATH')) {
      return unparsed.push({ offset: first.start, why: 'ALTER ROLE/DATABASE … SET search_path changes name resolution for later migrations; unqualified table names can no longer be resolved' });
    }

    if (w === 'SELECT') {
      // Top-level `SELECT … INTO <table>` creates a table. Inside plpgsql the
      // same syntax is ALWAYS a variable assignment (a table is made with
      // CREATE TABLE AS), so there it must not be read as a table.
      if (body) return;
      for (let m = from + 1; m < to; m++) {
        const u = ts[m] as SqlToken;
        if (isWord(u, 'FROM')) break;
        if (isWord(u, 'INTO')) {
          let n = m + 1;
          let temp = false;
          while (isWordIn(ts[n], ['TEMP', 'TEMPORARY', 'UNLOGGED', 'TABLE'])) {
            if (/^TEMP/i.test((ts[n] as SqlToken).value)) temp = true;
            n++;
          }
          const q = readQualified(ts, n);
          if (q) { const r = resolve(q, first.start, { forCreate: true, temp }); noteTemp(r, from); add('create', r, first.start, from); }
          break;
        }
      }
      return;
    }

    return dynamic(from, to);
  };

  /**
   * Dynamic SQL — `EXECUTE 'ALTER TABLE …'`, `EXECUTE cmd`, `EXECUTE format(…)`
   * — builds the statement at run time. A single literal can at least be read
   * and is flagged only when it talks about tables, RLS or search_path. A
   * variable, a `||` concatenation or a function call is unknown by
   * construction: whatever it does to table/RLS state cannot be known here, so
   * it is always missing coverage.
   */
  const dynamic = (from: number, to: number) => {
    // Only a leading EXECUTE (or `FOR … IN EXECUTE`) runs SQL; `CREATE TRIGGER
    // … EXECUTE FUNCTION f()` merely names a function.
    let ex = -1;
    for (let m = from; m < to; m++) {
      if (isWord(ts[m], 'EXECUTE') && (m === from || isWord(ts[m - 1], 'IN')) && !isWordIn(ts[m + 1], ['FUNCTION', 'PROCEDURE'])) { ex = m; break; }
    }
    if (ex === -1) return;
    let end = to;
    for (let m = ex + 1; m < to; m++) if (isWordIn(ts[m], ['INTO', 'USING'])) { end = m; break; }
    const arg = ts.slice(ex + 1, end);
    const one = arg[0];
    if (arg.length === 1 && one && isLiteral(one)) {
      if (STATE_TEXT.test(one.value)) unparsed.push({ offset: one.start, why: 'dynamic SQL (EXECUTE with a string) changes table/RLS state and cannot be interpreted statically' });
      return;
    }
    // Top-level EXECUTE runs a PREPAREd statement, which cannot be DDL.
    if (!inBody(ex)) return;
    // Joining the literal pieces of `'ALTER TABLE x DISABLE ROW ' || 'LEVEL
    // SECURITY'` only sharpens the message; the verdict is the same.
    const pieces = arg.filter(isLiteral).map((t) => t.value).join('');
    unparsed.push({
      offset: (ts[ex] as SqlToken).start,
      why: STATE_TEXT.test(pieces)
        ? 'dynamic SQL (EXECUTE with a run-time built string that mentions tables/RLS) cannot be interpreted statically'
        : 'dynamic SQL (EXECUTE with a variable or expression) has an effect on table/RLS state that cannot be known statically',
    });
  };

  // Split into statements and interpret each one.
  let s = 0;
  for (let i = 0; i <= ts.length; i++) {
    if (i === ts.length || isBoundary(i)) {
      if (i > s) interpret(s, i);
      s = i + 1;
    }
  }
  // Left open at end of file: committed or rolled back depending on the runner.
  if (txStart !== null) undoSince(txStart);
  return { events, unparsed };
}

/**
 * Flags each table whose latest state after replaying the migrations is
 * "created and RLS not enabled". Migrations are replayed in apply order
 * (files by name, statements by offset); CREATE / ENABLE / DISABLE / DROP /
 * RENAME are all modeled; CREATE IF NOT EXISTS on an existing table is a
 * no-op; comments and string literals are ignored; quoted and schema-qualified
 * names work.
 */
export const rlsMigrationsChecker: Checker = {
  id: 'rls-migrations',
  title: 'Tables created without RLS',
  level: 0,
  run(ctx) {
    const sqlFiles = ctx.files.filter((f) => f.ext === '.sql').sort((a, b) => a.rel.localeCompare(b.rel));

    // RLS is a PostgreSQL feature. The engine is decided per FILE, not per
    // project: a monorepo can hold a Postgres schema next to a Cloudflare D1
    // (SQLite) one, and a SQLite schema must never be told to enable RLS — that
    // engine has no such thing. A real D1 project once got five "critical" RLS
    // findings and a 0/100 because the old gate only knew MySQL's
    // `auto_increment` (with the underscore) and never heard of D1/wrangler.
    // A monorepo's dependencies often live in apps/*/package.json, not the
    // workspace root. Reading only the root file missed a D1/SQLite worker's
    // `wrangler`/`better-sqlite3` signal whenever the SQL itself carried no
    // dialect marker either, and defaulted it to Postgres — a phantom critical
    // on a database that has no RLS to enable.
    const pkg = ctx.files.filter((f) => f.rel.endsWith('package.json')).map((f) => f.content).join('\n');
    const reqs = ctx.files.filter((f) => f.rel === 'requirements.txt' || f.rel.endsWith('/requirements.txt')).map((f) => f.content).join('\n');
    // Checked with .some() against the files themselves, not a pre-joined
    // string: joining nearly the whole project's non-doc/non-SQL content into
    // one string on every scan doubled peak memory for the full scanned corpus
    // to answer what is, per project, a handful of existence checks that can
    // each stop at the first matching file.
    const codeFiles = ctx.files.filter((f) => !/\.(md|mdx|txt|rst|sql)$/i.test(f.rel));
    const matchesAnyCodeFile = (re: RegExp): boolean => codeFiles.some((f) => re.test(f.content));
    const pgProject =
      ctx.detection.backends.includes('supabase') ||
      /\b(pg|postgres|postgresql|@supabase\/|postgres\.js|node-postgres|pg-promise)\b/i.test(pkg) ||
      /\b(psycopg|asyncpg|sqlalchemy\+postgres)\b/i.test(reqs);
    const hasD1 = ctx.files.some((f) => /(^|\/)wrangler\.(toml|jsonc?)$/.test(f.rel) && /d1_databases/.test(f.content));
    const sqliteProject =
      hasD1 ||
      /"(better-sqlite3|sqlite3|@libsql\/client)"/i.test(pkg) ||
      matchesAnyCodeFile(/from\s+['"](bun:sqlite|drizzle-orm\/(d1|better-sqlite3|libsql))['"]/);
    const mysqlProject = /"(mysql2?|mariadb)"/i.test(pkg);
    const sqliteLabel = hasD1 ? 'Cloudflare D1 (SQLite)' : 'SQLite';

    const PG_MARK = /(row\s+level\s+security|gen_random_uuid|\b(?:big)?serial\b|::\s*\w+|\bjsonb\b|\bplpgsql\b|create\s+policy|uuid_generate)/i;
    const SQLITE_MARK = /(\bautoincrement\b|integer\s+primary\s+key|\bpragma\b|without\s+rowid)/i;
    const MYSQL_MARK = /(engine\s*=\s*innodb|\bauto_increment\b|`\w+`\s*varchar)/i;
    /** The engine a file is written for, or null when it is (or may as well be) PostgreSQL. */
    const foreignEngine = (sql: string): string | null => {
      if (PG_MARK.test(sql)) return null;
      if (SQLITE_MARK.test(sql)) return sqliteLabel;
      if (MYSQL_MARK.test(sql)) return 'MySQL';
      // No dialect marker in the file: fall back to what the project uses. With
      // no signal either way this is treated as Postgres — the tool's home turf.
      if (sqliteProject && !pgProject) return sqliteLabel;
      if (mysqlProject && !pgProject) return 'MySQL';
      return null;
    };
    const skipped: { file: string; engine: string }[] = [];
    const analyzed = sqlFiles.filter((f) => {
      const engine = foreignEngine(f.content);
      if (engine) skipped.push({ file: f.rel, engine });
      return !engine;
    });
    // Skipping is visible, not silent: an info finding names the files and says
    // where access control lives for that engine. Info does not move the gate —
    // the check does not apply, so the verdict must not become "incomplete".
    const notApplicable: Finding[] = skipped.length === 0 ? [] : [{
      id: 'rls_not_applicable',
      severity: 'info',
      title: `RLS check skipped for ${skipped.length} ${[...new Set(skipped.map((s) => s.engine))].join('/')} schema file(s) — Row Level Security is PostgreSQL-only`,
      detail: `${skipped.slice(0, 5).map((s) => s.file).join(', ')}${skipped.length > 5 ? ` (+${skipped.length - 5} more)` : ''}: this engine has no row-level security, so "table without RLS" does not apply here. Access control for this data must live in your server/Worker code.`,
      fix: 'Nothing to change in the schema. Make sure every query your API/Worker runs checks the caller\'s identity before reading or writing rows — that is where access control lives for this database.',
      checker: 'rls-migrations',
      level: 0,
      file: skipped[0]?.file ?? '',
      line: 1,
    }];
    // No early return here even when every SQL file present was a foreign
    // engine (`analyzed.length === 0 && skipped.length > 0`): that settles
    // those FILES (SQLite/MySQL truly have no RLS), but not the PROJECT — a
    // Supabase project whose only local .sql happens to be a SQLite cache
    // file has learned nothing about its real Postgres schema either. Both
    // this case and zero SQL files at all fall through to the checks below,
    // which decide from what was actually parsed (nothing, here) whether
    // anything about the applicable backend's schema was learned.

    // "No RLS" is a hole only when untrusted clients reach the database directly
    // (Supabase/PostgREST with the anon key, Hasura). A Postgres that only server
    // code talks to has no RLS by default and is not exposed by that — a critical
    // there would be noise. With no signal either way the exposed reading wins:
    // the tool's audience is mostly Supabase, and unknown must not read as safe.
    const exposed =
      ctx.detection.backends.includes('supabase') ||
      /@supabase\//i.test(pkg) ||
      matchesAnyCodeFile(/(\/rest\/v1\b|postgrest|hasura|SUPABASE_(?:ANON|PUBLISHABLE)_KEY|sb_publishable_)/i);
    const serverOnly =
      !exposed &&
      (/"(pg|postgres|pg-promise|@prisma\/client|drizzle-orm|knex|kysely|typeorm|sequelize)"/i.test(pkg) ||
        /\b(psycopg2?|asyncpg|sqlalchemy)\b/i.test(reqs));
    // Server-only is 'advisory', not 'warning': the fix text for this exact
    // case says "no action needed unless X" — a warning (−8 points, shown as
    // a problem to look into) contradicted its own explanation of itself.
    const missingSeverity = exposed || !serverOnly ? 'critical' as const : 'advisory' as const;

    const events: Event[] = [];
    const notUnderstood: string[] = [];
    analyzed.forEach((f, fileIdx) => {
      const { events: evs, unparsed } = readStatements(f.content);
      for (const e of evs) events.push({ ...e, file: f.rel, fileIdx, line: lineAt(f.content, e.offset) });
      for (const u of unparsed) notUnderstood.push(`${f.rel}:${lineAt(f.content, u.offset)} — ${u.why}`);
    });
    // True apply order: by migration file, then by statement position in the file.
    events.sort((a, b) => a.fileIdx - b.fileIdx || a.offset - b.offset);

    /** `keys`: every key this table has lived under, so a rename does not hide earlier statements. */
    // `everCreated` is separate from `created`: DROP clears `created` (the
    // table is gone NOW) but must not erase the fact that it once existed
    // HERE — that fact is what tells a legitimately dropped table apart from
    // one that was never created in this repo at all (an external table,
    // managed from the dashboard or a migration outside this scan). Once set,
    // `everCreated` is never cleared, including across a RENAME: the spread
    // `{...cur, ...}` below carries it (and `keys`, `guarded`, `enabled`) to
    // whatever name the table currently answers to.
    interface State {
      created: boolean; everCreated: boolean; enabled: boolean; file: string; line: number;
      display: string; stateFile: string; stateLine: number; guarded: boolean; keys: Set<string>;
    }
    const state = new Map<string, State>();
    for (const e of events) {
      const cur = state.get(e.key) ?? {
        created: false, everCreated: false, enabled: false, file: e.file, line: e.line,
        display: e.display, stateFile: e.file, stateLine: e.line, guarded: false, keys: new Set([e.key]),
      };
      if (e.kind === 'rename') {
        const to = e.toKey as string;
        cur.keys.add(to);
        if (e.conditional) {
          // Which name the table ends up under is unknown: keep it under both, both in doubt.
          cur.guarded = true; cur.stateFile = e.file; cur.stateLine = e.line;
          state.set(e.key, cur);
          if (!state.has(to)) state.set(to, { ...cur, keys: new Set(cur.keys), display: e.toDisplay ?? cur.display });
          continue;
        }
        state.delete(e.key);
        state.set(to, { ...cur, display: e.toDisplay ?? cur.display, stateFile: e.file, stateLine: e.line });
        continue;
      }
      // Doubt is a property of ANY guarded statement, not just a guarded ENABLE.
      // A conditional DROP used to delete the table from the model outright, so
      // a table left unprotected vanished from the report entirely. A later
      // unconditional statement settles the state and clears the doubt.
      if (e.conditional) {
        // Keep the table in the model: assume the guarded branch did NOT run
        // (the outcome that leaves data exposed), and record the uncertainty.
        if (e.kind === 'create' && !cur.created) { cur.created = true; cur.everCreated = true; cur.enabled = false; cur.file = e.file; cur.line = e.line; cur.display = e.display; }
        if (e.kind === 'enable') cur.enabled = true;
        if (e.kind === 'disable') cur.enabled = false;
        cur.guarded = true;
        cur.stateFile = e.file; cur.stateLine = e.line;
        state.set(e.key, cur);
        continue;
      }
      switch (e.kind) {
        case 'create':
          if (e.ifNotExists && cur.created) break; // existing table: no-op, keep RLS state
          cur.created = true; cur.everCreated = true; cur.enabled = false; cur.file = e.file; cur.line = e.line; cur.display = e.display;
          cur.stateFile = e.file; cur.stateLine = e.line; cur.guarded = false;
          break;
        case 'enable': cur.enabled = true; cur.stateFile = e.file; cur.stateLine = e.line; cur.guarded = false; break;
        case 'disable': cur.enabled = false; cur.stateFile = e.file; cur.stateLine = e.line; cur.guarded = false; break;
        case 'drop': cur.created = false; cur.enabled = false; cur.stateFile = e.file; cur.stateLine = e.line; cur.guarded = false; break;
      }
      state.set(e.key, cur);
    }

    // Within one directory, filename order IS the apply order, so the replay above
    // is authoritative. Across directories it is a guess (a root-level
    // `rls_policies.sql` sorts before `supabase/migrations/003_*.sql`).
    //
    // The ambiguity is symmetric: it matters whenever a statement of the OPPOSITE
    // polarity to the final state lives in another directory — an ENABLE that the
    // sort happened to put last is no more trustworthy than one it put first.
    // Checking only the RLS-off direction let `a/…DISABLE` + `z/…ENABLE` pass clean.
    const dirOf = (rel: string) => { const i = rel.lastIndexOf('/'); return i === -1 ? '' : rel.slice(0, i); };
    const turnsOff = (k: Event['kind']) => k === 'disable' || k === 'create';

    const findings: Finding[] = [];
    for (const [key, s] of state) {
      if (isTempKey(key)) continue; // temp tables are session-only: PostgREST never sees them
      if (s.everCreated && !s.created) continue; // created here, then legitimately DROPped: known, gone, not a problem
      // Reaching here means one of two things: `s.created` (created here and
      // still exists — the original, well-tested case), or `!s.everCreated`
      // (this key is only ever the target of ALTER/RENAME — an EXTERNAL
      // table this repo never creates, managed from the dashboard or a
      // migration outside this scan). Both get the SAME ambiguity/guard
      // evaluation below: a DISABLE right there in the scanned file is not
      // "no information" just because we cannot confirm the table exists,
      // and an unconditional ENABLE on either is equally provably safe.
      // Reusing one model — instead of a second, separate one for external
      // tables that has to relearn DROP/RENAME/guard/cross-directory order
      // on its own — is what keeps them from disagreeing with each other.
      const external = !s.everCreated;
      const ambiguous = events.some(
        (e) => s.keys.has(e.key) && dirOf(e.file) !== dirOf(s.stateFile) && (s.enabled ? turnsOff(e.kind) : e.kind === 'enable'),
      );
      if (s.enabled && !ambiguous && !s.guarded) continue; // provably protected (or provably fine, if external)
      // `guarded` means a statement we had to GUESS about decided this table's
      // state — a conditional ENABLE, DISABLE, CREATE, DROP or RENAME. Calling
      // that "critical" would be the same false confidence as calling it clean,
      // so it is reported as unconfirmed. A warning still fails CI (exit 1); it
      // just does not claim to know what only the database can tell.
      const kind = external ? 'external' : ambiguous ? 'order' : s.guarded ? 'guarded' : 'missing';
      findings.push({
        id: 'rls_missing',
        severity: kind === 'missing' ? missingSeverity : 'warning',
        title:
          kind === 'external' ? `Table "${s.display}" may have RLS disabled here, but is never created in this repo`
            : kind === 'missing'
              ? (missingSeverity === 'critical'
                ? `Table "${s.display}" created without RLS`
                : `Table "${s.display}" has no RLS (server-only database)`)
              : kind === 'order' ? `Table "${s.display}" may end up without RLS (migration order unclear)`
                : `Table "${s.display}" has an unconfirmed RLS state (conditional block)`,
        detail:
          kind === 'external'
            ? `"${s.display}" is not created by any migration this scan can see, but this project's SQL leaves it with Row Level Security off — or its state cannot be confirmed statically (a conditional branch, or statements in different directories with no reliable apply order). Either the table is real — created from the dashboard, or in a migration outside this repo — and RLS on it may now be off, or it does not exist and this is a no-op. This cannot be told apart statically — check the deployed state.`
            : kind === 'missing'
              ? (missingSeverity === 'critical'
                ? `"${s.display}" is created in a migration and its latest state does not enable Row Level Security. On Supabase the anon role has full table privileges by default, so with RLS off the public key can READ, INSERT, UPDATE and DELETE every row through the REST API. Static view only: this covers tables created by migrations in this repository — tables created from the dashboard or elsewhere are not listed here; the live probe enumerates all of them.`
                : `"${s.display}" is created without Row Level Security. Only server code (pg/Prisma/…) appears to talk to this database, so nothing hands its rows to clients directly — that is normal, not a hole. It becomes CRITICAL the moment a client-facing data API (Supabase/PostgREST anon key, Hasura) is put in front of the same database.`)
              : kind === 'order'
                ? `"${s.display}" has statements in directories other than "${s.stateFile}" that contradict its final RLS state. Files in separate directories have no reliable apply order, so this cannot be decided statically — check the deployed state.`
                : `"${s.display}" has a table or RLS statement whose execution cannot be confirmed statically: inside an IF/LOOP branch or a block with an EXCEPTION handler, after a RETURN, in a rolled-back or unterminated transaction, or on a name a TEMP table may shadow. Whether it took effect cannot be decided without running the migration, so its RLS state is NOT confirmed — check the deployed state.`,
        // The REVOKE-from-anon step only makes sense where an `anon` role is a
        // real thing to revoke from — the same condition `missingSeverity`
        // itself uses. Recommending it unconditionally told a server-only
        // Postgres user (no Supabase, no anon role) to revoke privileges from
        // a role that does not exist in their database, right next to a
        // detail explaining that RLS is not needed there at all. An external
        // table gets its own fix: we do not even know it exists, so neither
        // the anon-revoke step nor the server-only "nothing to do" fits.
        fix: kind === 'external'
          ? `Confirm whether "${s.display}" exists in the deployed database. If it does, re-enable RLS: ALTER TABLE ${s.display} ENABLE ROW LEVEL SECURITY; and add an owner/tenant policy.`
          : exposed || !serverOnly
            ? `ALTER TABLE ${s.display} ENABLE ROW LEVEL SECURITY; then add an owner/tenant policy, and drop any permissive "USING (true)" policy (policies are OR-ed). Until policies exist, stop the bleeding without breaking reads: REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ${s.display} FROM anon; This is a static hint — confirm the deployed state.`
            : `No action needed unless a client-facing data API (Supabase/PostgREST, Hasura) is ever put in front of this database — if it is, first ALTER TABLE ${s.display} ENABLE ROW LEVEL SECURITY and add an owner/tenant policy, then REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ${s.display} FROM the role that API uses to connect.`,
        checker: 'rls-migrations',
        level: 0,
        file: external ? s.stateFile : s.file,
        line: external ? s.stateLine : s.line,
      });
    }

    // Zero findings can mean two very different things: every table here has
    // RLS handled correctly, or no table definition was ever found in the SQL
    // at all — a maintenance script (`SELECT now();`), a seed file with no
    // CREATE TABLE (schema itself made from the dashboard), or literally zero
    // .sql files. `sqlFiles.length === 0` alone used to gate this and missed
    // the first two: presence of a .sql file is not presence of schema
    // information. `events` tells the two apart directly — a table that was
    // found and IS clean still produced a 'create' event, just no finding.
    //
    // A TEMP table's own 'create' does NOT count: it is session-only and
    // PostgREST never sees it (the same reason it is excluded from findings
    // below), so a migration that creates only a staging TEMP table — even
    // one that also DISABLEs RLS on a persistent table this repo never
    // defines — learned nothing about the real, permanent schema either.
    // `findings.length > 0` also counts as "learned something": an external
    // table (no local CREATE at all) can still produce a real finding — an
    // explicit DISABLE sitting right in the scanned file — and that finding
    // must not be thrown away just because no CREATE ever ran anywhere.
    const sawAnyTable = findings.length > 0 || events.some((e) => e.kind === 'create' && !isTempKey(e.key));
    if (!sawAnyTable && notUnderstood.length === 0 && ctx.detection.backends.includes('supabase')) {
      return {
        findings: [...notApplicable, {
          id: 'rls_unverifiable_no_migrations',
          severity: 'info',
          title: 'No table definitions found in SQL — RLS could not be checked statically',
          detail: 'This project talks to Supabase, but no CREATE TABLE (or SELECT ... INTO) was found in any .sql file here — either there are no migrations, or the ones present (a seed script, a maintenance query) do not define a schema. The schema may be managed from the dashboard, or migrations may live in a different repo. A static scan can only see table/RLS state from files it can read, so no table here could be verified this way — this is missing information, not a clean result.',
          fix: 'Run the live probe (consent + --i-own-this) to enumerate which tables the anon key can read, or check pg_class.relrowsecurity and pg_policies directly in the Supabase SQL editor.',
          checker: 'rls-migrations',
          level: 0,
        }],
        partial: 'no table definitions found in SQL for a Supabase project — RLS could not be checked for any table',
      };
    }
    const all = [...findings, ...notApplicable];
    if (notUnderstood.length === 0) return all;
    // Statements that can change table or RLS state and were not understood are
    // missing coverage. Returning them as `partial` makes the verdict incomplete
    // instead of letting an unknown construct read as clean.
    const shown = notUnderstood.slice(0, 5).join('; ');
    const more = notUnderstood.length > 5 ? ` (+${notUnderstood.length - 5} more)` : '';
    return { findings: all, partial: `${notUnderstood.length} SQL statement(s) affecting table/RLS state could not be interpreted: ${shown}${more}` };
  },
};
