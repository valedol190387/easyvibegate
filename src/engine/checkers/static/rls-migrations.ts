import type { Checker, Finding } from '../../types.js';
import { lineAt } from '../../util/text.js';

import { lexSql, type SqlToken } from '../../util/sql-lex.js';

/** Normalize one SQL identifier: quoted keeps case, unquoted folds to lowercase. */
function normIdent(raw: string, quoted: boolean): string {
  return quoted ? raw : raw.toLowerCase();
}
const keyOf = (schema: Name | undefined, table: Name) =>
  `${schema ? normIdent(schema.text, schema.quoted) : 'public'}.${normIdent(table.text, table.quoted)}`;
const displayOf = (schema: Name | undefined, table: Name) => (schema ? `${schema.text}.${table.text}` : table.text);

interface Name { text: string; quoted: boolean }

interface Event {
  kind: 'create' | 'enable' | 'disable' | 'drop';
  key: string;
  ifNotExists: boolean;
  file: string;
  line: number;
  display: string;
  fileIdx: number;
  offset: number;
  /** Sits inside an `IF … THEN … END IF` guard, so it may never execute. */
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
interface Stmt { events: Omit<Event, 'file' | 'fileIdx' | 'line'>[] }

const isWord = (t: SqlToken | undefined, w: string) => !!t && t.type === 'word' && t.value.toUpperCase() === w;
const isName = (t: SqlToken | undefined) => !!t && (t.type === 'word' || t.type === 'quotedIdent');
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
 * Token spans guarded by `IF … THEN … END IF` inside a DO block. IFs nest, so
 * they are matched with a stack. Returns index ranges into `ts`.
 */
function guardedRanges(ts: SqlToken[]): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  const open: number[] = [];
  for (let i = 0; i < ts.length; i++) {
    if (isWord(ts[i], 'END') && isWord(ts[i + 1], 'IF')) {
      const from = open.pop();
      if (from !== undefined) ranges.push([from, i]);
      i++; continue;
    }
    if (isWord(ts[i], 'IF')) open.push(i);
  }
  for (const from of open) ranges.push([from, ts.length]);
  return ranges;
}

/**
 * Flatten a file into tokens, splicing every `DO $$ … $$` body in place so its
 * DDL is analyzed as executed code while the surrounding file keeps its own
 * order. Returns the tokens plus the guarded index ranges.
 */
function flatten(sql: string): { ts: SqlToken[]; guards: Array<[number, number]> } {
  const top = lexSql(sql).filter((t) => t.type !== 'comment');
  const ts: SqlToken[] = [];
  const guards: Array<[number, number]> = [];
  for (let i = 0; i < top.length; i++) {
    const t = top[i] as SqlToken;
    // `DO $$ ... $$` is executed procedural code: lex its body and inline it.
    if (t.type === 'dollarString' && isWord(top[i - 1], 'DO')) {
      const inner = lexSql(t.value, t.bodyStart ?? t.start).filter((x) => x.type !== 'comment');
      const base = ts.length;
      for (const [a, b] of guardedRanges(inner)) guards.push([base + a, base + b]);
      ts.push(...inner);
      continue;
    }
    ts.push(t);
  }
  return { ts, guards };
}

/** Extract CREATE / ENABLE / DISABLE / DROP / SELECT INTO events from one file. */
function readStatements(sql: string): Stmt {
  const { ts, guards } = flatten(sql);
  const events: Stmt['events'] = [];
  const guarded = (i: number) => guards.some(([a, b]) => i >= a && i < b);
  const add = (
    kind: Event['kind'], schema: Name | undefined, table: Name, at: number, idx: number, ifNotExists = false,
  ) => events.push({
    kind, key: keyOf(schema, table), ifNotExists, display: displayOf(schema, table),
    offset: at, conditional: guarded(idx),
  });

  for (let i = 0; i < ts.length; i++) {
    const t = ts[i] as SqlToken;
    if (t.type !== 'word') continue;
    const w = t.value.toUpperCase();

    if (w === 'CREATE' && isWord(ts[i + 1], 'TABLE')) {
      const [j, ine] = skipIfExists(ts, i + 2);
      const q = readQualified(ts, j);
      if (q) add('create', q.schema, q.table, t.start, i, ine);
      continue;
    }

    if (w === 'DROP' && isWord(ts[i + 1], 'TABLE')) {
      const [j] = skipIfExists(ts, i + 2);
      const q = readQualified(ts, j);
      if (q) add('drop', q.schema, q.table, t.start, i);
      continue;
    }

    if (w === 'ALTER' && isWord(ts[i + 1], 'TABLE')) {
      // `ALTER TABLE [IF EXISTS] [ONLY] name ENABLE|DISABLE ROW LEVEL SECURITY`
      let [j] = skipIfExists(ts, i + 2);
      if (isWord(ts[j], 'ONLY')) j++;
      const q = readQualified(ts, j);
      if (!q) continue;
      let k = q.next;
      if (isWord(ts[k], '*')) k++;
      const verb = ts[k];
      if (!verb || verb.type !== 'word') continue;
      const v = verb.value.toUpperCase();
      if ((v !== 'ENABLE' && v !== 'DISABLE') || !isWord(ts[k + 1], 'ROW') || !isWord(ts[k + 2], 'LEVEL') || !isWord(ts[k + 3], 'SECURITY')) continue;
      add(v === 'DISABLE' ? 'disable' : 'enable', q.schema, q.table, t.start, i);
      continue;
    }

    if (w === 'SELECT') {
      // `SELECT ... INTO <table>` creates a table. Stop at the statement end.
      for (let k = i + 1; k < ts.length; k++) {
        const u = ts[k] as SqlToken;
        if (u.type === 'punct' && u.value === ';') break;
        if (u.type === 'word' && u.value.toUpperCase() === 'FROM') break;
        if (isWord(u, 'INTO')) {
          const q = readQualified(ts, k + 1);
          if (q) add('create', q.schema, q.table, t.start, i);
          break;
        }
      }
      continue;
    }
  }
  return { events };
}

/**
 * Flags each table whose latest state after replaying the migrations is
 * "created and RLS not enabled". Migrations are replayed in apply order
 * (files by name, statements by offset); CREATE / ENABLE / DISABLE / DROP are
 * all modeled; CREATE IF NOT EXISTS on an existing table is a no-op; comments
 * and string literals are ignored; quoted and schema-qualified names work.
 */
export const rlsMigrationsChecker: Checker = {
  id: 'rls-migrations',
  title: 'Tables created without RLS',
  level: 0,
  run(ctx) {
    const sqlFiles = ctx.files.filter((f) => f.ext === '.sql').sort((a, b) => a.rel.localeCompare(b.rel));
    if (sqlFiles.length === 0) return [];

    // RLS is a PostgreSQL feature. Do not tell a MySQL/SQLite project to enable it.
    const allSql = sqlFiles.map((f) => f.content).join('\n');
    const pkg = ctx.files.find((f) => f.rel === 'package.json')?.content ?? '';
    const postgresish =
      ctx.detection.backends.includes('supabase') ||
      /\b(pg|postgres|postgresql|@supabase\/|drizzle-orm|postgres\.js|node-postgres)\b/i.test(pkg) ||
      /(enable\s+row\s+level\s+security|gen_random_uuid|\bserial\b|::\s*\w+|\bjsonb\b)/i.test(allSql) ||
      /\b(psycopg|asyncpg|sqlalchemy\+postgres)\b/i.test(ctx.files.find((f) => f.rel === 'requirements.txt')?.content ?? '');
    const otherEngine =
      /(engine\s*=\s*innodb|auto_increment|\bpragma\b|`\w+`\s*varchar)/i.test(allSql) ||
      /\b(mysql2?|sqlite3|better-sqlite3|mariadb)\b/i.test(pkg);
    if (otherEngine && !postgresish) return [];

    const events: Event[] = [];
    sqlFiles.forEach((f, fileIdx) => {
      for (const e of readStatements(f.content).events) {
        events.push({ ...e, file: f.rel, fileIdx, line: lineAt(f.content, e.offset) });
      }
    });
    // True apply order: by migration file, then by statement position in the file.
    events.sort((a, b) => a.fileIdx - b.fileIdx || a.offset - b.offset);

    interface State { created: boolean; enabled: boolean; file: string; line: number; display: string; stateFile: string; guarded: boolean }
    const state = new Map<string, State>();
    for (const e of events) {
      const cur = state.get(e.key) ?? { created: false, enabled: false, file: e.file, line: e.line, display: e.display, stateFile: e.file, guarded: false };
      // Doubt is a property of ANY guarded statement, not just a guarded ENABLE.
      // A conditional DROP used to delete the table from the model outright, so
      // a table left unprotected vanished from the report entirely. A later
      // unconditional statement settles the state and clears the doubt.
      if (e.conditional) {
        // Keep the table in the model: assume the guarded branch did NOT run
        // (the outcome that leaves data exposed), and record the uncertainty.
        if (e.kind === 'create' && !cur.created) { cur.created = true; cur.enabled = false; cur.file = e.file; cur.line = e.line; cur.display = e.display; }
        if (e.kind === 'enable') cur.enabled = true;
        if (e.kind === 'disable') cur.enabled = false;
        cur.guarded = true;
        cur.stateFile = e.file;
        state.set(e.key, cur);
        continue;
      }
      switch (e.kind) {
        case 'create':
          if (e.ifNotExists && cur.created) break; // existing table: no-op, keep RLS state
          cur.created = true; cur.enabled = false; cur.file = e.file; cur.line = e.line; cur.display = e.display;
          cur.stateFile = e.file; cur.guarded = false;
          break;
        case 'enable': cur.enabled = true; cur.stateFile = e.file; cur.guarded = false; break;
        case 'disable': cur.enabled = false; cur.stateFile = e.file; cur.guarded = false; break;
        case 'drop': cur.created = false; cur.enabled = false; cur.stateFile = e.file; cur.guarded = false; break;
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
      if (!s.created) continue;
      const ambiguous = events.some(
        (e) => e.key === key && dirOf(e.file) !== dirOf(s.stateFile) && (s.enabled ? turnsOff(e.kind) : e.kind === 'enable'),
      );
      if (s.enabled && !ambiguous && !s.guarded) continue; // provably protected
      // `guarded` means a statement we had to GUESS about decided this table's
      // state — a conditional ENABLE, DISABLE, CREATE or DROP. Calling that
      // "critical" would be the same false confidence as calling it clean, so it
      // is reported as unconfirmed. A warning still fails CI (exit 1); it just
      // does not claim to know what only the database can tell.
      const kind = ambiguous ? 'order' : s.guarded ? 'guarded' : 'missing';
      findings.push({
        id: 'rls_missing',
        severity: kind === 'missing' ? 'critical' : 'warning',
        title:
          kind === 'missing' ? `Table "${s.display}" created without RLS`
            : kind === 'order' ? `Table "${s.display}" may end up without RLS (migration order unclear)`
              : `Table "${s.display}" has an unconfirmed RLS state (conditional block)`,
        detail:
          kind === 'missing'
            ? `"${s.display}" is created in a migration and its latest state does not enable Row Level Security. If this table holds user data on Supabase, the anon key can read every row.`
            : kind === 'order'
              ? `"${s.display}" has statements in directories other than "${s.stateFile}" that contradict its final RLS state. Files in separate directories have no reliable apply order, so this cannot be decided statically — check the deployed state.`
              : `"${s.display}" has RLS statements inside an "IF … THEN" guard in a DO block. Whether that branch runs cannot be decided without executing the migration, so its RLS state is NOT confirmed — check the deployed state.`,
        fix: `ALTER TABLE ${s.display} ENABLE ROW LEVEL SECURITY; then add an owner/tenant policy, and drop any permissive "USING (true)" policy (policies are OR-ed). This is a static hint — confirm the deployed state.`,
        checker: 'rls-migrations',
        level: 0,
        file: s.file,
        line: s.line,
      });
    }
    return findings;
  },
};
