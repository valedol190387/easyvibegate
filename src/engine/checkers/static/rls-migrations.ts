import type { Checker, Finding } from '../../types.js';
import { lineAt } from '../../util/text.js';

const IDENT = '(?:"[^"]+"|`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)';
const QUALIFIED = `(?:(${IDENT})\\s*\\.\\s*)?(${IDENT})`;
const CREATE_TABLE = new RegExp(`create\\s+table\\s+(if\\s+not\\s+exists\\s+)?${QUALIFIED}`, 'gi');
const RLS_STMT = new RegExp(`alter\\s+table\\s+(?:only\\s+)?${QUALIFIED}\\s+(enable|disable)\\s+row\\s+level\\s+security`, 'gi');
const DROP_TABLE = new RegExp(`drop\\s+table\\s+(?:if\\s+exists\\s+)?${QUALIFIED}`, 'gi');
// SELECT ... INTO <table> also creates a table.
const SELECT_INTO = new RegExp(`\\bselect\\b[^;]{0,400}?\\binto\\s+${QUALIFIED}`, 'gis');

/** Normalize one SQL identifier: quoted keeps case, unquoted folds to lowercase. */
function normIdent(raw: string): string {
  if (raw.startsWith('"') && raw.endsWith('"')) return raw.slice(1, -1);
  if (raw.startsWith('`') && raw.endsWith('`')) return raw.slice(1, -1);
  return raw.toLowerCase();
}
const keyOf = (schema: string | undefined, table: string) => `${schema ? normIdent(schema) : 'public'}.${normIdent(table)}`;
const displayOf = (schema: string | undefined, table: string) => (schema ? `${schema}.${table}` : table);

/**
 * Blank out comments and string literals (keeping newlines and offsets) so that
 * SQL inside a string — e.g. SELECT 'ALTER TABLE x ENABLE ROW LEVEL SECURITY' —
 * or inside a comment is never mistaken for an executed statement.
 * Handles -- and block comments, '...' with '' escapes (and E'...'), and
 * $$ / $tag$ dollar-quoted strings. Double-quoted identifiers are kept.
 */
export function maskSql(sql: string): string {
  const out = sql.split('');
  const n = sql.length;
  const blank = (from: number, to: number) => {
    for (let k = from; k < to && k < n; k++) if (out[k] !== '\n') out[k] = ' ';
  };
  let i = 0;
  while (i < n) {
    const ch = sql[i];
    const next = sql[i + 1];
    if (ch === '-' && next === '-') {
      let j = i;
      while (j < n && sql[j] !== '\n') j++;
      blank(i, j); i = j; continue;
    }
    if (ch === '/' && next === '*') {
      const close = sql.indexOf('*/', i + 2);
      const end = close === -1 ? n : close + 2;
      blank(i, end); i = end; continue;
    }
    if (ch === "'") {
      let j = i + 1;
      while (j < n) {
        if (sql[j] === "'") { if (sql[j + 1] === "'") { j += 2; continue; } break; }
        j++;
      }
      const end = Math.min(j + 1, n);
      blank(i, end); i = end; continue;
    }
    if (ch === '$') {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(sql.slice(i, i + 64));
      if (m) {
        const tag = m[0];
        const close = sql.indexOf(tag, i + tag.length);
        const end = close === -1 ? n : close + tag.length;
        // `DO $$ ... $$` is executed procedural code: its DDL is real, so keep the
        // body visible. Other dollar-quoted strings (EXECUTE format(...)) are blanked.
        const isDoBlock = /\bdo\s*$/i.test(sql.slice(Math.max(0, i - 8), i));
        if (isDoBlock) {
          const bodyStart = i + tag.length;
          const bodyEnd = close === -1 ? n : close;
          // Mask inside the body too (a string literal there is still a string),
          // then jump past the CLOSING delimiter — scanning from just after the
          // opening one would read that closing `$$` as a new opening tag and
          // blank the entire rest of the file, hiding every later statement.
          const inner = maskSql(sql.slice(bodyStart, bodyEnd));
          for (let k = 0; k < inner.length; k++) out[bodyStart + k] = inner[k] as string;
          blank(i, bodyStart);
          blank(bodyEnd, end);
          i = end; continue;
        }
        blank(i, end); i = end; continue;
      }
    }
    i++;
  }
  return out.join('');
}

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
 * Spans inside a `DO $$ … $$` body that sit between an `IF … THEN` and its
 * `END IF`. DDL there runs only when the condition holds, and deciding that
 * needs an interpreter — so statements in these spans are reported as
 * "cannot be confirmed" rather than assumed to have run.
 */
function conditionalRanges(sql: string): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  for (const m of sql.matchAll(/\bdo\s*(\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$)/gi)) {
    const tag = m[1] as string;
    const bodyStart = (m.index ?? 0) + m[0].length;
    const close = sql.indexOf(tag, bodyStart);
    const bodyEnd = close === -1 ? sql.length : close;
    const body = sql.slice(bodyStart, bodyEnd);
    const lower = body.toLowerCase();
    for (const im of body.matchAll(/\bif\b[\s\S]*?\bthen\b/gi)) {
      const from = im.index ?? 0;
      const endIdx = lower.indexOf('end if', from + im[0].length);
      ranges.push([bodyStart + from, endIdx === -1 ? bodyEnd : bodyStart + endIdx]);
    }
  }
  return ranges;
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
      const masked = maskSql(f.content);
      // Computed on the raw text: maskSql blanks the `$$` delimiters themselves,
      // so the DO blocks are no longer findable there. It preserves length, so
      // offsets from `masked` line up with these ranges exactly.
      const guards = conditionalRanges(f.content);
      const push = (kind: Event['kind'], schema: string | undefined, table: string, offset: number, ifNotExists = false) =>
        events.push({
          kind, key: keyOf(schema, table), ifNotExists, file: f.rel, line: lineAt(f.content, offset),
          display: displayOf(schema, table), fileIdx, offset,
          conditional: guards.some(([a, b]) => offset >= a && offset < b),
        });
      for (const m of masked.matchAll(CREATE_TABLE)) push('create', m[2], m[3] ?? '', m.index ?? 0, !!m[1]);
      for (const m of masked.matchAll(RLS_STMT)) push((m[3] ?? '').toLowerCase() === 'disable' ? 'disable' : 'enable', m[1], m[2] ?? '', m.index ?? 0);
      for (const m of masked.matchAll(DROP_TABLE)) push('drop', m[1], m[2] ?? '', m.index ?? 0);
      for (const m of masked.matchAll(SELECT_INTO)) push('create', m[1], m[2] ?? '', m.index ?? 0);
    });
    // True apply order: by migration file, then by statement position in the file.
    events.sort((a, b) => a.fileIdx - b.fileIdx || a.offset - b.offset);

    interface State { created: boolean; enabled: boolean; file: string; line: number; display: string; stateFile: string; guardedEnable: boolean }
    const state = new Map<string, State>();
    for (const e of events) {
      const cur = state.get(e.key) ?? { created: false, enabled: false, file: e.file, line: e.line, display: e.display, stateFile: e.file, guardedEnable: false };
      switch (e.kind) {
        case 'create':
          if (e.ifNotExists && cur.created) break; // existing table: no-op, keep RLS state
          cur.created = true; cur.enabled = false; cur.file = e.file; cur.line = e.line; cur.display = e.display;
          cur.stateFile = e.file; cur.guardedEnable = false;
          break;
        // A later unconditional ENABLE clears the doubt a guarded one left.
        case 'enable': cur.enabled = true; cur.stateFile = e.file; cur.guardedEnable = e.conditional; break;
        case 'disable': cur.enabled = false; cur.stateFile = e.file; cur.guardedEnable = false; break;
        case 'drop': cur.created = false; cur.enabled = false; cur.stateFile = e.file; cur.guardedEnable = false; break;
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
      if (s.enabled && !ambiguous && !s.guardedEnable) continue; // provably protected
      const kind = ambiguous ? 'order' : s.enabled ? 'guarded' : 'missing';
      findings.push({
        id: 'rls_missing',
        severity: kind === 'missing' ? 'critical' : 'warning',
        title:
          kind === 'missing' ? `Table "${s.display}" created without RLS`
            : kind === 'order' ? `Table "${s.display}" may end up without RLS (migration order unclear)`
              : `Table "${s.display}" enables RLS only inside a conditional block`,
        detail:
          kind === 'missing'
            ? `"${s.display}" is created in a migration and its latest state does not enable Row Level Security. If this table holds user data on Supabase, the anon key can read every row.`
            : kind === 'order'
              ? `"${s.display}" has statements in directories other than "${s.stateFile}" that contradict its final RLS state. Files in separate directories have no reliable apply order, so this cannot be decided statically — check the deployed state.`
              : `"${s.display}" only gets ENABLE ROW LEVEL SECURITY inside an "IF … THEN" guard in a DO block. Whether that branch runs cannot be decided without executing the migration, so RLS is NOT confirmed — check the deployed state.`,
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
