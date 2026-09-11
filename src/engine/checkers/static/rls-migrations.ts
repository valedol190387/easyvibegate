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
      // PostgreSQL block comments NEST: in `/* a /* b */ still a comment */` the
      // first `*/` closes only the inner one. Stopping there un-commented the
      // rest and made commented-out DDL look like executed DDL.
      let depth = 0;
      let j = i;
      while (j < n) {
        if (sql[j] === '/' && sql[j + 1] === '*') { depth++; j += 2; continue; }
        if (sql[j] === '*' && sql[j + 1] === '/') { depth--; j += 2; if (depth === 0) break; continue; }
        j++;
      }
      const end = depth === 0 ? j : n;
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
          // The `$$` delimiters stay VISIBLE on purpose: guard analysis reads this
          // same masked text and needs them to find the block. Sharing one masked
          // string is what keeps masking and guard parsing from disagreeing about
          // what is a string or a comment.
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
 *
 * IFs nest, so this matches them with a stack: taking the first `END IF` as the
 * outer block's terminator ends the guard early and lets a statement after the
 * inner `END IF` look unconditional. `ELSIF` is not an opener (`\bif\b` does not
 * match inside it).
 *
 * Takes the SAME masked text the statements are read from, so `'end if'` inside a
 * string literal or a comment cannot terminate a guard — two separate parsers
 * disagreeing about that is exactly how such statements slipped through.
 */
function conditionalRanges(src: string): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  for (const m of src.matchAll(/\bdo\s*(\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$)/gi)) {
    const tag = m[1] as string;
    const bodyStart = (m.index ?? 0) + m[0].length;
    const close = src.indexOf(tag, bodyStart);
    const bodyEnd = close === -1 ? src.length : close;
    const body = src.slice(bodyStart, bodyEnd);
    const open: number[] = [];
    for (const t of body.matchAll(/\bend\s+if\b|\bif\b/gi)) {
      const at = t.index ?? 0;
      if (/^end/i.test(t[0])) {
        const from = open.pop();
        if (from !== undefined) ranges.push([bodyStart + from, bodyStart + at]);
      } else {
        open.push(at);
      }
    }
    // An IF left unterminated guards everything to the end of the block.
    for (const from of open) ranges.push([bodyStart + from, bodyEnd]);
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
      const guards = conditionalRanges(masked);
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
