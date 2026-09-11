import type { Checker, Finding } from '../../types.js';
import { lineAt } from '../../util/text.js';

const IDENT = '(?:"[^"]+"|`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)';
const QUALIFIED = `(?:(${IDENT})\\s*\\.\\s*)?(${IDENT})`;
const CREATE_TABLE = new RegExp(`create\\s+table\\s+(if\\s+not\\s+exists\\s+)?${QUALIFIED}`, 'gi');
const RLS_STMT = new RegExp(`alter\\s+table\\s+(?:only\\s+)?${QUALIFIED}\\s+(enable|disable)\\s+row\\s+level\\s+security`, 'gi');
const DROP_TABLE = new RegExp(`drop\\s+table\\s+(?:if\\s+exists\\s+)?${QUALIFIED}`, 'gi');

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

    const events: Event[] = [];
    sqlFiles.forEach((f, fileIdx) => {
      const masked = maskSql(f.content);
      const push = (kind: Event['kind'], schema: string | undefined, table: string, offset: number, ifNotExists = false) =>
        events.push({ kind, key: keyOf(schema, table), ifNotExists, file: f.rel, line: lineAt(f.content, offset), display: displayOf(schema, table), fileIdx, offset });
      for (const m of masked.matchAll(CREATE_TABLE)) push('create', m[2], m[3] ?? '', m.index ?? 0, !!m[1]);
      for (const m of masked.matchAll(RLS_STMT)) push((m[3] ?? '').toLowerCase() === 'disable' ? 'disable' : 'enable', m[1], m[2] ?? '', m.index ?? 0);
      for (const m of masked.matchAll(DROP_TABLE)) push('drop', m[1], m[2] ?? '', m.index ?? 0);
    });
    // True apply order: by migration file, then by statement position in the file.
    events.sort((a, b) => a.fileIdx - b.fileIdx || a.offset - b.offset);

    interface State { created: boolean; enabled: boolean; file: string; line: number; display: string }
    const state = new Map<string, State>();
    for (const e of events) {
      const cur = state.get(e.key) ?? { created: false, enabled: false, file: e.file, line: e.line, display: e.display };
      switch (e.kind) {
        case 'create':
          if (e.ifNotExists && cur.created) break; // existing table: no-op, keep RLS state
          cur.created = true; cur.enabled = false; cur.file = e.file; cur.line = e.line; cur.display = e.display;
          break;
        case 'enable': cur.enabled = true; break;
        case 'disable': cur.enabled = false; break;
        case 'drop': cur.created = false; cur.enabled = false; break;
      }
      state.set(e.key, cur);
    }

    const findings: Finding[] = [];
    for (const s of state.values()) {
      if (!s.created || s.enabled) continue;
      findings.push({
        id: 'rls_missing',
        severity: 'critical',
        title: `Table "${s.display}" created without RLS`,
        detail: `"${s.display}" is created in a migration and its latest state does not enable Row Level Security. If this table holds user data on Supabase, the anon key can read every row.`,
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
