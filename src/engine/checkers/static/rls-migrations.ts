import type { Checker, Finding } from '../../types.js';
import { lineAt } from '../../util/text.js';

const IDENT = '(?:"[^"]+"|`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)';
const QUALIFIED = `(?:(${IDENT})\\s*\\.\\s*)?(${IDENT})`;
const CREATE_TABLE = new RegExp(`create\\s+table\\s+(?:if\\s+not\\s+exists\\s+)?${QUALIFIED}`, 'gi');
const RLS_STMT = new RegExp(`alter\\s+table\\s+(?:only\\s+)?${QUALIFIED}\\s+(enable|disable)\\s+row\\s+level\\s+security`, 'gi');

/** Normalize one SQL identifier: quoted keeps case, unquoted folds to lowercase. */
function normIdent(raw: string): string {
  if (raw.startsWith('"') && raw.endsWith('"')) return raw.slice(1, -1);
  if (raw.startsWith('`') && raw.endsWith('`')) return raw.slice(1, -1);
  return raw.toLowerCase();
}
function keyOf(schema: string | undefined, table: string): string {
  return `${schema ? normIdent(schema) : 'public'}.${normIdent(table)}`;
}
function displayOf(schema: string | undefined, table: string): string {
  return schema ? `${schema}.${table}` : table;
}

/** Replace SQL comments with equal-length blanks so match offsets stay accurate. */
function maskComments(sql: string): string {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/--[^\n]*/g, (m) => ' '.repeat(m.length));
}

interface Event {
  key: string;
  kind: 'create' | 'enable' | 'disable';
  file: string;
  line: number;
  display: string;
  order: number;
}

/**
 * Flags each table CREATEd in a migration whose latest RLS state is not enabled.
 * Keys by (schema, table); processes CREATE / ENABLE / DISABLE in apply order
 * (files sorted by name, then by position); ignores comments; handles quoted
 * and schema-qualified identifiers.
 */
export const rlsMigrationsChecker: Checker = {
  id: 'rls-migrations',
  title: 'Tables created without RLS',
  level: 0,
  run(ctx) {
    const sqlFiles = ctx.files.filter((f) => f.ext === '.sql').sort((a, b) => a.rel.localeCompare(b.rel));
    if (sqlFiles.length === 0) return [];

    const events: Event[] = [];
    let order = 0;
    for (const f of sqlFiles) {
      const masked = maskComments(f.content);
      for (const m of masked.matchAll(CREATE_TABLE)) {
        events.push({ key: keyOf(m[1], m[2] ?? ''), kind: 'create', file: f.rel, line: lineAt(f.content, m.index ?? 0), display: displayOf(m[1], m[2] ?? ''), order: order++ });
      }
      for (const m of masked.matchAll(RLS_STMT)) {
        const kind = (m[3] ?? '').toLowerCase() === 'disable' ? 'disable' : 'enable';
        events.push({ key: keyOf(m[1], m[2] ?? ''), kind, file: f.rel, line: lineAt(f.content, m.index ?? 0), display: displayOf(m[1], m[2] ?? ''), order: order++ });
      }
    }
    events.sort((a, b) => a.order - b.order);

    // Replay in apply order; last write wins for RLS state.
    const state = new Map<string, { created: boolean; enabled: boolean; file: string; line: number; display: string }>();
    for (const e of events) {
      const cur = state.get(e.key) ?? { created: false, enabled: false, file: e.file, line: e.line, display: e.display };
      if (e.kind === 'create') { cur.created = true; cur.enabled = false; cur.file = e.file; cur.line = e.line; cur.display = e.display; }
      else if (e.kind === 'enable') cur.enabled = true;
      else cur.enabled = false;
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
