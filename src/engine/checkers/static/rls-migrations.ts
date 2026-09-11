import type { Checker, Finding } from '../../types.js';
import { lineAt } from '../../util/text.js';

const CREATE_TABLE = /create\s+table\s+(?:if\s+not\s+exists\s+)?("?[A-Za-z0-9_.]+"?)/gi;
const ENABLE_RLS = /alter\s+table\s+(?:only\s+)?("?[A-Za-z0-9_.]+"?)\s+enable\s+row\s+level\s+security/gi;

/** Normalize a possibly schema-qualified / quoted table name to a bare lowercase name. */
function tableName(raw: string): string {
  const unquoted = raw.replace(/"/g, '');
  const parts = unquoted.split('.');
  return (parts[parts.length - 1] ?? unquoted).toLowerCase();
}

/** Replace SQL comments with equal-length blanks so match offsets stay accurate. */
function maskComments(sql: string): string {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/--[^\n]*/g, (m) => ' '.repeat(m.length));
}

/**
 * Flags each table that is CREATEd in a migration but never gets
 * `ENABLE ROW LEVEL SECURITY` anywhere in the migration set. Works per-table
 * (not per-file), tolerates CREATE and ENABLE living in different files, ignores
 * comments, and handles schema-qualified / quoted names.
 */
export const rlsMigrationsChecker: Checker = {
  id: 'rls-migrations',
  title: 'Tables created without RLS',
  level: 0,
  run(ctx) {
    const sqlFiles = ctx.files.filter((f) => f.ext === '.sql');
    if (sqlFiles.length === 0) return [];

    // 1. Collect every table that has RLS enabled anywhere.
    const enabled = new Set<string>();
    for (const f of sqlFiles) {
      const masked = maskComments(f.content);
      for (const m of masked.matchAll(ENABLE_RLS)) {
        if (m[1]) enabled.add(tableName(m[1]));
      }
    }

    // 2. Flag each created table that is not in that set, at its CREATE site.
    const findings: Finding[] = [];
    const reported = new Set<string>();
    for (const f of sqlFiles) {
      const masked = maskComments(f.content);
      for (const m of masked.matchAll(CREATE_TABLE)) {
        if (!m[1]) continue;
        const name = tableName(m[1]);
        if (enabled.has(name) || reported.has(name)) continue;
        reported.add(name);
        findings.push({
          id: 'rls_missing',
          severity: 'critical',
          title: `Table "${name}" created without RLS`,
          detail: `"${name}" is created in a migration but no migration runs ALTER TABLE ... ENABLE ROW LEVEL SECURITY for it. If this table holds user data on Supabase, the anon key can read every row.`,
          fix: `ALTER TABLE ${m[1].replace(/"/g, '')} ENABLE ROW LEVEL SECURITY; then add an owner/tenant policy. This is a static hint — confirm the deployed state (RLS can also be toggled outside migrations).`,
          checker: 'rls-migrations',
          level: 0,
          file: f.rel,
          line: lineAt(f.content, m.index ?? 0),
        });
      }
    }

    return findings;
  },
};
