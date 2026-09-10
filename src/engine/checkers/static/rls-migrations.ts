import type { Checker, Finding } from '../../types.js';
import { lineAt } from '../../util/text.js';

const CREATE_TABLE = /create\s+table\s+(?:if\s+not\s+exists\s+)?["'`]?([A-Za-z0-9_.]+)/gi;
const ENABLE_RLS = /enable\s+row\s+level\s+security/i;

/**
 * Flags SQL migrations that create tables but never enable Row Level Security.
 * This is the single most common critical hole in Supabase/Postgres vibe apps.
 */
export const rlsMigrationsChecker: Checker = {
  id: 'rls-migrations',
  title: 'Tables created without RLS',
  level: 0,
  run(ctx) {
    const findings: Finding[] = [];
    const sqlFiles = ctx.files.filter((f) => f.ext === '.sql');
    if (sqlFiles.length === 0) return findings;

    // Whether RLS is enabled anywhere across all migrations.
    const rlsEnabledSomewhere = sqlFiles.some((f) => ENABLE_RLS.test(f.content));

    for (const file of sqlFiles) {
      const created = [...file.content.matchAll(CREATE_TABLE)];
      if (created.length === 0) continue;
      const fileEnablesRls = ENABLE_RLS.test(file.content);
      if (fileEnablesRls) continue;

      const first = created[0]!;
      const tables = created.map((m) => m[1]).filter(Boolean).slice(0, 8).join(', ');
      findings.push({
        id: 'rls_missing',
        severity: 'critical',
        title: 'SQL migration creates tables but never enables RLS',
        detail:
          `Tables (${tables}) are created without ENABLE ROW LEVEL SECURITY. ` +
          (rlsEnabledSomewhere
            ? 'RLS is enabled in other migrations — confirm these tables are covered.'
            : 'No migration enables RLS at all, so the anon key can read every row.'),
        fix: 'For each user-data table run: ALTER TABLE <t> ENABLE ROW LEVEL SECURITY; then add policies like USING (auth.uid() = user_id).',
        checker: 'rls-migrations',
        level: 0,
        file: file.rel,
        line: lineAt(file.content, first.index ?? 0),
      });
    }

    return findings;
  },
};
