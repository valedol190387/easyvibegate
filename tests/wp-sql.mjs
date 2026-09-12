// SQL / RLS-model regressions (external audit F05–F09). Offline only.
// Every fix has a positive AND a negative half — an assertion of absence alone
// cannot tell a detector that stopped lying from one that stopped working.
//
// Vocabulary: `critical` = confident rls_missing; `warning` = rls_missing whose
// state could not be confirmed; `none` = clean AND the checker completed;
// `partial` = the checker reported missing coverage (verdict incomplete, exit 3).
import assert from 'node:assert';
import { rmSync } from 'node:fs';
import { scanStatic } from '../dist/engine/scan.js';
import { summarize, exitCodeFor } from '../dist/engine/report.js';
import { check, fixture, ids } from './_harness.mjs';

console.log('\nWP sql');

const C = 'CREATE TABLE orders (id serial);\n';
const E = 'ALTER TABLE orders ENABLE ROW LEVEL SECURITY;\n';
const D = 'ALTER TABLE orders DISABLE ROW LEVEL SECURITY;\n';
const RUN = 'static:rls-migrations';

/** One migration file → expected outcome. `opts.title` must match the finding's title. */
const rlsCase = async (name, sql, expect, opts = {}) => {
  const dir = fixture({ 'db/1.sql': sql });
  const r = await scanStatic(dir);
  const run = r.runs.find((x) => x.id === RUN);
  const rls = r.findings.filter((f) => f.id === 'rls_missing');
  const got = `status=${run?.status} findings=[${rls.map((f) => `${f.severity}:${f.title}`).join(' | ') || 'none'}] note=${run?.note ?? ''}`;
  check(name, () => {
    if (expect === 'partial') {
      assert.strictEqual(run?.status, 'partial', got);
      assert.match(run?.note ?? '', /could not be interpreted/, got);
      assert.strictEqual(exitCodeFor(summarize(r.findings, r.runs)), 3, got);
      return;
    }
    assert.strictEqual(run?.status, 'completed', got);
    if (expect === 'none') { assert.strictEqual(rls.length, 0, got); return; }
    assert.ok(rls.length > 0, got);
    assert.ok(rls.every((f) => f.severity === expect), got);
    if (opts.title) assert.ok(rls.some((f) => opts.title.test(f.title)), got);
  });
  rmSync(dir, { recursive: true, force: true });
};

// --- F05: executable SQL must not vanish without partial ---------------------
await rlsCase('F05: EXECUTE of a variable holding DDL is dynamic SQL → partial',
  C + E + "DO $$ DECLARE cmd text := 'ALTER TABLE orders DISABLE ROW LEVEL SECURITY;'; BEGIN EXECUTE cmd; END $$;\n", 'partial');
await rlsCase("F05: DO '…' with a plain-string body is executed code (DISABLE seen)",
  C + E + "DO 'BEGIN ALTER TABLE orders DISABLE ROW LEVEL SECURITY; END';\n", 'critical');
await rlsCase("F05: DO '…' body with doubled quotes still lexes; its ENABLE counts",
  C + "DO 'BEGIN PERFORM ''noop''; ALTER TABLE orders ENABLE ROW LEVEL SECURITY; END';\n", 'none');
await rlsCase('F05: EXECUTE of a || concatenation is dynamic SQL → partial',
  C + E + "DO $$ BEGIN EXECUTE 'ALTER TABLE orders DISABLE ROW ' || 'LEVEL SECURITY'; END $$;\n", 'partial');
await rlsCase('F05: EXECUTE format(…) is dynamic SQL → partial',
  C + E + "DO $$ BEGIN EXECUTE format('ALTER TABLE %I DISABLE ROW LEVEL SECURITY', 'orders'); END $$;\n", 'partial');
await rlsCase('F05: EXECUTE of a variable with no table text is STILL unknown → partial',
  C + E + "DO $$ DECLARE q text := 'NOTIFY ch'; BEGIN EXECUTE q; END $$;\n", 'partial');
await rlsCase('F05 (negative): CREATE TRIGGER … EXECUTE FUNCTION is not dynamic SQL',
  C + E + 'CREATE TRIGGER t AFTER INSERT ON orders FOR EACH ROW EXECUTE FUNCTION audit();\n', 'none');
await rlsCase('F05 (negative): a single unrelated EXECUTE literal keeps the check complete',
  C + E + "DO $$ BEGIN EXECUTE 'NOTIFY ch'; END $$;\n", 'none');

// --- F06: table identity ----------------------------------------------------
await rlsCase('F06: RENAME TO moves the state; DISABLE under the new name is seen',
  C + E + 'ALTER TABLE orders RENAME TO purchases;\nALTER TABLE purchases DISABLE ROW LEVEL SECURITY;\n', 'critical', { title: /purchases/ });
await rlsCase('F06 (negative): RENAME TO then ENABLE under the new name is clean',
  C + 'ALTER TABLE orders RENAME TO purchases;\nALTER TABLE purchases ENABLE ROW LEVEL SECURITY;\n', 'none');
await rlsCase('F06: SET SCHEMA moves the state; DISABLE on archive.orders is seen',
  C + E + 'ALTER TABLE orders SET SCHEMA archive;\nALTER TABLE archive.orders DISABLE ROW LEVEL SECURITY;\n', 'critical', { title: /archive\.orders/ });
await rlsCase('F06 (negative): SET SCHEMA then ENABLE under the new schema is clean',
  C + 'ALTER TABLE orders SET SCHEMA archive;\nALTER TABLE archive.orders ENABLE ROW LEVEL SECURITY;\n', 'none');
await rlsCase('F06: a table left unprotected in a search_path schema is a distinct table',
  'SET search_path TO app;\n' + C + 'SET search_path TO public;\n' + C + E, 'critical', { title: /app\.orders/ });
await rlsCase('F06 (negative): SET search_path TO app + CREATE orders + ENABLE app.orders is clean',
  'SET search_path TO app;\n' + C + 'ALTER TABLE app.orders ENABLE ROW LEVEL SECURITY;\n', 'none');
await rlsCase('F06 (negative): both search_path schemas protected is clean',
  'SET search_path = app, public;\n' + C + 'ALTER TABLE app.orders ENABLE ROW LEVEL SECURITY;\nRESET search_path;\n' + C + E, 'none');
await rlsCase('F06: a search_path starting with "$user" cannot be resolved → partial',
  'SET search_path TO "$user", public;\n' + C + E, 'partial');
await rlsCase('F06: SET search_path inside a DO block → partial',
  C + E + "DO $$ BEGIN SET search_path TO app; END $$;\n", 'partial');
await rlsCase('F06: search_path changed via a non-literal set_config → partial',
  "SELECT set_config('search_path', current_setting('x'), false);\n" + C + E, 'partial');
await rlsCase("F06 (negative): pg_dump's set_config('search_path', '', false) with qualified names is clean",
  "SELECT pg_catalog.set_config('search_path', '', false);\nCREATE TABLE public.orders (id serial);\nALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n", 'none');
await rlsCase('F06: an unqualified name under an empty search_path cannot be resolved → partial',
  "SELECT set_config('search_path', '', false);\n" + C + E, 'partial');
await rlsCase('F06: public."a.b" and "public.a".b are different tables',
  'CREATE TABLE public."a.b" (id serial);\nALTER TABLE "public.a".b ENABLE ROW LEVEL SECURITY;\n', 'critical', { title: /a\.b/ });
await rlsCase('F06: "a.b" (one name) and a.b (schema a) are different tables',
  'CREATE TABLE "a.b" (id serial);\nALTER TABLE a.b ENABLE ROW LEVEL SECURITY;\n', 'critical');
await rlsCase('F06 (negative): the same quoted "a.b" enabled under its own name is clean',
  'CREATE TABLE "a.b" (id serial);\nALTER TABLE "a.b" ENABLE ROW LEVEL SECURITY;\n', 'none');
await rlsCase('F06: an unqualified DROP hits the TEMP table; the later DISABLE public.orders is seen',
  C + E + 'CREATE TEMP TABLE orders (id serial);\nDROP TABLE orders;\nALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;\n', 'critical');
await rlsCase('F06 (negative): TEMP shadow + unqualified DROP leaves the protected permanent table alone',
  C + E + 'CREATE TEMP TABLE orders (id serial);\nDROP TABLE orders;\n', 'none');
await rlsCase('F06: a TEMP table created under a guard makes the unqualified DROP ambiguous → warning',
  C + E + "DO $$ BEGIN IF true THEN CREATE TEMP TABLE orders (id int); END IF; END $$;\nDROP TABLE orders;\n", 'warning');

// --- F07: control flow and rollbacks ----------------------------------------
await rlsCase('F07: ENABLE inside BEGIN … ROLLBACK is unconfirmed → warning',
  C + 'BEGIN;\n' + E + 'ROLLBACK;\n', 'warning');
await rlsCase('F07 (negative): ENABLE inside BEGIN … COMMIT is clean',
  C + 'BEGIN;\n' + E + 'COMMIT;\n', 'none');
await rlsCase('F07: START TRANSACTION … ROLLBACK is the same as BEGIN … ROLLBACK',
  C + 'START TRANSACTION;\n' + E + 'ROLLBACK;\n', 'warning');
await rlsCase('F07: a transaction still open at end of file is unconfirmed → warning',
  C + 'BEGIN;\n' + E, 'warning');
await rlsCase('F07: DISABLE undone by ROLLBACK TO SAVEPOINT is neither clean nor confident critical',
  C + 'BEGIN;\n' + E + 'SAVEPOINT s;\n' + D + 'ROLLBACK TO SAVEPOINT s;\nCOMMIT;\n', 'warning');
await rlsCase('F07: ENABLE inside WHILE … LOOP may run zero times → warning',
  C + 'DO $$ BEGIN WHILE false LOOP ALTER TABLE orders ENABLE ROW LEVEL SECURITY; END LOOP; END $$;\n', 'warning');
await rlsCase('F07: ENABLE inside FOR … LOOP is unconfirmed → warning',
  C + 'DO $$ DECLARE i int; BEGIN FOR i IN 1..3 LOOP ALTER TABLE orders ENABLE ROW LEVEL SECURITY; END LOOP; END $$;\n', 'warning');
await rlsCase('F07 (negative): a loop that does not touch RLS creates no doubt',
  C + E + "DO $$ DECLARE i int; BEGIN FOR i IN 1..3 LOOP RAISE NOTICE 'tick'; END LOOP; END $$;\n", 'none');
await rlsCase('F07: ENABLE after RETURN in the same block never runs → warning',
  C + 'DO $$ BEGIN RETURN; ALTER TABLE orders ENABLE ROW LEVEL SECURITY; END $$;\n', 'warning');
await rlsCase('F07 (negative): ENABLE before RETURN is clean',
  C + 'DO $$ BEGIN ALTER TABLE orders ENABLE ROW LEVEL SECURITY; RETURN; END $$;\n', 'none');
await rlsCase('F07: ENABLE in a block with an EXCEPTION section may be rolled back → warning',
  C + 'DO $$ BEGIN ALTER TABLE orders ENABLE ROW LEVEL SECURITY; PERFORM 1/0; EXCEPTION WHEN others THEN NULL; END $$;\n', 'warning');
await rlsCase('F07 (negative): ENABLE after an inner block with its own EXCEPTION section is clean',
  C + 'DO $$ BEGIN BEGIN PERFORM 1; EXCEPTION WHEN others THEN NULL; END; ALTER TABLE orders ENABLE ROW LEVEL SECURITY; END $$;\n', 'none');
await rlsCase('F07 (negative): RAISE EXCEPTION is not an EXCEPTION section',
  C + "DO $$ BEGIN ALTER TABLE orders ENABLE ROW LEVEL SECURITY; IF false THEN RAISE EXCEPTION 'x'; END IF; END $$;\n", 'none');

// --- F08: DROP TABLE takes a list ------------------------------------------
const TWO = 'CREATE TABLE other (id serial);\nALTER TABLE other ENABLE ROW LEVEL SECURITY;\n' + C + E;
await rlsCase('F08: DROP TABLE other, orders drops BOTH; the recreated orders is reported',
  TWO + 'DROP TABLE other, orders;\nCREATE TABLE IF NOT EXISTS orders (id serial);\n', 'critical', { title: /"orders"/ });
await rlsCase('F08 (negative): DROP TABLE other, orders followed by nothing is clean',
  TWO + 'DROP TABLE other, orders;\n', 'none');
await rlsCase('F08 (negative): DROP TABLE IF EXISTS a, b CASCADE parses fully',
  TWO + 'DROP TABLE IF EXISTS other, orders CASCADE;\n', 'none');
await rlsCase('F08: a DROP TABLE tail the analyzer cannot read → partial',
  TWO + 'DROP TABLE other, orders CASCADE CONSTRAINTS;\n', 'partial');

// --- F09: SELECT INTO inside plpgsql is a variable, not a table -------------
await rlsCase('F09: SELECT … INTO a plpgsql variable is not a table',
  'DO $$ DECLARE v integer; BEGIN SELECT 1 INTO v; END $$;\n', 'none');
await rlsCase('F09 (negative): top-level SELECT … INTO still creates a table',
  'SELECT 1 AS id INTO newtable;\n', 'critical', { title: /newtable/ });

// --- F25/F26 (integrator): engine gate and exposure-aware severity ----------
console.log('\nWP sql — F25/F26 engine + exposure');
{
  const D1 = {
    'apps/worker/wrangler.jsonc': '{ "name": "w", "d1_databases": [{ "binding": "DB", "database_name": "app" }] }\n',
    'apps/worker/package.json': '{"name":"w","dependencies":{"hono":"^4"}}\n',
    'apps/worker/schema.sql': 'CREATE TABLE IF NOT EXISTS users (\n  tg_id INTEGER PRIMARY KEY,\n  username TEXT\n);\nCREATE TABLE jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT);\n',
  };
  const dir = fixture(D1);
  const r = await scanStatic(dir);
  const s = summarize(r.findings, r.runs);
  check('F25: a Cloudflare D1 / SQLite schema gets no RLS finding (RLS is PostgreSQL-only)', () => {
    assert.ok(!ids(r).includes('rls_missing'), `got ${ids(r)}`);
  });
  check('F25: the skip is visible as an info finding, and the gate is not failed/incomplete', () => {
    const f = r.findings.find((x) => x.id === 'rls_not_applicable');
    assert.ok(f, `expected rls_not_applicable, got ${ids(r)}`);
    assert.strictEqual(f.severity, 'info');
    assert.match(f.title, /D1|SQLite/);
    assert.ok(s.gate === 'pass' || s.gate === 'warn', `gate was ${s.gate}`);
    assert.strictEqual(r.runs.find((x) => x.id === 'static:rls-migrations')?.status, 'completed');
  });
  rmSync(dir, { recursive: true, force: true });

  // SQLite by dialect alone (no wrangler, no deps) — AUTOINCREMENT without underscore.
  const dir2 = fixture({ 'db/schema.sql': 'CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);\n' });
  const r2 = await scanStatic(dir2);
  check('F25: SQLite dialect markers alone (AUTOINCREMENT, INTEGER PRIMARY KEY) skip the check', () => {
    assert.ok(!ids(r2).includes('rls_missing'), `got ${ids(r2)}`);
    assert.ok(ids(r2).includes('rls_not_applicable'));
  });
  rmSync(dir2, { recursive: true, force: true });

  // Mixed monorepo: only the Postgres file's tables are analyzed.
  const dir3 = fixture({
    'worker/wrangler.toml': '[[d1_databases]]\nbinding = "DB"\n',
    'worker/schema.sql': 'CREATE TABLE cache (k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID;\n',
    'supabase/migrations/001.sql': 'CREATE TABLE public.profiles (id uuid, bio jsonb);\n',
  });
  const r3 = await scanStatic(dir3);
  check('F25: in a mixed monorepo the Postgres schema is still checked and the SQLite one skipped', () => {
    const rls = r3.findings.filter((x) => x.id === 'rls_missing');
    assert.strictEqual(rls.length, 1, `got ${rls.map((f) => f.title)}`);
    assert.match(rls[0].title, /profiles/);
    assert.ok(ids(r3).includes('rls_not_applicable'));
  });
  rmSync(dir3, { recursive: true, force: true });

  // Negative: a Postgres-looking schema with no other signal is still critical (current behaviour).
  const dir4 = fixture({ 'db/1.sql': 'CREATE TABLE public.orders (id serial);\n' });
  const r4 = await scanStatic(dir4);
  check('F25 negative: a Postgres schema with no project signal stays critical', () => {
    assert.strictEqual(r4.findings.find((x) => x.id === 'rls_missing')?.severity, 'critical');
    assert.ok(!ids(r4).includes('rls_not_applicable'));
  });
  rmSync(dir4, { recursive: true, force: true });

  // F26: server-only Postgres → warning with server-only wording; Supabase → critical.
  const dir5 = fixture({ 'package.json': '{"name":"x","dependencies":{"pg":"^8"}}\n', 'db/1.sql': 'CREATE TABLE orders (id serial);\n' });
  const r5 = await scanStatic(dir5);
  check('F26: no RLS on a server-only Postgres (pg, no client data API) is a warning, not critical', () => {
    const f = r5.findings.find((x) => x.id === 'rls_missing');
    assert.ok(f, `got ${ids(r5)}`);
    assert.strictEqual(f.severity, 'warning');
    assert.match(f.title, /server-only/i);
  });
  rmSync(dir5, { recursive: true, force: true });

  const dir6 = fixture({ 'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n', 'db/1.sql': 'CREATE TABLE orders (id serial);\n' });
  const r6 = await scanStatic(dir6);
  check('F26 negative: the same schema behind Supabase stays critical', () => {
    assert.strictEqual(r6.findings.find((x) => x.id === 'rls_missing')?.severity, 'critical');
  });
  rmSync(dir6, { recursive: true, force: true });

  const dir7 = fixture({ 'package.json': '{"name":"x","dependencies":{"pg":"^8"}}\n', 'src/api.ts': 'const u = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;\n', 'db/1.sql': 'CREATE TABLE orders (id serial);\n' });
  const r7 = await scanStatic(dir7);
  check('F26 negative: pg on the server plus an anon key in the client code counts as exposed → critical', () => {
    assert.strictEqual(r7.findings.find((x) => x.id === 'rls_missing')?.severity, 'critical');
  });
  rmSync(dir7, { recursive: true, force: true });
}
