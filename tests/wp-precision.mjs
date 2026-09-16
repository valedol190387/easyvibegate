// Precision regressions from the real-project ground truth (25 projects in
// Pet&Tests): every class that was mostly noise, and the one real leak the
// tool under-reported. Each has its positive and negative half.
import assert from 'node:assert';
import { rmSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { scanStatic } from '../dist/engine/scan.js';
import { summarize, exitCodeFor } from '../dist/engine/report.js';
import { check, fixture, ids, runCli } from './_harness.mjs';

console.log('\nWP precision (real-project ground truth)');

const K = 'sk-proj-aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5';
const git = (dir, ...args) => spawnSync('git', ['-C', dir, '-c', 'user.email=t@t', '-c', 'user.name=t', ...args], { encoding: 'utf8' });
const repo = (files, { commit = [], ignore = '' } = {}) => {
  const dir = fixture({ ...files, ...(ignore ? { '.gitignore': ignore } : {}) });
  git(dir, 'init', '-q');
  if (ignore) git(dir, 'add', '.gitignore');
  for (const f of commit) git(dir, 'add', f);
  if (commit.length || ignore) git(dir, 'commit', '-q', '-m', 'x');
  return dir;
};
const sev = (r, id) => r.findings.filter((f) => f.id === id).map((f) => f.severity);

// --- secrets: severity follows git exposure ---------------------------------
{
  const dir = repo({ '.env': `OPENAI_API_KEY=${K}\n` }, { ignore: '.env\n' });
  const r = await scanStatic(dir);
  check('a vendor key in a GITIGNORED .env is advisory (it is where it belongs)', () => {
    assert.deepStrictEqual(sev(r, 'openai_key'), ['advisory'], `got ${JSON.stringify(sev(r, 'openai_key'))}`);
    assert.strictEqual(summarize(r.findings, r.runs).gate, 'pass');
  });
  rmSync(dir, { recursive: true, force: true });

  const dir2 = repo({ 'src/config.ts': `const key = "${K}";\n` }, { commit: ['src/config.ts'] });
  const r2 = await scanStatic(dir2);
  check('the same key COMMITTED in source stays critical', () => {
    assert.deepStrictEqual(sev(r2, 'openai_key'), ['critical']);
  });
  rmSync(dir2, { recursive: true, force: true });

  const dir3 = repo({ 'src/config.ts': `const key = "${K}";\n` }, { ignore: 'node_modules\n' });
  const r3 = await scanStatic(dir3);
  check('untracked (not ignored) in a repo is capped at warning and says why', () => {
    assert.deepStrictEqual(sev(r3, 'openai_key'), ['warning']);
    assert.match(r3.findings.find((f) => f.id === 'openai_key').detail, /not committed yet/i);
  });
  rmSync(dir3, { recursive: true, force: true });

  const dir4 = fixture({ 'script.py': `KEY = "${K}"\n` });
  const r4 = await scanStatic(dir4);
  check('in a folder that is not a git repo the key is a warning, not critical', () => {
    assert.deepStrictEqual(sev(r4, 'openai_key'), ['warning']);
  });
  rmSync(dir4, { recursive: true, force: true });
}

// --- the real leak: .env.example carrying the live value ----------------------
{
  const dir = repo({ '.env': `OPENAI_API_KEY=${K}\n`, '.env.example': `OPENAI_API_KEY=${K}\n` }, { commit: ['.env.example'], ignore: '.env\n' });
  const r = await scanStatic(dir);
  check('a committed .env.example holding the SAME value as .env is critical', () => {
    const f = r.findings.find((x) => x.file === '.env.example' && x.id === 'openai_key');
    assert.ok(f, `got ${JSON.stringify(r.findings.map((x) => [x.file, x.id, x.severity]))}`);
    assert.strictEqual(f.severity, 'critical');
    assert.match(f.title, /REAL value/);
  });
  rmSync(dir, { recursive: true, force: true });

  const dir2 = repo({ '.env': `OPENAI_API_KEY=${K}\n`, '.env.example': 'OPENAI_API_KEY=sk-proj-your-key-here\n' }, { commit: ['.env.example'], ignore: '.env\n' });
  const r2 = await scanStatic(dir2);
  check('negative: a placeholder in .env.example is not reported', () => {
    assert.ok(!r2.findings.some((x) => x.file === '.env.example' && x.severity !== 'info'), JSON.stringify(r2.findings.map((x) => [x.file, x.id, x.severity])));
  });
  rmSync(dir2, { recursive: true, force: true });
}

// --- generic_secret: cursors and cached API responses are not secrets --------
{
  const rnd = 'GU1VbXk3QzR0Zks5THN6UDhtWDJhSjZ2ECA';
  const dir = fixture({
    'src/api.json': `{"node":{"tracking_token":"${rnd}"},"pagination_token":"${rnd}","request_id":"${rnd}"}\n`,
    'src/keys.ts': `const cfg = { api_key: "${rnd}" };\n`,
    'data/cache/abc.json': `{"api_key":"${rnd}"}\n`,
  });
  const r = await scanStatic(dir);
  check('tracking/pagination tokens are not generic secrets; a real api_key still is', () => {
    const files = r.findings.filter((f) => f.id === 'generic_secret').map((f) => f.file);
    assert.deepStrictEqual(files, ['src/keys.ts'], `got ${files}`);
  });
  check('data/cache is not scanned at all', () => {
    assert.ok(!r.files.some((f) => f.rel.startsWith('data/cache/')));
  });
  rmSync(dir, { recursive: true, force: true });

  const dir2 = fixture({ 'src/img.ts': 'const token = "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB";\n' });
  const r2 = await scanStatic(dir2);
  check('a base64 image blob assigned to "token" is not a secret', () => {
    assert.ok(!ids(r2).includes('generic_secret'), `got ${ids(r2)}`);
  });
  rmSync(dir2, { recursive: true, force: true });
}

// --- db_url_password: local default credentials ------------------------------
{
  const dir = repo({
    'docker-compose.yml': 'services:\n  web:\n    environment:\n      DATABASE_URL: postgresql://opencut:opencut@db:5432/opencut\n',
    'ci.yml': 'env:\n  DATABASE_URL: postgresql://app:postgres@localhost:5432/app\n',
  }, { commit: ['docker-compose.yml', 'ci.yml'] });
  const r = await scanStatic(dir);
  check('password == user, or a default password on a local host, is not a leak', () => {
    assert.ok(!ids(r).includes('db_url_password'), `got ${ids(r)}`);
  });
  rmSync(dir, { recursive: true, force: true });

  const dir2 = repo({ 'deploy.yml': 'env:\n  DATABASE_URL: postgresql://app:Qx9vT2kLm8pR4sW7@prod-db.internal:5432/app\n' }, { commit: ['deploy.yml'] });
  const r2 = await scanStatic(dir2);
  check('negative: a real password on a real host, committed, is still critical', () => {
    assert.deepStrictEqual(sev(r2, 'db_url_password'), ['critical'], `got ${JSON.stringify(r2.findings.map((f) => [f.id, f.severity]))}`);
  });
  rmSync(dir2, { recursive: true, force: true });
}

// --- sql_interpolation: structure vs value ----------------------------------
{
  const dir = fixture({
    'a.ts': 'db.prepare(`UPDATE clients SET ${set} WHERE id = ?`);\n',
    'b.ts': 'db.prepare(`SELECT COUNT(*) c FROM ${t}`);\n',
    'c.ts': 'db.prepare(`INSERT INTO clients (${cols.join(", ")}) VALUES (${placeholders})`);\n',
    'd.ts': 'execSql(`SELECT id FROM products WHERE id = ${id}`);\n',
    'e.py': 'q = f"SELECT * FROM users WHERE name LIKE {pattern}"\n',
  });
  const r = await scanStatic(dir);
  const by = Object.fromEntries(r.findings.filter((f) => f.id === 'sql_interpolation').map((f) => [f.file, f.severity]));
  check('identifier/operator splices with parameterized values are info, not injection warnings', () => {
    assert.strictEqual(by['a.ts'], 'info', JSON.stringify(by));
    assert.strictEqual(by['b.ts'], 'info', JSON.stringify(by));
    assert.strictEqual(by['c.ts'], 'info', JSON.stringify(by));
  });
  check('negative: a VALUE spliced into WHERE / LIKE is still a warning', () => {
    assert.strictEqual(by['d.ts'], 'warning', JSON.stringify(by));
    assert.strictEqual(by['e.py'], 'warning', JSON.stringify(by));
  });
  rmSync(dir, { recursive: true, force: true });
}

// --- eval: the global, not a method ------------------------------------------
{
  const dir = fixture({ 'm.py': '_model.eval()\nresult = eval(user_input)\n', 'x.ts': 'const r = obj.eval(a); const s = eval(b);\n' });
  const r = await scanStatic(dir);
  check('model.eval() / obj.eval() are not flagged; bare eval( still is (one per file)', () => {
    const ev = r.findings.filter((f) => f.id === 'eval_use').map((f) => `${f.file}:${f.line}`).sort();
    assert.deepStrictEqual(ev, ['m.py:2', 'x.ts:1'], `got ${ev}`);
  });
  rmSync(dir, { recursive: true, force: true });
}

// --- score: a grade, not a body count -----------------------------------------
{
  const many = Array.from({ length: 200 }, (_, i) => ({ id: 'x', severity: 'warning', title: 't', detail: 'd', fix: 'f', checker: 'c', level: 0, file: `f${i}.ts`, line: 1 }));
  const s = summarize(many, [{ id: 'static:x', level: 0, status: 'completed' }]);
  check('200 warnings do not zero the score (capped), but the count is kept', () => {
    assert.ok(s.score >= 60, `score ${s.score}`);
    assert.strictEqual(s.counts.warning, 200);
    assert.strictEqual(s.gate, 'warn');
  });
  const crit = Array.from({ length: 6 }, (_, i) => ({ ...many[0], severity: 'critical', file: `c${i}.ts` }));
  const s2 = summarize(crit, [{ id: 'static:x', level: 0, status: 'completed' }]);
  check('negative: criticals can still take the score to 0', () => {
    assert.strictEqual(s2.score, 0);
    assert.strictEqual(s2.gate, 'fail');
  });
}

// --- from a real agent review of a report (Meditation project) --------------
{
  // The report itself named secret prefixes, a DB host and 141 endpoints — and
  // the report directory was not gitignored. It now ignores itself.
  const dir = repo({ 'index.ts': 'const a = 1;\n' }, { commit: ['index.ts'] });
  const out = join(dir, 'easyvibegate-report');
  const p = spawnSync(process.execPath, [new URL('../dist/cli/index.js', import.meta.url).pathname, dir, '--no-wizard', '--format', 'json'], { encoding: 'utf8' });
  check('the report directory writes a .gitignore that ignores itself', () => {
    assert.strictEqual(p.status, 0, p.stderr);
    const ig = spawnSync('git', ['-C', dir, 'check-ignore', '-q', 'easyvibegate-report/report.json']);
    assert.strictEqual(ig.status, 0, 'report.json should be ignored by git');
    const st = spawnSync('git', ['-C', dir, 'status', '--porcelain'], { encoding: 'utf8' }).stdout;
    assert.ok(!/easyvibegate-report/.test(st), `report dir shows up in git status: ${st}`);
  });
  rmSync(dir, { recursive: true, force: true });

  // "anon can read every row" understated it: with RLS off the anon role can
  // also write. The finding must say so and offer the interim REVOKE.
  const dir2 = fixture({ 'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n', 'db/1.sql': 'CREATE TABLE orders (id serial);\n' });
  const r2 = await scanStatic(dir2);
  check('the RLS finding says the anon key can WRITE, names the static-only scope, and gives an interim REVOKE', () => {
    const f = r2.findings.find((x) => x.id === 'rls_missing');
    assert.ok(f);
    assert.match(f.detail, /INSERT, UPDATE and DELETE/);
    assert.match(f.detail, /Static view only/);
    assert.match(f.fix, /REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON orders FROM anon/);
  });
  rmSync(dir2, { recursive: true, force: true });

  // A prod DB password inside a gitignored tool config (.claude/settings.local.json)
  // was an advisory. Gitignored .env stays advisory; any other gitignored file is a warning.
  const dir3 = repo({
    '.claude/settings.local.json': '{"permissions":{"allow":["Bash(PGPASSWORD=Qx9vT2kLm8pR4sW7 psql -h prod-db.internal -U app)"]}}\n',
    '.env': 'DATABASE_URL=postgresql://app:Qx9vT2kLm8pR4sW7@prod-db.internal:5432/app\n',
  }, { ignore: '.claude/settings.local.json\n.env\n' });
  const r3 = await scanStatic(dir3);
  check('a credential in a gitignored NON-env file is a warning; the gitignored .env stays advisory', () => {
    const settings = r3.findings.filter((x) => x.file === '.claude/settings.local.json');
    const envf = r3.findings.filter((x) => x.file === '.env' && x.id === 'db_url_password');
    assert.ok(settings.length > 0, `nothing reported for settings.local.json: ${JSON.stringify(r3.findings.map((x) => [x.file, x.id, x.severity]))}`);
    assert.ok(settings.every((x) => x.severity === 'warning'), JSON.stringify(settings.map((x) => [x.id, x.severity])));
    assert.deepStrictEqual(envf.map((x) => x.severity), ['advisory']);
  });
  rmSync(dir3, { recursive: true, force: true });
}

// --- eleven "secret in gitignored .env" lines are one observation -------------
{
  const dir = repo({ '.env.local': 'JWT_SECRET=Qx9vT2kLm8pR4sW7Zc3Bn6\nADMIN_PASSWORD=Hk4mP9sD2fG7jL1qW5\nCRON_SECRET=Rt6yU8iO3pA5sD7fG9h\n' }, { ignore: '.env.local\n' });
  const r = await scanStatic(dir);
  check('several name-based secrets in one gitignored .env fold into a single advisory naming the variables', () => {
    const env = r.findings.filter((f) => f.file === '.env.local' && f.id === 'env_secret');
    assert.strictEqual(env.length, 1, JSON.stringify(env.map((f) => [f.severity, f.title])));
    assert.strictEqual(env[0].severity, 'advisory');
    assert.match(env[0].title, /3 secrets in \.env\.local/);
    assert.match(env[0].detail, /JWT_SECRET, ADMIN_PASSWORD, CRON_SECRET/);
  });
  rmSync(dir, { recursive: true, force: true });

  // Negative: committed .env secrets are NOT folded — each one is a real leak line.
  const dir2 = repo({ '.env': 'JWT_SECRET=Qx9vT2kLm8pR4sW7Zc3Bn6\nADMIN_PASSWORD=Hk4mP9sD2fG7jL1qW5\n' }, { commit: ['.env'] });
  const r2 = await scanStatic(dir2);
  check('negative: secrets in a COMMITTED .env stay one warning per line', () => {
    const env = r2.findings.filter((f) => f.file === '.env' && f.id === 'env_secret');
    assert.strictEqual(env.length, 2, JSON.stringify(env.map((f) => [f.severity, f.title])));
    assert.ok(env.every((f) => f.severity === 'warning'));
  });
  rmSync(dir2, { recursive: true, force: true });
}

// --- from thinking through untested stacks before wider release --------------
console.log('\nWP precision (untested stacks, self-review)');
{
  // Monorepo: the SQLite/D1 signal lives in a SUBPACKAGE's package.json, not the
  // workspace root. Reading only the root file missed it whenever the SQL text
  // itself carried no dialect marker either — defaulting to Postgres and
  // producing a phantom critical on a database that has no RLS to enable.
  const dir = fixture({
    'package.json': '{"name":"monorepo","private":true,"workspaces":["apps/*"]}\n',
    'apps/worker/package.json': '{"name":"worker","dependencies":{"better-sqlite3":"^11.0.0"}}\n',
    'apps/worker/db/schema.sql': 'CREATE TABLE items (id INTEGER, name TEXT);\n',
  });
  const r = await scanStatic(dir);
  check('a SQLite dep declared only in a subpackage package.json still skips RLS (no phantom critical)', () => {
    assert.ok(!ids(r).includes('rls_missing'), `got ${ids(r)}`);
    assert.ok(ids(r).includes('rls_not_applicable'), `expected the skip to be visible, got ${ids(r)}`);
  });
  rmSync(dir, { recursive: true, force: true });

  // Same shape, no sqlite signal anywhere: stays the documented default (Postgres, critical).
  const dir2 = fixture({
    'package.json': '{"name":"monorepo","private":true}\n',
    'apps/worker/db/schema.sql': 'CREATE TABLE items (id INTEGER, name TEXT);\n',
  });
  const r2 = await scanStatic(dir2);
  check('negative: with no engine signal anywhere the ambiguous schema is still Postgres/critical', () => {
    assert.strictEqual(r2.findings.find((f) => f.id === 'rls_missing')?.severity, 'critical');
  });
  rmSync(dir2, { recursive: true, force: true });
}

{
  // A directory literally named "cache" nested under real source (not a top-level
  // data folder) is ordinary code. Skipping ambiguous names at ANY depth once
  // made a whole source subtree invisible to every static check, silently.
  const rnd = 'aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5';
  const dir = fixture({ 'src/lib/cache/keys.ts': `const apiSecret = "${rnd}";\n` });
  const r = await scanStatic(dir);
  check('a "cache" directory nested under source (depth ≥ 2) is still scanned', () => {
    assert.ok(r.files.some((f) => f.rel === 'src/lib/cache/keys.ts'), 'file was invisible to the walk');
    assert.ok(ids(r).includes('generic_secret'), `got ${ids(r)}`);
  });
  rmSync(dir, { recursive: true, force: true });
}

{
  // A Supabase project that ships no .sql migrations at all (schema managed from
  // the dashboard) used to say nothing about RLS — a silent, undeserved clean
  // score on the exact check this tool exists for. This IS the "unknown must
  // not read as clean" case (unlike the SQLite/D1 skip, which genuinely does
  // not apply): the check applies but could not run, so it must reduce
  // coverage, not just add an info line next to an otherwise-green gate.
  const dir = fixture({ 'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n', 'src/x.ts': 'export const x = 1;\n' });
  const r = await scanStatic(dir);
  const s = summarize(r.findings, r.runs);
  check('a Supabase project with zero SQL migrations reports the gap AND makes coverage incomplete', () => {
    assert.ok(ids(r).includes('rls_unverifiable_no_migrations'), `got ${ids(r)}`);
    assert.strictEqual(r.runs.find((x) => x.id === 'static:rls-migrations')?.status, 'partial');
    assert.strictEqual(s.gate, 'incomplete', 'a genuinely unverified check must not leave the gate at pass');
    assert.strictEqual(exitCodeFor(s), 3);
  });
  rmSync(dir, { recursive: true, force: true });

  // Negative: a plain project with no backend signal and no SQL stays silent.
  const dir2 = fixture({ 'src/x.ts': 'export const x = 1;\n' });
  const r2 = await scanStatic(dir2);
  check('negative: a non-Supabase project with no SQL says nothing about RLS', () => {
    assert.ok(!ids(r2).some((id) => id.startsWith('rls_')), `got ${ids(r2)}`);
  });
  rmSync(dir2, { recursive: true, force: true });
}

// --- ReDoS: a large file must never hang the whole scan ----------------------
// discoverFirebase/discoverSupabase/detect run on every file's raw content on
// every scan. An unbounded `[a-z0-9-]+` right before a literal host suffix
// (`.firebaseapp.com`, `.supabase.co`) is quadratic: at every position inside a
// long run of matching characters (a minified bundle, a base64 blob, a lockfile
// hash) the engine consumes to the end and backtracks one char at a time. A
// single 500KB matching run took over two minutes before this was bounded —
// this is almost certainly what an earlier "everything just hangs" report was.
{
  const { discoverFirebase } = await import('../dist/engine/checkers/backend/firebase.js');
  const { discoverSupabase } = await import('../dist/engine/checkers/backend/supabase.js');
  const { detect } = await import('../dist/engine/detect.js');
  const big = 'a'.repeat(500000); // no literal host suffix anywhere — worst case: never matches
  const files = [{ rel: 'big.js', content: big }];
  const budgetMs = 2000; // generous; a fixed regime should finish in single-digit ms

  check('discoverFirebase does not go quadratic on a large file with no match', () => {
    const t0 = Date.now();
    discoverFirebase(files);
    assert.ok(Date.now() - t0 < budgetMs, `took ${Date.now() - t0}ms`);
  });
  check('discoverSupabase does not go quadratic on a large file with no match', () => {
    const t0 = Date.now();
    discoverSupabase(files);
    assert.ok(Date.now() - t0 < budgetMs, `took ${Date.now() - t0}ms`);
  });
  check('detect() does not go quadratic on a large file with no match', () => {
    const t0 = Date.now();
    detect('/tmp', files.map((f) => ({ abs: '/tmp/big.js', rel: f.rel, content: f.content, ext: '.js', size: f.content.length })));
    assert.ok(Date.now() - t0 < budgetMs, `took ${Date.now() - t0}ms`);
  });

  // Negative: a real, legitimately long Firebase host is still recognized.
  const real = discoverFirebase([{ rel: 'firebase.ts', content: 'projectId: "my-app-12345", databaseURL: "https://my-app-12345-default-rtdb.firebaseio.com"' }]);
  check('negative: a real (short, legitimate) Firebase host is still discovered after bounding the regex', () => {
    assert.ok(real, 'discoverFirebase returned null for a valid config');
    assert.strictEqual(real.projectId, 'my-app-12345');
  });
}

// --- code-review fixes: --output must never be able to clobber the project ---
{
  const dir = repo({ 'index.ts': 'const a = 1;\n', '.gitignore': 'node_modules\n' }, {});
  const before = readFileSync(join(dir, '.gitignore'), 'utf8');
  const p = runCli([dir, '--no-wizard', '--format', 'none', '--output', dir]);
  check('--output pointing at the project root is refused, not silently applied', () => {
    assert.strictEqual(p.status, 2, `expected exit 2, got ${p.status}: ${p.stderr}`);
    assert.match(p.stderr, /must not be the scanned project itself/);
  });
  check('the project\'s real .gitignore is untouched after the refusal', () => {
    assert.strictEqual(readFileSync(join(dir, '.gitignore'), 'utf8'), before);
  });
  rmSync(dir, { recursive: true, force: true });

  // Negative: a subdirectory --output still works exactly as before.
  const dir2 = fixture({ 'index.ts': 'const a = 1;\n' });
  const p2 = runCli([dir2, '--no-wizard', '--format', 'json', '--output', join(dir2, 'reports')]);
  check('negative: --output at a subdirectory of the project still succeeds', () => {
    assert.strictEqual(p2.status, 0, p2.stderr);
    assert.ok(existsSync(join(dir2, 'reports', 'report.json')));
  });
  rmSync(dir2, { recursive: true, force: true });
}

// --- code-review fixes: INLINE_ENV matches bare names and common punctuation -
{
  const dir = fixture({
    '.claude/settings.local.json': '{"permissions":{"allow":["Bash(PGPASSWORD=Qx9vT2kLm8pR4sW7 psql -h prod-db.internal -U postgres)"]}}\n',
    'deploy.sh': 'export TOKEN=aB3dE5fG7hJ9kL1mN3pQ5rS7;\necho done\n',
    'run.js': 'foo(SECRET=sk_live_aB3dE5fG7hJ9kL1mN3,1);\n',
  });
  const r = await scanStatic(dir);
  check('a bare-named inline secret ("TOKEN=...;") followed by a semicolon is caught', () => {
    assert.ok(r.findings.some((f) => f.file === 'deploy.sh' && f.id === 'env_secret'), JSON.stringify(ids(r)));
  });
  check('an inline secret inside a function call, followed by a comma, is caught', () => {
    assert.ok(r.findings.some((f) => f.file === 'run.js' && f.id === 'env_secret'), JSON.stringify(ids(r)));
  });
  check('a real prod password inside a permission rule (parenthesis-terminated) is still caught', () => {
    assert.ok(r.findings.some((f) => f.file === '.claude/settings.local.json'), JSON.stringify(ids(r)));
  });
  rmSync(dir, { recursive: true, force: true });
}

// --- code-review fixes: folding must not defeat a line-scoped ignore comment -
{
  const dir = fixture({
    '.env.local': [
      'AAA_SECRET=Qx9vT2kLm8pR4sW7Zc3Bn6',
      '# easyvibegate-ignore',
      'BBB_SECRET=Hk4mP9sD2fG7jL1qW5xR8',
      'CCC_SECRET=Rt6yU8iO3pA5sD7fG9hJ2',
      '',
    ].join('\n'),
  }, {});
  const r = await scanStatic(dir);
  const env = r.findings.filter((f) => f.file === '.env.local' && f.id === 'env_secret');
  check('a secret with an inline ignore comment above it is dropped even when its neighbors get folded', () => {
    assert.ok(!env.some((f) => /BBB_SECRET/.test(f.detail)), `BBB_SECRET should be ignored: ${JSON.stringify(env.map((f) => f.detail))}`);
  });
  check('the remaining two secrets still fold into one summary naming only them', () => {
    assert.strictEqual(env.length, 1, JSON.stringify(env));
    assert.match(env[0].title, /2 secrets/);
    assert.match(env[0].detail, /AAA_SECRET/);
    assert.match(env[0].detail, /CCC_SECRET/);
    assert.ok(!/BBB_SECRET/.test(env[0].detail));
  });
  rmSync(dir, { recursive: true, force: true });

  // Negative: with no ignore comment at all, all three still fold together as before.
  const dir2 = fixture({
    '.env.local': 'AAA_SECRET=Qx9vT2kLm8pR4sW7Zc3Bn6\nBBB_SECRET=Hk4mP9sD2fG7jL1qW5xR8\nCCC_SECRET=Rt6yU8iO3pA5sD7fG9hJ2\n',
  });
  const r2 = await scanStatic(dir2);
  const env2 = r2.findings.filter((f) => f.file === '.env.local' && f.id === 'env_secret');
  check('negative: with no ignore comment, all three secrets fold into one summary', () => {
    assert.strictEqual(env2.length, 1, JSON.stringify(env2));
    assert.match(env2[0].title, /3 secrets/);
  });
  rmSync(dir2, { recursive: true, force: true });
}

// --- from a second external re-check of the review fixes ---------------------
console.log('\nWP precision (re-check of the code-review fixes)');

// --output must never touch a directory it did not create, anywhere it points.
{
  const dir = fixture({ 'index.ts': 'const a = 1;\n', 'docs/.gitignore': 'drafts/\nnotes.md\n', 'docs/report.md': 'my important draft doc\n' });
  const before = readFileSync(join(dir, 'docs', '.gitignore'), 'utf8');
  const p = runCli([dir, '--no-wizard', '--format', 'json', '--output', join(dir, 'docs')]);
  check('--output at an existing, non-empty, non-EasyVibeGate directory is refused', () => {
    assert.strictEqual(p.status, 2, `expected exit 2, got ${p.status}: ${p.stderr}`);
    assert.match(p.stderr, /was not created by a previous EasyVibeGate run/);
  });
  check('the real docs/.gitignore and docs/report.md are untouched after the refusal', () => {
    assert.strictEqual(readFileSync(join(dir, 'docs', '.gitignore'), 'utf8'), before);
    assert.strictEqual(readFileSync(join(dir, 'docs', 'report.md'), 'utf8'), 'my important draft doc\n');
  });
  rmSync(dir, { recursive: true, force: true });

  // Negative: re-running against a directory EasyVibeGate itself created is still fine.
  const dir2 = fixture({ 'index.ts': 'const a = 1;\n' });
  const out = join(dir2, 'reports');
  const p1 = runCli([dir2, '--no-wizard', '--format', 'json', '--output', out]);
  const p2 = runCli([dir2, '--no-wizard', '--format', 'json', '--output', out]);
  check('negative: reusing a directory from a PREVIOUS EasyVibeGate run still succeeds', () => {
    assert.strictEqual(p1.status, 0, p1.stderr);
    assert.strictEqual(p2.status, 0, p2.stderr);
  });
  rmSync(dir2, { recursive: true, force: true });
}

// A "cache"/"tmp" directory under an ordinary source root is not data.
{
  const rnd = 'GU1VbXk3QzR0Zks5THN6UDhtWDJhSjZ2ECA';
  const dir = fixture({
    'src/cache/index.ts': 'const opts = { algorithm: "none" };\n',
    'var/tmp/x.json': `{"pagination_token":"${rnd}"}\n`,
  });
  const r = await scanStatic(dir);
  check('src/cache (parent is an ordinary source root) is scanned, not skipped', () => {
    assert.ok(r.files.some((f) => f.rel === 'src/cache/index.ts'), 'src/cache/index.ts was invisible to the walk');
    assert.ok(ids(r).includes('jwt_alg_none'), `got ${ids(r)}`);
  });
  check('negative: var/tmp (a data-ish parent, same depth as data/cache) is still excluded', () => {
    assert.ok(!r.files.some((f) => f.rel.startsWith('var/tmp/')));
  });
  rmSync(dir, { recursive: true, force: true });
}

// The RLS fix text must not assume an `anon` role exists where there is none.
{
  const dir = fixture({ 'package.json': '{"name":"x","dependencies":{"pg":"^8"}}\n', 'db/1.sql': 'CREATE TABLE orders (id serial);\n' });
  const r = await scanStatic(dir);
  const f = r.findings.find((x) => x.id === 'rls_missing');
  check('a server-only Postgres warning does not tell the user to revoke privileges from a role ("anon") that does not exist', () => {
    assert.ok(f);
    assert.ok(!/FROM anon/.test(f.fix), `fix still mentions anon: ${f.fix}`);
    assert.match(f.fix, /No action needed unless/);
  });
  rmSync(dir, { recursive: true, force: true });

  const dir2 = fixture({ 'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n', 'db/1.sql': 'CREATE TABLE orders (id serial);\n' });
  const r2 = await scanStatic(dir2);
  const f2 = r2.findings.find((x) => x.id === 'rls_missing');
  check('negative: an exposed Supabase project still gets the concrete REVOKE FROM anon step', () => {
    assert.ok(f2);
    assert.match(f2.fix, /REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON orders FROM anon/);
  });
  rmSync(dir2, { recursive: true, force: true });
}

// A tool's own test suite / comments describing a backend must not make the
// project itself look like it uses that backend (dogfooding on EasyVibeGate's
// own repo found this twice: a literal mock URL in tests/, then the same
// literal in an explanatory source comment).
{
  const dir = fixture({
    'tests/supabase.test.ts': 'const url = "https://p.supabase.co"; // mock\n',
    'src/detect.ts': '// A real URL looks like https://p.supabase.co — do not match one here.\nexport const x = 1;\n',
    'db/1.sql': 'CREATE TABLE orders (id serial);\nALTER TABLE orders ENABLE ROW LEVEL SECURITY;\n',
  });
  const r = await scanStatic(dir);
  check('a mock URL in a test file does not make the project look like it uses that backend', () => {
    assert.ok(!r.detection.backends.includes('supabase'), `backends: ${JSON.stringify(r.detection.backends)}`);
  });
  check('the same URL shape inside a source comment (not a string) does not either', () => {
    assert.ok(!r.detection.backends.includes('supabase'), `backends: ${JSON.stringify(r.detection.backends)}`);
  });
  rmSync(dir, { recursive: true, force: true });

  // Negative: the same URL as a real, non-test, non-comment value is still detected.
  const dir2 = fixture({ 'src/config.ts': 'export const url = "https://p.supabase.co";\n' });
  const r2 = await scanStatic(dir2);
  check('negative: a real Supabase URL in ordinary source is still detected', () => {
    assert.ok(r2.detection.backends.includes('supabase'), `backends: ${JSON.stringify(r2.detection.backends)}`);
  });
  rmSync(dir2, { recursive: true, force: true });
}

// A .sql file existing is not the same as it defining a schema — a maintenance
// query or a seed script with no CREATE TABLE must not silence the "could not
// verify RLS" signal any more than having zero .sql files does.
{
  const dir = fixture({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n',
    'maintenance.sql': 'SELECT now();\n',
  });
  const r = await scanStatic(dir);
  const s = summarize(r.findings, r.runs);
  check('a .sql file with no CREATE TABLE (a maintenance query) still reports the coverage gap', () => {
    assert.ok(ids(r).includes('rls_unverifiable_no_migrations'), `got ${ids(r)}`);
    assert.strictEqual(s.gate, 'incomplete');
    assert.strictEqual(exitCodeFor(s), 3);
  });
  rmSync(dir, { recursive: true, force: true });

  const dir2 = fixture({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n',
    'supabase/seed.sql': 'INSERT INTO public.orders(id) VALUES (1);\n',
  });
  const r2 = await scanStatic(dir2);
  check('a seed.sql with no CREATE TABLE (schema made from the dashboard) also reports the gap', () => {
    assert.ok(ids(r2).includes('rls_unverifiable_no_migrations'), `got ${ids(r2)}`);
    assert.strictEqual(summarize(r2.findings, r2.runs).gate, 'incomplete');
  });
  rmSync(dir2, { recursive: true, force: true });

  // Negative: a real CREATE TABLE with RLS enabled is genuinely clean — no gap reported.
  const dir3 = fixture({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n',
    'db/1.sql': 'CREATE TABLE orders (id serial);\nALTER TABLE orders ENABLE ROW LEVEL SECURITY;\n',
  });
  const r3 = await scanStatic(dir3);
  check('negative: a real, RLS-enabled table is a genuine clean result, not an unverifiable gap', () => {
    assert.ok(!ids(r3).includes('rls_unverifiable_no_migrations'), `got ${ids(r3)}`);
    assert.strictEqual(summarize(r3.findings, r3.runs).gate, 'pass');
  });
  rmSync(dir3, { recursive: true, force: true });

  // Negative: a real CREATE TABLE missing RLS still reports the REAL finding, not the gap.
  const dir4 = fixture({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n',
    'db/1.sql': 'CREATE TABLE orders (id serial);\n',
  });
  const r4 = await scanStatic(dir4);
  check('negative: a real table missing RLS reports rls_missing, not the coverage-gap finding', () => {
    assert.ok(ids(r4).includes('rls_missing'));
    assert.ok(!ids(r4).includes('rls_unverifiable_no_migrations'), `got ${ids(r4)}`);
  });
  rmSync(dir4, { recursive: true, force: true });
}

// A TEMP table's own CREATE does not count as "we learned the schema" — it is
// session-only, excluded from findings for the same reason. A migration that
// only touches a TEMP staging table (even one that also DISABLEs RLS on a
// persistent table this repo never defines) must not silence the gap either.
{
  const dir = fixture({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n',
    'supabase/seed.sql': 'CREATE TEMP TABLE staging(id uuid);\n',
  });
  const r = await scanStatic(dir);
  check('a TEMP-table-only migration still reports the coverage gap, not a clean pass', () => {
    assert.ok(ids(r).includes('rls_unverifiable_no_migrations'), `got ${ids(r)}`);
    assert.strictEqual(summarize(r.findings, r.runs).gate, 'incomplete');
  });
  rmSync(dir, { recursive: true, force: true });

  const dir2 = fixture({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n',
    'supabase/seed.sql': 'CREATE TEMP TABLE staging(id uuid);\nALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;\n',
  });
  const r2 = await scanStatic(dir2);
  check('the same, plus a DISABLE on a table never defined locally, reports THAT specific table (not just the generic gap)', () => {
    // The unified per-table model (0.6.7) reports the real, specific finding
    // instead of falling back to the generic "no schema learned" message —
    // strictly more informative than the earlier fix's fallback-only result.
    const f = r2.findings.find((x) => x.id === 'rls_missing');
    assert.ok(f, `got ${ids(r2)}`);
    assert.match(f.title, /orders.*never created in this repo/);
    assert.strictEqual(summarize(r2.findings, r2.runs).gate, 'warn');
  });
  rmSync(dir2, { recursive: true, force: true });

  // Negative: a TEMP table alongside a REAL persistent one still finds the real one.
  const dir3 = fixture({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n',
    'db/1.sql': 'CREATE TEMP TABLE staging(id uuid);\nCREATE TABLE orders (id serial);\n',
  });
  const r3 = await scanStatic(dir3);
  check('negative: a real permanent table alongside a TEMP one is still found and reported', () => {
    assert.ok(ids(r3).includes('rls_missing'), `got ${ids(r3)}`);
    assert.ok(!ids(r3).includes('rls_unverifiable_no_migrations'));
  });
  rmSync(dir3, { recursive: true, force: true });
}

// A Supabase project whose only local .sql is a foreign-engine file (SQLite,
// MySQL) has learned nothing about its real Postgres schema either — that
// engine's files being "not applicable" must not silence the separate,
// still-true fact that Postgres schema info is missing for this project.
{
  const dir = fixture({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n',
    'local-cache.sql': 'CREATE TABLE cache(id INTEGER PRIMARY KEY AUTOINCREMENT);\n',
  });
  const r = await scanStatic(dir);
  check('a Supabase project whose only .sql is a SQLite file reports BOTH the skip and the coverage gap', () => {
    assert.ok(ids(r).includes('rls_not_applicable'), `got ${ids(r)}`);
    assert.ok(ids(r).includes('rls_unverifiable_no_migrations'), `got ${ids(r)}`);
    assert.strictEqual(summarize(r.findings, r.runs).gate, 'incomplete');
  });
  rmSync(dir, { recursive: true, force: true });

  // Negative: a genuinely SQLite-only project (no Supabase anywhere) is
  // unaffected — the skip note alone, gate stays pass, as before.
  const dir2 = fixture({ 'local-cache.sql': 'CREATE TABLE cache(id INTEGER PRIMARY KEY AUTOINCREMENT);\n' });
  const r2 = await scanStatic(dir2);
  check('negative: a plain SQLite-only project (no Supabase) still just gets the skip note, gate pass', () => {
    assert.ok(ids(r2).includes('rls_not_applicable'));
    assert.ok(!ids(r2).includes('rls_unverifiable_no_migrations'), `got ${ids(r2)}`);
    assert.strictEqual(summarize(r2.findings, r2.runs).gate, 'pass');
  });
  rmSync(dir2, { recursive: true, force: true });
}

// An explicit DISABLE, sitting right in a scanned migration, on a table this
// repo never shows being created must not vanish just because another table
// IN THE SAME FILE was found — that satisfied the project-level "learned
// something" check while the dangerous instruction next to it went unseen.
{
  const dir = fixture({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n',
    'db/1.sql': 'CREATE TABLE public.notes(id uuid);\nALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\nALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;\n',
  });
  const r = await scanStatic(dir);
  const s = summarize(r.findings, r.runs);
  check('a DISABLE on a table never created locally is reported, even next to a clean known table', () => {
    const f = r.findings.find((x) => x.id === 'rls_missing' && /orders/.test(x.title));
    assert.ok(f, `got ${JSON.stringify(r.findings.map((x) => [x.id, x.title]))}`);
    assert.strictEqual(f.severity, 'warning');
    assert.match(f.title, /never created in this repo/);
    assert.strictEqual(s.gate, 'warn');
  });
  rmSync(dir, { recursive: true, force: true });

  // Negative: an ENABLE (not disable) on an unmanaged table is the expected,
  // safe shape and must not be flagged.
  const dir2 = fixture({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n',
    'db/1.sql': 'CREATE TABLE public.notes(id uuid);\nALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\nALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n',
  });
  const r2 = await scanStatic(dir2);
  check('negative: an ENABLE on a table never created locally is not flagged', () => {
    assert.ok(!r2.findings.some((f) => /orders/.test(f.title ?? '')), JSON.stringify(r2.findings.map((f) => f.title)));
    assert.strictEqual(summarize(r2.findings, r2.runs).gate, 'pass');
  });
  rmSync(dir2, { recursive: true, force: true });

  // Negative: a table that IS created locally still uses the normal path
  // (critical, not this warning), even when disabled after being enabled.
  const dir3 = fixture({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n',
    'db/1.sql': 'CREATE TABLE public.orders(id uuid);\nALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;\n',
  });
  const r3 = await scanStatic(dir3);
  check('negative: a DISABLE on a table created in THIS file stays the normal critical finding', () => {
    const f = r3.findings.find((x) => x.id === 'rls_missing');
    assert.ok(f);
    assert.strictEqual(f.severity, 'critical');
    assert.ok(!/never created in this repo/.test(f.title));
  });
  rmSync(dir3, { recursive: true, force: true });
}

// F01 (0.6.7): the per-table model is unified — DROP, RENAME, guards and
// cross-directory order apply the SAME way to a table this repo never
// creates as they already did to one it does. A second, separate model for
// "external" tables (0.6.6) did not know any of that on its own.
{
  // A table created, disabled, then DROPped is known and gone — not a warning.
  const dir = fixture({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n',
    'db/1.sql': 'CREATE TABLE public.orders(id uuid);\nALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;\nDROP TABLE public.orders;\n',
  });
  const r = await scanStatic(dir);
  check('F01: CREATE, DISABLE, then DROP is a clean pass — the table no longer exists', () => {
    assert.ok(!ids(r).includes('rls_missing'), `got ${JSON.stringify(r.findings.map((f) => f.title))}`);
  });
  rmSync(dir, { recursive: true, force: true });

  // A table created, disabled, renamed, then re-enabled under the new name is clean.
  const dir2 = fixture({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n',
    'db/1.sql': 'CREATE TABLE public.orders(id uuid);\nALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;\nALTER TABLE public.orders RENAME TO orders_archive;\nALTER TABLE public.orders_archive ENABLE ROW LEVEL SECURITY;\n',
  });
  const r2 = await scanStatic(dir2);
  check('F01: CREATE, DISABLE, RENAME, then ENABLE under the new name is a clean pass', () => {
    assert.ok(!ids(r2).includes('rls_missing'), `got ${JSON.stringify(r2.findings.map((f) => f.title))}`);
  });
  rmSync(dir2, { recursive: true, force: true });

  // An unconditional external DISABLE is not cleared by a LATER conditional
  // (possibly-never-runs) ENABLE on the same external table.
  const dir3 = fixture({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n',
    'db/1.sql': "ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;\nDO $$ BEGIN\n  IF false THEN\n    ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n  END IF;\nEND $$;\n",
  });
  const r3 = await scanStatic(dir3);
  check('F01: an unconditional external DISABLE survives a later conditional ENABLE — still a warning', () => {
    const f = r3.findings.find((x) => x.id === 'rls_missing');
    assert.ok(f, `got ${ids(r3)}`);
    assert.match(f.title, /orders/);
  });
  rmSync(dir3, { recursive: true, force: true });

  // Cross-directory DISABLE/ENABLE on an external table is ambiguous, not clean.
  const dir4 = fixture({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n',
    'a/001.sql': 'ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;\n',
    'z/001.sql': 'ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n',
  });
  const r4 = await scanStatic(dir4);
  check('F01: an external table toggled in two different directories is not a confident clean pass', () => {
    const f = r4.findings.find((x) => x.id === 'rls_missing');
    assert.ok(f, `got ${ids(r4)}`);
    assert.strictEqual(summarize(r4.findings, r4.runs).gate, 'warn');
  });
  rmSync(dir4, { recursive: true, force: true });

  // The exact reported repro: a clean, known table must not silence an
  // external table's DISABLE sitting in the very same file.
  const dir5 = fixture({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"^2"}}\n',
    'db/1.sql': 'CREATE TABLE public.notes(id uuid);\nALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\nALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;\n',
  });
  const r5 = await scanStatic(dir5);
  check('F01: a clean known table does not mask an external DISABLE in the same file', () => {
    const f = r5.findings.find((x) => x.id === 'rls_missing');
    assert.ok(f, `got ${JSON.stringify(r5.findings.map((f2) => f2.title))}`);
    assert.match(f.title, /orders.*never created in this repo/);
    assert.strictEqual(summarize(r5.findings, r5.runs).gate, 'warn');
  });
  rmSync(dir5, { recursive: true, force: true });
}

// F02 (0.6.7): walk() skipped .mts, .cts, .jsonc and .json5 entirely — the
// lexer (code-lex.ts) already had a profile for all four, but the file never
// reached the scanner because TEXT_EXT didn't list the extensions.
{
  const dir = fixture({
    'config.mts': `export const OPENAI_KEY = "${K}";\n`,
    'settings.jsonc': `{\n  // secret key\n  "apiKey": "${K}"\n}\n`,
  });
  const r = await scanStatic(dir);
  check('F02: a TypeScript ESM (.mts) file is scanned for secrets', () => {
    const f = r.findings.find((x) => x.id === 'openai_key' && x.file === 'config.mts');
    assert.ok(f, `got ${JSON.stringify(r.findings.map((f2) => [f2.id, f2.file]))}`);
  });
  check('F02: a JSON-with-comments (.jsonc) file is scanned for secrets', () => {
    const f = r.findings.find((x) => x.id === 'openai_key' && x.file === 'settings.jsonc');
    assert.ok(f, `got ${JSON.stringify(r.findings.map((f2) => [f2.id, f2.file]))}`);
  });
  rmSync(dir, { recursive: true, force: true });
}
{
  const dir = fixture({
    'util.cts': `module.exports.OPENAI_KEY = "${K}";\n`,
    'settings.json5': `{\n  apiKey: "${K}",\n}\n`,
  });
  const r = await scanStatic(dir);
  check('F02: a TypeScript CommonJS (.cts) file is scanned for secrets', () => {
    const f = r.findings.find((x) => x.id === 'openai_key' && x.file === 'util.cts');
    assert.ok(f, `got ${JSON.stringify(r.findings.map((f2) => [f2.id, f2.file]))}`);
  });
  check('F02: a JSON5 (.json5) file is scanned for secrets', () => {
    const f = r.findings.find((x) => x.id === 'openai_key' && x.file === 'settings.json5');
    assert.ok(f, `got ${JSON.stringify(r.findings.map((f2) => [f2.id, f2.file]))}`);
  });
  rmSync(dir, { recursive: true, force: true });
}
{
  // Negative: an extension that is genuinely not text-scannable (a binary
  // blob) stays skipped — the fix must not turn walk() into "scan everything."
  const dir = fixture({ 'photo.jsonc.bak': 'not scanned, wrong extension' });
  const r = await scanStatic(dir);
  check('negative: an extension outside the walk allowlist is still skipped', () => {
    assert.ok(!ids(r).includes('openai_key'));
  });
  rmSync(dir, { recursive: true, force: true });
}

// F03 (0.6.7): INLINE_ENV was disabled for config-ish files (YAML, Dockerfile,
// docker-compose), leaving ASSIGN — a start-of-line, one-per-line regex — as
// the only detector there. It cannot see a secret mid-line: a Compose
// `environment:` list item, a CI `run:` step, or a second KEY=VALUE on the
// same Dockerfile ENV line. INLINE_ENV now runs everywhere, after ASSIGN.
const SECRET_VAL = 'Q7vB2mN9xK4rT8wY3pL6cD1hF5jA0eS2gU3iO9xN';
{
  const dir = fixture({
    'docker-compose.yml': `services:\n  app:\n    image: node:20\n    environment:\n      - API_TOKEN=${SECRET_VAL}\n`,
  });
  const r = await scanStatic(dir);
  check('F03: a secret in a Compose `environment:` YAML list item is found', () => {
    const f = r.findings.find((x) => x.id === 'env_secret' && x.file === 'docker-compose.yml');
    assert.ok(f, `got ${JSON.stringify(r.findings.map((f2) => [f2.id, f2.file]))}`);
  });
  rmSync(dir, { recursive: true, force: true });
}
{
  const dir = fixture({
    '.github/workflows/ci.yml': `name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: TOKEN=${SECRET_VAL} ./deploy.sh\n`,
  });
  const r = await scanStatic(dir);
  check('F03: a secret inline in a GitHub Actions `run:` step is found', () => {
    const f = r.findings.find((x) => x.id === 'env_secret' && x.file === '.github/workflows/ci.yml');
    assert.ok(f, `got ${JSON.stringify(r.findings.map((f2) => [f2.id, f2.file]))}`);
  });
  rmSync(dir, { recursive: true, force: true });
}
{
  const dir = fixture({ Dockerfile: `FROM node:20\nENV NODE_ENV=production API_TOKEN=${SECRET_VAL}\n` });
  const r = await scanStatic(dir);
  check('F03: the second KEY=VALUE on a multi-variable Dockerfile ENV line is found', () => {
    const f = r.findings.find((x) => x.id === 'env_secret' && x.file === 'Dockerfile');
    assert.ok(f, `got ${JSON.stringify(r.findings.map((f2) => [f2.id, f2.file]))}`);
    assert.match(f.detail, /API_TOKEN/);
  });
  check('negative: a non-secret-named var on the same line (NODE_ENV) is not flagged by itself', () => {
    const fs = r.findings.filter((x) => x.id === 'env_secret' && x.file === 'Dockerfile');
    assert.ok(!fs.some((f) => /NODE_ENV/.test(f.detail) && !/API_TOKEN/.test(f.detail)));
  });
  rmSync(dir, { recursive: true, force: true });
}
{
  // Negative: a plain single-assignment config/env line keeps ASSIGN's more
  // specific title/fix — INLINE_ENV firing on the same line must not
  // downgrade it to the generic "inline assignment" message.
  const dir = fixture({
    '.env': `API_TOKEN=${SECRET_VAL}\n`,
    'config.yml': `api_token: ${SECRET_VAL}\n`,
  });
  const r = await scanStatic(dir);
  check('negative: a plain .env assignment still reads as "Secret in env file", not "inline assignment"', () => {
    const fs = r.findings.filter((x) => x.file === '.env' && x.id === 'env_secret');
    assert.strictEqual(fs.length, 1, `got ${JSON.stringify(fs)}`);
    assert.strictEqual(fs[0].title, 'Secret in env file');
  });
  check('negative: a plain YAML key: value assignment still reads as "Secret in config file"', () => {
    const fs = r.findings.filter((x) => x.file === 'config.yml' && x.id === 'env_secret');
    assert.strictEqual(fs.length, 1, `got ${JSON.stringify(fs)}`);
    assert.strictEqual(fs[0].title, 'Secret in config file');
  });
  rmSync(dir, { recursive: true, force: true });
}

// F04 (0.6.7): NON_SECRET_NAME's "session" and "reset" terms blanket-excluded
// real credentials — sessionSecret (the express-session/cookie-session
// signing key), sessionToken and resetToken (bearer/account-recovery tokens)
// — from generic_secret detection, alongside genuinely non-secret ids like
// trackingToken.
{
  const dir = fixture({
    'config.js': [
      `const sessionSecret = "${SECRET_VAL}";`,
      `const sessionToken = "${SECRET_VAL}";`,
      `const resetToken = "${SECRET_VAL}";`,
      `const trackingToken = "${SECRET_VAL}";`,
      '',
    ].join('\n'),
  });
  const r = await scanStatic(dir);
  check('F04: a hardcoded sessionSecret is flagged as a possible secret', () => {
    const f = r.findings.find((x) => x.id === 'generic_secret' && x.line === 1);
    assert.ok(f, `got ${JSON.stringify(r.findings)}`);
  });
  check('F04: a hardcoded sessionToken is flagged as a possible secret', () => {
    const f = r.findings.find((x) => x.id === 'generic_secret' && x.line === 2);
    assert.ok(f, `got ${JSON.stringify(r.findings)}`);
  });
  check('F04: a hardcoded resetToken is flagged as a possible secret', () => {
    const f = r.findings.find((x) => x.id === 'generic_secret' && x.line === 3);
    assert.ok(f, `got ${JSON.stringify(r.findings)}`);
  });
  check('negative: trackingToken (an opaque API cursor, not a credential) stays excluded', () => {
    const f = r.findings.find((x) => x.id === 'generic_secret' && x.line === 4);
    assert.ok(!f, `got ${JSON.stringify(r.findings)}`);
  });
  rmSync(dir, { recursive: true, force: true });
}

// F05 (0.6.7): a "well-known default" password (e.g. "password") was exempt
// from db_url_password UNCONDITIONALLY, not just on a local/dev host — so the
// exact same weak password on a real remote host read as clean.
{
  const dir = fixture({ 'config.js': 'const DB_URL = "postgres://alice:password@db.audit.invalid/prod";\n' });
  const r = await scanStatic(dir);
  check('F05: a well-known-default password on a real remote host is still flagged', () => {
    assert.ok(ids(r).includes('db_url_password'), `got ${ids(r)}`);
  });
  rmSync(dir, { recursive: true, force: true });
}
{
  // Negative: the original local/dev-container intent is unchanged — a
  // compose service's throwaway default login on a local host stays quiet.
  const dir = fixture({ 'docker-compose.yml': 'services:\n  db:\n    image: postgres\n    environment:\n      DATABASE_URL: "postgres://opencut:opencut@localhost:5432/app"\n' });
  const r = await scanStatic(dir);
  check('negative: a default password on localhost stays exempt', () => {
    assert.ok(!ids(r).includes('db_url_password'), `got ${ids(r)}`);
  });
  rmSync(dir, { recursive: true, force: true });
}
{
  // Found while re-dogfooding the F05 fix: a markdown-style example URL in a
  // comment/docstring (`` `postgres://user:pass@localhost` ``) swallowed the
  // closing backtick into the host, so "localhost`" no longer matched
  // `^localhost$` and the local-host exemption silently stopped applying.
  const dir = fixture({
    'notes.js': '// Example: `postgres://opencut:opencut@localhost` is a throwaway dev login.\n',
  });
  const r = await scanStatic(dir);
  check('negative: an example DB URL inside a backtick-quoted comment still reads as local, not a leak', () => {
    assert.ok(!ids(r).includes('db_url_password'), `got ${ids(r)}`);
  });
  rmSync(dir, { recursive: true, force: true });
}

// F06 (0.6.7): dedup was keyed on file:line alone for a vendor-specific vs.
// name-based finding pair, so a specific match (openai_key) on a line
// silently deleted a DIFFERENT secret's name-based finding (generic_secret)
// on that same line, rather than only deleting a name-based finding for the
// SAME value the specific rule already reported.
{
  const dir = fixture({
    'config.js': `const key = "sk-proj-${SECRET_VAL}", password = "Zx9Km2Lp8Qr3Wv7Ty1Nb4Hs6Fd0Jc";\n`,
  });
  const r = await scanStatic(dir);
  check('F06: a second, distinct secret co-located on the same line as a vendor-pattern hit is still reported', () => {
    assert.ok(ids(r).includes('openai_key'), `got ${ids(r)}`);
    assert.ok(ids(r).includes('generic_secret'), `got ${ids(r)}`);
  });
  rmSync(dir, { recursive: true, force: true });
}
{
  // Negative: the SAME secret matched by both a vendor pattern and a
  // name-based rule must still collapse to one finding, not two.
  const dir = fixture({ 'config.js': `const openaiApiKey = "sk-proj-${SECRET_VAL}";\n` });
  const r = await scanStatic(dir);
  check('negative: the same secret caught by two rules on one line still dedupes to one finding', () => {
    const hits = r.findings.filter((f) => f.id === 'openai_key' || f.id === 'generic_secret');
    assert.strictEqual(hits.length, 1, `got ${JSON.stringify(hits)}`);
  });
  rmSync(dir, { recursive: true, force: true });
}

// F07 (0.6.7): client-exposure's PUBLIC_ASSIGN regex required the var name to
// be followed straight by `:`/`=`, so a quoted object-literal key (a real,
// common shape for config/JSON) never matched at all; and it scanned raw
// content, so commented-out code read as a live browser exposure.
{
  const dir = fixture({
    'config.js': `export const config = {\n  "NEXT_PUBLIC_STRIPE_SECRET": "sk_live_${SECRET_VAL}",\n};\n`,
  });
  const r = await scanStatic(dir);
  check('F07: a quoted object-literal property name is still recognized as a public-prefixed assignment', () => {
    const f = r.findings.find((x) => x.id === 'public_env_secret' && x.file === 'config.js');
    assert.ok(f, `got ${JSON.stringify(r.findings.map((f2) => [f2.id, f2.file, f2.line]))}`);
  });
  rmSync(dir, { recursive: true, force: true });
}
{
  const dir = fixture({
    'commented.js': `// const NEXT_PUBLIC_STRIPE_SECRET = "sk_live_${SECRET_VAL}";\nfunction real() { return 1; }\n`,
  });
  const r = await scanStatic(dir);
  check('negative: a public-prefixed secret inside a comment is not a live browser exposure', () => {
    assert.ok(!r.findings.some((x) => x.id === 'public_env_secret' && x.file === 'commented.js'), `got ${JSON.stringify(r.findings)}`);
  });
  rmSync(dir, { recursive: true, force: true });
}
{
  // Found while re-running the ground-truth check after the F07 comment-mask
  // fix: masking a `#` comment to blank space let the value gap after an
  // EMPTY-valued var (a common .env.example shape: `KEY=\n\n# comment\n`)
  // skip straight past the blank/commented lines onto the NEXT var's own
  // name, reporting that name as a leaked "secret" value.
  const dir = fixture({
    '.env.example': [
      'NEXT_PUBLIC_REPLICATE_API_TOKEN=',
      '',
      '# Seedance 2.0 (ByteDance) via PiAPI',
      '# Get your key at https://piapi.ai',
      'NEXT_PUBLIC_SEEDANCE_API_KEY=',
      '',
    ].join('\n'),
  });
  const r = await scanStatic(dir);
  check('negative: an empty public var before a comment does not swallow the next var name as its value', () => {
    assert.ok(!ids(r).includes('public_env_secret'), `got ${JSON.stringify(r.findings)}`);
  });
  rmSync(dir, { recursive: true, force: true });
}

// F08 (0.6.7): SQL-interpolation detection lost string-VALUE injections in two
// ways — the quoted-value shape (`name = '${x}'`) read as structural (info,
// not a warning) because VALUE_POSITION required the operator right before
// the hole with no SQL-literal quote in between, and a Python f-string using
// the OTHER quote character for its SQL value (`f"… = '{x}'"`) never matched
// the detection regex at all, since it excluded both quote characters.
{
  const dir = fixture({
    'db.js': "db.query(`UPDATE users SET name = '${name}', email = '${email}' WHERE id = '${id}'`);\n",
  });
  const r = await scanStatic(dir);
  check('F08: a quoted SQL string VALUE interpolation stays a warning, not downgraded to info', () => {
    const f = r.findings.find((x) => x.id === 'sql_interpolation' && x.file === 'db.js');
    assert.ok(f, `got ${JSON.stringify(r.findings)}`);
    assert.strictEqual(f.severity, 'warning', JSON.stringify(f));
  });
  rmSync(dir, { recursive: true, force: true });
}
{
  const dir = fixture({ 'db.py': `q = f"SELECT * FROM users WHERE name = '{pattern}'"\n` });
  const r = await scanStatic(dir);
  check('F08: a Python f-string SQL query with a nested-quote VALUE is detected at all', () => {
    const f = r.findings.find((x) => x.id === 'sql_interpolation' && x.file === 'db.py');
    assert.ok(f, `got ${JSON.stringify(r.findings)}`);
    assert.strictEqual(f.severity, 'warning', JSON.stringify(f));
  });
  rmSync(dir, { recursive: true, force: true });
}
{
  // Negative: a purely structural splice (column/table names, values still
  // parameterized) must still read as info, not be over-corrected to warning.
  const dir = fixture({ 'db.ts': 'db.prepare(`UPDATE clients SET ${set} WHERE id = ?`);\n' });
  const r = await scanStatic(dir);
  check('negative: a structural-only splice with parameterized values stays info', () => {
    const f = r.findings.find((x) => x.id === 'sql_interpolation' && x.file === 'db.ts');
    assert.ok(f, `got ${JSON.stringify(r.findings)}`);
    assert.strictEqual(f.severity, 'info', JSON.stringify(f));
  });
  rmSync(dir, { recursive: true, force: true });
}

// F09 (0.6.7): the CLI unconditionally excluded --output from the scan, even
// when --no-report (format 'none') means nothing is ever written there. A
// real project laid out with --output pointed at its own source (or any
// directory that happens to share a name/path with it) had that source
// silently dropped from the scan while producing zero report files.
{
  const dir = fixture({ 'src/config.js': `const OPENAI_KEY = "${K}";\n` });
  const p = runCli([dir, '--no-wizard', '--no-report', '--output', join(dir, 'src'), '--lang', 'en']);
  check('F09: --no-report --output <project>/src still scans the real source in src/', () => {
    assert.match(p.stdout, /OpenAI API key/, p.stdout);
    assert.match(p.stdout, /src[\\/]config\.js/, p.stdout);
  });
  rmSync(dir, { recursive: true, force: true });
}
{
  // Same guarantee via an explicit --format none (not just --no-report) —
  // the fix is keyed on "will a report be written", not on the flag name.
  const dir = fixture({ 'src/config.js': `const OPENAI_KEY = "${K}";\n` });
  const p = runCli([dir, '--no-wizard', '--format', 'none', '--output', join(dir, 'src'), '--lang', 'en']);
  check('F09: --format none --output <project>/src also still scans src/', () => {
    assert.match(p.stdout, /OpenAI API key/, p.stdout);
  });
  rmSync(dir, { recursive: true, force: true });
}
{
  // Negative: when a report WILL actually be written, the output directory
  // must still be excluded from the scan, exactly as before this fix.
  const dir = fixture({ 'config.js': `const OPENAI_KEY = "${K}";\n` });
  const out = join(dir, 'reports');
  mkdirSync(out, { recursive: true });
  const p = runCli([dir, '--no-wizard', '--format', 'json', '--output', out, '--lang', 'en']);
  check('negative: with a real report requested, --output stays excluded from the scan', () => {
    assert.ok(existsSync(join(out, 'report.json')), p.stdout + p.stderr);
    const report = JSON.parse(readFileSync(join(out, 'report.json'), 'utf8'));
    assert.ok(!report.findings.some((f) => f.file && f.file.startsWith('reports/')), JSON.stringify(report.findings));
  });
  rmSync(dir, { recursive: true, force: true });
}
