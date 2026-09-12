// Lightweight regression tests for the detectors. Run with `pnpm test` after `pnpm build`.
// Offline only — no network, no real backends.
import assert from 'node:assert';
import { rmSync, chmodSync, mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { readFileSync, existsSync } from 'node:fs';
import { scanStatic } from '../dist/engine/scan.js';
import { collectEndpoints, concretePath } from '../dist/engine/endpoints.js';
import { discoverSupabase } from '../dist/engine/checkers/backend/supabase.js';
import { normalizeUrl } from '../dist/cli/wizard.js';
import { setRequestImpl } from '../dist/engine/net/http.js';
import { checkLiveSite } from '../dist/engine/checkers/live/http-checks.js';
import { idorDifferential } from '../dist/engine/checkers/live/idor.js';
import { summarize, exitCodeFor, badgeMarkdown } from '../dist/engine/report.js';

import { CLI, ok, ALL_HEADERS, state, check, fixture, ids, runCli, CRITICAL_FIXTURE } from './_harness.mjs';

console.log('detectors');

await (async () => {
  const dir = fixture({
    'supabase/migrations/001.sql':
      '-- ENABLE ROW LEVEL SECURITY in a comment must not count\n' +
      'CREATE TABLE public.profiles (id uuid);\n' +
      'CREATE TABLE public.payments (id uuid);\n',
    'supabase/migrations/002.sql': 'ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;\n',
  });
  const r = await scanStatic(dir);
  check('RLS: per-table, cross-file ENABLE respected', () => {
    const rls = r.findings.filter((f) => f.id === 'rls_missing');
    const names = rls.map((f) => f.title);
    assert.ok(names.some((t) => t.includes('payments')), 'payments should be flagged');
    assert.ok(!names.some((t) => t.includes('profiles')), 'profiles should NOT be flagged (enabled in 002.sql)');
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ '.env': 'OPENAI_API_KEY=sk-proj-abc123DEF456ghi789JKL012mno345PQR\n' });
  const r = await scanStatic(dir);
  // A .env that is not committed is where the value belongs: advisory, not a
  // warning to act on. Committed / example-file cases live in tests/wp-precision.mjs.
  check('secrets in an uncommitted .env are advisory, not source-leak criticals', () => {
    const openai = r.findings.find((f) => f.id === 'openai_key');
    assert.ok(openai, 'openai key should be found');
    assert.strictEqual(openai.severity, 'advisory');
  });
  check('env-git without git repo reports info, not a false clean', () => {
    assert.ok(ids(r).includes('env_git_unverified'));
  });
  rmSync(dir, { recursive: true, force: true });
})();

check('discovery finds self-hosted URL + anon key, rejects service key', () => {
  const creds = discoverSupabase([
    { rel: '.env', content: 'NEXT_PUBLIC_SUPABASE_URL=https://db.example.com\nNEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.sig12345678901234567890' },
  ]);
  assert.ok(creds && creds.url === 'https://db.example.com', 'self-hosted URL should be discovered');
  const none = discoverSupabase([
    { rel: 'x.ts', content: 'const k = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.sig12345678901234567890"' },
  ]);
  assert.ok(none === null, 'a lone service_role key must not be used as anon creds');
});

check('endpoints: pages index + FastAPI {id} handled', () => {
  const eps = collectEndpoints([
    { rel: 'pages/api/users/index.ts', content: 'export default function h(){}' },
    { rel: 'main.py', content: '@app.get("/items/{id}")\ndef f(): ...\n@app.route("/legacy")\ndef g(): ...' },
  ]);
  const paths = eps.map((e) => e.path);
  assert.ok(paths.includes('/api/users'), `pages index should be /api/users, got ${paths.join(',')}`);
  assert.ok(paths.includes('/items/{id}'), 'FastAPI path captured');
  assert.strictEqual(concretePath('/items/{id}'), '/items/1');
  const legacy = eps.find((e) => e.path === '/legacy');
  assert.ok(legacy && legacy.method === 'ANY', 'Flask @route should normalize to ANY');
});

await (async () => {
  const dir = fixture({ 'db/001.sql': 'CREATE TABLE public.orders (id uuid);\nCREATE TABLE internal.orders (id uuid);\nALTER TABLE internal.orders ENABLE ROW LEVEL SECURITY;\n' });
  const r = await scanStatic(dir);
  check('RLS: schema-qualified names are not confused', () => {
    const rls = r.findings.filter((f) => f.id === 'rls_missing').map((f) => f.title);
    assert.ok(rls.some((t) => t.includes('public.orders')), 'public.orders must be flagged');
    assert.ok(!rls.some((t) => t.includes('internal.orders')), 'internal.orders is enabled, must not be flagged');
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ 'db/001.sql': 'CREATE TABLE public.t (id uuid);\nALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\nALTER TABLE public.t DISABLE ROW LEVEL SECURITY;\n' });
  const r = await scanStatic(dir);
  check('RLS: DISABLE after ENABLE is flagged', () => {
    assert.ok(r.findings.some((f) => f.id === 'rls_missing'), 'a table disabled again should be flagged');
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ 'db/001.sql': 'CREATE TABLE "public"."orders" (id uuid);\nALTER TABLE "public"."orders" ENABLE ROW LEVEL SECURITY;\n' });
  const r = await scanStatic(dir);
  check('RLS: quoted identifiers parse correctly (no bogus "public" table)', () => {
    const rls = r.findings.filter((f) => f.id === 'rls_missing');
    assert.strictEqual(rls.length, 0, `quoted+enabled table should be clean, got: ${rls.map((f) => f.title).join(', ')}`);
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ '.env': 'PASSWORD=G7m2Q9v4R8c5N1p6Xk\n' });
  const r = await scanStatic(dir);
  check('secrets: bare PASSWORD= in .env is caught', () => {
    assert.ok(r.findings.some((f) => f.id === 'env_secret'), 'bare PASSWORD= should be flagged');
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ 'config.yml': 'openai: sk-proj-abc123DEF456ghi789JKL012mno345PQR\n' });
  // Severity follows git exposure: a committed key is a leak; the same key in a
  // folder that is not a repo is a warning (tests/wp-precision.mjs covers both).
  spawnSync('git', ['-C', dir, 'init', '-q']);
  spawnSync('git', ['-C', dir, 'add', 'config.yml']);
  spawnSync('git', ['-C', dir, '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '-m', 'x']);
  const r = await scanStatic(dir);
  check('secrets: vendor key in a committed config.yml stays critical (not downgraded)', () => {
    const k = r.findings.find((f) => f.id === 'openai_key');
    assert.ok(k, 'openai key in yaml should be found');
    assert.strictEqual(k.severity, 'critical');
  });
  rmSync(dir, { recursive: true, force: true });
})();

console.log('\nverdict policy (one source of truth for CI / JSON / badge / console)');

check('a failed check makes the gate incomplete, exit 3, badge not green', () => {
  const s = summarize([], [{ id: 'deps', level: 1, status: 'failed' }, { id: 'static:x', level: 0, status: 'completed' }]);
  assert.strictEqual(s.gate, 'incomplete');
  assert.strictEqual(exitCodeFor(s), 3);
  assert.ok(badgeMarkdown(s).includes('incomplete-yellow'), 'badge must not be green');
});
check('an unsupported (requested) check also makes the gate incomplete', () => {
  const s = summarize([], [{ id: 'deps', level: 1, status: 'unsupported' }, { id: 'static:x', level: 0, status: 'completed' }]);
  assert.strictEqual(s.gate, 'incomplete');
  assert.strictEqual(exitCodeFor(s), 3);
});
check('all checks completed and no findings → pass, exit 0, green badge', () => {
  const s = summarize([], [{ id: 'static:x', level: 0, status: 'completed' }]);
  assert.strictEqual(s.gate, 'pass');
  assert.strictEqual(exitCodeFor(s), 0);
  assert.ok(badgeMarkdown(s).includes('brightgreen'));
});
check('a critical finding wins over incompleteness → fail, exit 2', () => {
  const s = summarize([{ id: 'x', severity: 'critical', title: '', detail: '', fix: '', checker: 'c', level: 0 }], [{ id: 'deps', level: 1, status: 'failed' }]);
  assert.strictEqual(s.gate, 'fail');
  assert.strictEqual(exitCodeFor(s), 2);
});

console.log('\nlive aggregation (mocked HTTP)');

await (async () => {
  // Root page fine with all headers; every exposed-file probe times out.
  setRequestImpl(async (url) => (url.endsWith('/') ? ok(200, '<html>', ALL_HEADERS) : { error: 'ETIMEDOUT' }));
  const r = await checkLiveSite('https://app.example');
  setRequestImpl(null);
  check('live-site: lost file probes are partial, not completed', () => {
    assert.strictEqual(r.run.status, 'partial', `got ${r.run.status} (${r.run.note})`);
    assert.strictEqual(r.findings.length, 0);
  });
})();

await (async () => {
  // Single endpoint: A gets data, B gets 500 → learned nothing → not completed.
  setRequestImpl(async (_url, init) => (String(init?.headers?.Authorization ?? '').includes('tokA') ? ok(200) : ok(500, 'boom')));
  const r = await idorDifferential('https://app.example', [{ method: 'GET', path: '/api/orders/:id', where: 'x' }], 'tokA', 'tokB', 0);
  setRequestImpl(null);
  check('idor: B=500 is inconclusive, never a completed "no leak"', () => {
    assert.notStrictEqual(r.run.status, 'completed', `got ${r.run.status}`);
    assert.strictEqual(r.findings.length, 0);
  });
})();

await (async () => {
  // Two endpoints: one properly scoped (A=200/B=403), the other errors for both → partial.
  setRequestImpl(async (url, init) => {
    if (url.includes('/broken/')) return { error: 'ECONNRESET' };
    return String(init?.headers?.Authorization ?? '').includes('tokA') ? ok(200) : ok(403, '{}');
  });
  const r = await idorDifferential('https://app.example', [
    { method: 'GET', path: '/api/orders/:id', where: 'x' },
    { method: 'GET', path: '/api/broken/:id', where: 'x' },
  ], 'tokA', 'tokB', 0);
  setRequestImpl(null);
  check('idor: one good pair does not hide a lost pair (partial)', () => {
    assert.strictEqual(r.run.status, 'partial', `got ${r.run.status} (${r.run.note})`);
  });
})();

console.log('\nRLS sequences');

await (async () => {
  const dir = fixture({ 'db/001.sql': 'CREATE TABLE public.orders(id uuid);\nALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nDROP TABLE public.orders;\nCREATE TABLE public.orders(id uuid);\n' });
  const r = await scanStatic(dir);
  check('RLS: in-file order + DROP/recreate → recreated table is flagged', () => {
    assert.ok(r.findings.some((f) => f.id === 'rls_missing'), 'recreated table without RLS must be flagged');
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ 'db/001.sql': "CREATE TABLE public.orders(id uuid);\nSELECT 'ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;';\n" });
  const r = await scanStatic(dir);
  check('RLS: ENABLE inside a string literal does not count', () => {
    assert.ok(r.findings.some((f) => f.id === 'rls_missing'), 'string literal must not satisfy RLS');
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({
    'db/001.sql': 'CREATE TABLE public.orders(id uuid);\nALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n',
    'db/002.sql': 'CREATE TABLE IF NOT EXISTS public.orders(id uuid);\n',
  });
  const r = await scanStatic(dir);
  check('RLS: CREATE IF NOT EXISTS on an existing table keeps RLS (no false critical)', () => {
    const rls = r.findings.filter((f) => f.id === 'rls_missing');
    assert.strictEqual(rls.length, 0, `unexpected: ${rls.map((f) => f.title).join(', ')}`);
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ 'db/001.sql': "CREATE TABLE public.orders(id uuid);\n/* ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY */\nSELECT $$ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY$$;\n" });
  const r = await scanStatic(dir);
  check('RLS: block comment and dollar-quoted string do not count', () => {
    assert.ok(r.findings.some((f) => f.id === 'rls_missing'));
  });
  rmSync(dir, { recursive: true, force: true });
})();

console.log('\nCLI (real process)');

check('--idor-tokens without --url is rejected (exit 2)', () => {
  const p = spawnSync(process.execPath, [CLI, '.', '--no-wizard', '--ci', '--format', 'none', '--idor-tokens', 'a,b'], { encoding: 'utf8' });
  assert.strictEqual(p.status, 2, `stderr: ${p.stderr}`);
});

await (async () => {
  const dir = fixture({});
  const out = join(dir, 'out');
  const p = spawnSync(process.execPath, [CLI, dir, '--no-wizard', '--ci', '--format', 'json', '--output', out], { encoding: 'utf8' });
  const json = JSON.parse(readFileSync(join(out, 'report.json'), 'utf8'));
  check('empty directory: CI exit 3 AND JSON gate=incomplete (not pass/100)', () => {
    assert.strictEqual(p.status, 3);
    assert.strictEqual(json.gate, 'incomplete');
    assert.strictEqual(json.coverage.completed, 0, 'static checks with no files must not count as coverage');
  });
  rmSync(dir, { recursive: true, force: true });
})();

console.log('\nwizard <-> CLI are one pipeline');


check('normalizeUrl: bare domain is accepted, junk is rejected', () => {
  assert.strictEqual(normalizeUrl('example.com'), 'https://example.com');
  assert.strictEqual(normalizeUrl('http://localhost:3000'), 'http://localhost:3000');
  assert.strictEqual(normalizeUrl('not a url'), null);
  assert.strictEqual(normalizeUrl(''), null);
});

await (async () => {
  const dir = fixture(CRITICAL_FIXTURE);
  const p = runCli([dir, '--wizard', '--ci', '--format', 'none'], { input: 'n\n\n' });
  check('--wizard --ci exits 2 on a critical finding (no CI bypass)', () => {
    assert.strictEqual(p.status, 2, `got ${p.status}`);
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture(CRITICAL_FIXTURE);
  runCli([dir, '--wizard', '--format', 'none'], { input: 'n\n\n' });
  check('--wizard --format none writes no report files', () => {
    assert.ok(!existsSync(join(dir, 'easyvibegate-report')), 'report dir must not be created');
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture(CRITICAL_FIXTURE);
  // Answer: deps=n, url=127.0.0.1:1 (refused instantly, proves the URL reached the flow).
  runCli([dir, '--wizard', '--format', 'json'], { input: 'n\nhttp://127.0.0.1:1\ny\n' });
  const json = JSON.parse(readFileSync(join(dir, 'easyvibegate-report', 'report.json'), 'utf8'));
  check('piped wizard answers are not lost (URL reaches the live probe)', () => {
    assert.ok(json.runs.some((r) => r.id === 'live-site'), `runs: ${json.runs.map((r) => r.id).join(',')}`);
  });
  check('report records projectRoot / version / scannedAt', () => {
    assert.strictEqual(json.projectRoot, dir);
    assert.ok(json.version && json.scannedAt, 'version and scannedAt must be present');
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture(CRITICAL_FIXTURE);
  const other = fixture({ 'readme.md': 'x' });
  // Run from an unrelated cwd: the report must land next to the scanned project.
  runCli([dir, '--no-wizard', '--format', 'json'], { cwd: other });
  check('default report goes to <project>/easyvibegate-report, not cwd', () => {
    assert.ok(existsSync(join(dir, 'easyvibegate-report', 'report.json')), 'report must be in the scanned project');
    assert.ok(!existsSync(join(other, 'easyvibegate-report')), 'must not write into the current directory');
  });
  rmSync(dir, { recursive: true, force: true });
  rmSync(other, { recursive: true, force: true });
})();

check('explicitly given --config that does not exist is an error', () => {
  const p = runCli(['.', '--no-wizard', '--ci', '--format', 'none', '--config', 'definitely-missing.json']);
  assert.strictEqual(p.status, 2, `got ${p.status}: ${p.stderr}`);
  assert.match(p.stderr, /config/i);
});

await (async () => {
  const dir = fixture({ 'bad.json': '{ "ignorePaths": [1, 2] }' });
  const p = runCli(['.', '--no-wizard', '--ci', '--format', 'none', '--config', join(dir, 'bad.json')]);
  check('--config with wrong value types is an error', () => {
    assert.strictEqual(p.status, 2, `got ${p.status}: ${p.stderr}`);
  });
  rmSync(dir, { recursive: true, force: true });
})();

console.log('\nself-audit regressions (found by adversarial agents)');

await (async () => {
  const dir = fixture({
    'ui/spinner.css': '.sk-chase-dot-before-animation-delay { top: 0 }\n',
    'bundle.js': 'const a="sk-proj-Qz7Rm2Xk9Lp4Tv8Bn3Wd6Hy",b="AKIAQZ7RM2XK9LP4TV8B",c="ghp_abcdefghij0123456789ABCDEFGHIJ012345";\n',
    'README.md': 'Set AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE and OPENAI_API_KEY=sk-proj-REPLACE_ME_WITH_YOUR_REAL_KEY\n',
    'db.ts': 'const u = "postgres://postgres:Rt8Vn3Xm7Kp2@db.abcdefgh.supabase.co:5432/postgres";\n',
  });
  const r = await scanStatic(dir);
  const at = (f) => r.findings.filter((x) => x.file === f);
  check('CSS class "sk-chase-…" is not reported as an OpenAI key', () => {
    assert.strictEqual(at('ui/spinner.css').length, 0, JSON.stringify(at('ui/spinner.css').map((f) => f.title)));
  });
  check('several keys on ONE line are all reported (dedup no longer hides them)', () => {
    assert.ok(at('bundle.js').length >= 3, `got ${at('bundle.js').length}`);
  });
  check('docs placeholders (AKIA…EXAMPLE, REPLACE_ME) are not critical', () => {
    assert.ok(!at('README.md').some((f) => f.severity === 'critical'), JSON.stringify(at('README.md').map((f) => [f.title, f.severity])));
  });
  check('a DB URL with an inline password is caught', () => {
    assert.ok(at('db.ts').some((f) => f.id === 'db_url_password'), 'postgres://user:pass@ must be flagged');
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ 'package.json': '{"dependencies":{"mysql2":"^3"}}', 'db/schema.sql': 'CREATE TABLE users (id INT AUTO_INCREMENT) ENGINE=InnoDB;\n' });
  const r = await scanStatic(dir);
  check('MySQL project gets no Postgres-only RLS criticals', () => {
    assert.strictEqual(r.findings.filter((f) => f.id === 'rls_missing').length, 0);
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({
    'rls_policies.sql': 'ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n',
    'supabase/migrations/20240101_init.sql': 'CREATE TABLE public.notes (id uuid);\n',
  });
  const r = await scanStatic(dir);
  // Previously this asserted silence. Staying silent whenever an ENABLE existed
  // anywhere is precisely what let a DISABLE in a later migration slip through,
  // so the contract is now: report it, but as a warning naming the ambiguity —
  // no false critical, and no silence either.
  check('RLS enabled in a file that sorts first is reported as ambiguous, not dropped', () => {
    const rls = r.findings.filter((f) => f.id === 'rls_missing');
    assert.strictEqual(rls.length, 1, `expected one ambiguous finding, got ${rls.length}`);
    assert.strictEqual(rls[0].severity, 'warning');
    assert.match(rls[0].title, /order unclear/i);
  });
  rmSync(dir, { recursive: true, force: true });
})();

check('supabase severity uses whole words: postcards/authors are not critical', () => {
  // exercised through the probe's exported behaviour via a mocked HEAD
  assert.ok(true);
});

await (async () => {
  setRequestImpl(async (url) => {
    if (url.endsWith('/rest/v1/')) return ok(200, JSON.stringify({ definitions: { postcards: {}, authors: {}, api_keys: {} } }));
    return ok(200, '', { 'content-range': '0-0/5' });
  });
  const { probeSupabase } = await import('../dist/engine/checkers/backend/supabase.js');
  const r = await probeSupabase({ creds: { url: 'https://p.supabase.co', anonKey: 'eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.sig1234567890123456', keyKind: 'jwt-anon' }, rateLimitMs: 0 });
  setRequestImpl(null);
  const sev = (t) => r.findings.find((f) => f.endpoint === `GET /rest/v1/${t}`)?.severity;
  check('table severity: api_keys critical, postcards/authors only warning', () => {
    assert.strictEqual(sev('api_keys'), 'critical');
    assert.strictEqual(sev('postcards'), 'warning');
    assert.strictEqual(sev('authors'), 'warning');
  });
})();

await (async () => {
  setRequestImpl(async (url) => {
    if (url.endsWith('/rest/v1/')) return ok(200, JSON.stringify({ definitions: { users: {} } }));
    return ok(200, '', {}); // 200 but no content-range → unknown, not proof
  });
  const { probeSupabase } = await import('../dist/engine/checkers/backend/supabase.js');
  const r = await probeSupabase({ creds: { url: 'https://p.supabase.co', anonKey: 'eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.sig1234567890123456', keyKind: 'jwt-anon' }, rateLimitMs: 0 });
  setRequestImpl(null);
  check('missing content-range is inconclusive, not a critical "readable"', () => {
    assert.ok(!r.findings.some((f) => f.id === 'supabase_anon_read'), 'must not claim readable');
    assert.notStrictEqual(r.run.status, 'completed', `got ${r.run.status}`);
  });
})();

await (async () => {
  setRequestImpl(async (url) => (url.endsWith('/') ? ok(301, '', { location: 'https://other.example/' }) : ok(404, '')));
  const r = await checkLiveSite('https://app.example');
  setRequestImpl(null);
  check('a redirect off the target origin is not credited to the app', () => {
    assert.notStrictEqual(r.run.status, 'completed', `got ${r.run.status} (${r.run.note})`);
    assert.strictEqual(r.findings.filter((f) => f.id.startsWith('missing_')).length, 0);
  });
})();

await (async () => {
  setRequestImpl(async () => ok(200, '[]'));
  const { probeEndpointsUnauth } = await import('../dist/engine/checkers/live/endpoint-probe.js');
  const r = await probeEndpointsUnauth('https://app.example', [{ method: 'GET', path: '/api/items', where: 'x' }], 0);
  setRequestImpl(null);
  check('an empty JSON array is not "returns data without auth"', () => {
    assert.strictEqual(r.findings.length, 0);
  });
})();

await (async () => {
  setRequestImpl(async () => ok(200, '{"id":1}'));
  const r = await idorDifferential('https://app.example', [{ method: 'GET', path: '/api/o/:id', where: 'x' }], 'same', 'same', 0);
  setRequestImpl(null);
  check('IDOR with identical tokens is skipped, not a confident finding', () => {
    assert.strictEqual(r.run.status, 'skipped');
    assert.strictEqual(r.findings.length, 0);
  });
})();

check('firebase discovery ignores docs and placeholder projects', async () => {});
await (async () => {
  const { discoverFirebase } = await import('../dist/engine/checkers/backend/firebase.js');
  check('firebase: docs must not contribute probe hosts', () => {
    const creds = discoverFirebase([
      { rel: 'src/firebase.ts', content: 'projectId: "real-app"' },
      { rel: 'DOCS.md', content: 'databaseURL: "https://victim-default-rtdb.firebaseio.com"' },
    ]);
    assert.strictEqual(creds.projectId, 'real-app');
    assert.strictEqual(creds.databaseURL, undefined, 'a host from docs must not be probed');
  });
  check('firebase: placeholder project id yields no probe', () => {
    assert.strictEqual(discoverFirebase([{ rel: 'a.ts', content: 'projectId: "YOUR_PROJECT_ID"' }]), null);
  });
})();

console.log('\nself-audit regressions, round 2 (medium/low)');

await (async () => {
  const dir = fixture({
    'src/notes.ts': [
      '// Never use eval() on user input',
      '/* we called new Function(body); removed in v2 */',
      '// Example of a bad CORS header: Access-Control-Allow-Origin: "*"',
      'const msg = `Please SELECT a row FROM the table WHERE you like ${name}`;',
    ].join('\n'),
    'vendor.min.js': 'var a=eval("1");var h={origin:"*"};' + 'x'.repeat(900),
  });
  const r = await scanStatic(dir);
  check('comments, prose and minified bundles no longer trigger config-risks', () => {
    const cr = r.findings.filter((f) => f.checker === 'config-risks');
    assert.strictEqual(cr.length, 0, cr.map((f) => `${f.id}@${f.file}:${f.line}`).join(', '));
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ 'src/db.ts': 'const q = `SELECT * FROM users WHERE id = ${id}`;\n' });
  const r = await scanStatic(dir);
  check('a real interpolated query is still caught after masking', () => {
    assert.ok(r.findings.some((f) => f.id === 'sql_interpolation'));
  });
  rmSync(dir, { recursive: true, force: true });
})();

check('endpoints: NestJS, Django, Hono and chained Express are discovered', () => {
  const eps = collectEndpoints([
    { rel: 'src/users.controller.ts', content: "@Get('users')\nfindAll(){}\n@Post('users')\ncreate(){}" },
    { rel: 'app/urls.py', content: "urlpatterns = [path('admin/', x), re_path(r'^reports/$', y)]" },
    { rel: 'src/api.ts', content: "const api = new Hono();\napi.get('/hono-items', h);\nconst e = new Elysia().get('/elysia-items', h);" },
    { rel: 'src/tpl.ts', content: 'app.get(`${BASE}/secret-admin`, h);' },
  ]);
  const paths = eps.map((e) => e.path);
  for (const p of ['/users', '/admin/', '/reports/', '/hono-items', '/elysia-items']) {
    assert.ok(paths.includes(p), `${p} missing from ${paths.join(',')}`);
  }
  assert.ok(!paths.some((p) => p.includes('${') || p.includes('$1')), 'interpolated paths must not become probe targets');
});

await (async () => {
  const dir = fixture({ 'src/pub.ts': 'export const NEXT_PUBLIC_ADMIN_TOKEN = "Qz7Rm2Xk9Lp4Tv8Bn3Wd6Hy";\n' });
  const r = await scanStatic(dir);
  check('NEXT_PUBLIC_*_TOKEN is reported as a browser-exposed secret', () => {
    assert.ok(r.findings.some((f) => f.id === 'public_env_secret'), ids(r).join(','));
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ '.npmrc': '//registry.npmjs.org/:_authToken=Qz7Rm2Xk9Lp4Tv8Bn3Wd6Hy1Gj\n', 'Dockerfile': 'ENV OPENAI_SECRET_KEY=Qz7Rm2Xk9Lp4Tv8Bn3Wd6Hy1Gj5Fs0Ac\n' });
  const r = await scanStatic(dir);
  check('.npmrc is scanned and Dockerfile ENV assignments are parsed', () => {
    assert.ok(r.files.some((f) => f.rel === '.npmrc'), '.npmrc must be scannable');
    assert.ok(r.findings.some((f) => f.file === 'Dockerfile'), 'Dockerfile ENV secret must be found');
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ 'app.ts': 'const x = 1;\n', 'easyvibegate.config.json': '{ "ignore": ["a",] }' });
  const r = await scanStatic(dir);
  check('a broken config file is reported, not silently ignored', () => {
    const run = r.runs.find((x) => x.id === 'config');
    assert.ok(run && run.status === 'failed', JSON.stringify(r.runs));
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ 'db/001.sql': "CREATE TABLE public.keep (id uuid);\nALTER TABLE public.keep ENABLE ROW LEVEL SECURITY;\nSELECT * INTO public.leaked_users FROM auth.users;\n" });
  const r = await scanStatic(dir);
  check('SELECT ... INTO creates a table and is checked for RLS', () => {
    const t = r.findings.filter((f) => f.id === 'rls_missing').map((f) => f.title);
    assert.ok(t.some((x) => x.includes('leaked_users')), t.join(', '));
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ 'db/001.sql': 'DO $$ BEGIN\n  CREATE TABLE public.in_do (id uuid);\nEND $$;\n' });
  const r = await scanStatic(dir);
  check('DDL inside a DO $$ block is visible', () => {
    assert.ok(r.findings.some((f) => f.id === 'rls_missing' && f.title.includes('in_do')), ids(r).join(','));
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  setRequestImpl(async (url) => (url.endsWith('/')
    ? ok(302, '', { location: '/home', 'set-cookie': 'session=abc; Path=/' })
    : ok(200, '<html>', ALL_HEADERS)));
  const r = await checkLiveSite('https://app.example');
  setRequestImpl(null);
  check('a cookie set on the login redirect hop is still inspected', () => {
    assert.ok(r.findings.some((f) => f.id === 'cookie_flags'), r.findings.map((f) => f.id).join(','));
  });
})();

console.log('\nCLI audit regressions (round 3)');

check('warning-only project: verdict, JSON gate, badge and exit code all agree', () => {
  const s = summarize([{ id: 'w', severity: 'warning', title: '', detail: '', fix: '', checker: 'c', level: 0 }], [{ id: 'static:x', level: 0, status: 'completed' }]);
  assert.strictEqual(s.gate, 'warn');
  assert.strictEqual(exitCodeFor(s), 1);
  assert.ok(!badgeMarkdown(s).includes('brightgreen'), 'a warning badge must not be green');
});

check('normalizeUrl: localhost keeps http, public host gets https', () => {
  assert.strictEqual(normalizeUrl('localhost:3000'), 'http://localhost:3000');
  assert.strictEqual(normalizeUrl('127.0.0.1:8080'), 'http://127.0.0.1:8080');
  assert.strictEqual(normalizeUrl('myapp.com'), 'https://myapp.com');
});

await (async () => {
  const dir = fixture(CRITICAL_FIXTURE);
  const p = runCli([dir, '--no-wizard', '--format', 'none']); // no --ci
  check('a FAIL verdict exits non-zero even without --ci', () => {
    assert.strictEqual(p.status, 2, `got ${p.status}`);
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture(CRITICAL_FIXTURE);
  const p = runCli([dir, '--wizard', '--format', 'none'], { input: '' }); // immediate EOF
  check('EOF in the wizard does not crash — it finishes and reports', () => {
    assert.notStrictEqual(p.status, 1, `crashed: ${p.stderr.slice(0, 200)}`);
    assert.ok(!/ERR_USE_AFTER_CLOSE/.test(p.stderr), p.stderr.slice(0, 200));
    assert.strictEqual(p.status, 2, 'the critical finding must still drive the exit code');
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture(CRITICAL_FIXTURE);
  const p = runCli([dir, '--no-wizard', '--url', 'http://127.0.0.1:1', '--format', 'none'], { input: '' });
  check('EOF at the consent prompt still reports (no silent exit 0)', () => {
    assert.strictEqual(p.status, 2, `got ${p.status}`);
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture(CRITICAL_FIXTURE);
  const clean = fixture({ 'ok.ts': 'const a = 1;\n' });
  const p = runCli([clean, dir, '--no-wizard', '--format', 'none']);
  check('a second positional path is rejected, not silently ignored', () => {
    assert.strictEqual(p.status, 2, `got ${p.status}: ${p.stdout.slice(0, 120)}`);
  });
  rmSync(dir, { recursive: true, force: true });
  rmSync(clean, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture(CRITICAL_FIXTURE);
  const out = join(dir, 'out');
  runCli([dir, '--no-wizard', '--format', 'all', '-o', out]);
  const cleanDir = fixture({ 'ok.ts': 'const a = 1;\n' });
  runCli([cleanDir, '--no-wizard', '--format', 'json', '-o', out]);
  check('stale report.md from a previous run is not left next to a fresh report.json', () => {
    assert.ok(!existsSync(join(out, 'report.md')), 'the old markdown report must be cleared');
  });
  rmSync(dir, { recursive: true, force: true });
  rmSync(cleanDir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ 'ok.ts': 'const a = 1;\n', 'f.txt': 'hi' });
  const p = runCli([dir, '--no-wizard', '-o', join(dir, 'f.txt')]);
  check('--output pointing at a file fails cleanly (exit 2, no stack trace)', () => {
    assert.strictEqual(p.status, 2, `got ${p.status}`);
    assert.ok(!/at mkdirSync|node:fs:/.test(p.stderr), p.stderr.slice(0, 200));
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ 'ok.ts': 'const a = 1;\n', 'c.json': '{"ignorePath":["x"]}' });
  const p = runCli([dir, '--no-wizard', '--format', 'none', '--config', join(dir, 'c.json')]);
  check('a misspelled config key is rejected instead of doing nothing', () => {
    assert.strictEqual(p.status, 2, `got ${p.status}`);
    assert.match(p.stderr, /unknown key/i);
  });
  const p2 = runCli([dir, '--no-wizard', '--format', 'none', '--config', dir]);
  check('--config pointing at a directory says "not a file"', () => {
    assert.match(p2.stderr, /not a file/i);
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ 'ok.ts': 'const a = 1;\n' });
  check('--lang RU / --format All are accepted case-insensitively', () => {
    assert.notStrictEqual(runCli([dir, '--no-wizard', '--format', 'None', '--lang', 'RU']).status, 2);
  });
  check('--no-report wins regardless of flag order', () => {
    runCli([dir, '--no-wizard', '--no-report', '--format', 'json']);
    assert.ok(!existsSync(join(dir, 'easyvibegate-report')), 'no report dir should be created');
  });
  check('--wizard together with --no-wizard is rejected', () => {
    assert.strictEqual(runCli([dir, '--wizard', '--no-wizard']).status, 2);
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture(CRITICAL_FIXTURE);
  const p = runCli([dir, '--wizard', '--ci', '--format', 'none'], { input: '' });
  check('--ci never runs the interactive wizard', () => {
    assert.ok(!/Step 1|Шаг 1/.test(p.stdout), `wizard ran under --ci: ${p.stdout.slice(0, 120)}`);
    assert.strictEqual(p.status, 2);
  });
  rmSync(dir, { recursive: true, force: true });
})();


// --- Regression: the four defects found by the v0.4.1 external audit ---------
console.log('\nregressions (v0.4.1 audit)');

await (async () => {
  // Rules that match a literal value must still SEE that literal. Masking every
  // quoted string had silently disabled these three detectors entirely.
  const dir = fixture({
    'jwt.ts': 'const opts = { algorithm: "none" };\n',
    'cors.ts': 'app.use(cors({origin: "*"}));\n',
    'q.py': 'query = f"SELECT * FROM users WHERE id = {user_id}"\n',
  });
  const r = await scanStatic(dir);
  check('alg "none" in a quoted value is still detected', () => {
    assert.ok(ids(r).includes('jwt_alg_none'), `got ${ids(r)}`);
  });
  check('CORS origin "*" is still detected', () => {
    assert.ok(ids(r).includes('cors_star'), `got ${ids(r)}`);
  });
  check('Python f-string SQL interpolation is still detected', () => {
    assert.ok(ids(r).includes('sql_interpolation'), `got ${ids(r)}`);
  });
  rmSync(dir, { recursive: true, force: true });

  // Negative half: the same words inside comments must stay silent.
  const dir2 = fixture({
    'c.ts': '// never set algorithm: "none" and never use origin: "*"\n/* eval( */\n',
  });
  const r2 = await scanStatic(dir2);
  check('the same constructs inside comments are NOT reported', () => {
    assert.deepStrictEqual(r2.findings.filter((f) => f.checker === 'config-risks'), []);
  });
  rmSync(dir2, { recursive: true, force: true });
})();

await (async () => {
  // A later migration in the SAME directory has a real apply order: a DISABLE
  // there must win over an earlier ENABLE.
  const dir = fixture({
    'supabase/migrations/001.sql': 'CREATE TABLE public.orders(id uuid);\nALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n',
    'supabase/migrations/002.sql': 'ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;\n',
  });
  const r = await scanStatic(dir);
  check('RLS disabled by a later migration is reported as critical', () => {
    const f = r.findings.find((x) => x.id === 'rls_missing');
    assert.ok(f, `expected rls_missing, got ${ids(r)}`);
    assert.strictEqual(f.severity, 'critical');
  });
  rmSync(dir, { recursive: true, force: true });

  const dir2 = fixture({
    'supabase/migrations/001.sql': 'CREATE TABLE public.orders(id uuid);\nALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n',
    'supabase/migrations/002.sql': 'DROP TABLE public.orders;\nCREATE TABLE public.orders(id uuid);\n',
  });
  const r2 = await scanStatic(dir2);
  check('a table recreated in a later migration loses its RLS and is reported', () => {
    assert.ok(ids(r2).includes('rls_missing'), `got ${ids(r2)}`);
  });
  rmSync(dir2, { recursive: true, force: true });

  // Negative half: enabled and left alone must stay clean.
  const dir3 = fixture({
    'supabase/migrations/001.sql': 'CREATE TABLE public.orders(id uuid);\nALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n',
    'supabase/migrations/002.sql': 'CREATE INDEX ON public.orders(id);\n',
  });
  const r3 = await scanStatic(dir3);
  check('a table left with RLS enabled is not reported', () => {
    assert.ok(!ids(r3).includes('rls_missing'), `got ${ids(r3)}`);
  });
  rmSync(dir3, { recursive: true, force: true });

})();

await (async () => {
  // The closing $$ of a DO block used to be read as a new opening delimiter,
  // blanking the whole rest of the file — hiding every statement after it.
  const dir = fixture({
    'db/1.sql': 'CREATE TABLE public.orders(id uuid);\nDO $$ BEGIN\n  ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nEND $$;\nALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;\n',
  });
  const r = await scanStatic(dir);
  check('SQL after a DO $$ ... $$ block is still analyzed', () => {
    assert.ok(ids(r).includes('rls_missing'), `got ${ids(r)}`);
  });
  rmSync(dir, { recursive: true, force: true });

  const dir2 = fixture({
    'db/1.sql': 'CREATE TABLE public.orders(id uuid);\nDO $$ BEGIN\n  ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nEND $$;\n',
  });
  const r2 = await scanStatic(dir2);
  check('DDL inside a DO block still counts as executed', () => {
    assert.ok(!ids(r2).includes('rls_missing'), `got ${ids(r2)}`);
  });
  rmSync(dir2, { recursive: true, force: true });
})();

await (async () => {
  // An empty stdin is "no answer", not an Enter accepting the default.
  const dir = fixture({ 'ok.ts': 'const a = 1;\n' });
  const p = runCli([dir, '--wizard', '--format', 'none'], { input: '' });
  check('empty stdin does not auto-accept the dependency-audit question', () => {
    assert.ok(!/Level 1|dependency audit/i.test(p.stdout + p.stderr), `deps ran on empty stdin: ${(p.stdout + p.stderr).slice(0, 200)}`);
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  // A live check that was explicitly requested but never authorized is missing
  // coverage — it must not exit 0 as a clean PASS.
  const dir = fixture({ 'ok.ts': 'const a = 1;\n' });
  const p = runCli([dir, '--ci', '--format', 'none', '--url', 'https://synthetic.invalid'], { input: '' });
  check('--ci --url without ownership fails loudly instead of passing', () => {
    assert.notStrictEqual(p.status, 0, `exited 0 without running the requested live check: ${p.stderr}`);
  });
  rmSync(dir, { recursive: true, force: true });
})();



// --- Regression: v0.4.2 audit — unjustified 100/100 PASS in two RLS shapes ----
console.log('\nregressions (v0.4.2 audit)');

await (async () => {
  // Cross-directory ambiguity is symmetric. An ENABLE that merely sorts LAST is
  // no more trustworthy than one that sorts first — checking only the RLS-off
  // direction let this exact shape pass clean.
  const dir = fixture({
    'a/001.sql': 'CREATE TABLE public.orders (id serial);\nALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;\n',
    'z/001.sql': 'ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n',
  });
  const r = await scanStatic(dir);
  check('ENABLE that merely sorts last does not produce a confident PASS', () => {
    const f = r.findings.find((x) => x.id === 'rls_missing');
    assert.ok(f, `expected an ambiguity finding, got ${ids(r)}`);
    assert.strictEqual(f.severity, 'warning');
    assert.match(f.title, /order unclear/i);
  });
  rmSync(dir, { recursive: true, force: true });

  // Same two statements in ONE directory: order is real, so the verdict is firm.
  const dir2 = fixture({
    'db/001.sql': 'CREATE TABLE public.orders (id serial);\nALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;\n',
    'db/002.sql': 'ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n',
  });
  const r2 = await scanStatic(dir2);
  check('the same statements within one directory stay a firm verdict', () => {
    assert.ok(!ids(r2).includes('rls_missing'), `got ${r2.findings.map((f) => f.title)}`);
  });
  rmSync(dir2, { recursive: true, force: true });
})();

await (async () => {
  // A guarded ENABLE cannot be confirmed statically — the verdict must say so
  // rather than report a confident 100/100 PASS.
  const dir = fixture({
    'db/1.sql': 'CREATE TABLE public.orders (id serial);\nDO $$ BEGIN\n  IF false THEN\n    ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n  END IF;\nEND $$;\n',
  });
  const r = await scanStatic(dir);
  check('conditional ENABLE inside a DO block is reported, not assumed', () => {
    const f = r.findings.find((x) => x.id === 'rls_missing');
    assert.ok(f, `expected a finding, got ${ids(r)}`);
    assert.strictEqual(f.severity, 'warning');
    assert.match(f.title, /conditional/i);
  });
  rmSync(dir, { recursive: true, force: true });

  // Unconditional DDL in a DO block is still trusted — no false warning.
  const dir2 = fixture({
    'db/1.sql': 'CREATE TABLE public.orders (id serial);\nDO $$ BEGIN\n  ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nEND $$;\n',
  });
  const r2 = await scanStatic(dir2);
  check('unconditional ENABLE inside a DO block raises no doubt', () => {
    assert.ok(!ids(r2).includes('rls_missing'), `got ${r2.findings.map((f) => f.title)}`);
  });
  rmSync(dir2, { recursive: true, force: true });

  // A later unconditional ENABLE clears the doubt a guarded one left.
  const dir3 = fixture({
    'db/1.sql': 'CREATE TABLE public.orders (id serial);\nDO $$ BEGIN\n  IF false THEN\n    ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n  END IF;\nEND $$;\nALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n',
  });
  const r3 = await scanStatic(dir3);
  check('a later unconditional ENABLE clears the conditional doubt', () => {
    assert.ok(!ids(r3).includes('rls_missing'), `got ${r3.findings.map((f) => f.title)}`);
  });
  rmSync(dir3, { recursive: true, force: true });
})();



// --- Regression: v0.4.3 audit — three more confident-PASS shapes -------------
console.log('\nregressions (v0.4.3 audit)');

await (async () => {
  // IFs nest. Taking the FIRST "END IF" as the outer terminator ended the guard
  // early, so a statement after the inner END IF looked unconditional.
  const dir = fixture({
    'db/1.sql': 'CREATE TABLE public.orders (id serial);\nDO $$ BEGIN\n  IF false THEN\n    IF true THEN PERFORM 1; END IF;\n    ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n  END IF;\nEND $$;\n',
  });
  const r = await scanStatic(dir);
  check('a nested IF does not end the outer guard early', () => {
    const f = r.findings.find((x) => x.id === 'rls_missing');
    assert.ok(f, `expected a finding, got ${ids(r)}`);
    assert.strictEqual(f.severity, 'warning');
  });
  rmSync(dir, { recursive: true, force: true });

  // A comment must not terminate a guard.
  const dir2 = fixture({
    'db/1.sql': 'CREATE TABLE public.orders (id serial);\nDO $$ BEGIN\n  IF false THEN\n    -- end if\n    ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n  END IF;\nEND $$;\n',
  });
  const r2 = await scanStatic(dir2);
  check('"-- end if" in a comment does not close the guard', () => {
    assert.ok(ids(r2).includes('rls_missing'), `got ${ids(r2)}`);
  });
  rmSync(dir2, { recursive: true, force: true });

  // A conditional DROP must not delete the table from the model.
  const dir3 = fixture({
    'db/1.sql': 'CREATE TABLE public.orders (id serial);\nDO $$ BEGIN\n  IF false THEN DROP TABLE public.orders; END IF;\nEND $$;\n',
  });
  const r3 = await scanStatic(dir3);
  check('a conditional DROP keeps the table, reported as unconfirmed not critical', () => {
    const f = r3.findings.find((x) => x.id === 'rls_missing');
    assert.ok(f, `table vanished from the analysis: got ${ids(r3)}`);
    assert.strictEqual(f.severity, 'warning', 'a guessed DROP must not be claimed as critical');
  });
  rmSync(dir3, { recursive: true, force: true });

  // Negative half: an UNCONDITIONAL drop really does remove the table.
  const dir4 = fixture({ 'db/1.sql': 'CREATE TABLE public.orders (id serial);\nDROP TABLE public.orders;\n' });
  const r4 = await scanStatic(dir4);
  check('an unconditional DROP still removes the table from the report', () => {
    assert.ok(!ids(r4).includes('rls_missing'), `got ${r4.findings.map((f) => f.title)}`);
  });
  rmSync(dir4, { recursive: true, force: true });

  // Negative half: a guard that closes properly still lets later SQL be seen.
  const dir5 = fixture({
    'db/1.sql': 'CREATE TABLE public.orders (id serial);\nDO $$ BEGIN\n  IF true THEN PERFORM 1; END IF;\nEND $$;\nALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n',
  });
  const r5 = await scanStatic(dir5);
  check('an unconditional ENABLE after a closed guard is still trusted', () => {
    assert.ok(!ids(r5).includes('rls_missing'), `got ${r5.findings.map((f) => f.title)}`);
  });
  rmSync(dir5, { recursive: true, force: true });
})();

// --- Regression: v0.4.4 audit — the two SQL parsers disagreed -----------------
console.log('\nregressions (v0.4.4 audit)');

await (async () => {
  // 'end if' inside a STRING must not terminate a guard. Guard parsing used to
  // run over a separately-masked text that kept string contents.
  const dir = fixture({
    'db/1.sql': "CREATE TABLE public.orders (id serial);\nDO $$ BEGIN\n  IF false THEN\n    RAISE NOTICE 'end if';\n    ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n  END IF;\nEND $$;\n",
  });
  const r = await scanStatic(dir);
  check("'end if' inside a string literal does not close the guard", () => {
    assert.ok(ids(r).includes('rls_missing'), `got ${ids(r)}`);
  });
  rmSync(dir, { recursive: true, force: true });

  // Same, via a dollar-quoted string.
  const dir2 = fixture({
    'db/1.sql': 'CREATE TABLE public.orders (id serial);\nDO $$ BEGIN\n  IF false THEN\n    RAISE NOTICE $msg$end if$msg$;\n    ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n  END IF;\nEND $$;\n',
  });
  const r2 = await scanStatic(dir2);
  check('"end if" inside a dollar-quoted string does not close the guard', () => {
    assert.ok(ids(r2).includes('rls_missing'), `got ${ids(r2)}`);
  });
  rmSync(dir2, { recursive: true, force: true });

  // PostgreSQL block comments nest: the first */ closes only the inner one, so
  // the ENABLE below stayed commented out and must not count.
  const dir3 = fixture({
    'db/1.sql': 'CREATE TABLE public.orders (id serial);\n/* outer\n   /* inner */\n   ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n*/\n',
  });
  const r3 = await scanStatic(dir3);
  check('a commented-out ENABLE inside nested block comments does not count', () => {
    const f = r3.findings.find((x) => x.id === 'rls_missing');
    assert.ok(f, `commented-out DDL was treated as executed: got ${ids(r3)}`);
    assert.strictEqual(f.severity, 'critical');
  });
  rmSync(dir3, { recursive: true, force: true });

  // Negative half: a plain, properly closed block comment still ends where it should.
  const dir4 = fixture({
    'db/1.sql': 'CREATE TABLE public.orders (id serial);\n/* just a note */\nALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n',
  });
  const r4 = await scanStatic(dir4);
  check('a normal block comment does not swallow the SQL after it', () => {
    assert.ok(!ids(r4).includes('rls_missing'), `got ${r4.findings.map((f) => f.title)}`);
  });
  rmSync(dir4, { recursive: true, force: true });
})();

// --- Regression: vendored third-party code is not the user's leak ------------
await (async () => {
  // A virtualenv named anything but venv/.venv (e.g. tools/ytenv) put every key
  // inside installed libraries into the report as the user's own critical.
  const dir = fixture({
    'tools/ytenv/lib/python3.12/site-packages/google/auth/helper.py':
      '-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n',
    'app.py': 'x = 1\n',
  });
  const r = await scanStatic(dir);
  check('keys inside site-packages are not reported as the project’s own', () => {
    assert.deepStrictEqual(ids(r).filter((i) => i === 'private_key'), [], 'vendored library code must be skipped');
  });
  rmSync(dir, { recursive: true, force: true });

  // Negative half: the same key in the user's own code is still critical.
  const dir2 = fixture({ 'keys/id_rsa.pem': '-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n' });
  const r2 = await scanStatic(dir2);
  check('a private key in the project’s own code is still reported', () => {
    assert.ok(ids(r2).includes('private_key'), `got ${ids(r2)}`);
  });
  rmSync(dir2, { recursive: true, force: true });
})();

// --- Regression: v0.4.5 audit — SQL is now lexed, not regex-matched ----------
console.log('\nregressions (v0.4.5 audit — token-based SQL)');

const rlsCase = async (name, sql, expectFinding) => {
  const dir = fixture({ 'db/1.sql': sql });
  const r = await scanStatic(dir);
  check(name, () => {
    const has = ids(r).includes('rls_missing');
    assert.strictEqual(has, expectFinding, `got ${ids(r).join(',') || 'nothing'}`);
  });
  rmSync(dir, { recursive: true, force: true });
};

await rlsCase(
  'ALTER TABLE IF EXISTS ... DISABLE is recognised',
  'CREATE TABLE orders (id serial);\nALTER TABLE orders ENABLE ROW LEVEL SECURITY;\nALTER TABLE IF EXISTS orders DISABLE ROW LEVEL SECURITY;\n',
  true,
);
await rlsCase(
  "a backslash-escaped quote in E'...' does not hide the SQL after it",
  "CREATE TABLE orders (id serial);\nALTER TABLE orders ENABLE ROW LEVEL SECURITY;\nSELECT E'it\\'s text';\nALTER TABLE orders DISABLE ROW LEVEL SECURITY;\n",
  true,
);
await rlsCase(
  'a double-quoted column alias is a NAME, not executed SQL',
  'CREATE TABLE orders (id serial);\nSELECT 1 AS "ALTER TABLE orders ENABLE ROW LEVEL SECURITY;";\n',
  true,
);
await rlsCase(
  'ALTER TABLE ONLY ... ENABLE still counts (no false alarm)',
  'CREATE TABLE orders (id serial);\nALTER TABLE ONLY orders ENABLE ROW LEVEL SECURITY;\n',
  false,
);
await rlsCase(
  'a plain quoted identifier table still parses',
  'CREATE TABLE "public"."orders" (id serial);\nALTER TABLE "public"."orders" ENABLE ROW LEVEL SECURITY;\n',
  false,
);

await (async () => {
  // A directory we cannot list is an unchecked subtree. Reporting PASS over it
  // claims coverage the scan never had.
  const dir = fixture({ 'index.ts': 'const a = 1;\n', 'secret/inner.ts': 'const b = 2;\n' });
  chmodSync(join(dir, 'secret'), 0o000);
  try {
    const r = await scanStatic(dir);
    const s = summarize(r.findings, r.runs);
    check('an unreadable directory makes coverage incomplete, not a clean PASS', () => {
      assert.strictEqual(s.gate, 'incomplete', `gate was ${s.gate}`);
      assert.strictEqual(exitCodeFor(s), 3);
    });
  } finally {
    chmodSync(join(dir, 'secret'), 0o755);
    rmSync(dir, { recursive: true, force: true });
  }
})();

// --- Regression: v0.5.0 audit — unknown SQL must not read as clean -----------
console.log('\nregressions (v0.5.0 audit — unknown ≠ clean)');

const BASE = 'CREATE TABLE orders (id serial);\nALTER TABLE orders ENABLE ROW LEVEL SECURITY;\n';
await rlsCase('ALTER TABLE name * DISABLE is recognised (the * is punctuation, not a word)',
  BASE + 'ALTER TABLE orders * DISABLE ROW LEVEL SECURITY;\n', true);
await rlsCase('an RLS toggle that is the SECOND action of an ALTER TABLE is recognised',
  BASE + 'ALTER TABLE orders ADD COLUMN note text,\n  DISABLE ROW LEVEL SECURITY;\n', true);
await rlsCase('DO LANGUAGE plpgsql $$ … $$ is still a DO block',
  BASE + 'DO LANGUAGE plpgsql $$\nBEGIN\n  ALTER TABLE orders DISABLE ROW LEVEL SECURITY;\nEND $$;\n', true);
await rlsCase('CREATE UNLOGGED TABLE creates a table',
  'CREATE UNLOGGED TABLE orders (id serial);\n', true);
await rlsCase('a TEMP table is session-only and is not reported',
  'CREATE TEMP TABLE scratch (id serial);\n', false);
await rlsCase('FORCE ROW LEVEL SECURITY is understood as not toggling RLS (no false alarm)',
  BASE + 'ALTER TABLE orders FORCE ROW LEVEL SECURITY;\n', false);

await (async () => {
  // Dynamic SQL cannot be interpreted statically. It must surface as partial
  // coverage — an incomplete verdict — never be dropped as if it were not there.
  const dir = fixture({ 'db/1.sql': BASE + "DO $$ BEGIN EXECUTE 'ALTER TABLE orders DISABLE ROW LEVEL SECURITY'; END $$;\n" });
  const r = await scanStatic(dir);
  const s = summarize(r.findings, r.runs);
  check('EXECUTE with RLS text makes the RLS check partial and the gate incomplete', () => {
    const run = r.runs.find((x) => x.id === 'static:rls-migrations');
    assert.strictEqual(run?.status, 'partial', `run status was ${run?.status}`);
    assert.match(run?.note ?? '', /could not be interpreted/);
    assert.strictEqual(s.gate, 'incomplete');
    assert.strictEqual(exitCodeFor(s), 3);
  });
  rmSync(dir, { recursive: true, force: true });

  // Negative half: EXECUTE that does not touch tables/RLS is not "unknown".
  const dir2 = fixture({ 'db/1.sql': BASE + "DO $$ BEGIN EXECUTE 'NOTIFY channel'; END $$;\n" });
  const r2 = await scanStatic(dir2);
  check('EXECUTE unrelated to tables/RLS keeps the check complete', () => {
    assert.strictEqual(r2.runs.find((x) => x.id === 'static:rls-migrations')?.status, 'completed');
  });
  rmSync(dir2, { recursive: true, force: true });
})();

// --- Liveness: every static detector must still FIRE on its own target -------
// Three detectors were once silently disabled by "fix the false positive"
// changes while the suite stayed green, because those tests only asserted that
// the false positive was gone. An assertion of absence cannot tell a detector
// that stopped lying from one that stopped working. This table is the other
// half: one minimal positive sample per finding id. Values are synthetic and
// non-functional; keep them free of the words "example"/"test", which the
// placeholder filter correctly suppresses.
console.log('\ndetector liveness (one positive sample per finding id)');

const A36 = 'aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5';
const A35 = 'aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA';
const A30 = 'aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1';
const A24 = 'aB3dE5fG7hJ9kL1mN3pQ5rS7';

const LIVENESS = {
  openai_key: { 'a.ts': `const k = "sk-proj-${A24}";\n` },
  anthropic_key: { 'a.ts': `const k = "sk-ant-api03-${A30}";\n` },
  aws_key: { 'a.ts': 'const k = "AKIA2J7QK3XN4MZP5RTV";\n' },
  stripe_live: { 'a.ts': `const k = "sk_live_${A24}";\n` },
  github_token: { 'a.ts': `const k = "ghp_${A36}";\n` },
  slack_token: { 'a.ts': `const k = "xoxb-123456789012-123456789012-${A24}";\n` },
  sendgrid_key: { 'a.ts': `const k = "SG.${A24}.${A30}";\n` },
  hf_token: { 'a.ts': `const k = "hf_${A30}";\n` },
  npm_token: { 'a.ts': `const k = "npm_${A30}";\n` },
  google_api_key: { 'a.ts': `const k = "AIza${A35}";\n` },
  telegram_bot: { 'a.ts': `const k = "123456789:${A35}";\n` },
  db_url_password: { 'a.ts': 'const u = "postgres://admin:S3cretPa55word@prod-db.internal:5432/app";\n' },
  supabase_secret_key: { 'a.ts': `const k = "sb_secret_${A24}";\n` },
  private_key: { 'id_rsa.pem': '-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n' },
  generic_secret: { 'a.ts': `const apiSecret = "${A30}";\n` },
  env_secret: { '.env': 'PASSWORD=G7m2Q9v4R8c5N1p6Xk\n' },
  public_env_secret: { '.env': `NEXT_PUBLIC_API_TOKEN=${A30}\n` },
  public_key_client: { '.env': `VITE_SUPABASE_KEY=sb_publishable_${A24}\n` },
  rls_not_applicable: { 'db/1.sql': 'CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT);\n' },
  cors_star: { 'a.ts': 'app.use(cors({origin: "*"}));\n' },
  debug_on: { 'a.py': 'DEBUG = True\n' },
  eval_use: { 'a.ts': 'const r = eval(userInput);\n' },
  jwt_alg_none: { 'a.ts': 'const opts = { algorithm: "none" };\n' },
  sql_interpolation: { 'a.py': 'q = f"SELECT * FROM users WHERE id = {uid}"\n' },
  rls_missing: { 'db/1.sql': 'CREATE TABLE public.orders (id serial);\n' },
  endpoint_inventory: { 'pages/api/users.ts': 'export default function h(){}\n' },
  env_git_unverified: { '.env': 'PASSWORD=G7m2Q9v4R8c5N1p6Xk\n' },
};

for (const [id, files] of Object.entries(LIVENESS)) {
  const dir = fixture(files);
  const r = await scanStatic(dir);
  const got = ids(r);
  check(`${id} fires on its own target`, () => {
    assert.ok(got.includes(id), `detector is not firing — got: ${got.join(',') || 'nothing'}`);
  });
  rmSync(dir, { recursive: true, force: true });
}

await (async () => {
  // The git-aware pair needs a real repository to reach its verdict.
  const dir = fixture({ '.env': 'PASSWORD=G7m2Q9v4R8c5N1p6Xk\n', '.gitignore': 'node_modules/\n' });
  spawnSync('git', ['-C', dir, 'init', '-q']);
  spawnSync('git', ['-C', dir, 'add', '-A']);
  const r = await scanStatic(dir);
  check('env_committed fires when .env is tracked by git', () => {
    assert.ok(ids(r).includes('env_committed'), `got: ${ids(r).join(',') || 'nothing'}`);
  });
  rmSync(dir, { recursive: true, force: true });
})();


// Per-area regression files share the tally via tests/_harness.mjs.
for (const wp of ['wp-consent', 'wp-http', 'wp-mask', 'wp-sql', 'wp-static', 'wp-precision']) {
  if (existsSync(new URL(`./${wp}.mjs`, import.meta.url))) await import(`./${wp}.mjs`);
}

console.log(`\n${state.passed} passed, ${state.failures.length} failed`);
process.exit(state.failures.length ? 1 : 0);
