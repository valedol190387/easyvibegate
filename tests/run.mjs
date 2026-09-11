// Lightweight regression tests for the detectors. Run with `pnpm test` after `pnpm build`.
// Offline only — no network, no real backends.
import assert from 'node:assert';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { scanStatic } from '../dist/engine/scan.js';
import { collectEndpoints, concretePath } from '../dist/engine/endpoints.js';
import { discoverSupabase } from '../dist/engine/checkers/backend/supabase.js';
import { setRequestImpl } from '../dist/engine/net/http.js';
import { checkLiveSite } from '../dist/engine/checkers/live/http-checks.js';
import { idorDifferential } from '../dist/engine/checkers/live/idor.js';
import { summarize, exitCodeFor, badgeMarkdown } from '../dist/engine/report.js';

const CLI = new URL('../dist/cli/index.js', import.meta.url).pathname;
const ok = (status, body = '{"id":1}', headers = {}) => ({ status, ok: status < 300, headers: new Headers(headers), body });
const ALL_HEADERS = { 'content-security-policy': 'x', 'strict-transport-security': 'x', 'x-frame-options': 'x', 'x-content-type-options': 'x' };

let passed = 0;
const failures = [];
function check(name, fn) {
  try { fn(); passed++; console.log(`  ✓ ${name}`); }
  catch (e) { failures.push(name); console.log(`  ✗ ${name}\n     ${e.message}`); }
}

function fixture(files) {
  const dir = mkdtempSync(join(tmpdir(), 'evg-test-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, content, 'utf8');
  }
  return dir;
}
const ids = (r) => r.findings.map((f) => f.id);

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
  check('secrets in .env are warnings, not source-leak criticals', () => {
    const openai = r.findings.find((f) => f.id === 'openai_key');
    assert.ok(openai, 'openai key should be found');
    assert.strictEqual(openai.severity, 'warning');
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
  const r = await scanStatic(dir);
  check('secrets: vendor key in config.yml stays critical (not downgraded)', () => {
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

console.log(`\n${passed} passed, ${failures.length} failed`);
process.exit(failures.length ? 1 : 0);
