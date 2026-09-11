// Lightweight regression tests for the detectors. Run with `pnpm test` after `pnpm build`.
// Offline only — no network, no real backends.
import assert from 'node:assert';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanStatic } from '../dist/engine/scan.js';
import { collectEndpoints, concretePath } from '../dist/engine/endpoints.js';
import { discoverSupabase } from '../dist/engine/checkers/backend/supabase.js';

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

console.log(`\n${passed} passed, ${failures.length} failed`);
process.exit(failures.length ? 1 : 0);
