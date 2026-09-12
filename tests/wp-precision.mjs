// Precision regressions from the real-project ground truth (25 projects in
// Pet&Tests): every class that was mostly noise, and the one real leak the
// tool under-reported. Each has its positive and negative half.
import assert from 'node:assert';
import { rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { scanStatic } from '../dist/engine/scan.js';
import { summarize } from '../dist/engine/report.js';
import { check, fixture, ids } from './_harness.mjs';

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
