// Regressions for the per-language lexer behind masking, inline suppression,
// generated-file coverage and config validation (audit findings F10/F11/F12/F15/F22).
// Every fix has a positive half (defect now handled) and a negative half
// (legitimate case unchanged) — a suite that only asserts absence once hid
// three dead detectors behind a green run.
import assert from 'node:assert';
import { rmSync, chmodSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { scanStatic } from '../dist/engine/scan.js';
import { summarize } from '../dist/engine/report.js';
import { loadConfig, applyIgnores, partitionIgnores, validateConfig, validateConfigFile } from '../dist/engine/config.js';
import { maskCode } from '../dist/engine/util/mask.js';
import { lexCode, langForFile } from '../dist/engine/util/code-lex.js';
import { check, fixture, ids } from './_harness.mjs';

console.log('\nWP mask');

const configRun = (r) => r.runs.find((x) => x.id === 'static:config-risks');
const crIds = (r) => r.findings.filter((f) => f.checker === 'config-risks').map((f) => f.id);

// --- F10: language-aware masking --------------------------------------------

await (async () => {
  const dir = fixture({
    'url.ts': 'const url="https://example.test"; const cfg={algorithm:"none"};\n',
    'priv.ts': 'class X { #value = eval(input); }\n',
    'floor.py': 'x = 4 // 2; debug = True\n',
  });
  const r = await scanStatic(dir);
  check('F10: `//` inside a URL string does not hide alg:none after it', () => {
    assert.ok(r.findings.some((f) => f.id === 'jwt_alg_none' && f.file === 'url.ts'), `got ${ids(r)}`);
  });
  check('F10: a JS #private field is not a comment — eval after it is seen', () => {
    assert.ok(r.findings.some((f) => f.id === 'eval_use' && f.file === 'priv.ts'), `got ${ids(r)}`);
  });
  check('F10: Python floor division `//` is not a comment — debug=True after it is seen', () => {
    assert.ok(r.findings.some((f) => f.id === 'debug_on' && f.file === 'floor.py'), `got ${ids(r)}`);
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({
    'c.ts': '// algorithm: "none"\nconst url="https://example.test"; // eval(input)\n',
    'c.py': '# debug = True\nx = 1  # eval(user)\n',
    'c.sql': '-- algorithm: "none"\n/* debug = True */\nSELECT 1;\n',
  });
  const r = await scanStatic(dir);
  check('F10 negative: the same constructs inside real comments stay silent', () => {
    assert.deepStrictEqual(crIds(r), []);
  });
  rmSync(dir, { recursive: true, force: true });
})();

check('F10 lexer: JS comment vs operator vs string are told apart', () => {
  const types = (src) => lexCode(src, 'js').map((t) => t.type);
  assert.deepStrictEqual(types('a // c'), ['word', 'comment']);
  assert.deepStrictEqual(types('a / b'), ['word', 'punct', 'word']);
  assert.deepStrictEqual(types('"//" + x'), ['string', 'punct', 'word']);
  assert.deepStrictEqual(types('/* c */ #p'), ['comment', 'word']);
  assert.deepStrictEqual(types('r = /\\/"/g; x'), ['word', 'punct', 'regex', 'punct', 'word'], 'a regex literal is atomic');
});

check('F10 lexer: Python comment vs operator vs string are told apart', () => {
  const types = (src) => lexCode(src, 'python').map((t) => t.type);
  assert.deepStrictEqual(types('a # c'), ['word', 'comment']);
  assert.deepStrictEqual(types('a // b'), ['word', 'punct', 'punct', 'word']);
  assert.deepStrictEqual(types('"#" + x'), ['string', 'punct', 'word']);
  assert.deepStrictEqual(types('"""a\n# b\n""" # c'), ['string', 'comment'], 'a triple-quoted string spans lines');
});

check('F10 lexer: language is chosen by extension, unknown stays legacy-mixed', () => {
  assert.strictEqual(langForFile('src/a.tsx'), 'js');
  assert.strictEqual(langForFile('app/main.py'), 'python');
  assert.strictEqual(langForFile('db/001.sql'), 'sql');
  assert.strictEqual(langForFile('.env.local'), 'hash');
  assert.strictEqual(langForFile('x/App.vue'), 'html');
  assert.strictEqual(langForFile('weird.xyz'), 'mixed');
});

check('F10 mask: strings are atomic and length/newlines are preserved', () => {
  const src = 'const u = "https://x"; // c\nconst v = `a ${b} // not a comment`;\n';
  const out = maskCode(src, { file: 'a.ts' });
  assert.strictEqual(out.length, src.length);
  assert.strictEqual(out.split('\n').length, src.split('\n').length);
  assert.ok(out.includes('const u = "https://x";'), 'string kept');
  assert.ok(!out.includes('// c'), 'comment blanked');
  assert.ok(out.includes('// not a comment`'), 'template contents kept');
  const noStr = maskCode(src, { file: 'a.ts', strings: true });
  assert.ok(!noStr.includes('https') && !noStr.includes('not a comment'), 'strings and templates blanked on request');
});

// --- F11: skipped files are visible as missing coverage -----------------------

await (async () => {
  const dir = fixture({
    'src/app.ts': 'const blob = "' + 'x'.repeat(900) + '"; const cfg = { algorithm: "none" };\n',
  });
  const r = await scanStatic(dir);
  check('F11: one long line no longer turns config-risks into a silent clean pass', () => {
    const run = configRun(r);
    const found = crIds(r).includes('jwt_alg_none');
    assert.ok(found || run.status === 'partial', `not found and run is ${run.status}: coverage lost silently`);
    assert.ok(found, 'length-bounded rules should scan the line, not skip it');
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({
    'vendor.min.js': 'var h={algorithm:"none"};\n',
    'src/ok.ts': 'const a = 1;\n',
  });
  const r = await scanStatic(dir);
  check('F11: a skipped .min.js is named in a partial run and the gate is incomplete', () => {
    const run = configRun(r);
    assert.strictEqual(run.status, 'partial', JSON.stringify(run));
    assert.match(run.note, /vendor\.min\.js/);
    assert.strictEqual(summarize(r.findings, r.runs).gate, 'incomplete');
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ 'src/ok.ts': 'const a = 1;\n' });
  const r = await scanStatic(dir);
  check('F11 negative: a project without generated files keeps config-risks completed', () => {
    assert.strictEqual(configRun(r).status, 'completed');
  });
  rmSync(dir, { recursive: true, force: true });
})();

// --- F12: suppression only from a comment token ------------------------------

await (async () => {
  const dir = fixture({
    'str.ts': 'const label = "easyvibegate-ignore";\nconst cfg = { algorithm: "none" };\n',
    'above.ts': '// easyvibegate-ignore\nconst cfg = { algorithm: "none" };\n',
    'same.ts': 'const cfg = { algorithm: "none" }; /* easyvibegate-ignore */\n',
    'py.py': '# easyvibegate-ignore\nDEBUG = True\n',
    'scoped-miss.ts': '// easyvibegate-ignore: eval_use\nconst cfg = { algorithm: "none" };\n',
    'scoped-hit.ts': '// easyvibegate-ignore: eval_use, jwt_alg_none\nconst cfg = { algorithm: "none" };\n',
  });
  const r = await scanStatic(dir);
  const files = (id) => r.findings.filter((f) => f.id === id).map((f) => f.file);
  check('F12: the marker inside a string literal does NOT suppress', () => {
    assert.ok(files('jwt_alg_none').includes('str.ts'), `got ${files('jwt_alg_none')}`);
  });
  check('F12 negative: a real `//` comment above still suppresses', () => {
    assert.ok(!files('jwt_alg_none').includes('above.ts'));
  });
  check('F12 negative: a block comment on the same line still suppresses', () => {
    assert.ok(!files('jwt_alg_none').includes('same.ts'));
  });
  check('F12 negative: a Python `#` comment still suppresses', () => {
    assert.ok(!files('debug_on').includes('py.py'));
  });
  check('F12: a scoped marker only suppresses the ids it names', () => {
    assert.ok(files('jwt_alg_none').includes('scoped-miss.ts'), 'scope for another id must not apply');
    assert.ok(!files('jwt_alg_none').includes('scoped-hit.ts'), 'scope naming the id must apply');
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({
    'db/001.sql': '-- easyvibegate-ignore\nCREATE TABLE public.orders (id serial);\n',
    'db/002.sql': "INSERT INTO t VALUES ('easyvibegate-ignore');\nCREATE TABLE public.users (id serial);\n",
  });
  const r = await scanStatic(dir);
  const files = r.findings.filter((f) => f.id === 'rls_missing').map((f) => f.file);
  check('F12: SQL `-- easyvibegate-ignore` suppresses, a SQL string with the marker does not', () => {
    assert.ok(!files.includes('db/001.sql'), `comment marker ignored: ${files}`);
    assert.ok(files.includes('db/002.sql'), `string marker suppressed a finding: ${files}`);
  });
  rmSync(dir, { recursive: true, force: true });
})();

check('F12: partitionIgnores exposes the suppressed findings for counting', () => {
  const files = [{ rel: 'a.ts', content: '// easyvibegate-ignore\nconst x = 1;\n' }];
  const finding = { id: 'eval_use', checker: 'config-risks', severity: 'warning', title: '', detail: '', fix: '', level: 0, file: 'a.ts', line: 2 };
  const cfg = { ignore: ['secrets'], ignorePaths: [] };
  const other = { ...finding, id: 'openai_key', checker: 'secrets', line: 99 };
  const kept = { ...finding, file: 'b.ts' };
  const res = partitionIgnores([finding, other, kept], cfg, files);
  assert.deepStrictEqual(res.kept, [kept]);
  assert.strictEqual(res.suppressed.length, 2);
  assert.deepStrictEqual(applyIgnores([finding, other, kept], cfg, files), [kept], 'applyIgnores keeps its return type');
});

// --- F15: parameterizing sql tags are not interpolation -----------------------

await (async () => {
  const dir = fixture({
    'tag.ts': 'const r = sql`SELECT * FROM users WHERE id = ${id}`;\n',
    'db.ts': 'const r = db.sql`SELECT * FROM users WHERE id = ${id}`;\n',
    'prisma.ts': 'const r = prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;\n',
    'plain.ts': 'const r = `SELECT * FROM users WHERE id = ${id}`;\n',
    'query.ts': 'db.query(`SELECT * FROM users WHERE id = ${id}`);\n',
    'unsafe.ts': 'sql.unsafe`SELECT * FROM users WHERE id = ${id}`;\n',
    'rawunsafe.ts': 'prisma.$queryRawUnsafe`SELECT * FROM users WHERE id = ${id}`;\n',
    'f.py': 'q = f"SELECT * FROM users WHERE id = {uid}"\n',
  });
  const r = await scanStatic(dir);
  const files = r.findings.filter((f) => f.id === 'sql_interpolation').map((f) => f.file);
  check('F15: sql`…` / db.sql`…` / prisma.$queryRaw`…` tags are parameterized, not reported', () => {
    for (const f of ['tag.ts', 'db.ts', 'prisma.ts']) assert.ok(!files.includes(f), `${f} reported: ${files}`);
  });
  check('F15 negative: untagged, .query(`…`), sql.unsafe and $queryRawUnsafe are still reported', () => {
    for (const f of ['plain.ts', 'query.ts', 'unsafe.ts', 'rawunsafe.ts']) assert.ok(files.includes(f), `${f} missing: ${files}`);
  });
  check('F15 negative: Python f-string SQL is still reported', () => {
    assert.ok(files.includes('f.py'), `got ${files}`);
  });
  rmSync(dir, { recursive: true, force: true });
})();

// --- F22: one validator for discovered and explicit configs -----------------

await (async () => {
  const dir = fixture({
    'a.ts': 'const cfg = { algorithm: "none" };\n',
    'easyvibegate.config.json': '{ "ignorePath": ["a.ts"] }',
  });
  const r = await scanStatic(dir);
  check('F22: a typo key in the auto-discovered config fails the config run → gate incomplete', () => {
    const run = r.runs.find((x) => x.id === 'config');
    assert.ok(run && run.status === 'failed', JSON.stringify(r.runs));
    assert.match(run.note, /unknown key/);
    // The critical finding wins the gate (fail > incomplete), so check coverage itself here.
    assert.strictEqual(summarize(r.findings, r.runs).coverage.incomplete, true);
    assert.ok(ids(r).includes('jwt_alg_none'), 'a broken config must not suppress anything');
  });
  rmSync(dir, { recursive: true, force: true });

  const clean = fixture({ 'a.ts': 'const a = 1;\n', 'easyvibegate.config.json': '{ "ignorePath": ["a.ts"] }' });
  const rc = await scanStatic(clean);
  check('F22: on an otherwise clean project the typo config makes the gate incomplete, not pass', () => {
    assert.strictEqual(summarize(rc.findings, rc.runs).gate, 'incomplete', JSON.stringify(rc.runs));
  });
  rmSync(clean, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({
    'a.ts': 'const cfg = { algorithm: "none" };\n',
    'easyvibegate.config.json': '{ "ignorePaths": [1, 2] }',
  });
  const r = await scanStatic(dir);
  check('F22: non-string array items in the discovered config are a failed config run', () => {
    const run = r.runs.find((x) => x.id === 'config');
    assert.ok(run && run.status === 'failed', JSON.stringify(r.runs));
    assert.match(run.note, /array of strings/);
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({
    'a.ts': 'const cfg = { algorithm: "none" };\n',
    'easyvibegate.config.json': '{ "ignore": ["jwt_alg_none"] }',
  });
  const r = await scanStatic(dir);
  check('F22 negative: a valid discovered config still applies and records no problem', () => {
    assert.ok(!r.runs.some((x) => x.id === 'config'), JSON.stringify(r.runs));
    assert.ok(!ids(r).includes('jwt_alg_none'), `got ${ids(r)}`);
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({
    'ok.json': '{ "ignore": ["x"], "ignorePaths": ["tests/"] }',
    'bad.json': '{ not json',
    'typo.json': '{ "ignorePath": ["x"] }',
    'types.json': '{ "ignore": "x" }',
    'list.json': '[1]',
  });
  check('F22: validateConfigFile mirrors the CLI checks', () => {
    assert.strictEqual(validateConfigFile(join(dir, 'ok.json')), null);
    assert.match(validateConfigFile(dir), /not a file/);
    assert.match(validateConfigFile(join(dir, 'missing.json')), /not found/);
    assert.match(validateConfigFile(join(dir, 'bad.json')), /invalid JSON/);
    assert.match(validateConfigFile(join(dir, 'typo.json')), /unknown key/);
    assert.match(validateConfigFile(join(dir, 'types.json')), /"ignore" must be an array of strings/);
    assert.match(validateConfigFile(join(dir, 'list.json')), /JSON object/);
  });
  check('F22: validateConfig on a parsed object', () => {
    assert.strictEqual(validateConfig({ ignore: [] }), null);
    assert.match(validateConfig({ ignorePath: [] }), /unknown key/);
    assert.match(validateConfig(null), /JSON object/);
  });
  check('F22: loadConfig with an explicit missing path is a problem, not "no config"', () => {
    assert.match(loadConfig(dir, join(dir, 'missing.json')).problem ?? '', /not found/);
    assert.strictEqual(loadConfig(dir).problem, undefined, 'no discoverable config here → defaults, no problem');
  });
  // An EXISTING config that cannot be read is missing rules, never "no config".
  if (process.getuid?.() !== 0) {
    const p = join(dir, 'easyvibegate.config.json');
    writeFileSync(p, '{ "ignore": ["x"] }');
    chmodSync(p, 0o000);
    check('F22: an unreadable existing config is reported as a problem', () => {
      assert.match(loadConfig(dir).problem ?? '', /cannot read/);
    });
    chmodSync(p, 0o644);
  }
  rmSync(dir, { recursive: true, force: true });
})();
