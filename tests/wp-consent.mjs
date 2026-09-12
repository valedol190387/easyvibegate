// Consent is bound to a concrete target, and a requested check that did not run
// stays visible in coverage (F02, F04/C01, C02, N14). Offline: the network is
// mocked in-process; CLI runs only ever decline or hit 127.0.0.1:1.
import assert from 'node:assert';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runFlow, planTargets } from '../dist/orchestrator/flow.js';
import { loadConfig } from '../dist/engine/config.js';
import { setRequestImpl } from '../dist/engine/net/http.js';
import { summarize, exitCodeFor } from '../dist/engine/report.js';
import { check, fixture, runCli, ok, state } from './_harness.mjs';

console.log('\nWP consent');

// A syntactically valid Supabase anon JWT (role=anon) — discovery only accepts that role.
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const ANON_JWT = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ role: 'anon', iss: 'supabase' })}.${'x'.repeat(32)}`;
const sbFile = (url) => `export const SUPABASE_URL = "${url}";\nexport const SUPABASE_ANON_KEY = "${ANON_JWT}";\n`;
const OLD = 'https://old.invalid';
const CURRENT = 'https://current.invalid';
const F02_FIXTURE = {
  'a.ts': sbFile(OLD),
  'z.ts': sbFile(CURRENT),
  'easyvibegate.config.json': JSON.stringify({ ignorePaths: ['a.ts'] }),
};
const outDir = () => mkdtempSync(join(tmpdir(), 'evg-out-'));
const runsOf = (out) => JSON.parse(readFileSync(join(out, 'report.json'), 'utf8')).runs;

// --- F02: the target shown at the consent prompt is the target that is probed ---

await (async () => {
  const dir = fixture(F02_FIXTURE);
  const asked = [];
  const sent = [];
  setRequestImpl(async (url) => { sent.push(url); return ok(200, '[]'); });
  const r = await runFlow({ root: dir, consent: async (req) => { asked.push(req); return true; } });
  setRequestImpl(null);
  check('F02: consent names the config-visible Supabase host, not the ignored file\'s host', () => {
    const sb = asked.find((q) => q.kind === 'supabase');
    assert.ok(sb, `no supabase consent asked; asked: ${asked.map((q) => q.kind).join(',')}`);
    assert.strictEqual(sb.target, CURRENT);
    assert.strictEqual(sb.explicit, false, 'an auto-discovered target is not explicit');
  });
  check('F02: every request goes to the host the user consented to', () => {
    assert.ok(sent.length > 0, 'the probe sent nothing');
    const strangers = sent.filter((u) => !u.startsWith(CURRENT));
    assert.deepStrictEqual(strangers, [], `requests left the consented host: ${strangers.slice(0, 3).join(', ')}`);
    assert.ok(r.runs.some((x) => x.id === 'supabase-probe' && x.status !== 'skipped' && x.status !== 'unsupported'));
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  // The real wizard: the Supabase question must print the host it will probe.
  const dir = fixture(F02_FIXTURE);
  const p = runCli([dir, '--wizard', '--format', 'none', '--lang', 'en'], { input: 'n\nn\n\n' });
  check('F02: the wizard question shows the config-visible host (and never the ignored one)', () => {
    assert.ok(p.stdout.includes(CURRENT), `wizard did not mention ${CURRENT}: ${p.stdout.slice(0, 400)}`);
    assert.ok(!p.stdout.includes(OLD), `wizard mentioned the ignored host ${OLD}`);
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  // A caller-supplied plan is executed as-is: no second discovery may swap the target.
  const dir = fixture(F02_FIXTURE);
  const plan = planTargets([{ rel: 'only.ts', content: sbFile('https://planned.invalid') }], loadConfig(dir));
  const asked = [];
  const sent = [];
  setRequestImpl(async (url) => { sent.push(url); return ok(200, '[]'); });
  await runFlow({ root: dir, plan, consent: async (req) => { asked.push(req.target); return true; } });
  setRequestImpl(null);
  check('F02: runFlow given a plan does not re-discover from the project files', () => {
    assert.deepStrictEqual(asked, ['https://planned.invalid']);
    assert.ok(sent.length > 0 && sent.every((u) => u.startsWith('https://planned.invalid')), `sent: ${sent.slice(0, 3).join(', ')}`);
  });
  rmSync(dir, { recursive: true, force: true });
})();

check('F02: planTargets applies ignorePaths and normalizes explicit URLs', () => {
  const files = [{ rel: 'a.ts', content: sbFile(OLD) }, { rel: 'z.ts', content: sbFile(CURRENT) }];
  const plan = planTargets(files, { ignore: [], ignorePaths: ['a.ts'] });
  assert.deepStrictEqual(plan.targets.map((x) => [x.kind, x.target, x.explicit]), [['supabase', CURRENT, false]]);
  const explicit = planTargets(files, { ignore: [], ignorePaths: [] }, { appUrl: 'https://App.invalid/', idorTokens: ['a', 'b'] });
  const live = explicit.targets.filter((x) => x.kind === 'live' || x.kind === 'idor');
  assert.deepStrictEqual(live.map((x) => [x.kind, x.target, x.explicit]), [['live', 'https://app.invalid', true], ['idor', 'https://app.invalid', true]]);
});

// --- C01: --url is remembered even when ownership is declined in the wizard ---

await (async () => {
  const dir = fixture({ 'ok.ts': 'const a = 1;\n' });
  const p = runCli([dir, '--wizard', '--url', 'https://audit.invalid', '--no-report', '--lang', 'en'], { input: 'n\nn\n' });
  check('C01: --wizard --url with ownership declined exits 3 (incomplete), not 0', () => {
    assert.strictEqual(p.status, 3, `got ${p.status}: ${p.stdout.slice(-300)}`);
  });
  check('C01: the ownership prompt still appears for --url and names the target', () => {
    assert.ok(/Confirm https:\/\/audit\.invalid is YOUR app/.test(p.stdout), `no ownership prompt: ${p.stdout.slice(0, 400)}`);
    assert.ok(/requested check that did not run/.test(p.stdout), 'the wizard must say the request stays in the report');
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ 'ok.ts': 'const a = 1;\n' });
  const out = outDir();
  runCli([dir, '--wizard', '--url', 'https://audit.invalid', '--format', 'json', '-o', out, '--lang', 'en'], { input: 'n\nn\n' });
  const runs = runsOf(out);
  check('C01: declined --url is recorded as unsupported live-site + endpoint-probe runs', () => {
    for (const id of ['live-site', 'endpoint-probe']) {
      const r = runs.find((x) => x.id === id);
      assert.ok(r, `${id} run missing; runs: ${runs.map((x) => x.id).join(',')}`);
      assert.strictEqual(r.status, 'unsupported', `${id}: ${r.status}`);
      assert.ok(/requested via --url .*ownership was not confirmed/.test(r.note ?? ''), `note: ${r.note}`);
    }
  });
  rmSync(dir, { recursive: true, force: true });
  rmSync(out, { recursive: true, force: true });
})();

await (async () => {
  // A URL typed into the wizard is a request too — it must not vanish on "n".
  const dir = fixture({ 'ok.ts': 'const a = 1;\n' });
  const out = outDir();
  runCli([dir, '--wizard', '--format', 'json', '-o', out, '--lang', 'en'], { input: 'n\nhttp://127.0.0.1:1\nn\n' });
  const runs = runsOf(out);
  check('C01: a URL typed in the wizard and then declined is unsupported, not gone', () => {
    const r = runs.find((x) => x.id === 'live-site');
    assert.ok(r, `live-site run missing; runs: ${runs.map((x) => x.id).join(',')}`);
    assert.strictEqual(r.status, 'unsupported');
    assert.ok(/requested in the wizard/.test(r.note ?? ''), `note: ${r.note}`);
  });
  rmSync(dir, { recursive: true, force: true });
  rmSync(out, { recursive: true, force: true });
})();

await (async () => {
  // Negative: saying yes still runs the live check (127.0.0.1:1 refuses instantly).
  const dir = fixture({ 'ok.ts': 'const a = 1;\n' });
  const out = outDir();
  runCli([dir, '--wizard', '--url', 'http://127.0.0.1:1', '--format', 'json', '-o', out, '--lang', 'en'], { input: 'n\ny\n' });
  const runs = runsOf(out);
  check('C01 negative: --wizard --url answered "y" still runs the live check', () => {
    const r = runs.find((x) => x.id === 'live-site');
    assert.ok(r, 'live-site run missing');
    assert.notStrictEqual(r.status, 'unsupported', `live check did not run: ${r.note}`);
  });
  rmSync(dir, { recursive: true, force: true });
  rmSync(out, { recursive: true, force: true });
})();

await (async () => {
  const dir = fixture({ 'ok.ts': 'const a = 1;\n' });
  const out = outDir();
  runCli([dir, '--no-wizard', '--i-own-this', '--url', 'http://127.0.0.1:1', '--format', 'json', '-o', out]);
  const runs = runsOf(out);
  check('C01 negative: --i-own-this --url runs the live checks without a prompt', () => {
    const r = runs.find((x) => x.id === 'live-site');
    assert.ok(r, 'live-site run missing');
    assert.notStrictEqual(r.status, 'unsupported', `live check did not run: ${r.note}`);
    assert.notStrictEqual(r.status, 'skipped');
  });
  rmSync(dir, { recursive: true, force: true });
  rmSync(out, { recursive: true, force: true });
})();

// --- C02: explicit Supabase creds + no consent = unsupported, never a clean PASS ---

await (async () => {
  const dir = fixture({ 'ok.ts': 'const a = 1;\n' });
  const asked = [];
  const r = await runFlow({
    root: dir,
    supabaseUrl: 'https://explicit.invalid/',
    supabaseKey: ANON_JWT,
    consent: async (req) => { asked.push(req); return false; },
  });
  check('C02: explicit --supabase-url declined is unsupported and makes the gate incomplete', () => {
    const run = r.runs.find((x) => x.id === 'supabase-probe');
    assert.ok(run, 'supabase-probe run missing');
    assert.strictEqual(run.status, 'unsupported');
    assert.ok(/requested via --supabase-url/.test(run.note ?? ''), `note: ${run.note}`);
    assert.strictEqual(asked[0]?.explicit, true, 'the consent request must be marked explicit');
    assert.strictEqual(asked[0]?.target, 'https://explicit.invalid', 'target is normalized (no trailing slash)');
    const s = summarize([], r.runs);
    assert.strictEqual(s.gate, 'incomplete');
    assert.strictEqual(exitCodeFor(s), 3);
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  // Negative: an auto-discovered backend declined at the prompt is a voluntary skip.
  const dir = fixture({ 'z.ts': sbFile(CURRENT) });
  const r = await runFlow({ root: dir, consent: async () => false });
  check('C02 negative: auto-discovered Supabase declined is skipped and the gate stays pass', () => {
    const run = r.runs.find((x) => x.id === 'supabase-probe');
    assert.ok(run, 'the declined probe must still be visible in coverage');
    assert.strictEqual(run.status, 'skipped');
    assert.strictEqual(run.note, 'declined by user');
    assert.strictEqual(summarize([], r.runs).gate, 'pass');
    assert.notStrictEqual(summarize(r.findings, r.runs).gate, 'incomplete');
  });
  rmSync(dir, { recursive: true, force: true });
})();

// --- N14: identical IDOR tokens ---

await (async () => {
  const dir = fixture({ 'ok.ts': 'const a = 1;\n' });
  const p = runCli([dir, '--no-wizard', '--ci', '--format', 'none', '--i-own-this', '--url', 'http://127.0.0.1:1', '--idor-tokens', 'a,a']);
  check('N14: --idor-tokens a,a is rejected at argument parsing (exit 2)', () => {
    assert.strictEqual(p.status, 2, `got ${p.status}`);
    assert.ok(/DIFFERENT tokens/.test(p.stderr), `stderr: ${p.stderr}`);
  });
  const p2 = runCli([dir, '--no-wizard', '--ci', '--format', 'none', '--i-own-this', '--url', 'http://127.0.0.1:1', '--idor-tokens', 'a,b']);
  check('N14 negative: two different tokens are still accepted', () => {
    assert.notStrictEqual(p2.status, 2, `rejected: ${p2.stderr}`);
    assert.ok(!/idor-tokens/.test(p2.stderr), `stderr: ${p2.stderr}`);
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  // Tokens given but the check cannot run (no id-scoped endpoints): unsupported.
  const dir = fixture({ 'ok.ts': 'const a = 1;\n' });
  setRequestImpl(async () => ok(200, '{"id":1}'));
  const r = await runFlow({ root: dir, appUrl: 'https://app.invalid', idorTokens: ['a', 'b'], consent: async () => true });
  setRequestImpl(null);
  check('N14: IDOR requested but unable to run is unsupported, not skipped', () => {
    const run = r.runs.find((x) => x.id === 'idor');
    assert.ok(run, 'idor run missing');
    assert.strictEqual(run.status, 'unsupported');
    assert.ok(run.note, 'the reason must be kept');
    assert.strictEqual(summarize([], r.runs).gate, 'incomplete');
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  // Negative: with an id-scoped endpoint and two accounts the IDOR check completes.
  const dir = fixture({ 'server.js': "app.get('/api/orders/:id', (req, res) => res.json({}));\n" });
  setRequestImpl(async () => ok(200, '{"id":1}'));
  const r = await runFlow({ root: dir, appUrl: 'https://app.invalid', idorTokens: ['tokA', 'tokB'], consent: async () => true });
  setRequestImpl(null);
  check('N14 negative: a runnable IDOR check still completes', () => {
    const run = r.runs.find((x) => x.id === 'idor');
    assert.ok(run, 'idor run missing');
    assert.strictEqual(run.status, 'completed', `status ${run.status}: ${run.note}`);
  });
  rmSync(dir, { recursive: true, force: true });
})();

await (async () => {
  // Explicit tokens but live ownership declined: IDOR is an unsupported request too.
  const dir = fixture({ 'ok.ts': 'const a = 1;\n' });
  const r = await runFlow({ root: dir, appUrl: 'https://app.invalid', idorTokens: ['a', 'b'], consent: async () => false });
  check('N14: IDOR tokens with ownership declined are recorded as unsupported', () => {
    const run = r.runs.find((x) => x.id === 'idor');
    assert.ok(run, 'idor run missing');
    assert.strictEqual(run.status, 'unsupported');
    assert.ok(/--idor-tokens/.test(run.note ?? ''), `note: ${run.note}`);
  });
  rmSync(dir, { recursive: true, force: true });
})();

void state;
