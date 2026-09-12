// Static-layer regressions (external audit F13/F14/F23/F24). Offline only:
// dependency audits run against FAKE npm/pnpm executables injected via PATH.
// Every fix has a positive AND a negative half — an assertion of absence alone
// cannot tell a detector that stopped lying from one that stopped working.
import assert from 'node:assert';
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { scanStatic } from '../dist/engine/scan.js';
import { walk } from '../dist/engine/walk.js';
import { detect } from '../dist/engine/detect.js';
import { auditDeps } from '../dist/engine/checkers/deep/deps.js';
import { summarize, exitCodeFor } from '../dist/engine/report.js';
import { check, fixture, ids, runCli } from './_harness.mjs';

console.log('\nWP static');

const RAND24 = 'aB3dE5fG7hJ9kL1mN3pQ5rS7';
const RAND35 = 'aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA';
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (role) => `${b64u({ alg: 'HS256' })}.${b64u({ role })}.sig12345678901234567890`;

// --- F13: a docs/fixtures path must not silence REAL key material ------------
await (async () => {
  // A freshly generated key is exactly what a careless deploy guide pastes.
  const pem = generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey
    .export({ type: 'pkcs1', format: 'pem' });
  const dir = fixture({
    'docs/deploy.md': `Copy this to the server:\n\n\`\`\`\n${pem}\`\`\`\n`,
    'docs/stripe.md': `Set STRIPE_KEY to sk_live_${RAND24} on the server.\n`,
    'docs/db.md': 'DATABASE_URL=postgres://app:Rt8Vn3Xm7Kp2Qz9@db.internal:5432/app\n',
  });
  const r = await scanStatic(dir);
  const at = (f, id) => r.findings.find((x) => x.file === f && x.id === id);
  check('F13: a real RSA private key in docs/ is a warning, not a docs-only info', () => {
    const f = at('docs/deploy.md', 'private_key');
    assert.ok(f, `private_key missing — got ${ids(r)}`);
    assert.strictEqual(f.severity, 'warning', `severity was ${f.severity}`);
    assert.match(f.title, /looks real/);
    const s = summarize(r.findings, r.runs);
    assert.notStrictEqual(s.gate, 'pass', 'a real key in docs must not PASS the gate');
  });
  check('F13: a real-looking Stripe live key and DB password in docs/ stay at warning', () => {
    assert.strictEqual(at('docs/stripe.md', 'stripe_live')?.severity, 'warning');
    assert.strictEqual(at('docs/db.md', 'db_url_password')?.severity, 'warning');
  });
  rmSync(dir, { recursive: true, force: true });

  // Negative half: obviously hand-typed samples in docs are still info.
  const dir2 = fixture({
    'docs/keys.md': '-----BEGIN RSA PRIVATE KEY-----\n(paste the key body here)\n-----END RSA PRIVATE KEY-----\n',
    'docs/db.md': 'DATABASE_URL=postgres://app:password@localhost:5432/app\n',
    'docs/token.md': `const apiSecret = "${RAND24}Qq1";\n`,
  });
  const r2 = await scanStatic(dir2);
  check('F13: a placeholder PEM / name-based hit in docs/ stay info; a default DB password is not a secret at all', () => {
    for (const id of ['private_key', 'generic_secret']) {
      const f = r2.findings.find((x) => x.id === id);
      assert.ok(f, `${id} should still be reported (as info) — got ${ids(r2)}`);
      assert.strictEqual(f.severity, 'info', `${id} was ${f.severity}`);
    }
    // `app:password@localhost` is a local container's default login, not a credential.
    assert.ok(!ids(r2).includes('db_url_password'), `default local password must not be reported — got ${ids(r2)}`);
  });
  rmSync(dir2, { recursive: true, force: true });

  // The same real key outside docs/, committed to git, is a critical source leak.
  const dir3 = fixture({ 'keys/server.pem': pem });
  spawnSync('git', ['-C', dir3, 'init', '-q']);
  spawnSync('git', ['-C', dir3, 'add', 'keys/server.pem']);
  spawnSync('git', ['-C', dir3, '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '-m', 'x']);
  const r3 = await scanStatic(dir3);
  check('F13: the same real key in a non-docs path, committed, is critical', () => {
    assert.strictEqual(r3.findings.find((x) => x.id === 'private_key')?.severity, 'critical');
  });
  rmSync(dir3, { recursive: true, force: true });
})();

// --- F14: public-by-design keys are not "server secrets" ---------------------
await (async () => {
  const dir = fixture({
    '.env': [
      `VITE_SUPABASE_API_KEY=sb_publishable_${RAND24}`,
      `VITE_FIREBASE_API_KEY=AIza${RAND35}`,
      `NEXT_PUBLIC_SUPABASE_ANON_TOKEN=${jwt('anon')}`,
      '',
    ].join('\n'),
  });
  const r = await scanStatic(dir);
  check('F14: publishable / anon JWT / Firebase web key behind a public prefix are not critical', () => {
    assert.ok(!ids(r).includes('public_env_secret'), `got ${ids(r)}`);
    assert.ok(!r.findings.some((f) => f.severity === 'critical'), JSON.stringify(r.findings.map((f) => [f.id, f.severity])));
  });
  check('F14: they get a public_key_client advisory pointing at RLS / rules / key restrictions', () => {
    const adv = r.findings.filter((f) => f.id === 'public_key_client');
    assert.strictEqual(adv.length, 3, `expected 3 advisories, got ${adv.length}`);
    assert.ok(adv.every((f) => f.severity === 'advisory'));
    assert.ok(adv.every((f) => /Row Level Security|security rules|restrict/i.test(f.fix)), adv[0].fix);
  });
  rmSync(dir, { recursive: true, force: true });

  // Negative half: real secrets behind a public prefix are still critical —
  // by value (service_role JWT under a name with no secret word, sk_live_),
  // and by name (generic high-entropy *_TOKEN).
  const dir2 = fixture({
    '.env': [
      `VITE_SUPABASE_SERVICE_ROLE_KEY=${jwt('service_role')}`,
      `NEXT_PUBLIC_STRIPE_SECRET=sk_live_${RAND24}`,
      `VITE_SUPABASE_KEY=${jwt('service_role')}`,
      `VITE_SUPABASE_URL_KEY=sb_secret_${RAND24}`,
      `NEXT_PUBLIC_API_TOKEN=${RAND35}`,
      '',
    ].join('\n'),
  });
  const r2 = await scanStatic(dir2);
  check('F14: service_role JWT, sb_secret_, sk_live_ and *_TOKEN behind a public prefix stay critical', () => {
    const crit = r2.findings.filter((f) => f.id === 'public_env_secret' && f.severity === 'critical');
    assert.strictEqual(crit.length, 5, `got ${crit.length}: ${JSON.stringify(r2.findings.map((f) => [f.id, f.line]))}`);
    assert.ok(!ids(r2).includes('public_key_client'), 'no advisory for real secrets');
  });
  rmSync(dir2, { recursive: true, force: true });
})();

// --- F23: skipped symlinks are missing coverage, not a clean PASS ------------
await (async () => {
  // The linked directory holds a table without RLS. We do not follow links
  // (loop/escape risk), so the finding is invisible — the run must say so.
  const outside = mkdtempSync(join(tmpdir(), 'evg-linked-'));
  mkdirSync(join(outside, 'sql'));
  writeFileSync(join(outside, 'sql', '001.sql'), 'CREATE TABLE public.users (id uuid, email text);\n');
  writeFileSync(join(outside, 'secret.ts'), `const k = "sk_live_${RAND24}";\n`);
  const dir = fixture({ 'index.ts': 'const a = 1;\n' });
  symlinkSync(join(outside, 'sql'), join(dir, 'migrations'));
  symlinkSync(join(outside, 'secret.ts'), join(dir, 'config.ts'));
  symlinkSync(join(dir, 'does-not-exist'), join(dir, 'dangling'));
  symlinkSync(outside, join(dir, 'node_modules'));
  try {
    const w = walk(dir);
    const r = await scanStatic(dir);
    const s = summarize(r.findings, r.runs);
    check('F23: symlinks to a directory and a scannable file are counted, not followed', () => {
      assert.strictEqual(w.skippedSymlinks, 2, `dangling and node_modules links must not count — got ${w.skippedSymlinks}`);
      assert.ok(!ids(r).includes('rls_missing') && !ids(r).includes('stripe_live'), 'targets must not be scanned through the link');
    });
    check('F23: the walk run is partial with a symlink note and the gate is incomplete', () => {
      const run = r.runs.find((x) => x.id === 'walk');
      assert.strictEqual(run?.status, 'partial', JSON.stringify(r.runs));
      assert.match(run?.note ?? '', /2 symlink\(s\) skipped — their targets were not scanned/);
      assert.strictEqual(s.gate, 'incomplete');
      assert.strictEqual(exitCodeFor(s), 3);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }

  // Negative half: the same project without links has full coverage.
  const dir2 = fixture({ 'index.ts': 'const a = 1;\n', 'db/001.sql': 'CREATE TABLE t (id uuid);\nALTER TABLE t ENABLE ROW LEVEL SECURITY;\n' });
  const r2 = await scanStatic(dir2);
  check('F23: a project without symlinks keeps full coverage', () => {
    assert.strictEqual(walk(dir2).skippedSymlinks, 0);
    assert.strictEqual(r2.runs.find((x) => x.id === 'walk'), undefined, JSON.stringify(r2.runs));
    assert.notStrictEqual(summarize(r2.findings, r2.runs).gate, 'incomplete');
  });
  rmSync(dir2, { recursive: true, force: true });
})();

// --- F24 / D01: `packageManager` decides, lockfiles only add -----------------
await (async () => {
  const dir = fixture({ 'package.json': '{"packageManager":"npm@10.2.0"}', 'pnpm-lock.yaml': 'lockfileVersion: 9\n' });
  const r = await scanStatic(dir);
  check('D01: packageManager: npm beats a stale pnpm-lock.yaml (npm is first)', () => {
    assert.strictEqual(r.detection.packageManagers[0], 'npm', r.detection.packageManagers.join(','));
    assert.ok(r.detection.packageManagers.includes('pnpm'), 'the stale lockfile is still visible');
    assert.strictEqual(r.detection.declaredPackageManager, 'npm');
  });
  rmSync(dir, { recursive: true, force: true });

  // Negative half: with no declaration the lockfile decides.
  const dir2 = fixture({ 'package.json': '{}', 'pnpm-lock.yaml': 'lockfileVersion: 9\n' });
  check('D01: without a packageManager field the lockfile decides', () => {
    const d = detect(dir2, walk(dir2).files);
    assert.deepStrictEqual(d.packageManagers, ['pnpm']);
    assert.strictEqual(d.declaredPackageManager, undefined);
  });
  rmSync(dir2, { recursive: true, force: true });
})();

// --- F24 / D02: audit exit codes and report shape ---------------------------
// Seam: PATH injection. A temp dir with executable `npm`/`pnpm` scripts is put
// in front of PATH; each script appends its name to $EVG_AUDIT_LOG, prints the
// given JSON and exits with the given code. No real audit ever runs.
const fakeBin = (scripts) => {
  const bin = mkdtempSync(join(tmpdir(), 'evg-fakebin-'));
  for (const [name, { json, code }] of Object.entries(scripts)) {
    const p = join(bin, name);
    writeFileSync(p, `#!/bin/sh\necho ${name} >> "$EVG_AUDIT_LOG"\ncat <<'EVG_EOF'\n${json}\nEVG_EOF\nexit ${code}\n`);
    chmodSync(p, 0o755);
  }
  return bin;
};
const withFakeAudit = async (scripts, fn) => {
  const bin = fakeBin(scripts);
  const log = join(bin, 'calls.log');
  writeFileSync(log, '');
  const savedPath = process.env.PATH;
  process.env.PATH = `${bin}:${savedPath}`;
  process.env.EVG_AUDIT_LOG = log;
  try {
    return await fn(() => readFileSync(log, 'utf8'));
  } finally {
    process.env.PATH = savedPath;
    delete process.env.EVG_AUDIT_LOG;
    rmSync(bin, { recursive: true, force: true });
  }
};

const ZERO = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 };
const report = (vulns, extra = {}) => JSON.stringify({ metadata: { vulnerabilities: vulns }, ...extra });

await (async () => {
  const root = fixture({ 'package.json': '{}' });
  try {
    // D01 (executable half): both managers detected, npm declared → npm invoked.
    await withFakeAudit({ npm: { json: report(ZERO), code: 0 }, pnpm: { json: report(ZERO), code: 0 } }, async (calls) => {
      const d = await auditDeps(root, ['npm', 'pnpm']);
      check('D01: auditDeps runs the FIRST detected manager (npm), not pnpm', () => {
        assert.strictEqual(calls().trim(), 'npm', `invoked: ${calls().trim() || 'nothing'}`);
        assert.strictEqual(d.run.status, 'completed');
      });
      check('D01: a conflicting lockfile is a visible note + advisory, not a failure', () => {
        assert.match(d.run.note ?? '', /audited with npm; pnpm/);
        const adv = d.findings.find((f) => f.id === 'deps_manager_conflict');
        assert.ok(adv && adv.severity === 'advisory', JSON.stringify(d.findings));
      });
    });

    // D02: a tool error with a hollow report must not be "0 vulnerabilities".
    await withFakeAudit({ pnpm: { json: '{"metadata":{"vulnerabilities":{}}}', code: 7 } }, async () => {
      const d = await auditDeps(root, ['pnpm']);
      check('D02: exit code 7 is a tool error → failed, with the code in the note', () => {
        assert.strictEqual(d.run.status, 'failed', JSON.stringify(d.run));
        assert.match(d.run.note ?? '', /exited with code 7/);
        assert.strictEqual(d.findings.length, 0);
      });
    });
    await withFakeAudit({ pnpm: { json: '{"metadata":{"vulnerabilities":{}}}', code: 0 } }, async () => {
      const d = await auditDeps(root, ['pnpm']);
      check('D02: exit 0 with an empty vulnerabilities object → failed: unparseable, never clean', () => {
        assert.strictEqual(d.run.status, 'failed', JSON.stringify(d.run));
        assert.match(d.run.note ?? '', /unparseable audit output/);
      });
    });
    await withFakeAudit({ npm: { json: report({ ...ZERO, high: 1, total: 5 }), code: 1 } }, async () => {
      const d = await auditDeps(root, ['npm']);
      check('D02: a total that does not match the severity sum → failed', () => {
        assert.strictEqual(d.run.status, 'failed', JSON.stringify(d.run));
        assert.match(d.run.note ?? '', /unparseable/);
      });
    });

    // Positive halves: the documented "vulnerabilities found" exit still parses,
    // and a genuinely clean report is completed with no findings.
    const oneHigh = report({ ...ZERO, high: 1, total: 1 }, { vulnerabilities: { lodash: { name: 'lodash', severity: 'high' } } });
    await withFakeAudit({ npm: { json: oneHigh, code: 1 } }, async () => {
      const d = await auditDeps(root, ['npm']);
      check('D02: exit 1 with a valid report (1 high) → completed with a critical finding', () => {
        assert.strictEqual(d.run.status, 'completed', JSON.stringify(d.run));
        const f = d.findings.find((x) => x.id === 'deps_vulnerabilities');
        assert.ok(f && f.severity === 'critical', JSON.stringify(d.findings));
        assert.ok(d.findings.some((x) => x.id === 'deps_top_packages' && /lodash/.test(x.detail)));
      });
    });
    await withFakeAudit({ pnpm: { json: report(ZERO), code: 0 } }, async () => {
      const d = await auditDeps(root, ['pnpm']);
      check('D02: exit 0 with a valid zero report → completed, no findings, no note', () => {
        assert.strictEqual(d.run.status, 'completed', JSON.stringify(d.run));
        assert.strictEqual(d.findings.length, 0);
        assert.strictEqual(d.run.note, undefined);
      });
    });
    // yarn v1 exits with a severity bitmask (here 8 = high) — that is not an error.
    // Its auditSummary has the five severity counters and no `total` field.
    const { total: _t, ...yarnZero } = ZERO;
    const yarnOut = `${JSON.stringify({ type: 'auditAdvisory', data: {} })}\n${JSON.stringify({ type: 'auditSummary', data: { vulnerabilities: { ...yarnZero, high: 1 } } })}\n`;
    await withFakeAudit({ yarn: { json: yarnOut, code: 8 } }, async () => {
      const d = await auditDeps(root, ['yarn']);
      check('D02: yarn v1 bitmask exit (8) with a valid summary → completed with a finding', () => {
        assert.strictEqual(d.run.status, 'completed', JSON.stringify(d.run));
        assert.ok(d.findings.some((x) => x.id === 'deps_vulnerabilities'));
      });
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
})();

// --- C05 (integrator): a custom --output directory is not scanned next time ---
{
  const dir = fixture({ 'index.ts': 'const a = 1;\n' });
  const out = join(dir, 'reports');
  const first = runCli([dir, '--no-wizard', '--format', 'json', '--output', out]);
  const second = runCli([dir, '--no-wizard', '--format', 'json', '--output', out]);
  check('C05: a custom --output dir inside the project is excluded from the next walk', () => {
    assert.strictEqual(first.status, 0, first.stderr);
    const j1 = JSON.parse(readFileSync(join(out, 'report.json'), 'utf8'));
    assert.strictEqual(second.status, 0, second.stderr);
    const j2 = JSON.parse(readFileSync(join(out, 'report.json'), 'utf8'));
    assert.strictEqual(j2.fileCount ?? j2.files ?? j2.summary?.files, j1.fileCount ?? j1.files ?? j1.summary?.files, 'file count grew: the report dir was scanned');
    assert.strictEqual(j1.fileCount ?? j1.files ?? j1.summary?.files, 1, `expected exactly 1 scanned file, got ${JSON.stringify(j1).slice(0, 200)}`);
  });
  rmSync(dir, { recursive: true, force: true });
}
