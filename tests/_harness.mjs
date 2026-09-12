// Shared helpers for the regression suite. `run.mjs` is the entry point; extra
// per-area files (tests/wp-*.mjs) import from here so they share one pass/fail
// tally. Offline only — no network, no real backends.
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

export const CLI = new URL('../dist/cli/index.js', import.meta.url).pathname;

/** A mocked HTTP response for setRequestImpl(). */
export const ok = (status, body = '{"id":1}', headers = {}) =>
  ({ status, ok: status < 300, headers: new Headers(headers), body });

export const ALL_HEADERS = {
  'content-security-policy': 'x', 'strict-transport-security': 'x',
  'x-frame-options': 'x', 'x-content-type-options': 'x',
};

/** Shared tally across every test file. */
export const state = { passed: 0, failures: [] };

export function check(name, fn) {
  try { fn(); state.passed++; console.log(`  ✓ ${name}`); }
  catch (e) { state.failures.push(name); console.log(`  ✗ ${name}\n     ${e.message}`); }
}

/** Write `{ 'rel/path': content }` into a fresh temp dir; returns its path. */
export function fixture(files) {
  const dir = mkdtempSync(join(tmpdir(), 'evg-test-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, content, 'utf8');
  }
  return dir;
}

export const ids = (r) => r.findings.map((f) => f.id);

export const CRITICAL_FIXTURE = { 'db/001.sql': 'CREATE TABLE public.users (id uuid, email text);\n' };

/** Run the real CLI as a child process. `opts.input` is piped to stdin. */
export const runCli = (argv, opts = {}) =>
  spawnSync(process.execPath, [CLI, ...argv], { encoding: 'utf8', input: opts.input ?? '', cwd: opts.cwd });
