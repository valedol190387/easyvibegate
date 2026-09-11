import { resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { scanStatic, type ScanResult } from '../engine/scan.js';
import { runFlow, type ConsentRequest } from '../orchestrator/flow.js';
import { discoverSupabase } from '../engine/checkers/backend/supabase.js';
import { discoverFirebase } from '../engine/checkers/backend/firebase.js';
import { summarize } from '../engine/report.js';
import { t, type Lang } from '../engine/i18n.js';
import { color } from '../engine/util/color.js';

export interface WizardArgs {
  path: string;
  config?: string;
  lang: Lang;
  /** Options already given on the command line — the wizard must not lose them. */
  appUrl?: string;
  deps?: boolean;
  idorTokens?: [string, string];
}

/** Normalize what a person types as a URL. Returns null if it cannot be one. */
export function normalizeUrl(input: string): string | null {
  const raw = input.trim();
  if (raw === '' || /\s/.test(raw)) return null;
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  try {
    const u = new URL(withScheme);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    const host = u.hostname;
    // A real host: localhost, an IP/bracketed IPv6, or something.with.a.dot
    if (!(host === 'localhost' || host.startsWith('[') || /^[^.]+\.[^.]+/.test(host))) return null;
    return u.toString().replace(/\/$/, '');
  } catch {
    return null;
  }
}

/** Read every line from a non-TTY stdin up front, so piped answers are not lost. */
async function readPipedLines(): Promise<string[]> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8').split('\n');
}

/**
 * The beginner-friendly guided run: plain questions, plain answers.
 * It only gathers input and runs the checks — writing reports, the verdict and
 * the exit code stay in the CLI's single shared pipeline, so `--ci` / `--format`
 * behave identically with and without the wizard.
 */
export async function runWizard(args: WizardArgs): Promise<ScanResult> {
  const root = resolve(args.path);
  const lang = args.lang;
  const w = (s = '') => process.stdout.write(s + '\n');

  const tty = !!process.stdin.isTTY;
  const piped = tty ? [] : await readPipedLines();
  let pipeIdx = 0;

  const rl = tty ? createInterface({ input: process.stdin, output: process.stdout }) : null;
  const ask = (question: string): Promise<string> => {
    if (!rl) {
      const line = piped[pipeIdx++] ?? '';
      process.stdout.write(question + line + '\n');
      return Promise.resolve(line.trim());
    }
    return new Promise((res) => {
      let done = false;
      const finish = (v: string) => { if (!done) { done = true; res(v.trim()); } };
      rl.question(question, finish);
      rl.once('close', () => finish(''));
    });
  };
  const askYesNo = async (question: string, def: boolean): Promise<boolean> => {
    const ans = (await ask(`${question} ${def ? '[Y/n]' : '[y/N]'} `)).toLowerCase();
    if (ans === '') return def;
    return ans.startsWith('y') || ans.startsWith('д'); // y/yes or Russian "да"
  };

  w();
  w(`  ${color.bold('🛡  EasyVibeGate')}`);
  w(color.gray(`  ${t(lang, 'wiz.sub1')}`));
  w(color.gray(`  ${t(lang, 'wiz.sub2')}`));
  w();
  w(color.gray(`  ${t(lang, 'wiz.project', { root })}`));
  w();

  // Step 1 — static code review (always, safe).
  w(`  ${color.bold(t(lang, 'wiz.step1'))}${color.gray(t(lang, 'wiz.step1hint'))}`);
  const staticResult = await scanStatic(root, { configPath: args.config });
  const s0 = summarize(staticResult.findings, staticResult.runs);
  w(color.gray(`  ${t(lang, 'wiz.step1result', { files: staticResult.fileCount, crit: s0.counts.critical, warn: s0.counts.warning })}`));
  w();

  // Step 2 — dependencies (an explicit --deps already answers this).
  w(`  ${color.bold(t(lang, 'wiz.step2'))}`);
  const runDeps = args.deps ? true : await askYesNo(t(lang, 'wiz.qDeps'), true);
  if (args.deps) w(color.gray(`  --deps → ${t(lang, 'wiz.fromFlag')}`));
  w();

  // Step 3 — live checks (opt-in, own project only).
  w(`  ${color.bold(t(lang, 'wiz.step3'))}${color.gray(t(lang, 'wiz.step3hint'))}`);
  const sb = discoverSupabase(staticResult.files);
  const fb = discoverFirebase(staticResult.files);
  let approveSupabase = false;
  let approveFirebase = false;

  if (sb) {
    w(color.gray(t(lang, 'wiz.sbFound', { url: sb.url })));
    w(color.gray(t(lang, 'wiz.sbDesc1')));
    w(color.gray(t(lang, 'wiz.sbDesc2')));
    approveSupabase = await askYesNo(t(lang, 'wiz.qSb'), false);
    w();
  }
  if (fb) {
    w(color.gray(t(lang, 'wiz.fbFound', { id: fb.projectId })));
    approveFirebase = await askYesNo(t(lang, 'wiz.qFb'), false);
    w();
  }

  // A URL from the command line wins; otherwise ask — and never silently discard
  // a non-empty answer that merely lacks a scheme.
  let appUrl = args.appUrl;
  if (!appUrl) {
    for (let attempt = 0; attempt < 2 && !appUrl; attempt++) {
      const raw = await ask(t(lang, 'wiz.qUrl'));
      if (raw === '') break; // empty = deliberately skip
      const normalized = normalizeUrl(raw);
      if (normalized) {
        appUrl = normalized;
        if (normalized !== raw) w(color.gray(`  → ${t(lang, 'wiz.urlNormalized', { url: normalized })}`));
      } else {
        w(color.yellow(`  ${t(lang, 'wiz.urlInvalid', { input: raw })}`));
      }
    }
  }
  rl?.close(); // all questions asked — release stdin before running checks
  w();

  const consent = async (req: ConsentRequest): Promise<boolean> => {
    switch (req.kind) {
      case 'supabase': return approveSupabase;
      case 'firebase': return approveFirebase;
      case 'live': return !!appUrl;
      case 'idor': return !!args.idorTokens;
      default: return false;
    }
  };
  const log = (m: string) => process.stdout.write(color.gray(`  … ${m}\n`));

  w(`  ${color.bold(t(lang, 'wiz.running'))}`);
  return runFlow({
    root,
    configPath: args.config,
    appUrl,
    runDeps,
    idorTokens: args.idorTokens,
    precomputedStatic: staticResult,
    consent,
    log,
  });
}
