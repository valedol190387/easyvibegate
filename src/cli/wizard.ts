import { resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { scanStatic, type ScanResult } from '../engine/scan.js';
import { consentKey, liveTargets, planTargets, runFlow, type ConsentRequest, type Target, type TargetPlan } from '../orchestrator/flow.js';
import { loadConfig } from '../engine/config.js';
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
  supabaseUrl?: string;
  supabaseKey?: string;
  /** --i-own-this / --yes: ownership already asserted, don't ask again. */
  autoYes?: boolean;
  /** The report directory — must not be scanned as project files. */
  excludeAbs?: string[];
}

/**
 * Normalize what a person types as a URL. Returns null if it cannot be one.
 * Loopback and private hosts default to http:// — a dev server is almost never
 * https, and silently guessing https makes the whole probe fail.
 */
export function normalizeUrl(input: string): string | null {
  const raw = input.trim();
  if (raw === '' || /\s/.test(raw)) return null;
  const hostPart = raw.replace(/^[a-z]+:\/\//i, '').split(/[/:?#]/)[0] ?? '';
  const isLocal = /^(localhost|127(\.\d+){3}|0\.0\.0\.0|\[::1\]|10(\.\d+){3}|192\.168(\.\d+){2}|172\.(1[6-9]|2\d|3[01])(\.\d+){2})$/i.test(hostPart);
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `${isLocal ? 'http' : 'https'}://${raw}`;
  try {
    const u = new URL(withScheme);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    const host = u.hostname;
    if (!(host === 'localhost' || host.startsWith('[') || /^[^.]+\.[^.]+/.test(host) || /^\d+(\.\d+){3}$/.test(host))) return null;
    return u.toString().replace(/\/$/, '');
  } catch {
    return null;
  }
}

/**
 * Read every line from a non-TTY stdin up front, so piped answers are not lost.
 * An empty stream is zero answers, not one blank line: `''.split('\n')` yields
 * `['']`, which reads as a deliberate Enter and would accept a question's
 * default — opting into a network action nobody asked for. The trailing newline
 * of a normal stream is dropped for the same reason.
 */
async function readPipedLines(): Promise<string[]> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  const text = Buffer.concat(chunks).toString('utf8');
  if (text === '') return [];
  return text.replace(/\r?\n$/, '').split('\n');
}

/**
 * The beginner-friendly guided run: plain questions, plain answers.
 * It only gathers input and runs the checks — writing reports, the verdict and
 * the exit code stay in the CLI's single shared pipeline.
 */
export async function runWizard(args: WizardArgs): Promise<ScanResult> {
  const root = resolve(args.path);
  const lang = args.lang;
  const w = (s = '') => process.stdout.write(s + '\n');

  const tty = !!process.stdin.isTTY;
  const piped = tty ? [] : await readPipedLines();
  let pipeIdx = 0;

  const rl = tty ? createInterface({ input: process.stdin, output: process.stdout }) : null;
  let inputEnded = false;
  rl?.on('close', () => { inputEnded = true; });

  /** Returns null when there is no answer left (EOF / Ctrl-D / exhausted pipe). */
  const ask = (question: string): Promise<string | null> => {
    if (inputEnded) return Promise.resolve(null);
    if (!rl) {
      if (pipeIdx >= piped.length) { inputEnded = true; return Promise.resolve(null); }
      const line = piped[pipeIdx++] ?? '';
      process.stdout.write(question + line + '\n');
      return Promise.resolve(line.trim());
    }
    return new Promise((res) => {
      let done = false;
      const finish = (v: string | null) => { if (!done) { done = true; res(v); } };
      rl.question(question, (a) => finish(a.trim()));
      // Ctrl-D closes the interface: answer "no input" instead of crashing the
      // next question with ERR_USE_AFTER_CLOSE.
      rl.once('close', () => { inputEnded = true; finish(null); });
    });
  };

  /** No answer means "no" — never opt into a network action on EOF. */
  const askYesNo = async (question: string, def: boolean): Promise<boolean> => {
    for (let attempt = 0; attempt < 2; attempt++) {
      const raw = await ask(`${question} ${def ? '[Y/n]' : '[y/N]'} `);
      if (raw === null) return false;
      const ans = raw.toLowerCase();
      if (ans === '') return def;
      if (/^(y|yes|д|да|1)/.test(ans)) return true;
      if (/^(n|no|н|нет|0)/.test(ans)) return false;
      w(color.yellow(`  ${t(lang, 'wiz.answerUnclear', { input: raw })}`));
    }
    return false;
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
  const staticResult = await scanStatic(root, { configPath: args.config, excludeAbs: args.excludeAbs });
  const s0 = summarize(staticResult.findings, staticResult.runs);
  w(color.gray(`  ${t(lang, 'wiz.step1result', { files: staticResult.fileCount, crit: s0.counts.critical, warn: s0.counts.warning })}`));
  w();

  // Step 2 — dependencies (an explicit --deps already answers this).
  w(`  ${color.bold(t(lang, 'wiz.step2'))}`);
  const runDeps = args.deps ? true : await askYesNo(t(lang, 'wiz.qDeps'), true);
  if (args.deps) w(color.gray(`  --deps → ${t(lang, 'wiz.fromFlag')}`));
  w();

  // Step 3 — live checks (opt-in, own project only).
  // The targets are planned ONCE here, over the same ignorePaths-filtered file
  // set the flow uses, and the very same plan is handed to runFlow. Consent is
  // bound to a concrete normalized target, so the host shown in a question is
  // exactly the host that gets probed — never a second discovery's pick.
  w(`  ${color.bold(t(lang, 'wiz.step3'))}${color.gray(t(lang, 'wiz.step3hint'))}`);
  const config = loadConfig(root, args.config);
  const base = planTargets(staticResult.files, config, {
    appUrl: args.appUrl,
    supabaseUrl: args.supabaseUrl,
    supabaseKey: args.supabaseKey,
    idorTokens: args.idorTokens,
  });
  const approved = new Set<string>();
  const sb = base.targets.find((x) => x.kind === 'supabase');
  const fb = base.targets.find((x) => x.kind === 'firebase');

  if (sb) {
    w(color.gray(t(lang, sb.explicit ? 'wiz.sbFromFlag' : 'wiz.sbFound', { url: sb.target })));
    w(color.gray(t(lang, 'wiz.sbDesc1')));
    w(color.gray(t(lang, 'wiz.sbDesc2')));
    const yes = args.autoYes ? true : await askYesNo(t(lang, 'wiz.qSb'), false);
    if (yes) approved.add(consentKey('supabase', sb.target));
    else if (sb.explicit) w(color.yellow(t(lang, 'wiz.notRun', { target: sb.target })));
    w();
  }
  if (fb) {
    w(color.gray(t(lang, 'wiz.fbFound', { id: fb.target })));
    const yes = args.autoYes ? true : await askYesNo(t(lang, 'wiz.qFb'), false);
    if (yes) approved.add(consentKey('firebase', fb.target));
    w();
  }

  // A URL from the command line wins; otherwise ask — and never silently discard
  // a non-empty answer that merely lacks a scheme. A typed URL extends the plan
  // the same way a flag would; it is still a request the person made.
  let live = base.targets.find((x) => x.kind === 'live');
  const extra: Target[] = [];
  if (!live) {
    for (let attempt = 0; attempt < 2 && !live; attempt++) {
      const raw = await ask(t(lang, 'wiz.qUrl'));
      if (raw === null || raw === '') break; // EOF or empty = deliberately skip
      const normalized = normalizeUrl(raw);
      if (normalized) {
        extra.push(...liveTargets(normalized, args.idorTokens, 'wizard'));
        live = extra.find((x) => x.kind === 'live');
        if (normalized !== raw) w(color.gray(`  → ${t(lang, 'wiz.urlNormalized', { url: normalized })}`));
      } else {
        w(color.yellow(`  ${t(lang, 'wiz.urlInvalid', { input: raw })}`));
      }
    }
  }
  // Probing a live host always needs ownership confirmation, even from --url.
  // A declined request is NOT dropped: it stays in the plan so the flow records
  // it as a requested check that did not run (visible in coverage, gate incomplete).
  if (live) {
    const yes = args.autoYes ? true : await askYesNo(t(lang, 'wiz.qOwn', { url: live.target }), false);
    if (yes) {
      approved.add(consentKey('live', live.target));
      if (args.idorTokens) approved.add(consentKey('idor', live.target));
    } else {
      w(color.yellow(t(lang, 'wiz.notRun', { target: live.target })));
    }
  }
  rl?.close();
  w();

  const plan: TargetPlan = { targets: [...base.targets, ...extra] };
  const consent = async (req: ConsentRequest): Promise<boolean> => approved.has(consentKey(req.kind, req.target));
  const log = (m: string) => process.stdout.write(color.gray(`  … ${m}\n`));

  w(`  ${color.bold(t(lang, 'wiz.running'))}`);
  return runFlow({
    excludeAbs: args.excludeAbs,
    root,
    configPath: args.config,
    runDeps,
    precomputedStatic: staticResult,
    plan,
    consent,
    log,
  });
}
