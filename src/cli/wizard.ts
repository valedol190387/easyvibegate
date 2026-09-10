import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { scanStatic } from '../engine/scan.js';
import { runFlow, type ConsentRequest } from '../orchestrator/flow.js';
import { discoverSupabase } from '../engine/checkers/backend/supabase.js';
import { discoverFirebase } from '../engine/checkers/backend/firebase.js';
import {
  badgeMarkdown,
  renderConsole,
  renderJson,
  renderMarkdown,
  renderNextSteps,
  renderVerdict,
  summarize,
} from '../engine/report.js';
import { buildAiFixPrompt } from '../engine/aifix.js';
import { t, type Lang } from '../engine/i18n.js';
import { color } from '../engine/util/color.js';

export interface WizardArgs {
  path: string;
  output: string;
  config?: string;
  lang: Lang;
}

/** The beginner-friendly guided run: plain questions, plain answers. */
export async function runWizard(args: WizardArgs): Promise<void> {
  const root = resolve(args.path);
  const lang = args.lang;
  const w = (s = '') => process.stdout.write(s + '\n');

  // One shared readline for the whole wizard (robust for TTY and piped input).
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  let closed = false;
  rl.on('close', () => { closed = true; });
  const ask = (question: string): Promise<string> =>
    new Promise((res) => {
      if (closed) { res(''); return; } // input ended (piped/EOF) — take the default
      let done = false;
      const finish = (v: string) => { if (!done) { done = true; res(v.trim()); } };
      rl.question(question, finish);
      rl.once('close', () => finish(''));
    });
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
  const s0 = summarize(staticResult.findings);
  w(color.gray(`  ${t(lang, 'wiz.step1result', { files: staticResult.fileCount, crit: s0.counts.critical, warn: s0.counts.warning })}`));
  w();

  // Step 2 — dependencies.
  w(`  ${color.bold(t(lang, 'wiz.step2'))}`);
  const runDeps = await askYesNo(t(lang, 'wiz.qDeps'), true);
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
  const urlAns = await ask(t(lang, 'wiz.qUrl'));
  const appUrl = /^https?:\/\//i.test(urlAns) ? urlAns : undefined;
  rl.close(); // all questions asked — release stdin before running checks
  w();

  const consent = async (req: ConsentRequest): Promise<boolean> => {
    switch (req.kind) {
      case 'supabase': return approveSupabase;
      case 'firebase': return approveFirebase;
      case 'live': return !!appUrl;
      default: return false; // writes and IDOR stay off in the beginner wizard
    }
  };
  const log = (m: string) => process.stdout.write(color.gray(`  … ${m}\n`));

  w(`  ${color.bold(t(lang, 'wiz.running'))}`);
  const result = await runFlow({
    root,
    configPath: args.config,
    appUrl,
    runDeps,
    writeProbe: false,
    precomputedStatic: staticResult,
    consent,
    log,
  });
  const summary = summarize(result.findings);

  w(renderConsole(result, summary, lang));
  w(renderVerdict(summary, lang));
  w();

  mkdirSync(args.output, { recursive: true });
  writeFileSync(join(args.output, 'report.md'), renderMarkdown(result, summary, lang), 'utf8');
  writeFileSync(join(args.output, 'report.json'), renderJson(result, summary), 'utf8');
  writeFileSync(join(args.output, 'ai-fix-prompt.md'), buildAiFixPrompt(result, summary, lang), 'utf8');

  w(renderNextSteps(summary, args.output, lang));
  w(color.gray(`  ${t(lang, 'next.fullReport', { path: `${args.output}/report.md` })}`));
  if (summary.counts.critical > 0 || summary.counts.warning > 0) {
    w(color.gray(`  ${t(lang, 'next.badge', { badge: badgeMarkdown(summary) })}`));
  }
  w();
}
