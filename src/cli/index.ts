#!/usr/bin/env node
import { existsSync, mkdirSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { runFlow, type ConsentRequest } from '../orchestrator/flow.js';
import {
  badgeMarkdown,
  coverage,
  renderConsole,
  renderJson,
  renderMarkdown,
  renderNextSteps,
  renderVerdict,
  summarize,
} from '../engine/report.js';
import { buildAiFixPrompt } from '../engine/aifix.js';
import { runWizard } from './wizard.js';
import { pickLang } from '../engine/i18n.js';
import { color } from '../engine/util/color.js';

const VERSION = '0.2.0';

type Format = 'all' | 'md' | 'json' | 'none';

interface Args {
  path: string;
  output: string;
  format: Format;
  ci: boolean;
  config?: string;
  appUrl?: string;
  supabaseUrl?: string;
  supabaseKey?: string;
  iOwnThis: boolean;
  yes: boolean;
  deps: boolean;
  noWizard: boolean;
  wizard: boolean;
  lang?: string;
  idorTokens?: [string, string];
  badIdorTokens: boolean;
  unknown: string[];
  help: boolean;
  version: boolean;
}

const HELP = `
🛡  easyvibegate — universal security scanner for vibe-coded apps

Usage:
  easyvibegate [path] [options]

Just run \`easyvibegate\` in your project for a guided, beginner-friendly wizard.
Level 0 (static, any stack) always runs. Level 1/2 need opt-in.
A fix plan (ai-fix-prompt.md) is always written next to the report.

Options:
  -o, --output <dir>     Report directory (default: ./easyvibegate-report)
  -f, --format <fmt>     all | md | json | none (default: all)
      --ci               Quiet; exit non-zero on findings (2 critical, 1 warning)
  -c, --config <file>    Path to a easyvibegate config JSON

  Level 1:
      --deps             Run the dependency vulnerability audit

  Level 2 (live probe — only against apps you own):
      --url <appUrl>     Probe a running app: headers, exposed files, unauth endpoints
      --supabase-url <u> Override the detected Supabase URL
      --supabase-key <k> Override the detected Supabase anon key
      --idor-tokens a,b  Two bearer tokens for the IDOR differential probe
      --i-own-this       Authorize probing without interactive prompts (for CI)
  -y, --yes              Assume yes to all consent prompts

  Other:
      --lang <ru|en>     Interface language (default: ru; use "en" for English)
      --no-wizard        Skip the guided wizard; run directly and print results

  -h, --help             Show help
  -v, --version          Show version

Ethics: the live probe sends real requests. Only run it against systems you own.
`;

function parseArgs(argv: string[]): Args {
  const a: Args = {
    path: '.',
    output: 'easyvibegate-report',
    format: 'all',
    ci: false,
    iOwnThis: false,
    yes: false,
    deps: false,
    noWizard: false,
    wizard: false,
    badIdorTokens: false,
    unknown: [],
    help: false,
    version: false,
  };
  let sawPath = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    switch (arg) {
      case '-h': case '--help': a.help = true; break;
      case '-v': case '--version': a.version = true; break;
      case '--ci': a.ci = true; break;
      case '-o': case '--output': a.output = argv[++i] ?? a.output; break;
      case '-f': case '--format': {
        const v = argv[++i];
        if (v === 'all' || v === 'md' || v === 'json' || v === 'none') a.format = v;
        break;
      }
      case '--no-report': a.format = 'none'; break;
      case '-c': case '--config': a.config = argv[++i]; break;
      case '--url': a.appUrl = argv[++i]; break;
      case '--supabase-url': a.supabaseUrl = argv[++i]; break;
      case '--supabase-key': a.supabaseKey = argv[++i]; break;
      case '--i-own-this': a.iOwnThis = true; break;
      case '-y': case '--yes': a.yes = true; break;
      case '--deps': a.deps = true; break;
      case '--no-wizard': case '--scan': a.noWizard = true; break;
      case '--wizard': a.wizard = true; break;
      case '--lang': a.lang = argv[++i]; break;
      case '--idor-tokens': {
        const v = argv[++i] ?? '';
        const parts = v.split(',').map((s) => s.trim()).filter(Boolean);
        if (parts.length === 2) a.idorTokens = [parts[0]!, parts[1]!];
        else a.badIdorTokens = true;
        break;
      }
      default:
        if (arg.startsWith('-')) a.unknown.push(arg);
        else if (!sawPath) { a.path = arg; sawPath = true; }
    }
  }
  return a;
}

function ask(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((res) => rl.question(question, (ans) => { rl.close(); res(ans); }));
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { process.stdout.write(HELP); return; }
  if (args.version) { process.stdout.write(`easyvibegate ${VERSION}\n`); return; }

  // Fail loudly on bad usage instead of silently doing the wrong thing.
  if (args.unknown.length > 0) {
    process.stderr.write(`easyvibegate: unknown option(s): ${args.unknown.join(', ')}\nRun with --help.\n`);
    process.exit(2);
  }
  if (args.badIdorTokens) {
    process.stderr.write('easyvibegate: --idor-tokens needs exactly two comma-separated tokens (tokenA,tokenB).\n');
    process.exit(2);
  }

  const root = resolve(args.path);
  if (!existsSync(root) || !statSync(root).isDirectory()) {
    process.stderr.write(`easyvibegate: path not found or not a directory: ${root}\n`);
    process.exit(2);
  }
  const autoYes = args.iOwnThis || args.yes;
  const lang = pickLang(args.lang);

  // Default to the friendly wizard when a human runs it in a terminal without
  // any automation/power flags. CI and flag-driven runs use direct mode.
  const powerFlags = args.ci || autoYes || !!args.appUrl || !!args.supabaseUrl || !!args.idorTokens || args.deps;
  if (args.wizard || (!args.noWizard && !powerFlags && !!process.stdin.isTTY)) {
    await runWizard({ path: args.path, output: args.output, config: args.config, lang });
    return;
  }

  const interactive = !!process.stdin.isTTY && !args.ci && !autoYes;
  const log = (m: string) => { if (!args.ci) process.stderr.write(color.gray(`  ${m}\n`)); };

  const consent = async (req: ConsentRequest): Promise<boolean> => {
    if (autoYes) return true;
    if (!interactive) {
      process.stderr.write(color.gray(`  skipped ${req.kind} probe of ${req.target} — needs --i-own-this or an interactive terminal\n`));
      return false;
    }
    const ans = await ask(color.yellow(`  Probe ${req.kind} → ${req.target}?\n    (${req.detail}) [y/N] `));
    return /^y(es)?$/i.test(ans.trim());
  };

  const result = await runFlow({
    root,
    configPath: args.config,
    appUrl: args.appUrl,
    supabaseUrl: args.supabaseUrl,
    supabaseKey: args.supabaseKey,
    runDeps: args.deps,
    idorTokens: args.idorTokens,
    consent,
    log,
  });
  const summary = summarize(result.findings);

  if (!args.ci) process.stdout.write(renderConsole(result, summary, lang) + '\n');

  if (args.format !== 'none') {
    mkdirSync(args.output, { recursive: true });
    const written: string[] = [];
    if (args.format === 'all' || args.format === 'md') {
      const p = join(args.output, 'report.md');
      writeFileSync(p, renderMarkdown(result, summary, lang), 'utf8');
      written.push(p);
    }
    if (args.format === 'all' || args.format === 'json') {
      const p = join(args.output, 'report.json');
      writeFileSync(p, renderJson(result, summary), 'utf8');
      written.push(p);
    }
    // The fix plan is the whole point — always produce it alongside a report.
    writeFileSync(join(args.output, 'ai-fix-prompt.md'), buildAiFixPrompt(result, summary, lang), 'utf8');
    if (!args.ci && written.length) {
      process.stdout.write(color.gray(`  report: ${written.join(', ')}\n`));
      process.stdout.write(color.gray(`  badge:  ${badgeMarkdown(summary)}\n\n`));
    }
  }

  if (!args.ci) {
    process.stdout.write(renderVerdict(summary, result.runs, lang) + '\n\n');
    if (args.format !== 'none') process.stdout.write(renderNextSteps(summary, args.output, lang));
  }

  if (args.ci) {
    // 2 = critical, 1 = warning, 3 = a check failed to run (incomplete), 0 = clean.
    const cov = coverage(result.runs);
    process.exit(
      summary.counts.critical > 0 ? 2 : summary.counts.warning > 0 ? 1 : cov.failed > 0 ? 3 : 0,
    );
  }
}

main().catch((err) => {
  process.stderr.write(`easyvibegate: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
