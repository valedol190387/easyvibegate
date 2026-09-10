#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { runFlow, type ConsentRequest } from '../orchestrator/flow.js';
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
  write: boolean;
  deps: boolean;
  noWizard: boolean;
  wizard: boolean;
  lang?: string;
  idorTokens?: [string, string];
  help: boolean;
  version: boolean;
}

const HELP = `
🛡  vibegate — universal security scanner for vibe-coded apps

Usage:
  vibegate [path] [options]

Just run \`vibegate\` in your project for a guided, beginner-friendly wizard.
Level 0 (static, any stack) always runs. Level 1/2 need opt-in.
A fix plan (ai-fix-prompt.md) is always written next to the report.

Options:
  -o, --output <dir>     Report directory (default: ./vibegate-report)
  -f, --format <fmt>     all | md | json | none (default: all)
      --ci               Quiet; exit non-zero on findings (2 critical, 1 warning)
  -c, --config <file>    Path to a vibegate config JSON

  Level 1:
      --deps             Run the dependency vulnerability audit

  Level 2 (live probe — only against apps you own):
      --url <appUrl>     Probe a running app: headers, exposed files, unauth endpoints
      --supabase-url <u> Override the detected Supabase URL
      --supabase-key <k> Override the detected Supabase anon key
      --idor-tokens a,b  Two bearer tokens for the IDOR differential probe
      --i-own-this       Authorize probing without interactive prompts (for CI)
  -y, --yes              Assume yes to all consent prompts
      --write            Allow canary write probes (default: read-only)

  Other:
      --lang <en|ru>     Interface language (default: from your locale, else en)
      --no-wizard        Skip the guided wizard; run directly and print results

  -h, --help             Show help
  -v, --version          Show version

Ethics: the live probe sends real requests. Only run it against systems you own.
`;

function parseArgs(argv: string[]): Args {
  const a: Args = {
    path: '.',
    output: 'vibegate-report',
    format: 'all',
    ci: false,
    iOwnThis: false,
    yes: false,
    write: false,
    deps: false,
    noWizard: false,
    wizard: false,
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
      case '--write': a.write = true; break;
      case '--deps': a.deps = true; break;
      case '--no-wizard': case '--scan': a.noWizard = true; break;
      case '--wizard': a.wizard = true; break;
      case '--lang': a.lang = argv[++i]; break;
      case '--idor-tokens': {
        const v = argv[++i] ?? '';
        const parts = v.split(',').map((s) => s.trim()).filter(Boolean);
        if (parts.length === 2) a.idorTokens = [parts[0]!, parts[1]!];
        break;
      }
      default:
        if (!arg.startsWith('-') && !sawPath) { a.path = arg; sawPath = true; }
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
  if (args.version) { process.stdout.write(`vibegate ${VERSION}\n`); return; }

  const root = resolve(args.path);
  const autoYes = args.iOwnThis || args.yes;
  const lang = pickLang(args.lang);

  // Default to the friendly wizard when a human runs it in a terminal without
  // any automation/power flags. CI and flag-driven runs use direct mode.
  const powerFlags = args.ci || autoYes || !!args.appUrl || !!args.supabaseUrl || !!args.idorTokens || args.deps || args.write;
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
    writeProbe: args.write,
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
    process.stdout.write(renderVerdict(summary, lang) + '\n\n');
    if (args.format !== 'none') process.stdout.write(renderNextSteps(summary, args.output, lang));
  }

  if (args.ci) {
    process.exit(summary.counts.critical > 0 ? 2 : summary.counts.warning > 0 ? 1 : 0);
  }
}

main().catch((err) => {
  process.stderr.write(`vibegate: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
