#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { planTargets, runFlow, type ConsentRequest } from '../orchestrator/flow.js';
import { scanStatic } from '../engine/scan.js';
import { loadConfig, validateConfigFile } from '../engine/config.js';
import {
  badgeMarkdown,
  exitCodeFor,
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
import { VERSION } from '../engine/version.js';

type Format = 'all' | 'md' | 'json' | 'none';

interface Args {
  path: string;
  output?: string;
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
  noReport: boolean;
  unknown: string[];
  argErrors: string[];
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
  -o, --output <dir>     Report directory (default: <project>/easyvibegate-report)
  -f, --format <fmt>     all | md | json | none (default: all)
      --ci               Non-interactive: no wizard, no prompts, quiet output
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

Exit codes (every mode): 2 = critical, 1 = warnings, 3 = a check did not complete, 0 = clean.
Ethics: the live probe sends real requests. Only run it against systems you own.
`;

function parseArgs(argv: string[]): Args {
  const a: Args = {
    path: '.',
    format: 'all',
    ci: false,
    iOwnThis: false,
    yes: false,
    deps: false,
    noWizard: false,
    wizard: false,
    badIdorTokens: false,
    noReport: false,
    unknown: [],
    argErrors: [],
    help: false,
    version: false,
  };
  let sawPath = false;
  let endOfFlags = false;
  let i = 0;
  // Read a required value; error if it's missing or looks like another flag.
  const need = (name: string): string | undefined => {
    const v = argv[i + 1];
    if (v === undefined || v.startsWith('-')) { a.argErrors.push(`${name} needs a value`); return undefined; }
    i++;
    return v;
  };

  for (; i < argv.length; i++) {
    const arg = argv[i]!;
    if (endOfFlags) {
      if (!sawPath) { a.path = arg; sawPath = true; } else a.argErrors.push(`unexpected extra path "${arg}"`);
      continue;
    }
    if (arg === '--') { endOfFlags = true; continue; }
    switch (arg) {
      case '-h': case '--help': a.help = true; break;
      case '-v': case '--version': a.version = true; break;
      case '--ci': a.ci = true; break;
      case '-o': case '--output': a.output = need('--output') ?? a.output; break;
      case '-f': case '--format': {
        const v = need('--format')?.toLowerCase();
        if (v === undefined) break;
        if (v === 'all' || v === 'md' || v === 'json' || v === 'none') a.format = v;
        else a.argErrors.push(`--format must be one of all|md|json|none (got "${v}")`);
        break;
      }
      case '--no-report': a.noReport = true; break;
      case '-c': case '--config': a.config = need('--config'); break;
      case '--url': a.appUrl = need('--url'); break;
      case '--supabase-url': a.supabaseUrl = need('--supabase-url'); break;
      case '--supabase-key': a.supabaseKey = need('--supabase-key'); break;
      case '--i-own-this': a.iOwnThis = true; break;
      case '-y': case '--yes': a.yes = true; break;
      case '--deps': a.deps = true; break;
      case '--no-wizard': case '--scan': a.noWizard = true; break;
      case '--wizard': a.wizard = true; break;
      case '--lang': {
        const v = need('--lang')?.toLowerCase();
        if (v === undefined) break;
        if (v === 'ru' || v === 'en') a.lang = v;
        else a.argErrors.push(`--lang must be ru or en (got "${v}")`);
        break;
      }
      case '--idor-tokens': {
        const v = need('--idor-tokens');
        if (v === undefined) break;
        const parts = v.split(',').map((s) => s.trim()).filter(Boolean);
        if (parts.length !== 2) a.badIdorTokens = true;
        // Two identical tokens are one identity: the differential could never
        // observe cross-user access, so the check would silently prove nothing.
        else if (parts[0] === parts[1]) a.argErrors.push('--idor-tokens needs two DIFFERENT tokens (two accounts) — identical tokens cannot test cross-user access');
        else a.idorTokens = [parts[0]!, parts[1]!];
        break;
      }
      default:
        if (arg.startsWith('-')) a.unknown.push(arg);
        else if (!sawPath) { a.path = arg; sawPath = true; }
        else a.argErrors.push(`unexpected extra path "${arg}" — scan one project at a time`);
    }
  }

  // Cross-option validation.
  if (a.noReport) a.format = 'none'; // wins regardless of flag order
  if (a.wizard && a.noWizard) a.argErrors.push('--wizard and --no-wizard cannot be combined');
  if (a.output !== undefined && a.output.trim() === '') a.argErrors.push('--output needs a directory path');
  const httpish = (u: string) => /^https?:\/\//i.test(u);
  if (a.appUrl && !httpish(a.appUrl)) a.argErrors.push('--url must start with http:// or https://');
  if (a.supabaseUrl && !httpish(a.supabaseUrl)) a.argErrors.push('--supabase-url must start with http:// or https://');
  if (!!a.supabaseUrl !== !!a.supabaseKey) a.argErrors.push('--supabase-url and --supabase-key must be provided together');
  if (a.idorTokens && !a.appUrl) a.argErrors.push('--idor-tokens requires --url (the running app to probe)');
  return a;
}

function ask(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((res) => {
    let done = false;
    const finish = (v: string) => { if (!done) { done = true; rl.close(); res(v); } };
    rl.question(question, finish);
    rl.once('close', () => finish('')); // Ctrl-D / EOF = "no", never a silent hang
  });
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
  if (args.argErrors.length > 0) {
    process.stderr.write(`easyvibegate: ${args.argErrors.join('; ')}\nRun with --help.\n`);
    process.exit(2);
  }

  const root = resolve(args.path);
  if (!existsSync(root) || !statSync(root).isDirectory()) {
    process.stderr.write(`easyvibegate: path not found or not a directory: ${root}\n`);
    process.exit(2);
  }
  // An explicitly requested config must exist and be valid — silently falling
  // back to defaults would apply different ignore rules than the user asked for.
  if (args.config !== undefined) {
    const problem = validateConfigFile(resolve(args.config));
    if (problem) {
      process.stderr.write(`easyvibegate: --config ${args.config}: ${problem}\n`);
      process.exit(2);
    }
  }

  const autoYes = args.iOwnThis || args.yes;
  const lang = pickLang(args.lang);
  // Reports land next to the scanned project by default, so scanning several
  // projects from one shell never overwrites another project's report.
  const outDir = args.output !== undefined ? resolve(args.output) : join(root, 'easyvibegate-report');
  // Excluding outDir from the scan only makes sense when something is
  // actually going to be written there. With --no-report (format 'none'),
  // nothing is ever written to it — so a `--no-report --output <project>/src`
  // run must not exclude real source just because it shares a path with an
  // output directory nothing will use.
  const excludeOutDir = args.format !== 'none' ? [outDir] : [];
  // The report directory gets its OWN `.gitignore` (see prepareOutputDir) and
  // has its stale report files deleted on every run. Both are safe for a
  // directory that exists only to hold reports — neither is safe for the
  // scanned project itself: `--output .` from the project root would replace
  // the project's real .gitignore with a bare `*`, silently un-tracking the
  // whole repo.
  if (args.output !== undefined && outDir === root) {
    process.stderr.write(`easyvibegate: --output must not be the scanned project itself (${root}) — pick a subdirectory, e.g. --output ${join(root, 'easyvibegate-report')}
`);
    process.exit(2);
  }

  // Use the friendly wizard when a human runs it in a terminal without
  // automation flags; --wizard forces it. Either way the pipeline below is shared.
  // --ci is a non-interactive contract: never ask questions there.
  const useWizard = !args.ci && (args.wizard || (!args.noWizard && !autoYes && !!process.stdin.isTTY));

  // Asking for a live check in a run that can never confirm ownership is a
  // misconfigured invocation, not a clean scan. Fail on the flags rather than
  // silently skipping the very check the run was set up to perform.
  const canConfirmOwnership = autoYes || useWizard || !!process.stdin.isTTY;
  if (!canConfirmOwnership) {
    const requested = [args.appUrl ? '--url' : '', args.supabaseUrl ? '--supabase-url' : ''].filter(Boolean);
    if (requested.length > 0) {
      process.stderr.write(
        `easyvibegate: ${requested.join(' and ')} asks for a live check, but this run is non-interactive and cannot confirm you own the target.\n` +
        'Add --i-own-this to assert ownership, or run it in a terminal.\n',
      );
      process.exit(2);
    }
  }

  let result;
  if (useWizard) {
    result = await runWizard({
      excludeAbs: excludeOutDir,
      path: args.path,
      config: args.config,
      lang,
      appUrl: args.appUrl,
      deps: args.deps,
      idorTokens: args.idorTokens,
      supabaseUrl: args.supabaseUrl,
      supabaseKey: args.supabaseKey,
      autoYes,
    });
  } else {
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
    // Same contract as the wizard: plan the concrete targets once, ask about
    // exactly those, execute exactly those.
    const staticResult = await scanStatic(root, { configPath: args.config, excludeAbs: excludeOutDir });
    const plan = planTargets(staticResult.files, loadConfig(root, args.config), {
      appUrl: args.appUrl,
      supabaseUrl: args.supabaseUrl,
      supabaseKey: args.supabaseKey,
      idorTokens: args.idorTokens,
    });
    result = await runFlow({
      root,
      configPath: args.config,
      runDeps: args.deps,
      precomputedStatic: staticResult,
      plan,
      consent,
      log,
    });
  }

  // ---- One shared pipeline: console, reports, verdict, exit code. ----
  const summary = summarize(result.findings, result.runs);

  if (!args.ci) process.stdout.write(renderConsole(result, summary, lang) + '\n');

  if (args.format !== 'none') {
    const problem = prepareOutputDir(outDir);
    if (problem) {
      process.stderr.write(`easyvibegate: --output ${outDir}: ${problem}\n`);
      process.exit(2);
    }
    const written: string[] = [];
    if (args.format === 'all' || args.format === 'md') {
      const p = join(outDir, 'report.md');
      writeFileSync(p, renderMarkdown(result, summary, lang), 'utf8');
      written.push(p);
    }
    if (args.format === 'all' || args.format === 'json') {
      const p = join(outDir, 'report.json');
      writeFileSync(p, renderJson(result, summary), 'utf8');
      written.push(p);
    }
    // The fix plan is the whole point — always produce it alongside a report.
    writeFileSync(join(outDir, 'ai-fix-prompt.md'), buildAiFixPrompt(result, summary, lang), 'utf8');
    if (!args.ci && written.length) {
      process.stdout.write(color.gray(`  report: ${written.join(', ')}\n`));
      process.stdout.write(color.gray(`  badge:  ${badgeMarkdown(summary)}\n\n`));
    }
  }

  if (!args.ci) {
    process.stdout.write(renderVerdict(summary, lang) + '\n\n');
    if (args.format !== 'none') process.stdout.write(renderNextSteps(summary, outDir, lang));
  }

  // Same contract in every mode: 2 critical, 1 warning, 3 incomplete, 0 clean.
  process.exit(exitCodeFor(summary));
}

// Written verbatim (never partially, never appended-to) so an exact match on
// disk is proof WE created this directory, not the user re-pointing --output
// at a folder of their own. Checking "does outDir === project root" only was
// not enough: `--output docs` on a real docs/ folder replaced its real
// .gitignore (losing rules like `drafts/`) and deleted a real docs/report.md.
const OUTPUT_DIR_MARKER = '# Written by EasyVibeGate: this report can contain secret prefixes and hosts. Never commit it.\n*\n';

/** Create the report dir and clear our own stale files, or explain why we cannot. */
function prepareOutputDir(dir: string): string | null {
  try {
    const existed = existsSync(dir);
    if (existed && !statSync(dir).isDirectory()) return 'exists and is not a directory';
    if (existed) {
      const ownsIt = existsSync(join(dir, '.gitignore')) && readFileSync(join(dir, '.gitignore'), 'utf8') === OUTPUT_DIR_MARKER;
      if (!ownsIt && readdirSync(dir).length > 0) {
        return 'already exists, is not empty, and was not created by a previous EasyVibeGate run — refusing to overwrite its .gitignore or delete files in it; point --output at an empty or dedicated directory';
      }
    }
    mkdirSync(dir, { recursive: true });
    // The report names secret prefixes, database hosts and every endpoint —
    // exactly what must not be committed. A `.gitignore` containing `*` inside
    // the directory makes git ignore it wherever the project's own .gitignore
    // stands (the trick node_modules-style caches use); the user's files are
    // never edited. Rewritten every run so a stray edit cannot un-ignore it —
    // safe now because we only ever reach this line for a directory that was
    // either empty or already marked as ours.
    writeFileSync(join(dir, '.gitignore'), OUTPUT_DIR_MARKER, 'utf8');
    // Old report.md next to a fresh report.json told two different stories.
    for (const name of ['report.md', 'report.json', 'ai-fix-prompt.md']) {
      const p = join(dir, name);
      if (existsSync(p)) rmSync(p, { force: true });
    }
    return null;
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}


main().catch((err) => {
  process.stderr.write(`easyvibegate: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
