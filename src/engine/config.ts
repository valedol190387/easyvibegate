import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding, ScanFile } from './types.js';
import { langForFile, lexCode } from './util/code-lex.js';
import { lineAt } from './util/text.js';

export interface VibegateConfig {
  /** Set when a config file existed but could not be used. */
  problem?: string;
  /** Suppress by checker id, finding id, or "<id>:<relpath>". */
  ignore: string[];
  /** Suppress any finding whose file path contains one of these substrings. */
  ignorePaths: string[];
}

const DEFAULT_CONFIG: VibegateConfig = { ignore: [], ignorePaths: [] };

const CONFIG_NAMES = ['easyvibegate.config.json', '.easyvibegaterc.json'];

const KNOWN_KEYS = ['ignore', 'ignorePaths'] as const;

/**
 * Validate a parsed config object. Returns a problem message or null.
 * One validator for the explicit `--config` file and the auto-discovered one:
 * a typo like "ignorePath" must be rejected the same way in both, otherwise it
 * silently does nothing and the user believes their rules are in effect.
 */
export function validateConfig(parsed: unknown): string | null {
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return 'must be a JSON object';
  const cfg = parsed as Record<string, unknown>;
  for (const key of KNOWN_KEYS) {
    const v = cfg[key];
    if (v === undefined) continue;
    if (!Array.isArray(v) || v.some((x) => typeof x !== 'string')) return `"${key}" must be an array of strings`;
  }
  const unknown = Object.keys(cfg).filter((k) => !(KNOWN_KEYS as readonly string[]).includes(k));
  if (unknown.length) return `unknown key(s): ${unknown.join(', ')} (expected ${KNOWN_KEYS.join(', ')})`;
  return null;
}

/** Read + parse + validate one config file. Every failure is a message, never a silent default. */
function readConfigFile(path: string): { config: VibegateConfig } | { problem: string } {
  try {
    if (!existsSync(path)) return { problem: 'file not found' };
    if (!statSync(path).isFile()) return { problem: 'not a file' };
  } catch (e) {
    return { problem: `cannot read (${e instanceof Error ? e.message : String(e)})` };
  }
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    return { problem: `cannot read (${e instanceof Error ? e.message : String(e)})` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    return { problem: `invalid JSON (${e instanceof Error ? e.message : String(e)})` };
  }
  const problem = validateConfig(parsed);
  if (problem) return { problem };
  const raw = parsed as Partial<VibegateConfig>;
  return { config: { ignore: raw.ignore ?? [], ignorePaths: raw.ignorePaths ?? [] } };
}

/** Problem with a config file the user pointed at (missing, directory, bad JSON, bad shape), or null. */
export function validateConfigFile(path: string): string | null {
  const r = readConfigFile(path);
  return 'problem' in r ? r.problem : null;
}

export function loadConfig(root: string, explicitPath?: string): VibegateConfig {
  const candidates = explicitPath ? [explicitPath] : CONFIG_NAMES.map((n) => join(root, n));
  for (const p of candidates) {
    // An auto-discovered name that is simply absent means "no config here".
    // Anything else (present but unreadable, a directory, broken, misspelled
    // keys) is a problem to report — the user's rules were NOT applied.
    if (!explicitPath && !existsSync(p)) continue;
    const r = readConfigFile(p);
    return 'problem' in r ? { ...DEFAULT_CONFIG, problem: `${p}: ${r.problem}` } : r.config;
  }
  return DEFAULT_CONFIG;
}

const INLINE_MARKER = 'easyvibegate-ignore';
/** Optional scope right after the marker: `easyvibegate-ignore: jwt_alg_none, config-risks`. */
const SCOPE_RE = /^:[ \t]*([\w-]+(?:[ \t]*,[ \t]*[\w-]+)*)/;

/**
 * Lines that carry a suppression directive, with the ids it is scoped to
 * (null = everything). Only a COMMENT token counts: the marker inside a string
 * literal (`const label = "easyvibegate-ignore"`) is data and must not switch
 * the scanner off for the next line. The lexer decides what a comment is per
 * language: `//`, `#`, a block comment, `--` for SQL.
 */
function inlineDirectives(file: ScanFile): Map<number, Set<string> | null> {
  const lines = new Map<number, Set<string> | null>();
  for (const t of lexCode(file.content, langForFile(file.rel))) {
    if (t.type !== 'comment' || !t.value.includes(INLINE_MARKER)) continue;
    let at = t.value.indexOf(INLINE_MARKER);
    while (at !== -1) {
      const line = lineAt(file.content, t.start + at);
      const scope = SCOPE_RE.exec(t.value.slice(at + INLINE_MARKER.length));
      const ids = scope?.[1] ? scope[1].split(',').map((s) => s.trim()) : null;
      const prev = lines.get(line);
      if (ids === null || prev === null) lines.set(line, null);
      else lines.set(line, new Set([...(prev ?? []), ...ids]));
      at = t.value.indexOf(INLINE_MARKER, at + INLINE_MARKER.length);
    }
  }
  return lines;
}

/**
 * Split findings into kept and suppressed (config rules or inline markers).
 * The suppressed half is returned so it can be counted — a rule that silences
 * a finding should be visible somewhere, never just make it disappear.
 */
export function partitionIgnores(
  findings: Finding[],
  config: VibegateConfig,
  files: ScanFile[],
): { kept: Finding[]; suppressed: Finding[] } {
  const byRel = new Map(files.map((f) => [f.rel, f]));
  const directives = new Map<string, Map<number, Set<string> | null>>();

  const isConfigIgnored = (f: Finding): boolean => {
    const keys = [f.id, f.checker];
    if (f.file) keys.push(`${f.id}:${f.file}`, `${f.checker}:${f.file}`);
    if (config.ignore.some((rule) => keys.includes(rule))) return true;
    if (f.file && config.ignorePaths.some((sub) => f.file!.includes(sub))) return true;
    return false;
  };

  const isInlineIgnored = (f: Finding): boolean => {
    if (!f.file || !f.line) return false;
    const file = byRel.get(f.file);
    if (!file) return false;
    let lines = directives.get(f.file);
    if (!lines) { lines = inlineDirectives(file); directives.set(f.file, lines); }
    // The marker applies to its own line or the line right below it.
    for (const line of [f.line, f.line - 1]) {
      if (!lines.has(line)) continue;
      const scope = lines.get(line) ?? null;
      if (scope === null || scope.has(f.id) || scope.has(f.checker)) return true;
    }
    return false;
  };

  const kept: Finding[] = [];
  const suppressed: Finding[] = [];
  for (const f of findings) (isConfigIgnored(f) || isInlineIgnored(f) ? suppressed : kept).push(f);
  return { kept, suppressed };
}

/** Drop findings suppressed by config rules or inline `// easyvibegate-ignore` markers. */
export function applyIgnores(findings: Finding[], config: VibegateConfig, files: ScanFile[]): Finding[] {
  return partitionIgnores(findings, config, files).kept;
}
