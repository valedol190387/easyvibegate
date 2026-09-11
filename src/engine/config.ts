import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding, ScanFile } from './types.js';

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

export function loadConfig(root: string, explicitPath?: string): VibegateConfig {
  const candidates = explicitPath ? [explicitPath] : CONFIG_NAMES.map((n) => join(root, n));
  for (const p of candidates) {
    let text: string;
    try {
      text = readFileSync(p, 'utf8');
    } catch {
      continue; // no such config here — try the next candidate
    }
    try {
      const raw = JSON.parse(text) as Partial<VibegateConfig>;
      return {
        ignore: Array.isArray(raw.ignore) ? raw.ignore : [],
        ignorePaths: Array.isArray(raw.ignorePaths) ? raw.ignorePaths : [],
      };
    } catch (e) {
      // The file exists but is broken: say so instead of silently ignoring every rule.
      return { ...DEFAULT_CONFIG, problem: `${p}: invalid JSON (${e instanceof Error ? e.message : String(e)})` };
    }
  }
  return DEFAULT_CONFIG;
}

const INLINE_MARKER = 'easyvibegate-ignore';

/** Drop findings suppressed by config rules or inline `// easyvibegate-ignore` markers. */
export function applyIgnores(
  findings: Finding[],
  config: VibegateConfig,
  files: ScanFile[],
): Finding[] {
  const byRel = new Map(files.map((f) => [f.rel, f.content.split('\n')]));

  const isConfigIgnored = (f: Finding): boolean => {
    const keys = [f.id, f.checker];
    if (f.file) keys.push(`${f.id}:${f.file}`, `${f.checker}:${f.file}`);
    if (config.ignore.some((rule) => keys.includes(rule))) return true;
    if (f.file && config.ignorePaths.some((sub) => f.file!.includes(sub))) return true;
    return false;
  };

  const isInlineIgnored = (f: Finding): boolean => {
    if (!f.file || !f.line) return false;
    const lines = byRel.get(f.file);
    if (!lines) return false;
    const current = lines[f.line - 1] ?? '';
    const prev = f.line >= 2 ? lines[f.line - 2] ?? '' : '';
    return current.includes(INLINE_MARKER) || prev.includes(INLINE_MARKER);
  };

  return findings.filter((f) => !isConfigIgnored(f) && !isInlineIgnored(f));
}
