import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding, ScanFile } from './types.js';

export interface VibegateConfig {
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
    try {
      const raw = JSON.parse(readFileSync(p, 'utf8')) as Partial<VibegateConfig>;
      return {
        ignore: Array.isArray(raw.ignore) ? raw.ignore : [],
        ignorePaths: Array.isArray(raw.ignorePaths) ? raw.ignorePaths : [],
      };
    } catch {
      /* try next candidate */
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
