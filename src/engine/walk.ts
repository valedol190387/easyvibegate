import { readdirSync, statSync, readFileSync } from 'node:fs';
import { join, relative, extname, sep } from 'node:path';
import type { ScanFile } from './types.js';

const SKIP_DIRS = new Set([
  '.git', 'node_modules', '.next', 'dist', 'build', 'out', '.venv', 'venv',
  '__pycache__', 'coverage', '.turbo', '.cache', 'vendor', '.svelte-kit',
  '.nuxt', '.output', 'target', '.idea', '.vscode', 'easyvibegate-report',
]);

const TEXT_EXT = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte',
  '.py', '.rb', '.php', '.go', '.rs', '.java', '.kt', '.cs',
  '.html', '.css', '.scss', '.json', '.yml', '.yaml', '.toml',
  '.env', '.sh', '.sql', '.md', '.txt', '.ini', '.conf', '.tf',
  '.pem', '.key', '.crt', '.cert', '.pkcs8',
  '.astro', '.properties', '.plist', '.swift', '.dart', '.ipynb', '.bash', '.zsh', '.mdx',
]);

const ALWAYS_NAMES = new Set([
  'Dockerfile', 'Gemfile', 'Procfile', 'Makefile', '.gitignore',
  '.npmrc', '.netrc', '.yarnrc', '.dockerignore', 'env.local', 'credentials',
]);

const MAX_SIZE = 1024 * 1024; // 1 MB

function isScannable(name: string): boolean {
  if (name.startsWith('.env')) return true;
  if (name.startsWith('docker-compose')) return true;
  if (ALWAYS_NAMES.has(name)) return true;
  return TEXT_EXT.has(extname(name).toLowerCase());
}

export interface WalkResult {
  files: ScanFile[];
  /** Files we could not read — recorded so a partial scan is never silent. */
  skippedOversized: number;
  skippedUnreadable: number;
}

/** Recursively collect scannable text files under `root`, skipping noise. */
export function walk(root: string): WalkResult {
  const out: ScanFile[] = [];
  let skippedOversized = 0;
  let skippedUnreadable = 0;
  const stack: string[] = [root];

  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      if (ent.isSymbolicLink()) continue;
      const full = join(dir, ent.name);
      if (ent.isDirectory()) {
        if (!SKIP_DIRS.has(ent.name)) stack.push(full);
        continue;
      }
      if (!ent.isFile() || !isScannable(ent.name)) continue;
      let st;
      try {
        st = statSync(full);
      } catch {
        skippedUnreadable++;
        continue;
      }
      if (st.size > MAX_SIZE) { skippedOversized++; continue; }
      let content;
      try {
        content = readFileSync(full, 'utf8');
      } catch {
        skippedUnreadable++;
        continue;
      }
      out.push({
        abs: full,
        rel: relative(root, full).split(sep).join('/'),
        content,
        ext: extname(ent.name).toLowerCase(),
        size: st.size,
      });
    }
  }
  return { files: out, skippedOversized, skippedUnreadable };
}
