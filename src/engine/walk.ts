import { readdirSync, statSync, readFileSync } from 'node:fs';
import { join, relative, extname, sep } from 'node:path';
import type { ScanFile } from './types.js';

const SKIP_DIRS = new Set([
  '.git', 'node_modules', '.next', 'dist', 'build', 'out', '.venv', 'venv',
  '__pycache__', 'coverage', '.turbo', '.cache', 'vendor', '.svelte-kit',
  '.nuxt', '.output', 'target', '.idea', '.vscode', 'vibegate-report',
]);

const TEXT_EXT = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte',
  '.py', '.rb', '.php', '.go', '.rs', '.java', '.kt', '.cs',
  '.html', '.css', '.scss', '.json', '.yml', '.yaml', '.toml',
  '.env', '.sh', '.sql', '.md', '.txt', '.ini', '.conf', '.tf',
]);

const ALWAYS_NAMES = new Set(['Dockerfile', 'Gemfile', 'Procfile', 'Makefile', '.gitignore']);

const MAX_SIZE = 1024 * 1024; // 1 MB

function isScannable(name: string): boolean {
  if (name.startsWith('.env')) return true;
  if (name.startsWith('docker-compose')) return true;
  if (ALWAYS_NAMES.has(name)) return true;
  return TEXT_EXT.has(extname(name).toLowerCase());
}

/** Recursively collect scannable text files under `root`, skipping noise. */
export function walk(root: string): ScanFile[] {
  const out: ScanFile[] = [];
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
        continue;
      }
      if (st.size > MAX_SIZE) continue;
      let content;
      try {
        content = readFileSync(full, 'utf8');
      } catch {
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
  return out;
}
