import { readdirSync, statSync, readFileSync } from 'node:fs';
import { join, relative, extname, sep, resolve } from 'node:path';
import type { ScanFile } from './types.js';

const SKIP_DIRS = new Set([
  '.git', 'node_modules', '.next', 'dist', 'build', 'out', '.venv', 'venv',
  '__pycache__', 'coverage', '.turbo', '.cache', 'vendor', '.svelte-kit',
  '.nuxt', '.output', 'target', '.idea', '.vscode', 'easyvibegate-report',
  // Installed third-party code, not the user's own. Matching only the venv
  // folder names above misses a venv called anything else (tools/ytenv/...),
  // and then every key inside a vendored library is reported as the user's leak.
  'site-packages', '__pypackages__', 'bower_components', 'Pods',
  // Yarn Berry vendors its own release script and zips dependencies here —
  // tool-managed, not the user's code (and often full of high-entropy blobs
  // that would otherwise read as secrets).
  '.yarn',
]);

/**
 * Names ambiguous enough that they are sometimes real source (a module named
 * "cache", a package called "tmp") and sometimes pure data. Skipped only when
 * `relDir` (the ambiguous directory's own path, relative to the project root,
 * e.g. "cache" or "data/cache") has at most 2 path segments — i.e. the
 * directory IS the root's own child, or is nested exactly one level below it.
 * The real-world evidence for this was `data/cache/*.json` full of API
 * pagination tokens, 559 of 569 "generic secrets" in one real project. Deeper
 * nesting (`apps/api/src/lib/cache/`, 4 segments) is ordinary source and stays
 * scanned; blanket name-matching at any depth once made a source directory
 * invisible to every check with no visible coverage gap.
 */
const AMBIGUOUS_DATA_DIRS = new Set(['cache', 'caches', 'tmp', 'temp', '.tmp']);
const isShallowDataDir = (name: string, relDir: string): boolean =>
  AMBIGUOUS_DATA_DIRS.has(name) && relDir.split('/').length <= 2;

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
  /** Directories we could not list. Their whole subtree went unchecked. */
  skippedDirs: number;
  /**
   * Symlinks to directories or scannable files that were NOT followed. Their
   * targets (e.g. `migrations -> ../shared/db`) went unchecked.
   */
  skippedSymlinks: number;
}

/** Recursively collect scannable text files under `root`, skipping noise. */
export interface WalkOptions {
  /**
   * Absolute directories to leave out — the report directory. Skipping it only
   * by its default name left a custom `--output <project>/reports` in the next
   * walk, so one source file turned into four scannable files.
   */
  excludeAbs?: string[];
}

export function walk(root: string, opts: WalkOptions = {}): WalkResult {
  const excluded = new Set((opts.excludeAbs ?? []).map((d) => resolve(d)));
  const out: ScanFile[] = [];
  let skippedOversized = 0;
  let skippedUnreadable = 0;
  let skippedDirs = 0;
  let skippedSymlinks = 0;
  const stack: string[] = [root];

  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      // A directory we cannot list is an unchecked subtree, not an empty one.
      // Swallowing this silently let a project with an unreadable folder report
      // full coverage and a clean PASS.
      skippedDirs++;
      continue;
    }
    for (const ent of entries) {
      const full = join(dir, ent.name);
      if (ent.isSymbolicLink()) {
        // Never followed: a link can loop or escape the project root. But a
        // link to a directory or a scannable file is unchecked content, and
        // silently dropping it let a project whose `migrations` was a symlink
        // PASS with full coverage. Count it so the walk is reported partial.
        const relLink = relative(root, full).split(sep).join('/');
        if (SKIP_DIRS.has(ent.name) || isShallowDataDir(ent.name, relLink)) continue;
        try {
          const target = statSync(full); // follows the link
          if (target.isDirectory() || (target.isFile() && isScannable(ent.name))) skippedSymlinks++;
        } catch {
          /* dangling link — nothing behind it to scan */
        }
        continue;
      }
      if (ent.isDirectory()) {
        const relDir = relative(root, full).split(sep).join('/');
        if (!SKIP_DIRS.has(ent.name) && !isShallowDataDir(ent.name, relDir) && !excluded.has(resolve(full))) stack.push(full);
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
  return { files: out, skippedOversized, skippedUnreadable, skippedDirs, skippedSymlinks };
}
