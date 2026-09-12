import { execFileSync } from 'node:child_process';

/**
 * How a file can leak through git. This — not the file's name — decides how
 * serious a secret inside it is:
 *
 *   committed  the secret is in history; anyone with the repo has it
 *   untracked  in a repo, not ignored: one `git add -A` away from committed
 *   ignored    gitignored: cannot leak through git (a .env doing its job)
 *   no-git     not a repository: nothing leaks via git; the risk is copying
 *
 * A secret in a gitignored .env was once reported at the same level as one in
 * a committed script, so people learned to ignore the warnings — including the
 * real ones.
 */
export type Exposure = 'committed' | 'untracked' | 'ignored' | 'no-git';

function git(root: string, args: string[]): string | null {
  try {
    return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 });
  } catch {
    return null;
  }
}

/**
 * Build a per-root resolver. Tracked files are listed once; ignore checks run
 * lazily and are cached, so a project with many findings still costs a few
 * git calls, not one per finding.
 */
export function createExposure(root: string): (rel: string) => Exposure {
  const isRepo = git(root, ['rev-parse', '--git-dir']) !== null;
  if (!isRepo) return () => 'no-git';
  const tracked = new Set((git(root, ['ls-files', '-z']) ?? '').split('\0').filter(Boolean));
  const cache = new Map<string, Exposure>();
  return (rel: string): Exposure => {
    const hit = cache.get(rel);
    if (hit) return hit;
    let ex: Exposure;
    if (tracked.has(rel)) ex = 'committed';
    else ex = git(root, ['check-ignore', '-q', '--', rel]) !== null ? 'ignored' : 'untracked';
    cache.set(rel, ex);
    return ex;
  };
}
