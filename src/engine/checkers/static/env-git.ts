import { execFileSync } from 'node:child_process';
import type { Checker, Finding } from '../../types.js';

function gitOk(root: string, args: string[]): boolean {
  try {
    execFileSync('git', ['-C', root, ...args], { stdio: 'ignore', timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Ensures .env files are actually kept out of Git, using Git's own semantics
 * (check-ignore + ls-files) rather than a text heuristic. A tracked .env is the
 * real leak; an un-ignored .env is a risk of becoming one.
 */
export const envGitChecker: Checker = {
  id: 'env-git',
  title: '.env exposure via git',
  level: 0,
  run(ctx) {
    const envFiles = ctx.files.filter(
      (f) => f.rel === '.env' || (/(^|\/)\.env(\.|$)/.test(f.rel) && !f.rel.endsWith('.example') && !f.rel.endsWith('.sample')),
    );
    if (envFiles.length === 0) return [];

    const findings: Finding[] = [];
    // Ask git itself: a subdirectory of a repo (monorepo package) is still in git.
    const isGit = gitOk(ctx.root, ['rev-parse', '--git-dir']);

    if (!isGit) {
      findings.push({
        id: 'env_git_unverified',
        severity: 'info',
        title: 'Cannot verify .env is ignored (not a git repo)',
        detail: `Found ${envFiles.map((f) => f.rel).join(', ')}, but this folder is not a git repository, so tracking cannot be checked here.`,
        fix: 'Before pushing, ensure a .gitignore ignores .env files (e.g. `.env*`), and never commit real secrets.',
        checker: 'env-git',
        level: 0,
      });
      return findings;
    }

    for (const env of envFiles) {
      const tracked = gitOk(ctx.root, ['ls-files', '--error-unmatch', '--', env.rel]);
      if (tracked) {
        findings.push({
          id: 'env_committed',
          severity: 'critical',
          title: `${env.rel} is committed to git`,
          detail: `${env.rel} is tracked by git — its secrets are in the repository (and its history), reachable by anyone with repo access.`,
          fix: `Untrack it: git rm --cached ${env.rel}; add it to .gitignore; and ROTATE every secret it contained (a committed secret is already burned; deleting it does not un-leak history).`,
          checker: 'env-git',
          level: 0,
          file: env.rel,
        });
        continue;
      }
      const ignored = gitOk(ctx.root, ['check-ignore', '-q', '--', env.rel]);
      if (!ignored) {
        findings.push({
          id: 'env_not_ignored',
          severity: 'warning',
          title: `${env.rel} is not gitignored`,
          detail: `${env.rel} is not tracked yet, but no .gitignore rule matches it, so it can be committed by accident.`,
          fix: 'Add a matching rule to .gitignore (e.g. `.env*`) so it can never be committed.',
          checker: 'env-git',
          level: 0,
          file: env.rel,
        });
      }
    }

    return findings;
  },
};
