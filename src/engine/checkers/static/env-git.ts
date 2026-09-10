import type { Checker, Finding } from '../../types.js';

/**
 * Ensures .env files are ignored by git. A committed .env is how most
 * hardcoded-secret leaks actually reach a public repo.
 */
export const envGitChecker: Checker = {
  id: 'env-git',
  title: '.env exposure via git',
  level: 0,
  run(ctx) {
    const findings: Finding[] = [];

    const envFiles = ctx.files.filter(
      (f) => f.rel === '.env' || (/(^|\/)\.env(\.|$)/.test(f.rel) && !f.rel.endsWith('.example') && !f.rel.endsWith('.sample')),
    );
    if (envFiles.length === 0) return findings;

    const gitignore = ctx.files.find((f) => f.rel === '.gitignore');
    const ignoreLines = gitignore
      ? gitignore.content.split('\n').map((l) => l.trim())
      : [];
    // Approximate: a full glob match needs git itself. If .gitignore references
    // .env at all, assume env files are handled — avoids noisy false alarms.
    const envIgnored = ignoreLines.some(
      (line) => !line.startsWith('#') && /(^|\/|\*)\.env/.test(line),
    );
    const covers = (_rel: string): boolean => envIgnored;

    if (!gitignore) {
      findings.push({
        id: 'gitignore_missing',
        severity: 'critical',
        title: '.env present but no .gitignore',
        detail: `Found ${envFiles.map((f) => f.rel).join(', ')} with no .gitignore. These will be committed and can leak every secret.`,
        fix: 'Add a .gitignore that ignores .env files: echo ".env*" >> .gitignore, then untrack any already-committed .env.',
        checker: 'env-git',
        level: 0,
        file: envFiles[0]!.rel,
      });
      return findings;
    }

    for (const env of envFiles) {
      if (!covers(env.rel)) {
        findings.push({
          id: 'env_not_ignored',
          severity: 'critical',
          title: '.env not covered by .gitignore',
          detail: `${env.rel} is not matched by any .gitignore rule and risks being committed.`,
          fix: 'Add a matching rule (e.g. ".env*") to .gitignore, and rotate any secret that may already be in git history.',
          checker: 'env-git',
          level: 0,
          file: env.rel,
        });
      }
    }

    return findings;
  },
};
