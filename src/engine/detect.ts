import type { Detection, ScanFile } from './types.js';

/** Infer the project's frameworks, backends, languages and package managers. */
export function detect(files: ScanFile[]): Detection {
  const relSet = new Set(files.map((f) => f.rel));
  const has = (p: string) => relSet.has(p);

  const frameworks = new Set<string>();
  const backends = new Set<string>();
  const languages = new Set<string>();
  const pms = new Set<string>();

  for (const f of files) {
    if (f.ext === '.ts' || f.ext === '.tsx') languages.add('typescript');
    else if (['.js', '.jsx', '.mjs', '.cjs'].includes(f.ext)) languages.add('javascript');
    else if (f.ext === '.py') languages.add('python');
    else if (f.ext === '.rb') languages.add('ruby');
    else if (f.ext === '.php') languages.add('php');
    else if (f.ext === '.go') languages.add('go');
    else if (f.ext === '.rs') languages.add('rust');
  }

  if (has('pnpm-lock.yaml')) pms.add('pnpm');
  if (has('package-lock.json')) pms.add('npm');
  if (has('yarn.lock')) pms.add('yarn');
  if (has('bun.lockb') || has('bun.lock')) pms.add('bun');

  const pkg = files.find((f) => f.rel === 'package.json');
  let deps: Record<string, string> = {};
  if (pkg) {
    try {
      const j = JSON.parse(pkg.content) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      deps = { ...(j.dependencies ?? {}), ...(j.devDependencies ?? {}) };
    } catch {
      /* ignore malformed package.json */
    }
  }
  const dep = (n: string) => n in deps;

  if (dep('next')) frameworks.add('next');
  if (dep('react')) frameworks.add('react');
  if (dep('vue')) frameworks.add('vue');
  if (dep('svelte') || dep('@sveltejs/kit')) frameworks.add('svelte');
  if (dep('nuxt')) frameworks.add('nuxt');
  if (dep('vite')) frameworks.add('vite');
  if (dep('express')) frameworks.add('express');
  if (dep('fastify')) frameworks.add('fastify');
  if (dep('koa')) frameworks.add('koa');
  if (dep('@nestjs/core')) frameworks.add('nestjs');
  if (dep('@supabase/supabase-js') || dep('@supabase/ssr')) backends.add('supabase');
  if (dep('firebase') || dep('firebase-admin')) backends.add('firebase');

  const reqs = files.find((f) => f.rel === 'requirements.txt');
  const pyproject = files.find((f) => f.rel === 'pyproject.toml');
  const pyText = `${reqs?.content ?? ''}\n${pyproject?.content ?? ''}`;
  if (/\bdjango\b/i.test(pyText)) frameworks.add('django');
  if (/\bflask\b/i.test(pyText)) frameworks.add('flask');
  if (/\bfastapi\b/i.test(pyText)) frameworks.add('fastapi');
  if (reqs || pyproject || has('manage.py')) languages.add('python');
  if (has('Gemfile')) {
    languages.add('ruby');
    const gem = files.find((f) => f.rel === 'Gemfile');
    if (gem && /\brails\b/i.test(gem.content)) frameworks.add('rails');
  }

  // Content fallback for projects without a package.json — kept strict to avoid
  // false positives from code that merely mentions a backend by name.
  if (!backends.has('supabase') && files.some((f) => /https?:\/\/[a-z0-9-]+\.supabase\.co/i.test(f.content))) {
    backends.add('supabase');
  }
  if (!backends.has('firebase') && files.some((f) => /\binitializeApp\s*\(/.test(f.content) && /firebase/i.test(f.content))) {
    backends.add('firebase');
  }

  return {
    frameworks: [...frameworks],
    backends: [...backends],
    languages: [...languages],
    packageManagers: [...pms],
    hasEnv: files.some((f) => f.rel === '.env' || /(^|\/)\.env(\.|$)/.test(f.rel)),
    hasGitignore: has('.gitignore'),
  };
}
