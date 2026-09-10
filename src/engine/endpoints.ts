import type { ScanFile } from './types.js';

export interface Endpoint {
  method: string;
  path: string;
  where: string;
}

const JS_ROUTE = /\b(?:app|router|fastify|server)\.(get|post|put|patch|delete|all)\s*\(\s*["'`]([^"'`]+)["'`]/gi;
const PY_ROUTE = /@\w+\.(get|post|put|patch|delete|route)\s*\(\s*["']([^"']+)["']/gi;

/** Extract HTTP endpoints declared across the project, any framework. */
export function collectEndpoints(files: Pick<ScanFile, 'rel' | 'content'>[]): Endpoint[] {
  const out: Endpoint[] = [];
  const seen = new Set<string>();
  const add = (method: string, path: string, where: string) => {
    const key = `${method} ${path}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ method, path, where });
  };

  for (const f of files) {
    // Next.js App Router: app/**/route.ts — the file path is the endpoint.
    if (/(^|\/)app\/.*\/route\.(t|j)sx?$/.test(f.rel)) {
      const path = '/' + f.rel.replace(/^.*?app\//, '').replace(/\/route\.(t|j)sx?$/, '');
      add('ANY', path.replace(/\/\((?:[^)]+)\)/g, ''), f.rel); // strip Next route groups
      continue;
    }
    // Next.js Pages API.
    if (/(^|\/)pages\/api\/.+\.(t|j)sx?$/.test(f.rel)) {
      const path = '/' + f.rel.replace(/^.*?pages\//, '').replace(/\/index$/, '').replace(/\.(t|j)sx?$/, '');
      add('ANY', path, f.rel);
      continue;
    }
    for (const m of f.content.matchAll(JS_ROUTE)) add((m[1] ?? 'any').toUpperCase(), m[2] ?? '', f.rel);
    for (const m of f.content.matchAll(PY_ROUTE)) add((m[1] ?? 'any').toUpperCase(), m[2] ?? '', f.rel);
  }

  return out;
}

/** Turn a route template into a concrete probe path (":id" / "[id]" -> "1"). */
export function concretePath(path: string): string {
  return path
    .replace(/\[\.\.\.[^\]]+\]/g, 'test')
    .replace(/\[[^\]]+\]/g, '1')
    .replace(/:([A-Za-z0-9_]+)/g, '1');
}
