import type { ScanFile } from './types.js';

export interface Endpoint {
  method: string;
  path: string;
  where: string;
}

const JS_ROUTE = /\b(?:app|router|fastify|server)\.(get|post|put|patch|delete|all)\s*\(\s*["'`]([^"'`]+)["'`]/gi;
const PY_ROUTE = /@\w+\.(get|post|put|patch|delete|route)\s*\(\s*["']([^"']+)["']/gi;

function normalizeMethod(m: string): string {
  const up = m.toUpperCase();
  // Flask's @app.route and Express's .all cover every verb → treat as ANY so
  // the GET-based probes still pick them up.
  if (up === 'ALL' || up === 'ROUTE') return 'ANY';
  return up;
}

/** Extract HTTP endpoints declared across the project, any framework. */
export function collectEndpoints(files: Pick<ScanFile, 'rel' | 'content'>[]): Endpoint[] {
  const out: Endpoint[] = [];
  const seen = new Set<string>();
  const add = (method: string, path: string, where: string) => {
    if (!path) return;
    const key = `${method} ${path}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ method, path, where });
  };

  for (const f of files) {
    // Next.js App Router: app/**/route.ts — the file path is the endpoint.
    if (/(^|\/)app\/.*\/route\.(t|j)sx?$/.test(f.rel)) {
      const p = '/' + f.rel.replace(/^.*?app\//, '').replace(/\/route\.(t|j)sx?$/, '');
      add('ANY', p.replace(/\/\((?:[^)]+)\)/g, ''), f.rel); // strip Next route groups
      continue;
    }
    // Next.js Pages API: strip extension first, then a trailing /index.
    if (/(^|\/)pages\/api\/.+\.(t|j)sx?$/.test(f.rel)) {
      const p = '/' + f.rel.replace(/^.*?pages\//, '').replace(/\.(t|j)sx?$/, '').replace(/\/index$/, '');
      add('ANY', p, f.rel);
      continue;
    }
    for (const m of f.content.matchAll(JS_ROUTE)) add(normalizeMethod(m[1] ?? 'any'), m[2] ?? '', f.rel);
    for (const m of f.content.matchAll(PY_ROUTE)) add(normalizeMethod(m[1] ?? 'any'), m[2] ?? '', f.rel);
  }

  return out;
}

/** Turn a route template into a concrete probe path (":id" / "[id]" / "{id}" -> "1"). */
export function concretePath(path: string): string {
  return path
    .replace(/\[\[?\.\.\.[^\]]+\]?\]/g, 'test') // [...slug] and [[...slug]]
    .replace(/\[[^\]]+\]/g, '1') // [id]
    .replace(/\{[^}]+\}/g, '1') // {id} (FastAPI / Flask / OpenAPI)
    .replace(/:([A-Za-z0-9_]+)/g, '1'); // :id (Express)
}
