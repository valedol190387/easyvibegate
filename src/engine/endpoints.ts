import type { ScanFile } from './types.js';

export interface Endpoint {
  method: string;
  path: string;
  where: string;
  /**
   * The route is declared on a router whose mount point could not be found, so
   * `path` may be missing a prefix. Probing it would hit a wrong URL and a 404
   * there would prove nothing — probes must record it as not verified instead.
   */
  unresolved?: true;
  /** Why it is unresolved (for the run note). */
  note?: string;
}

// Any receiver: app/router/api/server/v1/`this.x` … .get('/path'). Group 1 is the
// receiver identifier when it is a plain name (so a router can be tied to its mount).
const JS_ROUTE = /(?:\b([\w$]+)|[)\]])\s*\.(get|post|put|patch|delete|all|options|head)\s*\(\s*["'`](\/[^"'`]*)["'`]/gi;
const PY_ROUTE = /@\w+\.(get|post|put|patch|delete|route)\s*\(\s*["']([^"']+)["']/gi;
// NestJS: @Get('users') on a controller method, @Controller('api/orders') on the class.
const NEST_ROUTE = /@(Get|Post|Put|Patch|Delete|All)\s*\(\s*(?:["'`]([^"'`]*)["'`])?\s*\)/g;
const NEST_CONTROLLER = /@Controller\s*\(([^)]*)\)/g;
const NEST_GLOBAL_PREFIX = /\.setGlobalPrefix\s*\(\s*["'`]([^"'`]*)["'`]/g;
// Django: path('users/', ...) / re_path(r'^users/$', ...)
const DJANGO_ROUTE = /\b(?:re_)?path\s*\(\s*r?["']([^"']+)["']/gi;
// Express/Koa mounts: app.use('/api', router) / app.use('/api', auth, router) /
// app.use(router) / app.use(router.routes()). Single-line only — that is the
// common shape and a missed mount degrades to "unresolved", never to a wrong path.
const JS_MOUNT = /\b([\w$]+)\s*\.use\s*\(\s*(?:["'`](\/[^"'`]*)["'`]\s*,\s*)?([^;\n]*?)\)\s*;?\s*$/gm;
// const router = Router() / express.Router() / new Router({ prefix: '/api' }) (koa).
// `new Hono()` / `new Elysia()` are NOT here: those are usually the app itself.
const JS_ROUTER_DECL = /\b(?:const|let|var)\s+([\w$]+)(?:\s*:\s*[\w$.<>]+)?\s*=\s*(?:new\s+)?(?:express\.)?Router\s*\(\s*(\{[^}]*\})?/g;
const JS_IMPORT_DEFAULT = /\bimport\s+(?:([\w$]+)|\*\s+as\s+([\w$]+))\s+from\s+["']([^"']+)["']|\b(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*["']([^"']+)["']\s*\)/g;
const JS_IMPORT_NAMED = /\bimport\s+\{([^}]*)\}\s+from\s+["']([^"']+)["']|\b(?:const|let|var)\s+\{([^}]*)\}\s*=\s*require\(\s*["']([^"']+)["']\s*\)/g;
// Next.js route handlers: export async function GET / export const POST = / export { GET, POST }
const NEXT_HANDLER = /\bexport\s+(?:async\s+)?(?:function|const|let)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|\bexport\s*(?:(?:const|let)\s*)?\{([^}]*)\}/g;
const HTTP_VERBS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);

// Documentation is not code: `app.get('/delete-everything')` in a README must
// never become a live target.
const DOC_FILE = /\.(md|mdx|markdown|txt|rst|adoc)$/i;

function normalizeMethod(m: string): string {
  const up = m.toUpperCase();
  // Flask's @app.route and Express's .all cover every verb → treat as ANY so
  // the GET-based probes still pick them up.
  if (up === 'ALL' || up === 'ROUTE') return 'ANY';
  return up;
}

/** Join a mount/controller prefix and a route path without doubling slashes. */
function joinPath(prefix: string, path: string): string {
  const joined = `/${prefix}/${path}`.replace(/\/+/g, '/');
  return joined.length > 1 ? joined.replace(/\/$/, '') : joined;
}

/** Flask converters: `<int:id>` / `<string:x>` / `<path:p>` / `<id>` → `{id}` (probe-able). */
function flaskToTemplate(path: string): string {
  return path.replace(/<(?:\w+(?:\([^)]*\))?:)?(\w+)>/g, '{$1}');
}

/** Resolve a relative import specifier to one of the scanned files, if present. */
function resolveModule(fromRel: string, spec: string, rels: Set<string>): string | undefined {
  if (!spec.startsWith('.')) return undefined;
  const dir = fromRel.split('/').slice(0, -1);
  for (const part of spec.split('/')) {
    if (part === '.' || part === '') continue;
    if (part === '..') dir.pop();
    else dir.push(part);
  }
  const base = dir.join('/').replace(/\.(m|c)?jsx?$/, '').replace(/\.tsx?$/, '');
  const candidates = [base, ...['.ts', '.tsx', '.js', '.mjs', '.cjs', '.jsx'].map((e) => base + e),
    ...['/index.ts', '/index.tsx', '/index.js', '/index.mjs'].map((e) => base + e)];
  return candidates.find((c) => rels.has(c));
}

interface Mount { onIdent: string; prefix: string; targetIdent?: string; targetModule?: string }

/** Every `x.use([prefix,] …, target)` in a file — the target is its last argument. */
function findMounts(content: string): Mount[] {
  const out: Mount[] = [];
  for (const m of content.matchAll(JS_MOUNT)) {
    const args = (m[3] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    const last = args[args.length - 1];
    if (!last) continue;
    const mount: Mount = { onIdent: m[1] ?? '', prefix: m[2] ?? '' };
    const req = last.match(/^require\(\s*["']([^"']+)["']\s*\)$/);
    const koa = last.match(/^([\w$]+)\.(?:routes|middleware|allowedMethods)\(\)$/);
    if (req) mount.targetModule = req[1];
    else if (koa) mount.targetIdent = koa[1];
    else if (/^[\w$]+$/.test(last)) mount.targetIdent = last;
    else continue; // a call/expression — nothing we can tie a router to
    out.push(mount);
  }
  return out;
}

/** The prefix a NestJS @Controller(...) argument declares, or null if unreadable. */
function nestControllerPrefix(rawArg: string): string | null {
  const arg = rawArg.trim();
  if (arg === '') return '';
  const str = arg.match(/^["'`]([^"'`]*)["'`]$/);
  if (str) return str[1] ?? '';
  if (arg.startsWith('{')) {
    const p = arg.match(/\bpath\s*:\s*["'`]([^"'`]*)["'`]/);
    if (p) return p[1] ?? '';
    // Options without `path` (e.g. host-only) mean no prefix; a computed path is unreadable.
    return /\bpath\s*:/.test(arg) ? null : '';
  }
  return null; // array / variable / anything computed
}

/** Extract HTTP endpoints declared across the project, any framework. */
export function collectEndpoints(files: Pick<ScanFile, 'rel' | 'content'>[]): Endpoint[] {
  const out: Endpoint[] = [];
  const seen = new Set<string>();
  const add = (method: string, path: string, where: string, unresolvedNote?: string) => {
    if (!path) return;
    // A path built from variables cannot be probed — reporting it is noise.
    if (path.includes('${') || path.includes('" +') || path.includes("' +")) return;
    const key = `${method} ${path}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(unresolvedNote ? { method, path, where, unresolved: true, note: unresolvedNote } : { method, path, where });
  };

  const code = files.filter((f) => !DOC_FILE.test(f.rel));
  const rels = new Set(code.map((f) => f.rel));

  // Pass 1 — routers and where they are mounted. A router imported from another
  // file is followed through its import so `app.use('/api', ordersRouter)` reaches
  // `router.get('/')` in routes/orders.ts.
  const mountsByFile = new Map<string, Mount[]>();
  const importsByFile = new Map<string, Map<string, string>>(); // ident → resolved module rel
  const routerDecls = new Map<string, string>(); // `${file}#${ident}` → prefix declared inline (koa)
  for (const f of code) {
    mountsByFile.set(f.rel, findMounts(f.content));
    const imports = new Map<string, string>();
    for (const m of f.content.matchAll(JS_IMPORT_DEFAULT)) {
      const ident = m[1] ?? m[2] ?? m[4];
      const spec = m[3] ?? m[5];
      const target = spec ? resolveModule(f.rel, spec, rels) : undefined;
      if (ident && target) imports.set(ident, target);
    }
    for (const m of f.content.matchAll(JS_IMPORT_NAMED)) {
      const spec = m[2] ?? m[4];
      const target = spec ? resolveModule(f.rel, spec, rels) : undefined;
      if (!target) continue;
      for (const name of (m[1] ?? m[3] ?? '').split(',')) {
        const ident = name.trim().split(/\s+as\s+/).pop()?.trim();
        if (ident) imports.set(ident, target);
      }
    }
    importsByFile.set(f.rel, imports);
    for (const m of f.content.matchAll(JS_ROUTER_DECL)) {
      const inline = m[2]?.match(/\bprefix\s*:\s*["'`]([^"'`]*)["'`]/)?.[1] ?? '';
      routerDecls.set(`${f.rel}#${m[1]}`, inline);
    }
  }

  // Prefixes at which router `ident` (declared in `file`) is reachable, following
  // nested mounts a few levels up. null = not mounted anywhere we can see, or a
  // parent in the chain is not — either way the prefix is unknown.
  const prefixesOf = (file: string, ident: string, depth: number): string[] | null => {
    if (depth > 4) return null;
    const found: string[] = [];
    let mounted = false;
    for (const [mFile, mounts] of mountsByFile) {
      for (const mt of mounts) {
        const hits = (mFile === file && mt.targetIdent === ident)
          || (mt.targetIdent !== undefined && importsByFile.get(mFile)?.get(mt.targetIdent) === file)
          || (mt.targetModule !== undefined && resolveModule(mFile, mt.targetModule, rels) === file);
        if (!hits) continue;
        mounted = true;
        // Whatever the receiver is mounted at applies on top (router.use inside a router).
        const parents = routerDecls.has(`${mFile}#${mt.onIdent}`) ? prefixesOf(mFile, mt.onIdent, depth + 1) : [''];
        if (parents === null) return null;
        for (const parent of parents) found.push(joinPath(parent, mt.prefix));
      }
    }
    return mounted ? found : null;
  };

  // NestJS global prefix (app.setGlobalPrefix('api')) applies to every controller.
  let nestGlobal = '';
  for (const f of code) {
    const g = [...f.content.matchAll(NEST_GLOBAL_PREFIX)];
    if (g.length === 1) nestGlobal = g[0]?.[1] ?? '';
  }

  for (const f of code) {
    // Next.js App Router: app/**/route.ts — the file path is the endpoint, the
    // exported handler names are the methods (a POST-only route must not be GET-probed).
    if (/(^|\/)app\/.*\/route\.(t|j)sx?$/.test(f.rel)) {
      const p = '/' + f.rel.replace(/^.*?app\//, '').replace(/\/route\.(t|j)sx?$/, '');
      const clean = p.replace(/\/\((?:[^)]+)\)/g, ''); // strip Next route groups
      const methods = new Set<string>();
      for (const m of f.content.matchAll(NEXT_HANDLER)) {
        if (m[1]) methods.add(m[1]);
        for (const name of (m[2] ?? '').split(',')) {
          const ident = name.trim().split(/\s+as\s+/).pop()?.trim() ?? '';
          if (HTTP_VERBS.has(ident)) methods.add(ident);
        }
      }
      if (methods.size === 0) add('ANY', clean, f.rel); // re-exported / not parseable → as before
      for (const method of methods) add(method, clean, f.rel);
      continue;
    }
    // Next.js Pages API: strip extension first, then a trailing /index.
    if (/(^|\/)pages\/api\/.+\.(t|j)sx?$/.test(f.rel)) {
      const p = '/' + f.rel.replace(/^.*?pages\//, '').replace(/\.(t|j)sx?$/, '').replace(/\/index$/, '');
      add('ANY', p, f.rel);
      continue;
    }
    // Python decorators (`@app.get("/x/<int:id>")`) also look like JS calls to
    // JS_ROUTE; only PY_ROUTE knows how to template their converters.
    const isPython = /\.py$/i.test(f.rel);
    for (const m of isPython ? [] : f.content.matchAll(JS_ROUTE)) {
      const method = normalizeMethod(m[2] ?? 'any');
      const path = m[3] ?? '';
      const ident = m[1];
      const inline = ident !== undefined ? routerDecls.get(`${f.rel}#${ident}`) : undefined;
      // Routes on a Router() live under its mount point; `app.get` (no Router
      // declaration) is top-level, as before.
      if (ident !== undefined && inline !== undefined) {
        const prefixes = prefixesOf(f.rel, ident, 0);
        if (prefixes === null) {
          add(method, joinPath(inline, path), f.rel, `router "${ident}" (${f.rel}) is not mounted anywhere in the scanned code — its URL prefix is unknown`);
        } else {
          for (const prefix of prefixes) add(method, joinPath(joinPath(prefix, inline), path), f.rel);
        }
        continue;
      }
      add(method, path, f.rel);
    }
    for (const m of f.content.matchAll(PY_ROUTE)) add(normalizeMethod(m[1] ?? 'any'), flaskToTemplate(m[2] ?? ''), f.rel);

    // NestJS: walk decorators in source order so each @Get sits under the nearest
    // preceding @Controller prefix.
    const events: Array<{ at: number; ctrl?: string | null; method?: string; path?: string }> = [];
    for (const m of f.content.matchAll(NEST_CONTROLLER)) events.push({ at: m.index ?? 0, ctrl: nestControllerPrefix(m[1] ?? '') });
    for (const m of f.content.matchAll(NEST_ROUTE)) events.push({ at: m.index ?? 0, method: m[1] ?? 'any', path: m[2] ?? '' });
    events.sort((x, y) => x.at - y.at);
    let ctrl: string | null = '';
    for (const ev of events) {
      if (ev.ctrl !== undefined) { ctrl = ev.ctrl; continue; }
      const full = joinPath(joinPath(nestGlobal, ctrl ?? ''), ev.path ?? '');
      add(normalizeMethod(ev.method ?? 'any'), full, f.rel, ctrl === null
        ? `@Controller(...) argument in ${f.rel} could not be read — its URL prefix is unknown`
        : undefined);
    }

    if (/(^|\/)urls?\.py$/.test(f.rel) || /urlpatterns/.test(f.content)) {
      for (const m of f.content.matchAll(DJANGO_ROUTE)) add('ANY', '/' + (m[1] ?? '').replace(/^\^/, '').replace(/^\//, '').replace(/\$$/, ''), f.rel);
    }
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
