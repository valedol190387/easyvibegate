// WP http — live-probe regressions: "unknown ≠ clean" for every HTTP-driven
// check (endpoint probe, IDOR, exposed files, Supabase, Firebase) plus the
// endpoint inventory and backend discovery that feed them. Offline only: the
// network is always replaced with setRequestImpl().
import assert from 'node:assert/strict';
import { check, fixture, ids, ok, ALL_HEADERS, runCli, state } from './_harness.mjs';
import { classifyBody, setRequestImpl } from '../dist/engine/net/http.js';
import { discoverSupabase, probeSupabase } from '../dist/engine/checkers/backend/supabase.js';
import { discoverFirebase, probeFirebase } from '../dist/engine/checkers/backend/firebase.js';
import { probeEndpointsUnauth } from '../dist/engine/checkers/live/endpoint-probe.js';
import { checkLiveSite } from '../dist/engine/checkers/live/http-checks.js';
import { idorDifferential } from '../dist/engine/checkers/live/idor.js';
import { collectEndpoints, concretePath } from '../dist/engine/endpoints.js';

console.log('\nWP http');
void fixture; void ids; void runCli; void state; // shared harness surface, not all needed here

const ANON = 'eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.sig1234567890123456';
const SB_CREDS = { url: 'https://p.supabase.co', anonKey: ANON, keyKind: 'jwt-anon' };
const FB_CREDS = { projectId: 'audit-project' };
const truncated = (status, body, headers = {}) => ({ ...ok(status, body, headers), truncated: true });
const routeTo = (routes) => setRequestImpl(async (url, init) => {
  const path = new URL(url).pathname;
  for (const [match, res] of routes) if (path === match || (match instanceof RegExp && match.test(path))) return typeof res === 'function' ? res(url, init) : res;
  return ok(404, '');
});

// ───────────────────────── F03 B01: Supabase discovery pairs URL+key by provenance

check('F03/B01: URL from one file + key from another is returned as ambiguous, naming both', () => {
  const creds = discoverSupabase([
    { rel: '.env', content: 'NEXT_PUBLIC_SUPABASE_URL=https://aaaaaaaaaaaaaaaaaaaa.supabase.co\n' },
    { rel: 'src/lib/db.ts', content: `const key = "${ANON}";` },
  ]);
  assert.ok(creds, 'a pair must still be offered');
  assert.strictEqual(creds.ambiguous, true);
  assert.ok(creds.source.includes('.env') && creds.source.includes('src/lib/db.ts'), creds.source);
});

check('F03/B01 negative: a file holding both URL and key wins over a cross-file mix', () => {
  const creds = discoverSupabase([
    { rel: 'src/config.ts', content: 'const SUPABASE_URL = "https://cccccccccccccccccccc.supabase.co"' },
    { rel: '.env.local', content: `NEXT_PUBLIC_SUPABASE_URL=https://bbbbbbbbbbbbbbbbbbbb.supabase.co\nNEXT_PUBLIC_SUPABASE_ANON_KEY=${ANON}\n` },
  ]);
  assert.strictEqual(creds.url, 'https://bbbbbbbbbbbbbbbbbbbb.supabase.co', 'the same-file URL must be used');
  assert.strictEqual(creds.source, '.env.local');
  assert.strictEqual(creds.ambiguous, undefined);
});

check('F03/B01 negative: docs and .env.example never contribute a URL or key', () => {
  assert.strictEqual(discoverSupabase([
    { rel: 'README.md', content: `SUPABASE_URL=https://dddddddddddddddddddd.supabase.co\nSUPABASE_ANON_KEY=${ANON}` },
    { rel: '.env.example', content: `SUPABASE_URL=https://dddddddddddddddddddd.supabase.co\nSUPABASE_ANON_KEY=${ANON}` },
  ]), null);
});

// ───────────────────────── F03 B02: Firebase hosts must belong to the project by hostname

check('F03/B02: a databaseURL that only mentions the project in its query string is dropped', () => {
  const creds = discoverFirebase([{ rel: 'src/fb.ts', content: 'projectId: "audit-project",\ndatabaseURL: "https://unrelated.invalid/?project=audit-project"' }]);
  assert.strictEqual(creds.projectId, 'audit-project');
  assert.strictEqual(creds.databaseURL, undefined);
  const lookalike = discoverFirebase([{ rel: 'src/fb.ts', content: 'projectId: "audit-project",\ndatabaseURL: "https://audit-project.firebaseio.com.evil.example",\nstorageBucket: "evil-audit-project.appspot.com"' }]);
  assert.strictEqual(lookalike.databaseURL, undefined, 'a hostname that merely starts with the project host is not ours');
  assert.strictEqual(lookalike.storageBucket, undefined, 'a bucket that merely contains the id is not ours');
});

check('F03/B02 negative: the real firebaseio / regional / bucket forms are kept (origin only)', () => {
  const regional = discoverFirebase([{ rel: 'src/fb.ts', content: 'projectId: "audit-project",\ndatabaseURL: "https://audit-project-default-rtdb.europe-west1.firebasedatabase.app/",\nstorageBucket: "audit-project.appspot.com"' }]);
  assert.strictEqual(regional.databaseURL, 'https://audit-project-default-rtdb.europe-west1.firebasedatabase.app');
  assert.strictEqual(regional.storageBucket, 'audit-project.appspot.com');
  const legacy = discoverFirebase([{ rel: 'src/fb.ts', content: 'projectId: "audit-project",\ndatabaseURL: "https://audit-project.firebaseio.com/?x=1",\nstorageBucket: "gs://audit-project.firebasestorage.app/"' }]);
  assert.strictEqual(legacy.databaseURL, 'https://audit-project.firebaseio.com');
  assert.strictEqual(legacy.storageBucket, 'audit-project.firebasestorage.app');
});

// ───────────────────────── F16 / F21: endpoint inventory

check('F16/R01: Express mount prefix is applied, same file and across an import', () => {
  const eps = collectEndpoints([
    { rel: 'src/server.ts', content: "import express from 'express';\nimport ordersRouter from './routes/orders';\nconst app = express();\nconst router = express.Router();\nrouter.get('/health', h);\napp.use('/internal', router);\napp.use('/api/orders', ordersRouter);\napp.get('/ping', h);\n" },
    { rel: 'src/routes/orders.ts', content: "import { Router } from 'express';\nconst router = Router();\nrouter.get('/:id', h);\nexport default router;\n" },
  ]);
  const paths = eps.map((e) => `${e.method} ${e.path}`);
  assert.ok(paths.includes('GET /internal/health'), paths.join(','));
  assert.ok(paths.includes('GET /api/orders/:id'), paths.join(','));
  assert.ok(paths.includes('GET /ping'), 'app.get stays top-level');
  assert.ok(!paths.includes('GET /health') && !paths.includes('GET /:id'), 'unprefixed router paths must not be probed');
  assert.ok(eps.every((e) => !e.unresolved), 'every router here is mounted');
});

check('F16/R01 negative: a router that is never mounted is kept but marked unresolved', () => {
  const eps = collectEndpoints([{ rel: 'src/routes/lost.ts', content: "const router = Router();\nrouter.get('/lost', h);\nexport default router;\n" }]);
  const lost = eps.find((e) => e.path === '/lost');
  assert.ok(lost, 'the route is still inventoried');
  assert.strictEqual(lost.unresolved, true);
  assert.ok(/not mounted/.test(lost.note ?? ''), lost.note);
});

check('F16/R02: NestJS @Controller prefix (and global prefix) is applied', () => {
  const eps = collectEndpoints([
    { rel: 'src/orders.controller.ts', content: "@Controller('api/orders')\nexport class OrdersController {\n  @Get(':id')\n  find() {}\n  @Post()\n  create() {}\n}\n" },
    { rel: 'src/main.ts', content: "app.setGlobalPrefix('v1');\n" },
  ]);
  const paths = eps.map((e) => `${e.method} ${e.path}`);
  assert.ok(paths.includes('GET /v1/api/orders/:id'), paths.join(','));
  assert.ok(paths.includes('POST /v1/api/orders'), paths.join(','));
  assert.ok(!paths.includes('GET /:id'), 'the bare method path must not be probed');
});

check('F16/R02 negative: a bare @Get with no @Controller is unchanged; an unreadable @Controller arg is unresolved', () => {
  const plain = collectEndpoints([{ rel: 'src/a.controller.ts', content: "@Get('users')\nfindAll() {}\n" }]);
  assert.ok(plain.some((e) => e.path === '/users' && !e.unresolved));
  const computed = collectEndpoints([{ rel: 'src/b.controller.ts', content: "@Controller(PREFIX)\nexport class B {\n  @Get('items')\n  list() {}\n}\n" }]);
  const items = computed.find((e) => e.path.endsWith('/items'));
  assert.ok(items && items.unresolved === true, JSON.stringify(computed));
});

check('F16/R03: Flask converters become {name} templates and concretePath still resolves them', () => {
  const eps = collectEndpoints([{ rel: 'app.py', content: '@app.route("/orders/<int:id>")\ndef a(): ...\n@app.get("/files/<path:p>")\ndef b(): ...\n@app.get("/u/<string:name>/<uid>")\ndef c(): ...' }]);
  const paths = eps.map((e) => e.path);
  assert.ok(paths.includes('/orders/{id}'), paths.join(','));
  assert.ok(paths.includes('/files/{p}'), paths.join(','));
  assert.ok(paths.includes('/u/{name}/{uid}'), paths.join(','));
  assert.ok(!paths.some((p) => p.includes('<') || p.includes('int1')), 'no converter fragments may leak into a URL');
  assert.strictEqual(concretePath('/orders/{id}'), '/orders/1');
});

check('F16/R05: a POST-only Next.js route handler is POST, never ANY/GET', () => {
  const eps = collectEndpoints([
    { rel: 'app/api/orders/route.ts', content: 'export async function POST(req: Request) { return new Response("ok"); }\n' },
    { rel: 'app/api/items/route.ts', content: 'export async function GET() {}\nexport const DELETE = handler;\n' },
    { rel: 'app/api/legacy/route.ts', content: "export { handler as default } from './impl';\n" },
  ]);
  const of = (p) => eps.filter((e) => e.path === p).map((e) => e.method).sort();
  assert.deepStrictEqual(of('/api/orders'), ['POST']);
  assert.deepStrictEqual(of('/api/items'), ['DELETE', 'GET']);
  assert.deepStrictEqual(of('/api/legacy'), ['ANY'], 'no readable handler names → as before');
});

check('F21/R04: routes in documentation files are not inventoried; the same code in src is', () => {
  const docs = collectEndpoints([
    { rel: 'README.md', content: "app.get('/delete-everything', handler)" },
    { rel: 'docs/api.mdx', content: "app.get('/docs-only', handler)" },
    { rel: 'NOTES.txt', content: "app.get('/notes-only', handler)" },
  ]);
  assert.deepStrictEqual(docs, []);
  const code = collectEndpoints([{ rel: 'src/x.ts', content: "app.get('/delete-everything', handler)" }]);
  assert.ok(code.some((e) => e.path === '/delete-everything'));
});

// ───────────────────────── F16 N02/N03 + F18 N01: endpoint probe classifies every response

await (async () => {
  routeTo([['/api/items', ok(200, '[]')], ['/api/missing', ok(404, 'Not Found')]]);
  const r = await probeEndpointsUnauth('https://app.example', [
    { method: 'GET', path: '/api/items', where: 'x' },
    { method: 'GET', path: '/api/missing/:id', where: 'x' },
  ], 0);
  setRequestImpl(null);
  check('F16/N02: a 404 for a guessed id is not a verified endpoint → partial, named in the note', () => {
    assert.strictEqual(r.run.status, 'partial', `got ${r.run.status} (${r.run.note})`);
    assert.ok(/\/api\/missing\/1 \(HTTP 404\)/.test(r.run.note ?? ''), r.run.note);
    assert.strictEqual(r.findings.length, 0);
  });
})();

await (async () => {
  setRequestImpl(async () => ok(200, '<!doctype html><html><body>app</body></html>', { 'content-type': 'text/html' }));
  const r = await probeEndpointsUnauth('https://app.example', [{ method: 'GET', path: '/api/things', where: 'x' }], 0);
  setRequestImpl(null);
  check('F16/N03: an HTML SPA catch-all where JSON was expected is unknown, never completed', () => {
    assert.notStrictEqual(r.run.status, 'completed', `got ${r.run.status}`);
    assert.ok(/HTML/.test(r.run.note ?? ''), r.run.note);
    assert.strictEqual(r.findings.length, 0);
  });
})();

await (async () => {
  setRequestImpl(async () => truncated(200, '[{"id":1},{"id":2'));
  const r = await probeEndpointsUnauth('https://app.example', [{ method: 'GET', path: '/api/things', where: 'x' }], 0);
  setRequestImpl(null);
  check('F18/N01: a truncated JSON body is unknown — no finding, not completed', () => {
    assert.notStrictEqual(r.run.status, 'completed', `got ${r.run.status}`);
    assert.ok(/truncated/.test(r.run.note ?? ''), r.run.note);
    assert.strictEqual(r.findings.length, 0);
  });
})();

await (async () => {
  const hit = [];
  setRequestImpl(async (url) => { hit.push(new URL(url).pathname); return ok(200, '[]'); });
  const r = await probeEndpointsUnauth('https://app.example', [
    { method: 'GET', path: '/items', where: 'x', unresolved: true, note: 'router "r" is not mounted' },
    { method: 'GET', path: '/health', where: 'x' },
  ], 0);
  setRequestImpl(null);
  check('F16: an unresolved route is not probed at a guessed URL — recorded as unverified instead', () => {
    assert.deepStrictEqual(hit, ['/health']);
    assert.strictEqual(r.run.status, 'partial', `got ${r.run.status}`);
    assert.ok(/\/items \(router/.test(r.run.note ?? ''), r.run.note);
  });
})();

await (async () => {
  routeTo([['/api/public', ok(200, '[{"id":1,"email":"a@b.c"}]', { 'content-type': 'application/json' })], ['/api/private', ok(401, '{"error":"unauthorized"}')]]);
  const r = await probeEndpointsUnauth('https://app.example', [
    { method: 'GET', path: '/api/public', where: 'x' },
    { method: 'GET', path: '/api/private', where: 'x' },
  ], 0);
  setRequestImpl(null);
  check('F16/F18 negative: real JSON data still yields endpoint_no_auth; a 401 is a verified, clean endpoint', () => {
    assert.strictEqual(r.run.status, 'completed', `got ${r.run.status} (${r.run.note})`);
    assert.deepStrictEqual(r.findings.map((f) => f.endpoint), ['GET /api/public']);
    assert.strictEqual(r.findings[0].id, 'endpoint_no_auth');
  });
})();

// ───────────────────────── F17 N04: IDOR classifies every pair

const byToken = (aRes, bRes) => (_url, init) => (String(init?.headers?.Authorization ?? '').includes('tokA') ? aRes : bRes);

await (async () => {
  routeTo([[/^\/known\//, byToken(ok(200, '{"id":1,"owner":"A"}'), ok(403, '{"error":"forbidden"}'))], [/^\/missing\//, ok(404, '{"error":"not found"}')]]);
  const r = await idorDifferential('https://app.example', [
    { method: 'GET', path: '/known/:id', where: 'x' },
    { method: 'GET', path: '/missing/:id', where: 'x' },
  ], 'tokA', 'tokB', 0);
  setRequestImpl(null);
  check('F17/N04: one protected pair does not hide a pair that answered 404 to both → partial', () => {
    assert.strictEqual(r.run.status, 'partial', `got ${r.run.status} (${r.run.note})`);
    assert.ok(/\/missing\/1 \(guessed id not found/.test(r.run.note ?? ''), r.run.note);
    assert.strictEqual(r.findings.length, 0);
  });
})();

await (async () => {
  routeTo([[/^\/known\//, byToken(ok(200, '{"id":1,"owner":"A"}'), ok(403, '{"error":"forbidden"}'))]]);
  const clean = await idorDifferential('https://app.example', [{ method: 'GET', path: '/known/:id', where: 'x' }], 'tokA', 'tokB', 0);
  routeTo([[/^\/leaky\//, ok(200, '{"id":1,"ssn":"x"}')]]);
  const leak = await idorDifferential('https://app.example', [{ method: 'GET', path: '/leaky/:id', where: 'x' }], 'tokA', 'tokB', 0);
  setRequestImpl(null);
  check('F17 negative: all pairs verified → completed; both accounts reading data still reports idor_cross_user', () => {
    assert.strictEqual(clean.run.status, 'completed', `got ${clean.run.status} (${clean.run.note})`);
    assert.strictEqual(clean.findings.length, 0);
    assert.strictEqual(leak.run.status, 'completed', `got ${leak.run.status} (${leak.run.note})`);
    assert.deepStrictEqual(leak.findings.map((f) => f.id), ['idor_cross_user']);
  });
})();

await (async () => {
  routeTo([[/^\/t\//, byToken(ok(200, '{"id":1}'), truncated(200, '{"id":1,"blob":"'))]]);
  const r = await idorDifferential('https://app.example', [{ method: 'GET', path: '/t/:id', where: 'x' }], 'tokA', 'tokB', 0);
  setRequestImpl(null);
  check('F17/F18: a truncated side of a pair is unknown, not "only one account read data"', () => {
    assert.notStrictEqual(r.run.status, 'completed', `got ${r.run.status}`);
    assert.strictEqual(r.findings.length, 0);
  });
})();

// ───────────────────────── F18 N07/N10: Firebase responses go through the same classifier

const fbRoutes = (rtdb, firestore, storage) => setRequestImpl(async (url) => {
  if (url.includes('firebaseio.com')) return rtdb;
  if (url.includes('firestore.googleapis.com')) return firestore;
  return storage;
});

await (async () => {
  fbRoutes(ok(200, '<!doctype html><html><body>maintenance</body></html>', { 'content-type': 'text/html' }), ok(403, '{"error":{"code":403}}'), ok(403, '{"error":{"code":403}}'));
  const html = await probeFirebase({ creds: FB_CREDS, rateLimitMs: 0 });
  fbRoutes(ok(401, '{"error":"Permission denied"}'), truncated(200, '{"documents":[{"name":"x"'), ok(403, '{"error":{"code":403}}'));
  const cut = await probeFirebase({ creds: FB_CREDS, rateLimitMs: 0 });
  setRequestImpl(null);
  check('F18/N07: HTML instead of JSON from RTDB is an unverified sub-check → partial, named', () => {
    assert.strictEqual(html.run.status, 'partial', `got ${html.run.status} (${html.run.note})`);
    assert.ok(/RTDB \(HTML/.test(html.run.note ?? ''), html.run.note);
    assert.strictEqual(html.findings.length, 0);
  });
  check('F18/N10: a truncated Firestore body is unverified → partial, no finding', () => {
    assert.strictEqual(cut.run.status, 'partial', `got ${cut.run.status} (${cut.run.note})`);
    assert.ok(/firestore\/users \(body truncated/.test(cut.run.note ?? ''), cut.run.note);
    assert.strictEqual(cut.findings.length, 0);
  });
})();

await (async () => {
  fbRoutes(ok(401, '{"error":"Permission denied"}'), ok(403, '{"error":{"code":403}}'), ok(403, '{"error":{"code":403}}'));
  const locked = await probeFirebase({ creds: FB_CREDS, rateLimitMs: 0 });
  fbRoutes(ok(200, '{"users":true,"orders":true}'), ok(200, '{"documents":[{"name":"projects/x/documents/users/1"}]}'), ok(200, '{"items":[{"name":"a.png"}]}'));
  const open = await probeFirebase({ creds: FB_CREDS, rateLimitMs: 0 });
  setRequestImpl(null);
  check('F18 negative: locked rules (401/403 everywhere) are completed and clean', () => {
    assert.strictEqual(locked.run.status, 'completed', `got ${locked.run.status} (${locked.run.note})`);
    assert.strictEqual(locked.findings.length, 0);
  });
  check('F18 negative: real JSON data still yields the three Firebase findings', () => {
    assert.strictEqual(open.run.status, 'completed', `got ${open.run.status} (${open.run.note})`);
    assert.deepStrictEqual(open.findings.map((f) => f.id).sort(), ['firebase_firestore_open', 'firebase_rtdb_open', 'firebase_storage_open']);
  });
})();

// ───────────────────────── F18 N11 + F19 N06: exposed files (redirects, truncation)

const site = (files) => routeTo([['/', ok(200, '<html>', ALL_HEADERS)], ...files]);

await (async () => {
  site([['/backup.sql', truncated(200, 'x'.repeat(200))]]);
  const noSig = await checkLiveSite('https://app.example');
  site([['/backup.sql', truncated(200, '-- dump\nCREATE TABLE users (id int);\n' + 'x'.repeat(200))]]);
  const withSig = await checkLiveSite('https://app.example');
  setRequestImpl(null);
  check('F18/N11: a truncated backup.sql without a signature is unverified → partial, named', () => {
    assert.strictEqual(noSig.run.status, 'partial', `got ${noSig.run.status} (${noSig.run.note})`);
    assert.ok(/\/backup\.sql \(body truncated/.test(noSig.run.note ?? ''), noSig.run.note);
    assert.ok(!noSig.findings.some((f) => f.id === 'exposed_backup_sql'));
  });
  check('F18/N11 negative: a truncated body that does carry the signature is still a leak', () => {
    assert.ok(withSig.findings.some((f) => f.id === 'exposed_backup_sql'), withSig.findings.map((f) => f.id).join(','));
  });
})();

await (async () => {
  site([['/.env', ok(302, '', { location: '/files/.env' })], ['/files/.env', ok(200, 'DATABASE_URL=postgres://u:p@h/db\n')]]);
  const followed = await checkLiveSite('https://app.example');
  site([['/.env', ok(302, '', { location: 'https://cdn.other.example/.env' })]]);
  const offOrigin = await checkLiveSite('https://app.example');
  site([['/.env', ok(401, 'auth required')]]);
  const denied = await checkLiveSite('https://app.example');
  setRequestImpl(null);
  check('F19/N06: a same-origin redirect on /.env is followed and the served file is reported', () => {
    assert.ok(followed.findings.some((f) => f.id === 'exposed__env'), followed.findings.map((f) => f.id).join(','));
  });
  check('F19/N06: a redirect off the origin is never evidence of absence → partial, named', () => {
    assert.strictEqual(offOrigin.run.status, 'partial', `got ${offOrigin.run.status} (${offOrigin.run.note})`);
    assert.ok(/\/\.env \(redirect left the target origin/.test(offOrigin.run.note ?? ''), offOrigin.run.note);
    assert.ok(!offOrigin.findings.some((f) => f.id === 'exposed__env'));
  });
  check('F19 negative: a proper 401 on /.env (everything else 404) is completed and clean', () => {
    assert.strictEqual(denied.run.status, 'completed', `got ${denied.run.status} (${denied.run.note})`);
    assert.ok(!denied.findings.some((f) => f.id.startsWith('exposed_')));
  });
})();

// ───────────────────────── F19 N09 + F20 N08: Supabase enumeration and storage

const sb = (rest, storage, head = ok(200, '', { 'content-range': '0-0/0' })) => setRequestImpl(async (url, init) => {
  if (url.endsWith('/rest/v1/')) return rest;
  if (url.includes('/storage/v1/bucket')) return storage;
  return init?.method === 'HEAD' ? head : ok(404, '');
});
const EMPTY_OPENAPI = JSON.stringify({ swagger: '2.0', definitions: {}, paths: {} });

await (async () => {
  sb(ok(200, '{"error":"upstream problem"}'), ok(403, '{"message":"forbidden"}'));
  const envelope = await probeSupabase({ creds: SB_CREDS, rateLimitMs: 0 });
  sb(ok(200, '{"status":"ok","version":"1.2.3"}'), ok(403, ''));
  const notOpenApi = await probeSupabase({ creds: SB_CREDS, rateLimitMs: 0 });
  sb(ok(200, '<!doctype html><html>login</html>', { 'content-type': 'text/html' }), ok(403, ''));
  const html = await probeSupabase({ creds: SB_CREDS, rateLimitMs: 0 });
  setRequestImpl(null);
  check('F20/N08: a 200 error envelope from /rest/v1/ is a failed enumeration, never "zero tables"', () => {
    assert.strictEqual(envelope.run.status, 'failed', `got ${envelope.run.status} (${envelope.run.note})`);
    assert.ok(/enumerate/.test(envelope.run.note ?? ''), envelope.run.note);
    assert.strictEqual(envelope.findings.length, 0);
  });
  check('F20/N08: JSON without an OpenAPI shape (no definitions/schemas/paths) also fails enumeration', () => {
    assert.strictEqual(notOpenApi.run.status, 'failed', `got ${notOpenApi.run.status} (${notOpenApi.run.note})`);
    assert.ok(/OpenAPI/.test(notOpenApi.run.note ?? ''), notOpenApi.run.note);
    assert.strictEqual(html.run.status, 'failed', `got ${html.run.status} (${html.run.note})`);
  });
})();

await (async () => {
  sb(ok(200, EMPTY_OPENAPI), ok(403, '{"message":"forbidden"}'));
  const zero = await probeSupabase({ creds: SB_CREDS, rateLimitMs: 0 });
  sb(ok(200, JSON.stringify({ openapi: '3.0.0', components: { schemas: { profiles: {} } }, paths: { '/profiles': {} } })), ok(200, '[]'), ok(200, '', { 'content-range': '0-0/42' }));
  const open = await probeSupabase({ creds: SB_CREDS, rateLimitMs: 0 });
  setRequestImpl(null);
  check('F20 negative: a valid OpenAPI document with zero tables is completed with zero exposure', () => {
    assert.strictEqual(zero.run.status, 'completed', `got ${zero.run.status} (${zero.run.note})`);
    assert.strictEqual(zero.findings.length, 0);
  });
  check('F20 negative: OpenAPI 3 components.schemas still enumerates and reports a readable table', () => {
    assert.strictEqual(open.run.status, 'completed', `got ${open.run.status} (${open.run.note})`);
    assert.deepStrictEqual(open.findings.map((f) => f.id), ['supabase_anon_read']);
    assert.strictEqual(open.findings[0].severity, 'critical');
  });
})();

await (async () => {
  // One (empty) table so the table sub-check is verified and only storage is lost → partial.
  const ONE_TABLE = JSON.stringify({ swagger: '2.0', definitions: { posts: {} }, paths: {} });
  sb(ok(200, ONE_TABLE), ok(302, '', { location: 'https://p.supabase.co/login' }));
  const redirected = await probeSupabase({ creds: SB_CREDS, rateLimitMs: 0 });
  sb(ok(200, ONE_TABLE), truncated(200, '[{"name":"avatars","public":true'));
  const cut = await probeSupabase({ creds: SB_CREDS, rateLimitMs: 0 });
  sb(ok(200, EMPTY_OPENAPI), ok(200, '[{"name":"avatars","public":true}]'));
  const listable = await probeSupabase({ creds: SB_CREDS, rateLimitMs: 0 });
  setRequestImpl(null);
  check('F19/N09: a 302 from storage is an unverified sub-check → partial, named', () => {
    assert.strictEqual(redirected.run.status, 'partial', `got ${redirected.run.status} (${redirected.run.note})`);
    assert.ok(/storage \(HTTP 302/.test(redirected.run.note ?? ''), redirected.run.note);
  });
  check('F18: a truncated bucket listing is unverified, not "no buckets"', () => {
    assert.strictEqual(cut.run.status, 'partial', `got ${cut.run.status} (${cut.run.note})`);
    assert.strictEqual(cut.findings.length, 0);
  });
  check('F19/F18 negative: a real bucket listing is still reported as critical', () => {
    assert.strictEqual(listable.run.status, 'completed', `got ${listable.run.status} (${listable.run.note})`);
    assert.deepStrictEqual(listable.findings.map((f) => `${f.id}:${f.severity}`), ['supabase_bucket_listing:critical']);
  });
})();

// ───────────────────────── F18: the shared classifier itself

check('F18: classifyBody is one rule for every probe', () => {
  const kind = (res, expect = 'json') => classifyBody(res, expect).kind;
  assert.strictEqual(kind({ error: 'ETIMEDOUT' }), 'unknown');
  assert.strictEqual(kind(ok(503, 'down')), 'unknown');
  assert.strictEqual(kind(ok(302, '', { location: '/x' })), 'unknown');
  assert.strictEqual(kind(truncated(200, '[{"a":1')), 'unknown');
  assert.strictEqual(kind(truncated(200, 'raw bytes'), 'any'), 'unknown');
  assert.strictEqual(kind(ok(200, '<html></html>')), 'unknown');
  assert.strictEqual(kind(ok(200, 'not json')), 'unknown');
  assert.strictEqual(kind(ok(200, '{"error":"x"}')), 'unknown');
  assert.strictEqual(kind(ok(401, '')), 'denied');
  assert.strictEqual(kind(ok(403, '{}')), 'denied');
  assert.strictEqual(kind(ok(404, '')), 'absent');
  assert.strictEqual(kind(ok(200, '[]')), 'empty');
  assert.strictEqual(kind(ok(200, '{}')), 'empty');
  assert.strictEqual(kind(ok(204, '')), 'empty');
  assert.strictEqual(kind(ok(200, '[{"id":1}]')), 'data');
  assert.strictEqual(kind(ok(200, 'A=1\n'), 'any'), 'data');
  assert.strictEqual(kind(ok(200, ''), 'any'), 'empty');
});
