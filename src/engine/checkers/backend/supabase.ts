import type { CheckRun, Finding, ScanFile, Severity } from '../../types.js';
import { decodeJwtPayload } from '../../util/text.js';
import { classifyBody, isErr, request, sleep } from '../../net/http.js';

export interface SupabaseCreds {
  url: string;
  anonKey: string;
  /** How the key was recognized — used to keep messaging honest. */
  keyKind: 'jwt-anon' | 'publishable';
  /** Where the URL/key were found (for display). */
  source?: string;
  /**
   * URL and key did not come from the same file, so they may belong to
   * different environments. `source` names both files; callers should show it
   * before probing rather than present the pair as one discovered config.
   */
  ambiguous?: true;
}

const URL_ASSIGN = /(?:NEXT_PUBLIC_|VITE_|PUBLIC_)?SUPABASE(?:_PUBLIC)?_URL\s*[:=]\s*["'`]?(https?:\/\/[^"'`\s]+)/i;
const ANON_ASSIGN = /(?:NEXT_PUBLIC_|VITE_|PUBLIC_)?SUPABASE_(?:ANON|PUBLISHABLE)_KEY\s*[:=]\s*["'`]?([A-Za-z0-9._-]{20,})/i;
// Docs and templates hold example values, not the running config.
const NOT_CONFIG = /\.(md|mdx|txt|rst)$|\.(example|sample|template|dist)$/i;
// Next.js load order for a production build — the most specific file wins.
const ENV_ORDER = ['.env.production.local', '.env.local', '.env.production', '.env'];

export function classifyKey(key: string): 'jwt-anon' | 'jwt-authenticated' | 'jwt-service' | 'publishable' | 'secret' | 'unknown' {
  if (key.startsWith('sb_publishable_')) return 'publishable';
  if (key.startsWith('sb_secret_')) return 'secret';
  const payload = decodeJwtPayload(key);
  const role = payload?.['role'];
  if (role === 'anon') return 'jwt-anon';
  if (role === 'authenticated') return 'jwt-authenticated';
  if (role === 'service_role') return 'jwt-service';
  return 'unknown';
}

const BARE_URL = /https:\/\/[a-z0-9]{16,}\.supabase\.co/;
const BARE_PUBLISHABLE = /\bsb_publishable_[A-Za-z0-9_-]{10,}\b/;
const BARE_JWT = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

function isPublicKey(key: string): boolean {
  const kind = classifyKey(key);
  return kind === 'jwt-anon' || kind === 'publishable';
}

/**
 * The URL and *public* key ONE file declares — an explicit assignment first, a
 * bare literal as fallback. Never an authenticated/service key.
 */
function credsInFile(content: string): { url?: string; key?: string } {
  const url = content.match(URL_ASSIGN)?.[1] ?? content.match(BARE_URL)?.[0];
  let key = content.match(ANON_ASSIGN)?.[1];
  if (key && !isPublicKey(key)) key = undefined;
  key ??= content.match(BARE_PUBLISHABLE)?.[0]
    ?? [...content.matchAll(BARE_JWT)].map((m) => m[0]).find((k) => classifyKey(k) === 'jwt-anon');
  return { url, key };
}

function envRank(rel: string): number {
  const i = ENV_ORDER.indexOf(rel.split('/').pop() ?? rel);
  return i === -1 ? ENV_ORDER.length : i;
}

/**
 * Find a Supabase URL + a *public* key (anon JWT or publishable) in the project.
 * URL and key are paired by provenance: a file holding both wins (env files in
 * load order first). Only when no single file has both do we fall back to a
 * URL from one file and a key from another — flagged `ambiguous`, because the
 * two may belong to different environments and must never be presented as one
 * discovered config.
 */
export function discoverSupabase(files: Pick<ScanFile, 'content' | 'rel'>[]): SupabaseCreds | null {
  const scannable = files
    .filter((f) => !NOT_CONFIG.test(f.rel))
    .map((f) => ({ rel: f.rel, ...credsInFile(f.content) }))
    .sort((a, b) => envRank(a.rel) - envRank(b.rel)); // stable: ties keep scan order

  const make = (url: string, anonKey: string, source: string, ambiguous?: true): SupabaseCreds => ({
    url: url.replace(/\/+$/, ''),
    anonKey,
    keyKind: classifyKey(anonKey) === 'publishable' ? 'publishable' : 'jwt-anon',
    source,
    ...(ambiguous ? { ambiguous } : {}),
  });

  const paired = scannable.find((f) => f.url && f.key);
  if (paired?.url && paired.key) return make(paired.url, paired.key, paired.rel);

  const urlFile = scannable.find((f) => f.url);
  const keyFile = scannable.find((f) => f.key);
  if (!urlFile?.url || !keyFile?.key) return null;
  return make(urlFile.url, keyFile.key, `${urlFile.rel} (URL) + ${keyFile.rel} (key)`, true);
}

export interface ProbeResult {
  findings: Finding[];
  run: CheckRun;
}

export interface ProbeOptions {
  creds: SupabaseCreds;
  rateLimitMs?: number;
  log?: (msg: string) => void;
}

// Word-ish matching on the table name: "postcards" must not match "card",
// "authors" must not match "auth", but "api_keys" and "ssn_records" must hit.
const SENSITIVE_WORDS = [
  'user', 'users', 'account', 'accounts', 'payment', 'payments', 'order', 'orders',
  'subscription', 'subscriptions', 'auth', 'session', 'sessions', 'email', 'emails',
  'customer', 'customers', 'profile', 'profiles', 'token', 'tokens', 'secret', 'secrets',
  'credential', 'credentials', 'key', 'keys', 'apikey', 'apikeys', 'invoice', 'invoices',
  'billing', 'address', 'addresses', 'phone', 'phones', 'card', 'cards', 'password',
  'passwords', 'member', 'members', 'contact', 'contacts', 'message', 'messages', 'chat',
  'chats', 'kyc', 'passport', 'ssn', 'pii', 'salary', 'salaries', 'payroll', 'health',
  'medical', 'patient', 'patients', 'private', 'identity', 'identities', 'wallet', 'transaction', 'transactions',
];
const SENSITIVE_SET = new Set(SENSITIVE_WORDS);

function severityForTable(table: string): Severity {
  const words = table.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  return words.some((w) => SENSITIVE_SET.has(w) || SENSITIVE_SET.has(w.replace(/s$/, ''))) ? 'critical' : 'warning';
}

function authHeaders(key: string): Record<string, string> {
  return { apikey: key, Authorization: `Bearer ${key}` };
}

function curlEvidence(url: string, table: string): string {
  return `curl '${url}/rest/v1/${table}?select=*&limit=3' -H 'apikey: <ANON_KEY>' -H 'Authorization: Bearer <ANON_KEY>'`;
}

function parseCount(headers: Headers): number | null {
  const cr = headers.get('content-range');
  if (!cr) return null;
  const total = cr.split('/').pop();
  if (!total || total === '*') return null;
  const n = parseInt(total, 10);
  return Number.isNaN(n) ? null : n;
}

interface OpenApiDoc {
  definitions?: Record<string, unknown>;
  components?: { schemas?: Record<string, unknown> };
  paths?: Record<string, unknown>;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/**
 * PostgREST answers /rest/v1/ with an OpenAPI 2/3 document. Any other JSON
 * (`{"error":…}` from a gateway, a maintenance page's payload) is NOT an empty
 * schema — treating it as one would turn an outage into "zero tables exposed".
 */
function asOpenApi(v: unknown): OpenApiDoc | null {
  if (!isPlainObject(v)) return null;
  const schemas = isPlainObject(v['components']) ? v['components']['schemas'] : undefined;
  if (!isPlainObject(v['definitions']) && !isPlainObject(schemas) && !isPlainObject(v['paths'])) return null;
  return v as OpenApiDoc;
}

async function enumerate(creds: SupabaseCreds): Promise<{ tables: string[]; rpc: string[] } | { error: string }> {
  const res = await request(`${creds.url}/rest/v1/`, { headers: authHeaders(creds.anonKey) });
  const verdict = classifyBody(res, 'json');
  if (verdict.kind === 'denied') return { error: `anon key rejected (${verdict.reason})` };
  // Redirect, 5xx, truncated body, HTML, error envelope, empty JSON: the schema was not enumerated.
  if (verdict.kind !== 'data') return { error: `could not enumerate the PostgREST schema (${verdict.reason})` };
  const spec = asOpenApi(verdict.json);
  if (!spec) return { error: 'PostgREST did not return an OpenAPI document — schema enumeration failed' };
  const schemas = { ...(spec.definitions ?? {}), ...(spec.components?.schemas ?? {}) };
  let tables = Object.keys(schemas);
  const paths = Object.keys(spec.paths ?? {});
  if (tables.length === 0) {
    tables = paths.filter((p) => /^\/[^/{}]+$/.test(p) && p !== '/rpc' && !p.startsWith('/rpc/')).map((p) => p.slice(1));
  }
  const rpc = paths.filter((p) => p.startsWith('/rpc/')).map((p) => p.slice('/rpc/'.length)).filter(Boolean);
  return { tables, rpc };
}

/**
 * Actively probe a Supabase project with its public key — the same access any
 * visitor's browser has. READ-ONLY: it never writes. Returns the findings and a
 * status so a failed/partial probe is never reported as a clean result.
 */
export async function probeSupabase(opts: ProbeOptions): Promise<ProbeResult> {
  const { creds } = opts;
  const rl = opts.rateLimitMs ?? 120;
  const log = opts.log ?? (() => {});
  const findings: Finding[] = [];

  // Only a genuine public key proves anything about anonymous access. Reject
  // service/secret keys (bypass RLS) AND authenticated/unknown keys (not anon).
  const kind = classifyKey(creds.anonKey);
  if (kind !== 'jwt-anon' && kind !== 'publishable') {
    return {
      findings: [{
        id: 'supabase_key_not_public',
        severity: 'warning',
        title: 'Supabase probe skipped — key is not a public anon key',
        detail: `The provided key is "${kind}". Only a public anon (or publishable) key proves anything about anonymous access; probing with anything else is meaningless or unsafe.`,
        fix: 'Re-run with the public anon (or publishable) key. Keep service/secret keys server-side only.',
        checker: 'supabase-probe',
        level: 2,
      }],
      run: { id: 'supabase-probe', level: 2, status: 'skipped', note: `non-anon key (${kind})` },
    };
  }

  const enumerated = await enumerate(creds);
  if ('error' in enumerated) {
    return {
      findings: [],
      run: { id: 'supabase-probe', level: 2, status: 'failed', note: enumerated.error },
    };
  }

  const { tables, rpc } = enumerated;
  log(`Supabase: ${tables.length} table(s), ${rpc.length} rpc function(s) exposed to PostgREST`);

  const lost: string[] = []; // sub-checks that produced no verdict, for the note
  for (const table of tables) {
    await sleep(rl);
    // HEAD + count=exact returns only the row count in a header — no data pulled.
    const res = await request(`${creds.url}/rest/v1/${encodeURIComponent(table)}?select=*`, {
      method: 'HEAD',
      headers: { ...authHeaders(creds.anonKey), Prefer: 'count=exact', Range: '0-0', 'Range-Unit': 'items' },
    });
    // 5xx/429/timeout AND 3xx (a login redirect) mean we learned nothing here.
    if (isErr(res)) { lost.push(`${table} (${res.error})`); continue; }
    if (res.status === 429 || res.status >= 500 || (res.status >= 300 && res.status < 400)) { lost.push(`${table} (HTTP ${res.status})`); continue; }
    if (res.status === 200 || res.status === 206) {
      const count = parseCount(res.headers);
      if (count === null) { lost.push(`${table} (no content-range)`); continue; } // no usable count → inconclusive, not proof
      if (count > 0) {
        const sev = severityForTable(table);
        findings.push({
          id: 'supabase_anon_read',
          severity: sev,
          title: `Table "${table}" is readable by anyone`,
          detail:
            `The public key can read ${count} row(s) from "${table}".` +
            (sev === 'critical'
              ? ' The name suggests private/PII/financial data — if so, this is a serious leak.'
              : ' If this table is public content (e.g. products/articles) this may be intended — confirm.'),
          fix: `Enable RLS and make sure no permissive policy grants anon access: ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY; then DROP any "USING (true)" policy and add an owner/tenant policy (a new policy is OR-ed with existing ones, so a permissive policy left in place keeps access open).`,
          checker: 'supabase-probe',
          level: 2,
          endpoint: `GET /rest/v1/${table}`,
          evidence: curlEvidence(creds.url, table),
        });
      }
    }
  }

  // Storage buckets listable by anon.
  await sleep(rl);
  const buckets = await request(`${creds.url}/storage/v1/bucket`, { headers: authHeaders(creds.anonKey) });
  // One classifier for every probe: a redirect, a truncated or non-JSON 200, an
  // error envelope — none of them says "no buckets". 401/403/404 and `[]` do.
  const bv = classifyBody(buckets, 'json');
  if (bv.kind === 'unknown') lost.push(`storage (${bv.reason})`);
  if (bv.kind === 'data') {
    const parsed = bv.json;
    const list = (Array.isArray(parsed) ? parsed : (parsed as { buckets?: unknown })?.buckets) as
      Array<string | { name?: string; id?: string; public?: boolean }> | undefined;
    if (!Array.isArray(list)) {
      lost.push('storage (unrecognized bucket listing)'); // a 200 we cannot read is a lost sub-check
    } else if (list.length > 0) {
      const objs = list.map((b) => (typeof b === 'string' ? { name: b } : b));
      const publicOnes = objs.filter((b) => b.public).map((b) => b.name ?? b.id ?? '(unnamed)').join(', ');
      findings.push({
        id: 'supabase_bucket_listing',
        severity: publicOnes ? 'critical' : 'warning',
        title: 'Storage buckets are listable by anyone',
        detail: `The public key can list ${list.length} storage bucket(s)${publicOnes ? `; public: ${publicOnes}` : ''}.`,
        fix: 'Restrict bucket listing and mark buckets private unless public access is intentional; add storage RLS policies.',
        checker: 'supabase-probe',
        level: 2,
        endpoint: 'GET /storage/v1/bucket',
      });
    }
  }

  if (rpc.length > 0) {
    findings.push({
      id: 'supabase_rpc_exposed',
      severity: 'advisory',
      title: `${rpc.length} RPC function(s) exposed`,
      detail: `PostgREST exposes RPC: ${rpc.slice(0, 12).join(', ')}${rpc.length > 12 ? ' …' : ''}. Review that each checks the caller's identity.`,
      fix: 'Ensure SECURITY DEFINER functions verify auth.uid() internally and are not callable by anon when they should not be.',
      checker: 'supabase-probe',
      level: 2,
    });
  }

  const attempted = tables.length + 1; // tables + storage
  const totalErr = lost.length;
  const status = totalErr === 0 ? 'completed' : totalErr < attempted ? 'partial' : 'failed';
  const note = totalErr > 0
    ? `${totalErr}/${attempted} probe(s) not verified: ${lost.slice(0, 5).join(', ')}${totalErr > 5 ? ', …' : ''}`
    : undefined;
  return { findings, run: { id: 'supabase-probe', level: 2, status, note } };
}
