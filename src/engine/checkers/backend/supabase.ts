import type { CheckRun, Finding, ScanFile, Severity } from '../../types.js';
import { decodeJwtPayload } from '../../util/text.js';
import { isErr, request, sleep, unreliable } from '../../net/http.js';

export interface SupabaseCreds {
  url: string;
  anonKey: string;
  /** How the key was recognized — used to keep messaging honest. */
  keyKind: 'jwt-anon' | 'publishable';
  /** Where the URL/key were found (for display). */
  source?: string;
}

const URL_ASSIGN = /(?:NEXT_PUBLIC_|VITE_|PUBLIC_)?SUPABASE(?:_PUBLIC)?_URL\s*[:=]\s*["'`]?(https?:\/\/[^"'`\s]+)/i;
const ANON_ASSIGN = /(?:NEXT_PUBLIC_|VITE_|PUBLIC_)?SUPABASE_(?:ANON|PUBLISHABLE)_KEY\s*[:=]\s*["'`]?([A-Za-z0-9._-]{20,})/i;

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

/** Find a Supabase URL + a *public* key (anon JWT or publishable) in the project. */
export function discoverSupabase(files: Pick<ScanFile, 'content' | 'rel'>[]): SupabaseCreds | null {
  // Skip docs when discovering credentials so we don't mix an example URL with a real key.
  const scannable = files.filter((f) => !f.rel.endsWith('.md') && !f.rel.endsWith('.txt'));

  let url: string | undefined;
  let anonKey: string | undefined;
  let source: string | undefined;

  for (const f of scannable) {
    const u = f.content.match(URL_ASSIGN)?.[1];
    if (u && !url) { url = u; source = f.rel; }
    const k = f.content.match(ANON_ASSIGN)?.[1];
    if (k && !anonKey && ['publishable', 'jwt-anon'].includes(classifyKey(k))) anonKey = k;
    if (url && anonKey) break;
  }

  if (!url) {
    for (const f of scannable) {
      const m = f.content.match(/https:\/\/[a-z0-9]{16,}\.supabase\.co/);
      if (m) { url = m[0]; source ??= f.rel; break; }
    }
  }
  if (!anonKey) {
    // Only a genuine anon key or publishable key — never authenticated/service.
    outer: for (const f of scannable) {
      for (const m of f.content.matchAll(/\bsb_publishable_[A-Za-z0-9_-]{10,}\b/g)) { anonKey = m[0]; break outer; }
      for (const m of f.content.matchAll(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g)) {
        if (classifyKey(m[0]) === 'jwt-anon') { anonKey = m[0]; break outer; }
      }
    }
  }

  if (!url || !anonKey) return null;
  return {
    url: url.replace(/\/+$/, ''),
    anonKey,
    keyKind: classifyKey(anonKey) === 'publishable' ? 'publishable' : 'jwt-anon',
    source,
  };
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

async function enumerate(creds: SupabaseCreds): Promise<{ tables: string[]; rpc: string[] } | { error: string }> {
  const res = await request(`${creds.url}/rest/v1/`, { headers: authHeaders(creds.anonKey) });
  if (isErr(res)) return { error: res.error };
  if (res.status === 401 || res.status === 403) return { error: `anon key rejected (HTTP ${res.status})` };
  if (res.status >= 400) return { error: `PostgREST returned HTTP ${res.status}` };
  let spec: { definitions?: Record<string, unknown>; components?: { schemas?: Record<string, unknown> }; paths?: Record<string, unknown> };
  try {
    spec = JSON.parse(res.body);
  } catch {
    return { error: 'PostgREST did not return an OpenAPI document' };
  }
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

  let errored = 0;
  for (const table of tables) {
    await sleep(rl);
    // HEAD + count=exact returns only the row count in a header — no data pulled.
    const res = await request(`${creds.url}/rest/v1/${encodeURIComponent(table)}?select=*`, {
      method: 'HEAD',
      headers: { ...authHeaders(creds.anonKey), Prefer: 'count=exact', Range: '0-0', 'Range-Unit': 'items' },
    });
    // 5xx/429/timeout AND 3xx (a login redirect) mean we learned nothing here.
    if (isErr(res) || res.status === 429 || res.status >= 500 || (res.status >= 300 && res.status < 400)) { errored++; continue; }
    if (res.status === 200 || res.status === 206) {
      const count = parseCount(res.headers);
      if (count === null) { errored++; continue; } // no usable count → inconclusive, not proof
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
  let storageErrored = unreliable(buckets);
  if (!isErr(buckets) && buckets.status === 200) {
    try {
      const parsed = JSON.parse(buckets.body) as unknown;
      const list = (Array.isArray(parsed) ? parsed : (parsed as { buckets?: unknown })?.buckets) as
        Array<string | { name?: string; id?: string; public?: boolean }> | undefined;
      if (!Array.isArray(list)) throw new Error('unrecognized bucket listing');
      if (list.length > 0) {
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
    } catch { storageErrored = true; } // a 200 we cannot parse is a lost sub-check
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
  const totalErr = errored + (storageErrored ? 1 : 0);
  const status = totalErr === 0 ? 'completed' : totalErr < attempted ? 'partial' : 'failed';
  const note = totalErr > 0 ? `${totalErr}/${attempted} probe requests errored (5xx/429/timeout)` : undefined;
  return { findings, run: { id: 'supabase-probe', level: 2, status, note } };
}
