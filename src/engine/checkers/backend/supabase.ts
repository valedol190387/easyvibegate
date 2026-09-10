import type { Finding, ScanFile } from '../../types.js';
import { decodeJwtPayload } from '../../util/text.js';
import { isErr, request, sleep } from '../../net/http.js';

export interface SupabaseCreds {
  url: string;
  anonKey: string;
}

// Prefer the declared env vars — this handles self-hosted Supabase (custom
// domain) and non-JWT key formats, not just *.supabase.co + legacy anon JWTs.
const URL_ASSIGN = /(?:NEXT_PUBLIC_|VITE_|PUBLIC_)?SUPABASE(?:_PUBLIC)?_URL\s*[:=]\s*["'`]?(https?:\/\/[^"'`\s]+)/i;
const ANON_ASSIGN = /(?:NEXT_PUBLIC_|VITE_|PUBLIC_)?SUPABASE_ANON_KEY\s*[:=]\s*["'`]?([A-Za-z0-9._-]{20,})/i;

/** Find a Supabase URL + anon key in the project's source/env files. */
export function discoverSupabase(files: Pick<ScanFile, 'content'>[]): SupabaseCreds | null {
  let url: string | undefined;
  let anonKey: string | undefined;

  // 1. Declared env vars (works for self-hosted + any key format).
  for (const f of files) {
    url ??= f.content.match(URL_ASSIGN)?.[1];
    anonKey ??= f.content.match(ANON_ASSIGN)?.[1];
    if (url && anonKey) break;
  }

  // 2. Fallback: a *.supabase.co URL literal anywhere.
  if (!url) {
    for (const f of files) {
      const m = f.content.match(/https:\/\/[a-z0-9]{16,}\.supabase\.co/);
      if (m) { url = m[0]; break; }
    }
  }
  // 3. Fallback: any anon/authenticated-role JWT literal.
  if (!anonKey) {
    outer: for (const f of files) {
      for (const m of f.content.matchAll(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g)) {
        const payload = decodeJwtPayload(m[0]);
        if (payload && (payload['role'] === 'anon' || payload['role'] === 'authenticated')) {
          anonKey = m[0];
          break outer;
        }
      }
    }
  }

  if (!url || !anonKey) return null;
  return { url: url.replace(/\/+$/, ''), anonKey };
}

export interface ProbeOptions {
  creds: SupabaseCreds;
  /** Attempt anonymous writes (canary) — modifies the DB; caller must confirm. */
  write?: boolean;
  rateLimitMs?: number;
  log?: (msg: string) => void;
}

function authHeaders(key: string): Record<string, string> {
  return { apikey: key, Authorization: `Bearer ${key}` };
}

function curlEvidence(url: string, table: string): string {
  return `curl '${url}/rest/v1/${table}?select=*&limit=3' -H 'apikey: <ANON_KEY>' -H 'Authorization: Bearer <ANON_KEY>'`;
}

/** PostgREST filter matching a row on all its scalar columns (for canary cleanup). */
function deleteFilter(row: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(row)) {
    if (v === null) parts.push(`${encodeURIComponent(k)}=is.null`);
    else if (typeof v === 'object') continue; // skip json/array columns
    else parts.push(`${encodeURIComponent(k)}=eq.${encodeURIComponent(String(v))}`);
  }
  return parts.join('&');
}

function parseCount(headers: Headers): number | null {
  const cr = headers.get('content-range');
  if (!cr) return null;
  const total = cr.split('/').pop();
  if (!total || total === '*') return null;
  const n = parseInt(total, 10);
  return Number.isNaN(n) ? null : n;
}

/** List tables and RPC functions exposed by PostgREST via its OpenAPI root. */
async function enumerate(creds: SupabaseCreds): Promise<{ tables: string[]; rpc: string[] } | { error: string }> {
  const res = await request(`${creds.url}/rest/v1/`, { headers: authHeaders(creds.anonKey) });
  if (isErr(res)) return { error: res.error };
  if (res.status === 401 || res.status === 403) return { error: `anon key rejected (HTTP ${res.status})` };
  let spec: {
    definitions?: Record<string, unknown>;
    components?: { schemas?: Record<string, unknown> };
    paths?: Record<string, unknown>;
  };
  try {
    spec = JSON.parse(res.body);
  } catch {
    return { error: 'PostgREST did not return an OpenAPI document' };
  }

  // Swagger 2.0 uses `definitions`; OpenAPI 3 uses `components.schemas`.
  const schemas = { ...(spec.definitions ?? {}), ...(spec.components?.schemas ?? {}) };
  let tables = Object.keys(schemas);
  const paths = Object.keys(spec.paths ?? {});
  // Fallback: derive table names from single-segment, non-rpc paths.
  if (tables.length === 0) {
    tables = paths.filter((p) => /^\/[^/{}]+$/.test(p) && p !== '/rpc' && !p.startsWith('/rpc/')).map((p) => p.slice(1));
  }
  const rpc = paths.filter((p) => p.startsWith('/rpc/')).map((p) => p.slice('/rpc/'.length));
  return { tables, rpc };
}

/**
 * Actively probe a Supabase project with its anonymous key — the same access
 * any visitor's browser has. Confirms which tables/buckets are readable (and,
 * optionally, writable) by anyone, proving RLS is off rather than guessing.
 */
export async function probeSupabase(opts: ProbeOptions): Promise<Finding[]> {
  const { creds, write = false } = opts;
  const rl = opts.rateLimitMs ?? 120;
  const log = opts.log ?? (() => {});
  const findings: Finding[] = [];

  const enumerated = await enumerate(creds);
  if ('error' in enumerated) {
    findings.push({
      id: 'supabase_probe_error',
      severity: 'info',
      title: 'Supabase probe could not run',
      detail: `Could not enumerate tables: ${enumerated.error}`,
      fix: 'Check the Supabase URL and anon key, and that the project is reachable.',
      checker: 'supabase-probe',
      level: 2,
    });
    return findings;
  }

  const { tables, rpc } = enumerated;
  log(`Supabase: ${tables.length} table(s), ${rpc.length} rpc function(s) exposed to PostgREST`);

  for (const table of tables) {
    await sleep(rl);
    // Read probe: ask only for the row count, no data pulled.
    const res = await request(`${creds.url}/rest/v1/${table}?select=*`, {
      headers: { ...authHeaders(creds.anonKey), Prefer: 'count=exact', Range: '0-0', 'Range-Unit': 'items' },
    });
    if (isErr(res)) continue;

    if (res.status === 200 || res.status === 206) {
      const count = parseCount(res.headers);
      if (count === null || count > 0) {
        findings.push({
          id: 'supabase_anon_read',
          severity: 'critical',
          title: `Table "${table}" is readable by anyone`,
          detail:
            count === null
              ? `The anon key can query "${table}" — RLS is off or permissive.`
              : `The anon key can read ${count} row(s) from "${table}" — RLS is off or permissive.`,
          fix: `ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY; then add a policy, e.g. CREATE POLICY owner ON ${table} FOR SELECT USING (auth.uid() = user_id);`,
          checker: 'supabase-probe',
          level: 2,
          endpoint: `GET /rest/v1/${table}`,
          evidence: curlEvidence(creds.url, table),
        });
      }
      // count === 0: accessible but empty — inconclusive, not reported as a leak.
    }

    if (write) {
      await sleep(rl);
      const w = await request(`${creds.url}/rest/v1/${table}`, {
        method: 'POST',
        headers: { ...authHeaders(creds.anonKey), 'Content-Type': 'application/json', Prefer: 'return=representation' },
        body: JSON.stringify({}),
      });
      if (!isErr(w) && w.status !== 401 && w.status !== 403) {
        // 201 => inserted; 400/409 => policy allowed, schema/constraint rejected.
        let cleaned = true;
        if (w.status === 201) {
          cleaned = false;
          try {
            const rows = JSON.parse(w.body) as Array<Record<string, unknown>>;
            const row = rows[0];
            // Delete the exact canary row by matching every scalar column, so
            // cleanup works regardless of the primary key's name (id/uuid/composite).
            const filter = row ? deleteFilter(row) : '';
            if (filter) {
              const del = await request(`${creds.url}/rest/v1/${table}?${filter}`, {
                method: 'DELETE',
                headers: authHeaders(creds.anonKey),
              });
              cleaned = !isErr(del) && del.status >= 200 && del.status < 300;
            }
          } catch {
            /* leave cleaned=false */
          }
        }
        findings.push({
          id: 'supabase_anon_write',
          severity: 'critical',
          title: `Table "${table}" accepts writes from anyone`,
          detail:
            `An anonymous INSERT was not blocked by RLS (HTTP ${w.status}).` +
            (w.status === 201 ? (cleaned ? ' A canary row was inserted and deleted.' : ' A canary row was inserted — please verify it was removed.') : ''),
          fix: `Enable RLS on ${table} and add a WITH CHECK policy so only the owner can insert: CREATE POLICY ins ON ${table} FOR INSERT WITH CHECK (auth.uid() = user_id);`,
          checker: 'supabase-probe',
          level: 2,
          endpoint: `POST /rest/v1/${table}`,
        });
      }
    }
  }

  // Storage buckets readable/listable by anon.
  await sleep(rl);
  const buckets = await request(`${creds.url}/storage/v1/bucket`, { headers: authHeaders(creds.anonKey) });
  if (!isErr(buckets) && buckets.status === 200) {
    try {
      const list = JSON.parse(buckets.body) as Array<{ name?: string; public?: boolean }>;
      if (Array.isArray(list) && list.length > 0) {
        const publicOnes = list.filter((b) => b.public).map((b) => b.name).join(', ');
        findings.push({
          id: 'supabase_bucket_listing',
          severity: publicOnes ? 'critical' : 'warning',
          title: 'Storage buckets are listable by anyone',
          detail: `The anon key can list ${list.length} storage bucket(s)${publicOnes ? `; public: ${publicOnes}` : ''}.`,
          fix: 'Restrict bucket listing and mark buckets private unless public access is intentional; add storage RLS policies.',
          checker: 'supabase-probe',
          level: 2,
          endpoint: 'GET /storage/v1/bucket',
        });
      }
    } catch {
      /* ignore */
    }
  }

  // RPC functions are callable targets — advisory only (calling them blindly is unsafe).
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

  if (findings.length === 0) {
    findings.push({
      id: 'supabase_probe_clean',
      severity: 'info',
      title: 'Supabase anon probe found no open tables',
      detail: `Probed ${tables.length} table(s); none returned rows to the anon key. This is a good sign, not a guarantee.`,
      fix: 'Keep RLS enabled with owner-scoped policies on every user-data table.',
      checker: 'supabase-probe',
      level: 2,
    });
  }

  return findings;
}
