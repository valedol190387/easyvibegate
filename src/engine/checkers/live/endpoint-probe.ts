import type { CheckRun, Finding } from '../../types.js';
import type { Endpoint } from '../../endpoints.js';
import { concretePath } from '../../endpoints.js';
import { isErr, request, sleep, unreliable } from '../../net/http.js';

export interface EndpointProbeResult {
  findings: Finding[];
  run: CheckRun;
}

/** Real, non-empty JSON payload — `[]`, `{}` and `{"error":...}` are not data. */
function looksLikeData(body: string): boolean {
  const t = body.trim();
  if (t.length < 2 || !(t.startsWith('{') || t.startsWith('['))) return false;
  try {
    const v = JSON.parse(t) as unknown;
    if (Array.isArray(v)) return v.length > 0;
    if (v && typeof v === 'object') {
      const o = v as Record<string, unknown>;
      if ('error' in o || 'errors' in o) return false;
      return Object.keys(o).length > 0;
    }
    return false;
  } catch { return false; }
}

/**
 * Hit each GET-able endpoint with no authentication. A 200 with JSON data is a
 * candidate "no access control" hole — reported as a warning to confirm, since
 * some endpoints are legitimately public.
 */
export async function probeEndpointsUnauth(
  appUrl: string,
  endpoints: Endpoint[],
  rateLimitMs = 100,
): Promise<EndpointProbeResult> {
  const base = appUrl.replace(/\/$/, '');
  const findings: Finding[] = [];

  const candidates = endpoints.filter((e) => e.method === 'GET' || e.method === 'ANY');
  const MAX = 60;
  const targets = candidates.slice(0, MAX);
  const dropped = candidates.length - targets.length;
  if (targets.length === 0) {
    return { findings, run: { id: 'endpoint-probe', level: 2, status: 'skipped', note: 'no GET endpoints discovered' } };
  }

  let errors = 0;
  for (const e of targets) {
    await sleep(rateLimitMs);
    const path = concretePath(e.path).replace(/^\/?/, '/');
    const res = await request(base + path, { headers: { accept: 'application/json' } });
    if (isErr(res) || res.status === 429 || res.status >= 500 || (res.status >= 300 && res.status < 400)) { errors++; continue; }
    if (res.status !== 200) continue;
    if (!looksLikeData(res.body)) continue;

    findings.push({
      id: 'endpoint_no_auth',
      severity: 'warning',
      title: `Endpoint returns data without authentication`,
      detail: `GET ${path} responded 200 with JSON to an unauthenticated request. Confirm this endpoint is meant to be public.`,
      fix: 'Require a session/token check on this route (middleware or an explicit guard) if the data is not meant to be public.',
      checker: 'endpoint-probe',
      level: 2,
      endpoint: `GET ${path}`,
      evidence: `curl '${base}${path}'`,
    });
  }

  const status = errors >= targets.length ? 'failed' : errors > 0 || dropped > 0 ? 'partial' : 'completed';
  const notes: string[] = [];
  if (errors > 0) notes.push(`${errors}/${targets.length} endpoint requests errored`);
  if (dropped > 0) notes.push(`only ${MAX}/${candidates.length} endpoints probed (cap)`);
  const note = notes.length ? notes.join('; ') : undefined;
  return { findings, run: { id: 'endpoint-probe', level: 2, status, note } };
}
