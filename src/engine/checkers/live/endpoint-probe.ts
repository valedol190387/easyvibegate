import type { CheckRun, Finding } from '../../types.js';
import type { Endpoint } from '../../endpoints.js';
import { concretePath } from '../../endpoints.js';
import { classifyBody, request, sleep } from '../../net/http.js';

export interface EndpointProbeResult {
  findings: Finding[];
  run: CheckRun;
}

/**
 * Hit each GET-able endpoint with no authentication. A 2xx with JSON data is a
 * candidate "no access control" hole — reported as a warning to confirm, since
 * some endpoints are legitimately public.
 *
 * Every response is classified (see classifyBody): only data / empty / denied
 * count as a checked endpoint. A 404 (the inventory guessed the id or the
 * prefix), an HTML page where JSON was expected, a redirect, a truncated or
 * unparseable body all mean the endpoint was NOT verified — the run is
 * `partial` and the note says which ones.
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

  let verified = 0;
  const unverified: string[] = []; // "GET /path (reason)"
  for (const e of targets) {
    const path = concretePath(e.path).replace(/^\/?/, '/');
    // A route whose mount prefix is unknown would be probed at a wrong URL, and
    // a 404 there says nothing about the real one.
    if (e.unresolved) { unverified.push(`GET ${path} (${e.note ?? 'unresolved route prefix'})`); continue; }

    await sleep(rateLimitMs);
    const res = await request(base + path, { headers: { accept: 'application/json' } });
    const verdict = classifyBody(res, 'json');
    // `absent` is lumped with unknown on purpose: the id/prefix was guessed, so a
    // 404 does not prove the real resource is protected.
    if (verdict.kind === 'unknown' || verdict.kind === 'absent') { unverified.push(`GET ${path} (${verdict.reason})`); continue; }
    verified++;
    if (verdict.kind !== 'data') continue;

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

  const status = verified === 0 ? 'failed' : unverified.length > 0 || dropped > 0 ? 'partial' : 'completed';
  const notes: string[] = [];
  if (unverified.length > 0) {
    const shown = unverified.slice(0, 5).join(', ');
    notes.push(`${unverified.length}/${targets.length} endpoint(s) not verified: ${shown}${unverified.length > 5 ? ', …' : ''}`);
  }
  if (dropped > 0) notes.push(`only ${MAX}/${candidates.length} endpoints probed (cap)`);
  const note = notes.length ? notes.join('; ') : undefined;
  return { findings, run: { id: 'endpoint-probe', level: 2, status, note } };
}
