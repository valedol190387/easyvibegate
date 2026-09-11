import type { CheckRun, Finding } from '../../types.js';
import type { Endpoint } from '../../endpoints.js';
import { concretePath } from '../../endpoints.js';
import { isErr, request, sleep } from '../../net/http.js';

export interface EndpointProbeResult {
  findings: Finding[];
  run: CheckRun;
}

function looksLikeData(body: string): boolean {
  const t = body.trim();
  if (t.length < 2) return false;
  if (/<!doctype html|<html[\s>]/i.test(t.slice(0, 200))) return false;
  return t.startsWith('{') || t.startsWith('[');
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

  const targets = endpoints.filter((e) => e.method === 'GET' || e.method === 'ANY').slice(0, 60);
  if (targets.length === 0) {
    return { findings, run: { id: 'endpoint-probe', level: 2, status: 'skipped', note: 'no GET endpoints discovered' } };
  }

  let errors = 0;
  for (const e of targets) {
    await sleep(rateLimitMs);
    const path = concretePath(e.path).replace(/^\/?/, '/');
    const res = await request(base + path, { headers: { accept: 'application/json' } });
    if (isErr(res)) { errors++; continue; }
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

  const status = errors === 0 ? 'completed' : errors < targets.length ? 'partial' : 'failed';
  const note = errors > 0 ? `${errors}/${targets.length} endpoint requests errored` : undefined;
  return { findings, run: { id: 'endpoint-probe', level: 2, status, note } };
}
