import type { Finding } from '../../types.js';
import type { Endpoint } from '../../endpoints.js';
import { concretePath } from '../../endpoints.js';
import { isErr, request, sleep } from '../../net/http.js';

function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}`, accept: 'application/json' };
}

function hasData(body: string): boolean {
  const t = body.trim();
  return t.length > 2 && (t.startsWith('{') || t.startsWith('['));
}

/**
 * Differential IDOR/BOLA probe. For each object-scoped endpoint, requests the
 * same resource as two different users. If both get 200 with data on the same
 * id, the object is likely not owner-scoped — a candidate IDOR to verify.
 *
 * This is deterministic given two tokens; harvesting real object IDs and
 * judging ambiguous responses is left to the operator or the AI-driven skill.
 */
export async function idorDifferential(
  appUrl: string,
  endpoints: Endpoint[],
  tokenA: string,
  tokenB: string,
  rateLimitMs = 120,
): Promise<Finding[]> {
  const base = appUrl.replace(/\/$/, '');
  const findings: Finding[] = [];

  const idEndpoints = endpoints.filter(
    (e) => (e.method === 'GET' || e.method === 'ANY') && /(:[A-Za-z0-9_]+|\[[^\]]+\])/.test(e.path),
  ).slice(0, 40);

  for (const e of idEndpoints) {
    const path = concretePath(e.path).replace(/^\/?/, '/');
    await sleep(rateLimitMs);
    const a = await request(base + path, { headers: bearer(tokenA) });
    await sleep(rateLimitMs);
    const b = await request(base + path, { headers: bearer(tokenB) });
    if (isErr(a) || isErr(b)) continue;

    const aOk = a.status === 200 && hasData(a.body);
    const bOk = b.status === 200 && hasData(b.body);

    if (aOk && bOk) {
      // Both users getting data on the same id is a *candidate* IDOR, but it is
      // also exactly what a legitimately public/shared resource looks like. We
      // cannot confirm ownership without knowing whose object this id is, so we
      // never fail the gate on it — report as a warning to verify.
      const identical = a.body === b.body;
      findings.push({
        id: 'idor_cross_user',
        severity: 'warning',
        title: `Two accounts both read ${path}`,
        detail: identical
          ? `Both accounts received the identical object at ${path}. If this resource is meant to be private/per-user, that is an IDOR; if it is public/shared, it is fine — confirm which.`
          : `Both accounts got a 200 with data at ${path}. Verify each only ever sees their own record.`,
        fix: 'Enforce ownership server-side: check the authenticated user owns the requested id before returning it (or apply RLS). To confirm exploitability, request an id you know belongs to account A while authenticated as account B.',
        checker: 'idor',
        level: 2,
        endpoint: `GET ${path}`,
      });
    }
  }

  if (findings.length === 0) {
    findings.push({
      id: 'idor_clean',
      severity: 'info',
      title: 'IDOR differential found no shared objects',
      detail: `Probed ${idEndpoints.length} object-scoped endpoint(s) with two accounts; none returned the same object to both.`,
      fix: 'Keep verifying ownership on every object-scoped route.',
      checker: 'idor',
      level: 2,
    });
  }

  return findings;
}
