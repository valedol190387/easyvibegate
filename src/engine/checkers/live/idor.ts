import type { CheckRun, Finding } from '../../types.js';
import type { Endpoint } from '../../endpoints.js';
import { concretePath } from '../../endpoints.js';
import { isErr, request, sleep, unreliable } from '../../net/http.js';

export interface IdorResult {
  findings: Finding[];
  run: CheckRun;
}

function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}`, accept: 'application/json' };
}

/** Real, non-empty JSON payload — an empty collection or an error envelope is not data. */
function hasData(body: string): boolean {
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
 * Differential IDOR/BOLA probe. For each object-scoped endpoint, requests the
 * same resource as two different users and classifies the PAIR:
 *   - either side unreliable (timeout/5xx/429) → inconclusive, not a verdict
 *   - both 200 with data                       → candidate cross-user access
 *   - otherwise                                → a definitive (non-leaking) answer
 * Harvesting real object IDs and judging ambiguous cases is left to the
 * operator or the AI-driven skill; the run status says how much was proven.
 */
export async function idorDifferential(
  appUrl: string,
  endpoints: Endpoint[],
  tokenA: string,
  tokenB: string,
  rateLimitMs = 120,
): Promise<IdorResult> {
  const base = appUrl.replace(/\/$/, '');
  const findings: Finding[] = [];

  // Two different, non-empty identities or the comparison proves nothing.
  if (!tokenA.trim() || !tokenB.trim() || tokenA === tokenB) {
    return { findings, run: { id: 'idor', level: 2, status: 'skipped', note: 'needs two different non-empty account tokens' } };
  }

  const idCandidates = endpoints
    .filter((e) => (e.method === 'GET' || e.method === 'ANY') && /(:[A-Za-z0-9_]+|\[[^\]]+\]|\{[^}]+\})/.test(e.path));
  const MAX = 40;
  const idEndpoints = idCandidates.slice(0, MAX);
  const droppedPairs = idCandidates.length - idEndpoints.length;
  if (idEndpoints.length === 0) {
    return { findings, run: { id: 'idor', level: 2, status: 'skipped', note: 'no object-scoped (id) endpoints found' } };
  }

  let inconclusive = 0; // a side timed out / 5xx / 429 — we learned nothing
  let evaluated = 0; // both sides answered reliably
  let dataSeen = 0; // at least one side returned actual data (the guessed id exists)

  for (const e of idEndpoints) {
    const path = concretePath(e.path).replace(/^\/?/, '/');
    await sleep(rateLimitMs);
    const a = await request(base + path, { headers: bearer(tokenA) });
    await sleep(rateLimitMs);
    const b = await request(base + path, { headers: bearer(tokenB) });

    if (unreliable(a) || unreliable(b) || isErr(a) || isErr(b)) { inconclusive++; continue; }
    evaluated++;

    const aOk = a.status === 200 && hasData(a.body);
    const bOk = b.status === 200 && hasData(b.body);
    if (aOk || bOk) dataSeen++;

    if (aOk && bOk) {
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

  const total = idEndpoints.length;
  if (evaluated === 0) {
    return { findings, run: { id: 'idor', level: 2, status: 'failed', note: `all ${total} pair(s) were inconclusive (timeout/5xx/429)` } };
  }
  if (inconclusive > 0 || droppedPairs > 0) {
    const n: string[] = [];
    if (inconclusive > 0) n.push(`${inconclusive}/${total} pair(s) inconclusive (timeout/5xx/429)`);
    if (droppedPairs > 0) n.push(`only ${MAX}/${idCandidates.length} object endpoints probed (cap)`);
    return { findings, run: { id: 'idor', level: 2, status: 'partial', note: n.join('; ') } };
  }
  if (dataSeen === 0) {
    return { findings, run: { id: 'idor', level: 2, status: 'partial', note: 'no endpoint returned data for the guessed id — provide real object ids to confirm ownership' } };
  }
  return { findings, run: { id: 'idor', level: 2, status: 'completed' } };
}
