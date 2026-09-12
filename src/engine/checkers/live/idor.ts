import type { CheckRun, Finding } from '../../types.js';
import type { Endpoint } from '../../endpoints.js';
import { concretePath } from '../../endpoints.js';
import { classifyBody, isErr, request, sleep, unreliable } from '../../net/http.js';
import type { BodyVerdict } from '../../net/http.js';

export interface IdorResult {
  findings: Finding[];
  run: CheckRun;
}

function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}`, accept: 'application/json' };
}

type PairKind = 'cross-user' | 'protected' | 'unknown';

/**
 * What one (A, B) pair proves. Only a pair where at least one side gave a
 * definite answer AND the other side did not leak is "protected"; anything
 * where the guessed id did not exist, a token was rejected, or a body could
 * not be read proves nothing.
 */
function classifyPair(a: BodyVerdict, b: BodyVerdict, aStatus: number, bStatus: number): { kind: PairKind; reason: string } {
  if (a.kind === 'data' && b.kind === 'data') return { kind: 'cross-user', reason: 'both accounts read data' };
  if (a.kind === 'unknown' || b.kind === 'unknown') return { kind: 'unknown', reason: a.kind === 'unknown' ? `A: ${a.reason}` : `B: ${b.reason}` };
  if (a.kind === 'absent' || b.kind === 'absent') return { kind: 'unknown', reason: `guessed id not found (HTTP ${a.kind === 'absent' ? aStatus : bStatus})` };
  // A 401 means that token itself was rejected, so that account's access was never tested.
  if (aStatus === 401 || bStatus === 401) return { kind: 'unknown', reason: `token ${aStatus === 401 ? 'A' : 'B'} rejected (HTTP 401)` };
  // Neither side got data and neither answer was an error/404: no object behind
  // the guessed id (or both denied) — nothing leaked, but ownership was not exercised.
  if (a.kind !== 'data' && b.kind !== 'data') {
    if (a.kind === 'denied' && b.kind === 'denied') return { kind: 'protected', reason: 'both accounts denied' };
    return { kind: 'unknown', reason: 'no data for the guessed id from either account' };
  }
  // Exactly one side read data, the other was denied or got nothing: scoped correctly.
  return { kind: 'protected', reason: 'only one account read data' };
}

/**
 * Differential IDOR/BOLA probe. For each object-scoped endpoint, requests the
 * same resource as two different users and classifies the PAIR:
 *   - either side unreliable (timeout/5xx/429) → inconclusive, not a verdict
 *   - both 2xx with data                       → candidate cross-user access
 *   - one side data, other denied/empty        → protected (a verified pair)
 *   - 404 / rejected tokens / unreadable body  → unknown (not verified)
 * Any pair that could not be verified makes the run `partial`, so one good
 * pair never hides the others. Harvesting real object IDs and judging
 * ambiguous cases is left to the operator or the AI-driven skill.
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
  let verifiedPairs = 0; // protected or cross-user: a real verdict
  const unknown: string[] = []; // "GET /path (reason)"

  for (const e of idEndpoints) {
    const path = concretePath(e.path).replace(/^\/?/, '/');
    if (e.unresolved) { unknown.push(`GET ${path} (${e.note ?? 'unresolved route prefix'})`); continue; }
    await sleep(rateLimitMs);
    const a = await request(base + path, { headers: bearer(tokenA) });
    await sleep(rateLimitMs);
    const b = await request(base + path, { headers: bearer(tokenB) });

    if (unreliable(a) || unreliable(b) || isErr(a) || isErr(b)) { inconclusive++; continue; }
    evaluated++;

    const pair = classifyPair(classifyBody(a, 'json'), classifyBody(b, 'json'), a.status, b.status);
    if (pair.kind === 'unknown') { unknown.push(`GET ${path} (${pair.reason})`); continue; }
    verifiedPairs++;
    if (pair.kind !== 'cross-user') continue;

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

  const total = idEndpoints.length;
  if (evaluated === 0 && unknown.length === 0) {
    return { findings, run: { id: 'idor', level: 2, status: 'failed', note: `all ${total} pair(s) were inconclusive (timeout/5xx/429)` } };
  }
  if (inconclusive > 0 || droppedPairs > 0 || unknown.length > 0) {
    const n: string[] = [];
    if (inconclusive > 0) n.push(`${inconclusive}/${total} pair(s) inconclusive (timeout/5xx/429)`);
    if (unknown.length > 0) {
      n.push(`${unknown.length}/${total} pair(s) not verified: ${unknown.slice(0, 5).join(', ')}${unknown.length > 5 ? ', …' : ''}` +
        ' — provide real object ids to confirm ownership');
    }
    if (droppedPairs > 0) n.push(`only ${MAX}/${idCandidates.length} object endpoints probed (cap)`);
    return { findings, run: { id: 'idor', level: 2, status: 'partial', note: n.join('; ') } };
  }
  // Reaching here means every pair got a real verdict (protected or cross-user).
  return { findings, run: { id: 'idor', level: 2, status: verifiedPairs === total ? 'completed' : 'partial' } };
}
