import { scanStatic, type ScanResult } from '../engine/scan.js';
import { collectEndpoints } from '../engine/endpoints.js';
import { auditDeps } from '../engine/checkers/deep/deps.js';
import { discoverSupabase, probeSupabase } from '../engine/checkers/backend/supabase.js';
import { discoverFirebase, probeFirebase } from '../engine/checkers/backend/firebase.js';
import { checkLiveSite } from '../engine/checkers/live/http-checks.js';
import { probeEndpointsUnauth } from '../engine/checkers/live/endpoint-probe.js';
import { idorDifferential } from '../engine/checkers/live/idor.js';

export type ConsentKind = 'supabase' | 'supabase-write' | 'firebase' | 'live' | 'idor';

export interface ConsentRequest {
  kind: ConsentKind;
  target: string;
  detail: string;
}

export type Consent = (req: ConsentRequest) => Promise<boolean>;

export interface FlowOptions {
  root: string;
  configPath?: string;
  appUrl?: string;
  supabaseUrl?: string;
  supabaseKey?: string;
  runDeps?: boolean;
  /** Allow write-canary probing (still gated by consent). */
  writeProbe?: boolean;
  idorTokens?: [string, string];
  consent: Consent;
  log?: (msg: string) => void;
  /** Reuse an already-computed Level 0 result instead of scanning again. */
  precomputedStatic?: ScanResult;
}

/**
 * The tiered orchestrator, shared by the CLI wizard and the skill:
 *   Level 0 — static code review (always)
 *   Level 1 — dependency audit (opt-in)
 *   Level 2 — live probe of backends / running app (consent + ownership)
 */
export async function runFlow(opts: FlowOptions): Promise<ScanResult> {
  const log = opts.log ?? (() => {});
  const result = opts.precomputedStatic ?? (await scanStatic(opts.root, { configPath: opts.configPath }));
  const findings = result.findings;

  // Level 1 — dependency audit.
  if (opts.runDeps) {
    log('Level 1: dependency audit…');
    findings.push(...(await auditDeps(opts.root, result.detection.packageManagers)));
  }

  // Level 2 — Supabase active probe.
  const sbCreds =
    opts.supabaseUrl && opts.supabaseKey
      ? { url: opts.supabaseUrl, anonKey: opts.supabaseKey }
      : discoverSupabase(result.files);
  if (sbCreds) {
    const ok = await opts.consent({
      kind: 'supabase',
      target: sbCreds.url,
      detail: 'read tables, buckets and RPC using the public anon key',
    });
    if (ok) {
      let write = false;
      if (opts.writeProbe) {
        write = await opts.consent({
          kind: 'supabase-write',
          target: sbCreds.url,
          detail: 'attempt canary INSERTs (writes to the DB, auto-cleaned)',
        });
      }
      log(`Level 2: probing Supabase ${sbCreds.url}…`);
      findings.push(...(await probeSupabase({ creds: sbCreds, write, log })));
    }
  }

  // Level 2 — Firebase active probe.
  const fbCreds = discoverFirebase(result.files);
  if (fbCreds) {
    const ok = await opts.consent({
      kind: 'firebase',
      target: fbCreds.projectId,
      detail: 'anonymous reads of RTDB, Firestore and Storage',
    });
    if (ok) {
      log(`Level 2: probing Firebase ${fbCreds.projectId}…`);
      findings.push(...(await probeFirebase({ creds: fbCreds, log })));
    }
  }

  // Level 2 — live site + endpoint probe + IDOR.
  if (opts.appUrl) {
    const ok = await opts.consent({
      kind: 'live',
      target: opts.appUrl,
      detail: 'passive checks (headers, exposed files) + unauthenticated endpoint probe',
    });
    if (ok) {
      log(`Level 2: live checks on ${opts.appUrl}…`);
      findings.push(...(await checkLiveSite(opts.appUrl)));
      const endpoints = collectEndpoints(result.files);
      findings.push(...(await probeEndpointsUnauth(opts.appUrl, endpoints)));

      if (opts.idorTokens) {
        const idorOk = await opts.consent({
          kind: 'idor',
          target: opts.appUrl,
          detail: 'replay object-scoped endpoints with two accounts (IDOR test)',
        });
        if (idorOk) {
          findings.push(
            ...(await idorDifferential(opts.appUrl, endpoints, opts.idorTokens[0], opts.idorTokens[1])),
          );
        }
      }
    }
  }

  return { ...result, findings };
}
