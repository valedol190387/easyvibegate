import { scanStatic, type ScanResult } from '../engine/scan.js';
import { collectEndpoints } from '../engine/endpoints.js';
import { applyIgnores, loadConfig } from '../engine/config.js';
import { auditDeps } from '../engine/checkers/deep/deps.js';
import { classifyKey, discoverSupabase, probeSupabase } from '../engine/checkers/backend/supabase.js';
import { discoverFirebase, probeFirebase } from '../engine/checkers/backend/firebase.js';
import { checkLiveSite } from '../engine/checkers/live/http-checks.js';
import { probeEndpointsUnauth } from '../engine/checkers/live/endpoint-probe.js';
import { idorDifferential } from '../engine/checkers/live/idor.js';
import type { CheckRun, Finding } from '../engine/types.js';

export type ConsentKind = 'supabase' | 'firebase' | 'live' | 'idor';

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
  idorTokens?: [string, string];
  consent: Consent;
  log?: (msg: string) => void;
  precomputedStatic?: ScanResult;
}

/**
 * Tiered orchestrator shared by the CLI wizard and the skill. Every check that
 * runs records a status (completed/partial/failed/skipped/unsupported) so a
 * failed or not-run check is never mistaken for a clean result.
 */
export async function runFlow(opts: FlowOptions): Promise<ScanResult> {
  const log = opts.log ?? (() => {});
  const result = opts.precomputedStatic ?? (await scanStatic(opts.root, { configPath: opts.configPath }));
  const findings: Finding[] = [...result.findings];
  const runs: CheckRun[] = [...result.runs];

  // Files used for backend discovery / endpoint enumeration honor ignorePaths,
  // so an ignored path (e.g. tests/, fixtures/) does not feed the live probes.
  const config = loadConfig(opts.root, opts.configPath);
  const visible = result.files.filter((f) => !config.ignorePaths.some((sub) => f.rel.includes(sub)));

  // Level 1 — dependency audit.
  if (opts.runDeps) {
    log('Level 1: dependency audit…');
    const deps = await auditDeps(opts.root, result.detection.packageManagers);
    findings.push(...deps.findings);
    runs.push(deps.run);
  }

  // Level 2 — Supabase active probe (read-only).
  const sbCreds =
    opts.supabaseUrl && opts.supabaseKey
      ? { url: opts.supabaseUrl, anonKey: opts.supabaseKey, keyKind: classifyKey(opts.supabaseKey) === 'publishable' ? 'publishable' as const : 'jwt-anon' as const }
      : discoverSupabase(visible);
  if (sbCreds) {
    const ok = await opts.consent({
      kind: 'supabase',
      target: sbCreds.url,
      detail: 'read tables, buckets and RPC using the public key (read-only)',
    });
    if (ok === true) {
      log(`Level 2: probing Supabase ${sbCreds.url}…`);
      const r = await probeSupabase({ creds: sbCreds, log });
      findings.push(...r.findings);
      runs.push(r.run);
    } else {
      runs.push({ id: 'supabase-probe', level: 2, status: 'skipped', note: 'declined' });
    }
  }

  // Level 2 — Firebase active probe.
  const fbCreds = discoverFirebase(visible);
  if (fbCreds) {
    const ok = await opts.consent({
      kind: 'firebase',
      target: fbCreds.projectId,
      detail: 'anonymous reads of RTDB, Firestore and Storage',
    });
    if (ok === true) {
      log(`Level 2: probing Firebase ${fbCreds.projectId}…`);
      const r = await probeFirebase({ creds: fbCreds, log });
      findings.push(...r.findings);
      runs.push(r.run);
    } else {
      runs.push({ id: 'firebase-probe', level: 2, status: 'skipped', note: 'declined' });
    }
  }

  // Level 2 — live site + endpoint probe + IDOR.
  if (opts.appUrl) {
    const ok = await opts.consent({
      kind: 'live',
      target: opts.appUrl,
      detail: 'passive checks (headers, exposed files) + unauthenticated endpoint probe',
    });
    if (ok === true) {
      log(`Level 2: live checks on ${opts.appUrl}…`);
      const site = await checkLiveSite(opts.appUrl);
      findings.push(...site.findings);
      runs.push(site.run);

      const endpoints = collectEndpoints(visible);
      const ep = await probeEndpointsUnauth(opts.appUrl, endpoints);
      findings.push(...ep.findings);
      runs.push(ep.run);

      if (opts.idorTokens) {
        const idorOk = await opts.consent({
          kind: 'idor',
          target: opts.appUrl,
          detail: 'replay object-scoped endpoints with two accounts (IDOR test)',
        });
        if (idorOk === true) {
          const r = await idorDifferential(opts.appUrl, endpoints, opts.idorTokens[0], opts.idorTokens[1]);
          findings.push(...r.findings);
          runs.push(r.run);
        } else {
          runs.push({ id: 'idor', level: 2, status: 'skipped', note: 'declined' });
        }
      }
    } else {
      // Record every check the user asked for, so declining is visible as coverage.
      runs.push({ id: 'live-site', level: 2, status: 'skipped', note: 'declined' });
      runs.push({ id: 'endpoint-probe', level: 2, status: 'skipped', note: 'declined' });
      if (opts.idorTokens) runs.push({ id: 'idor', level: 2, status: 'skipped', note: 'declined' });
    }
  }

  // Apply config-based suppressions to the full finding set (Level 1/2 too).
  const filtered = applyIgnores(findings, config, result.files);

  return { ...result, findings: filtered, runs };
}
