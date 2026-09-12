import { scanStatic, type ScanResult } from '../engine/scan.js';
import { collectEndpoints } from '../engine/endpoints.js';
import { applyIgnores, loadConfig, type VibegateConfig } from '../engine/config.js';
import { auditDeps } from '../engine/checkers/deep/deps.js';
import { classifyKey, discoverSupabase, probeSupabase, type SupabaseCreds } from '../engine/checkers/backend/supabase.js';
import { discoverFirebase, probeFirebase, type FirebaseCreds } from '../engine/checkers/backend/firebase.js';
import { checkLiveSite } from '../engine/checkers/live/http-checks.js';
import { probeEndpointsUnauth } from '../engine/checkers/live/endpoint-probe.js';
import { idorDifferential } from '../engine/checkers/live/idor.js';
import type { CheckRun, Finding, ScanFile } from '../engine/types.js';

export type ConsentKind = 'supabase' | 'firebase' | 'live' | 'idor';

export interface ConsentRequest {
  kind: ConsentKind;
  /** The normalized target that WILL be probed if the answer is yes. */
  target: string;
  detail: string;
  /**
   * True when a person asked for this target (a flag or a typed answer);
   * false when it was only auto-discovered in the code.
   */
  explicit: boolean;
}

export type Consent = (req: ConsentRequest) => Promise<boolean>;

/**
 * One concrete thing the flow may probe. The plan is built once, after config
 * is applied, so the target a person consents to is byte-for-byte the target
 * that receives the requests. `source` names where it came from ("--url",
 * "wizard", "discovered:src/db.ts") and drives the coverage note when it is
 * not run.
 */
export type Target =
  | { kind: 'supabase'; target: string; explicit: boolean; source: string; creds: SupabaseCreds }
  | { kind: 'firebase'; target: string; explicit: boolean; source: string; creds: FirebaseCreds }
  | { kind: 'live'; target: string; explicit: boolean; source: string; appUrl: string }
  | { kind: 'idor'; target: string; explicit: boolean; source: string; appUrl: string; tokens: [string, string] };

export interface TargetPlan {
  readonly targets: readonly Target[];
}

export interface PlanOptions {
  appUrl?: string;
  /** Where `appUrl` came from, for the coverage note (default "--url"). */
  appUrlSource?: string;
  supabaseUrl?: string;
  supabaseKey?: string;
  idorTokens?: [string, string];
}

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
  /** Absolute directories to leave out of the walk (the report directory). */
  excludeAbs?: string[];
  /**
   * A plan built by planTargets(). When given, the flow executes exactly these
   * targets and never re-discovers — otherwise the wizard could show one host
   * in its consent question and the flow could probe another.
   */
  plan?: TargetPlan;
}

/** Files that feed discovery, endpoint enumeration and the plan: ignorePaths applied. */
export function visibleFiles<F extends Pick<ScanFile, 'rel'>>(files: F[], config: VibegateConfig): F[] {
  return files.filter((f) => !config.ignorePaths.some((sub) => f.rel.includes(sub)));
}

/** The identity a consent answer is bound to: kind + normalized target. */
export function consentKey(kind: ConsentKind, target: string): string {
  return `${kind} ${target}`;
}

/** Trailing slashes and host case must not make "the same" host look different. */
function normalizeTarget(url: string): string {
  const trimmed = url.trim().replace(/\/+$/, '');
  try {
    return new URL(trimmed).toString().replace(/\/$/, '');
  } catch {
    return trimmed;
  }
}

const DETAIL: Record<ConsentKind, string> = {
  supabase: 'read tables, buckets and RPC using the public key (read-only)',
  firebase: 'anonymous reads of RTDB, Firestore and Storage',
  live: 'passive checks (headers, exposed files) + unauthenticated endpoint probe',
  idor: 'replay object-scoped endpoints with two accounts (IDOR test)',
};

/**
 * The live-site targets that follow from an app URL. Exported so the wizard,
 * which learns the URL only after the backend questions, can extend the plan
 * without a second discovery pass.
 */
export function liveTargets(appUrl: string | undefined, idorTokens: [string, string] | undefined, source = '--url'): Target[] {
  if (!appUrl) return [];
  const target = normalizeTarget(appUrl);
  const out: Target[] = [{ kind: 'live', target, explicit: true, source, appUrl: target }];
  if (idorTokens) out.push({ kind: 'idor', target, explicit: true, source: '--idor-tokens', appUrl: target, tokens: idorTokens });
  return out;
}

/**
 * Build the immutable target plan: ONE discovery pass over the files that
 * survive `ignorePaths`, plus whatever the caller asked for explicitly. Both the
 * consent prompt and the probes work from this same list.
 */
export function planTargets(files: Pick<ScanFile, 'content' | 'rel'>[], config: VibegateConfig, opts: PlanOptions = {}): TargetPlan {
  const visible = visibleFiles(files, config);
  const targets: Target[] = [];

  if (opts.supabaseUrl && opts.supabaseKey) {
    const keyKind = classifyKey(opts.supabaseKey) === 'publishable' ? 'publishable' as const : 'jwt-anon' as const;
    const url = normalizeTarget(opts.supabaseUrl);
    targets.push({ kind: 'supabase', target: url, explicit: true, source: '--supabase-url', creds: { url, anonKey: opts.supabaseKey, keyKind } });
  } else {
    const sb = discoverSupabase(visible);
    if (sb) targets.push({ kind: 'supabase', target: sb.url, explicit: false, source: `discovered:${sb.source ?? 'code'}`, creds: sb });
  }

  const fb = discoverFirebase(visible);
  if (fb) targets.push({ kind: 'firebase', target: fb.projectId, explicit: false, source: 'discovered:code', creds: fb });

  targets.push(...liveTargets(opts.appUrl, opts.idorTokens, opts.appUrlSource));
  return { targets };
}

/** Which CheckRun ids a target produces when it runs — used to record the not-run case. */
function runIdsFor(target: Target): string[] {
  switch (target.kind) {
    case 'supabase': return ['supabase-probe'];
    case 'firebase': return ['firebase-probe'];
    case 'live': return ['live-site', 'endpoint-probe'];
    case 'idor': return ['idor'];
  }
}

/**
 * A target that was requested and did not run is missing coverage, never a
 * clean result: `unsupported` makes the gate incomplete. A target that was only
 * auto-discovered and declined is a voluntary skip — visible, gate unaffected.
 */
function notRun(target: Target): CheckRun[] {
  const ownership = target.kind === 'live' || target.kind === 'idor';
  const via = target.source === 'wizard' ? 'in the wizard' : `via ${target.source}`;
  const note = target.explicit
    ? `requested ${via} but ${ownership ? 'ownership was not confirmed' : 'consent was not given'}`
    : 'declined by user';
  return runIdsFor(target).map((id) => ({ id, level: 2, status: target.explicit ? 'unsupported' : 'skipped', note }));
}

/**
 * Tiered orchestrator shared by the CLI wizard and the skill. Every check that
 * runs records a status (completed/partial/failed/skipped/unsupported) so a
 * failed or not-run check is never mistaken for a clean result.
 */
export async function runFlow(opts: FlowOptions): Promise<ScanResult> {
  const log = opts.log ?? (() => {});
  const result = opts.precomputedStatic ?? (await scanStatic(opts.root, { configPath: opts.configPath, excludeAbs: opts.excludeAbs }));
  const findings: Finding[] = [...result.findings];
  const runs: CheckRun[] = [...result.runs];

  // Files used for endpoint enumeration (and, without a caller-supplied plan,
  // backend discovery) honor ignorePaths, so an ignored path (e.g. tests/,
  // fixtures/) does not feed the live probes.
  const config = loadConfig(opts.root, opts.configPath);
  const visible = visibleFiles(result.files, config);
  const plan = opts.plan ?? planTargets(result.files, config, opts);

  // Level 1 — dependency audit.
  if (opts.runDeps) {
    log('Level 1: dependency audit…');
    const deps = await auditDeps(opts.root, result.detection.packageManagers);
    findings.push(...deps.findings);
    runs.push(deps.run);
  }

  // Level 2 — execute exactly the plan, one consent per concrete target.
  // IDOR depends on the live-site consent: without ownership of the host, the
  // two-account replay must not run either.
  let liveApproved = false;
  let endpoints: ReturnType<typeof collectEndpoints> | undefined;
  for (const target of plan.targets) {
    const req: ConsentRequest = { kind: target.kind, target: target.target, detail: DETAIL[target.kind], explicit: target.explicit };
    const approved = target.kind === 'idor' ? liveApproved && (await opts.consent(req)) === true : (await opts.consent(req)) === true;
    if (!approved) {
      runs.push(...notRun(target));
      continue;
    }

    switch (target.kind) {
      case 'supabase': {
        log(`Level 2: probing Supabase ${target.target}…`);
        const r = await probeSupabase({ creds: target.creds, log });
        findings.push(...r.findings);
        runs.push(r.run);
        break;
      }
      case 'firebase': {
        log(`Level 2: probing Firebase ${target.target}…`);
        const r = await probeFirebase({ creds: target.creds, log });
        findings.push(...r.findings);
        runs.push(r.run);
        break;
      }
      case 'live': {
        liveApproved = true;
        log(`Level 2: live checks on ${target.appUrl}…`);
        const site = await checkLiveSite(target.appUrl);
        findings.push(...site.findings);
        runs.push(site.run);

        endpoints ??= collectEndpoints(visible);
        const ep = await probeEndpointsUnauth(target.appUrl, endpoints);
        findings.push(...ep.findings);
        runs.push(ep.run);
        break;
      }
      case 'idor': {
        endpoints ??= collectEndpoints(visible);
        const r = await idorDifferential(target.appUrl, endpoints, target.tokens[0], target.tokens[1]);
        findings.push(...r.findings);
        // Tokens are always an explicit request. If the check could not run
        // (identical tokens, no id-scoped endpoints…) that is a request not
        // honoured — `unsupported`, so it cannot hide inside a clean PASS.
        runs.push(r.run.status === 'skipped' ? { ...r.run, status: 'unsupported' } : r.run);
        break;
      }
    }
  }

  // Apply config-based suppressions to the full finding set (Level 1/2 too).
  const filtered = applyIgnores(findings, config, result.files);

  return { ...result, findings: filtered, runs };
}
