import type { CheckRun, Finding, ScanFile } from '../../types.js';
import { classifyBody, request, sleep } from '../../net/http.js';
import { DNS_LABEL, looksLikePlaceholder } from '../../util/text.js';

const FIREBASEIO_URL = new RegExp(`https://${DNS_LABEL}(?:-default-rtdb)?\\.firebaseio\\.com`);
const FIREBASEAPP_DOMAIN = new RegExp(`(${DNS_LABEL})\\.firebaseapp\\.com`);
const FIREBASEDATABASE_APP = new RegExp(`^${DNS_LABEL}\\.firebasedatabase\\.app$`);

export interface FirebaseProbeResult {
  findings: Finding[];
  run: CheckRun;
}

export interface FirebaseCreds {
  projectId: string;
  databaseURL?: string;
  storageBucket?: string;
}

const COMMON_COLLECTIONS = [
  'users', 'user', 'profiles', 'accounts', 'messages', 'chats', 'posts',
  'orders', 'payments', 'products', 'items', 'settings', 'admin', 'config',
];

/** Extract Firebase project identifiers from client config in the source. */
export function discoverFirebase(all: Pick<ScanFile, 'content' | 'rel'>[]): FirebaseCreds | null {
  // Docs/examples must not contribute hosts we would then send requests to.
  const files = all.filter((f) => !/\.(md|txt|mdx|rst)$/i.test(f.rel));
  let projectId: string | undefined;
  let databaseURL: string | undefined;
  let storageBucket: string | undefined;

  // This loop runs against every project file's raw content, including large
  // ones — see `DNS_LABEL` in util/text.ts for why the two host regexes below
  // are bounded instead of `[a-z0-9-]+`.
  for (const f of files) {
    projectId ??= f.content.match(/projectId\s*:\s*["']([^"']+)["']/)?.[1];
    databaseURL ??= f.content.match(/databaseURL\s*:\s*["']([^"']+)["']/)?.[1]
      ?? f.content.match(FIREBASEIO_URL)?.[0];
    storageBucket ??= f.content.match(/storageBucket\s*:\s*["']([^"']+)["']/)?.[1];
    if (!projectId) {
      const dom = f.content.match(FIREBASEAPP_DOMAIN)?.[1];
      if (dom) projectId = dom;
    }
  }

  if (!projectId || looksLikePlaceholder(projectId)) return null;
  // Only keep hosts that belong to the project we will name in the consent prompt.
  return {
    projectId,
    databaseURL: databaseURL ? ownDatabaseURL(databaseURL, projectId) : undefined,
    storageBucket: storageBucket ? ownStorageBucket(storageBucket, projectId) : undefined,
  };
}

/** The RTDB hostnames Firebase itself issues for a project — nothing else can be "its" database. */
function isOwnRtdbHost(host: string, projectId: string): boolean {
  const p = projectId.toLowerCase();
  const regional = `${p}-default-rtdb.`; // <project>-default-rtdb.<region>.firebasedatabase.app
  return host === `${p}.firebaseio.com`
    || host === `${p}-default-rtdb.firebaseio.com`
    // `host` here is already `new URL(...).hostname` (bounded by the caller,
    // ownDatabaseURL below), not raw file content — but it's bounded via the
    // shared constant anyway rather than `+`, so this stays safe even if that
    // ever changes and nothing here looks unlike its two siblings above.
    || (host.startsWith(regional) && FIREBASEDATABASE_APP.test(host.slice(regional.length)))
    || host === `${p}.firebaseapp.com`;
}

/**
 * A `databaseURL` is the project's own only when its HOSTNAME is one Firebase
 * issues for that project. A substring match would accept
 * `https://unrelated.invalid/?project=<id>` and send probes to a stranger.
 * Only the origin is kept: a path or query string is never part of a database URL.
 */
function ownDatabaseURL(raw: string, projectId: string): string | undefined {
  let u: URL;
  try { u = new URL(raw.trim()); } catch { return undefined; }
  if (u.protocol !== 'https:' || !isOwnRtdbHost(u.hostname.toLowerCase(), projectId)) return undefined;
  return u.origin;
}

/** A bucket is the project's own only under the two names Firebase assigns it. */
function ownStorageBucket(raw: string, projectId: string): string | undefined {
  const name = raw.trim().replace(/^gs:\/\//i, '').replace(/\/.*$/, '').toLowerCase();
  const p = projectId.toLowerCase();
  return name === `${p}.appspot.com` || name === `${p}.firebasestorage.app` ? name : undefined;
}

export interface FirebaseProbeOptions {
  creds: FirebaseCreds;
  rateLimitMs?: number;
  log?: (msg: string) => void;
}

// The payload shapes that prove an anonymous read got real objects back. The
// body itself has already passed classifyBody (parsed JSON, not an error
// envelope, not truncated), so these only look at the shape.
function hasFirestoreDocs(v: unknown): boolean {
  const o = v as { documents?: unknown } | null;
  return Array.isArray(o?.documents) && o.documents.length > 0;
}
function hasStorageObjects(v: unknown): boolean {
  const o = v as { items?: unknown; prefixes?: unknown } | null;
  return (Array.isArray(o?.items) && o.items.length > 0) || (Array.isArray(o?.prefixes) && o.prefixes.length > 0);
}

/**
 * Probe Firebase RTDB, Firestore and Storage for anonymous read access.
 * Every response goes through classifyBody: a redirect, a truncated body, an
 * HTML page or an error envelope in place of JSON is an unverified sub-check
 * (run `partial`, named in the note), never "nothing readable".
 */
export async function probeFirebase(opts: FirebaseProbeOptions): Promise<FirebaseProbeResult> {
  const { creds } = opts;
  const rl = opts.rateLimitMs ?? 120;
  const log = opts.log ?? (() => {});
  const findings: Finding[] = [];
  let attempts = 0;
  const lost: string[] = []; // "what (reason)"

  // 1. Realtime Database: the root .json endpoint.
  const rtdbBase = creds.databaseURL?.replace(/\/$/, '') ?? `https://${creds.projectId}-default-rtdb.firebaseio.com`;
  await sleep(rl);
  const rtdb = classifyBody(await request(`${rtdbBase}/.json?shallow=true`), 'json');
  attempts++; if (rtdb.kind === 'unknown') lost.push(`RTDB (${rtdb.reason})`);
  if (rtdb.kind === 'data') {
    findings.push({
      id: 'firebase_rtdb_open',
      severity: 'critical',
      title: 'Realtime Database is readable without auth',
      detail: `${rtdbBase}/.json returned data to an unauthenticated request — the database rules are wide open.`,
      fix: 'Set RTDB rules to require auth and ownership, e.g. ".read": "auth != null && auth.uid === $uid".',
      checker: 'firebase-probe',
      level: 2,
      endpoint: `GET ${rtdbBase}/.json`,
    });
  }

  // 2. Firestore: probe common collection names.
  const readable: string[] = [];
  for (const col of COMMON_COLLECTIONS) {
    await sleep(rl);
    const res = classifyBody(await request(
      `https://firestore.googleapis.com/v1/projects/${creds.projectId}/databases/(default)/documents/${col}?pageSize=1`,
    ), 'json');
    attempts++; if (res.kind === 'unknown') lost.push(`firestore/${col} (${res.reason})`);
    if (res.kind === 'data' && hasFirestoreDocs(res.json)) {
      readable.push(col);
    }
  }
  if (readable.length > 0) {
    findings.push({
      id: 'firebase_firestore_open',
      severity: 'critical',
      title: 'Firestore collections readable without auth',
      detail: `Anonymous reads succeeded on: ${readable.join(', ')}. Firestore rules allow public reads.`,
      fix: 'Tighten firestore.rules: match /{doc=**} { allow read: if request.auth != null && ...owner check... }',
      checker: 'firebase-probe',
      level: 2,
      endpoint: `GET firestore/${readable[0]}`,
    });
  }

  // 3. Storage bucket object listing.
  const bucket = creds.storageBucket ?? `${creds.projectId}.appspot.com`;
  await sleep(rl);
  const storage = classifyBody(await request(`https://firebasestorage.googleapis.com/v0/b/${bucket}/o`), 'json');
  attempts++; if (storage.kind === 'unknown') lost.push(`storage/${bucket} (${storage.reason})`);
  if (storage.kind === 'data' && hasStorageObjects(storage.json)) {
    findings.push({
      id: 'firebase_storage_open',
      severity: 'critical',
      title: 'Storage bucket is listable without auth',
      detail: `Objects in ${bucket} can be listed anonymously.`,
      fix: 'Set Storage rules to require auth: match /{path=**} { allow read: if request.auth != null; }',
      checker: 'firebase-probe',
      level: 2,
      endpoint: `GET storage/${bucket}`,
    });
  }

  log(`Firebase: probed RTDB, ${COMMON_COLLECTIONS.length} Firestore collections, storage bucket ${bucket}`);

  const errors = lost.length;
  const status = errors === 0 ? 'completed' : errors < attempts ? 'partial' : 'failed';
  const note = errors > 0
    ? `${errors}/${attempts} probe(s) not verified: ${lost.slice(0, 5).join(', ')}${errors > 5 ? ', …' : ''}`
    : undefined;
  return { findings, run: { id: 'firebase-probe', level: 2, status, note } };
}
