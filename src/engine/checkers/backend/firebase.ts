import type { CheckRun, Finding, ScanFile } from '../../types.js';
import { isErr, request, sleep, unreliable } from '../../net/http.js';
import { looksLikePlaceholder } from '../../util/text.js';

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

  for (const f of files) {
    projectId ??= f.content.match(/projectId\s*:\s*["']([^"']+)["']/)?.[1];
    databaseURL ??= f.content.match(/databaseURL\s*:\s*["']([^"']+)["']/)?.[1]
      ?? f.content.match(/https:\/\/[a-z0-9-]+(?:-default-rtdb)?\.firebaseio\.com/)?.[0];
    storageBucket ??= f.content.match(/storageBucket\s*:\s*["']([^"']+)["']/)?.[1];
    if (!projectId) {
      const dom = f.content.match(/([a-z0-9-]+)\.firebaseapp\.com/)?.[1];
      if (dom) projectId = dom;
    }
  }

  if (!projectId || looksLikePlaceholder(projectId)) return null;
  // Only keep hosts that belong to the project we will name in the consent prompt.
  if (databaseURL && !databaseURL.includes(projectId)) databaseURL = undefined;
  if (storageBucket && !storageBucket.includes(projectId)) storageBucket = undefined;
  return { projectId, databaseURL, storageBucket };
}

export interface FirebaseProbeOptions {
  creds: FirebaseCreds;
  rateLimitMs?: number;
  log?: (msg: string) => void;
}

/** Only a parsable, non-empty JSON payload proves anonymous read access. */
function hasJsonData(body: string): boolean {
  try {
    const v = JSON.parse(body) as unknown;
    if (v === null || v === undefined) return false;
    if (Array.isArray(v)) return v.length > 0;
    if (typeof v === 'object') {
      const o = v as Record<string, unknown>;
      if ('error' in o) return false;
      return Object.keys(o).length > 0;
    }
    return true;
  } catch { return false; }
}
function hasFirestoreDocs(body: string): boolean {
  try {
    const v = JSON.parse(body) as { documents?: unknown[]; error?: unknown };
    return !v.error && Array.isArray(v.documents) && v.documents.length > 0;
  } catch { return false; }
}
function hasStorageObjects(body: string): boolean {
  try {
    const v = JSON.parse(body) as { items?: unknown[]; prefixes?: unknown[]; error?: unknown };
    return !v.error && ((Array.isArray(v.items) && v.items.length > 0) || (Array.isArray(v.prefixes) && v.prefixes.length > 0));
  } catch { return false; }
}

/** Probe Firebase RTDB, Firestore and Storage for anonymous read access. */
export async function probeFirebase(opts: FirebaseProbeOptions): Promise<FirebaseProbeResult> {
  const { creds } = opts;
  const rl = opts.rateLimitMs ?? 120;
  const log = opts.log ?? (() => {});
  const findings: Finding[] = [];
  let attempts = 0;
  let errors = 0;

  // 1. Realtime Database: the root .json endpoint.
  const rtdbBase = creds.databaseURL?.replace(/\/$/, '') ?? `https://${creds.projectId}-default-rtdb.firebaseio.com`;
  await sleep(rl);
  const rtdb = await request(`${rtdbBase}/.json?shallow=true`);
  attempts++; if (unreliable(rtdb) || (!isErr(rtdb) && rtdb.status >= 300 && rtdb.status < 400)) errors++;
  if (!isErr(rtdb) && rtdb.status === 200 && hasJsonData(rtdb.body)) {
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
    const res = await request(
      `https://firestore.googleapis.com/v1/projects/${creds.projectId}/databases/(default)/documents/${col}?pageSize=1`,
    );
    attempts++; if (unreliable(res) || (!isErr(res) && res.status >= 300 && res.status < 400)) errors++;
    if (!isErr(res) && res.status === 200 && hasFirestoreDocs(res.body)) {
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
  const storage = await request(`https://firebasestorage.googleapis.com/v0/b/${bucket}/o`);
  attempts++; if (unreliable(storage) || (!isErr(storage) && storage.status >= 300 && storage.status < 400)) errors++;
  if (!isErr(storage) && storage.status === 200 && hasStorageObjects(storage.body)) {
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

  const status = errors === 0 ? 'completed' : errors < attempts ? 'partial' : 'failed';
  const note = errors > 0 ? `${errors}/${attempts} requests errored` : undefined;
  return { findings, run: { id: 'firebase-probe', level: 2, status, note } };
}
