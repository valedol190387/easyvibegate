import type { CheckRun, Finding, ScanFile } from '../../types.js';
import { isErr, request, sleep } from '../../net/http.js';

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
export function discoverFirebase(files: Pick<ScanFile, 'content'>[]): FirebaseCreds | null {
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

  return projectId ? { projectId, databaseURL, storageBucket } : null;
}

export interface FirebaseProbeOptions {
  creds: FirebaseCreds;
  rateLimitMs?: number;
  log?: (msg: string) => void;
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
  attempts++; if (isErr(rtdb)) errors++;
  if (!isErr(rtdb) && rtdb.status === 200 && rtdb.body.trim() !== 'null') {
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
    attempts++; if (isErr(res)) errors++;
    if (!isErr(res) && res.status === 200 && /"documents"|"name"/.test(res.body)) {
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
  attempts++; if (isErr(storage)) errors++;
  if (!isErr(storage) && storage.status === 200 && /"items"|"prefixes"/.test(storage.body)) {
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
