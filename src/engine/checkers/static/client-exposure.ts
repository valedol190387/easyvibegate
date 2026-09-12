import type { Checker, Finding } from '../../types.js';
import { lineAt, looksLikePlaceholder, redact } from '../../util/text.js';
import { classifyKey } from '../backend/supabase.js';

// Public env prefixes are inlined into the browser bundle by the bundler.
const PUBLIC_PREFIX = '(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|GATSBY_|PUBLIC_)';

// Every public-prefixed assignment; what it carries is decided by the VALUE
// first and the NAME second (below).
const PUBLIC_ASSIGN = new RegExp(`\\b(${PUBLIC_PREFIX}[A-Z0-9_]*)\\s*[:=]\\s*["']?([^"'\\s]{6,})`, 'gi');

// A public var whose NAME implies a real secret (not an anon/publishable key).
const SECRET_NAME = /(SERVICE_ROLE|SECRET|PRIVATE|PASSWORD|PASSWD|TOKEN|CREDENTIAL|API_KEY|ACCESS_KEY)/i;

// Value shapes that are server secrets no matter what the variable is called.
const SERVER_SECRET_VALUE = /^(?:sk_live_|rk_live_|sk-ant-|sk-(?:proj-)?[A-Za-z0-9_-]{20,}$)/;
const FIREBASE_WEB_KEY = /^AIza[0-9A-Za-z_-]{35}$/;

type ValueKind = 'server-secret' | 'client-key' | 'unknown';

/**
 * A key is public or secret by what it IS, not by what the variable is named.
 * A Supabase publishable key or a Firebase Web API key stored under a public
 * *_API_KEY name was reported as a leaked server secret with "rotate it"
 * advice, although both are designed to ship to the browser. Conversely a
 * service_role JWT behind a public *_KEY name (no secret word) went unreported.
 */
function classifyValue(value: string): ValueKind {
  const sb = classifyKey(value);
  if (sb === 'publishable' || sb === 'jwt-anon') return 'client-key';
  if (sb === 'secret' || sb === 'jwt-service' || sb === 'jwt-authenticated') return 'server-secret';
  if (FIREBASE_WEB_KEY.test(value)) return 'client-key';
  if (SERVER_SECRET_VALUE.test(value)) return 'server-secret';
  return 'unknown';
}

export const clientExposureChecker: Checker = {
  id: 'client-exposure',
  title: 'Secrets exposed to the browser',
  level: 0,
  run(ctx) {
    const findings: Finding[] = [];
    // The same public key is typically repeated across .env, .env.local and
    // config; one advisory per file+value is enough.
    const advised = new Set<string>();

    for (const file of ctx.files) {
      const { content, rel } = file;

      for (const m of content.matchAll(PUBLIC_ASSIGN)) {
        const name = m[1] ?? '';
        const value = m[2] ?? '';
        if (looksLikePlaceholder(value)) continue;
        const kind = classifyValue(value);
        const line = lineAt(content, m.index ?? 0);

        if (kind === 'client-key') {
          const key = `${rel}:${value}`;
          if (advised.has(key)) continue;
          advised.add(key);
          findings.push({
            id: 'public_key_client',
            severity: 'advisory',
            title: 'Public client key behind a public env var',
            detail: `${name} carries a key designed for the browser (${redact(value)}) — an anon/publishable Supabase key or a Firebase Web API key. It is not a leak by itself: its safety depends entirely on Row Level Security / Firebase security rules / API key restrictions.`,
            fix: 'Keep it public, and make the server side enforce access: enable RLS with policies on every table (Supabase), lock down security rules (Firebase), and restrict the key by API and HTTP referrer (Google Cloud console).',
            checker: 'client-exposure',
            level: 0,
            file: rel,
            line,
            evidence: redact(value),
          });
          continue;
        }

        // A proven server secret is critical regardless of the name; an
        // unknown value is critical only when the NAME says it is a secret.
        if (kind !== 'server-secret' && !SECRET_NAME.test(name)) continue;
        findings.push({
          id: 'public_env_secret',
          severity: 'critical',
          title: 'Server secret exposed via a public env var',
          detail: `A public-prefixed variable carries a secret-looking value (${redact(value)}). Anything with a public prefix is shipped to the browser.`,
          fix: 'Drop the public prefix, read this value only in server code, and rotate it — it may already be in a deployed bundle.',
          checker: 'client-exposure',
          level: 0,
          file: rel,
          line,
          evidence: redact(value),
        });
      }
    }

    return findings;
  },
};
