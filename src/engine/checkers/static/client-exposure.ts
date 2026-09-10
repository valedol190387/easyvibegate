import type { Checker, Finding } from '../../types.js';
import { lineAt, looksLikePlaceholder, redact } from '../../util/text.js';

// Public env prefixes are inlined into the browser bundle by the bundler.
const PUBLIC_PREFIX = '(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|GATSBY_|PUBLIC_)';

// A public var whose NAME implies a real secret (not an anon/publishable key).
const PUBLIC_SECRET = new RegExp(
  `\\b${PUBLIC_PREFIX}[A-Z0-9_]*(SERVICE_ROLE|SECRET|PRIVATE|PASSWORD|PASSWD)[A-Z0-9_]*\\s*[:=]\\s*["']?([^"'\\s]{6,})`,
  'g',
);

export const clientExposureChecker: Checker = {
  id: 'client-exposure',
  title: 'Secrets exposed to the browser',
  level: 0,
  run(ctx) {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      const { content, rel } = file;

      for (const m of content.matchAll(PUBLIC_SECRET)) {
        const value = m[2] ?? '';
        if (looksLikePlaceholder(value)) continue;
        findings.push({
          id: 'public_env_secret',
          severity: 'critical',
          title: 'Server secret exposed via a public env var',
          detail: `A public-prefixed variable carries a secret-looking value (${redact(value)}). Anything with a public prefix is shipped to the browser.`,
          fix: 'Drop the public prefix, read this value only in server code, and rotate it — it may already be in a deployed bundle.',
          checker: 'client-exposure',
          level: 0,
          file: rel,
          line: lineAt(content, m.index ?? 0),
          evidence: redact(value),
        });
      }
    }

    return findings;
  },
};
