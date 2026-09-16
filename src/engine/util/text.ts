/** Shannon entropy (bits per char) of a string. High for real secrets. */
export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq: Record<string, number> = {};
  for (const ch of s) freq[ch] = (freq[ch] ?? 0) + 1;
  let e = 0;
  for (const count of Object.values(freq)) {
    const p = count / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

/** Mask a sensitive value so it is safe to print in a report. */
export function redact(s: string): string {
  const t = s.trim();
  if (t.length <= 8) return '***';
  return `${t.slice(0, 4)}…${t.slice(-3)}`;
}

/** 1-based line number of a character offset inside `content`. */
export function lineAt(content: string, index: number): number {
  let line = 1;
  const stop = Math.min(index, content.length);
  for (let i = 0; i < stop; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}

const PLACEHOLDER = /(x{3,}|your[_-]?|<[^>]+>|\$\{|process\.env|import\.meta\.env|example|placeholder|changeme|dummy|test[_-]?key|xxxxx|\.\.\.)/i;

/** True if a captured value looks like a template/placeholder, not a real secret. */
export function looksLikePlaceholder(value: string): boolean {
  return PLACEHOLDER.test(value);
}

/** Decode a JWT payload without verifying the signature. Returns null on failure. */
export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const json = Buffer.from(parts[1]!, 'base64url').toString('utf8');
    const obj = JSON.parse(json);
    return typeof obj === 'object' && obj !== null ? obj : null;
  } catch {
    return null;
  }
}

/**
 * A DNS label, bounded to its real maximum (RFC 1035, 63 octets) — never `+`.
 * Used right before a literal host suffix (`.firebaseapp.com`, `.supabase.co`)
 * in a regex run against raw, unbounded file content. An open `[a-z0-9-]+` in
 * that position is a classic quadratic-time regex: at every position inside a
 * long run of matching characters (a minified bundle, a base64 blob, a lockfile
 * hash) the engine greedily consumes to the end and backtracks one character at
 * a time looking for a literal that never comes. Measured: a 500KB matching run
 * took over two minutes unbounded; bounded, the same file scans in single-digit
 * milliseconds — and no real hostname label is longer than this anyway.
 */
export const DNS_LABEL = '[a-z0-9-]{1,63}';
