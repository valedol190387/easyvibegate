export interface HttpOk {
  status: number;
  ok: boolean;
  headers: Headers;
  body: string;
  /** The body hit the buffer cap — anything past it was not seen. */
  truncated?: boolean;
  /** Set-Cookie values seen on every hop of a followed redirect chain. */
  hopCookies?: string[];
}
export interface HttpErr {
  error: string;
}
export type HttpResult = HttpOk | HttpErr;

export function isErr(r: HttpResult): r is HttpErr {
  return 'error' in r;
}

/** A transport error, a 429, or a 5xx — the response can't be trusted as a real result. */
export function unreliable(r: HttpResult): boolean {
  return isErr(r) || r.status === 429 || r.status >= 500;
}

// Cap the response body we buffer so a huge/hostile response can't blow up memory.
const MAX_BODY_BYTES = 2 * 1024 * 1024; // 2 MB

async function readCapped(res: Response, max: number): Promise<{ text: string; truncated: boolean }> {
  const reader = res.body?.getReader();
  if (!reader) {
    const t = await res.text();
    return t.length > max ? { text: t.slice(0, max), truncated: true } : { text: t, truncated: false };
  }
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
      total += value.byteLength;
      if (total >= max) {
        try { await reader.cancel(); } catch { /* ignore */ }
        break;
      }
    }
  }
  const buf = Buffer.concat(chunks);
  const truncated = total >= max;
  // Decode without leaving a mangled partial character at the cut.
  const text = new TextDecoder('utf-8', { fatal: false }).decode(buf.subarray(0, max)).replace(/\uFFFD$/, '');
  return { text, truncated };
}

export type RequestFn = (url: string, init?: RequestInit, timeoutMs?: number) => Promise<HttpResult>;

/** The real network implementation: fetch() with a hard timeout and no throw. */
async function realRequest(url: string, init: RequestInit = {}, timeoutMs = 8000): Promise<HttpResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    // Default to not following redirects (safer for probing); callers may opt in.
    const res = await fetch(url, { redirect: 'manual', ...init, signal: controller.signal });
    const { text, truncated } = await readCapped(res, MAX_BODY_BYTES);
    return { status: res.status, ok: res.status >= 200 && res.status < 300, headers: res.headers, body: text, truncated };
  } catch (e) {
    return { error: e instanceof Error ? e.message : String(e) };
  } finally {
    clearTimeout(timer);
  }
}

let impl: RequestFn = realRequest;

/** All probes go through here, so tests can swap the network for a fake. */
export function request(url: string, init: RequestInit = {}, timeoutMs = 8000): Promise<HttpResult> {
  return impl(url, init, timeoutMs);
}

/** Test hook: replace the network implementation (pass null to restore). */
export function setRequestImpl(fn: RequestFn | null): void {
  impl = fn ?? realRequest;
}

/**
 * Like request(), but follows redirects manually up to `maxHops`, so redirect
 * chains are bounded (no loops / unbounded following). Hosts are NOT restricted
 * because scanning your own app on localhost/dev is a first-class use case.
 */
export async function requestFollow(
  url: string,
  init: RequestInit = {},
  timeoutMs = 8000,
  maxHops = 5,
): Promise<HttpResult> {
  let current = url;
  const hopCookies: string[] = [];
  for (let hop = 0; hop <= maxHops; hop++) {
    const res = await request(current, { ...init, redirect: 'manual' }, timeoutMs);
    if (isErr(res)) return res;
    // A session cookie is usually set on the login redirect, not the final page.
    const withGetter = res.headers as Headers & { getSetCookie?: () => string[] };
    hopCookies.push(...(typeof withGetter.getSetCookie === 'function'
      ? withGetter.getSetCookie()
      : (res.headers.get('set-cookie') ? [res.headers.get('set-cookie') as string] : [])));
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location');
      if (!loc) return res;
      let next: URL;
      try {
        next = new URL(loc, current);
      } catch {
        return res;
      }
      // Staying on the target origin is the point: otherwise a third party's
      // headers/body would be credited to the app we were asked to check.
      if (next.origin !== new URL(url).origin) {
        return { error: `redirect left the target origin (${next.origin})` };
      }
      current = next.toString();
      continue;
    }
    return { ...res, hopCookies };
  }
  return { error: `too many redirects (>${maxHops})` };
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * What a response proves about the resource behind it:
 *   data    — 2xx with real content (non-empty JSON / non-empty body)
 *   empty   — 2xx but nothing in it ([] / {} / "" / 204)
 *   denied  — 401/403: the server answered and refused
 *   absent  — 404/405/410: nothing (for this method) at that URL. Whether that
 *             is conclusive depends on whether the URL was guessed — a 404 for
 *             a guessed id proves nothing, a 404 for a well-known API does.
 *   unknown — cannot be interpreted: transport error, 5xx/429, a redirect,
 *             truncated body, HTML/unparseable where JSON was expected, an
 *             error envelope, or any other 4xx.
 * Only data/empty/denied (and absent, where the URL was not guessed) are a
 * finished sub-check. `unknown` is lost coverage and must surface as `partial`.
 */
export type BodyKind = 'data' | 'empty' | 'denied' | 'absent' | 'unknown';

export interface BodyVerdict {
  kind: BodyKind;
  /** Short human reason, for the run note (e.g. "HTTP 404", "truncated body"). */
  reason: string;
  /** The parsed payload when `expect` was 'json' and the body parsed. */
  json?: unknown;
}

export function looksLikeHtml(body: string): boolean {
  return /<!doctype html|<html[\s>]|<head[\s>]|<body[\s>]/i.test(body.slice(0, 600));
}

/** A parsed JSON value with content. Error envelopes are handled by the caller. */
function jsonHasContent(v: unknown): boolean {
  if (v === null || v === undefined) return false;
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === 'object') return Object.keys(v as object).length > 0;
  if (typeof v === 'string') return v.length > 0;
  return true; // a bare number/boolean is content
}

/**
 * The ONE place a probe response is turned into a verdict, so every live check
 * applies the same rules (a truncated or unparseable body is never "clean").
 * `expect: 'json'` requires a parsable JSON body; `'any'` accepts any bytes.
 */
export function classifyBody(res: HttpResult, expect: 'json' | 'any'): BodyVerdict {
  if (isErr(res)) return { kind: 'unknown', reason: res.error };
  const { status } = res;
  if (status === 429 || status >= 500) return { kind: 'unknown', reason: `HTTP ${status}` };
  // A redirect is never evidence of absence — the resource may sit behind the hop.
  if (status >= 300 && status < 400) return { kind: 'unknown', reason: `HTTP ${status} redirect not followed` };
  if (status === 401 || status === 403) return { kind: 'denied', reason: `HTTP ${status}` };
  if (status === 404 || status === 405 || status === 410) return { kind: 'absent', reason: `HTTP ${status}` };
  if (status < 200 || status >= 300) return { kind: 'unknown', reason: `HTTP ${status}` };
  // Anything past the cap was not seen, so neither "no data" nor "no signature" holds.
  if (res.truncated) return { kind: 'unknown', reason: 'body truncated at the 2 MB cap' };
  if (status === 204) return { kind: 'empty', reason: 'HTTP 204' };

  const body = res.body;
  if (expect === 'any') {
    return body.trim().length > 0 ? { kind: 'data', reason: `HTTP ${status}` } : { kind: 'empty', reason: 'empty body' };
  }

  const ctype = (res.headers.get('content-type') ?? '').toLowerCase();
  if (ctype.includes('text/html') || looksLikeHtml(body)) return { kind: 'unknown', reason: 'HTML page where JSON was expected' };
  const t = body.trim();
  if (t.length === 0) return { kind: 'empty', reason: 'empty body' };
  let json: unknown;
  try {
    json = JSON.parse(t);
  } catch {
    return { kind: 'unknown', reason: 'body is not JSON' };
  }
  // `{"error": …}` with a 2xx is the server telling us something went wrong,
  // not an (empty) resource — it cannot be counted as checked.
  if (json && typeof json === 'object' && !Array.isArray(json)) {
    const o = json as Record<string, unknown>;
    if ('error' in o || 'errors' in o) return { kind: 'unknown', reason: 'error envelope in a 2xx body', json };
  }
  return jsonHasContent(json)
    ? { kind: 'data', reason: `HTTP ${status}`, json }
    : { kind: 'empty', reason: 'empty JSON', json };
}
