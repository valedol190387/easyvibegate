export interface HttpOk {
  status: number;
  ok: boolean;
  headers: Headers;
  body: string;
}
export interface HttpErr {
  error: string;
}
export type HttpResult = HttpOk | HttpErr;

export function isErr(r: HttpResult): r is HttpErr {
  return 'error' in r;
}

// Cap the response body we buffer so a huge/hostile response can't blow up memory.
const MAX_BODY_BYTES = 2 * 1024 * 1024; // 2 MB

async function readCapped(res: Response, max: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) {
    const t = await res.text();
    return t.length > max ? t.slice(0, max) : t;
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
  return Buffer.concat(chunks).subarray(0, max).toString('utf8');
}

/** fetch() with a hard timeout and no throw — network errors become { error }. */
export async function request(
  url: string,
  init: RequestInit = {},
  timeoutMs = 8000,
): Promise<HttpResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    // Default to not following redirects (safer for probing); callers may opt in.
    const res = await fetch(url, { redirect: 'manual', ...init, signal: controller.signal });
    const body = await readCapped(res, MAX_BODY_BYTES);
    return { status: res.status, ok: res.status >= 200 && res.status < 300, headers: res.headers, body };
  } catch (e) {
    return { error: e instanceof Error ? e.message : String(e) };
  } finally {
    clearTimeout(timer);
  }
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
  for (let hop = 0; hop <= maxHops; hop++) {
    const res = await request(current, { ...init, redirect: 'manual' }, timeoutMs);
    if (isErr(res)) return res;
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location');
      if (!loc) return res;
      try {
        current = new URL(loc, current).toString();
      } catch {
        return res;
      }
      continue;
    }
    return res;
  }
  return { error: `too many redirects (>${maxHops})` };
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
