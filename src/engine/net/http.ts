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

/** fetch() with a hard timeout and no throw — network errors become { error }. */
export async function request(
  url: string,
  init: RequestInit = {},
  timeoutMs = 8000,
): Promise<HttpResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    // Default to not following redirects (safer for probing); callers may opt in
    // via init.redirect: 'follow' (e.g. security-header checks on the real page).
    const res = await fetch(url, { redirect: 'manual', ...init, signal: controller.signal });
    const body = await res.text();
    return { status: res.status, ok: res.status >= 200 && res.status < 300, headers: res.headers, body };
  } catch (e) {
    return { error: e instanceof Error ? e.message : String(e) };
  } finally {
    clearTimeout(timer);
  }
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
