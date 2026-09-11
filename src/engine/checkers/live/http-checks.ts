import type { CheckRun, Finding } from '../../types.js';
import { isErr, request, requestFollow, unreliable } from '../../net/http.js';

export interface LiveResult {
  findings: Finding[];
  run: CheckRun;
}

interface ExposedProbe {
  path: string;
  signature: RegExp;
  title: string;
  severity: 'critical' | 'warning';
}

const EXPOSED: ExposedProbe[] = [
  { path: '.env', signature: /^[A-Z0-9_]+=.+/m, title: '.env file served publicly', severity: 'critical' },
  { path: '.env.local', signature: /^[A-Z0-9_]+=.+/m, title: '.env.local served publicly', severity: 'critical' },
  { path: '.env.production', signature: /^[A-Z0-9_]+=.+/m, title: '.env.production served publicly', severity: 'critical' },
  { path: '.git/config', signature: /\[core\]|\[remote/, title: '.git/config served publicly', severity: 'critical' },
  { path: '.git/HEAD', signature: /^ref:\s/m, title: '.git/HEAD served publicly', severity: 'critical' },
  { path: 'backup.sql', signature: /CREATE TABLE|INSERT INTO/i, title: 'SQL backup served publicly', severity: 'critical' },
  { path: 'config.json', signature: /"[^"]*(api[_-]?key|secret|password|token|credential)[^"]*"\s*:/i, title: 'config.json served publicly', severity: 'warning' },
];

interface HeaderCheck {
  header: string;
  id: string;
  title: string;
}

const SECURITY_HEADERS: HeaderCheck[] = [
  { header: 'content-security-policy', id: 'missing_csp', title: 'Missing Content-Security-Policy' },
  { header: 'strict-transport-security', id: 'missing_hsts', title: 'Missing Strict-Transport-Security' },
  { header: 'x-frame-options', id: 'missing_xfo', title: 'Missing X-Frame-Options' },
  { header: 'x-content-type-options', id: 'missing_xcto', title: 'Missing X-Content-Type-Options' },
];

function looksLikeHtml(body: string): boolean {
  return /<!doctype html|<html[\s>]/i.test(body.slice(0, 400));
}

/** Passive live checks on a deployed URL: exposed files + security headers. */
export async function checkLiveSite(appUrl: string): Promise<LiveResult> {
  const base = appUrl.replace(/\/$/, '');
  const findings: Finding[] = [];

  // Track every file probe: a timeout/5xx/429 there is a lost sub-check, not "file absent".
  let fileErrors = 0;
  for (const probe of EXPOSED) {
    const res = await request(`${base}/${probe.path}`);
    if (isErr(res) || res.status === 429 || res.status >= 500) { fileErrors++; continue; }
    if (res.status !== 200) continue; // 404 etc. = that file is simply not served
    if (looksLikeHtml(res.body)) continue; // SPA catch-all, not the real file
    if (!probe.signature.test(res.body)) continue;
    findings.push({
      id: `exposed_${probe.path.replace(/[^a-z0-9]/gi, '_')}`,
      severity: probe.severity,
      title: probe.title,
      detail: `${base}/${probe.path} is served and returns file content, not an app page.`,
      fix: 'Block dotfiles and backups at the web server/CDN, and remove the file from the deploy output.',
      checker: 'live-site',
      level: 2,
      endpoint: `GET /${probe.path}`,
    });
  }

  // Follow redirects (bounded) so headers are read from the real page, not a 301/302 hop.
  // Only analyze headers on a reliable response — a 5xx/429 must not masquerade as "headers missing".
  const root = await requestFollow(base + '/');
  // Only a genuine 2xx page supports a verdict about its headers.
  if (!isErr(root) && root.status >= 200 && root.status < 300) {
    for (const h of SECURITY_HEADERS) {
      if (!root.headers.get(h.header)) {
        findings.push({
          id: h.id,
          severity: 'warning',
          title: h.title,
          detail: `The response for ${base}/ does not set ${h.header}.`,
          fix: `Add the ${h.header} header at the app or CDN layer.`,
          checker: 'live-site',
          level: 2,
          endpoint: 'GET /',
        });
      }
    }
    const powered = root.headers.get('x-powered-by');
    if (powered) {
      findings.push({
        id: 'server_disclosure',
        severity: 'info',
        title: 'Technology disclosed via X-Powered-By',
        detail: `Response advertises "${powered}", helping an attacker fingerprint the stack.`,
        fix: 'Remove or mask the X-Powered-By header.',
        checker: 'live-site',
        level: 2,
        endpoint: 'GET /',
      });
    }
    // Inspect each Set-Cookie separately — one hardened cookie must not mask another.
    const cookies = root.hopCookies?.length ? root.hopCookies : getSetCookies(root.headers);
    for (const c of cookies) {
      const name = c.split('=', 1)[0]?.trim() || 'cookie';
      const secure = /;\s*secure/i.test(c);
      const httpOnly = /;\s*httponly/i.test(c);
      if (!secure || !httpOnly) {
        const missing = [!secure ? 'Secure' : null, !httpOnly ? 'HttpOnly' : null].filter(Boolean).join(' + ');
        findings.push({
          id: 'cookie_flags',
          severity: 'warning',
          title: `Cookie "${name}" missing ${missing}`,
          detail: `Set-Cookie for "${name}" is missing ${missing}. If it is a session/auth cookie, that weakens it against theft.`,
          fix: 'Set Secure and HttpOnly (and SameSite) on session/auth cookies.',
          checker: 'live-site',
          level: 2,
          endpoint: 'GET /',
        });
      }
    }
  }

  // Aggregate: the root page AND every file probe count. Losing any sub-check = partial;
  // losing all of them = failed.
  const rootBad = unreliable(root) || (!isErr(root) && (root.status < 200 || root.status >= 300));
  const truncated = !isErr(root) && root.truncated === true;
  const status = rootBad && fileErrors === EXPOSED.length ? 'failed' : rootBad || fileErrors > 0 || truncated ? 'partial' : 'completed';
  const notes: string[] = [];
  if (rootBad) notes.push(isErr(root) ? `could not reach ${base}/: ${root.error}` : `no usable 2xx page (HTTP ${root.status}) at ${base}/`);
  if (fileErrors > 0) notes.push(`${fileErrors}/${EXPOSED.length} exposed-file probes errored`);
  if (!isErr(root) && root.truncated) notes.push('response body hit the 2 MB cap — content past it was not inspected');
  return { findings, run: { id: 'live-site', level: 2, status, note: notes.length ? notes.join('; ') : undefined } };
}

/** Get individual Set-Cookie header values (undici exposes getSetCookie()). */
function getSetCookies(headers: Headers): string[] {
  const withGetter = headers as Headers & { getSetCookie?: () => string[] };
  if (typeof withGetter.getSetCookie === 'function') return withGetter.getSetCookie();
  const single = headers.get('set-cookie');
  return single ? [single] : [];
}
