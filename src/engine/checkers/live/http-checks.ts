import type { Finding } from '../../types.js';
import { isErr, request } from '../../net/http.js';

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
  { path: 'config.json', signature: /[{][\s\S]*(key|secret|password|token)/i, title: 'config.json served publicly', severity: 'warning' },
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
export async function checkLiveSite(appUrl: string): Promise<Finding[]> {
  const base = appUrl.replace(/\/$/, '');
  const findings: Finding[] = [];

  for (const probe of EXPOSED) {
    const res = await request(`${base}/${probe.path}`);
    if (isErr(res) || res.status !== 200) continue;
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

  // Follow redirects so headers are read from the real page, not a 301/302 hop.
  const root = await request(base + '/', { redirect: 'follow' });
  if (!isErr(root)) {
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
    const setCookie = root.headers.get('set-cookie');
    if (setCookie && (!/httponly/i.test(setCookie) || !/secure/i.test(setCookie))) {
      findings.push({
        id: 'cookie_flags',
        severity: 'warning',
        title: 'Cookie missing Secure/HttpOnly',
        detail: 'A cookie is set without both Secure and HttpOnly flags.',
        fix: 'Set Secure and HttpOnly (and SameSite) on session cookies.',
        checker: 'live-site',
        level: 2,
        endpoint: 'GET /',
      });
    }
  }

  return findings;
}
