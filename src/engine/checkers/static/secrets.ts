import type { Checker, Finding, Severity } from '../../types.js';
import { decodeJwtPayload, lineAt, looksLikePlaceholder, redact, shannonEntropy } from '../../util/text.js';

interface Pattern {
  id: string;
  title: string;
  re: RegExp;
  severity: Severity;
  fix: string;
}

const PATTERNS: Pattern[] = [
  {
    id: 'openai_key',
    title: 'OpenAI API key',
    re: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
    severity: 'critical',
    fix: 'Remove the key from source, read it from a server-side env var, and rotate it in the OpenAI dashboard.',
  },
  {
    id: 'anthropic_key',
    title: 'Anthropic API key',
    re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    severity: 'critical',
    fix: 'Move the key to a server-side env var and rotate it in the Anthropic console.',
  },
  {
    id: 'aws_key',
    title: 'AWS access key ID',
    re: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: 'critical',
    fix: 'Deactivate the key in IAM, rotate it, and never commit AWS credentials.',
  },
  {
    id: 'stripe_live',
    title: 'Stripe live secret key',
    re: /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/g,
    severity: 'critical',
    fix: 'Roll the key in the Stripe dashboard immediately and keep it server-side only.',
  },
  {
    id: 'github_token',
    title: 'GitHub token',
    re: /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}\b|\bgithub_pat_[0-9A-Za-z_]{22,}\b/g,
    severity: 'critical',
    fix: 'Revoke the token in GitHub settings and use a secret store instead.',
  },
  {
    id: 'slack_token',
    title: 'Slack token',
    re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
    severity: 'critical',
    fix: 'Revoke the token in the Slack app settings and rotate it.',
  },
  {
    id: 'google_api_key',
    title: 'Google API key',
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    severity: 'warning',
    fix: 'Restrict the key by API and referrer, or move it server-side, then rotate it.',
  },
  {
    id: 'telegram_bot',
    title: 'Telegram bot token',
    re: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g,
    severity: 'warning',
    fix: 'Revoke the token via BotFather and keep it server-side.',
  },
  {
    id: 'supabase_secret_key',
    title: 'Supabase secret key',
    re: /\bsb_secret_[A-Za-z0-9_-]{10,}\b/g,
    severity: 'critical',
    fix: 'This is a Supabase secret key (full DB access). Remove it, rotate it in Supabase settings, and keep it server-side only.',
  },
  {
    id: 'private_key',
    title: 'Private key material',
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
    severity: 'critical',
    fix: 'Remove the private key from the repo, rotate the key pair, and store secrets outside source control.',
  },
];

const GENERIC = /(?:api[_-]?key|secret|token|passwd|password|pwd|auth[_-]?token|access[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']([^"']{8,})["']/gi;

// Unquoted env-style assignment (KEY=value), e.g. in .env / yaml / Dockerfile.
const ENV_SECRET = /^\s*(?:export\s+)?[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|API[_-]?KEY|ACCESS[_-]?KEY)[A-Z0-9_]*\s*=\s*([^\s"'#]{8,})/gim;

const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

/** Env files hold secrets by design — the risk there is committing them, which
 *  env-git flags. So a secret in an env file is a warning, not a source leak. */
function isEnvFile(rel: string): boolean {
  return rel === '.env' || /(^|\/)\.env(\.|$)/.test(rel) || /\.(ya?ml|toml|ini|conf)$/.test(rel) || /(^|\/)Dockerfile$/.test(rel) || rel.endsWith('docker-compose.yml') || rel.endsWith('docker-compose.yaml');
}

export const secretsChecker: Checker = {
  id: 'secrets',
  title: 'Hardcoded secrets',
  level: 0,
  run(ctx) {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      const { content, rel } = file;
      const env = isEnvFile(rel);

      for (const p of PATTERNS) {
        for (const m of content.matchAll(p.re)) {
          // A secret in a server env/config file is expected — the risk is
          // committing it (env-git flags that), so it is a warning, not a source leak.
          const severity = env && p.severity === 'critical' ? 'warning' : p.severity;
          findings.push({
            id: p.id,
            severity,
            title: env ? `${p.title} (in env/config file)` : p.title,
            detail: env
              ? `${p.title} in ${rel} (${redact(m[0])}). Normal for server env — keep this file gitignored and out of client bundles.`
              : `${p.title} found in source: ${redact(m[0])}`,
            fix: env
              ? 'Keep this file out of git and out of client bundles; rotate the value if it may have been committed.'
              : p.fix,
            checker: 'secrets',
            level: 0,
            file: rel,
            line: lineAt(content, m.index ?? 0),
            evidence: redact(m[0]),
          });
        }
      }

      // Supabase service_role key (a JWT whose payload role is service_role).
      for (const m of content.matchAll(JWT)) {
        const payload = decodeJwtPayload(m[0]);
        if (payload && payload['role'] === 'service_role') {
          findings.push({
            id: 'supabase_service_role_key',
            severity: env ? 'warning' : 'critical',
            title: env ? 'Supabase service_role key (in env/config file)' : 'Supabase service_role key in source',
            detail: env
              ? `A service_role JWT is in ${rel}. Fine for server env only — never commit it or ship it to the client; keep the file gitignored.`
              : 'A service_role JWT bypasses Row Level Security entirely and is in source/client code. It must never ship to the client or the repo.',
            fix: env
              ? 'Keep it server-side only, ensure the file is gitignored, and rotate it if it may have been committed.'
              : 'Remove it, rotate the service_role key in Supabase settings, and use it only in trusted server code.',
            checker: 'secrets',
            level: 0,
            file: rel,
            line: lineAt(content, m.index ?? 0),
            evidence: redact(m[0]),
          });
        }
      }

      if (rel.endsWith('.md') || rel.endsWith('.txt')) continue;

      // Quoted key/secret assignments in code, filtered by placeholder + entropy.
      for (const m of content.matchAll(GENERIC)) {
        const value = m[1] ?? '';
        if (looksLikePlaceholder(value) || shannonEntropy(value) < 3.2) continue;
        findings.push({
          id: 'generic_secret',
          severity: 'warning',
          title: 'Possible hardcoded secret',
          detail: `A high-entropy value is assigned to a secret-looking name: ${redact(value)}`,
          fix: 'If this is a real credential, move it to a server-side env var and rotate it. If not, rename the variable or add `// easyvibegate-ignore`.',
          checker: 'secrets',
          level: 0,
          file: rel,
          line: lineAt(content, m.index ?? 0),
          evidence: redact(value),
        });
      }

      // Unquoted env-style assignments (e.g. .env / yaml / Dockerfile).
      if (env) {
        for (const m of content.matchAll(ENV_SECRET)) {
          const value = m[1] ?? '';
          if (looksLikePlaceholder(value) || shannonEntropy(value) < 3.0) continue;
          findings.push({
            id: 'env_secret',
            severity: 'warning',
            title: 'Secret in env/config file',
            detail: `A high-entropy value is assigned to a secret-looking name in ${rel}: ${redact(value)}`,
            fix: 'Fine for server env — keep this file gitignored and out of the client; rotate if it may have leaked.',
            checker: 'secrets',
            level: 0,
            file: rel,
            line: lineAt(content, m.index ?? 0),
            evidence: redact(value),
          });
        }
      }
    }

    // De-duplicate multiple matches on the same file:line, keeping the most severe.
    const rank: Record<Severity, number> = { critical: 0, warning: 1, info: 2, advisory: 3 };
    const byLine = new Map<string, Finding>();
    const passthrough: Finding[] = [];
    for (const f of findings) {
      if (f.file === undefined || f.line === undefined) { passthrough.push(f); continue; }
      const key = `${f.file}:${f.line}`;
      const cur = byLine.get(key);
      if (!cur || rank[f.severity] < rank[cur.severity]) byLine.set(key, f);
    }
    return [...passthrough, ...byLine.values()];
  },
};
