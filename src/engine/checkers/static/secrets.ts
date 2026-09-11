import type { Checker, Finding, Severity } from '../../types.js';
import { decodeJwtPayload, lineAt, looksLikePlaceholder, redact, shannonEntropy } from '../../util/text.js';

interface Pattern {
  id: string;
  title: string;
  re: RegExp;
  severity: Severity;
  fix: string;
  /** Extra shape check on the match — kills look-alikes (e.g. CSS class names). */
  validate?: (match: string) => boolean;
}

/** Real tokens mix case and digits; kebab-case identifiers do not. */
function looksRandom(s: string): boolean {
  const body = s.replace(/^[a-z]+[-_]/i, '');
  return /[A-Z]/.test(body) && /[0-9]/.test(body) && shannonEntropy(body) >= 3.2;
}

const PATTERNS: Pattern[] = [
  {
    id: 'openai_key',
    title: 'OpenAI API key',
    re: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
    severity: 'critical',
    fix: 'Remove the key from source, read it from a server-side env var, and rotate it in the OpenAI dashboard.',
    // ".sk-chase-dot-before-animation-delay" is a CSS class, not a key.
    validate: looksRandom,
  },
  {
    id: 'anthropic_key',
    title: 'Anthropic API key',
    re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    severity: 'critical',
    fix: 'Move the key to a server-side env var and rotate it in the Anthropic console.',
    validate: looksRandom,
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
    id: 'sendgrid_key',
    title: 'SendGrid API key',
    re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
    severity: 'critical',
    fix: 'Revoke the key in SendGrid and store it server-side only.',
  },
  {
    id: 'hf_token',
    title: 'Hugging Face token',
    re: /\bhf_[A-Za-z0-9]{30,}\b/g,
    severity: 'critical',
    fix: 'Revoke the token in Hugging Face settings and keep it server-side.',
  },
  {
    id: 'npm_token',
    title: 'npm access token',
    re: /\bnpm_[A-Za-z0-9]{30,}\b/g,
    severity: 'critical',
    fix: 'Revoke the token on npmjs.com and use a CI secret instead.',
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
    id: 'db_url_password',
    title: 'Database URL with an inline password',
    re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^\s:/@"']+:([^\s:/@"']{4,})@[^\s"']+/gi,
    severity: 'critical',
    fix: 'Move the connection string to a server-side env var and rotate the database password — a committed DB URL grants full data access.',
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

const GENERIC = /(?:api[_-]?key|secret|token|passwd|password|pwd|auth[_-]?token|access[_-]?token|client[_-]?secret|credential)["']?\s*[:=]\s*["']([^"']{8,})["']/gi;

const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

// KEY=value / key: value / Dockerfile ENV|ARG KEY=value, with a secret-looking NAME.
const ASSIGN = /^[ \t]*(?:export[ \t]+|ENV[ \t]+|ARG[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*[:=][ \t]*(.+)$/gm;
const SECRET_NAME = /(secret|token|password|passwd|private[_-]?key|api[_-]?key|access[_-]?key|credential)/i;

/** Only .env* files are "server env by design" — a secret there is a warning
 *  (env-git flags committing it). In real code/config it stays a source leak. */
function isEnvFile(rel: string): boolean {
  return /(^|\/)\.env($|\.)/.test(rel) && !/\.(example|sample|template)$/.test(rel);
}

/** Files where name=value secrets are worth scanning (env + common config). */
function isConfigish(rel: string): boolean {
  return /(^|\/)\.env($|\.)/.test(rel) || /\.(ya?ml|toml|ini|conf|properties|npmrc|netrc)$/.test(rel)
    || /(^|\/)(Dockerfile|\.npmrc|\.netrc)$/.test(rel) || /docker-compose\.ya?ml$/.test(rel);
}

/**
 * Documentation, examples and test fixtures are where sample keys legitimately
 * live. A hit there is worth mentioning but is not a credential leak.
 */
function isExampleContext(rel: string): boolean {
  return /\.(md|txt|mdx|rst)$/i.test(rel)
    || /\.(example|sample|template|dist)$/i.test(rel)
    || /(^|\/)(docs?|examples?|fixtures?|__fixtures__|__tests__|test|tests|spec|__mocks__)(\/|$)/i.test(rel)
    || /\.(test|spec)\.[a-z]+$/i.test(rel);
}

export const secretsChecker: Checker = {
  id: 'secrets',
  title: 'Hardcoded secrets',
  level: 0,
  run(ctx) {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      const { rel } = file;
      const content = file.content.replace(/^\uFEFF/, ''); // a BOM must not eat line 1
      const env = isEnvFile(rel);
      const example = isExampleContext(rel);

      const push = (f: Finding) => {
        if (example) {
          findings.push({
            ...f,
            severity: 'info',
            title: `${f.title} (in docs/example file)`,
            detail: `${f.detail} This looks like documentation or a fixture — confirm it is not a real credential.`,
          });
        } else findings.push(f);
      };

      for (const p of PATTERNS) {
        for (const m of content.matchAll(p.re)) {
          const hit = m[0];
          if (looksLikePlaceholder(hit)) continue; // YOUR_KEY / EXAMPLE / xxxxx / <...>
          if (p.validate && !p.validate(hit)) continue;
          // A secret in a server env/config file is expected — the risk is
          // committing it (env-git flags that), so it is a warning, not a leak.
          const severity = env && p.severity === 'critical' ? 'warning' : p.severity;
          push({
            id: p.id,
            severity,
            title: env ? `${p.title} (in env/config file)` : p.title,
            detail: env
              ? `${p.title} in ${rel} (${redact(hit)}). Normal for server env — keep this file gitignored and out of client bundles.`
              : `${p.title} found in source: ${redact(hit)}`,
            fix: env ? 'Keep this file out of git and out of client bundles; rotate the value if it may have been committed.' : p.fix,
            checker: 'secrets',
            level: 0,
            file: rel,
            line: lineAt(content, m.index ?? 0),
            evidence: redact(hit),
          });
        }
      }

      // Supabase service_role key (a JWT whose payload role is service_role).
      for (const m of content.matchAll(JWT)) {
        const payload = decodeJwtPayload(m[0]);
        if (payload && payload['role'] === 'service_role') {
          push({
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

      // Quoted key/secret assignments in code, filtered by placeholder + entropy.
      for (const m of content.matchAll(GENERIC)) {
        const value = m[1] ?? '';
        if (looksLikePlaceholder(value) || shannonEntropy(value) < 3.2) continue;
        push({
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

      // name=value / key: value assignments (env, config, Dockerfile ENV/ARG).
      if (isConfigish(rel)) {
        for (const m of content.matchAll(ASSIGN)) {
          const name = m[1] ?? '';
          if (!SECRET_NAME.test(name)) continue;
          const value = (m[2] ?? '').trim().replace(/^["']|["']$/g, '').replace(/["'].*$/, '');
          if (value.length < 8 || looksLikePlaceholder(value) || shannonEntropy(value) < 3.0) continue;
          push({
            id: 'env_secret',
            severity: 'warning',
            title: env ? 'Secret in env file' : 'Secret in config file',
            detail: `"${name}" holds a high-entropy value in ${rel}: ${redact(value)}`,
            fix: env
              ? 'Fine for server env — keep this file gitignored and out of the client; rotate if it may have leaked.'
              : 'Move this secret out of committed config into a server-side secret store, and rotate it.',
            checker: 'secrets',
            level: 0,
            file: rel,
            line: lineAt(content, m.index ?? 0),
            evidence: redact(value),
          });
        }
      }
    }

    // De-duplicate only true repeats: the same secret, same place, same rule.
    // (Keying on file:line alone hid every extra key on a minified line.)
    const rank: Record<Severity, number> = { critical: 0, warning: 1, info: 2, advisory: 3 };
    const seen = new Map<string, Finding>();
    for (const f of findings) {
      const key = `${f.file ?? ''}:${f.line ?? 0}:${f.id}:${f.evidence ?? ''}`;
      const cur = seen.get(key);
      if (!cur || rank[f.severity] < rank[cur.severity]) seen.set(key, f);
    }
    return [...seen.values()];
  },
};
