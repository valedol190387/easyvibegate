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
    id: 'private_key',
    title: 'Private key material',
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
    severity: 'critical',
    fix: 'Remove the private key from the repo, rotate the key pair, and store secrets outside source control.',
  },
];

const GENERIC = /(?:api[_-]?key|secret|token|passwd|password|pwd|auth[_-]?token|access[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']([^"']{8,})["']/gi;

const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

export const secretsChecker: Checker = {
  id: 'secrets',
  title: 'Hardcoded secrets',
  level: 0,
  run(ctx) {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      const { content, rel } = file;

      for (const p of PATTERNS) {
        for (const m of content.matchAll(p.re)) {
          findings.push({
            id: p.id,
            severity: p.severity,
            title: p.title,
            detail: `${p.title} found in source: ${redact(m[0])}`,
            fix: p.fix,
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
            severity: 'critical',
            title: 'Supabase service_role key in source',
            detail: 'A service_role JWT bypasses Row Level Security entirely. It must never ship to the client or the repo.',
            fix: 'Remove it, rotate the service_role key in Supabase settings, and use it only in trusted server code.',
            checker: 'secrets',
            level: 0,
            file: rel,
            line: lineAt(content, m.index ?? 0),
            evidence: redact(m[0]),
          });
        }
      }

      // Generic key/secret assignments, filtered by placeholder + entropy.
      if (rel.endsWith('.md') || rel.endsWith('.txt')) continue;
      for (const m of content.matchAll(GENERIC)) {
        const value = m[1] ?? '';
        if (looksLikePlaceholder(value)) continue;
        if (shannonEntropy(value) < 3.2) continue;
        findings.push({
          id: 'generic_secret',
          severity: 'warning',
          title: 'Possible hardcoded secret',
          detail: `A high-entropy value is assigned to a secret-looking name: ${redact(value)}`,
          fix: 'If this is a real credential, move it to an env var and rotate it. If not, rename the variable or add `// vibegate-ignore`.',
          checker: 'secrets',
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
