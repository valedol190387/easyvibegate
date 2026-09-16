import type { Checker, Finding, Severity } from '../../types.js';
import { decodeJwtPayload, lineAt, looksLikePlaceholder, looksLikeTestOrDocPath, redact, shannonEntropy } from '../../util/text.js';
import { createExposure, type Exposure } from '../../util/git-exposure.js';
import { partitionIgnores, type VibegateConfig } from '../../config.js';

/** No project-wide rules — used to run ONLY the inline-marker half of partitionIgnores. */
const EMPTY_CONFIG: VibegateConfig = { ignore: [], ignorePaths: [] };

/** Lower number = more severe. One copy, used both to cap a severity and to rank duplicates. */
const SEVERITY_RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2, advisory: 3 };
const atMost = (sev: Severity, cap: Severity): Severity => (SEVERITY_RANK[sev] < SEVERITY_RANK[cap] ? cap : sev);

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

/**
 * Detectors whose match is key MATERIAL by structure (a vendor prefix plus a
 * random body, a PEM block, a DB password), as opposed to the name-based
 * heuristics (generic_secret / env_secret). A hit from one of these in a
 * docs/fixtures path is still a leak if the value is real — a fresh RSA key
 * pasted into docs/deploy.md was once downgraded to info and PASSed the gate.
 */
const HIGH_CONFIDENCE = new Set([
  'openai_key', 'anthropic_key', 'aws_key', 'stripe_live', 'github_token', 'slack_token',
  'sendgrid_key', 'hf_token', 'npm_token', 'db_url_password', 'supabase_secret_key', 'private_key',
]);

const PEM_END = /-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/;

/**
 * Whether a high-confidence hit has the body of a real credential, so a
 * docs/example path alone must not silence it. Anything obviously hand-typed
 * (a PEM with no base64 body, a DB URL whose password is a plain word, a key
 * with no digits) is treated as a sample and may still go to info.
 */
function looksLikeRealMaterial(id: string, hit: string, content: string, index: number, group?: string): boolean {
  if (id === 'private_key') {
    // The regex only matches the header; the material is what follows it.
    const rest = content.slice(index + hit.length);
    const endAt = rest.search(PEM_END);
    const body = (endAt >= 0 ? rest.slice(0, endAt) : rest.slice(0, 4096)).replace(/\s+/g, '');
    return body.length >= 64 && /^[A-Za-z0-9+/=]+$/.test(body);
  }
  if (id === 'db_url_password') {
    const pw = group ?? '';
    return /[0-9]/.test(pw) && /[A-Za-z]/.test(pw) && shannonEntropy(pw) >= 3.0;
  }
  if (id === 'aws_key') return /[0-9]/.test(hit);
  return looksRandom(hit);
}

const DEFAULT_PASSWORDS = new Set(['postgres', 'password', 'passw0rd', 'secret', 'root', 'admin', 'test', 'dev', 'changeme', 'example', 'mysql', 'redis', 'mongo', 'user', 'guest', '123456', '12345678']);

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
    // The trailing char classes exclude backtick/paren/bracket/comma/semicolon
    // as well as the usual quote+whitespace: a URL written as a markdown-style
    // example (`` `postgres://user:pass@host` `` in a comment or docstring)
    // otherwise swallows the closing backtick into the host, which broke the
    // local-host check below (`localhost\`` never matches `^localhost$`).
    re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^\s:/@"'`)\];,]+:([^\s:/@"'`)\];,]{4,})@[^\s"'`)\];,]+/gi,
    severity: 'critical',
    fix: 'Move the connection string to a server-side env var and rotate the database password — a committed DB URL grants full data access.',
    // `postgres://opencut:opencut@localhost` in docker-compose / CI / a Dockerfile
    // is a local container's default login, not a credential. A password that
    // equals the user name, or is a well-known default, or is otherwise weak,
    // is only exempt on a local/single-label host (a compose service name) —
    // the exact same password on a real remote host is a live, guessable
    // credential, not a throwaway dev default, and must still be reported.
    validate: (hit) => {
      const m = /^[a-z+]+:\/\/([^\s:/@"'`)\];,]+):([^\s:/@"'`)\];,]+)@([^/\s:"'`)\];,]+)/i.exec(hit);
      if (!m) return true;
      const [, user = '', pw = '', host = ''] = m;
      const local = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal|[a-z0-9_-]+)$/i.test(host);
      const strong = /[0-9]/.test(pw) && /[A-Za-z]/.test(pw) && shannonEntropy(pw) >= 3.0;
      const weak = pw.toLowerCase() === user.toLowerCase() || DEFAULT_PASSWORDS.has(pw.toLowerCase()) || !strong;
      return !(local && weak);
    },
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

const GENERIC = /\b([A-Za-z0-9_-]*(?:api[_-]?key|secret|token|passwd|password|pwd|credential))["']?\s*[:=]\s*["']([^"']{8,})["']/gi;
/**
 * Names that contain "token"/"secret" but are not credentials: API cursors,
 * tracking ids, CSRF nonces, push tokens. 559 of 569 generic hits in one real
 * project were `tracking_token` / `pagination_token` inside cached API
 * responses.
 *
 * Deliberately NOT here: "session" and "reset". `sessionSecret` (the signing
 * key for express-session/cookie-session — a real, common config secret) and
 * `sessionToken`/`resetToken` (bearer auth / password-reset tokens, both
 * enough to take over an account) are genuine credentials, not opaque ids —
 * unlike `trackingToken`/`paginationToken`, they were being excluded outright.
 */
const NON_SECRET_NAME = /(pagination|tracking|page|next|prev|continuation|cursor|csrf|xsrf|cancel|request|device|push|fcm|expo|invite|share|verification|unsubscribe|confirm)/i;
/** Base64 blobs (thumbnails, binary) and anything longer than a real token. */
const looksLikeBlob = (v: string) => v.length > 200 || /^(\/9j\/|iVBOR|data:|R0lGOD|UklGR)/.test(v);

const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

// KEY=value / key: value / Dockerfile ENV|ARG KEY=value, with a secret-looking NAME.
const ASSIGN = /^[ \t]*(?:export[ \t]+|ENV[ \t]+|ARG[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*[:=][ \t]*(.+)$/gm;
const SECRET_NAME = /(secret|token|password|passwd|private[_-]?key|api[_-]?key|access[_-]?key|credential)/i;
/**
 * Shell-style `NAME=value` anywhere in a line, in any file: `PGPASSWORD=… psql`,
 * `TOKEN=… curl`, a permission rule in .claude/settings.local.json. Upper-case
 * names only, so prose like "password=…" in docs does not count.
 *
 * The leading class is `*` (zero or more), not `+`: a bare name that IS one of
 * the keywords (`SECRET=…`, `TOKEN=…`, `API_KEY=…`, no prefix at all — an
 * extremely common shape in real scripts) needs zero characters before the
 * keyword, and requiring at least one meant those never matched at all. There
 * is deliberately no trailing lookahead: `{8,}` on a fixed character class
 * already stops at the first character outside it, so a value followed by
 * `;`, `)`, `,` or `]` (`export TOKEN=abc123;`, `foo(SECRET=abc123)`) still
 * matches correctly — an earlier version's trailing negative lookahead
 * rejected exactly those common shell/call-site endings.
 */
// Values are ASCII token characters: `PASSWORD=та_же_что_и_выше` in a README is prose.
const INLINE_ENV = /\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_KEY|PRIVATE_KEY)[A-Z0-9_]*)=([A-Za-z0-9_\-./+=:@]{8,})/g;

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

// Documentation, examples and test fixtures are where sample keys legitimately
// live. A hit there is worth mentioning but is not a credential leak.
// (shared: also used by detect.ts, to keep a project's own test suite for
// backend-talking code from making the project look like it uses that backend.)

export const secretsChecker: Checker = {
  id: 'secrets',
  title: 'Hardcoded secrets',
  level: 0,
  run(ctx) {
    const findings: Finding[] = [];
    const exposure = createExposure(ctx.root);

    // Values from the REAL env files, per directory. A committed .env.example
    // that carries the same value as its sibling .env is not an example — it is
    // the key, published. (Seen in the wild: OPENAI/ANTHROPIC keys identical
    // in .env and a committed .env.example.)
    const realEnvValues = new Map<string, Set<string>>();
    for (const f of ctx.files) {
      if (!isEnvFile(f.rel)) continue;
      const dir = f.rel.includes('/') ? f.rel.slice(0, f.rel.lastIndexOf('/')) : '';
      const set = realEnvValues.get(dir) ?? new Set<string>();
      for (const m of f.content.matchAll(ASSIGN)) {
        const v = (m[2] ?? '').trim().replace(/^["']|["']$/g, '').replace(/["'].*$/, '');
        if (v.length >= 8) set.add(v);
      }
      realEnvValues.set(dir, set);
    }
    const dirOf = (rel: string) => (rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/')) : '');
    const isExampleEnv = (rel: string) => /(^|\/)\.env[^/]*\.(example|sample|template|dist)$/i.test(rel) || /(^|\/)(example|sample)\.env$/i.test(rel);

    for (const file of ctx.files) {
      const { rel } = file;
      const content = file.content.replace(/^\uFEFF/, ''); // a BOM must not eat line 1
      const env = isEnvFile(rel);
      const example = looksLikeTestOrDocPath(rel);
      const ex: Exposure = exposure(rel);

      // `proven` = the hit is structurally real key material (see
      // looksLikeRealMaterial). A docs/fixture path may only downgrade a
      // heuristic or sample-looking hit to info; proven material stays at
      // warning there — the path lowers confidence, it does not make it safe.

      /**
       * Severity = what the value is × how it can leak. The pattern says what it
       * is; the example/docs path lowers confidence; git exposure decides how
       * bad it is. `raw` is the unredacted value, only compared, never stored.
       */
      const push = (f: Finding, proven = false, raw?: string) => {
        let out: Finding = f;
        const realValueInExample = !!raw && isExampleEnv(rel) && (realEnvValues.get(dirOf(rel))?.has(raw) ?? false);
        if (realValueInExample) {
          // Not an example at all: the live value copied into the example file.
          out = {
            ...f,
            severity: ex === 'committed' ? 'critical' : 'warning',
            title: `${f.title} — the REAL value from .env, in an example file${ex === 'committed' ? ' that is committed' : ''}`,
            detail: `${f.detail} This value is identical to the one in the sibling .env: the example file carries the real credential${ex === 'committed' ? ', and it is committed to git' : ''}.`,
            fix: 'Replace the value in the example file with a placeholder, and rotate the credential — it has been published.',
          };
        } else if (example && proven) {
          out = {
            ...f,
            severity: f.severity === 'critical' ? 'warning' : f.severity,
            title: `${f.title} (in docs/example path — looks real)`,
            detail: `${f.detail} The path suggests documentation or a fixture, but the value has the structure of real key material — verify it, and rotate it if it is genuine.`,
          };
        } else if (example) {
          out = {
            ...f,
            severity: 'info',
            title: `${f.title} (in docs/example file)`,
            detail: `${f.detail} This looks like documentation or a fixture — confirm it is not a real credential.`,
          };
        }
        // Git exposure. A committed secret keeps its full severity. Everything
        // else cannot leak through the repository right now: an ignored file is
        // doing exactly what it should (advisory); an untracked file in a repo
        // or a folder that is not a repo is hygiene, capped at warning.
        if (!realValueInExample && out.severity !== 'info') {
          // A .env that is not committed is doing its job: secrets belong there.
          // Whether it WILL be committed (untracked, no .gitignore entry) is the
          // env-git check's finding, not this one's — reporting it twice at
          // warning is what made people stop reading.
          if (env && ex !== 'committed') {
            // This also covers `ex === 'ignored'`: an env file is always the
            // right place for a secret whether or not it's ALSO gitignored, so
            // there is nothing a separate ignored-env-file branch would add.
            out = { ...out, severity: 'advisory', detail: `${out.detail} Not committed — this is where the value belongs; keep the file out of git and out of client bundles.` };
          } else if (ex === 'ignored') {
            // Gitignored, but not an env file: a credential pasted into a tool
            // config or a script (a prod DB password inside a permission rule in
            // .claude/settings.local.json was reported as a mere advisory). It
            // cannot leak through git today; it still does not belong there.
            out = { ...out, severity: atMost(out.severity, 'warning'), detail: `${out.detail} The file is gitignored, so this cannot leak through git — but it is a credential pasted into a config/source file, not an env var. Move it to .env (also gitignored) so one \`git add -A\` or a shared zip never carries it.` };
          } else if (ex === 'untracked') {
            out = { ...out, severity: atMost(out.severity, 'warning'), detail: `${out.detail} The file is not committed yet — it is one \`git add -A\` away from being. Add it to .gitignore or move the value to an env var.` };
          } else if (ex === 'no-git') {
            out = { ...out, severity: atMost(out.severity, 'warning'), detail: `${out.detail} This folder is not a git repository, so nothing leaks through git; the risk is copying or zipping the folder. Move the value to an env var before this becomes a repo.` };
          }
        }
        findings.push(out);
      };

      for (const p of PATTERNS) {
        for (const m of content.matchAll(p.re)) {
          const hit = m[0];
          if (looksLikePlaceholder(hit)) continue; // YOUR_KEY / EXAMPLE / xxxxx / <...>
          if (p.validate && !p.validate(hit)) continue;
          // A secret in a server env/config file is expected — the risk is
          // committing it (env-git flags that), so it is a warning, not a leak.
          const severity = env && p.severity === 'critical' ? 'warning' : p.severity;
          const proven = HIGH_CONFIDENCE.has(p.id) && looksLikeRealMaterial(p.id, hit, content, m.index ?? 0, m[1]);
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
          }, proven, hit);
        }
      }

      // Supabase service_role key (a JWT whose payload role is service_role).
      // The decoded role proves what it is, so it is never a docs-only info.
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
          }, true, m[0]);
        }
      }

      // Quoted key/secret assignments in code, filtered by placeholder + entropy.
      for (const m of content.matchAll(GENERIC)) {
        const name = m[1] ?? '';
        const value = m[2] ?? '';
        if (NON_SECRET_NAME.test(name) || looksLikeBlob(value)) continue;
        // Credentials have no whitespace ("Show password" is UI text) and carry
        // digits or real length ("build-time-secret" is a label).
        if (/\s/.test(value) || (!/[0-9]/.test(value) && value.length < 24)) continue;
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
        }, false, value);
      }

      // name=value / key: value assignments (env, config, Dockerfile ENV/ARG).
      // Runs first so a plain, single-assignment line keeps this rule's more
      // specific title/fix on the dedup tie below, rather than INLINE_ENV's.
      if (isConfigish(rel)) {
        for (const m of content.matchAll(ASSIGN)) {
          const name = m[1] ?? '';
          if (!SECRET_NAME.test(name)) continue;
          const value = (m[2] ?? '').trim().replace(/^["']|["']$/g, '').replace(/["'].*$/, '');
          if (value.length < 8 || looksLikePlaceholder(value) || shannonEntropy(value) < 3.0) continue;
          // "build-time-secret" is a label, not a credential: real values carry digits or length.
          if (!/[0-9]/.test(value) && value.length < 24) continue;
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
          }, false, value);
        }
      }

      // Inline shell-style assignments mid-line, in every file including
      // config-ish ones. ASSIGN above is start-of-line and one-per-line, so it
      // never sees a Compose `environment:` list item (`- TOKEN=…`), a CI
      // step's inline `run: TOKEN=… cmd`, or a second KEY=VALUE later on the
      // same Dockerfile ENV line — all real leaks it silently missed while
      // this ran only for non-config files. Also still needed for the
      // original case: a prod DB password inside a permission rule in
      // .claude/settings.local.json, invisible to every other name-based rule.
      for (const m of content.matchAll(INLINE_ENV)) {
        const name = m[1] ?? '';
        const value = m[2] ?? '';
        if (looksLikePlaceholder(value) || shannonEntropy(value) < 3.0) continue;
        if (!/[0-9]/.test(value) && value.length < 24) continue;
        push({
          id: 'env_secret',
          severity: 'warning',
          title: 'Secret in an inline assignment',
          detail: `"${name}" is assigned a high-entropy value inline in ${rel}: ${redact(value)}`,
          fix: 'Move the value to a gitignored .env and reference it by name; rotate it if the file was ever shared.',
          checker: 'secrets',
          level: 0,
          file: rel,
          line: lineAt(content, m.index ?? 0),
          evidence: redact(value),
        }, false, value);
      }
    }

    // De-duplicate only true repeats: the same secret, same place, same rule.
    // (Keying on file:line alone hid every extra key on a minified line.)
    const seen = new Map<string, Finding>();
    for (const f of findings) {
      const key = `${f.file ?? ''}:${f.line ?? 0}:${f.id}:${f.evidence ?? ''}`;
      const cur = seen.get(key);
      if (!cur || SEVERITY_RANK[f.severity] < SEVERITY_RANK[cur.severity]) seen.set(key, f);
    }
    // A vendor pattern or a decoded JWT already identifies a VALUE on a line;
    // the name-based env_secret / generic_secret finding for that SAME value
    // is the same fact twice. Keyed on file:line:evidence, not just
    // file:line — two different secrets assigned on one line (`const
    // key="sk-proj-…", password="…"`) are two different facts, and dropping
    // the second because the first has a specific pattern hid it entirely.
    const NAME_BASED = new Set(['env_secret', 'generic_secret']);
    const specificAt = new Set([...seen.values()].filter((f) => !NAME_BASED.has(f.id)).map((f) => `${f.file ?? ''}:${f.line ?? 0}:${f.evidence ?? ''}`));
    const kept = [...seen.values()].filter((f) => !(NAME_BASED.has(f.id) && specificAt.has(`${f.file ?? ''}:${f.line ?? 0}:${f.evidence ?? ''}`)));

    // Eleven advisories saying "secret in gitignored .env.local — fine" are one
    // observation printed eleven times. Fold them into one line per file that
    // names the variables; anything above advisory stays line by line.
    //
    // The final `applyIgnores` pass (scan.ts) only sees whatever this checker
    // returns — once N findings become one summary Finding with a single
    // `line`, a `// easyvibegate-ignore` comment placed above any secret but
    // the first in the group can no longer reach it. Filter each candidate
    // through the SAME inline-marker check first (an empty config so only the
    // marker, not project-wide `ignore`/`ignorePaths` rules, applies here —
    // those still run again, correctly, against whatever this returns), so an
    // individually silenced secret is dropped before folding, not after.
    const byFile = new Map<string, Finding[]>();
    for (const f of kept) {
      if (f.id !== 'env_secret' || f.severity !== 'advisory' || !isEnvFile(f.file ?? '')) continue;
      byFile.set(f.file ?? '', [...(byFile.get(f.file ?? '') ?? []), f]);
    }
    const folded = new Set<Finding>();
    const summaries: Finding[] = [];
    for (const [file, allCandidates] of byFile) {
      const group = partitionIgnores(allCandidates, EMPTY_CONFIG, ctx.files).kept;
      // A member the marker silenced must not reappear individually either —
      // it is done with, not merely "too few left to fold".
      for (const f of allCandidates) if (!group.includes(f)) folded.add(f);
      if (group.length < 2) continue;
      for (const f of group) folded.add(f);
      const names = group.map((f) => /^"([^"]+)"/.exec(f.detail)?.[1] ?? '?');
      const first = group.reduce((a, b) => ((a.line ?? 0) <= (b.line ?? 0) ? a : b));
      summaries.push({
        ...first,
        title: `${group.length} secrets in ${file} (not committed — where they belong)`,
        detail: `${file} holds ${group.length} secret-looking values (${names.join(', ')}). The file is not committed, so nothing leaks through git; keep it that way and out of client bundles.`,
        fix: 'Nothing to change here. Keep the file gitignored; rotate any value that may ever have been committed or shared.',
        evidence: undefined,
      });
    }
    return [...kept.filter((f) => !folded.has(f)), ...summaries];
  },
};
