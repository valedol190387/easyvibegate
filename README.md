# 🛡 EasyVibeGate

![license: MIT](https://img.shields.io/badge/license-MIT-brightgreen) ![node](https://img.shields.io/badge/node-%3E%3D18-blue) ![lang](https://img.shields.io/badge/lang-en%20%7C%20ru-informational)

### 🇷🇺 Простыми словами

**Что это.** Проверка безопасности для приложений, собранных «на вайбе» с помощью ИИ (Cursor, Lovable, Bolt, Replit и т.п.). ИИ пишет код, который работает, но часто оставляет дыры: ключи прямо в коде, открытую всем базу данных, доступ к чужим данным. EasyVibeGate их находит и подсказывает, что чинить.

**Зачем.** Чтобы никто не скачал твою базу пользователей и не подделал данные через консоль браузера (F12).

**Как пользоваться — 3 шага:**
1. В папке своего проекта запусти одну команду.
2. Ответь на пару вопросов «да / нет».
3. Получишь понятный отчёт и готовый план починки — вставь его в свой ИИ (Cursor/Claude), и он всё исправит.

Разбираться в том, что внутри, не нужно: сложное — под капотом, снаружи одна команда и вопросы «да / нет». Интерфейс по умолчанию русский; английский — флагом `--lang en`.

---

**A security scanner for vibe-coded apps. It checks common risks and shows evidence where it can get it.**

Most scanners grep your code and say *"you might have leaked a key."* EasyVibeGate also goes to the
running backend: for **Supabase/Firebase** it walks in with the public key and shows which tables are
readable by anyone, with the exact `curl` — plus SQL to close it. It is honest about coverage: every
check reports whether it actually ran, so a failed or skipped check is never shown as a green "all clear".

> Status: **v0.3, early.** Best-supported stack: **Next.js + Supabase**. Code review runs on any stack;
> the live backend probe is read-only and Supabase/Firebase-focused. Not a penetration test.

## Quick start (made for beginners)

```bash
npx easyvibegate
```

Run it inside your project. A friendly wizard asks a few plain yes/no questions, then tells you what's
wrong in plain language and hands you a ready-to-use fix plan. No install, no config, no runtime deps.

**Then let your AI fix it:** open `easyvibegate-report/ai-fix-prompt.md` and paste it into your AI coding
assistant (Cursor, Claude Code, Windsurf…). For security fixes, pick a strong model like **Claude Fable**
or Opus — not a small "fast" one.

**Language / Язык:** the interface is **Russian by default**; use `--lang en` for English.
Security findings themselves stay in technical English so they hand off cleanly to your AI agent.

Power/CI usage skips the wizard:

```bash
easyvibegate . --no-wizard             # just scan and print results
easyvibegate . --deps                  # + dependency vulnerability audit
easyvibegate . --url https://myapp.com --i-own-this   # + live probe (own apps only)
easyvibegate . --ci                    # exit non-zero on findings, for CI
easyvibegate . --lang ru               # Russian interface
easyvibegate . --help
```

## What it checks

### Level 0 — code review (works now, any stack, read-only, zero install)
- **Hardcoded secrets** — OpenAI / Anthropic / AWS / Stripe / GitHub / Slack / Google keys, private keys, and the **Supabase `service_role` key** (decoded from JWTs, because that one bypasses all security).
- **Secrets shipped to the browser** — real secrets hiding behind `NEXT_PUBLIC_` / `VITE_` / `REACT_APP_` prefixes.
- **Dangerous config** — open CORS, debug mode on, `eval`, string-interpolated SQL, JWT `alg:none`.
- **Missing RLS** — SQL migrations that create tables but never `ENABLE ROW LEVEL SECURITY`.
- **`.env` / git hygiene** — env files not covered by `.gitignore`.
- **Endpoint inventory** — lists your routes as targets for the live probe (does *not* falsely claim they lack auth).

### Level 1 — dependency audit
Runs your package manager's audit (npm/pnpm/yarn) and summarizes known-vulnerable packages.

### Level 2 — live probe (read-only, own apps only, with your confirmation)
- **Supabase / Firebase** — walk in with the public key and list which tables/buckets are readable by anyone, with a reproducing `curl`. Table names that look sensitive (users, payments, …) are flagged critical; public-content tables are flagged as "confirm intent".
- **Any backend, best-effort** — hit discovered endpoints with no login; with two test accounts (`--idor-tokens a,b`), diff responses to spot candidate cross-user access (IDOR). These are warnings to verify, not proof — the tool never writes.

## Scoring

- **Gate:** `fail` if any critical finding, else `pass`.
- **Score:** 0–100 (critical −25, warning −8, info −2).
- **Badge:** a Markdown snippet you can drop in your README.

## Config & suppressing noise

Add a `easyvibegate.config.json`:

```json
{
  "ignore": ["generic_secret:src/fixtures/sample.ts"],
  "ignorePaths": ["tests/", "examples/"]
}
```

Or inline, on or above the flagged line:

```js
const token = "not-a-real-secret"; // easyvibegate-ignore
```

## In CI (GitHub Actions)

Add `.github/workflows/easyvibegate.yml`:

```yaml
name: EasyVibeGate
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npx easyvibegate . --ci
```

Exit codes: `2` = critical found, `1` = warnings, `0` = clean.

## As an AI-agent skill (Cursor / Claude Code / Windsurf)

The `skills/easyvibegate/SKILL.md` file makes EasyVibeGate a skill your AI agent can run and reason about
(it drives the interactive levels and the IDOR test). Install it by copying the folder into your
agent's skills directory, e.g.:

```bash
cp -r skills/easyvibegate ~/.claude/skills/easyvibegate     # Claude Code
```

## Config & suppressing noise

See `easyvibegate.config.json` (`ignore`, `ignorePaths`) and inline `// easyvibegate-ignore`, above.

## Honest limitations

EasyVibeGate is a **linter for common vibe-coding holes, not a penetration test.** Zero findings does not
mean you are safe. The static layer cannot know whether an endpoint enforces access control — only the
live probe can, and only against a running app you own. Never point the live probe at systems you do
not own.

## Contributing

Issues and PRs welcome. Build with `pnpm install && pnpm build`; the CLI entry is `dist/cli/index.js`.
New checks live under `src/engine/checkers/`; UI strings under `src/engine/i18n.ts`.

## License

MIT — see [LICENSE](LICENSE).
