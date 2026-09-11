# 🛡 EasyVibeGate

![license: MIT](https://img.shields.io/badge/license-MIT-brightgreen) ![node](https://img.shields.io/badge/node-%3E%3D18-blue) ![lang](https://img.shields.io/badge/lang-ru%20%7C%20en-informational)

🇷🇺 Русская версия: [README.md](README.md)

**A security scanner for vibe-coded apps. It checks common risks and shows evidence where it can get it.**

Most scanners grep your code and say *"you might have leaked a key."* EasyVibeGate also goes to the running backend: for **Supabase/Firebase** it walks in with the public key and shows which tables are readable by anyone, with the exact `curl` — plus SQL to close it. It is honest about coverage: every check reports whether it actually ran, so a failed or skipped check is never shown as a green "all clear".

> ⚠️ **Not published to npm yet** — `npx easyvibegate` will work after publishing.
> Today, install straight from GitHub: `npx github:valedol190387/easyvibegate`
> (it fetches the repo and builds itself).
>
> Status: **v0.3, early.** Best-supported stack: **Next.js + Supabase**. Code review runs on any stack; the live backend probe is read-only and Supabase/Firebase-focused. Not a penetration test.

## How to run

Three ways — pick whichever suits you.

### Option 1. Via an AI agent (easiest)

If you use **Cursor, Claude Code, or Codex**, you don't need to type anything in a terminal. Open the project in your agent and paste this prompt:

```
Check this project's security with EasyVibeGate and explain the result in plain language.

1. Run at the project root:  npx github:valedol190387/easyvibegate . --no-wizard --deps
   (After the npm release the short form is: npx easyvibegate . --no-wizard --deps)
   (Add  --url <my-app-url> --i-own-this  only if this is my project
    and I allow the live backend probe.)
2. Open and read the file:  easyvibegate-report/ai-fix-prompt.md
3. Explain in plain language: what was found, how serious it is, most urgent first.
4. Propose concrete fixes, but do NOT change code without my confirmation.
```

The agent runs it, reads the report, and explains the findings. You can also just say: "run EasyVibeGate and tell me what's wrong."

### Option 2. One command in the terminal

```bash
npx github:valedol190387/easyvibegate
```

Run it inside your project. (After the npm release: `npx easyvibegate`.) A friendly wizard asks a few plain yes/no questions, tells you what's wrong in plain language, and writes a ready-to-use fix plan. No install, no config, no runtime deps.

### Option 3. In CI (GitHub Actions)

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
      - run: npx github:valedol190387/easyvibegate . --ci
```

Exit codes: `2` = critical, `1` = warnings, `3` = a check failed to run, `0` = clean.

## What to do with the result

Open `easyvibegate-report/ai-fix-prompt.md` and paste it into your AI assistant (Cursor, Claude Code, Windsurf). For security fixes, pick a **strong model — Claude Fable or Opus**, not a small "fast" one. Rotate any leaked key immediately.

## What it checks

### Level 0 — code review (any stack, read-only, zero install)
- **Hardcoded secrets** — OpenAI / Anthropic / AWS / Stripe / GitHub / Google keys, private keys, Supabase `service_role`/secret keys.
- **Secrets shipped to the browser** — real secrets behind `NEXT_PUBLIC_` / `VITE_` / `REACT_APP_`.
- **Dangerous config** — open CORS, debug mode, `eval`, string-interpolated SQL, JWT `alg:none`.
- **Missing RLS** — migrations that create tables but never `ENABLE ROW LEVEL SECURITY` (per-table analysis).
- **.env / git hygiene** — via real git semantics: a committed `.env` is critical.
- **Endpoint inventory** — routes listed as live-probe targets (no false "no auth" claims).

### Level 1 — dependency audit
npm / pnpm / yarn audit. A registry error is reported as "failed", never "clean".

### Level 2 — live probe (read-only, own apps only, with your confirmation)
- **Supabase / Firebase** — walk in with the public key and list which tables/buckets are readable by anyone, with a reproducing `curl`. Sensitive-looking table names (users, payments…) are critical; public content is flagged "confirm intent".
- **Any backend, best-effort** — hit discovered endpoints with no login; with two test accounts (`--idor-tokens a,b`), diff responses to spot candidate cross-user access (IDOR). Warnings to verify, not proof — the tool never writes.

## Scoring & coverage

- **One gate policy everywhere** (CI, JSON, badge, console): `fail` — a critical finding; `incomplete` — nothing critical, but a check failed / ran partially / is unsupported; `pass` — everything ran and is clean.
- **Score:** 0–100. An `incomplete` run is **never a green badge**.
- **Coverage line:** "Checks: N ok · M failed · K skipped".
- **Exit codes (every mode, not just `--ci`):** `2` critical, `1` warnings, `3` a check did not complete, `0` clean.
- Reports record the scanned path, version and timestamp, so reports from different projects never get mixed up.

## Suppressing noise

`easyvibegate.config.json`:

```json
{ "ignore": ["generic_secret:src/fixtures/sample.ts"], "ignorePaths": ["tests/", "docs/"] }
```

Or inline, on or above the flagged line: `// easyvibegate-ignore`.

## As an AI-agent skill

`skills/easyvibegate/SKILL.md` makes EasyVibeGate a skill your agent can run and reason about. Copy it into your agent's skills dir, e.g. `cp -r skills/easyvibegate ~/.claude/skills/easyvibegate`.

## Honest limitations

EasyVibeGate is a **linter for common vibe-coding holes, not a penetration test.** Zero findings does not mean you are safe. The static layer cannot know whether an endpoint enforces access control — only the live probe can, and only against a running app you own. Never point the live probe at systems you do not own.

## Language

Interface is **Russian by default**; use `--lang en` for English. Security findings themselves stay in technical English so they hand off cleanly to your AI agent.

## Contributing

Issues and PRs welcome. Build with `pnpm install && pnpm build`; CLI entry is `dist/cli/index.js`; tests: `pnpm test`. New checks live under `src/engine/checkers/`; UI strings under `src/engine/i18n.ts`.

## License

MIT — see [LICENSE](LICENSE).
