# 🛡 VibeGate

![license: MIT](https://img.shields.io/badge/license-MIT-brightgreen) ![node](https://img.shields.io/badge/node-%3E%3D18-blue) ![lang](https://img.shields.io/badge/lang-en%20%7C%20ru-informational)

**Universal security scanner for vibe-coded apps. It doesn't just guess a hole exists — it proves the hole fires.**

Most scanners grep your code and say *"you might have leaked a key."* VibeGate is built to go further:
walk in with the anonymous key, read the data that should have been protected, and hand you back the
exact `curl` that did it — plus the SQL to close it. Works on any stack.

> Status: **v0.2**. Static review, dependency audit, and the live Supabase/Firebase/endpoint probe
> all work today.

## Quick start (made for beginners)

```bash
npx vibegate
```

Run it inside your project. A friendly wizard asks a few plain yes/no questions, then tells you what's
wrong in plain language and hands you a ready-to-use fix plan. No install, no config, no runtime deps.

**Then let your AI fix it:** open `vibegate-report/ai-fix-prompt.md` and paste it into your AI coding
assistant (Cursor, Claude Code, Windsurf…). For security fixes, pick a strong model like **Claude Fable**
or Opus — not a small "fast" one.

**Language / Язык:** the interface is English by default and Russian with `--lang ru`
(auto-detected from your locale). Security findings themselves stay in technical English
so they hand off cleanly to your AI agent.

Power/CI usage skips the wizard:

```bash
vibegate . --no-wizard             # just scan and print results
vibegate . --deps                  # + dependency vulnerability audit
vibegate . --url https://myapp.com --i-own-this   # + live probe (own apps only)
vibegate . --ci                    # exit non-zero on findings, for CI
vibegate . --lang ru               # Russian interface
vibegate . --help
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

### Level 2 — live probe (the point of the whole thing)
Against your **running** app, with your confirmation (own apps only):
- **Supabase / Firebase** — walk in with the public anon key and list which tables/buckets are readable (and, opt-in, writable) by anyone. Proves RLS is off instead of guessing.
- **Any backend** — hit your endpoints with no login; with two test accounts (`--idor-tokens a,b`), diff responses to catch cross-user access (IDOR).

## Scoring

- **Gate:** `fail` if any critical finding, else `pass`.
- **Score:** 0–100 (critical −25, warning −8, info −2).
- **Badge:** a Markdown snippet you can drop in your README.

## Config & suppressing noise

Add a `vibegate.config.json`:

```json
{
  "ignore": ["generic_secret:src/fixtures/sample.ts"],
  "ignorePaths": ["tests/", "examples/"]
}
```

Or inline, on or above the flagged line:

```js
const token = "not-a-real-secret"; // vibegate-ignore
```

## In CI (GitHub Actions)

Add `.github/workflows/vibegate.yml`:

```yaml
name: VibeGate
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npx vibegate . --ci
```

Exit codes: `2` = critical found, `1` = warnings, `0` = clean.

## As an AI-agent skill (Cursor / Claude Code / Windsurf)

The `skills/vibegate/SKILL.md` file makes VibeGate a skill your AI agent can run and reason about
(it drives the interactive levels and the IDOR test). Install it by copying the folder into your
agent's skills directory, e.g.:

```bash
cp -r skills/vibegate ~/.claude/skills/vibegate     # Claude Code
```

## Config & suppressing noise

See `vibegate.config.json` (`ignore`, `ignorePaths`) and inline `// vibegate-ignore`, above.

## Honest limitations

VibeGate is a **linter for common vibe-coding holes, not a penetration test.** Zero findings does not
mean you are safe. The static layer cannot know whether an endpoint enforces access control — only the
live probe can, and only against a running app you own. Never point the live probe at systems you do
not own.

## Contributing

Issues and PRs welcome. Build with `pnpm install && pnpm build`; the CLI entry is `dist/cli/index.js`.
New checks live under `src/engine/checkers/`; UI strings under `src/engine/i18n.ts`.

## License

MIT — see [LICENSE](LICENSE).
