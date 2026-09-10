---
name: easyvibegate
description: >-
  Run a tiered security audit of the current project with EasyVibeGate: static code
  review (secrets, exposed keys, missing RLS, dangerous config), an optional
  dependency audit, and — with the user's consent — a live probe of the running
  app and its Supabase/Firebase backend that proves whether data is readable or
  writable by anyone. Use when the user asks to check security, find leaks,
  audit RLS/IDOR, or make a vibe-coded app safe to ship.
---

# EasyVibeGate skill

You drive EasyVibeGate as a conversation. Explain each level before running it, and
never probe a live system without the user confirming they own it.

## 0. Install / locate
- If the repo has `easyvibegate` available, run `npx easyvibegate` (or `node dist/cli/index.js`).
- Otherwise run from source: `pnpm install && pnpm build` inside the easyvibegate repo.

## 1. Level 0 — code review (always safe, no consent needed)
Run:
```
npx easyvibegate <project-path>
```
Summarize the findings in plain language, most severe first. Point out the
critical ones (leaked service_role keys, missing RLS, secrets in the client).

## 2. Level 1 — dependency audit (ask first)
Ask: "Want me to run the dependency vulnerability audit?" If yes, add `--deps`.

## 3. Level 2 — live probe (needs a running app + explicit ownership)
Ask the user:
- "What's the URL of the running app?" → pass `--url <appUrl>`.
- "Confirm this is your own project?" → only then pass `--i-own-this`.
Supabase/Firebase creds are auto-detected from the code; the probe reads with the
public anon key. Keep it read-only unless the user explicitly asks to test writes
(`--write`).

For the **IDOR test**, this is where you (the AI) add value the CLI cannot:
1. Help the user obtain two test-account bearer tokens (walk them through logging
   in as two users and copying the tokens).
2. Pass them as `--idor-tokens <tokenA>,<tokenB>`.
3. If the CLI reports ambiguous cases, fetch the specific endpoints yourself with
   each token, compare the responses, and judge whether one user sees another's data.

## 4. Fix
Open `easyvibegate-report/ai-fix-prompt.md` and work through it in order. For leaked
secrets, tell the user exactly which keys to rotate — a committed key is already
burned. For missing RLS, apply the generated SQL migration.

## Safety
- Never run the live probe against a domain the user does not own.
- Never print full secret values; report masked evidence only.
- Writes are opt-in and use auto-cleaned canary rows.
