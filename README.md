# git-secret-gate 🔒

**Abort any commit that contains secrets — before it becomes permanent history.**

One shell script, zero dependencies. It scans what you've *staged* (the exact content about to enter git) and blocks the commit if it finds:

- 🔑 Secret-shaped strings **inside file content**: JWTs, private key blocks, AWS keys, GitHub/Slack/OpenAI/Stripe-style tokens, GoHighLevel PITs
- 📄 Credential-looking **filenames**: `.env`, `.pem`, `id_rsa`, `credentials*.json`…

## Why content scanning matters

`.gitignore` only blocks files you *expected* to be secret. The leaks that actually happen are tokens pasted into a config export, an API response saved as JSON, a workflow backup with an embedded key. Filename rules never catch those — **content scanning does**. This gate caught three real leaks in its first day of use (workflow exports with embedded live tokens that every filename rule missed).

## Install (once per repo)

```bash
cp gate.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Done. Every `git commit` now runs the gate automatically:

```
✅ secret-gate: staged content clean.        ← commit proceeds
🚨 SECRET-GATE: secret-shaped strings...     ← commit BLOCKED, nothing recorded
```

## Or run it manually

```bash
git add -A
./gate.sh          # ✅ or 🚨
git commit -m "..."
```

## Working with AI coding agents?

Paste this into your agent's instructions:

> Between `git add` and `git commit`, ALWAYS run `./gate.sh`. If it fails, ABORT the commit, unstage the flagged files, fix `.gitignore`, and rescan. Never use `--no-verify`.

An AI agent commits fast and often — exactly why it needs a mechanical gate, not a promise to be careful.

## Extend it

Patterns live in one variable (`PATTERNS`) — add your platform's token shapes. Keep the rule: **when the gate and your convenience disagree, the gate wins.**

## Author

**Roozbeh Bahrami** — AI automation specialist. Part of my verification-first toolkit, together with [claude-advisor-skill](https://github.com/roozbeh-bahrami/claude-advisor-skill). ⭐ if it saved your history.

## License

MIT
