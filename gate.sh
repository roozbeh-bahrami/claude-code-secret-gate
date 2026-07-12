#!/usr/bin/env bash
# git-secret-gate — abort any commit that contains secrets.
# Scans STAGED content (what's about to become permanent history), not just filenames.
# Install as a pre-commit hook:  cp gate.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
# Or run manually between `git add` and `git commit`:  ./gate.sh

set -euo pipefail

FAIL=0

# ---- 1. Dangerous FILENAMES staged? ----------------------------------------
BAD_NAMES=$(git diff --cached --name-only | grep -E '(^|/)\.env$|(^|/)\.env\.[^.]+$|\.pem$|\.p12$|(^|/)id_rsa|credentials.*\.json$' || true)
if [ -n "$BAD_NAMES" ]; then
  echo "🚨 SECRET-GATE: credential-looking FILES staged:"
  echo "$BAD_NAMES" | sed 's/^/   /'
  FAIL=1
fi

# ---- 2. Secret PATTERNS inside staged content? ------------------------------
# JWTs, private keys, AWS keys, GitHub/Slack/OpenAI/Stripe tokens, GHL PITs.
PATTERNS='eyJhbGciOi|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|xox[bapsr]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|pit-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}'
HITS=$(git diff --cached -U0 | grep -E '^\+' | grep -EIn "$PATTERNS" | head -10 || true)
if [ -n "$HITS" ]; then
  echo "🚨 SECRET-GATE: secret-shaped strings in staged content (showing max 10, values truncated):"
  echo "$HITS" | cut -c1-60 | sed 's/^/   /'
  FAIL=1
fi

# ---- Verdict ----------------------------------------------------------------
if [ "$FAIL" -eq 1 ]; then
  echo ""
  echo "❌ Commit BLOCKED. Fix:  git reset <file>  → add the path to .gitignore → re-scan."
  echo "   Override (you had better be sure):  git commit --no-verify"
  exit 1
fi
echo "✅ secret-gate: staged content clean."
