#!/usr/bin/env bash
# git-secret-gate — abort any commit that contains secrets.
# Scans STAGED content (what's about to become permanent history), not just filenames.
# Install as a pre-commit hook:  cp gate.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
# Or run manually between `git add` and `git commit`:  ./gate.sh

set -euo pipefail

FAIL=0

# ---- 1. Dangerous FILENAMES staged? ----------------------------------------
# .example / .template / .sample are TEMPLATES — they exist to be committed, and a project's
# .gitignore usually un-ignores them explicitly (`!.env.example`). Blocking them is a false
# positive on the one file that is meant to be shared. Content scanning still covers them, so a
# real token pasted into an .env.example is still caught by section 2.
# MEASURED 2026-08-29: this rule failed a CI run on a template holding `pit-xxxx` placeholders.
# -c core.quotePath=false, ALWAYS. MEASURED 2026-09-02 by an adversarial check of the MB
# pre-commit hook that calls this file: by default git C-QUOTES a path containing any non-ASCII
# byte, so `dossier-é/.env` arrives as `"dossier-\303\251/.env"` and the anchored `(^|/)\.env$`
# cannot match a name that ends in a quote. A credential file under a directory with an accent in
# it was reported clean. Every macOS screenshot filename contains U+202F, so this needed no
# exotic input. quotePath=false makes git print the real bytes; the greps then see the real name.
# FAIL CLOSED. MEASURED 2026-09-04, empirically, by putting a `git` on PATH that exits 1 with a
# real AKIA key staged: this gate printed "staged content clean" and exited 0. The leak would have
# committed. `set -euo pipefail` is on line 7 and does NOTHING here, because a pipeline ending in
# `|| true` is an OR-list and errexit never fires on one — so a scanner that CANNOT RUN was
# indistinguishable from a scan that found nothing. Confirmed independently by reviewer-Codex.
# The distinction that matters: grep exiting 1 means NO MATCH and is normal; git failing, or grep
# exiting >=2, means THE SCAN DID NOT HAPPEN and must block. Never merge those two into `|| true`.
STAGED_NAMES=$(git -c core.quotePath=false diff --cached --name-only) || {
  echo "🚨 SECRET-GATE: could not list staged files — git failed. FAILING CLOSED."; exit 1; }
BAD_NAMES=$(printf '%s\n' "$STAGED_NAMES" \
  | grep -vE '\.(example|template|sample|dist)$' \
  | grep -E '(^|/)\.env$|(^|/)\.env\.[^.]+$|\.pem$|\.p12$|(^|/)id_rsa|credentials.*\.json$' || true)
if [ -n "$BAD_NAMES" ]; then
  echo "🚨 SECRET-GATE: credential-looking FILES staged:"
  echo "$BAD_NAMES" | sed 's/^/   /'
  FAIL=1
fi

# ---- 2. Secret PATTERNS inside staged content? ------------------------------
# JWTs, private keys, AWS keys, GitHub/Slack/OpenAI/Stripe tokens, GHL PITs.
# THE `sk` ARM: A KEY HAS ITS ENTROPY IN ONE UNBROKEN RUN; A CSS CUSTOM PROPERTY IS WORDS JOINED
# BY HYPHENS. `sk-[A-Za-z0-9_-]{20,}` counted the hyphens, so `--sk-link-disabled-opacity: 0.42`
# and `--sk-headline-plus-first-element-margin` matched and a design system read as leaked keys.
# MEASURED 2026-08-29: this gate blocked the very commit that fixed the identical bug in
# web-studio/scripts/v3/secret-gate.js. A scanner that cries wolf on design tokens is worse than
# one pattern narrower, because it teaches people to reach for --no-verify.
#   FIX: the tail must contain a run of 16+ alphanumerics with NO separator inside it, and the
#   left side is anchored so `sk` inside `ask_`/`risk_`/`task_` cannot start a match. Both
#   separators are covered now — the old arm required a literal hyphen and so never saw a Stripe
#   `sk_live_` key at all. Every vendor still matches: stripe sk_live_ + 24, openai sk-proj- + 48,
#   anthropic sk-ant-api03- + 95. Fixtures in gate.test.sh; run it after any change here.
PATTERNS='eyJhbGciOi|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|xox[bapsr]-[A-Za-z0-9-]{10,}|(^|[^A-Za-z0-9_])sk[-_][A-Za-z0-9][A-Za-z0-9_-]*[A-Za-z0-9]{16,}|pit-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}'
# A line that is a DETECTOR is not a leak. A secret gate, a CI workflow and a .gitignore all have
# to contain the very shapes they look for, and blocking them is a false positive that teaches
# people to reach for --no-verify — which is the one habit this tool exists to prevent.
# The test is exact, not a filename exemption: a line carrying an ALTERNATION of two or more
# different secret families (a `|` between them) is a pattern, because no real token contains one.
# MEASURED 2026-08-29: this gate blocked the commit that added its own CI workflow.
# A FIXTURE IS NOT A LEAK EITHER. gate.test.sh has to contain real key SHAPES or it proves
# nothing, and this gate would block the file that proves this gate works. The exemption is
# structural, not a filename allowance and not a magic "allow" comment anyone can paste onto a
# real key: the line's first token must be the fixture helper `t MATCH` / `t NOMATCH`. A leaked
# credential is not preceded by a test-runner call.
# The second arm of the same idea: a line that WRITES its fake key into "$PROBE_SECRET" is a
# planted probe (GENERAL/scripts/prove-commit-gates.sh, which proves this gate fires in every
# repo). A real leak is not redirected into a variable named PROBE_SECRET.
IS_DETECTOR='eyJhbGciOi\|-----BEGIN|PRIVATE KEY\|AKIA|AKIA\[0-9A-Z\]|ghp_\[A-Za-z0-9\]|xox\[bapsr\]|PATTERNS=|--exclude|:\(exclude\)|^[0-9]+:\+t (MATCH|NOMATCH) |[$]PROBE_SECRET'
# FAIL CLOSED — same rule as section 1. The staged diff is captured on its own so a git failure
# is a BLOCK, not an empty result that reads as clean.
STAGED_DIFF=$(git diff --cached -U0) || {
  echo "🚨 SECRET-GATE: could not read the staged diff — git failed. FAILING CLOSED."; exit 1; }
HITS=$(printf '%s\n' "$STAGED_DIFF" | grep -E '^\+' | grep -EIn "$PATTERNS" \
       | grep -vE "$IS_DETECTOR" | head -10 || true)
# A grep that ERRORS (exit >=2: bad pattern, unreadable input) is not a grep that found nothing.
GREP_RC=${PIPESTATUS[2]:-0}
if [ "${GREP_RC:-0}" -ge 2 ]; then
  echo "🚨 SECRET-GATE: the content scanner errored (grep exit $GREP_RC). FAILING CLOSED."; exit 1
fi
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
