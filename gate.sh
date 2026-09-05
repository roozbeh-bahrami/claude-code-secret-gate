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
# JWTs, private keys, AWS keys, GitHub/Slack/OpenAI/Stripe tokens, CRM integration tokens,
# CRM inbound-webhook URLs, bare-UUID bearer tokens, and literal values in JSON credential slots.
#
# THE `sk` ARM: A KEY HAS ITS ENTROPY IN ONE UNBROKEN RUN; A CSS CUSTOM PROPERTY IS WORDS JOINED
# BY HYPHENS. The old `sk-[A-Za-z0-9_-]{20,}` counted the hyphens, so `--sk-link-disabled-opacity`
# and `--sk-headline-plus-first-element-margin` matched and a design system read as leaked keys.
# MEASURED 2026-08-29: this gate blocked the very commit that fixed the identical bug in a
# sibling repository's own scanner. A scanner that cries wolf on design tokens is worse than one
# pattern narrower, because it teaches people to reach for --no-verify.
#   FIX: the tail must contain a run of 16+ alphanumerics with NO separator inside it, and the
#   left side is anchored so `sk` inside `ask_`/`risk_`/`task_` cannot start a match. Both
#   separators are covered now — the old arm required a literal hyphen and so never saw a Stripe
#   `sk_live_` key at all. Every vendor still matches: stripe sk_live_ + 24, openai sk-proj- + 48,
#   anthropic sk-ant-api03- + 95. Fixtures in gate.test.sh; run it after any change here.
#
# THE LEFT ANCHOR WAS ONE CHARACTER TOO WIDE, MEASURED 2026-09-05. It excluded `_` as well as
# alphanumerics, so a vendor whose prefix ENDS in an underscore — `<vendor>_sk_<64 hex>` — could
# never start a match, and that shape is a real, live key format. `ask_`/`risk_`/`task_` stay
# excluded because the character before `sk` in each of them is a LETTER, which the class still
# refuses; only the underscore case changed. Both directions have fixtures.
#
# THE CRM INBOUND-WEBHOOK ARM, added 2026-09-05. An inbound webhook URL is a bearer credential
# wearing a URL's clothes: anyone holding it can POST straight into the CRM, with no
# authentication and no server-side validation, bypassing every `required` attribute and every
# line of page JavaScript. It is the highest-consequence shape this scanner can miss, because it
# does not look like a token to a human reader. MEASURED 2026-09-05: one such URL was sitting in
# a tracked file in a sibling repository and this scanner returned ZERO hits on it. Removing such
# a URL from a page is NOT containment; it must be rotated or revoked at the provider, because
# every copy ever pulled remains valid.
#
# BOTH OF THESE ARMS WERE NARROWED THE SAME DAY THEY WERE WRITTEN, by an independent reviewer:
#   (a) Widening the `sk` left anchor from [^A-Za-z0-9_] to [^A-Za-z0-9] admitted `_sk_`, which is
#       what the live vendor key needed — but it also admitted `dynamodb_sk_customerprofileindex`,
#       a plausible sort-key identifier. The original anchor is therefore RESTORED unchanged, so
#       every existing fixture keeps its exact meaning, and the underscore case gets its OWN arm
#       requiring a 24+ unbroken run immediately after `sk_`. The real key's run is 64; the false
#       positive's is 20. Both are fixtures below, so the boundary is recorded rather than
#       remembered.
#   (b) The JSON arm's value prefix was `[^"]*`, which happily consumed `${` and then matched the
#       long variable NAME inside a templated value — flagging `"API_KEY": "${MY_LONG_VARIABLE}"`,
#       the correct form, as a leak. Excluding `$` from the prefix kills that: a value that starts
#       with, or reaches, a `$` can no longer satisfy the run.
#   Neither defect was caught by the fixtures I wrote for my own change. That is the argument for
#   the second reader, not an argument for writing more of my own fixtures.
#
# THE BARE-UUID BEARER ARM. Some vendors issue a naked UUID as the token, with no prefix at all,
# so there is nothing about the value itself to detect. What IS detectable is the CONTEXT: the
# word `Bearer` immediately followed by a UUID is a credential in an Authorization header and
# nothing else. Same idea for the JSON arm: a key literally named Authorization / API_KEY /
# *_TOKEN / *_SECRET whose value carries a long unbroken run is a credential at rest, whereas a
# shell-style ${VAR} expansion is not. A placeholder and a live key look identical to a plain
# grep; that distinction is the entire point of the arm.
PATTERNS='eyJhbGciOi|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|xox[bapsr]-[A-Za-z0-9-]{10,}|(^|[^A-Za-z0-9_])sk[-_][A-Za-z0-9][A-Za-z0-9_-]*[A-Za-z0-9]{16,}|[A-Za-z0-9]_sk_[A-Za-z0-9]{24,}|pit-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}|leadconnectorhq\.com/hooks/[A-Za-z0-9_-]{8,}/webhook-trigger|[Bb]earer +[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|"(Authorization|API_KEY|API_KEY_[A-Z0-9_]+|[A-Z][A-Z0-9_]*(TOKEN|SECRET))" *: *"[^"$]*[A-Za-z0-9_-]{20,}'
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
# planted probe (the estate's commit-gate prover). A real leak is not redirected into a variable
# named PROBE_SECRET.
IS_DETECTOR='eyJhbGciOi\|-----BEGIN|PRIVATE KEY\|AKIA|AKIA\[0-9A-Z\]|ghp_\[A-Za-z0-9\]|xox\[bapsr\]|PATTERNS=|IS_DETECTOR=|--exclude|:\(exclude\)|^[0-9]+:\+t (MATCH|NOMATCH) |[$]PROBE_SECRET|webhook-trigger\||hooks/\[A-Za-z0-9_-\]'
# FAIL CLOSED — same rule as section 1. The staged diff is captured on its own so a git failure
# is a BLOCK, not an empty result that reads as clean.
STAGED_DIFF=$(git diff --cached -U0) || {
  echo "🚨 SECRET-GATE: could not read the staged diff — git failed. FAILING CLOSED."; exit 1; }
# THE SCAN'S EXIT STATUS MUST BE OBSERVABLE. MEASURED 2026-09-05, in bash 3.2, the shell this
# hook actually runs under: the previous shape was
#     HITS=$(... | grep -EIn "$PATTERNS" | ... | head -10 || true); GREP_RC=${PIPESTATUS[2]:-0}
# and it was dead code TWICE OVER. An assignment fed by a command substitution is a SIMPLE
# command, so PIPESTATUS afterwards holds exactly ONE element — the assignment's own status — and
# index 2 is unset, making GREP_RC always 0. Independently, the trailing `|| true` forces that
# status to 0 as well, so reading PIPESTATUS correctly would still not have helped. A grep that
# died on a bad pattern was indistinguishable from a grep that found nothing: the same fail-open
# shape section 1 was repaired for on 2026-09-04, one level up.
#   FIX: the pattern scan runs as its own SIMPLE command against a file, so `$?` is exactly its
#   status. 0 = hits, 1 = clean, >=2 = the scan DID NOT HAPPEN and must block.
SCAN_IN=$(mktemp) || { echo "🚨 SECRET-GATE: mktemp failed. FAILING CLOSED."; exit 1; }
trap 'rm -f "$SCAN_IN"' EXIT
printf '%s\n' "$STAGED_DIFF" | grep -E '^\+' > "$SCAN_IN" || true
set +e
PAT_HITS=$(grep -EIn "$PATTERNS" "$SCAN_IN")
PAT_RC=$?
set -e
if [ "$PAT_RC" -ge 2 ]; then
  echo "🚨 SECRET-GATE: the content scanner errored (grep exit $PAT_RC). FAILING CLOSED."; exit 1
fi
HITS=""
if [ "$PAT_RC" -eq 0 ]; then
  HITS=$(printf '%s\n' "$PAT_HITS" | grep -vE "$IS_DETECTOR" | head -10 || true)
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
