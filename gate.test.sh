#!/usr/bin/env bash
# gate.test.sh — fixtures for gate.sh's PATTERNS. Run after ANY change to that regex.
#
# A pattern with no fixture is a guess. Both directions are tested: real keys MUST match,
# and the strings that have actually caused false positives on this machine MUST NOT.
#
#   bash gate.test.sh
set -uo pipefail
PATTERNS=$(sed -n "s/^PATTERNS='\(.*\)'$/\1/p" "$(dirname "$0")/gate.sh")
[ -n "$PATTERNS" ] || { echo "could not read PATTERNS from gate.sh"; exit 1; }
P=0; F=0
t() {  # t MATCH|NOMATCH <string> <why>
  local want="$1" s="$2" why="$3" got
  if printf '%s\n' "$s" | grep -Eq "$PATTERNS"; then got=MATCH; else got=NOMATCH; fi
  if [ "$got" = "$want" ]; then P=$((P+1))
  else F=$((F+1)); printf '  FAIL want=%-8s got=%-8s %s\n         %s\n' "$want" "$got" "$why" "$s"; fi
}

# ── THE FIXTURES ARE ASSEMBLED AT RUNTIME, NOT STORED AS LITERALS. ──────────────────────────
# This repository is PUBLIC, and GitHub Push Protection refused a push whose gate.test.sh line 22
# held an invented Stripe-shaped key as a literal, reporting it as a "Stripe API Key"
# (GH013, 2026-08-30). The literal is not repeated here, for the same reason. It was right to: it
# cannot know the string is invented, and neither can anyone else's scanner. Publishing a
# key-SHAPED literal to a public repo means every downstream vendoring of this file trips their
# scanner too.
# There are two ways out and only one of them is honest. Clicking GitHub's "allow this secret"
# bypass would ship the literal and turn OFF the protection that just did its job correctly.
# Instead the prefix is joined to the body at runtime: the string the test asserts on is
# byte-identical, and no scanner — GitHub's or ours — sees a credential at rest.
P_SK='sk'; P_GH='gh'; P_G='g'; P_AWS='AK'; P_XOX='xo'; P_JWT='eyJ'; P_PEM='-----BEGIN'
echo "── gate.sh PATTERNS fixtures ─────────────────────────────────────────────"
# ── MUST MATCH: real key shapes ──
t MATCH   "${P_SK}-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH" 'openai sk-proj-'
t MATCH   "${P_SK}_live_51H8xQpKm3nRtYvWzAbCdEfGh"                    'stripe sk_live_'
t MATCH   "${P_SK}-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefghijklmno" 'anthropic sk-ant-'
t MATCH   "${P_GH}p_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"             'github classic PAT'
t MATCH   "${P_G}ithub_pat_11ABCDEFG0abcdefghijklmnop"                'github fine-grained PAT'
t MATCH   "${P_AWS}IAIOSFODNN7EXAMPLE"                                'aws access key id'
t MATCH   "${P_XOX}xb-123456789012-abcdefghijkl"                      'slack bot token'
t MATCH   "${P_JWT}hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"                 'jwt header'
t MATCH   'pit-1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d'                  'ghl private integration token'
t MATCH   "${P_PEM} RSA PRIVATE KEY-----"                             'pem private key'
t MATCH   "const key = \"${P_SK}-abcdefghijklmnopqrstuvwx\""          'key inside code'

# ── MUST NOT MATCH: the false positives measured on this machine ──
t NOMATCH '  --sk-link-disabled-opacity: 0.42;'                  'FP 2026-08-25 mb-website: css custom property'
t NOMATCH 'opacity:var(--sk-link-disabled-opacity,0.42)'         'FP: the same token, used'
t NOMATCH '  --sk-headline-plus-first-element-margin: 8px;'      'FP: long hyphenated css name'
t NOMATCH '  --sk-body-link-color: rgb(0,102,204);'              'FP: css colour token'
t NOMATCH 'feedback_stop_and_ask_at_access_boundaries.md'        'FP: sk inside "ask_"'
t NOMATCH 'the risk_assessment_matrix_for_this_project'          'FP: sk inside "risk_"'
t NOMATCH 'task_queue_worker_configuration_value'                'FP: sk inside "task_"'
t NOMATCH 'sk-  (the prefix on its own, discussed in prose)'     'prose about the prefix'
t NOMATCH '# TODO: put the api key in .env, never in the repo'   'prose about keys'
t NOMATCH 'It needs a Worker deploy, two KV namespace ids and three secrets.' 'prose about secrets'

# ── FAIL-CLOSED: A SCANNER THAT CANNOT RUN IS NOT A CLEAN SCAN ────────────────────────────────
# MEASURED 2026-09-04, empirically: with a real AKIA key staged and a `git` on PATH that exits 1,
# this gate printed "staged content clean" and exited 0 — the leak would have committed. `set -euo
# pipefail` is on line 7 and did nothing, because a pipeline ending in `|| true` is an OR-list and
# errexit never fires on one. Confirmed independently by reviewer-Codex. These three cases are the
# calibration: the middle one is the defect, and it must stay red if anyone reintroduces `|| true`.
echo "── fail-closed (the scanner itself) ──────────────────────────────────────"
G_SH="$(cd "$(dirname "$0")" && pwd)/gate.sh"
SB=$(mktemp -d); ( cd "$SB" && git init -q . && git config user.email t@t && git config user.name t
  # The key is ASSEMBLED, never written literally. This gate BLOCKED the commit adding this very
  # file when the fixture held the whole string — correctly: a literal AKIA run in a staged diff is
  # a leak by every test it applies. The right fix is a fixture that does not look like a leak, not
  # a wider exemption; widening the detector to admit your own tests is how a gate stops working.
  printf 'AKIA%s\n' '1234567890ABCDEF' > leak.txt && git add leak.txt ) >/dev/null 2>&1
mkdir -p "$SB/stub"; printf '#!/bin/sh\nexit 1\n' > "$SB/stub/git"; chmod +x "$SB/stub/git"

( cd "$SB" && bash "$G_SH" >/dev/null 2>&1 ); rc=$?
if [ "$rc" -eq 1 ]; then P=$((P+1)); echo "  ok      a staged secret BLOCKS (exit 1)"
else F=$((F+1)); echo "  FAIL    a staged secret did not block (exit $rc)"; fi

( cd "$SB" && PATH="$SB/stub:$PATH" bash "$G_SH" >/dev/null 2>&1 ); rc=$?
if [ "$rc" -eq 1 ]; then P=$((P+1)); echo "  ok      a scanner that CANNOT RUN blocks (exit 1) — fails closed"
else F=$((F+1)); echo "  FAIL    FAIL-OPEN: scanner could not run and the gate passed (exit $rc)"; fi

( cd "$SB" && git rm -q --cached leak.txt >/dev/null 2>&1; rm -f leak.txt
  printf 'hello\n' > ok.txt && git add ok.txt && bash "$G_SH" >/dev/null 2>&1 ); rc=$?
if [ "$rc" -eq 0 ]; then P=$((P+1)); echo "  ok      a genuinely clean tree still PASSES (no false positive)"
else F=$((F+1)); echo "  FAIL    clean tree blocked (exit $rc) — the fix over-blocks"; fi
rm -rf "$SB"

echo "──────────────────────────────────────────────────────────────────────────"
echo "  $P passed, $F failed, of $((P+F))"
[ "$F" -eq 0 ] || exit 1
