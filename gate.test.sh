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

echo "──────────────────────────────────────────────────────────────────────────"
echo "  $P passed, $F failed, of $((P+F))"
[ "$F" -eq 0 ] || exit 1
