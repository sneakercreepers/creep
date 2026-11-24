#!/usr/bin/env bash
# Writes the creep policy for a bench run (#36) to the file named by $1, from
# BENCH_CONTRACT, BENCH_ENDPOINT and BENCH_MODEL. Each value is checked
# against a closed pattern first, so no value can add a YAML key, an
# egress.allow entry or a consent of its own: the policy is the only layer
# that grants consent (ADR 0030 amendment, threat model B6). http:// is
# accepted only for 127.0.0.1, the runner's own Ollama.
set -euo pipefail

out="${1:?usage: bench-policy.sh <policy file>}"
contract="${BENCH_CONTRACT:-}"
endpoint="${BENCH_ENDPOINT:-}"
model="${BENCH_MODEL:-}"

fail() { echo "::error::bench-policy: $*" >&2; exit 2; }

case "$contract" in
  openai | anthropic) ;;
  *) fail "BENCH_CONTRACT must be openai or anthropic" ;;
esac
[[ "$model" =~ ^[A-Za-z0-9._:/@-]{1,128}$ ]] || fail "BENCH_MODEL must be 1 to 128 of A-Z a-z 0-9 . _ : / @ -"

label='[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
https_re="^https://(${label}(\.${label})+)(:([0-9]{1,5}))?(/[A-Za-z0-9._~/-]*)?$"
local_re='^http://127\.0\.0\.1:([0-9]{1,5})(/[A-Za-z0-9._~/-]*)?$'
if [[ "$endpoint" =~ $https_re ]]; then
  host="${BASH_REMATCH[1]}"
  port="${BASH_REMATCH[6]}"
  allow="$host${port:+:$port}"
  origin="https://$allow"
elif [[ "$endpoint" =~ $local_re ]]; then
  allow="127.0.0.1:${BASH_REMATCH[1]}"
  origin="http://$allow"
else
  fail "BENCH_ENDPOINT must be an https:// URL with a lowercase DNS name, or http://127.0.0.1:<port>"
fi

umask 077
cat >"$out" <<POLICY
defaults:
  model: { contract: "$contract", endpoint: "$endpoint", name: "$model" }
  egress: { allow: ["$allow"] }
consent: ["$origin"]
POLICY
echo "bench-policy: $contract model $model at $origin"
