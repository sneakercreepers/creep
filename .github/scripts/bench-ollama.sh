#!/usr/bin/env bash
# Prepares the nightly bench's local model (#36) in the Ollama service
# container: pulls BASE_MODEL, refuses it unless Ollama reports
# BASE_MODEL_DIGEST (the tag is mutable, the manifest digest is not; Ollama
# checks every layer against the manifest), then creates BENCH_MODEL from it
# with temperature 0, a fixed seed and a context that holds the bench's
# prompts, so the nightly numbers move only when creep or the pin does.
set -euo pipefail

url="${OLLAMA_URL:?}"
base="${BASE_MODEL:?}"
want="${BASE_MODEL_DIGEST:?}"
bench="${BENCH_MODEL:?}"

# The gate matches a baseline by model name, so the name carries the pin.
case "$bench" in
  *"-${want:0:12}") ;;
  *) echo "::error::BENCH_MODEL '$bench' must end with -${want:0:12}, the digest prefix" >&2; exit 2 ;;
esac

for _ in $(seq 60); do
  curl -fsS "$url/api/version" >/dev/null 2>&1 && break
  sleep 2
done
curl -fsS "$url/api/version"
echo

jq -n --arg m "$base" '{model: $m, stream: false}' |
  curl -fsS --max-time 1800 "$url/api/pull" -d @- >/dev/null
got="$(curl -fsS "$url/api/tags" | jq -r --arg m "$base" '.models[] | select(.name == $m) | .digest')"
if [ "$got" != "$want" ]; then
  echo "::error::$base has digest '$got', want '$want'; update BASE_MODEL_DIGEST only after reviewing the new model" >&2
  exit 1
fi

jq -n --arg m "$bench" --arg from "$base" \
  '{model: $m, from: $from, parameters: {temperature: 0, seed: 7, num_ctx: 16384}, stream: false}' |
  curl -fsS --max-time 300 "$url/api/create" -d @- >/dev/null
echo "bench model $bench from $base ($got)"
