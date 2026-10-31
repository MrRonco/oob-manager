#!/usr/bin/env bash
# ZAP scans against the dev harness with mock BMCs (plan 06 §3.2). Linux + Docker only
# (CI's zap jobs); `make zap-quick` / `make zap-full` build the harness and call this.
#   quick: passive baseline of the unauthenticated pages (every CI run, about 3 min).
#   full:  authenticated passive baseline (GET-only spider, state-changing paths excluded)
#          plus zap-api-scan of docs/api/openapi.yaml with a read-only token (nightly).
# Reports land in $OUT (HTML/JSON/Markdown only; the session and token never leave $WRK).
set -euo pipefail
MODE=${1:?usage: run.sh quick|full}
: "${ZAP_IMAGE:?}" "${BIN:?}"
PORT=${PORT:-18443}
OUT=${OUT:-zap-reports}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
STATE_NAME="oob-manager-zap-$PORT.json"
STATE="${TMPDIR:-/tmp}/$STATE_NAME"
BASE="https://127.0.0.1:$PORT"

WRK=$(mktemp -d)
# The ZAP image runs as its own non-root user, which must read the configs and write the
# reports. $WRK is a fresh temp dir on a throwaway CI runner, deleted on exit.
chmod 0777 "$WRK"
mkdir -p "$OUT"
OOB_DEV=1 OOB_DEV_LISTEN="127.0.0.1:$PORT" OOB_DEV_STATE="$STATE_NAME" \
  "$BIN" -test.run '^TestDevServer$' -test.timeout 0 >"$OUT/harness.log" 2>&1 &
HARNESS=$!
cleanup() { kill "$HARNESS" 2>/dev/null || true; rm -rf "$WRK"; }
trap cleanup EXIT
for _ in $(seq 90); do
  curl -sk -o /dev/null "$BASE/readyz" && [ -s "$STATE" ] && break
  sleep 2
done
curl -sk -o /dev/null "$BASE/readyz" || { echo "dev harness did not start"; tail -20 "$OUT/harness.log"; exit 1; }
cp "$HERE/rules.tsv" "$HERE/api-rules.tsv" "$REPO/docs/api/openapi.yaml" "$WRK/"

zap() { docker run --rm --network host -v "$WRK":/zap/wrk:rw "$ZAP_IMAGE" "$@"; }
# Copy the reports after every scan, so a later scan that hits the job timeout cannot
# take the earlier results with it.
save() { cp "$WRK"/*.html "$WRK"/*.json "$WRK"/*.md "$OUT/" 2>/dev/null || true; }
status=0
case "$MODE" in
quick)
  zap zap-baseline.py -t "$BASE/login" -c rules.tsv -m 1 -T 3 -s \
    -r quick.html -J quick.json -w quick.md || status=$?
  save
  ;;
full)
  # Never let the spider submit forms or follow a state-changing link.
  cat >"$WRK/auth.prop" <<PROP
spider.processform=false
spider.postform=false
PROP
  i=0
  for re in '.*/logout.*' '.*/stepup.*' '.*/power.*' '.*/fan/lease.*' '.*/console/.*' '.*/serial.*' \
    '.*/ws/.*' '.*/bmc/reset.*' '.*/delete.*' '.*/enable.*' '.*/disable.*' '.*/test.*' '.*/reset.*'; do
    printf 'globalexcludeurl.url_list.url(%d).regex=%s\nglobalexcludeurl.url_list.url(%d).enabled=true\n' "$i" "$re" "$i" >>"$WRK/auth.prop"
    i=$((i + 1))
  done
  NODE_TLS_REJECT_UNAUTHORIZED=0 node "$HERE/signin.mjs" "$STATE" "$WRK/auth.prop" 2>/dev/null
  zap zap-baseline.py -t "$BASE/" -c rules.tsv -m 3 -T 10 -s -z "-configfile /zap/wrk/auth.prop" \
    -r full.html -J full.json -w full.md || status=$?
  save
  # The read-only API: one request per second stays under the 60/min token limit, and the
  # active scan is capped (zap-api-scan's -T does not bound it): 8 min in all, 1 per rule.
  {
    echo 'scanner.threadPerHost=1'
    echo 'scanner.delayInMs=1000'
    echo 'scanner.maxScanDurationInMins=8'
    echo 'scanner.maxRuleDurationInMins=1'
    # Stay on the API: probes of other paths (/WEB-INF/…, POST /) get the UI's HTML 404,
    # which is correct there but would trip the API-only content-type rule 100001. The bare
    # target URL (no path) is excluded too: the scan requests it once and gets the UI page.
    echo 'globalexcludeurl.url_list.url(0).regex=^https?://[^/]+(/(?!api/|healthz|readyz|metrics).*)?$'
    echo 'globalexcludeurl.url_list.url(0).enabled=true'
    echo 'replacer.full_list(0).description=token'
    echo 'replacer.full_list(0).enabled=true'
    echo 'replacer.full_list(0).matchtype=REQ_HEADER'
    echo 'replacer.full_list(0).matchstr=Authorization'
    echo 'replacer.full_list(0).regex=false'
    printf 'replacer.full_list(0).replacement=Bearer %s\n' "$(jq -r .api_token "$STATE")"
  } >"$WRK/api.prop"
  zap zap-api-scan.py -t /zap/wrk/openapi.yaml -f openapi -O "$BASE" -c api-rules.tsv -T 8 -s \
    -z "-configfile /zap/wrk/api.prop" -r api.html -J api.json -w api.md || status=$((status | $?))
  ;;
*) echo "unknown mode $MODE"; exit 2 ;;
esac
save
exit "$status"
