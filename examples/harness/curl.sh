#!/usr/bin/env bash
# semgate over HTTP with curl: health, check, approve (human side), re-check.
#   semgate harness init --purpose "Software development in ~/code/app"
#   semgate serve --http --token-file ~/.semgate/http/check.token --approve-token-file ~/.semgate/http/approve.token
#   bash examples/harness/curl.sh
set -eu
URL="${SEMGATE_URL:-http://127.0.0.1:8787}"
CHECK_TOKEN="$(cat "${SEMGATE_CHECK_TOKEN_FILE:-$HOME/.semgate/http/check.token}")"
APPROVE_TOKEN="$(cat "${SEMGATE_APPROVE_TOKEN_FILE:-$HOME/.semgate/http/approve.token}")"
REQ="{\"tool\": \"bash\", \"arguments\": {\"command\": \"git push origin main\"}, \"session_id\": \"curl-demo-1\",
      \"cwd\": \"$PWD\", \"user_messages\": [\"commit my changes and push them\"]}"

curl -s "$URL/v1/health"; echo

echo "== check (agent side, check token)"
ANSWER="$(curl -s -X POST "$URL/v1/check" -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CHECK_TOKEN" --data-binary "$REQ")"
echo "$ANSWER"
ID="$(printf '%s' "$ANSWER" | sed -n 's/.*"approval_id": *"\([0-9a-f]\{32\}\)".*/\1/p')"
if [ -z "$ID" ]; then echo "no ask, nothing to approve"; exit 0; fi

echo "== approve (HUMAN side, approve token)"
curl -s -X POST "$URL/v1/approve" -H "Content-Type: application/json" \
  -H "Authorization: Bearer $APPROVE_TOKEN" \
  --data-binary "{\"approval_id\": \"$ID\", \"approved\": true, \"by\": \"${USER:-human}\"}"; echo

echo "== re-check: allow, once"
curl -s -X POST "$URL/v1/check" -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CHECK_TOKEN" --data-binary "$REQ"; echo
