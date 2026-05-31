#!/usr/bin/env bash
#
# Manual smoke test against the REAL GitHub API. Validates the two behaviours the
# unit-test mock cannot: that bgh-proxy's node-resolution GraphQL query is schema-valid
# against live GitHub, and that media-type passthrough (diff/raw) works end to end. It
# also spot-checks policy enforcement. Uses a read-only policy; never writes anything.
#
# Usage (from repo root):
#   BGH_GITHUB_TOKEN=$(gh auth token) ./scripts/smoke-test.sh [owner/repo]
#
set -euo pipefail

REPO="${1:-cli/cli}"            # a repo you can read; default cli/cli
OWNER="${REPO%%/*}"; NAME="${REPO##*/}"
TOKEN="${BGH_GITHUB_TOKEN:-${GITHUB_TOKEN:-$(gh auth token 2>/dev/null || true)}}"
[[ -z "$TOKEN" ]] && { echo "no token: set BGH_GITHUB_TOKEN or run gh auth login" >&2; exit 1; }

pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILED=1; }
FAILED=0
gql() { curl -sS -H "Authorization: token $TOKEN" -X POST https://api.github.com/graphql -d "$1"; }

echo "== 1. node-resolution query is schema-valid on live GitHub =="
REPO_ID=$(gql "{\"query\":\"{repository(owner:\\\"$OWNER\\\",name:\\\"$NAME\\\"){id}}\"}" \
            | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
if [[ -z "$REPO_ID" ]]; then
  fail "could not fetch a repo node id for $REPO"
else
  RESOLVE='{"query":"query($ids:[ID!]!){nodes(ids:$ids){__typename ... on RepositoryNode{repository{nameWithOwner}} ... on Repository{nameWithOwner} ... on Ref{repository{nameWithOwner}} ... on Release{repository{nameWithOwner}}}}","variables":{"ids":["'"$REPO_ID"'"]}}'
  RESP=$(gql "$RESOLVE")
  if grep -q '"errors"' <<<"$RESP"; then
    fail "resolver query returned GraphQL errors (SCHEMA MISMATCH — mutations would break):"; echo "$RESP" | head -c 400; echo
  elif grep -q "\"nameWithOwner\":\"$OWNER/$NAME\"" <<<"$RESP"; then
    pass "nodes(ids:) resolved the repo node -> $OWNER/$NAME"
  else
    fail "unexpected resolver response:"; echo "$RESP" | head -c 400; echo
  fi
fi

echo "== 2/3. start proxy (socket mode, read-only policy for $REPO) =="
BINDIR=$(mktemp -d); BIN="$BINDIR/bgh-proxy"
go build -o "$BIN" ./cmd/bgh-proxy/
export HOME=$(mktemp -d); mkdir -p "$HOME/.config/bgh"
SOCK="$HOME/.config/bgh/proxy.sock"
cat >"$HOME/.config/bgh/config.toml" <<EOF
socket = "$SOCK"
mode = "socket"
policy_file = "$HOME/.config/bgh/policy.toml"
audit_log = "$HOME/.config/bgh/audit.jsonl"
admin_bind = "127.0.0.1:17844"
EOF
cat >"$HOME/.config/bgh/policy.toml" <<EOF
[defaults]
mode = "deny"
[[repo]]
name = "$REPO"
access = "read"
EOF
BGH_GITHUB_TOKEN="$TOKEN" "$BIN" serve >"$HOME/serve.log" 2>&1 &
PROXY_PID=$!
trap 'kill $PROXY_PID 2>/dev/null; rm -rf "$HOME" "$BINDIR"' EXIT
for _ in $(seq 1 50); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
[[ -S "$SOCK" ]] || { fail "proxy did not start"; cat "$HOME/serve.log"; exit 1; }
sock() { curl -sS --unix-socket "$SOCK" -H "Authorization: token x" "$@"; }

echo "== 2. media-type passthrough (diff) through the proxy =="
PR=$(gql "{\"query\":\"{repository(owner:\\\"$OWNER\\\",name:\\\"$NAME\\\"){pullRequests(first:1){nodes{number}}}}\"}" \
       | grep -o '"number":[0-9]*' | head -1 | cut -d: -f2)
if [[ -n "${PR:-}" ]]; then
  DIFF=$(sock -H "Accept: application/vnd.github.v3.diff" "http://localhost/repos/$REPO/pulls/$PR")
  grep -q '^diff --git' <<<"$DIFF" \
    && pass "Accept: vnd.github.diff returned a diff (client header forwarded)" \
    || { fail "diff media-type not honoured (got JSON?):"; head -c 160 <<<"$DIFF"; echo; }
else
  echo "  (skipped: $REPO has no pull requests)"
fi

echo "== 3. policy enforcement through the proxy =="
A=$(sock -o /dev/null -w '%{http_code}' "http://localhost/repos/$REPO/pulls?per_page=1")
[[ "$A" != 403 ]] && pass "allowed repo read -> HTTP $A" || fail "allowed repo was denied ($A)"
D=$(sock -o /dev/null -w '%{http_code}' "http://localhost/repos/github/docs/pulls?per_page=1")
[[ "$D" == 403 ]] && pass "unlisted repo read -> HTTP 403 (denied)" || fail "unlisted repo not denied ($D)"

echo
[[ "$FAILED" == 0 ]] && echo "all checks passed" || { echo "some checks FAILED"; exit 1; }
