#!/usr/bin/env bash
#
# End-to-end ISOLATION test against the REAL GitHub API. Stands up bgh-proxy with a
# policy that allows ONE private repo and denies another, then attempts to reach the
# denied repo through every bypass vector and asserts each is blocked and the denied
# repo's secret marker never leaks. Also confirms the allowed repo still works.
#
# This is what proves the security holds against real GitHub (not just the unit mock):
# multi-root GraphQL, node-id reads/mutations, case variants, and path traversal.
#
# Requirements: a token with `repo` scope (issues created/closed; no repo deletion).
#   Resolved from: BGH_GITHUB_TOKEN, GITHUB_TOKEN, ~/.config/bgh/github-token, or gh.
# Usage (from repo root):  ./scripts/integration-test.sh
#
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOK="${BGH_GITHUB_TOKEN:-${GITHUB_TOKEN:-$(cat ~/.config/bgh/github-token 2>/dev/null || gh auth token 2>/dev/null || true)}}"
[ -z "$TOK" ] && { echo "no token (set BGH_GITHUB_TOKEN, or run bgh-proxy login)"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }

api(){ curl -sS -H "Authorization: token $TOK" -H "Accept: application/vnd.github+json" "$@"; }
OWNER=$(api https://api.github.com/user | python3 -c 'import json,sys;print(json.load(sys.stdin)["login"])')
ALLOW="bgh-test-allowed"; DENY="bgh-test-denied"
echo "owner=$OWNER  allow=$ALLOW  deny=$DENY"

ensure_repo(){ # create a private repo if it does not exist
  if [ "$(api -o /dev/null -w '%{http_code}' https://api.github.com/repos/$OWNER/$1)" != 200 ]; then
    api -X POST https://api.github.com/user/repos \
      -d "{\"name\":\"$1\",\"private\":true,\"auto_init\":true,\"description\":\"bgh-proxy isolation test\"}" >/dev/null
    echo "  created $OWNER/$1"
  fi
}
ensure_repo "$ALLOW"; ensure_repo "$DENY"

# Fresh secret issue in the denied repo each run (issues are cheap; closed at the end).
MARK="BGH_SECRET_$(python3 -c 'import secrets;print(secrets.token_hex(4))')"
ISSUE_JSON=$(api -X POST https://api.github.com/repos/$OWNER/$DENY/issues \
  -d "{\"title\":\"DENIED secret\",\"body\":\"$MARK must never leak through the proxy\"}")
NODE=$(printf '%s' "$ISSUE_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin)["node_id"])')
NUM=$(printf  '%s' "$ISSUE_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin)["number"])')
echo "  denied issue #$NUM node=$NODE marker=$MARK"

# GraphQL request bodies (generated in python to avoid shell-quoting issues).
BODYDIR=$(mktemp -d)
OWNER="$OWNER" DENY="$DENY" ALLOW="$ALLOW" NODE="$NODE" MARK="$MARK" BODYDIR="$BODYDIR" python3 - <<'PY'
import json,os
o,deny,allow,node,mark,d=(os.environ[k] for k in("OWNER","DENY","ALLOW","NODE","MARK","BODYDIR"))
def w(n,q): open(f"{d}/{n}.json","w").write(json.dumps({"query":q}))
w("single",   f'query{{repository(owner:"{o}",name:"{deny}"){{issue(number:1){{title body}}}}}}')
w("multiroot",f'query{{a:repository(owner:"{o}",name:"{allow}"){{name}} b:repository(owner:"{o}",name:"{deny}"){{issue(number:1){{title body}}}}}}')
w("nodeid",   f'query{{node(id:"{node}"){{... on Issue{{title body}}}}}}')
w("search",   f'query{{search(query:"repo:{o}/{deny} {mark}",type:ISSUE,first:5){{nodes{{... on Issue{{title body}}}}}}}}')
w("mutation", f'mutation{{addComment(input:{{subjectId:"{node}",body:"x"}}){{clientMutationId}}}}')
w("nav_repos",f'query{{repository(owner:"{o}",name:"{allow}"){{owner{{repositories(first:100){{nodes{{name issues(first:10){{nodes{{body}}}}}}}}}}}}}}')
w("nav_byname",f'query{{repository(owner:"{o}",name:"{allow}"){{owner{{repository(name:"{deny}"){{issues(first:5){{nodes{{body}}}}}}}}}}}}')
w("allowed",  f'query{{repository(owner:"{o}",name:"{allow}"){{issue(number:1){{title}}}}}}')
PY

# Build the proxy with the real environment (so go uses its module/toolchain cache).
PROXY="$(mktemp -u)"
(cd "$ROOT" && go build -o "$PROXY" ./cmd/bgh-proxy/) || exit 1

# Isolated runtime dir: deny-default policy that allows only the allowed repo. HOME is
# overridden only for the serve process so its store/secret land here (not the real ~).
T=$(mktemp -d); mkdir -p "$T/.config/bgh"; SOCK="$T/p.sock"
printf 'socket="%s"\nmode="socket"\npolicy_file="%s"\naudit_log="%s"\nadmin_bind="127.0.0.1:18831"\n' \
  "$SOCK" "$T/.config/bgh/policy.toml" "$T/.config/bgh/audit.jsonl" > "$T/.config/bgh/config.toml"
printf '[defaults]\nmode="deny"\n[[repo]]\nname="%s/%s"\naccess="read"\n' "$OWNER" "$ALLOW" > "$T/.config/bgh/policy.toml"
HOME="$T" BGH_GITHUB_TOKEN="$TOK" "$PROXY" serve >"$T/serve.log" 2>&1 &
PID=$!
cleanup(){ kill $PID 2>/dev/null; rm -rf "$T" "$BODYDIR" "$PROXY"
  api -X PATCH https://api.github.com/repos/$OWNER/$DENY/issues/$NUM -d '{"state":"closed"}' >/dev/null 2>&1; }
trap cleanup EXIT
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "proxy failed to start"; cat "$T/serve.log"; exit 1; }

P=0; F=0
req(){ curl -sS --unix-socket "$SOCK" -H "Authorization: token dummy" "$@"; }
den(){ local desc="$1"; shift; local body code
  body=$(req -w $'\n%{http_code}' "$@"); code=$(printf '%s' "$body"|tail -1); body=$(printf '%s' "$body"|sed '$d')
  if [ "$code" = 403 ] && ! printf '%s' "$body" | grep -q "$MARK"; then echo "  PASS  $desc"; P=$((P+1))
  else echo "  FAIL  $desc (code=$code leak=$(printf '%s' "$body"|grep -q "$MARK" && echo YES || echo no))"; F=$((F+1)); fi; }
code(){ local desc="$1" want="$2"; shift 2; local c; c=$(req -o /dev/null -w '%{http_code}' "$@")
  [ "$c" = "$want" ] && { echo "  PASS  $desc ($c)"; P=$((P+1)); } || { echo "  FAIL  $desc (got $c want $want)"; F=$((F+1)); }; }
gql(){ den "$1" -X POST http://localhost/graphql -d @"$BODYDIR/$2.json"; }

echo "== the denied private repo must be unreachable via every vector =="
den  "REST repo"            "http://localhost/repos/$OWNER/$DENY"
den  "REST issue"           "http://localhost/repos/$OWNER/$DENY/issues/$NUM"
den  "REST issue UPPERCASE" "http://localhost/repos/$OWNER/$(printf '%s' "$DENY"|tr a-z A-Z)/issues/$NUM"
code "REST .. traversal -> 400" 400 --path-as-is "http://localhost/repos/$OWNER/$ALLOW/../../$OWNER/$DENY/issues/$NUM"
gql  "GraphQL repository()"   single
gql  "GraphQL multi-root"     multiroot
gql  "GraphQL node(id) read"  nodeid
gql  "GraphQL search repo:"   search
gql  "GraphQL node-id mutation" mutation
gql  "GraphQL nav owner.repositories" nav_repos
gql  "GraphQL nav owner.repository(denied)" nav_byname
echo "== the allowed repo must still work =="
code "REST allowed issue"  200 "http://localhost/repos/$OWNER/$ALLOW/issues/1"
code "GraphQL allowed"     200 -X POST http://localhost/graphql -d @"$BODYDIR/allowed.json"

echo; echo "RESULT: $P passed, $F failed"
[ "$F" = 0 ] && echo "isolation holds against real GitHub" || { echo "ISOLATION FAILURE"; exit 1; }
