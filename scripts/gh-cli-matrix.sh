#!/usr/bin/env bash
#
# gh CAN/CANNOT matrix against a bgh-proxy deployment, driven by REAL gh (not curl), so it
# exercises gh's actual REST + GraphQL query shapes end-to-end. Proves the policy boundary
# holds for everyday commands and surfaces any false-denies (a gh query shape the classifier
# doesn't recognize yet) without ever trusting a green that came from github.com directly.
#
# Usage:  scripts/gh-cli-matrix.sh <proxy-host> <owner> [allowed-repo] [denied-repo]
#   e.g.  scripts/gh-cli-matrix.sh proxy.example.ts.net myuser
#
# Assumes the gh token you're logged in with: <owner>/<allowed-repo>=read-write,
# <owner>/<denied-repo>=none, org <owner>=read (enumeration). `search` is OPTIONAL (granted only
# if you enabled "allow search"), so it is reported informationally, not asserted. A "x" on a
# should-WORK line is a false-deny (fixable); a "x" on a should-BLOCK line would be a real leak.
set -uo pipefail

usage(){ echo "usage: $0 <proxy-host> <owner> <allowed-repo> <denied-repo>"; echo "  e.g. $0 proxy.example.ts.net myuser my-allowed-repo my-denied-repo"; exit 1; }
HOST="${1:-}"; OWNER="${2:-}"; AR="${3:-}"; DR="${4:-}"
{ [ -z "$HOST" ] || [ -z "$OWNER" ] || [ -z "$AR" ] || [ -z "$DR" ]; } && usage
ALLOW="$OWNER/$AR"; DENY="$OWNER/$DR"; OTHER="octocat/Hello-World"  # octocat/Hello-World = GitHub's public sample (an owner you can't access)
export GH_HOST="$HOST"
command -v gh      >/dev/null || { echo "gh not found"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
pass=0; fail=0; note=0

# Canary: refuse to run if gh is talking to github.com instead of the proxy (a GITHUB_TOKEN /
# http_unix_socket bypass would otherwise produce false greens). The proxy answers /user with
# a synthetic {"login":"bgh-proxy"}; the real API never does.
who=$(gh api user --hostname "$HOST" 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("login",""))' 2>/dev/null)
if [ "$who" != "bgh-proxy" ]; then
  echo "!! gh is NOT on the proxy (gh api user => '$who', want 'bgh-proxy')."
  echo "   Fix:  unset GITHUB_TOKEN GH_TOKEN ; gh config set http_unix_socket \"\" ; gh auth status"
  exit 1
fi
echo "on the proxy (gh api user => bgh-proxy)"
echo "policy assumed: $ALLOW=read-write, $DENY=none, org $OWNER=read"
echo

can(){    local l="$1"; shift; local o; o=$("$@" 2>&1); if echo "$o"|grep -qiE 'bgh: denied|HTTP 403'; then echo "  x WRONGLY BLOCKED  $l"; fail=$((fail+1)); else echo "  + CAN      $l"; pass=$((pass+1)); fi; }
cannot(){ local l="$1"; shift; local o; o=$("$@" 2>&1); if echo "$o"|grep -qiE 'bgh: denied|HTTP 403'; then echo "  + CANNOT   $l"; pass=$((pass+1)); else echo "  x NOT BLOCKED  $l  [${o:0:70}]"; fail=$((fail+1)); fi; }
info(){   local l="$1"; shift; local o; o=$("$@" 2>&1); if echo "$o"|grep -qiE 'bgh: denied|HTTP 403'; then echo "  . $l -> CANNOT (not granted)"; else echo "  . $l -> CAN (granted)"; fi; }

echo "== should WORK (allowed repo / your account) =="
can "repo view (allowed)"          gh repo view "$ALLOW"
can "issue list (allowed)"         gh issue list -R "$ALLOW"
can "pr list (allowed)"            gh pr list -R "$ALLOW"
can "pr status (allowed)"          gh pr status -R "$ALLOW"
can "release list (allowed)"       gh release list -R "$ALLOW"
can "run list (allowed)"           gh run list -R "$ALLOW" -L 1
can "workflow list (allowed)"      gh workflow list -R "$ALLOW"
can "repo list (your account)"     gh repo list
can "org list"                     gh org list
can "api repo (allowed)"           gh api "repos/$ALLOW"
can "api graphql repository()"     gh api graphql -f query="{repository(owner:\"$OWNER\",name:\"$AR\"){name}}"

echo "== optional (off unless your token grants it) =="
info "search repos (needs the 'allow search' grant)"  gh search repos --owner "$OWNER" -L 5

echo "== should be BLOCKED (denied repo / other owner) =="
cannot "repo view (denied)"        gh repo view "$DENY"
cannot "issue list (denied)"       gh issue list -R "$DENY"
cannot "pr list (denied)"          gh pr list -R "$DENY"
cannot "api repo (denied)"         gh api "repos/$DENY"
cannot "api graphql repository(denied)" gh api graphql -f query="{repository(owner:\"$OWNER\",name:\"$DR\"){name}}"
cannot "repo view (other owner)"   gh repo view "$OTHER"
cannot "issue list (other owner)"  gh issue list -R "$OTHER"
cannot "api repo (other owner)"    gh api "repos/$OTHER"

echo "== WRITE =="
url=$(gh issue create -R "$ALLOW" --title "bgh matrix probe" --body "transient" 2>&1)
if   echo "$url"|grep -qiE 'bgh: denied|HTTP 403'; then echo "  x WRONGLY BLOCKED  issue create (allowed)"; fail=$((fail+1));
elif echo "$url"|grep -q 'http'; then echo "  + CAN      issue create (allowed rw)"; pass=$((pass+1)); gh issue close -R "$ALLOW" "$url" >/dev/null 2>&1;
else echo "  ? issue create unclear [${url:0:70}]"; note=$((note+1)); fi
cannot "issue create (denied)"     gh issue create -R "$DENY" --title x --body x

echo "== GIT (proxy is API-only: clone is expected to fail, and must NOT leak the denied repo) =="
rm -rf /tmp/bgh-ca /tmp/bgh-cd
gh repo clone "$ALLOW" /tmp/bgh-ca >/dev/null 2>&1; echo "  . clone allowed: $([ -d /tmp/bgh-ca/.git ] && echo cloned || echo 'failed (API-only proxy)')"
gh repo clone "$DENY"  /tmp/bgh-cd >/dev/null 2>&1
if [ -d /tmp/bgh-cd/.git ]; then echo "  x LEAK: denied repo cloned via git!"; fail=$((fail+1)); else echo "  + denied repo NOT cloned"; pass=$((pass+1)); fi
rm -rf /tmp/bgh-ca /tmp/bgh-cd

echo
echo "==== $pass passed, $fail FAILED, $note unclear ===="
[ "$fail" = 0 ] && echo "Every command behaved per policy." || { echo "Review the x lines above."; exit 1; }
