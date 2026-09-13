#!/usr/bin/env bash
# pezkuwi/host/test-publish.sh [lists directory]
#
# phishing-publish.sh against a scratch repository and web root: it publishes good lists, leaves
# index.html alone, and refuses, serving exactly what it served before, when master's history
# was rewritten, a protected domain would be blocked, the deny list shrinks too far, an entry
# ends in a dot, or all/ holds something other than top-level domain directories.
#
# The lists directory (default: the repository root) must hold publishable lists: all.json,
# address.json, all/. Nothing here touches a network or a real web root.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LISTS="$(cd "${1:-$HERE/../..}" && pwd)"
SB="$(mktemp -d "${TMPDIR:-/tmp}/phishing-publish-test.XXXXXX")"
trap 'rm -rf "$SB"' EXIT
PASS=0
FAIL=0

check() {
  if [ "$2" = "$3" ]; then printf '  PASS  %-58s %s\n' "$1" "$3"; PASS=$((PASS + 1))
  else printf '  FAIL  %-58s expected [%s] got [%s]\n' "$1" "$2" "$3"; FAIL=$((FAIL + 1)); fi
}
g() { git -C "$SB/work" -c user.email=t@example.invalid -c user.name=t "$@"; }
served() { (cd "$SB/www" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) | sha256sum | cut -c1-16; }
publish() { "$SB/publish.sh" >"$SB/out" 2>&1; echo $?; }
# edit <message> <python applied to the lists in the work tree>
edit() {
  (cd "$SB/work" && python3 -c "$2")
  g add -A
  g commit -qm "$1"
  g push -q origin HEAD:master
}

sed -e "s#^REPO_URL=.*#REPO_URL=$SB/remote.git#" \
    -e "s#^STATE_DIR=.*#STATE_DIR=$SB/state#" \
    -e "s#^WEB_ROOT=.*#WEB_ROOT=$SB/www#" \
    -e "s#^LOCK_FILE=.*#LOCK_FILE=$SB/publish.lock#" \
    -e "s#--chown=root:root ##" \
    "$HERE/phishing-publish.sh" >"$SB/publish.sh"
chmod +x "$SB/publish.sh"
if grep -nE '^(REPO_URL=https|STATE_DIR=/var|WEB_ROOT=/var|LOCK_FILE=/run)' "$SB/publish.sh"; then
  echo "HARNESS: a production path survived the rewrite; refusing to run" >&2
  exit 2
fi

git init -q --bare -b master "$SB/remote.git"
git init -q -b master "$SB/work"
g remote add origin "$SB/remote.git"
cp -r "$LISTS/all.json" "$LISTS/address.json" "$LISTS/all" "$SB/work/"
g add -A && g commit -qm lists && g push -q origin HEAD:master
# Every later case pushes to this remote. If the first push did not land, each would fail on git
# and the "served lists did not change" checks would pass for that reason alone.
if [ "$(git --git-dir="$SB/remote.git" rev-parse --verify -q refs/heads/master)" != "$(g rev-parse HEAD)" ]; then
  echo "HARNESS: the scratch remote did not receive master; no case ran" >&2
  exit 2
fi

# The web root as the host had it: older lists, a stray file the sync no longer writes, the page.
mkdir -p "$SB/www/all/com"
python3 - "$LISTS/all.json" "$SB/www" <<'PY'
import json, sys
deny = json.load(open(sys.argv[1]))["deny"]
older = deny[: len(deny) - len(deny) // 100]
json.dump({"allow": [], "deny": older, "denySub": []}, open(f"{sys.argv[2]}/all.json", "w"))
PY
printf '{}\n' >"$SB/www/address.json"
printf '[]\n' >"$SB/www/all/all.json"
printf '<html>page</html>\n' >"$SB/www/index.html"
INDEX="$(sha256sum "$SB/www/index.html")"

echo "== publishes good lists"
check "exit" 0 "$(publish)"
check "all.json is master's" "$(sha256sum <"$LISTS/all.json")" "$(sha256sum <"$SB/www/all.json")"
check "a shard is master's" "$(sha256sum <"$LISTS/all/com/all.json")" "$(sha256sum <"$SB/www/all/com/all.json")"
check "the stray all/all.json is gone" no "$([ -e "$SB/www/all/all.json" ] && echo yes || echo no)"
check "index.html untouched" "$INDEX" "$(sha256sum "$SB/www/index.html")"
check "the published commit is recorded" "$(git -C "$SB/work" rev-parse HEAD)" "$(cat "$SB/state/published")"
check "nothing new: exit" 0 "$(publish)"
check "nothing new: silent" "" "$(cat "$SB/out")"

refused() { # refused <label> <python> <text the refusal must give>
  local before rc
  before="$(served)"
  edit "$1" "$2"
  rc="$(publish)"
  check "$1: refused" "1 REFUSED" "$rc $(grep -o '^REFUSED' "$SB/out")"
  # For the reason too: checks overlap, and a refusal from the wrong one would hide that the right
  # one no longer works.
  check "$1: for its reason" yes "$(grep -qF -- "$3" "$SB/out" && echo yes || echo no)"
  check "$1: the served lists did not change" "$before" "$(served)"
  g reset -q --hard HEAD~1
  g push -q -f origin HEAD:master
  rm -rf "$SB/state/repo.git"
}

L='import json, os; a = json.load(open("all.json"))'
W='; json.dump(a, open("all.json", "w"))'
refused "blocks a protected domain" "$L; a['deny'].append('pezkuwichain.io'); os.makedirs('all/io', exist_ok=True); s = json.load(open('all/io/all.json')) if os.path.exists('all/io/all.json') else []; json.dump(s + ['pezkuwichain.io'], open('all/io/all.json', 'w'))$W" "would block our domain pezkuwichain.io"
refused "shrinks more than the limit" "$L; keep = set(a['deny'][: len(a['deny']) // 2]); a['deny'] = [u for u in a['deny'] if u in keep]$W
for t in os.listdir('all'):
    json.dump([u for u in json.load(open(f'all/{t}/all.json')) if u in keep], open(f'all/{t}/all.json', 'w'))" "the deny list would shrink"
refused "an entry ends in a dot" "$L; a['deny'].append('scam-test.xyz.')$W" "all/ and all.json disagree"
refused "a file in all/" "open('all/all.json', 'w').write('[]')" "is not a top-level domain directory"
refused "shards disagree with all.json" "import json; s = json.load(open('all/com/all.json')); json.dump(s[1:], open('all/com/all.json', 'w'))" "all/ and all.json disagree"

echo "== rewritten history"
edit "one more" "import json; a = json.load(open('address.json')); a['next.example'] = []; json.dump(a, open('address.json', 'w'))"
g commit -q --allow-empty -m "published next"
g push -q origin HEAD:master
[ "$(g rev-list --count HEAD)" = 3 ] || { echo "HARNESS: expected three commits before rewriting history" >&2; exit 2; }
check "a new commit publishes" 0 "$(publish)"
published="$(served)"
g reset -q --hard HEAD~2
# A different list on the rewritten branch, so publishing it would change what is served.
(cd "$SB/work" && python3 -c 'import json; a = json.load(open("address.json")); a["rewritten.example"] = []; json.dump(a, open("address.json", "w"))')
g commit -qam "rewritten"
g push -q -f origin HEAD:master
check "a non-descendant master: refused" "1 REFUSED" "$(publish) $(grep -o '^REFUSED' "$SB/out")"
check "a non-descendant master: served lists unchanged" "$published" "$(served)"

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
