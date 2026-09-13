#!/usr/bin/env bash
#
# /usr/local/sbin/phishing-publish: keeps phishing.pezkuwichain.io on the lists in
# pezkuwichain/phishing master.
#
# This is the reviewed copy. It is installed by hand, as root, with its systemd units:
#
#   install -m 0755 pezkuwi/host/phishing-publish.sh /usr/local/sbin/phishing-publish
#   install -m 0644 pezkuwi/host/phishing-publish.service pezkuwi/host/phishing-publish.timer /etc/systemd/system/
#   systemctl daemon-reload && systemctl enable --now phishing-publish.timer
#
# The host pulls and nothing pushes to it, so no key to this host sits anywhere else. The
# extension and the apps fetch these lists to decide what to block, so the host does not
# publish whatever master holds. It checks first:
#
#   - master descends from the commit published last: no rewritten history;
#   - every file parses; all.json holds a deny list; each all/<tld>/all.json holds only that
#     top-level domain, and together they hold exactly the deny list;
#   - the deny list does not shrink by more than MAX_SHRINK_PERCENT against what is served now;
#   - no entry blocks one of our own domains (PROTECTED).
#
# Then it replaces the served lists in one rsync (--delay-updates) and leaves index.html alone.
#
#   exit 0   published, or nothing new
#   exit 1   refused; the served lists stay exactly as they were
set -euo pipefail

REPO_URL=https://github.com/pezkuwichain/phishing.git
STATE_DIR=/var/lib/phishing-publish
WEB_ROOT=/var/www/phishing
LOCK_FILE=/run/lock/phishing-publish.lock
MAX_SHRINK_PERCENT=2
MIN_DENY=10000
# Kept here, not read from the repository: this check must hold even if master does not.
PROTECTED="dks.news pex.mom pex.network pezkiwi.app pezkuwi.com pezkuwichain.io"

export LC_ALL=C GIT_TERMINAL_PROMPT=0
umask 022

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "another publish is running"
  exit 0
fi

MIRROR="$STATE_DIR/repo.git"
install -d -m 700 "$STATE_DIR"
if [ ! -d "$MIRROR" ]; then
  git init -q --bare "$MIRROR"
fi
git --git-dir="$MIRROR" fetch -q --no-tags "$REPO_URL" +refs/heads/master:refs/remotes/origin/master

new="$(git --git-dir="$MIRROR" rev-parse --verify refs/remotes/origin/master)"
old="$(cat "$STATE_DIR/published" 2>/dev/null || true)"
if [ "$new" = "$old" ]; then
  exit 0
fi
if [ -n "$old" ] && ! git --git-dir="$MIRROR" merge-base --is-ancestor "$old" "$new"; then
  echo "REFUSED: master ${new:0:12} does not descend from the published ${old:0:12}; its history was rewritten"
  exit 1
fi

stage="$(mktemp -d "$STATE_DIR/stage.XXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
git --git-dir="$MIRROR" archive "$new" all.json address.json all | tar -x -C "$stage"
if [ -n "$(find "$stage" ! -type f ! -type d)" ]; then
  echo "REFUSED: the lists at ${new:0:12} hold something other than files and directories"
  exit 1
fi

# shellcheck disable=SC2086 # PROTECTED is a list of names, split on purpose
python3 - "$stage" "$WEB_ROOT" "$MAX_SHRINK_PERCENT" "$MIN_DENY" $PROTECTED <<'PY'
import json
import os
import sys

stage, web, max_shrink, min_deny, protected = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5:]


def refuse(reason):
    print(f"REFUSED: {reason}")
    sys.exit(1)


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        refuse(f"{path} does not parse: {e}")


lists = load(os.path.join(stage, "all.json"))
deny = lists.get("deny") if isinstance(lists, dict) else None
if not isinstance(deny, list) or not all(isinstance(u, str) for u in deny):
    refuse("all.json holds no deny list of names")
if len(deny) < min_deny:
    refuse(f"all.json blocks {len(deny)} sites, fewer than {min_deny}")

address = load(os.path.join(stage, "address.json"))
if not isinstance(address, dict) or not all(isinstance(v, list) for v in address.values()):
    refuse("address.json is not a map of sites to addresses")

# An entry ending in a dot ("scam.xyz.") has an empty top-level domain, so no shard below can hold
# it and the shards-match check refuses it: the package would never find it in all/<tld>/all.json.
sharded = []
for top in sorted(os.listdir(os.path.join(stage, "all"))):
    if not os.path.isdir(os.path.join(stage, "all", top)):
        refuse(f"all/{top} is not a top-level domain directory")
    shard = load(os.path.join(stage, "all", top, "all.json"))
    if not isinstance(shard, list) or any(not isinstance(u, str) or u.rsplit(".", 1)[-1] != top for u in shard):
        refuse(f"all/{top}/all.json holds entries of another top-level domain")
    sharded += shard
if sorted(sharded) != sorted(deny):
    refuse("all/ and all.json disagree")

served = os.path.join(web, "all.json")
if os.path.exists(served):
    was = len(load(served).get("deny", []))
    if len(deny) * 100 < was * (100 - max_shrink):
        refuse(f"the deny list would shrink from {was} to {len(deny)} sites, more than {max_shrink}%")


def parts(host):
    return host.lower().rstrip(".").split(".")[::-1]


# The package's rule: an entry blocks a host when its labels match the host's from the right.
for domain in protected:
    d = parts(domain)
    for entry in deny:
        e = parts(entry)
        if len(e) <= len(d) and d[:len(e)] == e:
            refuse(f"the entry {entry} would block our domain {domain}")

print(f"checked: {len(deny)} blocked sites, {sum(len(v) for v in address.values())} scam addresses")
PY

rsync -a --checksum --delete --delay-updates --chown=root:root --exclude index.html "$stage/" "$WEB_ROOT/"
printf '%s\n' "$new" >"$STATE_DIR/published.new"
mv -f "$STATE_DIR/published.new" "$STATE_DIR/published"
echo "published ${new:0:12}"
