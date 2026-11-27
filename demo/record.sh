#!/bin/sh
# Record demo/demo.tape against a model server that is already running, then check
# the result. Leaves the take (demo.mp4, transcript.jsonl, the edited copy) in the
# directory it prints; nothing in the repo is touched.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
make -C "$repo" clean >/dev/null && make -C "$repo" >/dev/null
d=$("$repo/demo/prepare.sh")
echo "take: $d"
(cd "$d" && FWDEMO=$d vhs "$repo/demo/demo.tape")
cmp "$repo/demo/textstats/test_textstats.py" "$d/home/textstats/test_textstats.py"
(cd "$d/home/textstats" && python3 -m unittest)
echo "OK: tests pass and test_textstats.py is unchanged; now watch $d/demo.mp4"
