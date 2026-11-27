#!/bin/sh
# Record demo/demo.tape against a model server that is already running, then check
# the result. Rebuilds flywheel in the repo (make clean && make). The take goes to
# the directory it prints: demo.mp4, plus the edited copy and transcript.jsonl
# under home/. The tape approves every command the model asks to run, and a
# temporary HOME is not a sandbox.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
make -C "$repo" clean >/dev/null && make -C "$repo" >/dev/null
d=$("$repo/demo/prepare.sh")
echo "take: $d"
(cd "$d" && FWDEMO=$d vhs "$repo/demo/demo.tape")
cmp "$repo/demo/textstats/test_textstats.py" "$d/home/textstats/test_textstats.py"
(cd "$d/home/textstats" && python3 -m unittest)
echo "OK: tests pass and test_textstats.py is unchanged; now watch $d/demo.mp4"
