#!/bin/bash
# TB2.0 small-slice benchmark run — flywheel vs published leaderboard
# 10 tasks, sequential (engine is single-slot), results to bench-tb/jobs/
set -e
cd "$(dirname "$0")"
# SPIRAL=0 disables the failure-spiral rescue, SPIRAL=N sets it, unset = binary default
# REPEATS = attempts per task (harbor -k)
SPIRAL="${SPIRAL:-}"
REPEATS="${REPEATS:-1}"
JOB="jobs/slice-${SPIRAL:+spiral$SPIRAL-}$(date +%m%d-%H%M)"
echo "slice start $(date +%H:%M:%S) job=$JOB"
TASKS="circuit-fibsqrt make-mips-interpreter fix-git count-dataset-tokens dna-insert filter-js-from-html extract-elf chess-best-move git-multibranch gcode-to-text"
ARGS=""
[ -n "$SPIRAL" ] && ARGS="$ARGS --ak spiral=$SPIRAL"
for t in $TASKS; do ARGS="$ARGS --include-task-name $t"; done
PYTHONPATH=. ~/.local/bin/harbor run -d terminal-bench@2.0 \
  --agent flywheel_agent:FlywheelAgent \
  $ARGS \
  -k "$REPEATS" -n 1 --n-concurrent-agents 1 -y \
  -o "$JOB" > "$JOB.log" 2>&1
echo "slice done $(date +%H:%M:%S)"
python3 - "$JOB" <<'PYE'
import json, sys, os, glob
jobdir = sys.argv[1]
rows = []
for rj in glob.glob(os.path.join(jobdir, "*", "*__*", "result.json")):
    try:
        d = json.load(open(rj))
        task = d.get("task_name", "?")
        vr = d.get("verifier_result") or {}
        rw = (vr.get("rewards") or {}).get("reward", 0)
        rows.append((task, rw))
    except Exception as e:
        rows.append((os.path.basename(os.path.dirname(rj)), "err"))
passed = sum(1 for _, r in rows if r == 1.0)
print(f"\n=== SLICE RESULT: {passed}/{len(rows)} passed")
for t, r in rows:
    print(f"  {t}: {r}")
PYE
