#!/bin/bash
# rerun only the 7 tasks whose images failed to pull overnight
set -e
cd "$(dirname "$0")"
JOB="jobs/slice-retry-$(date +%m%d-%H%M)"
echo "retry7 start $(date +%H:%M:%S) job=$JOB"
TASKS="fix-git count-dataset-tokens dna-insert filter-js-from-html extract-elf gcode-to-text git-multibranch"
ARGS=""
for t in $TASKS; do ARGS="$ARGS --include-task-name $t"; done
PYTHONPATH=. ~/.local/bin/harbor run -d terminal-bench@2.0 \
  --agent flywheel_agent:FlywheelAgent \
  $ARGS \
  -k 1 -n 1 --n-concurrent-agents 1 -y \
  -o "$JOB" > "$JOB.log" 2>&1
echo "retry7 done $(date +%H:%M:%S)"
