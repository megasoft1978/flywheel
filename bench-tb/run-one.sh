#!/bin/bash
# run one development task and keep its logs: run-one.sh <task-name>
cd "$(dirname "$0")" || exit 1
TASK="${1:?task name}"
JOB="jobs/dev-$TASK-$(date +%m%d-%H%M%S)"
PYTHONPATH=. harbor run -d "${DATASET:-terminal-bench/terminal-bench-2-1}" \
  --agent flywheel_agent:FlywheelAgent --include-task-name "*$TASK" \
  -k 1 -n 1 -y -o "$JOB" > "$JOB.log" 2>&1
rc=$?
tail -25 "$JOB.log"
echo "exit=$rc job=bench-tb/$JOB"
