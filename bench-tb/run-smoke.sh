#!/bin/bash
# single-task flywheel smoke on Terminal-Bench 2.0 via Harbor
set -e
cd "$(dirname "$0")"
TASK="${1:-circuit-fibsqrt}"
JOB="jobs/smoke-$TASK-$(date +%H%M%S)"
echo "smoke: task=$TASK job=$JOB $(date +%H:%M:%S)"
PYTHONPATH=. ~/.local/bin/harbor run -d terminal-bench@2.0 \
  --agent flywheel_agent:FlywheelAgent \
  --ak engine_url=http://host.docker.internal:8312/v1 \
  --include-task-name "$TASK" \
  -k 1 -n 1 --n-concurrent-agents 1 -y \
  -o "$JOB" 2>&1 | tail -40
echo "smoke done $(date +%H:%M:%S) → $JOB"
