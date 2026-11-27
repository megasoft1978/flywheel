#!/bin/bash
# Terminal-Bench 2.1 runner: one harness at a time, resumable, dry-run capable.
#
#   run-tb21.sh [--harness flywheel|terminus-2|opencode] [--tasks FILE] [--dry-run]
#               [--job-name NAME] [--include TASK ...] [--smoke]
#
# Resume: a task counts as done when <jobs>/<job-name>/<task>__*/result.json exists.
#         Only tasks without one are passed to harbor. Existing job dirs are never deleted.
# Dry-run: prints the exact harbor command(s) and the missing-task count; runs nothing.
# Smoke: runs only the first missing task of the chosen harness (one trial).
set -eo pipefail   # no -u: bash 3.2 (macOS) errors on empty arrays
cd "$(dirname "$0")"

DATASET="terminal-bench/terminal-bench-2-1"   # pinned at freeze: see PROTOCOL.md (record digest)
ENDPOINT="${TB_ENDPOINT:-http://host.docker.internal:8312/v1}"   # from containers
MODEL_NAME="local/qwen-pi4"
TIMEOUT_MULT="${TB_TIMEOUT_MULT:-1.0}"    # 1.0 = dataset per-task defaults, no overrides
CONCURRENCY=1                             # single-slot local engine
ATTEMPTS=1                                # one trial per task

HARNESS=""
TASKS_FILE="tb21-tasks.txt"               # 89 task names, one per line (filled at freeze)
DRY=0; SMOKE=0; JOB_NAME=""; INCLUDE=()
while [ $# -gt 0 ]; do
  case "$1" in
    --harness) HARNESS="$2"; shift 2 ;;
    --tasks) TASKS_FILE="$2"; shift 2 ;;
    --job-name) JOB_NAME="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --smoke) SMOKE=1; shift ;;
    --include) shift; while [ $# -gt 0 ] && [[ "$1" != --* ]]; do INCLUDE+=("$1"); shift; done ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

case "$HARNESS" in
  flywheel)
    AGENT_ARGS=(--agent-import-path flywheel_agent:FlywheelAgent
                --ak "engine_url=$ENDPOINT" --ak "fw_model=$MODEL_NAME") ;;
  terminus-2)
    AGENT_ARGS=(--agent terminus-2 --model "openai/$MODEL_NAME"
                --ak "base_url=$ENDPOINT" --ak "parser_name=json") ;;
  opencode)
    OC_CFG="{\"provider\":{\"local\":{\"npm\":\"@ai-sdk/openai-compatible\",\"name\":\"local\",\"options\":{\"baseURL\":\"$ENDPOINT\"},\"models\":{\"qwen-pi4\":{\"name\":\"qwen-pi4\"}}}}}"
    AGENT_ARGS=(--agent opencode --model "$MODEL_NAME"
                --ak "opencode_config=$OC_CFG") ;;
  *) echo "usage: --harness flywheel|terminus-2|opencode" >&2; exit 2 ;;
esac

[ -n "$JOB_NAME" ] || JOB_NAME="tb21-$HARNESS"
JOBS_DIR="jobs/tb21"
JOB_DIR="$JOBS_DIR/$JOB_NAME"

# Build the list of tasks still missing a result (resumability).
if [ ${#INCLUDE[@]} -gt 0 ]; then
  ALL=("${INCLUDE[@]}")
else
  [ -f "$TASKS_FILE" ] || { echo "missing $TASKS_FILE (task list is filled at freeze)" >&2; exit 1; }
  ALL=()
  while IFS= read -r line; do ALL+=("$line"); done < <(grep -v '^[[:space:]]*\(#\|$\)' "$TASKS_FILE")
fi
MISSING=()
for t in "${ALL[@]}"; do
  if ls "$JOB_DIR/$t"__*/result.json >/dev/null 2>&1; then continue; fi
  MISSING+=("$t")
done
[ "$SMOKE" = 1 ] && MISSING=("${MISSING[@]:0:1}")

echo "harness=$HARNESS dataset=$DATASET job=$JOB_DIR"
echo "tasks: total=${#ALL[@]} done=$(( ${#ALL[@]} - ${#MISSING[@]} )) to_run=${#MISSING[@]}"

[ ${#MISSING[@]} -eq 0 ] && { echo "nothing to run"; exit 0; }

CMD=(harbor run -d "$DATASET" "${AGENT_ARGS[@]}"
     -k "$ATTEMPTS" -n "$CONCURRENCY" --n-concurrent-agents 1
     --timeout-multiplier "$TIMEOUT_MULT"
     -o "$JOBS_DIR" --job-name "$JOB_NAME" -y)
for t in "${MISSING[@]}"; do CMD+=(--include-task-name "$t"); done

if [ "$DRY" = 1 ]; then
  printf 'DRY-RUN:'; printf ' %q' "${CMD[@]}"; echo
  exit 0
fi

mkdir -p "$JOBS_DIR"
PYTHONPATH="$PWD" "${CMD[@]}" 2>&1 | tee -a "$JOBS_DIR/$JOB_NAME.log"
echo "finished $(date '+%Y-%m-%d %H:%M:%S'); harvest: python3 -I harvest_tb21.py $JOB_DIR"
