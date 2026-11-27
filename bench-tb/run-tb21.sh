#!/bin/bash
# Terminal-Bench 2.1 runner: one harness at a time, resumable, dry-run capable.
#
#   run-tb21.sh --harness flywheel|terminus-2|opencode [--dry-run] [--smoke]
#               [--rerun TASK ...] [--job-name NAME] [--tasks FILE] [--include TASK ...]
#
# Tasks:  tb21-tasks.txt (89 names, pinned dataset digest). Harbor always gets the job's full
#         task list; it skips trials that already have a result.
# Resume: partial and cancelled trial dirs are moved to jobs/tb21-archive/ before Harbor starts
#         (Harbor would delete them). Existing job dirs and trials are never deleted.
# Rerun:  --rerun TASK archives that task's finished trial, logs it in <job>/reruns.jsonl and runs
#         it again. The report lists every entry.
# Subset: --tasks or --include need their own --job-name.
# Dry-run: prints the exact harbor command and what would be archived; changes nothing.
# Smoke:  --smoke runs one task (the first of the list) in jobs/tb21-smoke/, apart from scored jobs.
set -eo pipefail   # no -u: bash 3.2 (macOS) errors on empty arrays
cd "$(dirname "$0")"

DATASET="terminal-bench/terminal-bench-2-1"
ALL_TASKS_FILE="tb21-tasks.txt"
DIGEST="$(sed -n 's/^# dataset-digest: //p' "$ALL_TASKS_FILE")"
ENDPOINT="${TB_ENDPOINT:-http://host.docker.internal:8312/v1}"       # from containers
HOST_ENDPOINT="${TB_HOST_ENDPOINT:-http://127.0.0.1:8312/v1}"        # Terminus 2 runs on the host
MODEL_NAME="local/qwen-pi4"
# Model settings: flywheel's defaults (src/main.c). See PROTOCOL.md for what cannot be matched.
TEMPERATURE=0
MAX_TOKENS=12000
OPENCODE_VERSION="1.19.6"                 # config keys below were checked against this source
TIMEOUT_MULT="${TB_TIMEOUT_MULT:-1.0}"    # 1.0 = dataset per-task defaults, no overrides
CONCURRENCY=1                             # single-slot local engine
ATTEMPTS=1                                # one trial per task

usage() { sed -n '2,/^set /{/^set /!p;}' "$0"; }
need() { [ $# -ge 2 ] && [ -n "$2" ] && [[ "$2" != --* ]] || { echo "$1 needs a value" >&2; exit 2; }; }

HARNESS=""; TASKS_FILE=""
DRY=0; SMOKE=0; JOB_NAME=""; INCLUDE=(); RERUN=()
while [ $# -gt 0 ]; do
  case "$1" in
    --harness) need "$@"; HARNESS="$2"; shift 2 ;;
    --tasks) need "$@"; TASKS_FILE="$2"; shift 2 ;;
    --job-name) need "$@"; JOB_NAME="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --smoke) SMOKE=1; shift ;;
    --include) need "$@"; shift; while [ $# -gt 0 ] && [[ "$1" != --* ]]; do INCLUDE+=("$1"); shift; done ;;
    --rerun) need "$@"; RERUN+=("$2"); shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

case "$HARNESS" in
  flywheel)
    AGENT_ARGS=(--agent flywheel_agent:FlywheelAgent
                --ak "engine_url=$ENDPOINT" --ak "fw_model=$MODEL_NAME") ;;
  terminus-2)
    # litellm strips the "openai/" provider prefix, so the engine receives $MODEL_NAME.
    AGENT_ARGS=(--agent terminus-2 --model "openai/$MODEL_NAME"
                --ak "base_url=$HOST_ENDPOINT" --ak "parser_name=json"
                --ak "temperature=$TEMPERATURE"
                --ak "llm_call_kwargs={\"max_tokens\":$MAX_TOKENS}")
    export OPENAI_API_KEY=dummy ;;   # never send a real key to the local engine
  opencode)
    # --model is <provider>/<model id>; OpenCode splits at the first "/".
    OC_MODEL="{\"name\":\"$MODEL_NAME\",\"temperature\":true,\"limit\":{\"context\":0,\"output\":$MAX_TOKENS}}"
    OC_PROVIDER="{\"npm\":\"@ai-sdk/openai-compatible\",\"name\":\"local\",\"options\":{\"baseURL\":\"$ENDPOINT\"},\"models\":{\"$MODEL_NAME\":$OC_MODEL}}"
    T="{\"temperature\":$TEMPERATURE}"
    OC_CFG="{\"provider\":{\"local\":$OC_PROVIDER},\"agent\":{\"build\":$T,\"general\":$T,\"explore\":$T,\"compaction\":$T}}"
    AGENT_ARGS=(--agent opencode --model "local/$MODEL_NAME"
                --ak "version=$OPENCODE_VERSION" --ak "opencode_config=$OC_CFG") ;;
  *) echo "usage: --harness flywheel|terminus-2|opencode" >&2; exit 2 ;;
esac

[[ "$DIGEST" == sha256:* ]] || { echo "no dataset-digest line in $ALL_TASKS_FILE" >&2; exit 1; }

# read_names FILE -> namespaced task names, one per line
read_names() { sed -e 's/[[:space:]]*$//' -e '/^[[:space:]]*#/d' -e '/^$/d' -e 's|^.*/||' -e 's|^|terminal-bench/|' "$1"; }
# canonical NAME (bare or namespaced) -> namespaced; Harbor silently drops names it does not know
canonical() {
  local n="terminal-bench/${1#terminal-bench/}"
  grep -qxF -- "$n" <<< "$(read_names "$ALL_TASKS_FILE")" || { echo "unknown task: $1" >&2; return 1; }
  echo "$n"
}

if [ "$SMOKE" = 0 ] && [ -z "$JOB_NAME" ] && { [ -n "$TASKS_FILE" ] || [ ${#INCLUDE[@]} -gt 0 ]; }; then
  echo "--tasks/--include run a subset: give it its own --job-name" >&2; exit 2
fi

ALL=()
if [ ${#INCLUDE[@]} -gt 0 ]; then
  for t in "${INCLUDE[@]}"; do n="$(canonical "$t")"; ALL+=("$n"); done
else
  SRC="${TASKS_FILE:-$ALL_TASKS_FILE}"
  [ -f "$SRC" ] || { echo "missing $SRC" >&2; exit 1; }
  while IFS= read -r line; do n="$(canonical "$line")"; ALL+=("$n"); done < <(read_names "$SRC")
  if [ -z "$TASKS_FILE" ] && [ ${#ALL[@]} -ne 89 ]; then
    echo "$ALL_TASKS_FILE has ${#ALL[@]} tasks, expected 89" >&2; exit 1
  fi
fi
[ ${#ALL[@]} -gt 0 ] || { echo "no tasks" >&2; exit 1; }
[ "$SMOKE" = 1 ] && ALL=("${ALL[0]}")

RERUN_ARGS=()
if [ ${#RERUN[@]} -gt 0 ]; then
  for t in "${RERUN[@]}"; do
    n="$(canonical "$t")"
    grep -qxF -- "$n" <<< "$(printf '%s\n' "${ALL[@]}")" || { echo "--rerun $t: not in this job's task list" >&2; exit 2; }
    RERUN_ARGS+=(--rerun "$n")
  done
fi

[ -n "$JOB_NAME" ] || JOB_NAME="tb21-$HARNESS"
JOBS_DIR="jobs/tb21"
[ "$SMOKE" = 1 ] && JOBS_DIR="jobs/tb21-smoke"
JOB_DIR="$JOBS_DIR/$JOB_NAME"

# One runner at a time: all harnesses share the engine and the Docker host.
if [ "$DRY" = 0 ]; then
  LOCK="jobs/tb21.lock"
  mkdir -p jobs
  if ! mkdir "$LOCK" 2>/dev/null; then
    echo "another runner holds $LOCK (pid $(cat "$LOCK/pid" 2>/dev/null || echo '?'))." >&2
    echo "If that process is gone, remove $LOCK/pid and $LOCK by hand." >&2
    exit 1
  fi
  trap 'rm -f "$LOCK/pid"; rmdir "$LOCK"' EXIT
  trap 'exit 130' INT TERM
  echo $$ > "$LOCK/pid"
fi

STATE=(python3 -I tb21_state.py --job-dir "$JOB_DIR" --archive-dir "${JOBS_DIR}-archive/$JOB_NAME"
       --dataset "$DATASET" --digest "$DIGEST")
[ "$DRY" = 1 ] && STATE+=(--dry-run)
[ ${#RERUN_ARGS[@]} -gt 0 ] && STATE+=("${RERUN_ARGS[@]}")
COUNTS="$("${STATE[@]}" "${ALL[@]}")"
read -r DONE TODO <<< "$COUNTS"

echo "harness=$HARNESS dataset=$DATASET@$DIGEST job=$JOB_DIR"
echo "tasks: total=${#ALL[@]} done=$DONE to_run=$TODO"

[ "$TODO" -eq 0 ] && { echo "nothing to run"; exit 0; }

CMD=(harbor run -d "$DATASET@$DIGEST" "${AGENT_ARGS[@]}"
     -k "$ATTEMPTS" -n "$CONCURRENCY" --n-concurrent-agents 1
     --timeout-multiplier "$TIMEOUT_MULT"
     -o "$JOBS_DIR" --job-name "$JOB_NAME" -y)
for t in "${ALL[@]}"; do CMD+=(--include-task-name "$t"); done

if [ "$DRY" = 1 ]; then
  printf 'DRY-RUN:'; printf ' %q' "${CMD[@]}"; echo
  exit 0
fi

mkdir -p "$JOBS_DIR"
PYTHONPATH="$PWD" "${CMD[@]}" 2>&1 | tee -a "$JOBS_DIR/$JOB_NAME.log"
echo "finished $(date '+%Y-%m-%d %H:%M:%S'); harvest: python3 -I harvest_tb21.py $JOB_DIR"
