# Benchmark protocol (draft: freeze before the first scored run)

Goal: show whether Qwen3.8-27B running locally, driven by flywheel, can do real work,
compared with two other harnesses on the same model. The result is published whatever it says.

Status: Terminal-Bench 2.1 preparation only. No scored run has started. Nothing here is a result.

## Tracks
1. Terminal-Bench 2.1 through Harbor: all 89 tasks, three harnesses, same local model.
2. About 20 everyday tasks (bug fix, small feature, data wrangling, git recovery),
   each with hidden tests, published together with the results. (Not yet written.)

## Dataset and harness (pinned at freeze)
- Dataset: `terminal-bench/terminal-bench-2-1` on the Harbor registry (Harbor 0.27.0).
  Official sources: https://github.com/harbor-framework/terminal-bench-2-1 and
  https://www.vals.ai/benchmarks/terminal-bench-2-1 (the Vals page says 2.1 is archived and
  superseded by Terminal-Bench 4.0; we still use 2.1 because it is the dataset the owner chose).
- The registry `latest` tag moves. At freeze, record the dataset manifest digest from
  `harbor dataset download` output and the 89-line task list in `bench-tb/tb21-tasks.txt`
  (not yet generated; generate from the downloaded dataset, never from memory).
- Harbor version: 0.27.0 (`harbor --version`). Agents: `terminus-2` and `opencode` are built
  into Harbor; flywheel is the custom agent `bench-tb/flywheel_agent.py` (import path
  `flywheel_agent:FlywheelAgent`).
- Note: Harbor reported `--ak` kwargs as ignored in the 2.0 pilot. Verify at smoke time; the
  flywheel defaults in `flywheel_agent.py` are authoritative until then.

## Runners (same tasks, containers, time limits, model)
- flywheel + local `local/qwen-pi4` (Splash on :8312 on the host)
- Terminus 2 + the same local model
- OpenCode + the same local model
- Endpoint from containers: `http://host.docker.internal:8312/v1`.
- Run via `bench-tb/run-tb21.sh --harness <name>`. Dry-run prints the exact command.
- Not in scope for this slice: Claude Haiku 5.5 through Harbor's claude-code agent. Needs owner credential.

## Run settings
- Trials: 1 per task (`-k 1`). The official leaderboard requires 5 trials per task; this is
  not a leaderboard submission, so 1 trial is allowed and labelled as such.
- Per-task timeout: dataset defaults from each task's own config, timeout multiplier 1.0,
  no per-task overrides (`--timeout-multiplier 1.0`). Record the per-task values at freeze.
- Concurrency: 1 trial at a time (`-n 1 --n-concurrent-agents 1`). The local engine is
  single-slot and parallel trials would share one model server.
- Never run two jobs on the same engine or the same Docker host at once.

## Reporting
- Report two rows per harness:
  - all 89 tasks (primary)
  - the 79 tasks not used in development
- Development set: the 10 tasks in the README pilot table
  (count-dataset-tokens, chess-best-move, extract-elf, circuit-fibsqrt, fix-git,
  make-mips-interpreter, git-multibranch, dna-insert, filter-js-from-html, gcode-to-text).
  Shown separately as development tasks, never as the held-out score. Confirm each name
  exists in 2.1 at freeze; 26 tasks changed from 2.0.
- Pass rate with a 95% Wilson interval (`harvest_tb21.py`). Missing and error trials count as
  not passed in the primary rate; the scored-only rate is shown next to it with its own
  interval. Every missing or errored task is listed by name.
- Time per task (wall seconds from `result.json`), plus the three charts from the harvester.
- Trajectories published with the results after a secret and personal-data check.
- Required label on every published table: "self-run on the official dataset and harness,
  trajectories public". Never claim a leaderboard rank, never "beats Claude".
- Published third-party rows (for example the Vals AI Terminus 2 table, Oct 2026) may be cited
  only as separate rows labelled "different infrastructure" (Daytona remote execution, their
  own time limits, their own trial counts), never placed in the same table as our rows.
- The landing page tables are generated from result files, never typed by hand.

## Rules
- Freeze first: tagged commit, binary hash (`dist/flywheel-linux-*`), Harbor version, dataset
  digest, engine and model versions, all settings.
- No tuning on scored tasks. Harness work uses the development set, one task at a time:
  run, read the trajectory, fix the general cause in the harness, add a test, re-run.
- A fix must be general. Nothing task-specific goes into the harness or its prompts.
- Every attempt counts. Re-run only infrastructure failures (agent never started), and list each one.
- Resumable: `run-tb21.sh` only runs tasks without a `result.json`. Existing job dirs are never deleted.
- No paid model calls anywhere in the benchmark or its tests.

## Estimated runtime (estimate, not measured)
- Assumption: average 15 min per task including setup and verification; 89 tasks.
- Per harness: about 22 h wall time sequentially. Three harnesses: about 67 h.
- Overnight-sized chunks: resume across nights with `run-tb21.sh`.
- Real numbers replace this after the smoke test and the first development-set pass.

## Order of work
1. Check: dataset download and task count (89), per-task timeouts, Docker resources, Harbor
   agent kwargs, host engine reachable from containers.
2. Smoke: one task per harness, sequential, only when Docker and the host are not loaded.
   Not yet run (host load average was 67 when this was prepared).
3. Fix what would waste runs on the development set.
4. Write and validate the everyday tasks.
5. Freeze, run, harvest, build the landing page.

## Needs the owner
- Claude credential for the Haiku runs inside containers (set by the owner, never committed).
- OK before publishing the page.
- Confirmation that 1 trial per task is acceptable (the official leaderboard needs 5).
