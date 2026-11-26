# Benchmark protocol (draft: freeze before the first scored run)

Goal: show whether Qwen3.8-27B running locally, driven by flywheel, can do real work.
The result is published whatever it says.

## Tracks
1. Terminal-Bench 2.1 through Harbor, every task in the dataset.
2. About 20 everyday tasks (bug fix, small feature, data wrangling, git recovery),
   each with hidden tests, published together with the results.

## Runners (same tasks, containers, time limits)
- flywheel + local Qwen3.8-27B
- OpenCode + the same local model (isolates what the harness adds)
- Claude Haiku 5.5 through Harbor's claude-code agent

## Rules
- Freeze first: tagged commit, binary hash, engine and model versions, all settings.
- No tuning on benchmark tasks. Harness work uses a separate development set.
- Everyday tasks are written and frozen before any runner attempts them; each must fail
  untouched and pass with a reference solution.
- One attempt per task in the first round, labelled as such. More trials later.
- Task default timeouts and resources; no per-task overrides.
- Every attempt counts. Re-run only infrastructure failures (agent never started),
  and list each one.
- Publish pass rate with a 95% interval, time per task, and raw trajectories
  (checked for secrets and personal data first).
- The landing page tables are generated from result files, never typed by hand.

## Order of work
1. Check: dataset task count, submission rules, Docker resources per task, OpenCode with a
   local endpoint, host engine reachable from containers.
2. Fix what would waste runs (chatty verification gate, no DONE on hard tasks) on the
   development set (the 10 pilot tasks are now development tasks and are reported as such).
3. Write and validate the everyday tasks.
4. Freeze, run overnight, harvest, build the landing page.

## Needs the owner
- Claude credential for the Haiku runs inside containers (set by the owner, never committed).
- OK before publishing the page.
