# Benchmark protocol (draft: freeze before the first scored run)

Goal: show whether Qwen3.8-27B running locally, driven by flywheel, can do real work,
compared with two other harnesses on the same model. The result is published whatever it says.

Status: Terminal-Bench 2.1 preparation only. No scored run has started. Nothing here is a result.

## Open blockers (resolve before freeze)
- flywheel time limit (fixed in code by FW-TBTIME and FW-TBCLAMP, not yet
  smoke-tested):
  flywheel gets the task's Harbor agent timeout (task.toml `agent.timeout_sec` x
  `--timeout-multiplier`, read from `bench-tb/tb21-timeouts.tsv` by task name). Harbor does not
  pass it to custom agents; only its `asyncio.wait_for` around `run()` enforces it
  (`harbor/trial/trial.py:784`, `:1724`). flywheel `-W` = budget - 60 s (refused if <= 0),
  `-T` 20000 (never binds), `-t` 180 s.
  - With `-W`, command and gate timeouts are cut to the time left, and no further tool call or
    gate starts once it has expired; the run ends as `finish=wall` with its summary and
    transcript written. The limit counts whole seconds from the start of the task. Not covered:
    background processes a command leaves behind, and any process that leaves the command's process
    group (setsid, GNU timeout). Harbor's kill is still the hard cap.
  - Before a scored run: one smoke task must show flywheel exiting before Harbor's kill
    (`FW_EXIT`, `finish=wall`), and whether the kill stops the flywheel process in the container
    before the verifier runs (not checked in the Docker exec path).

## Tracks
1. Terminal-Bench 2.1 through Harbor: all 89 tasks, three harnesses, same local model.
2. About 20 everyday tasks (bug fix, small feature, data wrangling, git recovery),
   each with hidden tests, published together with the results. (Not yet written.)

## Dataset and harness (pinned at freeze)
- Dataset: `terminal-bench/terminal-bench-2-1` on the Harbor registry (Harbor 0.27.0).
  Official sources: https://github.com/harbor-framework/terminal-bench-2-1 and
  https://www.vals.ai/benchmarks/terminal-bench-2-1 (the Vals page says 2.1 is archived and
  superseded by Terminal-Bench 4.0; we still use 2.1 because it is the dataset the owner chose).
- The registry `latest` tag moves. `bench-tb/tb21-tasks.txt` holds the 89 task names and the
  manifest digest read from the registry metadata on 2026-11-27 (no task content downloaded):
  `sha256:7d7bdc1cbedad549fc1140404bd4dc45e5fd0ea7c4186773687d177ad3a0699a`. The runner passes
  `-d <dataset>@<digest>` and the harvester rejects any other digest. Re-check it at freeze.
- `bench-tb/tb21-timeouts.tsv` holds agent and verifier timeouts from `task.toml` in the official
  repo (commit `12b7565679ce5006230b820666353673a133db93`). Load-bearing: flywheel's time limit
  reads it (`bench-tb/flywheel_agent.py`). It is not verified against the pinned dataset digest
  above; check it against the downloaded task.toml files at freeze.
- Harbor version: 0.27.0 (`harbor --version`). Agents: `terminus-2` and `opencode` are built
  into Harbor; flywheel is the custom agent `bench-tb/flywheel_agent.py`
  (`--agent flywheel_agent:FlywheelAgent`).
- `--ak` kwargs reach the agent (checked with `harbor run --print-config` and the Harbor
  source, not with a real run).

## Runners (same tasks, containers, model)
- flywheel + local `local/qwen-pi4` (Splash on :8312 on the host)
- Terminus 2 + the same local model (`--model openai/local/qwen-pi4`; the server sees
  `local/qwen-pi4`)
- OpenCode 1.19.6 (pinned) + the same local model (`--model local/local/qwen-pi4`; OpenCode takes
  `local` as the provider and sends `local/qwen-pi4`)
- flywheel and OpenCode run inside the task container: `http://host.docker.internal:8312/v1`
  (`TB_ENDPOINT`). Terminus 2 calls the model from the host: `http://127.0.0.1:8312/v1`
  (`TB_HOST_ENDPOINT`), with a dummy API key.
- Run via `bench-tb/run-tb21.sh --harness <name>` (`-h` for options). `--dry-run` prints the
  exact command.

## Model settings
Set the same where the harness allows it:

| setting | flywheel | Terminus 2 | OpenCode |
|---|---|---|---|
| temperature | 0 | 0 | 0 (build, general, explore, compaction agents) |
| max output tokens | 12000 | 12000 | 12000 (model output limit) |

The engine's thinking budget (`--thinking-token-budget`) is a server setting, so it applies to
all three.

Cannot match, and to be disclosed with the results:
- flywheel raises temperature to 0.5 (top_p 0.95) to escape loops. At temperature 0 it sends no
  top_p.
- OpenCode's title agent keeps its own temperature (0.5).
- Time limits: all three harnesses are cut by the same Harbor per-task agent timeout. flywheel
  also stops itself at `-W`, 60 s earlier: it cuts the running model request, command or gate and
  ends the run, so it has 60 s less working time than the budget. Terminus 2
  sends commands non-blocking and waits min(duration, 60) s without killing them
  (`harbor/agents/terminus_2/terminus_2.py:1400`, `:1434`); its 180 s blocking cap
  (`tmux_session.py:792`) is not on that path. It has no turn limit by default. flywheel's
  20000-turn limit (`-T`) is not expected to bind. OpenCode's own bash timeout is not in Harbor's
  source and is not checked yet.
- OpenCode automatic context compaction is off (context limit set to 0). Each harness otherwise
  keeps its own context handling, prompts and tool set.
- The Terminus 2 behaviour above was checked in Harbor's source. OpenCode's was not. The resolved
  Harbor config was checked only. Confirm the actual requests in the engine log at smoke time.

## Run settings
- Trials: 1 per task (`-k 1`). The official leaderboard requires 5 trials per task; this is
  not a leaderboard submission, so 1 trial is allowed and labelled as such.
- Per-task timeout: dataset defaults from each task's own config, timeout multiplier 1.0,
  no per-task overrides (`--timeout-multiplier 1.0`). Record the per-task values at freeze.
  A `TB_TIMEOUT_MULT` other than 1.0 makes the harvest fail.
- Concurrency: 1 trial at a time (`-n 1 --n-concurrent-agents 1`). The local engine is
  single-slot and parallel trials would share one model server.
- Never run two jobs on the same engine or the same Docker host at once.

## Reporting
- Harvest: `python3 -I harvest_tb21.py JOB_DIR...` (from `bench-tb/`). Per harness:
  - held-out-79, the tasks not used in development: the headline
  - all-89, secondary. The 10 development tasks were used to develop flywheel only, so this
    number is not neutral between harnesses; that note is printed under the tables and on the
    charts
  - dev-10, shown only as development tasks, never as the held-out score
- Development set: the 10 tasks in the README pilot table, in `bench-tb/tb21-dev-tasks.txt`.
  All 10 names are in the 2.1 list; 26 tasks changed from 2.0. The harvester requires that
  committed list (except with `--synthetic`), checks 89/10/79 and marks dev rows in the grid.
- Classification, in this order:
  - flywheel and OpenCode run inside the task container, so the tested agent can forge their
    evidence of a model API or transport error (the OpenCode log, `/tmp/fw_out.log`, command output
    that Harbor turns into an API exception). Such a trial is `error` only if the host recorded a
    model server outage (`<job>/outages.jsonl`, outside the trial dirs mounted into the container)
    that overlaps it. Without that it is a scored fail, whatever reward was written: short,
    unrecorded outages count against the agent. Not covered: an error raised while installing the
    agent, before it ran, and Terminus 2, which runs on the host.
  - otherwise `error` if Harbor 0.27.0 marks the reward invalid for the trial's exception
    (`has_valid_reward=False`: API, network, environment and verifier failures), whatever reward
    was written
  - otherwise a verifier reward is pass (1.0) or fail, even if the trial also raised
  - no reward after an agent timeout or other agent-side exception is fail if verification never
    started, `error` if verification ran and failed itself
  - any other trial without a reward is `error`

  Agent timeouts are also flagged and counted.
  The report marks each listed flywheel or OpenCode API error as without host proof (fail) or
  with the outage window (`error`), and lists OpenCode log errors by name for audit. Harvest and
  rerun use the same overlap check. Missing or invalid timestamps prove nothing; an unreadable
  `outages.jsonl` proves nothing and stops the harvest.
- flywheel failures: exit status 1 covers both a normal unfinished task (`finish=turns`, `wall`,
  `aborted`: scored by the verifier) and a failed model request (`finish=error:...`). The agent
  raises `ApiError` for the latter (`ContextWindowExceededError` for a context-size rejection,
  which stays a scored result) and `NonZeroAgentExitCodeError` for any other nonzero exit.
- Model server outages: the runner probes `$TB_HOST_ENDPOINT/models` before the run and every
  15 s during it. After 3 failed probes it records the window in `<job>/outages.jsonl` and stops
  Harbor. A harness that records an outage only as a generic exit error still scores fail until
  the trial is re-run under the rule below.
- Pass rate with a 95% Wilson interval. Missing and error trials count as not passed in the
  primary rate; the scored-only rate is shown next to it with its own interval. Every missing or
  errored task is listed by name, every failed trial with its exception, and every archived or
  re-run trial with its reason and evidence. Rerun counts per harness and first-attempt rates
  (each re-run task scored by its first finished trial; cancelled and partial trials are counted
  separately) are shown.
- Time per task is the whole trial time (`started_at` to `finished_at`: environment setup, agent
  and verifier), plus the three charts from the harvester.
- The harvester writes nothing and exits nonzero on: no trials, unexpected or duplicate trials,
  unreadable results, wrong dataset, digest, agent, model or timeout settings, or a task list
  that is not the 89-task list. `--partial` (subset) and `--synthetic` (fixtures) relax the last
  check; every output, charts included, is stamped PARTIAL or SYNTHETIC. A run with missing
  tasks is stamped PARTIAL.
- Trajectories published with the results after a secret and personal-data check.
- Required label on every published table: "self-run on the official dataset and harness,
  trajectories public". The harvester adds the trajectories part only with
  `--trajectories-url <published URL>`; pass it only once they are really public. Never claim a
  leaderboard rank, never "beats Claude".
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
- Every attempt counts. One rerun rule for all three harnesses, applied by
  `run-tb21.sh --harness <name> --rerun <task> --reason "<why>"`:
  - never a trial with reward 1
  - an `error` trial (see Classification) may be re-run
  - a fail may be re-run only if it overlaps a recorded model server outage;
    `--rerun-without-evidence` overrides this, and the report counts and marks every such rerun

  The old trial is archived and logged in the job's `reruns.jsonl`, which the report includes.
- Resume: run the same command again. It passes Harbor the same dataset digest and full task list
  (Harbor refuses a job whose config differs); Harbor skips finished trials. Before that, trial
  dirs with no usable result (which Harbor would delete) and cancelled trials are moved to
  `jobs/tb21-archive/<job>/`. Existing job dirs are never deleted.
- Subsets (`--include`, `--tasks`) need their own `--job-name`. `--smoke` runs one development
  task (never a held-out one) in `jobs/tb21-smoke/`, apart from the scored jobs.
- One runner at a time (lock `jobs/tb21.lock`; after a killed run, remove it by hand).
- No paid model calls anywhere in the benchmark or its tests.

## Estimated runtime (rough guess, not measured)
- Guess: average 15 min per task including setup and verification; 89 tasks.
- Per harness: about 22 h wall time sequentially. Three harnesses: about 67 h.
- Worst case for agent time alone: the 89 agent timeouts sum to 42.2 h per harness, so
  126.6 h for the three harnesses (sum x 3). Environment builds and verifiers come on top
  (verifier timeouts sum to 41.4 h per harness).
- Overnight-sized chunks: resume across nights with `run-tb21.sh`.
- Real numbers replace this after the smoke test and the first development-set pass.

## Order of work
1. Check: dataset digest and per-task timeouts against the downloaded dataset, Docker resources,
   flywheel time limit smoke check (Open blockers), host engine reachable from containers and from the host.
2. Smoke: one task per harness, sequential, only when Docker and the host are not loaded.
   Not yet run (host load average was 67 when this was prepared).
3. Fix what would waste runs on the development set.
4. Write and validate the everyday tasks.
5. Freeze, run, harvest, build the landing page.

## Needs the owner
- OK before publishing the page.
- Confirmation that 1 trial per task is acceptable (the official leaderboard needs 5).
