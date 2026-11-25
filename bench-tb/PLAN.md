# Terminal-Bench 2.0 adoption plan (user decisions: TB2.0, published-leaderboard comparison, small slice first)

## Architecture (from terminal_bench/agents research)
- TB agents execute INSIDE Linux Docker containers (setup script installs agent in-container).
- flywheel is pure C17 + libcurl + vendored cJSON → cross-compile/static-build for Linux amd64+arm64.
- Container reaches host Splash engine via host.docker.internal:8021 (Docker Desktop on macOS supports it; else --add-host or host network).

## Steps
1. Portability milestone: build flywheel on Linux (docker run --rm -v $PWD:/src alpine/debian gcc/musl static build).
   - linuxify: osascript clipboard paste is macOS-only (guard with #ifdef __APPLE__), leaks/ncurses none, rest is POSIX.
   - Add Makefile target `make linux-static` producing dist/flywheel-linux-{amd64,arm64}.
2. TB harness setup: uv/python venv in bench-tb/, `uv run tb run` works, GPU no. tasks live in original-tasks/ or registry.
3. Custom agent: subclass BaseAgent (terminal_bench.agents) — setup script copies static binary into container,
   env FW_ENGINE_URL=http://host.docker.internal:8021/v1, run `flywheel -f instruction` non-interactive one-shot per task.
   - flywheel non-interactive mode already exists (one-shot arg). Needs: stdin-independent, exit code, DONE protocol ok.
4. Slice validation: 10-15 representative tasks (mix: hello-world, sysadmin, build, debugging) end-to-end.
5. Full run overnight; publish score.
6. Comparison table in README + docs/index.html: flywheel+Qwen3.8-27B (local, $0) vs published TB2.0 leaderboard
   (Claude Sonnet, GPT, Gemini rows). Framing: cost-adjusted performance, only harness measured against its model.
7. TUI+code iteration continues in parallel (deferred review items: no-with-feedback, gutter rhythm, @mentions).

## Open questions
- TB2.0 exact task-set id/registry for 2.0 (vs original-tasks 1.0).
- Whether containers have outbound network by default (needed for host.docker.internal engine path) — verify with hello-world.


## Progress log (2026-11-25 session 2)
- Harness corrected: TB2.0 runs on **Harbor** (`uv tool install harbor`), NOT terminal-bench 1.x.
- Oracle smoke: PASSED 2/2 (circuit-fibsqrt, make-mips-interpreter) — Docker pipeline + dataset download validated. Jobs in bench-tb/jobs/.
- Engine: Splash lives on port **8312** (not 8021). Server up: local/qwen-pi4, ctx 262144.
- flywheel_agent.py written for Harbor BaseAgent (setup: upload binary per uname arch; run: one-shot).
- BLOCKER: Linux static build stalls — apk large downloads stall inside containers (small files ok).
  Docker Desktop container-network egress broken for big transfers; oracle still passed (tasks need no net).
- CRITICAL UNVERIFIED: whether containers can reach host.docker.internal:8312 — test in flight with curlimages/curl.
  If THAT path is also broken, flywheel-in-container cannot reach the engine and the whole approach needs
  host networking (--network host unsupported for TB) or engine-in-container sidecar.
- Compile fixes needed for musl: -D_GNU_SOURCE (wcwidth/usleep/killpg/realpath implicit decls) — done in build script.
- bench validation (tsreact vtools1 imperfect tasks) restarted with correct task ids — results in /tmp/fwbench_result.txt.
- next: finish static build (consider host-side musl.cc toolchain download since host network is fine),
  verify container->host engine path, then single-task agent smoke.


## 2026-11-25 late — pipeline validated, slice running

- **Static binaries built** via zig+minihttp (pure-C HTTP/SSE client, zero deps):
  `dist/flywheel-linux-arm64` (2.4MB) + `dist/flywheel-linux-amd64` (2.3MB).
  Build: `zig cc -target {arch}-linux-musl -DFW_MINI_HTTP` (see git history / build-zig.sh).
- **TB2.0 containers are x86_64** (Rosetta-emulated on Apple Silicon) — amd64 binary required.
- Smoke on circuit-fibsqrt: pipeline end-to-end green (binary uploads, engine reachable
  at host.docker.internal:8312, tools execute in-container, verifier scores). reward 0.0 —
  hard task, agent hit turn cap without DONE; expected for first smoke.
- minihttp transport validated equivalent to curl build on host.
- **Slice running** (10 tasks, wall 900s each, sequential): `bench-tb/harvest.sh` for results.
- Leaderboard: `bench-tb/leaderboard-tb2.json` (120 official entries, archived 2026-03).
- Known issues: agent kwargs (`--ak`) are ignored by harbor (options_model undeclared) —
  defaults in flywheel_agent.py are authoritative. Model rarely emits DONE on hard tasks;
  termination is finish_reason-driven, so hard tasks burn the full wall budget.
