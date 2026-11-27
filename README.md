# flywheel

From-scratch C agent harness for local OpenAI-compatible engines
(tuned for Splash + Qwen3.8-27B on Apple Silicon). Single binary;
macOS links only libcurl + vendored cJSON, and the Linux build
(`zig cc -target x86_64-linux-musl`, see `bench-tb/build-zig.sh`)
is fully static with **zero dependencies** — it speaks HTTP/SSE
directly over sockets (`src/minihttp.c`).

Build: `make` → `./flywheel`

## Benchmark: Terminal-Bench 2.0

Public, harness-agnostic terminal benchmark: the agent runs inside
Linux Docker containers and end-state tests score the task. flywheel
competes through a Harbor custom agent (`bench-tb/flywheel_agent.py`):
the static binary is uploaded into each container and talks back to
the Splash engine on the host — inference stays on Apple Silicon,
zero tokens cost nothing.

Reference numbers from the official tbench.ai 2.0 leaderboard
(archived 2026-03, best published result per agent+model):

| harness | model | TB2.0 |
|---|---|---|
| ForgeCode | Claude Opus 4.6 | 81.8% |
| Codex CLI | GPT-5.2 | 62.9% |
| Claude Code | Claude Opus 4.6 | 58.0% |
| Claude Code | Claude Sonnet 4.5 | 40.1% |
| Goose | Claude Haiku 4.5 | 35.5% |
| Terminus 2 | Claude Haiku 4.5 | 28.3% |
| Claude Code | Claude Haiku 4.5 | 27.5% |
| Dakou Agent | Qwen3-Coder-**480B** (cloud) | 27.2% |
| **flywheel** | **Qwen3.8-27B, local, $0/token** | slice in progress |

The bar flywheel aims at: the best any harness extracted from
Qwen3-Coder-480B — a cloud model ~18x larger — is 27.2%, and
Claude Haiku 4.5 tops out at 35.5% across all published harnesses.
Harness quality is half the product at small scale; that is the
measured claim, not a slogan.

Reproduce: `bench-tb/run-slice.sh` (10-task slice) — needs Docker
and a local OpenAI-compatible engine on `:8312`. Full task list and
oracle validation notes in `bench-tb/PLAN.md`.

## Modes

```bash
flywheel                          # interactive REPL
flywheel "fix the bug in x.ts"    # one-shot
flywheel -f prompt.md -T 60 -W 900 --transcript run.jsonl
```

## Interactive TUI

- Input never dies: type while the agent works — Enter queues the
  message, `Esc` interrupts (also during Bash), scrollback stays
  anchored instead of yanking to bottom (`End` jumps back).
- Markdown rendered as it streams: headings, bold/italic/code,
  fenced code boxes, tables, clickable OSC-8 links.
- Collapsible tool output and thinking: click or `^O` to expand;
  mouse wheel + PgUp/PgDn scroll.
- Approval menus for risky commands: `1 yes / 2 always / 3 no`,
  arrow keys or mouse, persisted per-prefix rules in `.flywheel.allow`.
- Structured tools `write_file` / `edit_file` (path-confined to the
  project, unique-match edits) beside `bash`.
- Slash menu `/init /clear /model /allow /status /diagnose /help /exit` with
  live filtering, bracketed paste collapse, clipboard-image paste
  (ctrl+V), live telemetry: tok/s, context gauge, completion pills.

## Learned mitigations (from the tsreact bench, v8 = 11.74→12.66/13)

- **period-1/2/3 + repeat loop breaker**: same-command similarity
  (Ratcliff gestalt >0.82/0.88) → prune turns, inject corrective msg,
  2-turn escape temp (0.5 + pp 0.25), alternating context resets.
- **lenient tool-arg extraction**: escape raw control chars inside
  JSON strings → auto-close truncated JSON → direct `"command"` key
  scan fallback; repairs counted in `--transcript`.
- **heredoc delimiter rewrite**: `<<'EOF'` colliding with payload
  → `FW_EOF_n`.
- **auto-gate**: per-language verify command every 8 write-turns and
  before DONE (ts `tsc --noEmit`, py compileall, go vet, cargo check).
- **verification gate** (MAX_GATES=1): one enumerate-and-verify pass
  before finish.
- **deny rules**: sudo/rm-rf/outside-cwd writes blocked pre-exec.
- **30s cmd timeout** w/ hang hint, wall clock, turn nudges.
- **graveyard**: bounded list (6) of failed commands + output tails
  (`src/spiral.c`), re-injected after every loop prune / context reset so the
  model does not walk back into a dead end it already tried. Failure = non-zero
  exit with real output, timeout, or tool error (silent probes like a `grep`
  miss don't count).
- **failure-spiral rescue** (`--spiral N`): after N consecutive failing tool
  results, one fresh-context call (task + graveyard + latest failure only,
  ≤1600 tok) diagnoses the root cause and is injected as a user message. Max 3
  per task; counted as `rescues=` in the run summary. Default: **3 in one-shot /
  bench mode, off in the interactive TUI** (failing tests are normal there). In
  the TUI a hint appears after 3 failures in a row and `/diagnose` runs the
  same review on demand, then continues the task with it. `--spiral 0` disables
  everything automatic; `--spiral N` forces auto mode in the TUI too. Idea from
  Cortheon's graveyard backtracking / death-spiral rescue.

## Language profiles

Auto-detected from `package.json | pyproject.toml|setup.py |
go.mod | Cargo.toml` in `-C` dir; force with `-P ts|python|go|rust|generic`.
Project instructions auto-loaded from `.flywheel.md | AGENTS.md |
CLAUDE.md` in the working dir.

## Env / flags

`FW_ENDPOINT` (def `http://127.0.0.1:8312/v1`), `FW_MODEL`
(def `local/qwen-pi4`). `-T` turns · `-W` wall · `-t` cmd timeout ·
`-K` max tokens · `--temp/--topp/--pp` · `--think N` · `--gates N` ·
`--sys TEXT` · `-q` quiet.

Server-side thinking budget recommended: Splash
`--thinking-token-budget 1024` (bench optimum: off→1.70, 512→2.65,
1024→2.81, 2048→2.81 on the 3-hard suite).

## Bench mode

`flywheel [flags] bench <suite-dir> <tag> [task-id ...]` — pure-C suite runner
(no Python). Suite layout:

```
<suite>/suite.json          {"copy_files": [...], "clone_dirs": [...],
                             "skip_deliverables": [...], "grade_script": "run_task.sh",
                             "grade_timeout": 400}
<suite>/tasks/<id>/prompt.md     task prompt
<suite>/tasks/<id>/starter/      optional, copied into the sandbox
<suite>/tasks/<id>/tests/        hidden tests (never shown to the agent)
<suite>/run_task.sh <id> <dir>   grader -> one JSON line on stdout
```

Per task: fresh `/tmp` sandbox (clone_dirs via `cp -cR` copy-on-write, fallback
`cp -R`), in-process agent run, deliverables collected (skipping
skip_deliverables + `*.test.*`/`*.spec.*`), graded, appended to
`<suite>/runs/<tag>/summary.json`. Scoring: `gated` counts passed/total only
when tsc/typecheck is clean; `raw` ignores the gate. Output format matches the
retired Python harness, so scores are directly comparable across runs.

## Comparing two runs

`bench-tb/paired_stats.py BASE CAND` compares two Harbor job dirs (or two flywheel
`summary.json`) task-by-task: pass rate with 95% Wilson CIs, fixed/broken pairs,
exact McNemar p. A 10-task slice rarely reaches significance; the tool says so
instead of letting a +1 task swing read as a win. `make test-py` runs its tests.

## Interactive TUI (v2)

claude-code-style: pinned rounded input box, status line, scroll-region output,
line editing (←→ home/end/del, ^W ^U ^K ^A ^E), history (↑↓), alt+enter
multiline, bracketed paste with large-paste `[paste#N]` collapse, ctrl+V
clipboard-image paste (macOS, saves `.flywheel/paste-N.png`), slash menu
(/init /clear /model /allow /status /diagnose /help /exit) with live filtering.

## Permissions

bash-only agent ⇒ interactive approval: `y` once · `a` always · `n` deny.
"always" derives a prefix rule (two tokens for git/npx/npm/…) persisted to
`.flywheel.allow` in the project (+ `~/.config/flywheel/allow` global).
Builtin auto-allow: read-only commands (ls cat grep rg git status/diff/log…).
Deny rules (sudo, rm -rf /, writes outside cwd) always win.
Bench/one-shot modes auto-approve — no behavior change for automation.

## Tests

`make test` — unit (37: deny/heredoc/args/perm/utf8/msgs/sim) + pty integration
(11: rendering, editing, menu, paste, exit). `make sanitize` — ASan+UBSan build.
