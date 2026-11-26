# flywheel

**A terminal coding agent written in C, built for a local model on your own machine.**

flywheel talks to any OpenAI-compatible endpoint and is tuned for Qwen3.8-27B served by
Splash on Apple Silicon. It is one small binary of about 6k lines of C (plus vendored
cJSON): macOS links only `libcurl`, and the Linux build is fully static.

[Website](https://megasoft1978.github.io/flywheel/) · [Benchmarks](#benchmarks) · [Safety model](#safety-model) · MIT

```text
$ flywheel "test_calc.py fails. Fix the bug in calc.py and run the test."
⏺ Bash(ls -la && cat calc.py test_calc.py)
⏺ Edit(calc.py)
  ⎿  ok: edited calc.py at line 2 (32 bytes)
⏺ Bash(python3 test_calc.py)
  ⎿  ok
● flywheel: finish=done turns=4 calls=3 tokens=249 secs=2
```

<sub>Trimmed output of a real run on a deliberately trivial task, with `--gates 0`.</sub>

## Quickstart

macOS (Apple Silicon), with `clang` and `libcurl`:

```bash
git clone https://github.com/megasoft1978/flywheel
cd flywheel
make
./flywheel setup     # optional: installs the engine and downloads the model, asking first
./flywheel init      # writes .flywheel.md for the current project
./flywheel           # interactive session
```

Already running an OpenAI-compatible server? Skip `setup` and point at it:

```bash
FW_ENDPOINT=http://127.0.0.1:8312/v1 FW_MODEL=local/qwen-pi4 ./flywheel
```

Static Linux binaries (x86_64 and aarch64, needs `zig`): `bench-tb/build-zig.sh` → `dist/`.

## Usage

```bash
flywheel                            # interactive REPL
flywheel "fix the bug in x.ts"      # one-shot
flywheel -f prompt.md -T 60 -W 900 --transcript run.jsonl
flywheel bench <suite-dir> <tag>    # run a benchmark suite
```

| flag | meaning | default |
|---|---|---|
| `-e URL` / `-m NAME` | endpoint / model | `http://127.0.0.1:8312/v1` / `local/qwen-pi4` |
| `-C DIR` | working directory | current |
| `-P ts\|python\|go\|rust\|generic` | language profile | auto-detected |
| `-T N` / `-W SEC` / `-t SEC` | max turns / wall clock / command timeout | 60 / off / 30 |
| `--gates N` | verification passes before finishing | 1 |
| `--transcript FILE` | JSONL log of the run | off |

`flywheel --help` lists the rest. Settings can also live in `~/.config/flywheel/config`.
Project instructions are loaded from `.flywheel.md`, `AGENTS.md` or `CLAUDE.md`.

## What the harness does for a small model

Small local models fail in repetitive, recoverable ways. flywheel handles them in the harness:

- **Loop breaker.** Detects repeated and near-repeated commands, prunes the loop, injects a
  correction and temporarily raises temperature.
- **Tool-call repair.** Recovers shell commands from JSON with raw control characters.
  Truncated or auto-closed arguments are rejected, never executed.
- **Structured file tools.** `write_file` and `edit_file` with unique-match edits, confined
  to the project directory.
- **Verification gate.** Per-language checks (`tsc --noEmit`, `compileall`, `go vet`,
  `cargo check`) and one requirement-by-requirement pass before finishing.
- **Failure handling.** HTTP errors and cut-off streams are reported as errors, not success;
  transient transport errors are retried.

## Interactive terminal UI

- Keep typing while the agent works: Enter queues, `Esc` interrupts, scrollback stays put.
- Streaming markdown, code boxes, tables and links.
- Tool output and thinking collapse; click or `^O` to expand.
- Slash menu (`/init /clear /model /allow /status /help /exit`), input history,
  large-paste collapse, clipboard images with `^V` (macOS).
- Live tokens per second, context gauge and completion summary.

## Safety model

flywheel runs shell commands on your machine. **It is not a sandbox.**

- **Interactive mode** asks before running anything that is not on a short read-only list.
  Chaining, redirection, shell expansion and write or exec flags always prompt. So does
  `git`, because a repository's config and hooks can make even `git status` run a program.
- The approval dialog shows the whole command, with control and invisible characters made
  visible, and ignores keys typed before it appeared.
- "Always allow" rules are stored per project under `~/.config/flywheel/`. Rules shipped
  inside a repository are not trusted.
- **One-shot and `bench` modes approve commands automatically.** Only the deny rules apply.
- Deny rules (`sudo`, destructive `rm`, writes outside the project) are best-effort and can
  be bypassed, for example through an interpreter. Run untrusted tasks in a container or VM.

## Benchmarks

Both results below are early and small. They are published with their limits.

### Terminal-Bench 2.0 pilot: 4 of 10 tasks

flywheel with Qwen3.8-27B running locally, through a [Harbor](https://github.com/harbor-framework/harbor) custom agent.

| passed | failed |
|---|---|
| `count-dataset-tokens` | `chess-best-move` (needs vision; the model is text-only) |
| `extract-elf` | `circuit-fibsqrt` |
| `fix-git` | `make-mips-interpreter` |
| `git-multibranch` | `dna-insert` |
| | `filter-js-from-html` |
| | `gcode-to-text` |

**This is not a leaderboard score and should not be compared with one.** The 10 tasks were
hand-picked, not the full set; each ran once; seven were re-run after a Docker network outage
stopped them from starting; and the two sessions used different builds. It also predates a
fix for missing file-tool parameter schemas. A full run is still to be done.

### Coding suite: 13 TypeScript and React tasks

A private suite of hidden-test tasks. Score = fraction of tests passing per task, zero if the
type check fails, summed over 13.

| runner | protocol | first attempt | after retry | tasks fully passing |
|---|---|---|---|---|
| flywheel + Qwen3.8-27B (local) | agent loop, one run | 10.15 | — | 8 / 13 |
| Claude Sonnet 5.5 | one-shot generation, no tools | 12.00 | 13.00 | 13 / 13 |
| Claude Haiku 5.5 | one-shot generation, no tools | 12.00 | 13.00 | 13 / 13 |

**The frontier models are clearly ahead.** The protocols differ, so this is a reference point
rather than a head-to-head: the Claude runs wrote code without tools and could retry once;
flywheel ran as an agent. flywheel was also tuned on this suite, and the suite is not public.
The flywheel run predates the current build.

### Reproducing the pilot

Needs Docker, Harbor (`uv tool install harbor`), `zig`, and a local engine on `:8312`:

```bash
bench-tb/build-zig.sh
bench-tb/run-slice.sh
bench-tb/harvest.sh
```

## Development

```bash
make              # build
make test-unit    # unit tests, both HTTP transports
make test         # unit tests + terminal UI tests
make sanitize     # the same under AddressSanitizer and UBSan
```

The terminal UI tests drive the real binary through
[mica-terminal](https://github.com/megasoft1978/mica-terminal), expected at `../mica-terminal`
with `build/libvterm.a` built. Without it, `make test` skips them and says so.

## License

[MIT](LICENSE)
