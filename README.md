# flywheel

**A terminal coding agent in C for a model running on your Mac.**

The tested setup is Qwen3.8-27B served locally by Splash with a DFlash2 drafter. No cloud
account and no API key. flywheel is about 7k lines of C (plus vendored cJSON): the macOS build
links only `libcurl`, and the Linux build is static.

![flywheel fixing a Python bug in the terminal, with approval dialogs](docs/demo.gif)

15 s excerpt of one real run at original speed (approvals answered by the recording script): [full 56 s video](https://megasoft1978.github.io/flywheel/) · [transcript](demo/transcript.jsonl).

[Website](https://megasoft1978.github.io/flywheel/) · [Results](#results) · [Safety](#safety) · [Limits](#limits) · MIT

## Results

Early, small and from one run each. Details and caveats are under [Benchmarks](#benchmarks).

- Private TypeScript/React suite: 8 of 13 tasks passed all hidden tests, score 10.15 of 13,
  median 5.7 minutes per task.
- Terminal-Bench 2.0 pilot: 4 of 10 hand-picked tasks.

## Tested stack

| part | what was used |
|---|---|
| model | [`uub336/Qwen3.8-27B-pi-mlx-4bit`](https://huggingface.co/uub336/Qwen3.8-27B-pi-mlx-4bit) (~15 GB, MLX) |
| drafter | [`z-lab/Qwen3.8-27B-DFlash2`](https://huggingface.co/z-lab/Qwen3.8-27B-DFlash2) (~3.9 GB) |
| engine | Splash 1.7.2 (`brew install incoai/tap/splash`) |
| machine | Apple M5 Max, 64 GB |

Smaller Macs are untested.

## Quickstart

macOS on Apple Silicon, with `clang` and `libcurl`. The model and drafter need about 19 GB of
disk. `setup` needs Homebrew and `aria2c` (`brew install aria2`) installed first.

```bash
git clone https://github.com/megasoft1978/flywheel
cd flywheel
make
./flywheel setup     # optional: installs the engine and downloads the model, asking first
./flywheel init      # writes .flywheel.md for the current project
./flywheel           # interactive session
```

Already running the server? Point at it:

```bash
FW_ENDPOINT=http://127.0.0.1:8312/v1 FW_MODEL=local/qwen-pi4 ./flywheel
```

flywheel speaks the chat-completions protocol to a local server. It sends no API key, so hosted
services that require one will not work. Other engines and models are untested.

Static Linux binaries (x86_64 and aarch64, needs `zig`): `bench-tb/build-zig.sh` → `dist/`.
The Linux build speaks plain HTTP only.

## Usage

```bash
flywheel                            # interactive REPL
flywheel "fix the bug in x.ts"      # one-shot (approves commands automatically)
flywheel -f prompt.md -T 60 -W 900 --transcript run.jsonl
flywheel bench <suite-dir> <tag>    # run a benchmark suite
```

| flag | meaning | default |
|---|---|---|
| `-e URL` / `-m NAME` | endpoint / model | `http://127.0.0.1:8312/v1` / `local/qwen-pi4` |
| `-C DIR` | working directory | current |
| `-P ts\|python\|go\|rust\|generic` | language profile | auto-detected |
| `-T N` / `-t SEC` | max turns / command timeout | 60 / 30 |
| `-W SEC` | wall clock, limits model requests only | off |
| `--gates N` | requirement-check passes before finishing | 1 |
| `--transcript FILE` | JSONL log of the run | off |
| `--allow-outside-writes` | throwaway containers only, see [Safety](#safety) | off |

`flywheel --help` lists the rest. Settings can also live in `~/.config/flywheel/config`.
Project instructions come from the first of `.flywheel.md`, `AGENTS.md` or `CLAUDE.md`
(first 3,800 characters).

## What the harness does

- **Loop breaker.** When similar commands keep returning similar results, it prunes those turns,
  adds a correction and temporarily raises temperature. The second and fourth prunes also restart the
  context from the task, the file list and the check output. Successful file edits count as repeats only
  when their text is identical.
- **Tool-call repair.** Recovers shell commands from JSON containing raw control characters.
  Truncated or auto-closed arguments are rejected, never executed.
- **File tools.** `write_file` and `edit_file` with unique-match edits and atomic replacement, confined to the project.
  A file with several hard links is not written. A file whose owner or group cannot be kept, or in a
  directory that refuses new files, is written in place instead, which is not atomic.
- **Verification gate.** A per-language check (`tsc --noEmit`, `python3 -I -m compileall`,
  `go vet`, `cargo check`) and one requirement-by-requirement pass before finishing. A passing
  check means the code type-checks or compiles, not that it is correct. A run whose last check
  fails or times out ends as `check-failed` or `check-timeout`, not `done`. Go and Rust are
  experimental.
- **Transient errors.** HTTP 429 and 5xx and dropped connections are retried up to three times;
  cut-off streams are reported as errors.

## Interactive terminal UI

- Keep typing while the agent works: Enter queues, `Esc` interrupts, scrollback stays put.
- Streaming markdown, code boxes, tables and links.
- Tool output and thinking collapse; click or `^O` to expand.
- Slash menu (`/init /clear /model /allow /status /copy /mouse /help /exit`), input history,
  large-paste collapse.
- `/copy` copies the last assistant reply as plain text (escape sequences, control characters and
  bidi, zero-width and tag characters removed; the England, Scotland and Wales flags stay). It uses
  `pbcopy` on a local macOS session (never one found through a relative `PATH` entry or inside the
  project), otherwise, over SSH or if `pbcopy` fails,
  OSC 52 (replies up to 74994 bytes). A terminal never confirms OSC 52, so paste to check; tmux
  needs `set-clipboard on`.
- Mouse reporting is on by default and takes over drag-to-select. Hold the terminal's bypass key
  while dragging (usually `Shift`; `Option` in iTerm2, `Fn` in Terminal.app), or type `/mouse` to
  turn reporting off. While it is off, scroll with `PgUp`/`PgDn` and expand the latest block with
  `^O`; `/mouse` turns it back on.
- Live tokens per second (end to end), context gauge and completion summary.

## Safety

flywheel runs shell commands and project code on your machine. **It is not a sandbox.** Do not
run it on an untrusted repository or task outside a container or VM.

**Interactive mode**

- Asks before running anything that is not on a short read-only list. Chaining, redirection,
  shell expansion and write or exec flags prompt. So does `git`, because a repository's config
  and hooks can make even `git status` run a program.
- Asks before running the verification gate, showing the exact command. If you decline, the
  summary says the check was not run.
- The dialog shows the whole command, with control and invisible characters made visible, and
  ignores keys typed before it appeared.
- "Always allow" rules are stored per project under `~/.config/flywheel/`; rules shipped inside
  a repository are not trusted. A remembered `npm run`, `go test`, `cargo test` or gate check runs
  whatever the project files contain at that moment, including files the model wrote.

**One-shot and `bench` modes approve everything automatically**, the verification gate included.
`tsc` (through `npx`, which uses a project-local binary), `cargo check` (which runs `build.rs`)
and similar tools execute code from the project.

**Deny rules are best-effort** (`sudo`, destructive `rm`, writes outside the project) and apply
in every mode. They read the command text only:

- Scripts, interpreters, build tools and unlisted commands (`shred`, `tar`, `curl -o`)
  are not inspected.
- Values of unknown `$VARS`, the output of `$(...)` and arguments fed through `xargs` are not seen.
- Write checks do not follow symlinks.
- `/tmp` and `/dev` (except disk devices) are writable.
- Keeping reads inside the project applies only to the auto-approved built-in commands.

`--allow-outside-writes` is for throwaway containers: commands may write and delete outside the
working directory, recursively too. `sudo`, the other basic deny rules and recursive `rm` of `/`
or your home directory stay blocked.

## Limits

- Text only. The model has vision, but flywheel sends it text only.
- No API key support. The Linux build has no HTTPS.
- No context compaction.
- Go and Rust gates are experimental.
- The harness was tuned on the private suite below.
- Not yet measured against OpenCode with the same model, or against Claude Haiku 5.5 run as an
  agent. The planned protocol is in [`bench/PROTOCOL.md`](bench/PROTOCOL.md).

## Benchmarks

### Terminal-Bench 2.0 pilot: 4 of 10 tasks

flywheel with Qwen3.8-27B running locally, through a [Harbor](https://github.com/harbor-framework/harbor) custom agent.

| passed | failed |
|---|---|
| `count-dataset-tokens` | `chess-best-move` (needs reading an image) |
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
| Claude Sonnet 5.5 | one-shot generation, no tools | 12.00 | 13.00 | 12 / 13, then 13 / 13 |
| Claude Haiku 5.5 | one-shot generation, no tools | 12.00 | 13.00 | 12 / 13, then 13 / 13 |

**The Claude models are clearly ahead.** The protocols differ, so this is a reference point
rather than a head-to-head: the Claude runs wrote code without tools and the retry was shown
the failing hidden test; flywheel ran as an agent and never saw those tests. The Haiku row
combines two runs (8 tasks and 5). flywheel was also tuned on this suite, the suite is not
public, and the flywheel run predates the current build. An earlier Python version of the
harness scored higher on total score (11.74) with fewer tasks fully passing (7 / 13).

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
