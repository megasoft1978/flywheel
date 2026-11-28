# Advanced

[Back to the README](../README.md)

- [Tested stack and servers](#tested-stack-and-servers)
- [Command line](#command-line)
- [Configuration](#configuration)
- [Images](#images)
- [What the harness does](#what-the-harness-does)
- [Interactive terminal UI](#interactive-terminal-ui)
- [Development](#development)
- [About the demo recording](#about-the-demo-recording)

## Tested stack and servers

| part | what was used |
|---|---|
| model | [`uub336/Qwen3.8-27B-pi-mlx-4bit`](https://huggingface.co/uub336/Qwen3.8-27B-pi-mlx-4bit) (~15 GB, MLX) |
| drafter | [`z-lab/Qwen3.8-27B-DFlash2`](https://huggingface.co/z-lab/Qwen3.8-27B-DFlash2) (~3.9 GB) |
| engine | Splash 1.7.2 (`brew install incoai/tap/splash`) |
| machine | Apple M5 Max, 64 GB |

Smaller Macs are untested.

`flywheel setup` installs the engine and downloads the model, asking first. It needs Homebrew and
`aria2c` (`brew install aria2`), and the model and drafter need about 19 GB of disk.

Already running the server? Point at it:

```bash
flywheel -e http://127.0.0.1:8312/v1 -m local/qwen-pi4
```

flywheel speaks the chat-completions protocol to a local server. It sends no API key, so hosted
services that require one will not work. Other engines and models are untested.

Static Linux binaries (x86_64 and aarch64, needs `zig`): `bench-tb/build-zig.sh` → `dist/`.
The Linux build speaks plain HTTP only.

## Command line

```bash
flywheel                            # interactive session
flywheel "fix the bug in x.ts"      # one-shot (approves commands automatically; sandboxed on macOS)
flywheel -f task.md                 # task from a file
flywheel setup                      # engine + model, asks first
```

**One-shot** is a run given its task up front: a prompt argument, `-f FILE` or piped input. It
approves commands automatically, as does `bench`; network access is excepted and cannot be granted.

| flag | meaning | default |
|---|---|---|
| `-C DIR` | working directory | current |
| `-m MODEL` | model name | `local/qwen-pi4` |
| `-e URL` | endpoint | `http://127.0.0.1:8312/v1` |
| `-f FILE` | task from a file | |
| `--unsafe` | no sandbox, full environment; see [Safety](safety.md). Goes before `bench` | off |
| `--version` | print the version | |
| `--help` | help; `--help all` lists more | |

`--help` leaves these out; they work:

| flag or command | meaning | default |
|---|---|---|
| `-T N` / `-t SEC` | max turns / command timeout | 60 / 30 |
| `-W SEC` | wall clock for the task: cuts model requests, commands and checks; ends as `wall` | off |
| `--transcript FILE` | JSONL log of the run | off |
| `-q` | quiet, for non-interactive runs | off |
| `--allow-outside-writes` | throwaway containers only, see [Safety](safety.md) | off |
| `init` | writes `.flywheel.md` for the current project | |
| `bench <suite-dir> <tag>` | run a benchmark suite | |

```bash
flywheel -f task.md -T 60 -W 900 --transcript run.jsonl
```

## Configuration

Settings can also live in `~/.config/flywheel/config`, as `key=value` lines: `endpoint`, `model`,
`maxturns`, `wall`, `cmd_timeout`. The environment variables `FW_ENDPOINT` and `FW_MODEL` override
the file, and flags override both.

Project instructions come from the first of `.flywheel.md`, `AGENTS.md` or `CLAUDE.md`
(first 3,800 characters). A file that links outside the project or into a credential store is skipped.

The language profile is detected from the project and picks the verification gate:

| file in the project | profile | check |
|---|---|---|
| `package.json` | TypeScript | `tsc --noEmit` |
| `pyproject.toml`, `setup.py` or `requirements.txt` | Python | `python3 -I -m compileall` |
| `go.mod` | Go (experimental) | `go vet` |
| `Cargo.toml` | Rust (experimental) | `cargo check` |
| none of these | generic | no check |

## Images

In the interactive UI and in one-shot mode (`flywheel "describe ./shot.png"`), with the same rules.
One-shot searches only a one-line prompt given on the command line: a `-f` file, piped stdin and a
prompt of several lines are never searched. It prints `✓ N image(s) attached` on stderr, or
`flywheel: not sent: ...` and exits 2 when an image cannot be loaded:

- Drag an image file onto the terminal, or type its path: absolute, `~/`, `./`, `../` or `file://`,
  ending in `.png`, `.jpg`, `.jpeg`, `.gif` or `.webp`. Shell escapes and quotes are understood.
- Give an `http://` or `https://` URL ending the same way. Only public addresses are fetched, with no
  redirects and no proxy. The static Linux build refuses URLs.
- `/paste` attaches the picture on the clipboard (a local macOS session, not over SSH). A file copied
  in Finder may give its icon, so drag files instead.

A message holding only images keeps them for your next one; `^C` or `/clear` drops them. If one cannot
be loaded, nothing is sent and the message returns to the input box; messages queued behind it wait
until your next message is sent (`^C` or `/clear` drops them). Only what you type or paste is
searched, never model output, tool output or project files. A pasted block of several lines is not
searched, and nothing in a backtick code span or fence (also one left unclosed) is attached or
fetched. Naming an image file attaches it, even outside the project.

Limits: 10 MB per file, and 64 images or 32 MB (encoded) per conversation. On macOS, images over
1568 px on a side are downscaled. Images stay in the conversation until `/clear`, and while they do, a
model without vision gets nothing. If the server refuses a request with images (HTTP 400, 413, 415 or
422), the images of the newest message it has not accepted before are dropped, that message's text
stays, and the run says so; nothing is retried. Accepted images are not dropped, and neither is
anything when the refusal is about the context size.

The engine must serve the model with vision. `flywheel setup` starts it that way. A server started
with `--language-only` (as earlier versions did) has to be stopped and started again; flywheel refuses
images while the server reports no vision.

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
- Slash menu (`/init /clear /model /allow /status /paste /copy /mouse /help /exit`), input history,
  large-paste collapse.
- Images, see [Images](#images).
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
- If `SIGTERM`, `SIGHUP`, `SIGQUIT` or a crash ends flywheel, it puts the terminal back first and
  then dies of that signal. On macOS, `SIGTERM` and `SIGHUP` also kill the running command's
  process group.

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

flywheel is about 11k lines of C (plus vendored cJSON): the macOS build links only `libcurl`, and
the Linux build is static.

## About the demo recording

The GIF in the README is a 15 s excerpt of one real run at original speed. The
[56 s video](https://megasoft1978.github.io/flywheel/) is that run uncut: flywheel fixes two bugs
in a small Python project and the 4 tests pass. One edit by the model fails along the way. Approval
dialogs, including the project check, were answered "Yes" by the recording script, and `ls` was set
to show numeric user ids. Qwen3.8-27B 4-bit with the DFlash2 drafter, Splash 1.7.2, Apple M5 Max
64 GB, `flywheel -T 20 -W 120 --transcript`. It was recorded with an earlier build, before the
sandbox and image input. [Transcript](../demo/transcript.jsonl), [script](../demo/record.sh).
