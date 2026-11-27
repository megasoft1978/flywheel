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
flywheel "fix the bug in x.ts"      # one-shot (approves commands automatically, sandboxed)
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
| `--unsafe` | no sandbox, full environment; see [Safety](#safety). Goes before `bench` | off |

`flywheel --help` lists the rest. Settings can also live in `~/.config/flywheel/config`.
Project instructions come from the first of `.flywheel.md`, `AGENTS.md` or `CLAUDE.md`
(first 3,800 characters). A file that links outside the project or into a credential store is skipped.

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

flywheel runs shell commands and project code on your machine. On macOS, the commands the model
runs and the verification gate go through a Seatbelt sandbox (`sandbox-exec`): **they cannot write
outside the project or reach the network unless you approve it.** That is the whole claim. Run an
untrusted repository or task in a VM.

**Sandbox (macOS)**

- Writes: the working directory and a private `$TMPDIR` (plus `/dev/null` and similar). Not `/tmp`.
  Not the project's `.envrc`, `.git/hooks`, `.git/config`, `.git/config.worktree`,
  `.git/commondir`, `.git/rebase-merge`, `.git/rebase-apply` or `.git/sequencer`, which run or
  redirect code later, outside the sandbox. Without a real `.git` directory, nothing can create
  `.git`. The project directory itself and the directories above these files and the stores below
  cannot be renamed or removed.
- Never a `HEAD` in the root, in any case of the name: with `.git` made invalid, git would treat the
  root as a repository. So a root file called `head` cannot be written or checked out (a directory
  of that name that already exists works).
- Anywhere it can write, nested ones included: no creating, changing, renaming in or linking a
  `.envrc` or a nested `.git` (directory, file or symlink), and none of `config`,
  `config.worktree`, `commondir`, `hooks`, `rebase-merge`, `rebase-apply` or `sequencer` in a
  `.git` directory, its `modules` or its `worktrees`. The same holds in the project's git directory
  when `.git` is a link or a `gitdir:` file. No new entry can appear in `.git/modules` or `.git/worktrees`. These are fixed
  rules by name, in every spelling the filesystem treats as the same: nothing is scanned, moved
  or repaired, and detached processes are bound by them too. In a root that is already a bare
  repository (or has a `HEAD` file), the same names are closed there. Every link and `gitdir:` or
  `commondir` file on the way to the project's protected files is closed too, so none can be pointed
  elsewhere, and so is whatever a linked hook in a protected hooks directory leads to. A path
  through `/System/Volumes/Data`, a name at the root starting with a dot (`/.vol`, `/.nofollow`:
  second spellings the rules would miss) or `/dev` (other than `/dev/null`) is refused. If the rules cannot be built, a store is a link that cannot be followed (a loop), or a protected file or git
  directory cannot be followed or read (a loop, or no permission), the command is not run and the
  file tools do not write; the message names the path.
- What `core.hooksPath` names is closed like `.git/hooks`, also to the file tools and before it
  exists; for husky's `.husky/_`, all of `.husky`. Every value in the system, global, repository,
  worktree and submodule configs counts, also one that another overrides, and every `include` and
  `includeIf` file is followed whatever its condition; those config files are closed too. A
  relative value is closed in each work tree, also linked worktrees outside the project, and in
  the git directories, where hooks run on receive. Linked
  hooks directly in such a directory are followed. If a value covers the whole project (`.`, the
  project root or a directory above it), cannot be resolved (`%(prefix)`, an unknown `~user`) or a
  config cannot be read or parsed (also a tab inside an unquoted value, or a
  `.git/worktrees/<name>` without a readable `gitdir`: `git worktree prune`), no command runs, the
  file tools do not write, and the message says why. `/dev/null` turns hooks off and is fine.
- A command that was given the network has all its processes killed when it ends, detached ones
  included, so that none keeps that access. Other background processes (a dev server) keep
  running, still inside the sandbox.
- In a linked git worktree, also its own git directory and the main repository's `objects`, `refs`
  and `logs`, so commits work. Config and hooks there stay closed.
- Reads: **nothing under your home directory** (`$HOME` and the account's home), except:
  - the project (the working directory) and `$TMPDIR`;
  - for a linked git worktree, its git directory and the main repository's git directory;
  - for a submodule, its git directory under `.git/modules/` of the nearest repository above, if
    its `core.worktree` points back to the project and that repository is not at or above a home;
  - git's global configs, every file they include, and `core.excludesfile` and
    `core.attributesfile` when they name an existing file by an absolute or `~` path (a relative
    value opens nothing); `~/.config/git/{ignore,attributes}`;
  - toolchains and downloaded dependencies: `~/.cargo/{bin,registry,git}`, `~/.rustup`,
    `~/go/{bin,pkg/mod}`, `~/.nvm/versions`, `~/.bun/bin`, `~/.pyenv`, `~/.rbenv`,
    `~/Library/Python`, `~/.local/{bin,lib}`, `~/.local/share/uv/{python,tools}`,
    `~/.local/share/pipx/venvs`, `~/.sdkman/candidates`, `~/.m2/repository`,
    `~/.gradle/{caches,wrapper/dists,jdks}`. One that is a symlink opens its target, unless the
    target is or holds a home directory. The list is fixed.

  A git file or toolchain folder reached through a link that a command could change (one inside the
  project, `$TMPDIR` or a linked worktree's writable directories) is not opened at all. Where those
  files and folders, or the way to them, lie in such a place, they cannot be written, created,
  replaced or moved, so no command can plant a link there for itself or a later one.

  Names and contents of everything else there are closed, also through other spellings and
  symlinks. Of the directories and links on the way to the readable places, only metadata can be
  read. If `$HOME` is itself a second spelling (`/System/Volumes/Data/...`), no command runs.
- Credential stores in your home directory are neither readable nor writable, also inside the
  places above, through the file tools and where they are symlinks: `~/.ssh`, `~/.aws`,
  `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.azure`, `~/.netrc`, `~/.git-credentials`,
  `~/.config/{gh,flywheel,gcloud,git/credentials}`, `~/.npmrc`, `~/.pypirc`,
  `~/.cargo/credentials*`, `~/.gem/credentials`, `~/.pgpass`, `~/.vault-token`,
  `~/.m2/settings.xml`, `~/.gradle/gradle.properties`, shell and REPL history files, keychains,
  cookies and the common browser profiles.
- Also unreadable in the toolchain folders: `~/.nvm/versions/**/etc/npmrc`,
  `~/.nvm/versions/**/lib/node_modules/npm/npmrc`,
  `~/.sdkman/candidates/maven/*/conf/settings.xml`, `uv-receipt.toml` of uv tools,
  `pipx_metadata.json` of pipx environments and `~/.cargo/registry/credentials*` (they can hold
  index or registry logins). `~/.cargo/git/db` **stays readable**, and a git dependency's URL there
  may carry a token.
- **Outside your home directory everything you can read stays readable**, and so does every file in
  the places above that is not on the store list (`.env` files in the project, tokens written into
  a git config or a dependency's clone URL). Its contents can reach the model.
- Network: none, not even localhost. In an interactive session the model can ask for it for one
  command; you are asked every time, whatever your "always allow" rules say. One-shot and `bench`
  cannot grant it. Allowed network is any IP address, not one host.
- Environment: only `PATH`, `HOME`, `LANG` and `TERM` are passed on; `TMPDIR`, `XDG_CACHE_HOME`,
  `GOCACHE` and `npm_config_cache` point into the private temporary directory. A `PATH` entry under
  your home that passes through a link is passed on as where it leads.

What stops working inside it:

- Tools that write under `$HOME`: package caches and global installs (`cargo`, `pip --user`,
  Gradle and the like). Fetch dependencies yourself first.
- Anything that reads under `$HOME` outside the places listed above: programs installed elsewhere
  there (also when on your `PATH`), configs such as `~/.cargo/config.toml`, sibling projects and
  path dependencies, shell startup files. Toolchains moved with `CARGO_HOME`, `RUSTUP_HOME` and
  the like are not found.
- git when the project is a subdirectory of a repository under `$HOME` or a `--separate-git-dir`
  checkout: its git directory is outside the project and unreadable (from a subdirectory git would
  also have to list the repository root). Start flywheel at the repository root. In a submodule
  `status` and `log` work. Hooks, `core.hooksPath` directories and object alternates under `$HOME`
  outside the project cannot be read.
- `git init`, and anything that writes `.git/config` or hooks: `git config`, `git remote add`,
  `git push -u`, `git branch -u`, hook installers such as husky or `pre-commit install`.
  Neither can anything that changes a `core.hooksPath` directory, such as editing `.husky/` or a
  checkout, merge or stash that touches files tracked there. `add`,
  `commit`, branches and stash work in the project's own repository. Git may report success
  although the setting was not saved; the tool output says so.
- `git init`, `clone`, `worktree add` and `submodule add` anywhere below the project, also in
  `$TMPDIR`, and so tests that make repositories and package installs that clone one (git
  dependencies) or ship an `.envrc`.
- Rebase and cherry-pick sequences: the model cannot start, continue or abort a rebase,
  `git pull --rebase`, `git am` or a cherry-pick or revert of several commits inside the sandbox.
  You still can, outside it.
- Removing a directory that holds a nested `.git` or `.envrc` (`rm -rf` removes the
  rest and leaves the protected files), and
  `git worktree remove` or `prune`. Renaming the directory around them works.
- Programs started by Node (`npm run`, `npm exec`) can fail with exit 255 when the lookup on
  `PATH` meets `EPERM`: a link under `$HOME` that could not be resolved, or a closed directory that
  holds the name looked up. Take that entry off `PATH` (or, for scripts, use
  `npm run --script-shell=/bin/bash`).
- `pipx` fails when `~/Library/Application Support/pipx` exists: it checks that
  folder and is refused.
- Tools that need a denied file: private registry logins in `~/.npmrc`, `~/.m2/settings.xml`,
  `~/.gradle/gradle.properties` and the like.
- `git fetch`/`push` (offline; over SSH it also fails with network approved, as keys and
  `known_hosts` are unreadable), and Keychain or `gh` credentials.
- A submodule opened as the project, or a worktree whose link back from the main repository does
  not match: no commits.
- New file names with non-ASCII characters in a directory that holds a credential store.
- Docker, `ssh-agent` and other Unix sockets, local servers and tests that open a port (unless
  network is approved), `ps`, pseudo-terminals, `open` and AppleScript.

Where it does not protect you:

- Other files inside the project can be changed, including build scripts, `Makefile`,
  `package.json` and the scripts your hooks call from elsewhere. You or your editor may later run
  them **outside** the sandbox.
- Only a `.git` and what is under it is recognized by name. A bare repository under another name,
  existing or written by hand (`HEAD`, `objects`, `refs`, `config`), can be created and changed
  by commands (and assembled with the file tools), and git run later inside it obeys it; the same holds for the target of a `.git`
  link file that points outside any `.git`, for what a nested config or `.envrc` symlink, or nested
  or submodule hook links, point to, for hard links that already exist, and for new directories
  under a `.git/modules/<group>/` of submodules with a `/` in their name. In a project that is
  itself a bare repository, `modules/` is not closed.
- Links in subdirectories of a hooks directory are not followed: what they point to can be changed.
- `core.hooksPath` is looked for in the repository the project is in (the first `.git` upward, and
  any directory that looks bare on the way), its submodules and its linked worktrees. Not in
  repositories above that one, in other repositories below the project, in the system config
  of a git installed somewhere unusual, or in `GIT_CONFIG_PARAMETERS` and `GIT_CONFIG_COUNT`.
- For a linked worktree whose directory is missing, a relative `core.hooksPath` containing `..` is
  resolved by name and the missing directory itself is not closed: a command may be able to create
  it as a link and redirect that worktree's hooks. `git worktree prune` removes the stale entry.
- Started in your home directory (or above it), the sandbox makes all of it readable and
  writable, except the stores listed above; the toolchain folders and the git files named above are
  read-only there, and missing ones cannot be created (the same for those a project holds, as in a
  dotfiles repository). Start it in a project directory.
- Metadata (existence, size, dates) of the directories above the project and the other readable
  places can be read, and a missing path is reported as missing rather than denied.
- A store reached through a chain of several symlinks is protected at both ends, but a link in the
  middle of the chain can be renamed.
- File tools do not go through the sandbox; they have their own project confinement and refuse the
  stores and the protected files.
- **`bench` grading scripts run the code the model wrote, unsandboxed and with your environment.**
  Run untrusted suites or models in a VM.
- A background process of a command without network access, or of any command with `--unsafe` or
  without a sandbox, keeps running after the command ends, also after flywheel exits.

**No sandbox** (Linux, or `sandbox-exec` unavailable, for example inside another sandbox):
one-shot and `bench` refuse to run unless you pass `--unsafe`. Interactive mode says so and keeps
asking for approval. `--unsafe` turns the sandbox and the environment filtering off.

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

**One-shot and `bench` modes approve everything automatically**, the verification gate included
(network excepted).
`tsc` (through `npx`, which uses a project-local binary), `cargo check` (which runs `build.rs`)
and similar tools execute code from the project.

**Deny rules are best-effort** (`sudo`, destructive `rm`, writes outside the project) and apply
in every mode. They read the command text only:

- Scripts, interpreters, build tools and unlisted commands (`shred`, `tar`, `curl -o`)
  are not inspected.
- Values of unknown `$VARS`, the output of `$(...)` and arguments fed through `xargs` are not seen.
- Write checks do not follow symlinks.
- They allow `/tmp` and `/dev` (except disk devices); the sandbox does not.
- Keeping reads inside the project applies only to the auto-approved built-in commands.

`--allow-outside-writes` is for throwaway containers: commands may write and delete outside the
working directory, recursively too. `sudo`, the other basic deny rules and recursive `rm` of `/`
or your home directory stay blocked. It relaxes only these text rules: on macOS the sandbox still
applies unless `--unsafe` is also given.

## Limits

- Text only. The model has vision, but flywheel sends it text only.
- No API key support. The Linux build has no HTTPS.
- No context compaction.
- No sandbox on Linux yet.
- Detached background processes are found and killed only for sandboxed commands that had the
  network.
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
