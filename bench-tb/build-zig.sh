#!/bin/bash
# Static, dependency-free Linux binaries (x86_64 + aarch64 musl) via zig cc.
# Uses the built-in plain-HTTP client (-DFW_MINI_HTTP), so no libcurl needed.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v zig >/dev/null || { echo "zig not found" >&2; exit 1; }
mkdir -p dist
SRC="src/main.c src/util.c src/agent.c src/http.c src/minihttp.c src/msgs.c src/tools.c
     src/bench.c src/args.c src/sim.c src/profile.c src/tui.c src/image.c third_party/cjson/cJSON.c"
for pair in x86_64:amd64 aarch64:arm64; do
  out="dist/flywheel-linux-${pair#*:}"
  zig cc -target "${pair%:*}-linux-musl" -O2 -static -s -std=c17 -D_GNU_SOURCE -DFW_MINI_HTTP \
    -Wall -Wextra -Isrc -Ithird_party/cjson -o "$out" $SRC
  file "$out"
done
echo BUILD-DONE
