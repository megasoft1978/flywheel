#!/bin/bash
# Static Linux build of flywheel inside Alpine docker (musl => runs on any distro)
set -e
cd "$(dirname "$0")/.."
mkdir -p dist
ARCH="${1:-arm64}"
PLATFORM="linux/$ARCH"
docker run --rm --platform "$PLATFORM" -v "$PWD":/src -w /src alpine:3.21 sh -c '
  set -e
  echo "[1/4] apk update"; apk update
  echo "[2/4] apk add toolchain"; apk add --no-cache gcc musl-dev
  echo "[3/4] apk add curl static libs"; apk add --no-cache curl-dev curl-static openssl-libs-static zlib-static brotli-static zstd-static nghttp2-static libpsl-static
  echo "[4/4] compile"
  gcc -O2 -static -Wall -std=c17 -D_GNU_SOURCE -Isrc -Ithird_party/cjson \
    -o /tmp/flywheel \
    src/main.c src/util.c src/agent.c src/http.c src/msgs.c src/tools.c src/bench.c src/args.c src/sim.c src/spiral.c src/profile.c src/tui.c \
    third_party/cjson/cJSON.c -lcurl -lssl -lcrypto -lz -lbrotlidec -lbrotlicommon -lzstd -lnghttp2 -lpsl
  cp /tmp/flywheel /src/dist/flywheel-linux-'"$ARCH"'
  echo BUILD-OK
' 2>&1 | tail -8
ls -la dist/flywheel-linux-$ARCH 2>/dev/null && file dist/flywheel-linux-$ARCH
