#!/bin/bash
# Host-side static aarch64-linux-musl build (container egress is broken; host network is fine).
# 1. musl.cc cross toolchain  2. curl static no-TLS (engine is plain HTTP)  3. flywheel static
set -e
W=~/Desktop/Freelance/flywheel/bench-tb/musl-work
mkdir -p "$W" && cd "$W"
TC="$W/aarch64-linux-musl-cross"
if [ ! -x "$TC/bin/aarch64-linux-musl-gcc" ]; then
  echo "[1] downloading musl toolchain"
  curl -sL -o tc.tgz https://musl.cc/aarch64-linux-musl-cross.tgz
  tar xzf tc.tgz
fi
export PATH="$TC/bin:$PATH"
CURLSRC="$W/curl-8.12.1"
CURLP="$W/curl-prefix"
if [ ! -f "$CURLP/lib/libcurl.a" ]; then
  echo "[2] building static curl (no-TLS: engine is plain HTTP)"
  [ -d "$CURLSRC" ] || { curl -sL -o curl.tgz https://curl.se/download/curl-8.12.1.tar.gz; tar xzf curl.tgz; }
  cd "$CURLSRC"
  ./configure --host=aarch64-linux-musl --prefix="$CURLP" \
    --disable-shared --enable-static --without-ssl --without-zlib --without-brotli \
    --without-zstd --without-libpsl --without-libidn2 --without-nghttp2 \
    --disable-ldap --disable-ldaps --disable-rtsp --disable-dict --disable-telnet \
    --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-smtp \
    --disable-gopher --disable-mqtt --disable-manual --disable-ipv6 \
    --without-ca-bundle --without-ca-path >/dev/null
  make -j8 >/dev/null
  make install >/dev/null
  cd "$W"
fi
echo "[3] building flywheel static"
cd ~/Desktop/Freelance/flywheel
mkdir -p dist
"$TC/bin/aarch64-linux-musl-gcc" -O2 -static -std=c17 -D_GNU_SOURCE \
  -Isrc -Ithird_party/cjson -I"$CURLP/include" \
  -o dist/flywheel-linux-arm64 \
  src/main.c src/util.c src/agent.c src/http.c src/msgs.c src/tools.c src/bench.c \
  src/args.c src/sim.c src/spiral.c src/profile.c src/tui.c third_party/cjson/cJSON.c \
  "$CURLP/lib/libcurl.a" 2>&1 | grep -E "error|undefined" | head -8
ls -la dist/flywheel-linux-arm64 && file dist/flywheel-linux-arm64 | head -1
