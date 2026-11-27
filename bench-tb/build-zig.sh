#!/bin/bash
# Static aarch64-linux-musl flywheel via zig cc (native macOS host, no container network needed)
set -e
W=~/Desktop/Freelance/flywheel/bench-tb/zig-work
mkdir -p "$W" && cd "$W"
CURLSRC="$W/curl-8.12.1"
CURLP="$W/curl-prefix"
if [ ! -f "$CURLP/lib/libcurl.a" ]; then
  echo "[1] curl source"
  [ -d "$CURLSRC" ] || { curl -sL -o curl.tgz https://curl.se/download/curl-8.12.1.tar.gz && tar xzf curl.tgz; }
  echo "[2] configure+build static curl (no-TLS, plain HTTP engine)"
  cd "$CURLSRC"
  CC="zig cc -target aarch64-linux-musl" \
  ./configure --host=aarch64-linux-musl --prefix="$CURLP" \
    --disable-shared --enable-static --without-ssl --without-zlib --without-brotli \
    --without-zstd --without-libpsl --without-libidn2 --without-nghttp2 \
    --disable-ldap --disable-ldaps --disable-rtsp --disable-dict --disable-telnet \
    --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-smtp \
    --disable-gopher --disable-mqtt --disable-manual \
    --without-ca-bundle --without-ca-path >/tmp/fwcurlconf.log 2>&1 || { echo CONF-FAIL; tail -12 /tmp/fwcurlconf.log; exit 1; }
  make -j8 >/dev/null 2>&1 || { echo MAKE-FAIL; exit 1; }
  make install >/dev/null 2>&1 || { echo INSTALL-FAIL; exit 1; }
  cd "$W"
fi
echo "[3] flywheel static"
cd ~/Desktop/Freelance/flywheel
mkdir -p dist
zig cc -target aarch64-linux-musl -O2 -static -std=c17 -D_GNU_SOURCE \
  -Isrc -Ithird_party/cjson -I"$CURLP/include" \
  -o dist/flywheel-linux-arm64 \
  src/main.c src/util.c src/agent.c src/http.c src/msgs.c src/tools.c src/bench.c \
  src/args.c src/sim.c src/spiral.c src/profile.c src/tui.c third_party/cjson/cJSON.c \
  "$CURLP/lib/libcurl.a" 2>&1 | grep -iE "error|undefined" | head -8
ls -la dist/flywheel-linux-arm64 2>/dev/null && echo BUILD-DONE
