CC      = clang
CFLAGS  = -O2 -Wall -Wextra -std=c17 -D_POSIX_C_SOURCE=200809L
LDFLAGS = -lcurl
SRC     = src/main.c src/util.c src/agent.c src/http.c src/msgs.c src/tools.c src/bench.c \
          src/args.c src/sim.c src/profile.c src/tui.c \
          third_party/cjson/cJSON.c
BIN     = flywheel
# sanitizer builds get their own directory: make does not track CFLAGS, so
# sharing outputs would leave an instrumented ./flywheel that looks up to date
TESTDIR = tests
SAN     = build-asan
SAN_CFLAGS = -g -O1 -Wall -Wextra -std=c17 -D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE -fsanitize=address,undefined -fno-sanitize-recover=all

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -Isrc -Ithird_party/cjson -o $@ $(SRC) $(LDFLAGS)

debug:
	mkdir -p $(SAN)
	$(MAKE) -B BIN=$(SAN)/flywheel-debug CFLAGS='-g -O0 -Wall -Wextra -std=c17 -D_POSIX_C_SOURCE=200809L -fsanitize=address' $(SAN)/flywheel-debug

PREFIX ?= $(HOME)/.local/bin

install: $(BIN)
	mkdir -p $(PREFIX)
	install -m 755 $(BIN) $(PREFIX)/flywheel

MICA_DIR ?= ../mica-terminal
MICA_CFLAGS = -I$(MICA_DIR)/include -I$(MICA_DIR)/third_party/libvterm/include
MICA_LIBS = $(MICA_DIR)/src/session.c $(MICA_DIR)/build/libvterm.a -framework CoreFoundation -framework SystemConfiguration -framework Network -framework Security -framework CoreImage -lpthread

clean:
	rm -f $(BIN) tests/test_unit tests/test_unit_mini tests/test_mica_tui
	rm -rf $(SAN)

.PHONY: clean debug install test test-unit test-mica sanitize

# the TUI test needs a mica-terminal checkout; skip it (loudly) without one
ifneq ($(wildcard $(MICA_DIR)/src/session.c),)
MICA_DEPS = $(BIN) $(TESTDIR)/test_mica_tui
# HOME is a throwaway so "always allow" rules never reach the real config
MICA_RUN = HOME=$$(mktemp -d) ./$(TESTDIR)/test_mica_tui ./$(BIN)
else
MICA_DEPS =
MICA_RUN = @echo "SKIP mica TUI test: MICA_DIR=$(MICA_DIR) not found"
endif

test-unit: $(BIN) $(TESTDIR)/test_unit $(TESTDIR)/test_unit_mini
	FW_BIN=./$(BIN) ./$(TESTDIR)/test_unit
	FW_BIN=./$(BIN) ./$(TESTDIR)/test_unit_mini

test-mica: $(MICA_DEPS)
	$(MICA_RUN)

test: $(BIN) test-unit test-mica

# built twice: libcurl transport and the FW_MINI_HTTP one
UNIT_SRC = tests/test_unit.c src/tools.c src/args.c src/sim.c src/util.c src/msgs.c \
           src/agent.c src/http.c src/profile.c src/bench.c third_party/cjson/cJSON.c

$(TESTDIR)/test_unit: $(UNIT_SRC)
	$(CC) $(CFLAGS) -Isrc -Ithird_party/cjson -o $@ $^ -lcurl

$(TESTDIR)/test_unit_mini: $(UNIT_SRC) src/minihttp.c
	$(CC) $(CFLAGS) -D_DARWIN_C_SOURCE -DFW_MINI_HTTP -Isrc -Ithird_party/cjson -o $@ $^

$(TESTDIR)/test_mica_tui: tests/test_mica_tui.c $(MICA_DIR)/src/session.c $(MICA_DIR)/build/libvterm.a
	$(CC) -O2 -Wall -Wextra -std=c17 $(MICA_CFLAGS) -o $@ tests/test_mica_tui.c $(MICA_LIBS)

sanitize:
	mkdir -p $(SAN)
	$(MAKE) -B BIN=$(SAN)/flywheel TESTDIR=$(SAN) CFLAGS='$(SAN_CFLAGS)' test-unit test-mica
