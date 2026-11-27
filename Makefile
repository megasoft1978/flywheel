CC      = clang
CFLAGS  = -O2 -Wall -Wextra -std=c17 -D_POSIX_C_SOURCE=200809L
LDFLAGS = -lcurl
SRC     = src/main.c src/util.c src/agent.c src/http.c src/msgs.c src/tools.c src/bench.c \
          src/args.c src/sim.c src/spiral.c src/profile.c src/tui.c \
          third_party/cjson/cJSON.c
BIN     = flywheel

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -Isrc -Ithird_party/cjson -o $@ $(SRC) $(LDFLAGS)

debug: CFLAGS = -g -O0 -Wall -Wextra -std=c17 -D_POSIX_C_SOURCE=200809L -fsanitize=address
debug: $(BIN)

PREFIX ?= $(HOME)/.local/bin

install: $(BIN)
	mkdir -p $(PREFIX)
	install -m 755 $(BIN) $(PREFIX)/$(BIN)

MICA_DIR ?= ../mica-terminal
MICA_CFLAGS = -I$(MICA_DIR)/include -I$(MICA_DIR)/third_party/libvterm/include
MICA_LIBS = $(MICA_DIR)/src/session.c $(MICA_DIR)/build/libvterm.a -framework CoreFoundation -framework SystemConfiguration -framework Network -framework Security -framework CoreImage -lpthread

clean:
	rm -f $(BIN) tests/test_unit tests/test_mica_tui

.PHONY: clean debug install test test-py sanitize

test: $(BIN) tests/test_unit tests/test_mica_tui
	./tests/test_unit
	./tests/test_mica_tui ./$(BIN)

test-py:
	python3 tests/test_paired_stats.py

tests/test_unit: tests/test_unit.c src/tools.c src/args.c src/sim.c src/spiral.c src/util.c src/msgs.c third_party/cjson/cJSON.c
	$(CC) $(CFLAGS) -Isrc -Ithird_party/cjson -o $@ $^ -lcurl

tests/test_mica_tui: tests/test_mica_tui.c $(MICA_DIR)/src/session.c $(MICA_DIR)/build/libvterm.a
	$(CC) -O2 -Wall -Wextra -std=c17 $(MICA_CFLAGS) -o $@ tests/test_mica_tui.c $(MICA_LIBS)

sanitize: CFLAGS = -g -O1 -Wall -Wextra -std=c17 -D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE -fsanitize=address,undefined
sanitize: clean $(BIN) tests/test_unit tests/test_mica_tui
	./tests/test_unit
	./tests/test_mica_tui ./$(BIN)
