CC      ?= cc
CFLAGS  ?= -O2 -g
# "override" so these survive `make CFLAGS=...` on the command line
override CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Iinclude -D_DEFAULT_SOURCE
LDLIBS  += -lpcap

BIN  := wirewatch
SRC  := $(wildcard src/*.c)
OBJ  := $(SRC:src/%.c=build/%.o)
HDRS := $(wildcard include/*.h)

.PHONY: all clean sanitize test

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

build/%.o: src/%.c $(HDRS) | build
	$(CC) $(CFLAGS) -c -o $@ $<

build:
	mkdir -p build

# Rebuild with AddressSanitizer + UndefinedBehaviorSanitizer. Use this when
# feeding the parser weird or truncated captures: it turns silent memory bugs
# into loud crashes with a stack trace.
sanitize: clean
	$(MAKE) CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined" \
	        LDFLAGS="-fsanitize=address,undefined"

# Compare our decoding field-by-field with Wireshark's (needs tshark + python3)
test: $(BIN)
	python3 tests/verify_against_tshark.py ./$(BIN) samples/*.pcap

clean:
	rm -rf build $(BIN)
