CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Iinclude -D_DEFAULT_SOURCE
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

clean:
	rm -rf build $(BIN)
