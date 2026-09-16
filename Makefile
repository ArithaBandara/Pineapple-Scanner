# Makefile for the multi-threaded TCP port scanner / banner grabber.

CC      := cc
CSTD    := -std=c11
WARN    := -Wall -Wextra -Wpedantic
OPT     := -O3
DEFS    := -D_POSIX_C_SOURCE=200809L
CFLAGS  := $(CSTD) $(WARN) $(OPT) $(DEFS) -Iinclude
LDFLAGS := -pthread

SRC_DIR := src
OBJ_DIR := build
BIN     := portscan

SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SOURCES))

.PHONY: all clean debug

all: $(BIN)

$(BIN): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c include/scanner.h | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Debug build: keep symbols, disable optimization, add sanitizers for
# development/testing (e.g. `make debug && ./portscan-debug -H 127.0.0.1`).
debug: CFLAGS := $(CSTD) $(WARN) -O0 -g $(DEFS) -Iinclude -fsanitize=address,undefined
debug: LDFLAGS := -pthread -fsanitize=address,undefined
debug: $(BIN)-debug

$(BIN)-debug: $(SOURCES) include/scanner.h
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

clean:
	rm -rf $(OBJ_DIR) $(BIN) $(BIN)-debug
