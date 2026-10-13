# husk makefile — static analysis, zero dependencies
CC      ?= cc
CFLAGS  ?= -O2
WARN    := -Wall -Wextra -pedantic
SRCDIR  := src
OBJ     := $(patsubst $(SRCDIR)/%.c,build/%.o,$(wildcard $(SRCDIR)/*.c))
CORE    := $(filter-out build/main.o,$(OBJ))

.PHONY: all clean test e2e asan static fixtures

all: husk

build:
	@mkdir -p build

build/%.o: $(SRCDIR)/%.c src/husk.h | build
	$(CC) -c $(CFLAGS) $(WARN) $< -o $@

husk: $(OBJ)
	$(CC) $(CFLAGS) $(WARN) -o $@ $(OBJ) -lm

asan:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"

static: clean
	$(MAKE) CFLAGS="-O2 -static"

test: husk
	$(CC) -c $(CFLAGS) $(WARN) tests/test_main.c -o build/test_main.o
	$(CC) $(CFLAGS) $(WARN) -o build/test_main build/test_main.o $(CORE) -lm
	./build/test_main

e2e: husk
	./tests/e2e_local.sh

clean:
	rm -rf build husk test_tmp
