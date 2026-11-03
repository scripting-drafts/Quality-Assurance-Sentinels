CC ?= cc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wno-unused-result
LDFLAGS ?=
PREFIX ?= $(abspath $(CURDIR)/..)

all: qa_sample

qa_sample: qa_sample.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: qa_sample
	mkdir -p $(PREFIX)/bin
	install -m 0755 qa_sample $(PREFIX)/bin/qa_sample

clean:
	rm -f qa_sample

.PHONY: all install clean
