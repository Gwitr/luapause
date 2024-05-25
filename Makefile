CC=gcc
CFLAGS=-g -Wall -Wextra -pedantic -I/usr/include/lua5.3
LFLAGS=-llua5.3

build: luapause.c arena.c arena.h
	$(CC) $(CFLAGS) -o luapause luapause.c arena.c $(LFLAGS)

clean:
	rm -f luapause

@PHONY: build clean