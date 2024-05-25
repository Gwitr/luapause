#ifndef ARENA_H
#define ARENA_H

#include <stdlib.h>

#define LUA_BASE_ADDR (void*)0x0000000002000000ULL

extern void *alloc_arena;
extern size_t current_usage, peak_usage, arena_memsize;

// TODO: quite wasteful; each area basically has 24 extra bytes stuck on top of it
struct alloc_list
{
    struct alloc_list *prev;
    struct alloc_list *next;
    size_t sz;
};

int arena_init(size_t memsize);

void *arena_realloc(void *ptr, size_t sz);
void arena_free(void *ptr);

void arena_recalc_usage(void);
void arena_stats(void);

#endif  // ARENA_H
