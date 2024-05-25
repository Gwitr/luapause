#include "arena.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <sys/mman.h>

void *alloc_arena = NULL;
size_t current_usage = sizeof(struct alloc_list), peak_usage = sizeof(struct alloc_list), arena_memsize = 0;

void arena_free(void *ptr)
{
    if (!ptr)
        return;
    struct alloc_list *list = (struct alloc_list *)((char*)ptr - sizeof(struct alloc_list));
    // VERY rudimentary safety
    if (list->sz == 0) {
        fprintf(stderr, "arena_free: double free\n");
        abort();
    }

    current_usage -= list->sz + sizeof(struct alloc_list);
    if (current_usage == 0)
        current_usage = sizeof(struct alloc_list);
    if (peak_usage < current_usage) peak_usage = current_usage;

    if (list->prev)
        list->prev->next = list->next;
    list->next->prev = list->prev;
    list->sz = 0;
}

void arena_recalc_usage(void)
{
    struct alloc_list *src_list = alloc_arena;
    current_usage = sizeof(struct alloc_list);
    while (src_list->sz != 0) {
        current_usage += src_list->sz + sizeof(struct alloc_list);
        src_list = src_list->next;
    }
    peak_usage = current_usage;
}

void arena_stats(void)
{
    printf("=== ARENA ALLOCATION STATISTICS ===\n");
    struct alloc_list *src_list = alloc_arena;
    void *last = NULL;
    while (src_list->sz != 0) {
        void *ptr = (char*)src_list + sizeof(struct alloc_list);
        printf("at %p: size %llu", ptr, (unsigned long long)src_list->sz);
        if (last) {
            printf(" dst %lld", (long long)((char*)ptr - (char*)last));
        }
        printf("\n");
        last = ptr;
        src_list = src_list->next;
    }
    printf("-----------------------------------\n");
    printf("Usage: %llu/%llu; %.4f%%\n", (unsigned long long)current_usage, (unsigned long long)arena_memsize, (double)current_usage/arena_memsize*100);
    printf("Peak usage: %llu/%llu; %.4f%%\n", (unsigned long long)peak_usage, (unsigned long long)arena_memsize, (double)peak_usage/arena_memsize*100);
    printf("===================================\n");
}

// extremely basic allocator implementation
void *arena_realloc(void *ptr, size_t sz)
{
    // TODO: you go out of your way to make sure the linked list is sorted; you should use that property here and
    // binary search. linked lists make it inefficient, but maybe some sort of acceleration structure could help?
    struct alloc_list *src_list = alloc_arena;
    while (src_list->sz != 0) {
        if ((void*)((char*)src_list + sizeof(struct alloc_list)) == ptr)
            break;
        src_list = src_list->next;
    }
    if (ptr != NULL && src_list->sz == 0) {
        fprintf(stderr, "arena_realloc: realloc unallocated %p\n", ptr);
        abort();
    }

    struct alloc_list *cur_list = alloc_arena;
    if (cur_list->sz == 0) {
        assert(ptr == NULL);
        if (sz >= arena_memsize - sizeof(struct alloc_list) * 2)
            return NULL;
        cur_list->next = (void*)((char*)alloc_arena + arena_memsize - sizeof(struct alloc_list));
        cur_list->next->prev = cur_list;
        cur_list->next->next = NULL;
        cur_list->next->sz = 0;
        cur_list->sz = sz;
        current_usage += sz + sizeof(struct alloc_list);
        if (peak_usage < current_usage) peak_usage = current_usage;
        return (char*)alloc_arena + sizeof(struct alloc_list);
    }
    void *result = NULL;
    while (cur_list->sz != 0) {
        void *end;
        void *start = (char*)cur_list + sizeof(struct alloc_list) + cur_list->sz;
        if ((intptr_t)start % sizeof(struct alloc_list) > 0) {
            start = (char*)start + (sizeof(struct alloc_list) - (intptr_t)start % sizeof(struct alloc_list));
        }
        if (cur_list->next->sz == 0) {
            end = (void*)((char*)alloc_arena + arena_memsize - sizeof(struct alloc_list) - 1);
        } else {
            end = (void*)((char*)cur_list->next - 1);
        }
        if (start > end) {
            cur_list = cur_list->next;
            continue;
        }
        if ((unsigned long)((char*)end - (char*)start) < sizeof(struct alloc_list) + sz) {
            cur_list = cur_list->next;
            continue;
        }
        result = start;
        break;
    }
    if (!result)
        return NULL;
    struct alloc_list *new_list = result;
    new_list->prev = cur_list;
    new_list->next = new_list->prev->next;
    new_list->prev->next = new_list;
    new_list->next->prev = new_list;
    void *new_ptr = (void*)((char*)result + sizeof(struct alloc_list));
    new_list->sz = sz;
    current_usage += sz + sizeof(struct alloc_list);
    if (peak_usage < current_usage) peak_usage = current_usage;

    if (ptr) {
        memcpy(new_ptr, ptr, src_list->sz < sz ? src_list->sz : sz);
        arena_free(ptr);
    }
    return new_ptr;
}

int arena_init(size_t memsize)
{
    arena_memsize = memsize;
    alloc_arena = mmap(LUA_BASE_ADDR, arena_memsize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_PRIVATE, -1, 0);
    if (alloc_arena == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }
    if (alloc_arena != LUA_BASE_ADDR) {
        char buf[256];
        snprintf(buf, 256, "mmap failed (got area at %p, expected %p)", alloc_arena, LUA_BASE_ADDR);
        perror(buf);
        return 1;
    }
    *(struct alloc_list *)alloc_arena = (struct alloc_list){ .prev = NULL, .next = NULL, .sz = 0 };
    return 0;
}