// gcc -g -Wall -Wextra -pedantic -o luapause luapause.c arena.c -llua5.3 -I/usr/include/lua5.3
// (compiles with 2 warnings)

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/wait.h>
#include <sys/personality.h>

#include "arena.h"

#define DEFAULT_MEMSIZE 65536ULL

enum modes { UNKNOWN, START, RESUME, HELP } mode = UNKNOWN;
const char *dump_path = NULL, *src_path = NULL;
int verbose = 0;
int memsize = 0;

static void fprint_stack_string(FILE *file, lua_State *state, int level, const char *dft);
static void collect_args(int argc, char **argv);
static void disable_aslr(char **argv);
static lua_State *load_lua_state(const char *path);
static lua_State *new_lua_state(const char *srcpath);
static int dump_lua_state(const char *path, lua_State *state);

// int getopt(argc, argv, const char *optstring);

int main(int argc, char **argv)
{
    lua_State *state = NULL;

    disable_aslr(argv);
    collect_args(argc, argv);

    if (mode == RESUME)
        state = load_lua_state(dump_path);
    else if (mode == START)
        state = new_lua_state(src_path);
    if (!state)
        return 1;

    if (luaL_loadstring(state, mode == START ? "_main_coro = coroutine.create(_main) return 0" : "if coroutine.status(_main_coro) == 'dead' then return 100 end coroutine.resume(_main_coro) return 0") != LUA_OK) {
        fprintf(stderr, "luaL_loadstring failed: ");
        fprint_stack_string(stderr, state, -1, "<error not a string>");
        fprintf(stderr, "\n");
        if (verbose) arena_stats();
        return 1;
    }

    if (lua_pcall(state, 0, 1, 0) != LUA_OK) {
        fprint_stack_string(stderr, state, -1, "<error not a string>");
        fprintf(stderr, "\n");
        if (verbose) arena_stats();
        return 1;
    }

    if (dump_lua_state(dump_path, state)) {
        if (verbose) arena_stats();
        return 1;
    }

    if (verbose) arena_stats();
    return lua_tonumber(state, -1);
}

static void fprint_stack_string(FILE *file, lua_State *state, int level, const char *dft)
{
    // note: messes with the value (lua_tolstring will in-place convert a number into a string)
    size_t len_str;
    const char *str = lua_tolstring(state, level, &len_str);
    if (str)
        fprintf(file, "%.*s", (int)len_str, str);
    else if (dft)
        fprintf(file, dft);
}

static void collect_args(int argc, char **argv)
{
    const char *const program_name = argv[0];
    int c;
    while ((c = getopt(argc, argv, "hvm:")) != -1) {
        char *strtol_end;
        switch (c) {
            case 'v':
            verbose = 1;
            break;
            case 'm':
            memsize = strtol(optarg, &strtol_end, 10);
            if (strtol_end == optarg) {
                fprintf(stderr, "%s: -m requires integer\n", program_name);
                exit(1);
            }
            if (memsize < 1024LL*24) {
                fprintf(stderr, "%s: memsize too small\n", program_name);
                exit(1);
            }
            break;
            case 'h':
            fprintf(stderr, "%s init [-v] [-h] [-m memsize] dumpfile srcfile - initializes an interpreter instance from the source code and saves it to a dumpfile\n", program_name);
            fprintf(stderr, "%s resume [-v] [-h] dumpfile - resumes an interpreter from an existing dump file\n", program_name);
            fprintf(stderr, "   -v          verbose mode; prints allocator info after execution\n");
            fprintf(stderr, "   -h          shows this help message\n");
            fprintf(stderr, "   -m memsize  sets the size available for the interpreter in bytes (default %llu); only valid with -s\n", DEFAULT_MEMSIZE);
            fprintf(stderr, "Note: `%s resume' signals the end of the source file execution by exiting with code 100\n", program_name);
            exit(0);
            case '?':
            exit(1);
        }
    }
    if (argv[optind] == NULL) {
        fprintf(stderr, "%s: no mode specified\n", program_name);
        exit(1);
    }
    if (strcmp(argv[optind], "init") == 0) {
        mode = START;
    } else if (strcmp(argv[optind], "resume") == 0) {
        mode = RESUME;
    } else {
        fprintf(stderr, "%s: unknown mode %s\n", program_name, argv[optind]);
        exit(1);
    }
    if (argv[optind+1] == NULL) {
        fprintf(stderr, "%s: no dumpfile specified\n", program_name);
        exit(1);
    }
    dump_path = argv[optind+1];
    if (mode == START && argv[optind+2] == NULL) {
        fprintf(stderr, "%s: no srcfile specified\n", program_name);
        exit(1);
    }
    if ((mode == RESUME && argv[optind+2] != NULL) || (mode == START && argv[optind+3] != NULL)) {
        fprintf(stderr, "%s: trailing parameters\n", program_name);
        exit(1);
    }
    if (mode == START) {
        src_path = argv[optind+2];
        if (memsize == 0) memsize = DEFAULT_MEMSIZE;
    } else {
        if (memsize != 0) {
            fprintf(stderr, "%s: -m only valid for init mode\n", program_name);
            exit(1);
        }
    }
}

static void disable_aslr(char **argv)
{
    if (personality(0xffffffffUL) & ADDR_NO_RANDOMIZE)
        return;

    char procpath[20];
    sprintf(procpath, "/proc/%d/exe", getppid());
    char *parent_path = realpath(procpath, NULL);
    if (parent_path != NULL) {
        char *self_path = realpath("/proc/self/exe", NULL);
        if (self_path == NULL || strcmp(parent_path, self_path) == 0) {
            fprintf(stderr, "failed to disable ASLR\n");
            exit(1);
        }
        free(parent_path);
        free(self_path);
    }

    int c = fork();
    if (c == 0) {
        personality(personality(0xffffffffUL) | ADDR_NO_RANDOMIZE);
        execvp(realpath("/proc/self/exe", NULL), argv);
        _exit(255);
    }
    int status;
    do {
        waitpid(c, &status, 0);
    } while (!WIFEXITED(status));
    exit(WEXITSTATUS(status));
}

static lua_State *load_lua_state(const char *path)
{
    lua_State *state;
    lua_State *(*p_lua_newstate)(lua_Alloc, void*);

    FILE *f = fopen(path, "r+b");  // we don't write to it with this handle, but this also verifies it's writable at all
    if (!f) {
        perror("couldn't open dump file");
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (arena_init(sz - sizeof(p_lua_newstate) - sizeof(void*))) {
        fclose(f);
        return NULL;
    }
    if (fread(&p_lua_newstate, sizeof(p_lua_newstate), 1, f) != 1 || fread(&state, sizeof(void*), 1, f) != 1 || fread(alloc_arena, 1, arena_memsize, f) != arena_memsize) {
        fprintf(stderr, "memory dump is corrupted\n");
        fclose(f);
        return NULL;
    }
    fclose(f);
    if (p_lua_newstate != lua_newstate) {
        fprintf(stderr, "dynamic linker placed Lua at the incorrect location (expected &lua_newstate = %p, but it's %p)\n", (void*)p_lua_newstate, (void*)lua_newstate);
        return NULL;
    }
    arena_recalc_usage();
    return state;
}

static void *allocator(void *ud, void *ptr, size_t osize, size_t nsize)
{
    (void)ud; (void)osize;
    if (nsize != 0)
        return arena_realloc(ptr, nsize);
    arena_free(ptr);
    return NULL;
}

static lua_State *new_lua_state(const char *srcpath)
{
    if (arena_init(memsize))
        return NULL;
    lua_State *state = lua_newstate(allocator, NULL);
    if (!state) {
        fprintf(stderr, "lua_newstate failed\n");
        return NULL;
    }
    luaL_requiref(state, "base", luaopen_base, 1);
    lua_pop(state, 1);
    luaL_requiref(state, "string", luaopen_string, 1);
    lua_pop(state, 1);
    luaL_requiref(state, "utf8", luaopen_utf8, 1);
    lua_pop(state, 1);
    luaL_requiref(state, "table", luaopen_table, 1);
    lua_pop(state, 1);
    luaL_requiref(state, "coroutine", luaopen_coroutine, 1);
    lua_pop(state, 1);

    // Load & compile source code file
    FILE *f = fopen(srcpath, "r+b");
    if (!f) {
        perror("couldn't open source file");
        lua_close(state);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *srccode = malloc(sz + 1);
    if (!srccode) {
        fprintf(stderr, "out of memory while loading source file");
        fclose(f);
        lua_close(state);
        return NULL;
    }
    if (fread(srccode, 1, sz, f) != sz) {
        perror("error reading source file");
        fclose(f);
        lua_close(state);
        return NULL;
    }
    fclose(f);
    srccode[sz] = 0;
    if (luaL_loadstring(state, srccode) != LUA_OK) {
        fprintf(stderr, "luaL_loadstring failed: ");
        fprint_stack_string(stderr, state, -1, "<error not a string>");
        fprintf(stderr, "\n");
        lua_close(state);
        return NULL;
    }
    lua_setglobal(state, "_main");
    return state;
}

static int dump_lua_state(const char *path, lua_State *state)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        perror("freopen failed");
        return 1;
    }
    lua_State *(*p_lua_newstate)(lua_Alloc, void*) = lua_newstate;
    if (fwrite(&p_lua_newstate, sizeof(p_lua_newstate), 1, f) != 1 ||
        fwrite(&state, sizeof(void*), 1, f) != 1 ||
        fwrite(alloc_arena, 1, arena_memsize, f) != arena_memsize
       ) {
        fprintf(stderr, "failed to write memory dump\n");
        fclose(f);
        return 1;
    }
    return 0;
}
