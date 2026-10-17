/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <luajit.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <limits.h>

#ifdef FLB_HAVE_SANITIZE_ADDRESS
#include <sanitizer/asan_interface.h>
#endif

#include "fts.h"

/*
 * LuaJIT raises errors by resetting the C stack pointer instead of calling
 * longjmp(), so AddressSanitizer never sees the frames it skips and keeps
 * their redzones poisoned. Later calls reusing that stack report bogus
 * errors. After a failed protected call, clear the shadow of the stack below
 * the current frame, which only holds those dead frames; the window covers
 * nested C and Lua calls up to LuaJIT's C call limit. Builds without the
 * sanitizer compile this to nothing.
 */
#define FTS_UNWOUND_STACK_SIZE (256 * 1024)

#ifdef FLB_HAVE_SANITIZE_ADDRESS
__attribute__((noinline))
#endif
void fts_sanitizer_forget_unwound_frames(void)
{
#ifdef FLB_HAVE_SANITIZE_ADDRESS
    char *top;

    top = (char *) __builtin_frame_address(0);
    __asan_unpoison_memory_region(top - FTS_UNWOUND_STACK_SIZE, FTS_UNWOUND_STACK_SIZE);
#endif
}

/* A policy cannot catch budget exhaustion and continue an endless loop. */
static int policy_pcall(lua_State *l)
{
    struct fts_runtime *ctx;
    void *data;
    int ret;

    luaL_checktype(l, 1, LUA_TFUNCTION);
    ret = lua_pcall(l, lua_gettop(l) - 1, LUA_MULTRET, 0);
    if (ret != 0) {
        fts_sanitizer_forget_unwound_frames();
    }

    lua_getallocf(l, &data);
    ctx = data;
    if (!ctx->jit && ctx->instructions_left <= 0) {
        return luaL_error(l, "Lua instruction limit exceeded");
    }

    lua_pushboolean(l, ret == 0);
    lua_insert(l, 1);
    return lua_gettop(l);
}

/* Enforce the count budget in interpreted Lua, including script initialization. */
static void budget_hook(lua_State *l, lua_Debug *ar)
{
    struct fts_runtime *ctx;
    void *data;

    lua_getallocf(l, &data);
    ctx = data;
    ctx->instructions_left -= 1000;

    if (!ctx->jit && ctx->instructions_left <= 0) {
        luaL_error(l, "Lua instruction limit exceeded");
    }
}

static void *bounded_allocator(void *data, void *ptr, size_t old_size, size_t new_size)
{
    struct fts_runtime *ctx = data;
    void *result;
    size_t used;

    if (!ptr) {
        old_size = 0;
    }

    if (ctx->lua_bytes >= old_size) {
        used = ctx->lua_bytes - old_size;
    }
    else {
        used = 0;
    }

    if (new_size > old_size &&
        (new_size > ctx->memory_limit || ctx->native_bytes > ctx->memory_limit - new_size ||
         used > ctx->memory_limit - ctx->native_bytes - new_size)) {
        return NULL;
    }

    result = ctx->original_allocator(ctx->allocator_data, ptr, old_size, new_size);
    if (result || new_size == 0) {
        ctx->lua_bytes = used + new_size;
    }

    return result;
}

static int policy_collectgarbage(lua_State *l)
{
    const char *option;
    int arguments;

    option = luaL_optstring(l, 1, "collect");
    if (strcmp(option, "collect") != 0 && strcmp(option, "count") != 0 &&
        strcmp(option, "step") != 0) {
        return luaL_error(l, "FTS collectgarbage supports collect, count and step only");
    }

    arguments = lua_gettop(l);
    lua_pushvalue(l, lua_upvalueindex(1));
    lua_insert(l, 1);
    lua_call(l, arguments, LUA_MULTRET);
    return lua_gettop(l);
}

static int restricted_require(lua_State *l)
{
    const char *name;
    size_t length;

    name = luaL_checklstring(l, 1, &length);
    if (length != sizeof("fluentbit") - 1 || memcmp(name, "fluentbit", length) != 0) {
        return luaL_error(l, "only the fluentbit module is available in FTS policies");
    }

    lua_pushvalue(l, lua_upvalueindex(1));
    return 1;
}

void fts_runtime_destroy(struct fts_runtime *ctx)
{
    fts_undo_commit(ctx);
    flb_free(ctx->undo);
    ctx->undo = NULL;
    ctx->undo_size = 0;

    if (ctx->vm) {
        flb_luajit_destroy(ctx->vm);
        ctx->vm = NULL;
    }
}

/*
 * Helper code has a private copy of the standard environment. Policies cannot
 * replace validation primitives or discover this environment through getfenv().
 */
static void copy_table(lua_State *l, int index)
{
    int source;
    int target;

    if (index < 0 && index > LUA_REGISTRYINDEX) {
        source = lua_gettop(l) + index + 1;
    }
    else {
        source = index;
    }

    lua_newtable(l);
    target = lua_gettop(l);

    lua_pushnil(l);
    while (lua_next(l, source)) {
        lua_pushvalue(l, -2);
        lua_pushvalue(l, -2);
        lua_rawset(l, target);
        lua_pop(l, 1);
    }
}

int fts_load_helpers(lua_State *l, const char *code, size_t size, const char *name)
{
    struct fts_runtime *ctx;
    void *data;

    lua_getallocf(l, &data);
    ctx = data;

    if (luaL_loadbuffer(l, code, size, name) != 0) {
        return -1;
    }

    lua_rawgeti(l, LUA_REGISTRYINDEX, ctx->helpers_env_ref);
    lua_setfenv(l, -2);
    if (lua_pcall(l, 0, 0, 0) != 0) {
        fts_sanitizer_forget_unwound_frames();
        return -1;
    }
    return 0;
}

static int initialize_policy(lua_State *l)
{
    struct fts_runtime *ctx;
    const char *blocked[] = {"io", "os", "debug", "jit", "ffi", "package", "coroutine",
                            "module", "load", "loadfile", "loadstring", "dofile",
                            "newproxy", "xpcall", "getfenv", "setfenv", "print", NULL};
    int i;
    int ret;
    int environment;

    ctx = lua_touserdata(l, 1);
    copy_table(l, LUA_GLOBALSINDEX);
    environment = lua_gettop(l);

    /* tables used by validation must also be independent of policy globals */
    lua_getglobal(l, "math");
    copy_table(l, -1);
    lua_setfield(l, environment, "math");
    lua_pop(l, 1);

    lua_getglobal(l, "string");
    copy_table(l, -1);
    lua_setglobal(l, "string");
    lua_pop(l, 1);

    lua_getglobal(l, "table");
    copy_table(l, -1);
    lua_setfield(l, environment, "table");
    lua_pop(l, 1);

    lua_pushliteral(l, "");
    lua_getmetatable(l, -1);
    lua_pushliteral(l, "string");
    lua_setfield(l, -2, "__metatable");
    lua_pop(l, 2);

    ctx->helpers_env_ref = luaL_ref(l, LUA_REGISTRYINDEX);

    if (fts_register_values(l) != 0) {
        return luaL_error(l, "cannot register fluentbit module");
    }

    if (ctx->adapter->register_helpers(l) != 0) {
        return luaL_error(l, "cannot register FTS signal helpers");
    }

    lua_getglobal(l, "package");
    lua_getfield(l, -1, "loaded");
    lua_getfield(l, -1, "fluentbit");
    lua_pushvalue(l, -1);
    ctx->module_ref = luaL_ref(l, LUA_REGISTRYINDEX);

    /* public helper overrides do not affect the private adapter module */
    copy_table(l, -1);
    lua_pushcclosure(l, restricted_require, 1);
    lua_setglobal(l, "require");

    /* removing globals alone leaves Lua 5.1 module() able to recover loaded libraries */
    for (i = 0; blocked[i]; i++) {
        lua_pushnil(l);
        lua_setfield(l, -2, blocked[i]);
    }
    lua_pop(l, 3);

    for (i = 0; blocked[i]; i++) {
        lua_pushnil(l);
        lua_setglobal(l, blocked[i]);
    }

    lua_pushcfunction(l, policy_pcall);
    lua_setglobal(l, "pcall");

    lua_getglobal(l, "collectgarbage");
    lua_pushcclosure(l, policy_collectgarbage, 1);
    lua_setglobal(l, "collectgarbage");

    if (ctx->code) {
        ret = flb_luajit_load_buffer(ctx->vm, ctx->code, strlen(ctx->code), "fts_policy");
    }
    else {
        ret = flb_luajit_load_script(ctx->vm, ctx->script);
    }

    if (ret != 0) {
        return lua_error(l);
    }

    lua_call(l, 0, 0);

    lua_getglobal(l, ctx->call);
    if (!lua_isfunction(l, -1)) {
        return luaL_error(l, "FTS callback function not found");
    }
    ctx->policy_ref = luaL_ref(l, LUA_REGISTRYINDEX);

    /* field-name strings are callback upvalues, see fts_getfield() */
    for (i = 0; i < FTS_KEY_COUNT; i++) {
        lua_rawgeti(l, LUA_REGISTRYINDEX, ctx->key_refs[i]);
    }
    lua_pushcclosure(l, ctx->adapter->run_callback, FTS_KEY_COUNT);
    ctx->callback_ref = luaL_ref(l, LUA_REGISTRYINDEX);

    if (!lua_checkstack(l, 32)) {
        return luaL_error(l, "cannot reserve policy stack");
    }

    return 0;
}

int fts_runtime_initialize(struct fts_runtime *ctx, struct flb_config *config)
{
    lua_State *l;
    int ret;

    ctx->vm = flb_luajit_create(config);
    if (!ctx->vm) {
        return FLB_PROCESSOR_FAILURE;
    }
    l = ctx->vm->state;

    ret = luaJIT_setmode(l, 0, LUAJIT_MODE_ENGINE | (ctx->jit ? LUAJIT_MODE_ON : LUAJIT_MODE_OFF));
    if (ctx->jit && !ret) {
        lua_pushliteral(l, "JIT is unavailable in this LuaJIT build");
        return FLB_PROCESSOR_FAILURE;
    }

    ctx->original_allocator = lua_getallocf(l, &ctx->allocator_data);
    ctx->lua_bytes = (size_t) lua_gc(l, LUA_GCCOUNT, 0) * 1024 + lua_gc(l, LUA_GCCOUNTB, 0);
    lua_setallocf(l, bounded_allocator, ctx);

    ctx->instructions_left = ctx->instruction_limit;
    if (!ctx->jit) {
        lua_sethook(l, budget_hook, LUA_MASKCOUNT, 1000);
    }

    lua_pushcfunction(l, initialize_policy);
    lua_pushlightuserdata(l, ctx);
    ret = lua_pcall(l, 1, 0, 0);
    if (ret != 0) {
        fts_sanitizer_forget_unwound_frames();
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}

/*
 * Native values are invisible to the Lua allocator, so the collector is paced
 * explicitly: each chunk performs incremental work proportional to the native
 * bytes it charged. A full collection only runs on emergency or when close to
 * the memory limit, avoiding a full cycle per chunk or error.
 */
void fts_collect(struct fts_runtime *ctx, int emergency)
{
    lua_State *l = ctx->vm->state;
    size_t used = ctx->native_bytes + ctx->lua_bytes;
    size_t allocated;

    allocated = ctx->native_allocated;
    ctx->native_allocated = 0;

    if (emergency || used > ctx->memory_limit - ctx->memory_limit / 4) {
        lua_gc(l, LUA_GCCOLLECT, 0);
    }
    else if (allocated > 0) {
        lua_gc(l, LUA_GCSTEP, (int) (allocated / 1024 < INT_MAX ? allocated / 1024 + 1 : INT_MAX));
    }
    else if (used > ctx->memory_limit / 2) {
        lua_gc(l, LUA_GCSTEP, 64);
    }
}

/* adapters supply their own snapshot and result contract inside the protected call */
int fts_runtime_call(struct fts_runtime *ctx, void *data, int results)
{
    lua_State *l;
    int ret;
    int base;

    l = ctx->vm->state;
    base = lua_gettop(l);
    ctx->instructions_left = ctx->instruction_limit;

    lua_rawgeti(l, LUA_REGISTRYINDEX, ctx->callback_ref);
    lua_pushlightuserdata(l, data);
    ret = lua_pcall(l, 1, results, 0);
    if (ret != 0) {
        fts_sanitizer_forget_unwound_frames();
    }
    if (ret == 0 && !ctx->jit && ctx->instructions_left <= 0) {
        lua_settop(l, base);
        lua_pushliteral(l, "Lua instruction limit exceeded");
        ret = LUA_ERRRUN;
    }

    if (ret != 0) {
        /* unwound snapshots and garbage must not poison subsequent callbacks */
        fts_collect(ctx, ret == LUA_ERRMEM);
        if (!lua_gc(l, LUA_GCISRUNNING, 0)) {
            lua_gc(l, LUA_GCRESTART, -1);
        }
    }

    return ret;
}

void fts_report_policy_error(struct flb_processor_instance *ins)
{
    struct fts_runtime *ctx;
    struct flb_processor *processor;
    struct flb_input_instance *input;
    struct flb_output_instance *output;
    char stage[32];
    char *labels[5];

    if (!ins->pu || !ins->pu->parent) {
        return;
    }

    processor = ins->pu->parent;
    if (!processor->cmt_errors) {
        return;
    }

    labels[0] = "unknown";
    labels[1] = "unknown";
    if (processor->source_plugin_type == FLB_PLUGIN_INPUT && processor->data) {
        input = processor->data;
        labels[0] = "input";
        labels[1] = (char *) flb_input_name(input);
    }
    else if (processor->source_plugin_type == FLB_PLUGIN_OUTPUT && processor->data) {
        output = processor->data;
        labels[0] = "output";
        labels[1] = (char *) flb_output_name(output);
    }

    snprintf(stage, sizeof(stage), "%zu", ins->pu->stage);
    labels[2] = ins->pu->name;
    labels[3] = stage;

    ctx = ins->context;
    if (ctx->adapter->event_type == FLB_PROCESSOR_METRICS) {
        labels[4] = "metrics";
    }
    else if (ctx->adapter->event_type == FLB_PROCESSOR_TRACES) {
        labels[4] = "traces";
    }
    else {
        labels[4] = "logs";
    }

    cmt_counter_inc(processor->cmt_errors, cfl_time_now(), 5, labels);
}

