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

#ifndef FLB_PROCESSOR_FTS_H
#define FLB_PROCESSOR_FTS_H

#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_luajit.h>
#include <cfl/cfl_variant.h>

#define FTS_MAX_DEPTH 64

/* Each signal owns its representation, validation and commit semantics. */
struct fts_signal_adapter {
    int event_type;
    int (*register_helpers)(lua_State *l);
    lua_CFunction run_callback;
};

enum fts_key {
    FTS_KEY_TAG, FTS_KEY_BODY, FTS_KEY_METADATA, FTS_KEY_TIMESTAMP,
    FTS_KEY_SEC, FTS_KEY_NSEC, FTS_KEY_CONTEXT, FTS_KEY_ATTRIBUTES,
    FTS_KEY_COUNT
};

struct fts_runtime;

/* Reversible in-place edits of chunk-owned log values. */
struct fts_undo_entry {
    int type;
    struct cfl_list *list;
    struct cfl_kvpair *pair;
    struct cfl_list *prev;
    struct cfl_array *array;
    size_t index;
    struct cfl_variant *old;
};

struct fts_value {
    struct cfl_variant *owned;
    unsigned int readonly : 1;
    unsigned int dirty : 1;
    unsigned int depth_changed : 1;
    unsigned int borrowed : 1;
    unsigned int record : 1;
    unsigned int inplace : 1;
    struct fts_runtime *ctx;
    uint64_t generation;
    size_t charged;

    /*
     * Views: owning root and the node resolved at the root's last epoch.
     * Roots: epoch advances on every write, invalidating view caches.
     */
    struct fts_value *root;
    struct cfl_variant *cache;
    uint64_t epoch;
};

struct fts_runtime {
    struct flb_luajit *vm;
    char *script;
    char *code;
    char *call;
    char *error_mode;
    const struct fts_signal_adapter *adapter;
    const void *value_metatable;
    int value_metatable_ref;
    const void *empty_metatable;
    int empty_metatable_ref;
    int key_refs[FTS_KEY_COUNT];
    int tag_ref;
    uint64_t generation;
    struct fts_undo_entry *undo;
    size_t undo_count;
    size_t undo_size;
    size_t undo_held;
    size_t undo_charged;
    int inplace_ok;
    int tag_ready;
    int callback_ref;
    int policy_ref;
    int module_ref;
    int helpers_env_ref;
    int jit;
    int instruction_limit;
    int instructions_left;
    size_t memory_limit;
    size_t lua_bytes;
    size_t native_bytes;
    size_t native_allocated;    /* native bytes charged since the last GC pacing */
    size_t output_limit;
    lua_Alloc original_allocator;
    void *allocator_data;
};

extern const struct fts_signal_adapter fts_logs_adapter;

/* runtime: Lua VM lifecycle, policy calls and error reporting */
int fts_runtime_initialize(struct fts_runtime *ctx, struct flb_config *config);
void fts_runtime_destroy(struct fts_runtime *ctx);
void fts_report_policy_error(struct flb_processor_instance *ins);
void fts_sanitizer_forget_unwound_frames(void);
int fts_runtime_call(struct fts_runtime *ctx, void *data, int results);
int fts_register_values(lua_State *l);
void fts_collect(struct fts_runtime *ctx, int emergency);

/* cached field-name keys */
void fts_getfield(lua_State *l, int index, enum fts_key key);
void fts_setfield(lua_State *l, int index, enum fts_key key);

/* Lua values backed by msgpack or cfl_variant data */
struct fts_value *fts_push_empty_map(lua_State *l);
struct fts_value *fts_push_borrowed(lua_State *l, struct cfl_variant *source);

/* undo log for in-place edits */
void fts_undo_rollback(struct fts_runtime *ctx, size_t mark);
void fts_undo_commit(struct fts_runtime *ctx);

/* helpers and value utilities */
int fts_load_helpers(lua_State *l, const char *code, size_t size, const char *name);
int fts_values_equal(struct cfl_variant *a, struct cfl_variant *b, int depth);
int fts_valid_utf8(const char *text, size_t length);
struct cfl_variant *fts_copy_value(struct cfl_variant *value, int depth);
struct cfl_variant *fts_copy_value_in(struct cfl_variant *value, int depth,
                                      struct cfl_arena *arena);
size_t fts_value_cost(struct cfl_variant *value, int depth);
void fts_charge_value(lua_State *l, struct fts_value *owner, size_t bytes);
struct cfl_kvpair *fts_find_pair(struct cfl_variant *value, const char *key, size_t length);
struct cfl_variant *fts_resolve_value(lua_State *l, int index, int depth);
struct fts_value *fts_push_owned(lua_State *l, struct cfl_variant *value, int readonly);

/* logs signal */

int fts_process_logs(struct flb_processor_instance *ins, void *data,
                     const char *tag, int tag_len);

#endif
