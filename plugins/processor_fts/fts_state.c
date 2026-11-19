/* Fluent Bit: bounded local decision state, Apache-2.0. */
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_random.h>
#include <cfl/cfl_hash.h>
#ifdef FLB_SYSTEM_WINDOWS
#include <windows.h>
#endif
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include "fts.h"
#include "fts_state.h"

struct fts_state_entry {
    struct fts_state_entry *next;
    struct fts_state_entry *original;
    struct fts_state_value value;
    uint64_t hash;
    size_t length;
    char key[];
};

static uint64_t monotonic_now(void *data)
{
#ifndef FLB_SYSTEM_WINDOWS
    struct timespec ts;
#endif

    (void) data;
#ifdef FLB_SYSTEM_WINDOWS
    return GetTickCount64() * UINT64_C(1000000);
#else
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t) ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
#endif
}

size_t fts_state_base_cost(size_t max_keys)
{
    size_t buckets = 1;

    if (max_keys == 0 || max_keys > 65536) {
        return 0;
    }
    while (buckets < max_keys) {
        buckets *= 2;
    }
    return sizeof(struct fts_state) + 2 * buckets * sizeof(struct fts_state_entry *);
}

static uint64_t add_time(uint64_t now, uint64_t duration)
{
    return now > UINT64_MAX - duration ? UINT64_MAX : now + duration;
}

static void release_entry(struct fts_state *state, struct fts_state_entry *entry)
{
    state->bytes -= sizeof(*entry) + entry->length;
    flb_free(entry);
}

struct fts_state *fts_state_create(int kind, uint64_t ttl_ms, uint64_t rate,
                                  uint64_t burst, size_t max_keys, size_t max_key_bytes,
                                  size_t limit)
{
    struct fts_state *state;
    size_t base_cost;

    base_cost = fts_state_base_cost(max_keys);
    if ((kind != FTS_STATE_DEDUPE && kind != FTS_STATE_THROTTLE) ||
        ttl_ms == 0 || ttl_ms > UINT64_C(86400000) ||
        max_keys == 0 || max_keys > 65536 || max_key_bytes == 0 || max_key_bytes > 65536 ||
        !base_cost || limit < base_cost ||
        (kind == FTS_STATE_THROTTLE && (rate == 0 || rate > 1000000 ||
         burst == 0 || burst > 1000000 || ttl_ms * rate < burst * 1000))) {
        return NULL;
    }
    state = flb_calloc(1, base_cost);
    if (!state) {
        return NULL;
    }
    if (flb_random_bytes((unsigned char *) &state->hash_seed, sizeof(state->hash_seed)) != 0) {
        flb_free(state);
        return NULL;
    }
    state->base = (struct fts_state_entry **) (state + 1);
    state->bucket_count = (base_cost - sizeof(*state)) / (2 * sizeof(*state->base));
    state->overlay = state->base + state->bucket_count;
    state->bytes = base_cost;
    state->kind = kind;
    state->ttl_ns = ttl_ms * UINT64_C(1000000);
    state->rate = rate;
    state->burst = burst;
    state->max_keys = max_keys;
    state->max_key_bytes = max_key_bytes;
    state->limit = limit;
    state->clock = monotonic_now;
    return state;
}

void fts_state_finish(struct fts_state *state, int commit)
{
    struct fts_state_entry *entry;
    struct fts_state_entry *next;
    size_t i;

    if (!state || !state->active) {
        return;
    }
    for (i = 0; i < state->bucket_count; i++) {
        for (entry = state->overlay[i]; entry; entry = next) {
            next = entry->next;
            if (commit && !entry->original) {
                entry->next = state->base[i];
                state->base[i] = entry;
                state->keys++;
            }
            else {
                if (commit) {
                    entry->original->value = entry->value;
                }
                release_entry(state, entry);
            }
        }
        state->overlay[i] = NULL;
    }
    if (commit) {
        state->total_overflow += state->overflow;
        state->total_dropped += state->dropped;
    }
    if (commit && state->changed) {
        state->commits++;
    }
    if (!commit) {
        state->overflow = 0;
        state->dropped = 0;
    }
    state->proposed_keys = 0;
    state->save_entry = NULL;
    state->active = 0;
}

void fts_state_destroy(struct fts_state *state)
{
    struct fts_state_entry *entry;
    struct fts_state_entry *next;
    size_t i;

    if (!state) {
        return;
    }
    fts_state_finish(state, 0);
    for (i = 0; i < state->bucket_count; i++) {
        for (entry = state->base[i]; entry; entry = next) {
            next = entry->next;
            release_entry(state, entry);
        }
    }
    flb_free(state);
}

void fts_state_begin(struct fts_state *state)
{
    struct fts_state_entry **cursor;
    struct fts_state_entry *entry;
    uint64_t now;
    size_t i;

    if (!state) {
        return;
    }
    fts_state_finish(state, 0);
    now = state->clock(state->clock_data);
    if (now > state->now) {
        state->now = now;
    }
    state->changed = 0;
    state->overflow = 0;
    state->dropped = 0;
    /* Expiration is maintenance, independent of admission rollback. */
    for (i = 0; i < state->bucket_count; i++) {
        cursor = &state->base[i];
        while ((entry = *cursor)) {
            if (entry->value.expires <= state->now) {
                *cursor = entry->next;
                release_entry(state, entry);
                state->keys--;
                state->expirations++;
            }
            else {
                cursor = &entry->next;
            }
        }
    }
    state->active = 1;
}

void fts_state_savepoint(struct fts_state *state)
{
    if (!state) {
        return;
    }
    state->save_entry = NULL;
    state->save_new = 0;
    state->save_changed = state->changed;
    state->save_overflow = state->overflow;
    state->save_dropped = state->dropped;
}

void fts_state_rollback_item(struct fts_state *state)
{
    struct fts_state_entry *entry;
    struct fts_state_entry **cursor;

    if (!state) {
        return;
    }
    entry = state->save_entry;
    if (entry && state->save_new) {
        cursor = &state->overlay[entry->hash % state->bucket_count];
        while (*cursor != entry) {
            cursor = &(*cursor)->next;
        }
        *cursor = entry->next;
        if (!entry->original) {
            state->proposed_keys--;
        }
        release_entry(state, entry);
    }
    else if (entry) {
        entry->value = state->save_value;
    }
    state->changed = state->save_changed;
    state->overflow = state->save_overflow;
    state->dropped = state->save_dropped;
    state->save_entry = NULL;
}

static struct fts_state_entry *lookup(struct fts_state_entry *entry, const char *key,
                                       size_t length, uint64_t hash, int *work)
{
    while (entry) {
        if (*work < 1) {
            return NULL;
        }
        (*work)--;
        if (entry->hash == hash && entry->length == length) {
            if (length / 8 >= (size_t) *work) {
                *work = 0;
                return NULL;
            }
            *work -= (int) (length / 8) + 1;
            if (memcmp(entry->key, key, length) == 0) {
                return entry;
            }
        }
        entry = entry->next;
    }
    return NULL;
}

int fts_state_decide(struct fts_state *state, const char *key, size_t length, int *work)
{
    struct fts_state_entry *entry;
    struct fts_state_entry *original;
    uint64_t hash;
    uint64_t elapsed;
    uint64_t refill;
    uint64_t capacity;
    size_t cost;
    size_t bucket;
    int dropped = 0;

    if (!state || !state->active || state->save_entry || !work || (!key && length)) {
        return FTS_STATE_ERROR;
    }
    if (length > state->max_key_bytes) {
        state->overflow++;
        return FTS_STATE_OVERFLOW;
    }
    if (*work < 1 || length / 8 >= (size_t) *work) {
        *work = 0;
        return FTS_STATE_BUDGET;
    }
    *work -= (int) (length / 8) + 1;
    hash = XXH3_64bits_withSeed(key, length, state->hash_seed);
    bucket = hash % state->bucket_count;
    entry = lookup(state->overlay[bucket], key, length, hash, work);
    if (*work < 1) {
        return FTS_STATE_BUDGET;
    }
    if (!entry) {
        original = lookup(state->base[bucket], key, length, hash, work);
        if (*work < 1) {
            return FTS_STATE_BUDGET;
        }
        cost = sizeof(*entry) + length;
        if ((!original && state->keys + state->proposed_keys >= state->max_keys) ||
            cost > state->limit - state->bytes) {
            state->overflow++;
            return FTS_STATE_OVERFLOW;
        }
        entry = flb_calloc(1, cost);
        if (!entry) {
            return -1;
        }
        state->bytes += cost;
        entry->original = original;
        entry->hash = hash;
        entry->length = length;
        memcpy(entry->key, key, length);
        if (original) {
            entry->value = original->value;
        }
        else {
            state->proposed_keys++;
        }
        entry->next = state->overlay[bucket];
        state->overlay[bucket] = entry;
        state->save_new = 1;
    }
    state->save_entry = entry;
    state->save_value = entry->value;
    if (state->kind == FTS_STATE_DEDUPE) {
        dropped = entry->value.expires > state->now;
        if (!dropped) {
            entry->value.expires = add_time(state->now, state->ttl_ns);
        }
        /* Duplicates do not extend the first admission's TTL. */
    }
    else {
        capacity = state->burst * UINT64_C(1000000000);
        if (entry->value.expires == 0) {
            entry->value.credits = capacity;
            entry->value.updated = state->now;
        }
        elapsed = state->now - entry->value.updated;
        refill = elapsed >= capacity / state->rate + 1 ? capacity : elapsed * state->rate;
        if (refill >= capacity - entry->value.credits) {
            entry->value.credits = capacity;
        }
        else {
            entry->value.credits += refill;
        }
        dropped = entry->value.credits < UINT64_C(1000000000);
        if (!dropped) {
            entry->value.credits -= UINT64_C(1000000000);
        }
        entry->value.updated = state->now;
        entry->value.expires = add_time(state->now, state->ttl_ns);
    }
    state->changed = 1;
    state->dropped += dropped;
    return dropped ? FTS_STATE_DROP : FTS_STATE_KEEP;
}

static int configure(lua_State *l)
{
    struct fts_runtime *ctx = lua_touserdata(l, lua_upvalueindex(1));

    if (ctx->state || ctx->window || !ctx->state_input || !ctx->state_commit || strcmp(ctx->state_commit, "local") != 0) {
        return luaL_error(l, "invalid_configuration");
    }
    if (ctx->state_limit < fts_state_base_cost((size_t) luaL_checknumber(l, 5))) {
        strcpy(ctx->recipe_parameter, "state_limit");
        strcpy(ctx->recipe_reason, "range");
        return luaL_error(l, "invalid_parameter");
    }
    ctx->state = fts_state_create((int) luaL_checkinteger(l, 1),
        (uint64_t) luaL_checknumber(l, 2), (uint64_t) luaL_checknumber(l, 3),
        (uint64_t) luaL_checknumber(l, 4), (size_t) luaL_checknumber(l, 5),
        (size_t) luaL_checknumber(l, 6), ctx->state_limit);
    if (!ctx->state) {
        return luaL_error(l, "invalid_configuration");
    }
    return 0;
}

static int decide(lua_State *l)
{
    struct fts_runtime *ctx = lua_touserdata(l, lua_upvalueindex(1));
    const char *key;
    size_t length;
    int result;

    key = luaL_checklstring(l, 1, &length);
    result = fts_state_decide(ctx->state, key, length, &ctx->instructions_left);
    if (result < 0) {
        return luaL_error(l, result == FTS_STATE_BUDGET ? "budget_exceeded" : "operation_failed");
    }
    lua_pushboolean(l, result == FTS_STATE_DROP);
    return 1;
}

int fts_state_register(struct fts_runtime *ctx)
{
    lua_State *l = ctx->vm->state;

    lua_pushlightuserdata(l, ctx);
    lua_pushcclosure(l, configure, 1);
    lua_setfield(l, -2, "_recipe_state_configure");
    lua_pushlightuserdata(l, ctx);
    lua_pushcclosure(l, decide, 1);
    lua_setfield(l, -2, "_recipe_state_decide");
    return 0;
}

static struct cmt_counter *state_counter(struct cmt *metrics, const char *name, const char *description)
{
    struct cfl_list *head;
    struct cmt_counter *counter;
    char *labels[] = {"name", "scope", "processor", "stage", "signal", "outcome"};

    cfl_list_foreach(head, &metrics->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        if (counter->opts.ns && counter->opts.subsystem && counter->opts.name &&
            strcmp(counter->opts.ns, "fluentbit") == 0 &&
            strcmp(counter->opts.subsystem, "fts") == 0 && strcmp(counter->opts.name, name) == 0) {
            return counter;
        }
    }
    return cmt_counter_create(metrics, "fluentbit", "fts", (char *) name, (char *) description, 6, labels);
}

int fts_state_metrics_initialize(struct fts_runtime *ctx, void *data)
{
    struct cmt *metrics = data;
    struct cfl_list *head;
    struct cmt_gauge *gauge;
    char *labels[] = {"name", "scope", "processor", "stage", "signal", "outcome"};

    if (!ctx->state) {
        return 0;
    }
    cfl_list_foreach(head, &metrics->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        if (strcmp(gauge->opts.fqname, "fluentbit_fts_state_keys") == 0) {
            ctx->state_keys = gauge;
            break;
        }
    }
    if (!ctx->state_keys) {
        ctx->state_keys = cmt_gauge_create(metrics, "fluentbit", "fts", "state_keys",
                                         "Committed local state keys.", 6, labels);
    }
    ctx->state_evictions = state_counter(metrics, "evictions_total", "Expired state keys; no capacity eviction.");
    ctx->state_overflow = state_counter(metrics, "overflow_untracked_total",
                                        "Committed untracked admissions at capacity.");
    ctx->state_commits = state_counter(metrics, "local_state_commits_total",
                                       "Local batch commits; not delivery acknowledgments.");
    ctx->state_dropped = state_counter(metrics, "dropped_by_policy_total", "Committed stateful suppression decisions.");
    if (!ctx->state_keys || !ctx->state_evictions || !ctx->state_overflow ||
        !ctx->state_commits || !ctx->state_dropped) {
        return -1;
    }
    fts_state_metrics_update(ctx);
    return 0;
}

void fts_state_metrics_update(struct fts_runtime *ctx)
{
    char *labels[6];
    uint64_t timestamp;
    struct fts_state *state = ctx->state;

    if (!state || !ctx->state_keys || !ctx->state_evictions || !ctx->state_overflow ||
        !ctx->state_commits || !ctx->state_dropped) {
        return;
    }
    timestamp = cfl_time_now();
    labels[0] = ctx->recipe_owner;
    labels[1] = ctx->recipe_scope;
    labels[2] = ctx->recipe_processor;
    labels[3] = ctx->recipe_stage;
    labels[4] = "logs";
    labels[5] = "current";
    cmt_gauge_set(ctx->state_keys, timestamp, state->keys, 6, labels);
    labels[5] = "expired";
    cmt_counter_set(ctx->state_evictions, timestamp, state->expirations, 6, labels);
    labels[5] = "keep";
    cmt_counter_set(ctx->state_overflow, timestamp, state->total_overflow, 6, labels);
    labels[5] = "local";
    cmt_counter_set(ctx->state_commits, timestamp, state->commits, 6, labels);
    labels[5] = "drop";
    cmt_counter_set(ctx->state_dropped, timestamp, state->total_dropped, 6, labels);
}
