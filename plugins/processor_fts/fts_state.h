/* Fluent Bit: bounded local decision state, Apache-2.0. */
#ifndef FLB_FTS_STATE_H
#define FLB_FTS_STATE_H

#include <stdint.h>
#include <stddef.h>

#define FTS_STATE_DEDUPE 1
#define FTS_STATE_THROTTLE 2
#define FTS_STATE_KEEP 0
#define FTS_STATE_DROP 1
#define FTS_STATE_OVERFLOW 2
#define FTS_STATE_ERROR -1
#define FTS_STATE_BUDGET -2

struct fts_runtime;
struct fts_state_entry;
struct fts_state_value {
    uint64_t expires;
    uint64_t updated;
    uint64_t credits;
};
struct fts_state {
    struct fts_state_entry **base;
    struct fts_state_entry **overlay;
    size_t bucket_count;
    uint64_t hash_seed;
    size_t keys;
    size_t proposed_keys;
    size_t bytes;
    size_t limit;
    size_t max_keys;
    size_t max_key_bytes;
    int kind;
    uint64_t ttl_ns;
    uint64_t rate;
    uint64_t burst;
    uint64_t now;
    uint64_t (*clock)(void *);
    void *clock_data;
    int active;
    int changed;
    struct fts_state_entry *save_entry;
    struct fts_state_value save_value;
    int save_new;
    int save_changed;
    uint64_t overflow;
    uint64_t dropped;
    uint64_t save_overflow;
    uint64_t save_dropped;
    uint64_t total_overflow;
    uint64_t total_dropped;
    uint64_t expirations;
    uint64_t commits;
};

size_t fts_state_base_cost(size_t max_keys);
struct fts_state *fts_state_create(int kind, uint64_t ttl_ms, uint64_t rate,
                                  uint64_t burst, size_t max_keys, size_t max_key_bytes,
                                  size_t limit);
void fts_state_destroy(struct fts_state *state);
void fts_state_begin(struct fts_state *state);
void fts_state_savepoint(struct fts_state *state);
void fts_state_rollback_item(struct fts_state *state);
int fts_state_decide(struct fts_state *state, const char *key, size_t length, int *work);
void fts_state_finish(struct fts_state *state, int commit);
int fts_state_register(struct fts_runtime *ctx);
int fts_state_metrics_initialize(struct fts_runtime *ctx, void *metrics);
void fts_state_metrics_update(struct fts_runtime *ctx);
#endif
