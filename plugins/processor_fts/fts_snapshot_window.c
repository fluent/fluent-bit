/* Fluent Bit: generic owned-snapshot windows; policy/reduction stays in Lua. */
#include <string.h>
#include <time.h>
#include <fluent-bit/flb_random.h>
#include <cfl/cfl_hash.h>
#include "fts.h"
#include "fts_snapshot_window.h"
#ifdef FLB_SYSTEM_WINDOWS
#include <windows.h>
#endif

struct snapshot_version {
    struct cfl_variant *value;
    void *payload;
    size_t size;
    size_t cost;
    size_t samples;
};

struct snapshot_entry {
    struct snapshot_entry *next;
    struct snapshot_version *committed;
    struct snapshot_version *batch;
    struct snapshot_version *item;
    uint64_t hash;
    uint64_t deadline;
    uint64_t expires;
    size_t length;
    size_t tag_length;
    size_t cost;
    int hashed;
    int queued;
    int touched;
    struct cfl_list all;
    struct cfl_list queue;
    struct cfl_list transaction;
    char key[];
};

struct fts_snapshot_window {
    struct snapshot_entry **buckets;
    struct snapshot_entry *item;
    size_t bucket_count;
    size_t keys;
    size_t max_keys;
    size_t max_key_bytes;
    size_t max_samples;
    size_t limit;
    size_t bytes;
    size_t held;
    size_t pending;
    uint64_t seed;
    uint64_t now;
    uint64_t interval;
    uint64_t timeout;
    uint64_t (*clock)(void *);
    void *clock_data;
    int active;
    int stopped;
    struct cfl_list all;
    struct cfl_list open;
    struct cfl_list ready;
    struct cfl_list transaction;
};

static uint64_t now_monotonic(void *data)
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

static uint64_t deadline(uint64_t now, uint64_t duration)
{
    return duration > UINT64_MAX - now ? UINT64_MAX : now + duration;
}

static void sample_time(struct fts_snapshot_window *window)
{
    uint64_t now;

    now = window->clock(window->clock_data);
    if (now > window->now) {
        window->now = now;
    }
}

static int fits(struct fts_snapshot_window *window, size_t cost)
{
    return cost <= window->limit && window->bytes <= window->limit - cost;
}

static void free_version(struct fts_snapshot_window *window, struct snapshot_version *version)
{
    if (version != NULL) {
        window->bytes -= version->cost;
        cfl_variant_destroy(version->value);
        flb_free(version->payload);
        flb_free(version);
    }
}

static void unhash(struct fts_snapshot_window *window, struct snapshot_entry *entry)
{
    struct snapshot_entry **link;

    if (!entry->hashed) {
        return;
    }
    link = &window->buckets[entry->hash % window->bucket_count];
    while (*link != entry) {
        link = &(*link)->next;
    }
    *link = entry->next;
    entry->hashed = 0;
}

static void free_entry(struct fts_snapshot_window *window, struct snapshot_entry *entry)
{
    unhash(window, entry);
    cfl_list_del(&entry->all);
    if (entry->queued) {
        cfl_list_del(&entry->queue);
    }
    if (entry->touched) {
        cfl_list_del(&entry->transaction);
    }
    free_version(window, entry->item);
    free_version(window, entry->batch);
    free_version(window, entry->committed);
    window->keys--;
    window->bytes -= entry->cost;
    flb_free(entry);
}

static struct snapshot_entry *lookup(struct fts_snapshot_window *window, const char *key,
                                      size_t length, uint64_t hash, int *work)
{
    struct snapshot_entry *entry;

    for (entry = window->buckets[hash % window->bucket_count]; entry; entry = entry->next) {
        if (work != NULL && *work <= 1) {
            *work = 0;
            return NULL;
        }
        if (work != NULL) {
            (*work)--;
        }
        if (entry->hash == hash && entry->length == length && memcmp(entry->key, key, length) == 0) {
            return entry;
        }
    }
    return NULL;
}

static void close_due(struct fts_snapshot_window *window)
{
    struct snapshot_entry *entry;

    while (!cfl_list_is_empty(&window->open)) {
        entry = cfl_list_entry(window->open.next, struct snapshot_entry, queue);
        if (window->now < entry->deadline) {
            break;
        }
        cfl_list_del(&entry->queue);
        cfl_list_add(&entry->queue, &window->ready);
        entry->queued = 2;
        unhash(window, entry);
    }
}

struct fts_snapshot_window *fts_snapshot_window_create(size_t max_keys, size_t max_key_bytes,
                                                       size_t max_samples, size_t limit,
                                                       uint64_t interval_ms, uint64_t timeout_ms)
{
    struct fts_snapshot_window *window;
    size_t buckets;
    size_t base;

    if (!max_keys || max_keys > 65536 || !max_key_bytes || max_key_bytes > 65536 ||
        !max_samples || max_samples > 1000000 || !interval_ms || interval_ms > 86400000 ||
        !timeout_ms || timeout_ms > 86400000) {
        return NULL;
    }
    buckets = 1;
    while (buckets < max_keys) {
        buckets *= 2;
    }
    base = sizeof(*window) + buckets * sizeof(struct snapshot_entry *);
    if (base > limit) {
        return NULL;
    }
    window = flb_calloc(1, base);
    if (window == NULL) {
        return NULL;
    }
    if (flb_random_bytes((unsigned char *) &window->seed, sizeof(window->seed)) != 0) {
        flb_free(window);
        return NULL;
    }
    window->buckets = (struct snapshot_entry **) (window + 1);
    window->bucket_count = buckets;
    window->max_keys = max_keys;
    window->max_key_bytes = max_key_bytes;
    window->max_samples = max_samples;
    window->limit = limit;
    window->bytes = base;
    window->interval = interval_ms * UINT64_C(1000000);
    window->timeout = timeout_ms * UINT64_C(1000000);
    window->clock = now_monotonic;
    cfl_list_init(&window->all);
    cfl_list_init(&window->open);
    cfl_list_init(&window->ready);
    cfl_list_init(&window->transaction);
    return window;
}

void fts_snapshot_window_clock(struct fts_snapshot_window *window,
                                uint64_t (*clock)(void *), void *data)
{
    if (window != NULL && !window->active) {
        window->clock = clock ? clock : now_monotonic;
        window->clock_data = data;
    }
}

void fts_snapshot_window_begin(struct fts_snapshot_window *window)
{
    if (window == NULL || window->active || window->stopped) {
        return;
    }
    sample_time(window);
    close_due(window);
    window->active = 1;
}

const struct cfl_variant *fts_snapshot_window_get(struct fts_snapshot_window *window,
                                                  const char *key, size_t length, size_t *samples, int *work)
{
    struct snapshot_entry *entry;
    struct snapshot_version *version;

    if (samples) {
        *samples = 0;
    }
    if (window == NULL || !window->active || length > window->max_key_bytes ||
        (key == NULL && length != 0)) {
        return NULL;
    }
    entry = lookup(window, key, length, XXH3_64bits_withSeed(key, length, window->seed), work);
    if (entry == NULL) {
        return NULL;
    }
    version = entry->item ? entry->item : entry->batch ? entry->batch : entry->committed;
    if (samples && version) {
        *samples = version->samples;
    }
    return version ? version->value : NULL;
}

int fts_snapshot_window_put(struct fts_snapshot_window *window, const char *key, size_t length,
                             const struct cfl_variant *value, void **payload, size_t size,
                             const char *tag, size_t tag_length, int *work)
{
    struct snapshot_entry *entry;
    struct snapshot_version *version;
    struct snapshot_version *previous;
    uint64_t hash;
    size_t key_cost;
    size_t value_cost;
    size_t cost;

    if (window == NULL || !window->active || window->item != NULL || value == NULL ||
        payload == NULL || *payload == NULL || size == 0 || (tag == NULL && tag_length) ||
        (key == NULL && length != 0)) {
        return FTS_SNAPSHOT_ERROR;
    }
    if (length > window->max_key_bytes || window->pending == SIZE_MAX ||
        window->held > SIZE_MAX - window->pending - 1) {
        return FTS_SNAPSHOT_OVERFLOW;
    }
    hash = XXH3_64bits_withSeed(key, length, window->seed);
    entry = lookup(window, key, length, hash, work);
    if (work != NULL && *work <= 0) {
        return FTS_SNAPSHOT_BUDGET;
    }
    if (entry && (entry->tag_length != tag_length ||
                  (tag_length && memcmp(entry->key + entry->length, tag, tag_length) != 0))) {
        return FTS_SNAPSHOT_ERROR;
    }
    previous = entry ? (entry->batch ? entry->batch : entry->committed) : NULL;
    if (previous && previous->samples >= window->max_samples) {
        return FTS_SNAPSHOT_OVERFLOW;
    }
    if (length > SIZE_MAX - sizeof(*entry) || tag_length > SIZE_MAX - sizeof(*entry) - length) {
        return FTS_SNAPSHOT_ERROR;
    }
    key_cost = entry ? 0 : sizeof(*entry) + length + tag_length;
    value_cost = fts_value_cost((struct cfl_variant *) value, 0);
    if (value_cost > SIZE_MAX - sizeof(*version) || size > SIZE_MAX - sizeof(*version) - value_cost) {
        return FTS_SNAPSHOT_OVERFLOW;
    }
    cost = sizeof(*version) + value_cost + size;
    if (cost > SIZE_MAX - key_cost || !fits(window, cost + key_cost) ||
        (!entry && window->keys >= window->max_keys)) {
        return FTS_SNAPSHOT_OVERFLOW;
    }
    version = flb_calloc(1, sizeof(*version));
    if (version == NULL) {
        return FTS_SNAPSHOT_ERROR;
    }
    version->value = fts_copy_value((struct cfl_variant *) value, 0);
    if (version->value == NULL) {
        flb_free(version);
        return FTS_SNAPSHOT_ERROR;
    }
    if (entry == NULL) {
        entry = flb_calloc(1, key_cost);
        if (entry == NULL) {
            cfl_variant_destroy(version->value);
            flb_free(version);
            return FTS_SNAPSHOT_ERROR;
        }
        entry->hash = hash;
        entry->length = length;
        entry->tag_length = tag_length;
        entry->cost = key_cost;
        memcpy(entry->key, key, length);
        if (tag_length) {
            memcpy(entry->key + length, tag, tag_length);
        }
        entry->deadline = deadline(window->now, window->interval);
        entry->expires = deadline(entry->deadline, window->timeout);
        entry->next = window->buckets[hash % window->bucket_count];
        window->buckets[hash % window->bucket_count] = entry;
        entry->hashed = 1;
        cfl_list_add(&entry->all, &window->all);
        window->keys++;
        window->bytes += key_cost;
    }
    version->cost = cost;
    version->samples = previous ? previous->samples + 1 : 1;
    version->payload = *payload;
    version->size = size;
    *payload = NULL;
    entry->item = version;
    window->item = entry;
    window->bytes += cost;
    return FTS_SNAPSHOT_ACCEPT;
}

int fts_snapshot_window_item(struct fts_snapshot_window *window, int accept)
{
    struct snapshot_entry *entry;

    if (window == NULL || !window->active) {
        return accept ? -1 : 0;
    }
    entry = window->item;
    if (entry == NULL) {
        return accept ? -1 : 0;
    }
    window->item = NULL;
    if (accept) {
        free_version(window, entry->batch);
        entry->batch = entry->item;
        entry->item = NULL;
        if (!entry->touched) {
            cfl_list_add(&entry->transaction, &window->transaction);
            entry->touched = 1;
        }
        window->pending++;
    }
    else {
        free_version(window, entry->item);
        entry->item = NULL;
        if (entry->committed == NULL && entry->batch == NULL) {
            free_entry(window, entry);
        }
    }
    return 0;
}

void fts_snapshot_window_finish(struct fts_snapshot_window *window, int commit)
{
    struct snapshot_entry *entry;
    struct cfl_list *head;
    struct cfl_list *tmp;

    if (window == NULL || !window->active) {
        return;
    }
    fts_snapshot_window_item(window, 0);
    cfl_list_foreach_safe(head, tmp, &window->transaction) {
        entry = cfl_list_entry(head, struct snapshot_entry, transaction);
        cfl_list_del(head);
        entry->touched = 0;
        if (commit) {
            free_version(window, entry->committed);
            entry->committed = entry->batch;
            entry->batch = NULL;
            if (!entry->queued) {
                cfl_list_add(&entry->queue, &window->open);
                entry->queued = 1;
            }
        }
        else {
            free_version(window, entry->batch);
            entry->batch = NULL;
            if (entry->committed == NULL) {
                free_entry(window, entry);
            }
        }
    }
    if (commit) {
        window->held += window->pending;
    }
    window->pending = 0;
    window->active = 0;
}

void fts_snapshot_window_poll(struct fts_snapshot_window *window, fts_snapshot_emit_fn emit,
                               fts_snapshot_settle_fn settle, void *data)
{
    struct snapshot_entry *entry;
    struct snapshot_version *version;
    const char *reason;

    if (window == NULL || window->active || window->stopped || emit == NULL || settle == NULL) {
        return;
    }
    sample_time(window);
    close_due(window);
    while (!cfl_list_is_empty(&window->ready)) {
        entry = cfl_list_entry(window->ready.next, struct snapshot_entry, queue);
        version = entry->committed;
        reason = "expired";
        if (window->now < entry->expires) {
            if (emit(data, version->payload, version->size, version->cost,
                     entry->key + entry->length, entry->tag_length) != 0) {
                return;
            }
            reason = "released";
        }
        window->held -= version->samples;
        settle(data, version->samples, reason);
        free_entry(window, entry);
    }
}

void fts_snapshot_window_stop(struct fts_snapshot_window *window,
                               fts_snapshot_settle_fn settle, void *data)
{
    struct snapshot_entry *entry;
    struct cfl_list *head;
    struct cfl_list *tmp;
    size_t samples;

    if (window == NULL) {
        return;
    }
    fts_snapshot_window_finish(window, 0);
    window->stopped = 1;
    cfl_list_foreach_safe(head, tmp, &window->all) {
        entry = cfl_list_entry(head, struct snapshot_entry, all);
        samples = entry->committed ? entry->committed->samples : 0;
        window->held -= samples;
        if (settle && samples) {
            settle(data, samples, "shutdown");
        }
        free_entry(window, entry);
    }
}

void fts_snapshot_window_destroy(struct fts_snapshot_window *window)
{
    if (window) {
        fts_snapshot_window_stop(window, NULL, NULL);
        flb_free(window);
    }
}

size_t fts_snapshot_window_pending(struct fts_snapshot_window *window)
{
    return window ? window->pending : 0;
}

size_t fts_snapshot_window_held(struct fts_snapshot_window *window)
{
    return window ? window->held : 0;
}

size_t fts_snapshot_window_bytes(struct fts_snapshot_window *window)
{
    return window ? window->bytes : 0;
}
