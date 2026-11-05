/* Fluent Bit: bounded transactional log windows, Apache-2.0. */
#include <string.h>
#include <time.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_random.h>
#include <cfl/cfl_hash.h>
#include <cfl/cfl_list.h>

#define WINDOW_RELEASE_BYTES 65536
#ifdef FLB_SYSTEM_WINDOWS
#include <windows.h>
#endif
#include "fts_window.h"

struct window_item {
    struct window_item *next;
    void *buffer;
    size_t bytes;
    int error;
    int baseline_keep;
    size_t tag_length;
    char tag[];
};

struct window_key {
    struct window_key *next;
    struct window_item *head;
    struct window_item *tail;
    struct window_item *pending_head;
    struct window_item *pending_tail;
    uint64_t hash;
    uint64_t deadline;
    uint64_t closed_until;
    uint64_t ready_until;
    size_t length;
    int provisional;
    int closed;
    int any_error;
    int hashed;
    int queued;
    int marked;
    int transactional;
    struct cfl_list all;
    struct cfl_list queue;
    struct cfl_list marker;
    struct cfl_list transaction;
    void *batch;
    size_t batch_bytes;
    size_t batch_records;
    char key[];
};

struct fts_window {
    struct window_key **buckets;
    size_t bucket_count;
    size_t max_keys;
    size_t max_key_bytes;
    size_t keys;
    size_t limit;
    size_t bytes;
    size_t records;
    size_t pending;
    uint64_t seed;
    uint64_t now;
    uint64_t hold_ns;
    uint64_t late_ns;
    uint64_t ready_ns;
    uint64_t (*clock)(void *);
    void *clock_data;
    int active;
    int stopped;
    struct cfl_list all_keys;
    struct cfl_list open;
    struct cfl_list ready;
    struct cfl_list closed;
    struct cfl_list transactions;
    size_t poll_visits;
};

static uint64_t monotonic(void *data)
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
    return now > UINT64_MAX - duration ? UINT64_MAX : now + duration;
}

static void sample_time(struct fts_window *window)
{
    uint64_t value;

    value = window->clock(window->clock_data);
    if (value > window->now) {
        window->now = value;
    }
}

static void free_item(struct fts_window *window, struct window_item *item)
{
    window->bytes -= sizeof(*item) + item->bytes + item->tag_length;
    flb_free(item->buffer);
    flb_free(item);
}

static void unhash_key(struct fts_window *window, struct window_key *key)
{
    struct window_key **link;

    if (!key->hashed) {
        return;
    }
    link = &window->buckets[key->hash % window->bucket_count];
    while (*link != key) {
        link = &(*link)->next;
    }
    *link = key->next;
    key->hashed = 0;
}

static void free_batch(struct fts_window *window, struct window_key *key)
{
    window->bytes -= key->batch_bytes;
    flb_free(key->batch);
    key->batch = NULL;
    key->batch_bytes = 0;
    key->batch_records = 0;
}

static void free_key(struct fts_window *window, struct window_key *key)
{
    unhash_key(window, key);
    cfl_list_del(&key->all);
    if (key->queued) {
        cfl_list_del(&key->queue);
    }
    if (key->marked) {
        cfl_list_del(&key->marker);
    }
    if (key->transactional) {
        cfl_list_del(&key->transaction);
    }
    free_batch(window, key);
    window->bytes -= sizeof(*key) + key->length;
    window->keys--;
    flb_free(key);
}

static int fits(struct fts_window *window, size_t amount)
{
    return window->bytes <= window->limit && amount <= window->limit - window->bytes;
}

static struct window_key *lookup(struct fts_window *window, const char *key,
                                 size_t length, uint64_t hash, int *work)
{
    struct window_key *entry;

    for (entry = window->buckets[hash % window->bucket_count]; entry; entry = entry->next) {
        if (work != NULL && --*work <= 0) {
            *work = 0;
            return NULL;
        }
        /* An old ready generation can coexist with a new generation of a key.
         * It still counts toward max_keys/bytes until its payloads settle. */
        if (work != NULL && entry->hash == hash && entry->length == length) {
            if (length / 8 + 1 >= (size_t) *work) {
                *work = 0;
                return NULL;
            }
            *work -= (int) (length / 8 + 1);
        }
        if (entry->hash == hash && entry->length == length &&
            memcmp(entry->key, key, length) == 0 &&
            (window->now < entry->deadline || window->now < entry->closed_until)) {
            return entry;
        }
    }
    return NULL;
}

struct fts_window *fts_window_create(size_t max_keys, size_t max_key_bytes,
                                      size_t limit, uint64_t hold_ms,
                                      uint64_t late_ms, uint64_t ready_ms)
{
    struct fts_window *window;
    size_t count;
    size_t cost;
    uint64_t seed;

    if (max_keys == 0 || max_keys > 65536 || max_key_bytes == 0 || max_key_bytes > 65536 ||
        hold_ms == 0 || hold_ms > 86400000 || late_ms > 86400000 ||
        ready_ms == 0 || ready_ms > 86400000) {
        return NULL;
    }
    count = 1;
    while (count < max_keys) {
        count *= 2;
    }
    cost = sizeof(*window) + count * sizeof(struct window_key *);
    if (cost > limit || flb_random_bytes((unsigned char *) &seed, sizeof(seed)) != 0) {
        return NULL;
    }
    window = flb_calloc(1, cost);
    if (window == NULL) {
        return NULL;
    }
    window->buckets = (struct window_key **) (window + 1);
    window->bucket_count = count;
    window->max_keys = max_keys;
    window->max_key_bytes = max_key_bytes;
    window->limit = limit;
    window->bytes = cost;
    window->seed = seed;
    window->hold_ns = hold_ms * UINT64_C(1000000);
    window->late_ns = late_ms * UINT64_C(1000000);
    window->ready_ns = ready_ms * UINT64_C(1000000);
    window->clock = monotonic;
    cfl_list_init(&window->all_keys);
    cfl_list_init(&window->open);
    cfl_list_init(&window->ready);
    cfl_list_init(&window->closed);
    cfl_list_init(&window->transactions);
    return window;
}

void fts_window_clock(struct fts_window *window, uint64_t (*clock)(void *), void *data)
{
    if (window != NULL && clock != NULL) {
        window->clock = clock;
        window->clock_data = data;
    }
}

void fts_window_begin(struct fts_window *window)
{
    if (window != NULL && !window->stopped && !window->active) {
        sample_time(window);
        window->active = 1;
    }
}

int fts_window_classify(struct fts_window *window, const char *key, size_t length)
{
    return fts_window_classify_work(window, key, length, NULL);
}

int fts_window_classify_work(struct fts_window *window, const char *key, size_t length, int *work)
{
    struct window_key *entry;
    uint64_t hash;

    if (window == NULL || !window->active || window->stopped || key == NULL) {
        return FTS_WINDOW_ERROR;
    }
    if (length > window->max_key_bytes) {
        return FTS_WINDOW_OVERFLOW;
    }
    if (work != NULL) {
        if (*work < 1 || length / 8 + 1 >= (size_t) *work) {
            *work = 0;
            return FTS_WINDOW_BUDGET;
        }
        *work -= (int) (length / 8 + 1);
    }
    hash = XXH3_64bits_withSeed(key, length, window->seed);
    entry = lookup(window, key, length, hash, work);
    if (work != NULL && *work <= 0) {
        return FTS_WINDOW_BUDGET;
    }
    if (entry != NULL && window->now >= entry->deadline) {
        return FTS_WINDOW_LATE;
    }
    return FTS_WINDOW_ACCEPT;
}

int fts_window_stage(struct fts_window *window, const char *key, size_t length,
                     void **buffer, size_t bytes, int error, int baseline_keep)
{
    return fts_window_stage_tagged(window, key, length, buffer, bytes, error, baseline_keep, NULL, 0);
}

int fts_window_stage_tagged(struct fts_window *window, const char *key, size_t length,
                            void **buffer, size_t bytes, int error, int baseline_keep,
                            const char *tag, size_t tag_length)
{
    struct window_key *entry;
    struct window_item *item;
    size_t cost;
    size_t key_cost;
    uint64_t hash;
    int result;

    result = fts_window_classify(window, key, length);
    if (result != FTS_WINDOW_ACCEPT) {
        return result;
    }
    if (buffer == NULL || *buffer == NULL || bytes == 0 || bytes > SIZE_MAX - sizeof(*item)) {
        return FTS_WINDOW_ERROR;
    }
    hash = XXH3_64bits_withSeed(key, length, window->seed);
    entry = lookup(window, key, length, hash, NULL);
    if ((tag == NULL && tag_length != 0) || tag_length > SIZE_MAX - sizeof(*item) - bytes) {
        return FTS_WINDOW_ERROR;
    }
    cost = sizeof(*item) + bytes + tag_length;
    key_cost = entry == NULL ? sizeof(*entry) + length : 0;
    if (cost > SIZE_MAX - key_cost || !fits(window, cost + key_cost) ||
        (entry == NULL && window->keys >= window->max_keys)) {
        return FTS_WINDOW_OVERFLOW;
    }
    item = flb_calloc(1, sizeof(*item) + tag_length);
    if (item == NULL) {
        return FTS_WINDOW_ERROR;
    }
    if (entry == NULL) {
        entry = flb_calloc(1, key_cost);
        if (entry == NULL) {
            flb_free(item);
            return FTS_WINDOW_ERROR;
        }
        entry->hash = hash;
        entry->length = length;
        memcpy(entry->key, key, length);
        entry->deadline = deadline(window->now, window->hold_ns);
        entry->closed_until = deadline(entry->deadline, window->late_ns);
        entry->ready_until = deadline(entry->deadline, window->ready_ns);
        entry->provisional = 1;
        entry->next = window->buckets[hash % window->bucket_count];
        window->buckets[hash % window->bucket_count] = entry;
        window->keys++;
        window->bytes += key_cost;
        entry->hashed = 1;
        cfl_list_add(&entry->all, &window->all_keys);
    }
    if (!entry->transactional) {
        entry->transactional = 1;
        cfl_list_add(&entry->transaction, &window->transactions);
    }
    item->tag_length = tag_length;
    if (tag_length != 0) {
        memcpy(item->tag, tag, tag_length);
    }
    item->buffer = *buffer;
    *buffer = NULL;
    item->bytes = bytes;
    item->error = !!error;
    item->baseline_keep = !!baseline_keep;
    if (entry->pending_tail != NULL) {
        entry->pending_tail->next = item;
    }
    else {
        entry->pending_head = item;
    }
    entry->pending_tail = item;
    window->bytes += cost;
    window->pending++;
    return FTS_WINDOW_ACCEPT;
}

size_t fts_window_pending(struct fts_window *window)
{
    return window != NULL ? window->pending : 0;
}

void fts_window_finish(struct fts_window *window, int commit)
{
    struct window_key *entry;
    struct window_item *item;
    struct window_item *next;
    struct cfl_list *head;
    struct cfl_list *tmp;

    if (window == NULL || !window->active) {
        return;
    }
    cfl_list_foreach_safe(head, tmp, &window->transactions) {
        entry = cfl_list_entry(head, struct window_key, transaction);
        cfl_list_del(head);
        entry->transactional = 0;
        if (commit) {
            for (item = entry->pending_head; item != NULL; item = item->next) {
                entry->any_error |= item->error;
            }
            if (entry->pending_head != NULL) {
                if (entry->tail != NULL) {
                    entry->tail->next = entry->pending_head;
                }
                else {
                    entry->head = entry->pending_head;
                }
                entry->tail = entry->pending_tail;
            }
            if (entry->provisional) {
                /* Fixed hold duration and monotonic admission make this FIFO
                 * a deadline queue without a scan or a sorting allocation. */
                cfl_list_add(&entry->queue, &window->open);
                entry->queued = 1;
            }
            entry->provisional = 0;
        }
        else {
            for (item = entry->pending_head; item != NULL; item = next) {
                next = item->next;
                free_item(window, item);
            }
        }
        entry->pending_head = NULL;
        entry->pending_tail = NULL;
        if (entry->provisional) {
            free_key(window, entry);
        }
    }
    if (commit) {
        window->records += window->pending;
    }
    window->pending = 0;
    window->active = 0;
}

static void close_window(struct fts_window *window, struct window_key *entry,
                          fts_window_drop_fn drop, void *data)
{
    struct window_item **link;
    struct window_item *item;
    size_t dropped;

    cfl_list_del(&entry->queue);
    entry->queued = 0;
    entry->closed = 1;
    dropped = 0;
    link = &entry->head;
    entry->tail = NULL;
    while (*link != NULL) {
        item = *link;
        if (!entry->any_error && !item->baseline_keep) {
            *link = item->next;
            free_item(window, item);
            dropped++;
        }
        else {
            entry->tail = item;
            link = &item->next;
        }
    }
    window->records -= dropped;
    if (dropped != 0) {
        drop(data, dropped, "decision");
    }
    /* Markers enter at the fixed deadline, not at release completion: a BUSY
     * older window must not disrupt marker expiry ordering. */
    cfl_list_add(&entry->marker, &window->closed);
    entry->marked = 1;
    if (entry->head != NULL) {
        cfl_list_add(&entry->queue, &window->ready);
        entry->queued = 2;
    }
}

static int release_batch(struct fts_window *window, struct window_key *entry,
                          fts_window_emit_fn emit, void *data)
{
    struct window_item *item;
    struct window_item *first;
    size_t bytes;
    size_t records;
    size_t offset;
    size_t index;
    int result;

    first = entry->head;
    if (entry->batch == NULL) {
        bytes = first->bytes;
        records = 1;
        for (item = first->next; item != NULL && bytes < WINDOW_RELEASE_BYTES; item = item->next) {
            if (item->tag_length != first->tag_length ||
                memcmp(item->tag, first->tag, first->tag_length) != 0 ||
                item->bytes > WINDOW_RELEASE_BYTES - bytes) {
                break;
            }
            bytes += item->bytes;
            records++;
        }
        if (records > 1 && fits(window, bytes)) {
            entry->batch = flb_malloc(bytes);
            if (entry->batch != NULL) {
                offset = 0;
                item = first;
                for (index = 0; index < records; index++) {
                    memcpy((char *) entry->batch + offset, item->buffer, item->bytes);
                    offset += item->bytes;
                    item = item->next;
                }
                entry->batch_bytes = bytes;
                entry->batch_records = records;
                window->bytes += bytes;
            }
        }
    }
    if (entry->batch != NULL) {
        records = entry->batch_records;
        result = emit(data, &entry->batch, entry->batch_bytes, records, first->tag, first->tag_length);
    }
    else {
        /* No headroom (or allocator failure): transferring the first original
         * buffer makes progress even when the store is completely full. */
        records = 1;
        result = emit(data, &first->buffer, first->bytes, 1, first->tag, first->tag_length);
    }
    if (result != 0) {
        return result;
    }
    free_batch(window, entry);
    for (index = 0; index < records; index++) {
        item = entry->head;
        entry->head = item->next;
        free_item(window, item);
    }
    window->records -= records;
    if (entry->head == NULL) {
        entry->tail = NULL;
    }
    return 0;
}

void fts_window_poll(struct fts_window *window, fts_window_emit_fn emit,
                      fts_window_drop_fn drop, void *data)
{
    struct window_key *entry;
    struct window_item *item;
    struct window_item *next;
    size_t discarded;

    if (window == NULL || window->active || window->stopped || emit == NULL || drop == NULL) {
        return;
    }
    sample_time(window);
    window->poll_visits = 0;
    while (!cfl_list_is_empty(&window->open)) {
        entry = cfl_list_entry(window->open.next, struct window_key, queue);
        window->poll_visits++;
        if (window->now < entry->deadline) {
            break;
        }
        close_window(window, entry, drop, data);
    }
    while (!cfl_list_is_empty(&window->closed)) {
        entry = cfl_list_entry(window->closed.next, struct window_key, marker);
        window->poll_visits++;
        if (window->now < entry->closed_until) {
            break;
        }
        cfl_list_del(&entry->marker);
        entry->marked = 0;
        unhash_key(window, entry);
        if (!entry->queued) {
            free_key(window, entry);
        }
    }
    while (!cfl_list_is_empty(&window->ready)) {
        entry = cfl_list_entry(window->ready.next, struct window_key, queue);
        window->poll_visits++;
        if (window->now >= entry->ready_until) {
            free_batch(window, entry);
            discarded = 0;
            for (item = entry->head; item != NULL; item = next) {
                next = item->next;
                free_item(window, item);
                discarded++;
            }
            entry->head = NULL;
            entry->tail = NULL;
            window->records -= discarded;
            if (discarded != 0) {
                drop(data, discarded, "ready_expired");
            }
        }
        while (entry->head != NULL) {
            if (release_batch(window, entry, emit, data) != 0) {
                /* One BUSY/error ends this tick, without futile queue probes. */
                return;
            }
        }
        cfl_list_del(&entry->queue);
        entry->queued = 0;
        if (!entry->marked) {
            free_key(window, entry);
        }
    }
}

void fts_window_stop(struct fts_window *window, fts_window_drop_fn drop, void *data)
{
    struct window_key *entry;
    struct window_item *item;
    struct window_item *next;
    struct cfl_list *head;
    struct cfl_list *tmp;
    size_t records;

    if (window == NULL) {
        return;
    }
    fts_window_finish(window, 0);
    window->stopped = 1;
    cfl_list_foreach_safe(head, tmp, &window->all_keys) {
        entry = cfl_list_entry(head, struct window_key, all);
        records = 0;
        for (item = entry->head; item != NULL; item = next) {
            next = item->next;
            free_item(window, item);
            records++;
        }
        if (drop != NULL && records != 0) {
            drop(data, records, "shutdown");
        }
        free_key(window, entry);
    }
    window->records = 0;
}

size_t fts_window_poll_visits(struct fts_window *window)
{
    return window != NULL ? window->poll_visits : 0;
}

void fts_window_destroy(struct fts_window *window)
{
    if (window != NULL) {
        fts_window_stop(window, NULL, NULL);
        flb_free(window);
    }
}

size_t fts_window_bytes(struct fts_window *window)
{
    return window != NULL ? window->bytes : 0;
}

size_t fts_window_records(struct fts_window *window)
{
    return window != NULL ? window->records : 0;
}
