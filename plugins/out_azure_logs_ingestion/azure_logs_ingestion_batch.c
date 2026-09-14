/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>

#ifdef FLB_SYSTEM_WINDOWS
#include <windows.h>
#endif

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_coro.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_event.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_scheduler.h>

#include "azure_logs_ingestion.h"
#include "azure_logs_ingestion_batch.h"

/*
 * Linux timerfd-backed callback timers round the initial expiration down to
 * a whole-second boundary. Polling at one second avoids a tight loop while
 * the monotonic deadline below prevents an early timeout on every backend.
 */
#define AZ_LI_BATCH_DEADLINE_POLL_MS 1000

struct az_li_pending_batch;

struct az_li_pending_flush {
    struct flb_event_chunk *event_chunk;
    size_t size;
    int complete;
    int result;
    int send;
    struct flb_coro *coro;
    struct az_li_pending_batch *batch;
    struct mk_list _head;
};

struct az_li_pending_batch {
    uint64_t deadline_ms;
    size_t count;
    size_t total_size;
    size_t references;
    struct flb_az_li *ctx;
    struct az_li_pending_flush *leader;
    struct flb_sched_timer *timer;
    struct mk_list entries;
    struct mk_list _head;
};

struct flb_az_li_batch {
    int draining;
    int drain_attempted;
    struct az_li_pending_batch *collecting;
    struct mk_list batches;
};

static void pending_flush_destroy(struct az_li_pending_flush *entry)
{
    if (entry == NULL) {
        return;
    }

    if (entry->_head.next != NULL && entry->_head.prev != NULL) {
        mk_list_del(&entry->_head);
    }
    flb_free(entry);
}

static void pending_batch_destroy(struct az_li_pending_batch *batch)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct az_li_pending_flush *entry;

    if (batch == NULL) {
        return;
    }

    if (batch->timer != NULL) {
        flb_sched_timer_invalidate(batch->timer);
        batch->timer = NULL;
    }
    mk_list_foreach_safe(head, tmp, &batch->entries) {
        entry = mk_list_entry(head, struct az_li_pending_flush, _head);
        pending_flush_destroy(entry);
    }
    if (batch->_head.next != NULL && batch->_head.prev != NULL) {
        mk_list_del(&batch->_head);
    }
    flb_free(batch);
}

static int schedule_batch_wakeup(struct az_li_pending_batch *batch,
                                 int milliseconds);

static int monotonic_time_ms(uint64_t *milliseconds)
{
#ifdef FLB_SYSTEM_WINDOWS
    LARGE_INTEGER counter;
    LARGE_INTEGER frequency;
    uint64_t seconds;
    uint64_t remainder;

    if (QueryPerformanceFrequency(&frequency) == 0 ||
        QueryPerformanceCounter(&counter) == 0 ||
        frequency.QuadPart <= 0 || counter.QuadPart < 0) {
        return -1;
    }

    seconds = ((uint64_t) counter.QuadPart) /
              ((uint64_t) frequency.QuadPart);
    remainder = ((uint64_t) counter.QuadPart) %
                ((uint64_t) frequency.QuadPart);
    *milliseconds = seconds * 1000 +
                    (remainder * 1000) / ((uint64_t) frequency.QuadPart);
#else
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
        return -1;
    }

    *milliseconds = ((uint64_t) now.tv_sec * 1000) +
                    ((uint64_t) now.tv_nsec / 1000000);
#endif
    return 0;
}

static int set_batch_deadline(struct az_li_pending_batch *batch)
{
    uint64_t now_ms;

    if (monotonic_time_ms(&now_ms) == -1) {
        return -1;
    }

    batch->deadline_ms = now_ms + ((uint64_t) batch->ctx->batch_timeout * 1000);
    return 0;
}

static void batch_mark_draining(struct flb_az_li *ctx)
{
    if (ctx->batch->draining == FLB_FALSE) {
        ctx->batch->draining = FLB_TRUE;
        flb_plg_debug(ctx->ins, "draining deferred batches");
    }
}

static void close_batch(struct flb_az_li *ctx,
                        struct az_li_pending_batch *batch,
                        struct az_li_pending_flush *sender,
                        struct flb_config *config)
{
    if (batch->timer != NULL) {
        flb_sched_timer_invalidate(batch->timer);
        batch->timer = NULL;
    }
    if (ctx->batch->collecting == batch) {
        ctx->batch->collecting = NULL;
    }
    sender->send = FLB_TRUE;

    if (ctx->batch->draining == FLB_TRUE &&
        config->shutdown_by_hot_reloading == FLB_FALSE) {
        ctx->batch->drain_attempted = FLB_TRUE;
    }
}

static void batch_wakeup(struct flb_config *config, void *data)
{
    uint64_t now_ms;
    struct flb_coro *previous_coro;
    struct flb_az_li *ctx;
    struct az_li_pending_batch *batch;

    batch = data;
    ctx = batch->ctx;
    batch->timer = NULL;

    if (ctx == NULL || ctx->batch == NULL ||
        ctx->batch->collecting != batch || batch->leader == NULL) {
        return;
    }

    if (config->is_shutting_down == FLB_TRUE) {
        batch_mark_draining(ctx);
    }

    if (ctx->batch->draining == FLB_FALSE &&
        batch->count < (size_t) ctx->batch_chunk_count &&
        monotonic_time_ms(&now_ms) == 0 && now_ms < batch->deadline_ms) {
        if (schedule_batch_wakeup(batch, AZ_LI_BATCH_DEADLINE_POLL_MS) == 0) {
            return;
        }
    }

    close_batch(ctx, batch, batch->leader, config);
    previous_coro = flb_coro_get();
    flb_coro_resume(batch->leader->coro);
    flb_coro_set(previous_coro);
}

static int schedule_batch_wakeup(struct az_li_pending_batch *batch,
                                 int milliseconds)
{
    int ret;
    struct flb_sched *scheduler;
    struct flb_sched_timer *timer;

    scheduler = flb_sched_ctx_get();
    if (scheduler == NULL) {
        return -1;
    }

    timer = NULL;
    ret = flb_sched_timer_cb_create(scheduler, FLB_SCHED_TIMER_CB_ONESHOT,
                                    milliseconds, batch_wakeup, batch, &timer);
    if (ret == -1) {
        return -1;
    }

    if (batch->timer != NULL) {
        flb_sched_timer_invalidate(batch->timer);
    }
    batch->timer = timer;
    return 0;
}

static struct az_li_pending_batch *pending_batch_create(struct flb_az_li *ctx)
{
    struct az_li_pending_batch *batch;

    batch = flb_calloc(1, sizeof(struct az_li_pending_batch));
    if (batch == NULL) {
        flb_errno();
        return NULL;
    }
    batch->ctx = ctx;
    mk_list_init(&batch->entries);
    mk_list_add(&batch->_head, &ctx->batch->batches);
    return batch;
}

static struct az_li_pending_flush *pending_flush_create(
                                    struct az_li_pending_batch *batch,
                                    struct flb_event_chunk *event_chunk)
{
    struct az_li_pending_flush *entry;

    if (event_chunk->size > 0 && event_chunk->data == NULL) {
        return NULL;
    }
    if (batch->total_size > SIZE_MAX - event_chunk->size) {
        return NULL;
    }

    entry = flb_calloc(1, sizeof(struct az_li_pending_flush));
    if (entry == NULL) {
        flb_errno();
        return NULL;
    }
    entry->event_chunk = event_chunk;
    entry->size = event_chunk->size;
    entry->coro = flb_coro_get();
    entry->batch = batch;
    if (entry->coro == NULL) {
        pending_flush_destroy(entry);
        return NULL;
    }

    mk_list_add(&entry->_head, &batch->entries);
    batch->count++;
    batch->references++;
    batch->total_size += entry->size;
    if (batch->leader == NULL) {
        batch->leader = entry;
    }
    return entry;
}

static int concatenate_batch(struct az_li_pending_batch *batch,
                             void **output, size_t *output_size)
{
    char *buffer;
    char *cursor;
    struct mk_list *head;
    struct az_li_pending_flush *entry;

    buffer = flb_malloc(batch->total_size > 0 ? batch->total_size : 1);
    if (buffer == NULL) {
        flb_errno();
        return -1;
    }

    cursor = buffer;
    mk_list_foreach(head, &batch->entries) {
        entry = mk_list_entry(head, struct az_li_pending_flush, _head);
        memcpy(cursor, entry->event_chunk->data, entry->size);
        cursor += entry->size;
    }

    *output = buffer;
    *output_size = batch->total_size;
    return 0;
}

static void complete_batch(struct az_li_pending_batch *batch,
                           struct az_li_pending_flush *sender,
                           int result)
{
    struct flb_coro *previous_coro;
    struct mk_list *head;
    struct mk_list *tmp;
    struct az_li_pending_flush *entry;

    mk_list_foreach(head, &batch->entries) {
        entry = mk_list_entry(head, struct az_li_pending_flush, _head);
        entry->result = result;
        entry->complete = FLB_TRUE;
    }

    previous_coro = flb_coro_get();
    mk_list_foreach_safe(head, tmp, &batch->entries) {
        entry = mk_list_entry(head, struct az_li_pending_flush, _head);
        if (entry != sender) {
            flb_coro_resume(entry->coro);
            flb_coro_set(previous_coro);
        }
    }
}

static int send_pending_batch(struct flb_az_li *ctx,
                              struct az_li_pending_batch *batch,
                              struct flb_config *config)
{
    int result;
    void *buffer;
    size_t size;

    buffer = NULL;
    if (concatenate_batch(batch, &buffer, &size) == -1) {
        return FLB_RETRY;
    }

    result = az_li_send_payload(ctx, buffer, size, config);
    flb_free(buffer);
    if (result != FLB_OK) {
        return FLB_RETRY;
    }
    return FLB_OK;
}

int az_li_batch_init(struct flb_az_li *ctx)
{
    ctx->batch = flb_calloc(1, sizeof(struct flb_az_li_batch));
    if (ctx->batch == NULL) {
        flb_errno();
        return -1;
    }
    mk_list_init(&ctx->batch->batches);
    return 0;
}

int az_li_batch_flush(struct flb_az_li *ctx,
                      struct flb_event_chunk *event_chunk,
                      struct flb_config *config)
{
    int result;
    struct az_li_pending_batch *batch;
    struct az_li_pending_flush *entry;

    if (ctx->batch == NULL) {
        return FLB_RETRY;
    }
    if (config->is_shutting_down == FLB_TRUE) {
        batch_mark_draining(ctx);
    }
    if (ctx->batch->draining == FLB_TRUE &&
        ctx->batch->drain_attempted == FLB_TRUE &&
        config->shutdown_by_hot_reloading == FLB_FALSE) {
        return FLB_RETRY;
    }

    batch = ctx->batch->collecting;
    if (batch == NULL) {
        batch = pending_batch_create(ctx);
        if (batch == NULL) {
            return FLB_RETRY;
        }
        ctx->batch->collecting = batch;
    }

    entry = pending_flush_create(batch, event_chunk);
    if (entry == NULL) {
        if (batch->count == 0) {
            ctx->batch->collecting = NULL;
            pending_batch_destroy(batch);
        }
        return FLB_RETRY;
    }

    flb_plg_debug(ctx->ins, "deferred batch queued chunks=%zu/%i bytes=%zu",
                  batch->count, ctx->batch_chunk_count, batch->total_size);

    if (batch->count == 1) {
        if (set_batch_deadline(batch) == -1 ||
            schedule_batch_wakeup(batch,
                                  ctx->batch->draining ? 1 :
                                  AZ_LI_BATCH_DEADLINE_POLL_MS) == -1) {
            ctx->batch->collecting = NULL;
            pending_flush_destroy(entry);
            pending_batch_destroy(batch);
            return FLB_RETRY;
        }
    }
    if (batch->count == (size_t) ctx->batch_chunk_count) {
        close_batch(ctx, batch, entry, config);
    }

    if (entry->send == FLB_FALSE) {
        flb_coro_yield(entry->coro, FLB_FALSE);
        while (entry->complete == FLB_FALSE && entry->send == FLB_FALSE) {
            flb_coro_yield(entry->coro, FLB_FALSE);
        }
    }

    if (entry->send == FLB_TRUE) {
        flb_plg_debug(ctx->ins, "sending deferred batch chunks=%zu bytes=%zu",
                      batch->count, batch->total_size);
        result = send_pending_batch(ctx, batch, config);
        if (config->is_shutting_down == FLB_TRUE &&
            config->shutdown_by_hot_reloading == FLB_FALSE) {
            batch_mark_draining(ctx);
            ctx->batch->drain_attempted = FLB_TRUE;
        }
        complete_batch(batch, entry, result);
    }

    result = entry->result;
    pending_flush_destroy(entry);
    batch->references--;
    if (batch->references == 0) {
        pending_batch_destroy(batch);
    }
    return result;
}

void az_li_batch_destroy(struct flb_az_li *ctx)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct az_li_pending_batch *batch;

    if (ctx == NULL || ctx->batch == NULL) {
        return;
    }

    if (mk_list_is_empty(&ctx->batch->batches) != 0) {
        flb_plg_error(ctx->ins, "destroying output with pending deferred batches");
    }
    mk_list_foreach_safe(head, tmp, &ctx->batch->batches) {
        batch = mk_list_entry(head, struct az_li_pending_batch, _head);
        pending_batch_destroy(batch);
    }
    flb_free(ctx->batch);
    ctx->batch = NULL;
}
