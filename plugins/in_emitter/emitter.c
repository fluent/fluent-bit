/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_ring_buffer.h>

#include <sys/types.h>
#include <sys/stat.h>

#define DEFAULT_EMITTER_RING_BUFFER_FLUSH_FREQUENCY 2000

/* return values */
#define FLB_EMITTER_BUSY     -2

struct em_chunk {
    flb_sds_t tag;
    struct msgpack_sbuffer mp_sbuf;  /* msgpack sbuffer        */
    struct msgpack_packer mp_pck;    /* msgpack packer         */
    struct mk_list _head;
};

struct input_ref {
    struct flb_input_instance *i_ins;
    struct mk_list _head;
};

struct flb_emitter {
    int coll_fd;                        /* collector id */
    struct mk_list chunks;              /* list of all pending chunks */
    struct flb_input_instance *ins;     /* input instance */
    struct flb_ring_buffer *msgs;       /* ring buffer for cross-thread messages */
    int ring_buffer_size;               /* size of the ring buffer */
    struct mk_list i_ins_list;          /* instance list of linked/sending inputs */
};

struct em_chunk *em_chunk_create(const char *tag, int tag_len,
                                 struct flb_emitter *ctx)
{
    struct em_chunk *ec;

    ec = flb_calloc(1, sizeof(struct em_chunk));
    if (!ec) {
        flb_errno();
        return NULL;
    }

    ec->tag = flb_sds_create_len(tag, tag_len);
    if (!ec->tag) {
        flb_errno();
        flb_free(ec);
        return NULL;
    }

    msgpack_sbuffer_init(&ec->mp_sbuf);
    msgpack_packer_init(&ec->mp_pck, &ec->mp_sbuf, msgpack_sbuffer_write);

    mk_list_add(&ec->_head, &ctx->chunks);

    return ec;
}

static void em_chunk_destroy(struct em_chunk *ec)
{
    mk_list_del(&ec->_head);
    flb_sds_destroy(ec->tag);
    msgpack_sbuffer_destroy(&ec->mp_sbuf);
    flb_free(ec);
}

int static do_in_emitter_add_record(struct em_chunk *ec,
                                    struct flb_input_instance *in)
{
    struct flb_emitter *ctx = (struct flb_emitter *) in->context;
    int ret;

    if (flb_input_buf_paused(ctx->ins) == FLB_TRUE) {
        flb_plg_debug(ctx->ins, "_emitter %s paused. Not processing records.",
                         ctx->ins->name);
        return FLB_EMITTER_BUSY;
    }

    /* Associate this backlog chunk to this instance into the engine */
    ret = flb_input_log_append(in,
                               ec->tag, flb_sds_len(ec->tag),
                               ec->mp_sbuf.data,
                               ec->mp_sbuf.size);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "error registering chunk with tag: %s", ec->tag);
        /* Release the echunk */
        em_chunk_destroy(ec);
        return -1;
    }
    em_chunk_destroy(ec);
    return 0;
}

/*
 * Function used by filters to ingest custom records with custom tags, at the
 * moment it's only used by rewrite_tag filter.
 */
int in_emitter_add_record(const char *tag, int tag_len,
                          const char *buf_data, size_t buf_size,
                          struct flb_input_instance *in,
                          struct flb_input_instance *i_ins)
{
    struct em_chunk temporary_chunk;
    struct mk_list *head;
    struct input_ref *i_ref;
    bool ref_found;
    struct mk_list *tmp;

    struct em_chunk *ec;
    struct flb_emitter *ctx;

    ctx = (struct flb_emitter *) in->context;
    ec = NULL;
    /* Iterate over list of already known (source) inputs */
    /* If new, add it to the list to be able to pause it later on */
    ref_found = false;
    mk_list_foreach_safe(head, tmp, &ctx->i_ins_list) {
        i_ref = mk_list_entry(head, struct input_ref, _head);
        if(i_ref->i_ins == i_ins){
            ref_found = true;
            break;
        }
    }
    if (!ref_found) {
        i_ref = flb_malloc(sizeof(struct input_ref));
        if (!i_ref) {
            flb_errno();
            return FLB_FILTER_NOTOUCH;
        }
        i_ref->i_ins = i_ins;
        mk_list_add(&i_ref->_head, &ctx->i_ins_list);
        /* If in_emitter is paused, but new input plugin is not paused, pause it */
        if (flb_input_buf_paused(ctx->ins) == FLB_TRUE &&
                flb_input_buf_paused(i_ins) == FLB_FALSE) {
            flb_input_pause(i_ins);
        }
    }


    /* Restricted by mem_buf_limit */
    if (flb_input_buf_paused(ctx->ins) == FLB_TRUE) {
        flb_plg_debug(ctx->ins, "emitter memory buffer limit reached. Not accepting record.");
        return FLB_EMITTER_BUSY;
    }

    /* Use the ring buffer first if it exists */
    if (ctx->msgs) {
        memset(&temporary_chunk, 0, sizeof(struct em_chunk));

        temporary_chunk.tag = flb_sds_create_len(tag, tag_len);

        if (temporary_chunk.tag == NULL) {
            flb_plg_error(ctx->ins,
                          "cannot allocate memory for tag: %s",
                          tag);
            return -1;
        }

        msgpack_sbuffer_init(&temporary_chunk.mp_sbuf);
        msgpack_sbuffer_write(&temporary_chunk.mp_sbuf, buf_data, buf_size);

        return flb_ring_buffer_write(ctx->msgs,
                                     (void *) &temporary_chunk,
                                     sizeof(struct em_chunk));
    }

    /* Check if any target chunk already exists */
    mk_list_foreach(head, &ctx->chunks) {
        ec = mk_list_entry(head, struct em_chunk, _head);
        if (flb_sds_cmp(ec->tag, tag, tag_len) != 0) {
            ec = NULL;
            continue;
        }
        break;
    }

    /* No candidate chunk found, so create a new one */
    if (!ec) {
        ec = em_chunk_create(tag, tag_len, ctx);
        if (!ec) {
            flb_plg_error(ctx->ins, "cannot create new chunk for tag: %s",
                      tag);
            return -1;
        }
    }

    /* Append raw msgpack data */
    msgpack_sbuffer_write(&ec->mp_sbuf, buf_data, buf_size);
    return 0;
}

/*
 * Triggered by refresh_interval, it re-scan the path looking for new files
 * that match the original path pattern.
 */
static int in_emitter_ingest_ring_buffer(struct flb_input_instance *in,
                                  struct flb_config *config, void *context)
{
    int ret;
    struct flb_emitter *ctx = (struct flb_emitter *)context;
    struct em_chunk ec;
    (void) config;
    (void) in;


    while ((ret = flb_ring_buffer_read(ctx->msgs, (void *)&ec,
                                       sizeof(struct em_chunk))) == 0) {
        ret = flb_input_log_append(in,
                                   ec.tag, flb_sds_len(ec.tag),
                                   ec.mp_sbuf.data,
                                   ec.mp_sbuf.size);
        flb_sds_destroy(ec.tag);
        msgpack_sbuffer_destroy(&ec.mp_sbuf);
    }
    return ret;
}

static int cb_queue_chunks(struct flb_input_instance *in,
                           struct flb_config *config, void *data)
{
    int ret;
    struct mk_list *tmp;
    struct mk_list *head;
    struct em_chunk *echunk;
    struct flb_emitter *ctx;

    /* Get context */
    ctx = (struct flb_emitter *) data;

    /* Try to enqueue chunks under our limits */
    mk_list_foreach_safe(head, tmp, &ctx->chunks) {
        echunk = mk_list_entry(head, struct em_chunk, _head);

        /* Associate this backlog chunk to this instance into the engine */
        ret = do_in_emitter_add_record(echunk, in);
        if (ret == -1) {
            continue;
        }
    }

    return 0;
}

static int in_emitter_start_ring_buffer(struct flb_input_instance *in, struct flb_emitter *ctx)
{
    if (ctx->ring_buffer_size <= 0) {
        return 0;
    }

    if (ctx->msgs != NULL) {
        flb_warn("emitter %s already has a ring buffer",
                  flb_input_name(in));
        return 0;
    }

    ctx->msgs = flb_ring_buffer_create(sizeof(void *) * ctx->ring_buffer_size);
    if (!ctx->msgs) {
        flb_error("emitter %s could not initialize ring buffer",
                  flb_input_name(in));
        return -1;
    }

    return flb_input_set_collector_time(in, in_emitter_ingest_ring_buffer,
                                       1, 0, in->config);
}

/* Initialize plugin */
static int cb_emitter_init(struct flb_input_instance *in,
                           struct flb_config *config, void *data)
{
    struct flb_sched *scheduler;
    struct flb_emitter *ctx;
    int ret;

    scheduler = flb_sched_ctx_get();

    ctx = flb_calloc(1, sizeof(struct flb_emitter));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = in;
    mk_list_init(&ctx->chunks);

    mk_list_init(&ctx->i_ins_list);


    ret = flb_input_config_map_set(in, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    if (scheduler != config->sched &&
        scheduler != NULL &&
        ctx->ring_buffer_size == 0) {

        ctx->ring_buffer_size = DEFAULT_EMITTER_RING_BUFFER_FLUSH_FREQUENCY;

        flb_plg_debug(in,
                      "threaded emitter instances require ring_buffer_size"
                      " being set, using default value of %u",
                      ctx->ring_buffer_size);
    }

    if (ctx->ring_buffer_size > 0) {
        ret = in_emitter_start_ring_buffer(in, ctx);
        if (ret == -1) {
            flb_free(ctx);
            return -1;
        }
    }
    else{
        ret = flb_input_set_collector_time(in, cb_queue_chunks, 0, 25000000, config);
        if (ret < 0) {
            flb_error("[in_emitter] could not create collector");
            flb_free(ctx);
            return -1;
        }
        ctx->coll_fd = ret;
    }

    /* export plugin context */
    flb_input_set_context(in, ctx);

    return 0;
}

static void cb_emitter_pause(void *data, struct flb_config *config)
{
    struct flb_emitter *ctx = data;
    struct mk_list *tmp;
    struct mk_list *head;
    struct input_ref *i_ref;

    /* Pause all known senders */
    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
    mk_list_foreach_safe(head, tmp, &ctx->i_ins_list) {
        i_ref = mk_list_entry(head, struct input_ref, _head);
        flb_input_pause(i_ref->i_ins);
    }
}

static void cb_emitter_resume(void *data, struct flb_config *config)
{
    struct flb_emitter *ctx = data;
    struct mk_list *tmp;
    struct mk_list *head;
    struct input_ref *i_ref;

    /* Resume all known senders */
    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
    mk_list_foreach_safe(head, tmp, &ctx->i_ins_list) {
        i_ref = mk_list_entry(head, struct input_ref, _head);
        flb_input_resume(i_ref->i_ins);
    }
}

static int cb_emitter_exit(void *data, struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_emitter *ctx = data;
    struct em_chunk *echunk;
    struct em_chunk ec;
    struct input_ref *i_ref;
    int ret;

    mk_list_foreach_safe(head, tmp, &ctx->chunks) {
        echunk = mk_list_entry(head, struct em_chunk, _head);
        mk_list_del(&echunk->_head);
        flb_free(echunk);
    }

    if (ctx->msgs) {
        while ((ret = flb_ring_buffer_read(ctx->msgs, (void *)&ec,
                                        sizeof(struct em_chunk))) == 0) {
            flb_sds_destroy(ec.tag);
            msgpack_sbuffer_destroy(&ec.mp_sbuf);
        }
        flb_ring_buffer_destroy(ctx->msgs);
    }

    mk_list_foreach_safe(head,tmp, &ctx->i_ins_list) {
        i_ref = mk_list_entry(head, struct input_ref, _head);
        mk_list_del(&i_ref->_head);
        flb_free(i_ref);
    }


    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
   {
    FLB_CONFIG_MAP_INT, "ring_buffer_size", "0",
    0, FLB_TRUE, offsetof(struct flb_emitter, ring_buffer_size),
    "use a ring buffer to ingest messages for the emitter (required across threads)."
   },
   {0}
};

/* Plugin reference */
struct flb_input_plugin in_emitter_plugin = {
    .name         = "emitter",
    .description  = "Record Emitter",
    .cb_init      = cb_emitter_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_ingest    = NULL,
    .cb_flush_buf = NULL,
    .config_map   = config_map,
    .cb_pause     = cb_emitter_pause,
    .cb_resume    = cb_emitter_resume,
    .cb_exit      = cb_emitter_exit,

    /* This plugin can only be configured and invoked by the Engine only */
    .flags        = FLB_INPUT_PRIVATE
};
