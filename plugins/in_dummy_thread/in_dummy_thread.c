/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_input_thread.h>
#include <monkey/mk_core/mk_list.h>
#include <mpack/mpack.h>

#include "in_dummy_thread.h"

static void in_dummy_thread_callback(int write_fd, void *data)
{
    int i;
    struct flb_time t;
    struct flb_in_dummy_thread_config *ctx;
    struct flb_input_thread *it = data;

    ctx = container_of(it, struct flb_in_dummy_thread_config, it);
    mpack_writer_t *writer = &it->writer;

    for (i = 0; i < ctx->samples && !flb_input_thread_exited(it); i++) {
        mpack_write_tag(writer, mpack_tag_array(2));
        flb_time_get(&t);
        flb_time_append_to_mpack(writer, &t, 0);
        mpack_write_tag(writer, mpack_tag_map(1));
        mpack_write_cstr(writer, "message");
        mpack_write_cstr(writer, ctx->message);
        mpack_writer_flush_message(writer);
        fflush(it->write_file);
        sleep(1);
    }
}

/* Initialize plugin */
static int in_dummy_thread_init(struct flb_input_instance *in,
                                struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_dummy_thread_config *ctx;
    (void) data;

    /* Allocate space for the configuration context */
    ctx = flb_malloc(sizeof(struct flb_in_dummy_thread_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    
    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *)ctx);
    if (ret == -1) {
        return -1;
    }


    if (ctx->samples <= 0) {
        ctx->samples = 1000000;
    }

    /* create worker thread */
    ret = flb_input_thread_init(&ctx->it, in_dummy_thread_callback, &ctx->it);
    if (ret) {
        flb_errno();
        flb_plg_error(ctx->ins, "Could not initialize worker thread");
        goto init_error;
    }

    /* Set the context */
    flb_input_set_context(in, &ctx->it);

    /* Collect upon data available on the pipe read fd */
    ret = flb_input_set_collector_event(in,
                                        flb_input_thread_collect,
                                        ctx->it.read,
                                        config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector for thread dummy input plugin");
        goto init_error;
    }
    ctx->it.coll_fd = ret;

    return 0;

init_error:
    flb_free(ctx);

    return -1;
}

/* Cleanup serial input */
static int in_dummy_thread_exit(void *in_context, struct flb_config *config)
{
    struct flb_input_thread *it;
    struct flb_in_dummy_thread_config *ctx;

    if (!in_context) {
        return 0;
    }

    it = in_context;
    ctx = container_of(it, struct flb_in_dummy_thread_config, it);
    flb_input_thread_destroy(it, ctx->ins);
    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "message", "thready dummy",
     0, FLB_TRUE, offsetof(struct flb_in_dummy_thread_config, message),
     "Define dummy message"
    },
    {
     FLB_CONFIG_MAP_INT, "samples", "1000000",
     0, FLB_TRUE, offsetof(struct flb_in_dummy_thread_config, samples),
     "Define the number of samples to send"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_dummy_thread_plugin = {
    .name         = "dummy_thread",
    .description  = "Generate dummy data in a separate thread",
    .cb_init      = in_dummy_thread_init,
    .cb_pre_run   = NULL,
    .cb_collect   = flb_input_thread_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_dummy_thread_exit,
    .config_map   = config_map
};
