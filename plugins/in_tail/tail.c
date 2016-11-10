/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_stats.h>

struct flb_in_tail_config {
    /* Config properties */
    char *path;
};

/* cb_collect callback */
static int in_tail_collect(struct flb_config *config, void *in_context)
{
    int fd;
    int ret;
    uint64_t val;
    struct flb_in_tail_config *ctx = in_context;

    return 0;
}

/* Set plugin configuration */
static int in_tail_config_read(struct flb_in_tail_config *random_config,
                                 struct flb_input_instance *in)
{
    char *val = NULL;

    /* samples */
    val = flb_input_get_property("path", in);
    if (!val) {
        flb_error("[in_tail] no path to tail");
        return -1;
    }

    return 0;
}

/* Initialize plugin */
static int in_tail_init(struct flb_input_instance *in,
                        struct flb_config *config, void *data)
{
    int ret = -1;
    struct flb_in_tail_config *ctx = NULL;

    /* Allocate space for the configuration */
    ctx = flb_malloc(sizeof(struct flb_in_tail_config));
    if (!ctx) {
        return -1;
    }

    /* Initialize head config */
    ret = in_tail_config_read(ctx, in);
    if (ret < 0) {
        flb_free(ctx);
        return -1;
    }

    flb_input_set_context(in, ctx);
    return 0;
}

/* cb_flush callback */
static void *in_tail_flush(void *in_context, size_t *size)
{
    char *buf = NULL;
    struct flb_in_tail_config *ctx = in_context;

    *size = 0;
    return buf;
}

static int in_tail_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_tail_config *ctx = data;

    flb_free(ctx);

    return 0;
}


struct flb_input_plugin in_tail_plugin = {
    .name         = "tail",
    .description  = "Tail files",
    .cb_init      = in_tail_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_tail_collect,
    .cb_flush_buf = in_tail_flush,
    .cb_exit      = in_tail_exit
};
