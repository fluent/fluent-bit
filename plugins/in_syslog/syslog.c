/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_stats.h>

#define DEFAULT_INTERVAL_SEC  1
#define DEFAULT_INTERVAL_NSEC 0

/* Configuration */
struct flb_syslog {


};

/* cb_collect callback */
static int in_syslog_collect(struct flb_input_instance *i_ins,
                             struct flb_config *config, void *in_context)
{
    (void) i_ins;
    (void) config;
    (void) in_context;

    return 0;
}

/* Set plugin configuration */
static int in_syslog_config_read(struct flb_syslog *ctx,
                                 struct flb_input_instance *in)
{
    return 0;
}

/* Initialize plugin */
static int in_syslog_init(struct flb_input_instance *in,
                          struct flb_config *config, void *data)
{
    int ret;
    struct flb_syslog *ctx;

    /* Allocate space for the configuration */
    ctx = flb_malloc(sizeof(struct flb_syslog));
    if (!ctx) {
        return -1;
    }

    /* Initialize head config */
    ret = in_syslog_config_read(ctx, in);
    if (ret < 0) {
        flb_free(ctx);
        return -1;
    }

    flb_input_set_context(in, ctx);
    return 0;
}

static int in_syslog_exit(void *data, struct flb_config *config)
{
    (void) data;
    (void) config;

    return 0;
}


struct flb_input_plugin in_syslog_plugin = {
    .name         = "syslog",
    .description  = "Syslog",
    .cb_init      = in_syslog_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_syslog_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_syslog_exit
};
