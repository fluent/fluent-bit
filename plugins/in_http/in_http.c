/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <monkey/monkey.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "in_http.h"
#include "in_http_info.h"

/* Init CPU input */
int in_http_init(struct flb_config *config)
{
    mk_config = mk_server_init();
    mk_config->server_conf_file = FLB_HTTP_CONFIG;
    mk_config->path_config      = FLB_HTTP_CONF_PATH;
    mk_config->sites_conf_dir   = FLB_HTTP_SITES;
    mk_config->mimes_conf_file  = FLB_HTTP_MIMES;
    mk_server_setup();

    return 0;
}

/* Callback invoked after setup but before to join the main loop */
int in_http_pre_run(void *in_context, struct flb_config *config)
{
    /* EXPERIMENTAL!!! */
    mk_server_loop();
    return 0;
}

/* Callback to gather CPU usage between now and previous snapshot */
int in_http_collect(struct flb_config *config, void *in_context)
{
    return 0;
}

void *in_http_flush(void *in_context, int *size)
{
    return NULL;
}

/* Plugin reference */
struct flb_input_plugin in_http_plugin = {
    .name         = "http",
    .description  = "HTTP Service",
    .cb_init      = in_http_init,
    .cb_pre_run   = in_http_pre_run,
    .cb_collect   = in_http_collect,
    .cb_flush_buf = in_http_flush
};
