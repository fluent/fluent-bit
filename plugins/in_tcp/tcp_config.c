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

#include <stdlib.h>
#include <fluent-bit/flb_utils.h>

#include "tcp.h"
#include "tcp_conn.h"
#include "tcp_config.h"

struct flb_in_tcp_config *tcp_config_init(struct flb_input_instance *i_ins)
{
    char tmp[16];
    char *listen;
    char *buffer_size;
    char *chunk_size;
    struct flb_in_tcp_config *config;

    config = flb_malloc(sizeof(struct flb_in_tcp_config));
    memset(config, '\0', sizeof(struct flb_in_tcp_config));

    /* Listen interface (if not set, defaults to 0.0.0.0) */
    if (!i_ins->host.listen) {
        listen = flb_input_get_property("listen", i_ins);
        if (listen) {
            config->listen = flb_strdup(listen);
        }
        else {
            config->listen = flb_strdup("0.0.0.0");
        }
    }
    else {
        config->listen = i_ins->host.listen;
    }

    /* Listener TCP Port */
    if (i_ins->host.port == 0) {
        config->tcp_port = flb_strdup("5170");
    }
    else {
        snprintf(tmp, sizeof(tmp) - 1, "%d", i_ins->host.port);
        config->tcp_port = flb_strdup(tmp);
    }

    /* Chunk size */
    chunk_size = flb_input_get_property("chunk_size", i_ins);
    if (!chunk_size) {
        config->chunk_size = FLB_IN_TCP_CHUNK; /* 32KB */
    }
    else {
        /* Convert KB unit to Bytes */
        config->chunk_size  = (atoi(chunk_size) * 1024);
    }

    /* Buffer size */
    buffer_size = flb_input_get_property("buffer_size", i_ins);
    if (!buffer_size) {
        config->buffer_size = config->chunk_size;
    }
    else {
        /* Convert KB unit to Bytes */
        config->buffer_size  = (atoi(buffer_size) * 1024);
    }

    flb_debug("[in_tcp] Listen='%s' TCP_Port=%s",
              config->listen, config->tcp_port);

    return config;
}

int tcp_config_destroy(struct flb_in_tcp_config *config)
{
    flb_free(config->listen);
    flb_free(config->tcp_port);
    flb_free(config);

    return 0;
}
