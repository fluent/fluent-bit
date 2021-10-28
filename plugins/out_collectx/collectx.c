/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <msgpack.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "collectx.h"

#define SO_NAME "/opt/mellanox/collectx/lib/providers/libevents_fluent_aggr_provider.so"


typedef struct collectx_plugin_input_data {
    int32_t fluent_aggr_sock_fd;
    char    collector_sock_name[108];
} collectx_plugin_input_data_t;


static int cb_collectx_init(struct flb_output_instance *ins,
                            struct flb_config *config, void *data) {
    int ret;
    struct flb_collectx *ctx = NULL;
    (void) config;

    ctx = flb_calloc(1, sizeof(struct flb_collectx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    flb_output_set_context(ins, ctx);

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    collectx_plugin_input_data_t* input_data = (collectx_plugin_input_data_t*)data;
    ctx->fluent_aggr_sock_fd = input_data->fluent_aggr_sock_fd;

    if (input_data->fluent_aggr_sock_fd < 0) {
        flb_plg_info(ctx->ins, "Failed to initialize because : ctx->fluent_aggr_sock_fd = %d", ctx->fluent_aggr_sock_fd);
        return -1;
    }

    size_t name_len = strlen(input_data->collector_sock_name);
    ctx->collector_sock_name = NULL;
    ctx->collector_sock_name = flb_malloc(name_len + 1);
    if (!ctx->collector_sock_name) {
        flb_errno();
        flb_free(ctx);
        return -1;
    }
    strcpy(ctx->collector_sock_name, input_data->collector_sock_name);
    ctx->collector_sock_name[name_len] = '\0';

    /* Export context */
    flb_plg_info(ctx->ins, "ctx->fluent_aggr_sock_fd = %d", ctx->fluent_aggr_sock_fd);
    return 0;
}


static void cb_collectx_flush(struct flb_event_chunk *event_chunk,
                              struct flb_output_flush *out_flush,
                              struct flb_input_instance *i_ins,
                              void *out_context,
                              struct flb_config *config)
{
    struct flb_collectx *ctx = out_context;
    (void) i_ins;
    (void) config;

    ipc_msg_t msg;
    int msg_len = sizeof(ipc_msg_t);
    memset(&msg, 0, sizeof(ipc_msg_t));

    // 1. SEND DATA
    msg.buffer_addr = (void*)event_chunk->data;
    msg.data_size   = event_chunk->size;
    msg.tag         = event_chunk->tag;
    msg.status      = 0;

    flb_plg_info(ctx->ins, "[cb_collectx_flush] send data of size %zu, with tag '%s'", event_chunk->size, event_chunk->tag);

    struct sockaddr_un collector_sock_address;
    memset(&collector_sock_address, 0, sizeof(struct sockaddr_un));
    collector_sock_address.sun_family = AF_UNIX;
    snprintf(collector_sock_address.sun_path, sizeof(collector_sock_address.sun_path),"%s", ctx->collector_sock_name);

    socklen_t address_length = sizeof(struct sockaddr_un);

    do {
        int bytes_sent = sendto(ctx->fluent_aggr_sock_fd, (char*) &msg, msg_len, 0,
                                (struct sockaddr*) &collector_sock_address, address_length);

        if (bytes_sent == -1) {
            flb_plg_info(ctx->ins, "[cb_collectx_flush] sendto() failed:  %s", strerror(errno));
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        if (bytes_sent != msg_len) {
            flb_plg_info(ctx->ins, "[cb_collectx_flush] sendto() sent %d instead of %d bytes", bytes_sent, msg_len);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        // RECEIVE MSG TO FINISH with buffer
        socklen_t bytes_in = recvfrom(ctx->fluent_aggr_sock_fd, (char*) &msg, msg_len, 0,
                                    (struct sockaddr*) &collector_sock_address, (socklen_t*) &address_length);

        if (bytes_in != msg_len) {
            flb_plg_info(ctx->ins, "[cb_collectx_flush] received %d, expected %d bytes", bytes_in, msg_len);
            return FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        if (bytes_in < 0) {
            flb_plg_info(ctx->ins, "[cb_collectx_flush] recvfrom() failed: %s", strerror(errno));
            return FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        flb_plg_info(ctx->ins, "[cb_collectx_flush] got reply from recvfrom with status %d", msg.status);

        if (msg.status == -1) {
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    } while (msg.status != 0);

    FLB_OUTPUT_RETURN(FLB_OK);
}


static int cb_collectx_exit(void *data, struct flb_config *config)
{
    struct flb_collectx *ctx = data;

    flb_free(ctx->collector_sock_name);
    ctx->collector_sock_name = NULL;
    if (ctx != NULL) {
        flb_free(ctx);
    }
    return 0;
}


/* Configuration properties map */
static struct flb_config_map config_map[] = {
    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_collectx_plugin = {
    .name         = "collectx",
    .description  = "Pushes events into Collectx on demand",
    .cb_init      = cb_collectx_init,
    .cb_flush     = cb_collectx_flush,
    .cb_exit      = cb_collectx_exit,
    .flags        = 0,
    .config_map   = config_map
};
