/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#ifndef FLB_IN_FW_H
#define FLB_IN_FW_H

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_metric.h>
#include <fluent-bit/flb_input_trace.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#define FW_INSTANCE_STATE_RUNNING           0
#define FW_INSTANCE_STATE_ACCEPTING_CLIENT  1
#define FW_INSTANCE_STATE_PROCESSING_PACKET 2
#define FW_INSTANCE_STATE_PAUSED            3


enum {
    FW_HANDSHAKE_HELO        = 1,
    FW_HANDSHAKE_PINGPONG    = 2,
    FW_HANDSHAKE_ESTABLISHED = 3,
};

struct flb_in_fw_helo {
    flb_sds_t nonce;
    int nonce_len;
    flb_sds_t salt;
    int salt_len;
};

struct flb_in_fw_user {
    flb_sds_t name;
    flb_sds_t password;
    struct mk_list _head;
};

struct flb_downstream_worker_runtime;

struct flb_in_fw_config {
    size_t buffer_max_size;         /* Max Buffer size             */
    size_t buffer_chunk_size;       /* Chunk allocation size       */

    /* Network */
    char *listen;                   /* Listen interface            */
    char *tcp_port;                 /* TCP Port                    */

    flb_sds_t tag_prefix;           /* tag prefix                  */

    /* Unix Socket */
    char *unix_path;                /* Unix path for socket        */
    unsigned int unix_perm;         /* Permission for socket       */
    flb_sds_t unix_perm_str;        /* Permission (config map)     */

    /* secure forward */
    flb_sds_t shared_key;         /* shared key      */
    int owns_shared_key;          /* own flag of shared key */
    flb_sds_t self_hostname;     /* hostname used in certificate  */
    struct mk_list users;        /* username and password pairs  */
    int empty_shared_key;        /* use an empty string as shared key */

    int coll_fd;
    int workers;                    /* Listener worker count       */
    int worker_id;                  /* Worker id                   */
    int use_ingress_queue;          /* Queue records to main loop  */
    int listener_registered;        /* Listener event registered   */
    struct mk_event listener_event; /* Worker listener event       */
    struct mk_event_loop *event_loop; /* Worker event loop          */
    struct flb_net_setup net_setup; /* Worker network setup        */
    struct flb_downstream *downstream; /* Client manager          */
    struct mk_list connections;     /* List of active connections */
    struct flb_input_instance *ins; /* Input plugin instace       */

    struct flb_log_event_decoder *log_decoder;
    struct flb_log_event_encoder *log_encoder;

    pthread_mutex_t conn_mutex;

    int state;
    
    /* Plugin is paused */
    int is_paused;

    struct flb_downstream_worker_runtime *runtime;
};

static inline int fw_ingest_logs(struct flb_in_fw_config *ctx,
                                 const char *tag, size_t tag_len,
                                 const void *buf, size_t buf_size)
{
    if (ctx->use_ingress_queue == FLB_TRUE) {
        return flb_input_ingress_queue_log(ctx->ins, tag, tag_len, buf, buf_size);
    }

    return flb_input_log_append(ctx->ins, tag, tag_len, buf, buf_size);
}

static inline int fw_ingest_metrics(struct flb_in_fw_config *ctx,
                                    const char *tag, size_t tag_len,
                                    struct cmt *cmt)
{
    if (ctx->use_ingress_queue == FLB_TRUE) {
        return flb_input_ingress_queue_metrics(ctx->ins, tag, tag_len, cmt);
    }

    return flb_input_metrics_append(ctx->ins, tag, tag_len, cmt);
}

static inline int fw_ingest_traces(struct flb_in_fw_config *ctx,
                                   const char *tag, size_t tag_len,
                                   struct ctrace *ctr)
{
    if (ctx->use_ingress_queue == FLB_TRUE) {
        return flb_input_ingress_queue_traces(ctx->ins, tag, tag_len, ctr);
    }

    return flb_input_trace_append(ctx->ins, tag, tag_len, ctr);
}

#endif
