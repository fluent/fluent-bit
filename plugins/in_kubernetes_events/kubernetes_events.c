/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include "kubernetes_events.h"
#include "kubernetes_events_conf.h"

static int timestamp_lookup(struct k8s_events *ctx, char *ts, struct flb_time *tm)
{
    time_t time;
    struct tm t = {0};

    if (strptime(ts, "%Y-%m-%dT%H:%M:%SZ", &t) == NULL) {
        return -1;
    }

    time = mktime(&t);
    if (time == -1) {
        flb_plg_error(ctx->ins, "invalid timestamp '%s'", ts);
        return -1;
    }

    tm->tm.tv_sec = time;
    tm->tm.tv_nsec = 0;

    return 0;
}

static int process_events(struct k8s_events *ctx, char *in_data, size_t in_size)
{
    int i;
    int ret;
    int root_type;
    int items_found = FLB_FALSE;
    size_t consumed = 0;
    char *buf_data;
    size_t buf_size;
    size_t off = 0;
    struct flb_time ts;
    struct flb_ra_value *rval;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object k;
    msgpack_object items;
    msgpack_object entry;

    ret = flb_pack_json(in_data, in_size, &buf_data, &buf_size, &root_type, &consumed);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not process payload, incomplete or bad formed JSON");
        return -1;
    }

    /* unpack */
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf_data, buf_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        flb_plg_error(ctx->ins, "Cannot unpack response");
        flb_free(buf_data);
        return -1;
    }

    /* lookup the items array */
    root = result.data;
    for (i = 0; i < root.via.map.size; i++) {
        k = root.via.map.ptr[i].key;

        if (k.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (k.via.str.size != 5) {
            continue;
        }

        if (strncmp(k.via.str.ptr, "items", 5) != 0) {
            continue;
        }

        items = root.via.map.ptr[i].val;
        if (items.type != MSGPACK_OBJECT_ARRAY) {
            flb_plg_error(ctx->ins, "Cannot unpack response");
            break;
        }

        items_found = FLB_TRUE;
        break;
    }

    if (!items_found) {
        flb_plg_error(ctx->ins, "Cannot unpack response");
        flb_free(buf_data);
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    /* get the resourceVersion of the last item */
    entry = items.via.array.ptr[items.via.array.size - 1];
    if (entry.type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "Cannot unpack response");
        flb_free(buf_data);
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    /* lookup resourceVersion */
    rval = flb_ra_get_value_object(ctx->ra_resource_version, entry);
    if (!rval || rval->type != FLB_RA_STRING) {
        flb_plg_error(ctx->ins, "cannot retrieve resourceVersion");
        flb_free(buf_data);
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    /* check if we should process this payload based on the last item resourceVersion */
    if (ctx->last_resource_version) {
        /* compare resourceVersion */
        if (strcmp(rval->val.string, ctx->last_resource_version) == 0) {
            flb_plg_debug(ctx->ins, "resourceVersion %s is equal to last resourceVersion %s, skipping payload",
                          rval->val.string, ctx->last_resource_version);
            flb_free(buf_data);
            flb_ra_key_value_destroy(rval);
            msgpack_unpacked_destroy(&result);
            return 0;
        }
        else {
            cfl_sds_destroy(ctx->last_resource_version);
            ctx->last_resource_version = cfl_sds_create(rval->val.string);
        }
    }
    else {
        ctx->last_resource_version = cfl_sds_create(rval->val.string);
    }
    flb_ra_key_value_destroy(rval);

    /* reset the log encoder */
    flb_log_event_encoder_reset(ctx->encoder);

    /* print every item from the items array */
    for (i = 0; i < items.via.array.size; i++) {
        entry = items.via.array.ptr[i];
        if (entry.type != MSGPACK_OBJECT_MAP) {
            flb_plg_error(ctx->ins, "Cannot unpack response");
            break;
        }

        /* get event timestamp */
        rval = flb_ra_get_value_object(ctx->ra_timestamp, entry);
        if (!rval || rval->type != FLB_RA_STRING) {
            flb_plg_error(ctx->ins, "cannot retrieve event timestamp");
            flb_free(buf_data);
            msgpack_unpacked_destroy(&result);
            return -1;
        }

        /* convert timestamp */
        ret = timestamp_lookup(ctx, rval->val.string, &ts);
        if (ret == -1) {
            flb_free(buf_data);
            flb_ra_key_value_destroy(rval);
            msgpack_unpacked_destroy(&result);
            return -1;
        }
        flb_ra_key_value_destroy(rval);

        /* encode content as a log event */
        flb_log_event_encoder_begin_record(ctx->encoder);
        flb_log_event_encoder_set_timestamp(ctx->encoder, &ts);

        ret = flb_log_event_encoder_set_body_from_msgpack_object(ctx->encoder, &entry);
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_commit_record(ctx->encoder);
        }
    }

    if (ctx->encoder->output_length > 0) {
        flb_input_log_append(ctx->ins, NULL, 0,
                             ctx->encoder->output_buffer,
                             ctx->encoder->output_length);
    }

    flb_free(buf_data);
    msgpack_unpacked_destroy(&result);
    return ret;
}

static int k8s_events_collect(struct flb_input_instance *ins,
                              struct flb_config *config, void *in_context)
{
    int ret;
    size_t b_sent;
    struct flb_connection *u_conn = NULL;
    struct flb_http_client *c = NULL;
    struct k8s_events *ctx = in_context;

    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_plg_error(ins, "upstream connection initialization error");
        goto exit;
    }

    c = flb_http_client(u_conn, FLB_HTTP_GET, K8S_EVENTS_KUBE_API_URI,
                        NULL, 0, ctx->ins->host.name, ctx->ins->host.port, NULL, 0);
    if (!c) {
        flb_plg_error(ins, "unable to create http client");
        goto exit;
    }
    flb_http_buffer_size(c, 0);

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_error(ins, "http do error");
        goto exit;
    }

    if (c->resp.status != 200) {
        flb_plg_error(ins, "http status code error: %d", c->resp.status);
        goto exit;
    }

    if (c->resp.payload_size <= 0) {
        flb_plg_error(ins, "empty response");
        goto exit;
    }

    ret = process_events(ctx, c->resp.payload, c->resp.payload_size);

exit:
    if (c) {
        flb_http_client_destroy(c);
    }
    if (u_conn) {
        flb_upstream_conn_release(u_conn);
    }
    FLB_INPUT_RETURN(0);
}

static int k8s_events_init(struct flb_input_instance *ins,
                           struct flb_config *config, void *data)
{
    struct k8s_events *ctx = NULL;

    ctx = k8s_events_conf_create(ins);
    if (!ctx) {
        return -1;
    }

    ctx->coll_id = flb_input_set_collector_time(ins,
                                                k8s_events_collect,
                                                1,
                                                0, config);
    return 0;
}

static int k8s_events_exit(void *data, struct flb_config *config)
{
    struct k8s_events *ctx = data;

    if (!ctx) {
        return 0;
    }

    k8s_events_conf_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    /* Full Kubernetes API server URL */
    {
     FLB_CONFIG_MAP_STR, "kube_url", "https://kubernetes.default.svc",
     0, FLB_FALSE, 0,
     "Kubernetes API server URL"
    },

    /* Kubernetes TLS: CA file */
    {
     FLB_CONFIG_MAP_STR, "kube_ca_file", K8S_EVENTS_KUBE_CA,
     0, FLB_TRUE, offsetof(struct k8s_events, tls_ca_file),
     "Kubernetes TLS CA file"
    },

    /* Kubernetes TLS: CA certs path */
    {
     FLB_CONFIG_MAP_STR, "kube_ca_path", NULL,
     0, FLB_TRUE, offsetof(struct k8s_events, tls_ca_path),
     "Kubernetes TLS ca path"
    },

    /* Kubernetes Token file */
    {
     FLB_CONFIG_MAP_STR, "kube_token_file", K8S_EVENTS_KUBE_TOKEN,
     0, FLB_TRUE, offsetof(struct k8s_events, token_file),
     "Kubernetes authorization token file"
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_kubernetes_events_plugin = {
    .name         = "kubernetes_events",
    .description  = "Kubernetes Events",
    .cb_init      = k8s_events_init,
    .cb_pre_run   = NULL,
    .cb_collect   = k8s_events_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = k8s_events_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET | FLB_INPUT_CORO | FLB_INPUT_THREADED
};
