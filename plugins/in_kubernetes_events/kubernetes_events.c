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


#include <sys/types.h>
#include <sys/stat.h>

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_strptime.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_compat.h>

#include "kubernetes_events.h"
#include "kubernetes_events_conf.h"

static int file_to_buffer(const char *path,
                          char **out_buf, size_t *out_size)
{
    int ret;
    int len;
    char *buf;
    ssize_t bytes;
    FILE *fp;
    struct stat st;

    if (!(fp = fopen(path, "r"))) {
        return -1;
    }

    ret = stat(path, &st);
    if (ret == -1) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    buf = flb_calloc(1, (st.st_size + 1));
    if (!buf) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    bytes = fread(buf, st.st_size, 1, fp);
    if (bytes < 1) {
        flb_free(buf);
        fclose(fp);
        return -1;
    }

    fclose(fp);

    // trim new lines
    for (len = st.st_size; len > 0; len--) {
        if (buf[len-1] != '\n' && buf[len-1] != '\r') {
            break;
        }
    }
    buf[len] = '\0';

    *out_buf = buf;
    *out_size = len;

    return 0;
}

/* Set K8s Authorization Token and get HTTP Auth Header */
static int get_http_auth_header(struct k8s_events *ctx)
{
    int ret;
    char *temp;
    char *tk = NULL;
    size_t tk_size = 0;

    if (!ctx->token_file) {
        return 0;
    }

    ret = file_to_buffer(ctx->token_file, &tk, &tk_size);
    if (ret == -1) {
        flb_plg_warn(ctx->ins, "cannot open %s", ctx->token_file);
        return -1;
    }
    ctx->token_created = time(NULL);

    /* Token */
    if (ctx->token != NULL) {
        flb_free(ctx->token);
    }
    ctx->token = tk;
    ctx->token_len = tk_size;

    /* HTTP Auth Header */
    if (ctx->auth == NULL) {
        ctx->auth = flb_malloc(tk_size + 32);
    }
    else if (ctx->auth_len < tk_size + 32) {
        temp = flb_realloc(ctx->auth, tk_size + 32);
        if (temp == NULL) {
            flb_errno();
            flb_free(ctx->auth);
            ctx->auth = NULL;
            return -1;
        }
        ctx->auth = temp;
    }

    if (!ctx->auth) {
        return -1;
    }

    ctx->auth_len = snprintf(ctx->auth, tk_size + 32, "Bearer %s", tk);
    return 0;
}

/* Refresh HTTP Auth Header if K8s Authorization Token is expired */
static int refresh_token_if_needed(struct k8s_events *ctx)
{
    int expired = FLB_FALSE;
    int ret;

    if (ctx->token_created > 0) {
        if (time(NULL) > ctx->token_created + ctx->token_ttl) {
            expired = FLB_TRUE;
        }
    }

    if (expired || ctx->token_created == 0) {
        ret = get_http_auth_header(ctx);
        if (ret == -1) {
            return -1;
        }
    }

    return 0;
}
static int timestamp_lookup(struct k8s_events *ctx, char *ts, struct flb_time *time)
{
    struct flb_tm tm;

    if (flb_strptime(ts, "%Y-%m-%dT%H:%M:%SZ", &tm) == NULL) {
        return -1;
    }

    time->tm.tv_sec = flb_parser_tm2time(&tm);
    time->tm.tv_nsec = 0;

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

    if (pthread_mutex_trylock(&ctx->lock) != 0) {
        FLB_INPUT_RETURN(0);
    }

    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_plg_error(ins, "upstream connection initialization error");
        goto exit;
    }

    ret = refresh_token_if_needed(ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "failed to refresh token");
        goto exit;
    }

    c = flb_http_client(u_conn, FLB_HTTP_GET, K8S_EVENTS_KUBE_API_URI,
                        NULL, 0, ctx->api_host, ctx->api_port, NULL, 0);
    if (!c) {
        flb_plg_error(ins, "unable to create http client");
        goto exit;
    }
    flb_http_buffer_size(c, 0);

    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    if (ctx->auth_len > 0) {
        flb_http_add_header(c, "Authorization", 13, ctx->auth, ctx->auth_len);
    }

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_error(ins, "http do error");
        goto exit;
    }

    if (c->resp.status == 200) {
        ret = process_events(ctx, c->resp.payload, c->resp.payload_size);
    }
    else {
        if (c->resp.payload_size > 0) {
            flb_plg_error(ctx->ins, "http_status=%i:\n%s", c->resp.status, c->resp.payload);
        }
        else {
            flb_plg_error(ctx->ins, "http_status=%i", c->resp.status);
        }
    }

exit:
    pthread_mutex_unlock(&ctx->lock);
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

    /* TLS: set debug 'level' */
    {
     FLB_CONFIG_MAP_INT, "tls.debug", "0",
     0, FLB_TRUE, offsetof(struct k8s_events, tls_debug),
     "set TLS debug level: 0 (no debug), 1 (error), "
     "2 (state change), 3 (info) and 4 (verbose)"
    },

    /* TLS: enable verification */
    {
     FLB_CONFIG_MAP_BOOL, "tls.verify", "true",
     0, FLB_TRUE, offsetof(struct k8s_events, tls_verify),
     "enable or disable verification of TLS peer certificate"
    },

    /* TLS: set tls.vhost feature */
    {
     FLB_CONFIG_MAP_STR, "tls.vhost", NULL,
     0, FLB_TRUE, offsetof(struct k8s_events, tls_vhost),
     "set optional TLS virtual host"
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

    /* Kubernetes Token file TTL */
    {
     FLB_CONFIG_MAP_TIME, "kube_token_ttl", "10m",
     0, FLB_TRUE, offsetof(struct k8s_events, token_ttl),
     "kubernetes token ttl, until it is reread from the token file. Default: 10m"
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
