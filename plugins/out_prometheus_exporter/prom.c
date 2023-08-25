/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_metrics.h>

#include "prom.h"
#include "prom_http_conn.h"
#include "prom_metrics.h"

static void prom_exporter_destroy(struct prom_exporter *ctx) 
{
    if (!ctx) {
        return 0;
    }

    if (ctx->ht_metrics) {
        flb_hash_table_destroy(ctx->ht_metrics);
    }

    prom_metrics_destroy_metrics();
    flb_kv_release(&ctx->kv_labels);
    flb_downstream_destroy(ctx->downstream);
    flb_free(ctx->request_event);
    mk_destroy(ctx->mk_ctx);
    flb_free(ctx);

    return;
}

static int request_event_handler(void* data) 
{
    struct mk_event *event;
    struct prom_exporter *ctx;
    struct flb_connection *connection;
    struct prom_http_conn *conn;

    event = data;
    ctx = event->data; 
    connection = flb_downstream_conn_get(ctx->downstream);
    if (connection == NULL) {
        flb_plg_error(ctx->ins, "could not accept new connection");
        return -1;
    }

    flb_plg_trace(ctx->ins, "new TCP connection arrived FD=%i",
                  connection->fd);

    conn = prom_http_conn_create(connection, ctx);
    if (conn == NULL) {
        flb_downstream_conn_release(connection);
        return -1;
    }

    /* Add connection to list */
    mk_list_add(&conn->_head, &ctx->connections);

    return 0;
}

static int config_add_labels(struct flb_output_instance *ins,
                             struct prom_exporter *ctx)
{
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *k = NULL;
    struct flb_slist_entry *v = NULL;
    struct flb_kv *kv;

    if (!ctx->add_labels || mk_list_size(ctx->add_labels) == 0) {
        return 0;
    }

    /* iterate all 'add_label' definitions */
    flb_config_map_foreach(head, mv, ctx->add_labels) {
        if (mk_list_size(mv->val.list) != 2) {
            flb_plg_error(ins, "'add_label' expects a key and a value, "
                          "e.g: 'add_label version 1.8.0'");
            return -1;
        }

        k = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        v = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        kv = flb_kv_item_create(&ctx->kv_labels, k->str, v->str);
        if (!kv) {
            flb_plg_error(ins, "could not append label %s=%s\n", k->str, v->str);
            return -1;
        }
    }

    return 0;
}

static int cb_prom_init(struct flb_output_instance *ins,
                        struct flb_config *config,
                        void *data)
{
    int ret;
    struct prom_exporter *ctx;

    flb_output_net_default("0.0.0.0", 2021 , ins);

    ctx = flb_calloc(1, sizeof(struct prom_exporter));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    flb_kv_init(&ctx->kv_labels);
    flb_output_set_context(ins, ctx);

    /* Load config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        return -1;
    }

    /* Parse 'add_label' */
    ret = config_add_labels(ins, ctx);
    if (ret == -1) {
        return -1;
    }

    /* HTTP Server to use for request parsing */
    ctx->mk_ctx = mk_create();
    ctx->mk_ctx->server->keep_alive = MK_TRUE;

    ctx->downstream = flb_downstream_create(FLB_TRANSPORT_TCP,
                                            ins->flags,
                                            ins->host.name,
                                            ins->host.port,
                                            ins->tls,
                                            config,
                                            &ins->net_setup);
    if (ctx->downstream == NULL) {
        flb_plg_error(ctx->ins,
                      "could not initialize downstream on %s:%s. Aborting",
                      ctx->ins->host.name, ctx->ins->host.port);

        prom_exporter_destroy(ctx);
        return -1;
    }

    // TODO: Check for threaded output in flb_downstream?

    /* Hash table for metrics */
    ctx->ht_metrics = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 32, 0);
    if (!ctx->ht_metrics) {
        flb_plg_error(ctx->ins, "could not initialize hash table for metrics");
        return -1;
    }

    mk_list_init(&ctx->connections);

    ctx->request_event = flb_calloc(1, sizeof(struct mk_event));
    ctx->request_event->mask = MK_EVENT_EMPTY;
    ctx->request_event->status = MK_EVENT_NONE;
    ctx->request_event->handler = request_event_handler;
    ctx->request_event->data = ctx;
    ctx->request_event->fd = ctx->downstream->server_fd;

    /* Add custom event to the engine to handle requests to the Prometheus server endpoint. */
    ret = mk_event_add(flb_engine_evl_get(), ctx->downstream->server_fd, 
                       FLB_ENGINE_EV_CUSTOM, MK_EVENT_READ, ctx->request_event);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "could not add request handler event");
        return -1;
    }

    flb_plg_info(ctx->ins, "listening iface=%s tcp_port=%d",
                 ins->host.name, ins->host.port);

    return 0;
}

static void append_labels(struct prom_exporter *ctx, struct cmt *cmt)
{
    struct flb_kv *kv;
    struct mk_list *head;

    mk_list_foreach(head, &ctx->kv_labels) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        cmt_label_add(cmt, kv->key, kv->val);
    }
}

static int hash_store(struct prom_exporter *ctx, struct flb_input_instance *ins,
                      cfl_sds_t buf)
{
    int ret;
    int len;

    len = strlen(ins->name);

    /* store/override the content into the hash table */
    ret = flb_hash_table_add(ctx->ht_metrics, ins->name, len,
                             buf, cfl_sds_len(buf));
    if (ret < 0) {
        return -1;
    }

    return 0;
}

static flb_sds_t hash_format_metrics(struct prom_exporter *ctx)
{
    int size = 2048;
    flb_sds_t buf;

    struct mk_list *head;
    struct flb_hash_table_entry *entry;


    buf = flb_sds_create_size(size);
    if (!buf) {
        return NULL;
    }

    /* Take every hash entry and compose one buffer with the whole content */
    mk_list_foreach(head, &ctx->ht_metrics->entries) {
        entry = mk_list_entry(head, struct flb_hash_table_entry, _head_parent);
        flb_sds_cat_safe(&buf, entry->val, entry->val_size);
    }

    return buf;
}

static void cb_prom_flush(struct flb_event_chunk *event_chunk,
                          struct flb_output_flush *out_flush,
                          struct flb_input_instance *ins, void *out_context,
                          struct flb_config *config)
{
    int ret;
    int add_ts;
    size_t off = 0;
    flb_sds_t metrics;
    cfl_sds_t text;
    struct cmt *cmt;
    struct prom_exporter *ctx = out_context;

    /*
     * A new set of metrics has arrived, perform decoding, apply labels,
     * convert to Prometheus text format and store the output in the
     * hash table for metrics.
     */
    ret = cmt_decode_msgpack_create(&cmt,
                                    (char *) event_chunk->data,
                                    event_chunk->size, &off);
    if (ret != 0) {
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* append labels set by config */
    append_labels(ctx, cmt);

    /* add timestamp in the output format ? */
    if (ctx->add_timestamp) {
        add_ts = CMT_TRUE;
    }
    else {
        add_ts = CMT_FALSE;
    }

    /* convert to text representation */
    text = cmt_encode_prometheus_create(cmt, add_ts);
    if (!text) {
        cmt_destroy(cmt);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }
    cmt_destroy(cmt);

    if (cfl_sds_len(text) == 0) {
        flb_plg_debug(ctx->ins, "context without metrics (empty)");
        cmt_encode_text_destroy(text);
        FLB_OUTPUT_RETURN(FLB_OK);
    }

    /* register payload of metrics / override previous one */
    ret = hash_store(ctx, ins, text);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not store metrics coming from: %s",
                      flb_input_name(ins));
        cmt_encode_prometheus_destroy(text);
        cmt_destroy(cmt);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }
    cmt_encode_prometheus_destroy(text);

    /* retrieve a full copy of all metrics */
    metrics = hash_format_metrics(ctx);
    if (!metrics) {
        flb_plg_error(ctx->ins, "could not retrieve metrics");
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* push new (full) metrics payload */
    ret = prom_metrics_push_new_metrics((char *) metrics, flb_sds_len(metrics));
    flb_sds_destroy(metrics);

    if (ret != 0) {
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_prom_exit(void *data, struct flb_config *config)
{
    int ret;
    struct prom_exporter *ctx = data;

    if (!ctx) {
        return 0;
    }

    prom_exporter_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_SIZE, "buffer_max_size", PROM_BUFFER_MAX_SIZE,
     0, FLB_TRUE, offsetof(struct prom_exporter, buffer_max_size),
     ""
    },

    {
     FLB_CONFIG_MAP_SIZE, "buffer_chunk_size", PROM_BUFFER_CHUNK_SIZE,
     0, FLB_TRUE, offsetof(struct prom_exporter, buffer_chunk_size),
     ""
    },

    {
     FLB_CONFIG_MAP_BOOL, "add_timestamp", "false",
     0, FLB_TRUE, offsetof(struct prom_exporter, add_timestamp),
     "Add timestamp to every metric honoring collection time."
    },

    {
     FLB_CONFIG_MAP_SLIST_1, "add_label", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct prom_exporter, add_labels),
     "TCP port for listening for HTTP connections."
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_prometheus_exporter_plugin = {
    .name        = "prometheus_exporter",
    .description = "Prometheus Exporter",
    .cb_init     = cb_prom_init,
    .cb_flush    = cb_prom_flush,
    .cb_exit     = cb_prom_exit,
    .flags       = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
    .event_type  = FLB_OUTPUT_METRICS,
    .config_map  = config_map,
};
