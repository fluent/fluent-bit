/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include "prom_http.h"

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

    /* HTTP Server context */
    ctx->http = prom_http_server_create(ctx,
                                        ins->host.name, ins->host.port, config);
    if (!ctx->http) {
        flb_plg_error(ctx->ins, "could not initialize HTTP server, aborting");
        return -1;
    }

    /* Hash table for metrics */
    ctx->ht_metrics = flb_hash_table_create_with_ttl(ctx->ttl, FLB_HASH_TABLE_EVICT_NONE, 32, 0);
    if (!ctx->ht_metrics) {
        flb_plg_error(ctx->ins, "could not initialize hash table for metrics");
        return -1;
    }

    /* Start HTTP Server */
    ret = prom_http_server_start(ctx->http);
    if (ret == -1) {
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
    cfl_sds_t text = NULL;
    cfl_sds_t tmp = NULL;
    struct cmt *cmt;
    struct prom_exporter *ctx = out_context;
    int ok = CMT_DECODE_MSGPACK_SUCCESS;

    text = flb_sds_create_size(128);
    if (text == NULL) {
        flb_plg_debug(ctx->ins, "failed to allocate buffer for text representation of metrics");
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Clear old metrics */
    flb_hash_table_clear(ctx->ht_metrics);

    /*
     * A new set of metrics has arrived, perform decoding, apply labels,
     * convert to Prometheus text format and store the output in the
     * hash table for metrics.
     * Note that metrics might be concatenated. So, we need to consume
     * until the end of event_chunk.
     */
    while ((ret = cmt_decode_msgpack_create(&cmt,
                                            (char *) event_chunk->data,
                                            event_chunk->size, &off)) == ok) {

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
        tmp = cmt_encode_prometheus_create(cmt, add_ts);
        if (!tmp) {
            cmt_destroy(cmt);
            flb_sds_destroy(text);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
        ret = flb_sds_cat_safe(&text, tmp, flb_sds_len(tmp));
        if (ret != 0) {
            flb_plg_error(ctx->ins, "could not concatenate text representant coming from: %s",
                          flb_input_name(ins));
            cmt_encode_prometheus_destroy(tmp);
            flb_sds_destroy(text);
            cmt_destroy(cmt);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
        cmt_encode_prometheus_destroy(tmp);
        cmt_destroy(cmt);
    }

    if (cfl_sds_len(text) == 0) {
        flb_plg_debug(ctx->ins, "context without metrics (empty)");
        flb_sds_destroy(text);
        FLB_OUTPUT_RETURN(FLB_OK);
    }

    /* register payload of metrics / override previous one */
    ret = hash_store(ctx, ins, text);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not store metrics coming from: %s",
                      flb_input_name(ins));
        flb_sds_destroy(text);
        cmt_destroy(cmt);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }
    flb_sds_destroy(text);

    /* retrieve a full copy of all metrics */
    metrics = hash_format_metrics(ctx);

    if (!metrics) {
        flb_plg_error(ctx->ins, "could not retrieve metrics");
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* push new (full) metrics payload */
    ret = prom_http_server_mq_push_metrics(ctx->http,
                                           (char *) metrics,
                                           flb_sds_len(metrics));
    flb_sds_destroy(metrics);

    if (ret != 0) {
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_prom_exit(void *data, struct flb_config *config)
{
    struct prom_exporter *ctx = data;

    if (!ctx) {
        return 0;
    }

    if (ctx->ht_metrics) {
        flb_hash_table_destroy(ctx->ht_metrics);
    }

    flb_kv_release(&ctx->kv_labels);
    prom_http_server_stop(ctx->http);
    prom_http_server_destroy(ctx->http);
    flb_free(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
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

    {
     FLB_CONFIG_MAP_TIME, "ttl", "0s",
     0, FLB_TRUE, offsetof(struct prom_exporter, ttl),
     "Expiring time for metrics"
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
    .flags       = FLB_OUTPUT_NET,
    .event_type  = FLB_OUTPUT_METRICS,
    .config_map  = config_map,
};
