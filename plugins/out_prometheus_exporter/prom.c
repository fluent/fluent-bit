/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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
#include <fluent-bit/flb_kv.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_encode_text.h>
#include <cmetrics/cmt_decode_msgpack.h>

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
                                        ctx->listen, ctx->tcp_port, config);
    if (!ctx->http) {
        flb_plg_error(ctx->ins, "could not initialize HTTP server, aborting");
        flb_free(ctx);
        return -1;
    }

    /* Start HTTP Server */
    ret = prom_http_server_start(ctx->http);
    if (ret == -1) {
        return -1;
    }

    flb_plg_info(ctx->ins, "listening iface=%s tcp_port=%s",
                 ctx->listen, ctx->tcp_port, config);
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

static void cb_prom_flush(const void *data, size_t bytes,
                          const char *tag, int tag_len,
                          struct flb_input_instance *ins, void *out_context,
                          struct flb_config *config)
{
    int ret;
    size_t off = 0;
    cmt_sds_t text;
    struct cmt *cmt;
    struct prom_exporter *ctx = out_context;

    ret = cmt_decode_msgpack_create(&cmt, (char *) data, bytes, &off);
    if (ret != 0) {
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* append labels set by config */
    append_labels(ctx, cmt);

    /* convert to text representation */
    text = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    if (!text) {
        cmt_destroy(cmt);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }
    cmt_destroy(cmt);

    ret = prom_http_server_mq_push_metrics(ctx->http,
                                           (char *) text,
                                           flb_sds_len(text));
    cmt_encode_prometheus_destroy(text);

    if (ret != 0) {
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_prom_exit(void *data, struct flb_config *config)
{
    struct prom_exporter *ctx = data;

    flb_kv_release(&ctx->kv_labels);

    prom_http_server_stop(ctx->http);
    prom_http_server_destroy(ctx->http);
    flb_free(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "listen", "0.0.0.0",
     0, FLB_TRUE, offsetof(struct prom_exporter, listen),
     "Listener network interface."
    },

    {
     FLB_CONFIG_MAP_STR, "port", "2021",
     0, FLB_TRUE, offsetof(struct prom_exporter, tcp_port),
     "TCP port for listening for HTTP connections."
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
    .flags       = FLB_OUTPUT_NET,
    .event_type  = FLB_OUTPUT_METRICS,
    .config_map  = config_map,
};
