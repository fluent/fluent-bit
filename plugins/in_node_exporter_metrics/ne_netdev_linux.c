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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

#include <unistd.h>

static int netdev_hash_set(struct flb_ne *ctx, struct cmt_counter *c,
                           char *metric_name)
{
    int ret;
    int len;

    len = strlen(metric_name);
    ret = flb_hash_table_add(ctx->netdev_ht,
                             metric_name, len, c, 0);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not register hash entry");
        return -1;
    }

    return 0;
}

static struct cmt_counter *netdev_hash_get(struct flb_ne *ctx,
                                           char *device, char *metric_name)
{
    int ret;
    int len;
    size_t out_size;
    struct cmt_counter *c;

    len = strlen(metric_name);
    ret = flb_hash_table_get(ctx->netdev_ht,
                             metric_name, len,
                             (void *) &c, &out_size);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "hash entry '%s' not found", metric_name);
        return NULL;
    }

    return c;
}

static int netdev_configure(struct flb_ne *ctx)
{
    int ret;
    int parts;
    int n = 0;
    int len;
    char tmp[256];
    char metric_name[256];
    struct mk_list *head;
    struct mk_list *prop_head;
    struct mk_list list;
    struct mk_list head_list;
    struct mk_list split_list;
    struct mk_list rx_list;
    struct mk_list tx_list;
    struct flb_slist_entry *line;
    struct flb_slist_entry *dev;
    struct flb_slist_entry *rx_header;
    struct flb_slist_entry *tx_header;
    struct flb_slist_entry *prop;

    struct cmt_counter *c;

    /* Initialize hash table */
    ctx->netdev_ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 16, 0);
    if (!ctx->netdev_ht) {
        return -1;
    }

    mk_list_init(&list);
    mk_list_init(&head_list);
    mk_list_init(&split_list);
    mk_list_init(&rx_list);
    mk_list_init(&tx_list);

    ret = ne_utils_file_read_lines(ctx->path_procfs, "/net/dev", &list);
    if (ret == -1) {
        return -1;
    }

    /* Validate file header (second header) */
    line = flb_slist_entry_get(&list, 1);
    ret = flb_slist_split_string(&head_list, line->str, '|', -1);
    if (ret != 3) {
        flb_plg_error(ctx->ins, "invalid header line in net/dev: %s",
                      line->str);
        flb_slist_destroy(&list);
        return -1;
    }

    /* column names */
    rx_header = flb_slist_entry_get(&head_list, 1);
    tx_header = flb_slist_entry_get(&head_list, 2);

    flb_slist_split_string(&rx_list, rx_header->str, ' ', -1);
    flb_slist_split_string(&tx_list, tx_header->str, ' ', -1);

    n = 0;
    mk_list_foreach(head, &list) {
        line = mk_list_entry(head, struct flb_slist_entry, _head);

        if (n < 2) {
            /* skip first two lines */
            n++;
            continue;
        }

        mk_list_init(&split_list);
        ret = flb_slist_split_string(&split_list, line->str, ' ', 1);
        if (ret == -1) {
            continue;
        }
        parts = ret;

        if (parts < 1) {
            flb_slist_destroy(&split_list);
            continue;
        }

        /* device */
        dev = flb_slist_entry_get(&split_list, 0);

        /* sanitize device name */
        len = flb_sds_len(dev->str);
        len--;
        flb_sds_len_set(dev->str, len - 1);
        dev->str[len] = '\0';

        /* iterate all rx and tx fields to create a unique metric for each one */
        mk_list_foreach(prop_head, &rx_list) {
            prop = mk_list_entry(prop_head, struct flb_slist_entry, _head);

            /* help string */
            snprintf(tmp, sizeof(tmp) - 1,
                     "Network device statistic %s.",
                     prop->str);

            /* metric name */
            snprintf(metric_name, sizeof(metric_name) - 1,
                     "receive_%s_total", prop->str);

            /* create the metric */
            c = cmt_counter_create(ctx->cmt, "node", "network", metric_name,
                                   tmp,
                                   1, (char *[]) {"device"});

            netdev_hash_set(ctx, c, metric_name);
        }

        mk_list_foreach(prop_head, &tx_list) {
            prop = mk_list_entry(prop_head, struct flb_slist_entry, _head);

            /* help string */
            snprintf(tmp, sizeof(tmp) - 1, "Network device statistic %s.",
                     prop->str);

            /* metric name */
            snprintf(metric_name, sizeof(metric_name) - 1,
                     "transmit_%s_total", prop->str);

            /* create the metric */
            c = cmt_counter_create(ctx->cmt, "node", "network", metric_name,
                                   tmp,
                                   1, (char *[]) {"device"});

            netdev_hash_set(ctx, c, metric_name);
        }

        flb_slist_destroy(&split_list);
    }

    flb_slist_destroy(&head_list);
    flb_slist_destroy(&rx_list);
    flb_slist_destroy(&tx_list);
    flb_slist_destroy(&list);

    return 0;
}

static int netdev_update(struct flb_ne *ctx)
{
    int ret;
    int parts;
    int n = 0;
    int len;
    int pos;
    int rx_len;
    uint64_t ts;
    double val;
    char metric_name[256];
    char *type;
    struct mk_list *head;
    struct mk_list *prop_head;
    struct mk_list list;
    struct mk_list head_list;
    struct mk_list split_list;
    struct mk_list rx_list;
    struct mk_list tx_list;
    struct flb_slist_entry *line;
    struct flb_slist_entry *dev;
    struct flb_slist_entry *rx_header;
    struct flb_slist_entry *tx_header;
    struct flb_slist_entry *prop;
    struct flb_slist_entry *prop_name;

    struct cmt_counter *c;

    mk_list_init(&list);
    mk_list_init(&head_list);
    mk_list_init(&split_list);
    mk_list_init(&rx_list);
    mk_list_init(&tx_list);

    ret = ne_utils_file_read_lines(ctx->path_procfs, "/net/dev", &list);
    if (ret == -1) {
        return -1;
    }

    /* Validate file header (second header) */
    line = flb_slist_entry_get(&list, 1);
    ret = flb_slist_split_string(&head_list, line->str, '|', -1);
    if (ret != 3) {
        flb_plg_error(ctx->ins, "invalid header line in net/dev: %s",
                      line->str);
        flb_slist_destroy(&list);
        return -1;
    }

    /* column names */
    rx_header = flb_slist_entry_get(&head_list, 1);
    tx_header = flb_slist_entry_get(&head_list, 2);

    /* split rx properties */
    flb_slist_split_string(&rx_list, rx_header->str, ' ', -1);
    rx_len = mk_list_size(&rx_list);

    /* split tx properties */
    flb_slist_split_string(&tx_list, tx_header->str, ' ', -1);

    n = 0;
    ts = cfl_time_now();
    mk_list_foreach(head, &list) {
        line = mk_list_entry(head, struct flb_slist_entry, _head);

        if (n < 2) {
            /* skip first two lines */
            n++;
            continue;
        }

        mk_list_init(&split_list);
        ret = flb_slist_split_string(&split_list, line->str, ' ', -1);
        if (ret == -1) {
            continue;
        }
        parts = ret;

        if (parts < 1) {
            flb_slist_destroy(&split_list);
            continue;
        }

        /* device */
        dev = flb_slist_entry_get(&split_list, 0);

        /* sanitize device name */
        len = flb_sds_len(dev->str);
        len--;
        flb_sds_len_set(dev->str, len - 1);
        dev->str[len] = '\0';

        /* iterate line fields */
        n = 0;
        mk_list_foreach(prop_head, &split_list) {
            if (n == 0) {
                /* skip device name */
                n++;
                continue;
            }

            prop = mk_list_entry(prop_head, struct flb_slist_entry, _head);
            pos = n - 1;
            if (pos < rx_len) {
                prop_name = flb_slist_entry_get(&rx_list, pos);
                type = "receive";
            }
            else {
                pos = (n - 1) - rx_len;
                prop_name = flb_slist_entry_get(&tx_list, pos);
                type = "transmit";
            }

            /* metric name */
            snprintf(metric_name, sizeof(metric_name) - 1,
                     "%s_%s_total", type, prop_name->str);

            c = netdev_hash_get(ctx, dev->str, metric_name);
            if (!c) {
                flb_plg_error(ctx->ins, "no hash metric found for %s:%s",
                              dev->str, prop->str);
                continue;
            }

            ne_utils_str_to_double(prop->str, &val);
            ret = cmt_counter_set(c, ts, val, 1, (char *[]) {dev->str});
            n++;
        }
        flb_slist_destroy(&split_list);
    }

    flb_slist_destroy(&head_list);
    flb_slist_destroy(&rx_list);
    flb_slist_destroy(&tx_list);
    flb_slist_destroy(&list);

    return 0;
}


static int ne_netdev_init(struct flb_ne *ctx)
{
    netdev_configure(ctx);
    return 0;
}

static int ne_netdev_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *)in_context;

    netdev_update(ctx);
    return 0;
}

static int ne_netdev_exit(struct flb_ne *ctx)
{
    if (ctx->netdev_ht) {
        flb_hash_table_destroy(ctx->netdev_ht);
    }
    return 0;
}

struct flb_ne_collector netdev_collector = {
    .name = "netdev",
    .cb_init = ne_netdev_init,
    .cb_update = ne_netdev_update,
    .cb_exit = ne_netdev_exit
};
