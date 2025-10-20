/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

#define _GNU_SOURCE

#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

#define NETSTAT_PROTO_NONE 0
#define NETSTAT_PROTO_TCP  1
#define NETSTAT_PROTO_UDP  2

static int netstat_configure(struct flb_ne *ctx)
{
    ctx->netstat_Tcp_CurrEstab =
        cmt_gauge_create(ctx->cmt, "node", "netstat", "Tcp_CurrEstab",
                         "Number of TCP connections in ESTABLISHED or CLOSE-WAIT state.",
                         0, NULL);
    if (!ctx->netstat_Tcp_CurrEstab) {
        return -1;
    }

    ctx->netstat_Tcp_ActiveOpens =
        cmt_counter_create(ctx->cmt, "node", "netstat", "Tcp_ActiveOpens",
                           "Total number of TCP connections that have made a direct transition to SYN-SENT state.",
                           0, NULL);
    if (!ctx->netstat_Tcp_ActiveOpens) {
        return -1;
    }

    ctx->netstat_Tcp_PassiveOpens =
        cmt_counter_create(ctx->cmt, "node", "netstat", "Tcp_PassiveOpens",
                           "Total number of TCP connections made in response to incoming SYN requests.",
                           0, NULL);
    if (!ctx->netstat_Tcp_PassiveOpens) {
        return -1;
    }

    ctx->netstat_Tcp_RetransSegs =
        cmt_counter_create(ctx->cmt, "node", "netstat", "Tcp_RetransSegs",
                           "Total number of TCP segments retransmitted.",
                           0, NULL);
    if (!ctx->netstat_Tcp_RetransSegs) {
        return -1;
    }

    ctx->netstat_Udp_InDatagrams =
        cmt_counter_create(ctx->cmt, "node", "netstat", "Udp_InDatagrams",
                           "Total number of received UDP datagrams delivered to UDP users.",
                           0, NULL);
    if (!ctx->netstat_Udp_InDatagrams) {
        return -1;
    }

    ctx->netstat_Udp_InErrors =
        cmt_counter_create(ctx->cmt, "node", "netstat", "Udp_InErrors",
                           "Total number of UDP datagrams that could not be delivered.",
                           0, NULL);
    if (!ctx->netstat_Udp_InErrors) {
        return -1;
    }

    ctx->netstat_Udp_OutDatagrams =
        cmt_counter_create(ctx->cmt, "node", "netstat", "Udp_OutDatagrams",
                           "Total number of UDP datagrams sent from this host.",
                           0, NULL);
    if (!ctx->netstat_Udp_OutDatagrams) {
        return -1;
    }

    ctx->netstat_Udp_NoPorts =
        cmt_counter_create(ctx->cmt, "node", "netstat", "Udp_NoPorts",
                           "Total number of received UDP datagrams for which there was no application at the destination port.",
                           0, NULL);
    if (!ctx->netstat_Udp_NoPorts) {
        return -1;
    }

    return 0;
}

static void netstat_process_tcp(struct flb_ne *ctx,
                                struct mk_list *headers, int headers_count,
                                struct mk_list *values, int values_count,
                                uint64_t ts)
{
    int idx;
    double d_val;
    struct flb_slist_entry *key;
    struct flb_slist_entry *val;

    for (idx = 1; idx < headers_count && idx < values_count; idx++) {
        key = flb_slist_entry_get(headers, idx);
        val = flb_slist_entry_get(values, idx);

        if (!key || !val) {
            continue;
        }

        if (ne_utils_str_to_double(val->str, &d_val) != 0) {
            continue;
        }

        if (strcmp(key->str, "CurrEstab") == 0 && ctx->netstat_Tcp_CurrEstab) {
            cmt_gauge_set(ctx->netstat_Tcp_CurrEstab, ts, d_val, 0, NULL);
        }
        else if (strcmp(key->str, "ActiveOpens") == 0 && ctx->netstat_Tcp_ActiveOpens) {
            cmt_counter_set(ctx->netstat_Tcp_ActiveOpens, ts, d_val, 0, NULL);
        }
        else if (strcmp(key->str, "PassiveOpens") == 0 && ctx->netstat_Tcp_PassiveOpens) {
            cmt_counter_set(ctx->netstat_Tcp_PassiveOpens, ts, d_val, 0, NULL);
        }
        else if (strcmp(key->str, "RetransSegs") == 0 && ctx->netstat_Tcp_RetransSegs) {
            cmt_counter_set(ctx->netstat_Tcp_RetransSegs, ts, d_val, 0, NULL);
        }
    }
}

static void netstat_process_udp(struct flb_ne *ctx,
                                struct mk_list *headers, int headers_count,
                                struct mk_list *values, int values_count,
                                uint64_t ts)
{
    int idx;
    double d_val;
    struct flb_slist_entry *key;
    struct flb_slist_entry *val;

    for (idx = 1; idx < headers_count && idx < values_count; idx++) {
        key = flb_slist_entry_get(headers, idx);
        val = flb_slist_entry_get(values, idx);

        if (!key || !val) {
            continue;
        }

        if (ne_utils_str_to_double(val->str, &d_val) != 0) {
            continue;
        }

        if (strcmp(key->str, "InDatagrams") == 0 && ctx->netstat_Udp_InDatagrams) {
            cmt_counter_set(ctx->netstat_Udp_InDatagrams, ts, d_val, 0, NULL);
        }
        else if (strcmp(key->str, "NoPorts") == 0 && ctx->netstat_Udp_NoPorts) {
            cmt_counter_set(ctx->netstat_Udp_NoPorts, ts, d_val, 0, NULL);
        }
        else if (strcmp(key->str, "InErrors") == 0 && ctx->netstat_Udp_InErrors) {
            cmt_counter_set(ctx->netstat_Udp_InErrors, ts, d_val, 0, NULL);
        }
        else if (strcmp(key->str, "OutDatagrams") == 0 && ctx->netstat_Udp_OutDatagrams) {
            cmt_counter_set(ctx->netstat_Udp_OutDatagrams, ts, d_val, 0, NULL);
        }
    }
}

static void netstat_process_pair(struct flb_ne *ctx,
                                 const char *header_line,
                                 const char *value_line,
                                 int proto,
                                 uint64_t ts)
{
    int headers_count;
    int values_count;
    struct mk_list headers;
    struct mk_list values;

    mk_list_init(&headers);
    mk_list_init(&values);

    headers_count = flb_slist_split_string(&headers, header_line, ' ', -1);
    values_count = flb_slist_split_string(&values, value_line, ' ', -1);

    if (headers_count > 1 && values_count > 1) {
        if (proto == NETSTAT_PROTO_TCP) {
            netstat_process_tcp(ctx, &headers, headers_count, &values, values_count, ts);
        }
        else if (proto == NETSTAT_PROTO_UDP) {
            netstat_process_udp(ctx, &headers, headers_count, &values, values_count, ts);
        }
    }

    flb_slist_destroy(&headers);
    flb_slist_destroy(&values);
}

static int netstat_update(struct flb_ne *ctx)
{
    int ret;
    uint64_t ts;
    struct mk_list list;
    struct mk_list *head;
    struct flb_slist_entry *line;
    const char *prev_line;
    int prev_proto;

    mk_list_init(&list);
    ret = ne_utils_file_read_lines(ctx->path_procfs, "/net/snmp", &list);
    if (ret == -1) {
        return -1;
    }

    ts = cfl_time_now();
    prev_line = NULL;
    prev_proto = NETSTAT_PROTO_NONE;

    mk_list_foreach(head, &list) {
        line = mk_list_entry(head, struct flb_slist_entry, _head);

        if (prev_proto != NETSTAT_PROTO_NONE) {
            if (prev_proto == NETSTAT_PROTO_TCP && strncmp(line->str, "Tcp:", 4) == 0) {
                netstat_process_pair(ctx, prev_line, line->str, NETSTAT_PROTO_TCP, ts);
                prev_proto = NETSTAT_PROTO_NONE;
                prev_line = NULL;
                continue;
            }
            else if (prev_proto == NETSTAT_PROTO_UDP && strncmp(line->str, "Udp:", 4) == 0) {
                netstat_process_pair(ctx, prev_line, line->str, NETSTAT_PROTO_UDP, ts);
                prev_proto = NETSTAT_PROTO_NONE;
                prev_line = NULL;
                continue;
            }

            prev_proto = NETSTAT_PROTO_NONE;
            prev_line = NULL;
        }

        if (strncmp(line->str, "Tcp:", 4) == 0) {
            prev_line = line->str;
            prev_proto = NETSTAT_PROTO_TCP;
        }
        else if (strncmp(line->str, "Udp:", 4) == 0) {
            prev_line = line->str;
            prev_proto = NETSTAT_PROTO_UDP;
        }
    }

    flb_slist_destroy(&list);
    return 0;
}

static int ne_netstat_init(struct flb_ne *ctx)
{
    return netstat_configure(ctx);
}

static int ne_netstat_update(struct flb_input_instance *ins,
                             struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *) in_context;

    netstat_update(ctx);
    return 0;
}

struct flb_ne_collector netstat_collector = {
    .name = "netstat",
    .cb_init = ne_netstat_init,
    .cb_update = ne_netstat_update,
    .cb_exit = NULL
};

