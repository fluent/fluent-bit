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

#define _GNU_SOURCE

#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

#define NETSTAT_PROTO_NONE 0
#define NETSTAT_PROTO_TCP  1
#define NETSTAT_PROTO_UDP  2
#define NETSTAT_PROTO_TCPEXT 3
#define NETSTAT_PROTO_IPEXT 4

struct netstat_dynamic_metric {
    char *name;
    struct cmt_gauge *gauge;
    struct mk_list _head;
};

static void netstat_dynamic_metrics_destroy(struct flb_ne *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct netstat_dynamic_metric *entry;

    mk_list_foreach_safe(head, tmp, &ctx->netstat_dynamic_metrics) {
        entry = mk_list_entry(head, struct netstat_dynamic_metric, _head);
        mk_list_del(&entry->_head);
        if (entry->name != NULL) {
            flb_free(entry->name);
        }
        flb_free(entry);
    }
}

static int netstat_is_static_metric(const char *name)
{
    if (strcmp(name, "Tcp_CurrEstab") == 0 ||
        strcmp(name, "Tcp_ActiveOpens") == 0 ||
        strcmp(name, "Tcp_PassiveOpens") == 0 ||
        strcmp(name, "Tcp_RetransSegs") == 0 ||
        strcmp(name, "Udp_InDatagrams") == 0 ||
        strcmp(name, "Udp_NoPorts") == 0 ||
        strcmp(name, "Udp_InErrors") == 0 ||
        strcmp(name, "Udp_OutDatagrams") == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static struct cmt_gauge *netstat_dynamic_metric_get(struct flb_ne *ctx, const char *name)
{
    int ret;
    size_t name_len;
    char *metric_name;
    struct mk_list *head;
    struct netstat_dynamic_metric *entry;

    mk_list_foreach(head, &ctx->netstat_dynamic_metrics) {
        entry = mk_list_entry(head, struct netstat_dynamic_metric, _head);
        if (strcmp(entry->name, name) == 0) {
            return entry->gauge;
        }
    }

    entry = flb_calloc(1, sizeof(struct netstat_dynamic_metric));
    if (entry == NULL) {
        flb_errno();
        return NULL;
    }

    name_len = strlen(name);
    metric_name = flb_malloc(name_len + 1);
    if (metric_name == NULL) {
        flb_free(entry);
        return NULL;
    }

    ret = snprintf(metric_name, name_len + 1, "%s", name);
    if (ret < 0 || ret >= (int) (name_len + 1)) {
        flb_free(metric_name);
        flb_free(entry);
        return NULL;
    }

    entry->gauge = cmt_gauge_create(ctx->cmt, "node", "netstat", metric_name,
                                    "Network statistics from /proc/net/netstat.",
                                    0, NULL);
    if (entry->gauge == NULL) {
        flb_free(metric_name);
        flb_free(entry);
        return NULL;
    }

    entry->name = metric_name;
    mk_list_add(&entry->_head, &ctx->netstat_dynamic_metrics);

    return entry->gauge;
}

static int netstat_configure(struct flb_ne *ctx)
{
    mk_list_init(&ctx->netstat_dynamic_metrics);

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
    int idx;
    double d_val;
    struct cmt_gauge *metric;
    char metric_name[256];
    struct flb_slist_entry *proto_name;
    struct flb_slist_entry *key;
    struct flb_slist_entry *val;

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
        else if (proto == NETSTAT_PROTO_TCPEXT || proto == NETSTAT_PROTO_IPEXT) {
            for (idx = 1; idx < headers_count && idx < values_count; idx++) {
                key = flb_slist_entry_get(&headers, idx);
                val = flb_slist_entry_get(&values, idx);

                if (key == NULL || val == NULL) {
                    continue;
                }

                if (ne_utils_str_to_double(val->str, &d_val) != 0) {
                    continue;
                }

                if (proto == NETSTAT_PROTO_TCPEXT) {
                    snprintf(metric_name, sizeof(metric_name) - 1, "TcpExt_%s", key->str);
                }
                else {
                    snprintf(metric_name, sizeof(metric_name) - 1, "IpExt_%s", key->str);
                }
                metric_name[sizeof(metric_name) - 1] = '\0';

                metric = netstat_dynamic_metric_get(ctx, metric_name);
                if (metric != NULL) {
                    cmt_gauge_set(metric, ts, d_val, 0, NULL);
                }
            }
        }
        else {
            proto_name = flb_slist_entry_get(&headers, 0);
            if (proto_name != NULL && strlen(proto_name->str) > 1) {
                proto_name->str[strlen(proto_name->str) - 1] = '\0';
            }

            for (idx = 1; idx < headers_count && idx < values_count; idx++) {
                key = flb_slist_entry_get(&headers, idx);
                val = flb_slist_entry_get(&values, idx);

                if (key == NULL || val == NULL || proto_name == NULL) {
                    continue;
                }

                if (ne_utils_str_to_double(val->str, &d_val) != 0) {
                    continue;
                }

                snprintf(metric_name, sizeof(metric_name) - 1, "%s_%s",
                         proto_name->str, key->str);
                metric_name[sizeof(metric_name) - 1] = '\0';

                if (netstat_is_static_metric(metric_name) == FLB_TRUE) {
                    continue;
                }

                metric = netstat_dynamic_metric_get(ctx, metric_name);
                if (metric != NULL) {
                    cmt_gauge_set(metric, ts, d_val, 0, NULL);
                }
            }
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

    mk_list_foreach(head, &list) {
        line = mk_list_entry(head, struct flb_slist_entry, _head);

        if (prev_line != NULL) {
            if (strncmp(prev_line, "Tcp:", 4) == 0 && strncmp(line->str, "Tcp:", 4) == 0) {
                netstat_process_pair(ctx, prev_line, line->str, NETSTAT_PROTO_TCP, ts);
                netstat_process_pair(ctx, prev_line, line->str, NETSTAT_PROTO_NONE, ts);
                prev_line = NULL;
                continue;
            }
            else if (strncmp(prev_line, "Udp:", 4) == 0 && strncmp(line->str, "Udp:", 4) == 0) {
                netstat_process_pair(ctx, prev_line, line->str, NETSTAT_PROTO_UDP, ts);
                netstat_process_pair(ctx, prev_line, line->str, NETSTAT_PROTO_NONE, ts);
                prev_line = NULL;
                continue;
            }
            else if ((strncmp(prev_line, "Ip:", 3) == 0 && strncmp(line->str, "Ip:", 3) == 0) ||
                     (strncmp(prev_line, "Icmp:", 5) == 0 && strncmp(line->str, "Icmp:", 5) == 0) ||
                     (strncmp(prev_line, "IcmpMsg:", 8) == 0 && strncmp(line->str, "IcmpMsg:", 8) == 0) ||
                     (strncmp(prev_line, "UdpLite:", 8) == 0 && strncmp(line->str, "UdpLite:", 8) == 0)) {
                netstat_process_pair(ctx, prev_line, line->str, NETSTAT_PROTO_NONE, ts);
                prev_line = NULL;
                continue;
            }

            prev_line = NULL;
        }

        if (strchr(line->str, ':') != NULL) {
            prev_line = line->str;
        }
    }

    flb_slist_destroy(&list);

    mk_list_init(&list);
    ret = ne_utils_file_read_lines(ctx->path_procfs, "/net/netstat", &list);
    if (ret == 0) {
        prev_line = NULL;
        prev_proto = NETSTAT_PROTO_NONE;

        mk_list_foreach(head, &list) {
            line = mk_list_entry(head, struct flb_slist_entry, _head);

            if (prev_proto != NETSTAT_PROTO_NONE) {
                if (prev_proto == NETSTAT_PROTO_TCPEXT && strncmp(line->str, "TcpExt:", 7) == 0) {
                    netstat_process_pair(ctx, prev_line, line->str, NETSTAT_PROTO_TCPEXT, ts);
                    prev_proto = NETSTAT_PROTO_NONE;
                    prev_line = NULL;
                    continue;
                }
                else if (prev_proto == NETSTAT_PROTO_IPEXT && strncmp(line->str, "IpExt:", 6) == 0) {
                    netstat_process_pair(ctx, prev_line, line->str, NETSTAT_PROTO_IPEXT, ts);
                    prev_proto = NETSTAT_PROTO_NONE;
                    prev_line = NULL;
                    continue;
                }

                prev_proto = NETSTAT_PROTO_NONE;
                prev_line = NULL;
            }

            if (strncmp(line->str, "TcpExt:", 7) == 0) {
                prev_line = line->str;
                prev_proto = NETSTAT_PROTO_TCPEXT;
            }
            else if (strncmp(line->str, "IpExt:", 6) == 0) {
                prev_line = line->str;
                prev_proto = NETSTAT_PROTO_IPEXT;
            }
        }
    }

    flb_slist_destroy(&list);

    mk_list_init(&list);
    ret = ne_utils_file_read_lines(ctx->path_procfs, "/net/snmp6", &list);
    if (ret == 0) {
        mk_list_foreach(head, &list) {
            int i;
            int six_index;
            int metric_name_len;
            double d_val;
            char metric_name[256];
            char value[128];
            char raw_name[128];
            char proto_name[64];
            char field_name[64];
            struct cmt_gauge *metric;

            line = mk_list_entry(head, struct flb_slist_entry, _head);
            if (sscanf(line->str, "%127s %127s", raw_name, value) != 2) {
                continue;
            }

            six_index = -1;
            i = 0;
            while (raw_name[i] != '\0') {
                if (raw_name[i] == '6') {
                    six_index = i;
                    break;
                }
                i++;
            }
            if (six_index == -1 || six_index == 0 || raw_name[six_index + 1] == '\0') {
                continue;
            }

            snprintf(proto_name, sizeof(proto_name) - 1, "%.*s",
                     six_index + 1, raw_name);
            proto_name[sizeof(proto_name) - 1] = '\0';

            snprintf(field_name, sizeof(field_name) - 1, "%s",
                     raw_name + six_index + 1);
            field_name[sizeof(field_name) - 1] = '\0';

            metric_name_len = snprintf(metric_name, sizeof(metric_name) - 1, "%s_%s",
                                       proto_name, field_name);
            if (metric_name_len < 0) {
                continue;
            }
            metric_name[sizeof(metric_name) - 1] = '\0';

            if (ne_utils_str_to_double(value, &d_val) != 0) {
                continue;
            }

            metric = netstat_dynamic_metric_get(ctx, metric_name);
            if (metric != NULL) {
                cmt_gauge_set(metric, ts, d_val, 0, NULL);
            }
        }
        flb_slist_destroy(&list);
    }

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

static int ne_netstat_exit(struct flb_ne *ctx)
{
    if (ctx != NULL) {
        netstat_dynamic_metrics_destroy(ctx);
    }

    return 0;
}

struct flb_ne_collector netstat_collector = {
    .name = "netstat",
    .cb_init = ne_netstat_init,
    .cb_update = ne_netstat_update,
    .cb_exit = ne_netstat_exit
};
