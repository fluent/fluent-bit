/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2025 The Fluent Bit Authors
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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include "we.h"
#include "we_wmi.h"
#include "we_wmi_tcp.h"
#include "we_util.h"
#include "we_metric.h"

#include <iphlpapi.h>

const char* TCP_STATE_STRINGS[] = {
    "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT",
    "CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING", "DELETE_TCB", "UNKNOWN"
};

static inline int windows_state_to_index(int state)
{
    switch(state) {
        case MIB_TCP_STATE_ESTAB:
            return 0;
        case MIB_TCP_STATE_SYN_SENT:
            return 1;
        case MIB_TCP_STATE_SYN_RCVD:
            return 2;
        case MIB_TCP_STATE_FIN_WAIT1:
            return 3;
        case MIB_TCP_STATE_FIN_WAIT2:
            return 4;
        case MIB_TCP_STATE_TIME_WAIT:
            return 5;
        /* MIB_TCP_STATE_CLOSED is 1 */
        case MIB_TCP_STATE_CLOSE_WAIT:
            return 7;
        case MIB_TCP_STATE_LAST_ACK:
            return 8;
        case MIB_TCP_STATE_LISTEN:
            return 9;
        case MIB_TCP_STATE_CLOSING:
            return 10;
        case MIB_TCP_STATE_DELETE_TCB:
            return 11;
        default:                      
            return 12;
    }
}

static int we_tcp_get_state_metrics(struct flb_we *ctx, const char *af_label)
{
    PMIB_TCPTABLE2 tcp_table = NULL;
    ULONG buffer_size = 0;
    DWORD result;
    DWORD idx = 0;
    int state_index;
    int i = 0;
    const char *state_label;
    uint64_t timestamp = cfl_time_now();
    int af_family = (strcmp(af_label, "ipv4") == 0) ? AF_INET : AF_INET6;
    unsigned int state_counts[13] = {0};
    const char *labels[2];

    result = GetExtendedTcpTable(NULL, &buffer_size, FALSE, af_family, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        flb_plg_error(ctx->ins, "TCP state metrics: error getting buffer size: %lu", result);
        return -1;
    }

    tcp_table = (PMIB_TCPTABLE2)flb_malloc(buffer_size);
    if (tcp_table == NULL) {
        flb_plg_error(ctx->ins, "TCP state metrics: could not allocate buffer");
        return -1;
    }

    result = GetExtendedTcpTable(tcp_table, &buffer_size, FALSE, af_family, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != NO_ERROR) {
        flb_plg_error(ctx->ins, "TCP state metrics: error getting table: %lu", result);
        flb_free(tcp_table);
        return -1;
    }

    for (idx = 0; idx < tcp_table->dwNumEntries; idx++) {
        state_index = windows_state_to_index(tcp_table->table[idx].dwState);
        state_counts[state_index]++;
    }

    flb_free(tcp_table);

    for (i = 0; i < 13; i++) {
        if (state_counts[i] > 0) {
            state_label = TCP_STATE_STRINGS[i];
            labels[0] = af_label;
            labels[1] = state_label;
            cmt_gauge_set(ctx->wmi_tcp->connections_state, timestamp,
                          (double)state_counts[i], 2, (char **)labels);
        }
    }

    return 0;
}

int we_wmi_tcp_init(struct flb_we *ctx)
{
    ctx->wmi_tcp = flb_calloc(1, sizeof(struct we_wmi_tcp_counters));
    if (!ctx->wmi_tcp) {
        flb_errno();
        return -1;
    }
    ctx->wmi_tcp->operational = FLB_FALSE;

    struct cmt_gauge *g;
    struct cmt_counter *c;
    char *wmi_label[] = {"af"};
    char *state_labels[] = {"af", "state"};

    g = cmt_gauge_create(ctx->cmt, "windows", "tcp",
                         "connections_state",
                         "Number of connections in a given state.",
                         2, state_labels);
    if (!g) {
        return -1;
    }
    ctx->wmi_tcp->connections_state = g;

    c = cmt_counter_create(ctx->cmt, "windows", "tcp", 
                           "connection_failures_total",
                           "Total number of connection failures.",
                           1, wmi_label);
    if (!c) { 
        return -1; 
    }
    ctx->wmi_tcp->connection_failures = c;

    g = cmt_gauge_create(ctx->cmt, "windows", "tcp", 
                         "connections_active",
                         "Number of active TCP connections.",
                         1, wmi_label);
    if (!g) { 
        return -1; 
    }
    ctx->wmi_tcp->connections_active = g;

    c = cmt_counter_create(ctx->cmt, "windows", "tcp", 
                           "connections_established_total",
                           "Total number of TCP connections established.",
                           1, wmi_label);
    if (!c) { 
        return -1; 
    }
    ctx->wmi_tcp->connections_established = c;

    c = cmt_counter_create(ctx->cmt, "windows", "tcp",
                           "connections_passive_total",
                           "Total number of passive TCP connections.",
                           1, wmi_label);
    if (!c) { 
        return -1; 
    }
    ctx->wmi_tcp->connections_passive = c;

    c = cmt_counter_create(ctx->cmt, "windows", "tcp",
                           "connections_reset_total",
                           "Total number of reset TCP connections.",
                           1, wmi_label);
    if (!c) { 
        return -1; 
    }
    ctx->wmi_tcp->connections_reset = c;

    g = cmt_gauge_create(ctx->cmt, "windows", "tcp",
                         "segments_total",
                         "Total TCP segments sent or received per second.",
                         1, wmi_label);
    if (!g) { 
        return -1; 
    }
    ctx->wmi_tcp->segments_total = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "tcp",
                         "segments_total",
                         "TCP segments received per second.",
                         1, wmi_label);
    if (!g) { 
        return -1; 
    }
    ctx->wmi_tcp->segments_received_total = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "tcp",
                         "segments_retransmitted_total",
                         "TCP segments retransmitted per second.",
                         1, wmi_label);
    if (!g) { 
        return -1; 
    }
    ctx->wmi_tcp->segments_retransmitted_total = g;
    
    g = cmt_gauge_create(ctx->cmt, "windows", "tcp",
                         "segments_sent_total",
                         "TCP segments sent per second.",
                         1, wmi_label);
    if (!g) { 
        return -1; 
    }
    ctx->wmi_tcp->segments_sent_total = g;

    /* NOTE: Once we tried to use perflib to obtain those of metrics for TCPv4 and TCPv6,
     * there is no way to process the correct metrics.
     * Sometimes, they are not publised under the normal perflib registery data.
     * So, we use WMI instead of perflib here.
     */
    /* Setup TCPv4 Query Spec */
    ctx->wmi_tcp->v4_info = flb_calloc(1, sizeof(struct wmi_query_spec));
    if (!ctx->wmi_tcp->v4_info) {
        flb_errno();
        return -1;
    }
    ctx->wmi_tcp->v4_info->wmi_counter = "Win32_PerfFormattedData_TCPIP_TCPv4";

    /* Setup TCPv6 Query Spec */
    ctx->wmi_tcp->v6_info = flb_calloc(1, sizeof(struct wmi_query_spec));
    if (!ctx->wmi_tcp->v6_info) {
        flb_errno();
        return -1;
    }
    ctx->wmi_tcp->v6_info->wmi_counter = "Win32_PerfFormattedData_TCPIP_TCPv6";
    
    ctx->wmi_tcp->operational = FLB_TRUE;
    return 0;
}

int we_wmi_tcp_exit(struct flb_we *ctx)
{
    if (ctx->wmi_tcp) {
        ctx->wmi_tcp->operational = FLB_FALSE;
        flb_free(ctx->wmi_tcp->v4_info);
        flb_free(ctx->wmi_tcp->v6_info);
        flb_free(ctx->wmi_tcp);
    }
    return 0;
}

int we_wmi_tcp_update(struct flb_we *ctx)
{
    uint64_t timestamp = 0;
    IEnumWbemClassObject* enumerator = NULL;
    IWbemClassObject *class_obj = NULL;
    ULONG ret = 0;
    double val = 0;
    HRESULT hr;
    char *ipv4_label = "ipv4";
    char *ipv6_label = "ipv6";

    if (!ctx->wmi_tcp->operational) {
        flb_plg_error(ctx->ins, "WMI TCP collector not yet in operational state");
        return -1;
    }

    /* Collect the new state-based metrics first. This does not require WMI coinitialization. */
    we_tcp_get_state_metrics(ctx, ipv4_label);
    we_tcp_get_state_metrics(ctx, ipv6_label);

    if (FAILED(we_wmi_coinitialize(ctx))) {
        return -1;
    }

    timestamp = cfl_time_now();

    if (SUCCEEDED(we_wmi_execute_query(ctx, ctx->wmi_tcp->v4_info, &enumerator))) {
        hr = enumerator->lpVtbl->Next(enumerator, WBEM_INFINITE, 1, &class_obj, &ret);
        if(0 != ret) {
            val = we_wmi_get_property_value(ctx, "ConnectionFailures", class_obj);
            cmt_counter_set(ctx->wmi_tcp->connection_failures, timestamp, val, 1, &ipv4_label);

            val = we_wmi_get_property_value(ctx, "ConnectionsActive", class_obj);
            cmt_gauge_set(ctx->wmi_tcp->connections_active, timestamp, val, 1, &ipv4_label);
            
            val = we_wmi_get_property_value(ctx, "ConnectionsEstablished", class_obj);
            cmt_counter_set(ctx->wmi_tcp->connections_established, timestamp, val, 1, &ipv4_label);

            val = we_wmi_get_property_value(ctx, "ConnectionsPassive", class_obj);
            cmt_counter_set(ctx->wmi_tcp->connections_passive, timestamp, val, 1, &ipv4_label);

            val = we_wmi_get_property_value(ctx, "ConnectionsReset", class_obj);
            cmt_counter_set(ctx->wmi_tcp->connections_reset, timestamp, val, 1, &ipv4_label);

            val = we_wmi_get_property_value(ctx, "SegmentsPersec", class_obj);
            cmt_gauge_set(ctx->wmi_tcp->segments_total, timestamp, val, 1, &ipv4_label);

            val = we_wmi_get_property_value(ctx, "SegmentsReceivedPersec", class_obj);
            cmt_gauge_set(ctx->wmi_tcp->segments_received_total, timestamp, val, 1, &ipv4_label);

            val = we_wmi_get_property_value(ctx, "SegmentsRetransmittedPersec", class_obj);
            cmt_gauge_set(ctx->wmi_tcp->segments_retransmitted_total, timestamp, val, 1, &ipv4_label);

            val = we_wmi_get_property_value(ctx, "SegmentsSentPersec", class_obj);
            cmt_gauge_set(ctx->wmi_tcp->segments_sent_total, timestamp, val, 1, &ipv4_label);

            class_obj->lpVtbl->Release(class_obj);
        }
        enumerator->lpVtbl->Release(enumerator);
    }

    if (SUCCEEDED(we_wmi_execute_query(ctx, ctx->wmi_tcp->v6_info, &enumerator))) {
        hr = enumerator->lpVtbl->Next(enumerator, WBEM_INFINITE, 1, &class_obj, &ret);
        if(0 != ret) {
            val = we_wmi_get_property_value(ctx, "ConnectionFailures", class_obj);
            cmt_counter_set(ctx->wmi_tcp->connection_failures, timestamp, val, 1, &ipv6_label);

            val = we_wmi_get_property_value(ctx, "ConnectionsActive", class_obj);
            cmt_gauge_set(ctx->wmi_tcp->connections_active, timestamp, val, 1, &ipv6_label);
            
            val = we_wmi_get_property_value(ctx, "ConnectionsEstablished", class_obj);
            cmt_counter_set(ctx->wmi_tcp->connections_established, timestamp, val, 1, &ipv6_label);

            val = we_wmi_get_property_value(ctx, "ConnectionsPassive", class_obj);
            cmt_counter_set(ctx->wmi_tcp->connections_passive, timestamp, val, 1, &ipv6_label);

            val = we_wmi_get_property_value(ctx, "ConnectionsReset", class_obj);
            cmt_counter_set(ctx->wmi_tcp->connections_reset, timestamp, val, 1, &ipv6_label);

            val = we_wmi_get_property_value(ctx, "SegmentsPersec", class_obj);
            cmt_gauge_set(ctx->wmi_tcp->segments_total, timestamp, val, 1, &ipv6_label);

            val = we_wmi_get_property_value(ctx, "SegmentsReceivedPersec", class_obj);
            cmt_gauge_set(ctx->wmi_tcp->segments_received_total, timestamp, val, 1, &ipv6_label);

            val = we_wmi_get_property_value(ctx, "SegmentsRetransmittedPersec", class_obj);
            cmt_gauge_set(ctx->wmi_tcp->segments_retransmitted_total, timestamp, val, 1, &ipv6_label);

            val = we_wmi_get_property_value(ctx, "SegmentsSentPersec", class_obj);
            cmt_gauge_set(ctx->wmi_tcp->segments_sent_total, timestamp, val, 1, &ipv6_label);

            class_obj->lpVtbl->Release(class_obj);
        }
        enumerator->lpVtbl->Release(enumerator);
    }

    we_wmi_cleanup(ctx);
    return 0;
}