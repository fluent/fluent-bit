/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2022-2026 The Fluent Bit Authors
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
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include "we.h"
#include "we_net.h"
#include "we_util.h"
#include "we_metric.h"
#include "we_perflib.h"


struct we_perflib_metric_source net_metric_sources[] = {
        WE_PERFLIB_METRIC_SOURCE("bytes_received_total",
                                 "Bytes Received/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("bytes_sent_total",
                                 "Bytes Sent/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("bytes_total",
                                 "Bytes Total/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("packets_outbound_discarded_total",
                                 "Packets Outbound Discarded",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("packets_outbound_errors_total",
                                 "Packets Outbound Errors",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("packets_received_discarded_total",
                                 "Packets Received Discarded",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("packets_received_errors_total",
                                 "Packets Received Errors",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("packets_received_total",
                                 "Packets Received/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("packets_received_unknown_total",
                                 "Packets Received Unknown",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("packets_total",
                                 "Packets/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("packets_sent_total",
                                 "Packets Sent/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("current_bandwidth_bits",
                                 "Current Bandwidth",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("output_queue_length_packets",
                                 "Output Queue Length",
                                 NULL),

        WE_PERFLIB_TERMINATOR_SOURCE()
    };

struct we_perflib_metric_spec net_metric_specs[] = {
        WE_PERFLIB_COUNTER_SPEC("bytes_received_total",
                                "Total amount of received bytes",
                                "nic"),

        WE_PERFLIB_COUNTER_SPEC("bytes_sent_total",
                                "Total amount of sent bytes",
                                "nic"),

        WE_PERFLIB_COUNTER_SPEC("bytes_total",
                                "Total amount of bytes",
                                "nic"),

        WE_PERFLIB_COUNTER_SPEC("packets_outbound_discarded_total",
                                "Total amount of outbound discarded bytes",
                                "nic"),

        WE_PERFLIB_COUNTER_SPEC("packets_outbound_errors_total",
                                "Total number of outbound errors",
                                "nic"),

        WE_PERFLIB_COUNTER_SPEC("packets_received_discarded_total",
                                "Total amount of received discarded bytes",
                                "nic"),

        WE_PERFLIB_COUNTER_SPEC("packets_received_errors_total",
                                "Total number of received packets' errors",
                                "nic"),

        WE_PERFLIB_COUNTER_SPEC("packets_received_total",
                                "Total number of received packets",
                                "nic"),

        WE_PERFLIB_COUNTER_SPEC("packets_received_unknown_total",
                                "Total number of received unknown",
                                "nic"),

        WE_PERFLIB_COUNTER_SPEC("packets_total",
                                "Total amount of packets",
                                "nic"),

        WE_PERFLIB_COUNTER_SPEC("packets_sent_total",
                                "Total amount of sent packets",
                                "nic"),

        WE_PERFLIB_GAUGE_SPEC("current_bandwidth_bits",
                                "Current Bandwidth /bits",
                                "nic"),

        WE_PERFLIB_GAUGE_SPEC("output_queue_length_packets",
                              "A length of output queue packets",
                              "nic"),

        WE_PERFLIB_TERMINATOR_SPEC()
    };


int we_net_init(struct flb_we *ctx)
{
    struct we_perflib_metric_source *metric_sources;
    int                              result;

    ctx->net.operational = FLB_FALSE;

    ctx->net.metrics = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 32, 128);

    if (ctx->net.metrics == NULL) {
        flb_plg_error(ctx->ins, "could not create metrics hash table");

        return -1;
    }

    result = we_initialize_perflib_metric_specs(ctx->cmt,
                                                ctx->net.metrics,
                                                "windows",
                                                "net",
                                                &ctx->net.metric_specs,
                                                net_metric_specs);

    if (result != 0) {
        flb_plg_error(ctx->ins, "could not initialize net metric specs");

        return -2;
    }

    ctx->net.query = (char *) "Network Interface";

    result = we_initialize_perflib_metric_sources(ctx->net.metrics,
                                                  &ctx->net.metric_sources,
                                                  net_metric_sources);

    if (result != 0) {
        flb_plg_error(ctx->ins, "could not initialize net metric sources");

        we_deinitialize_perflib_metric_specs(ctx->net.metric_specs);
        flb_free(ctx->net.metric_specs);

        return -3;
    }

    ctx->net.operational = FLB_TRUE;

    return 0;
}

int we_net_exit(struct flb_we *ctx)
{
    we_deinitialize_perflib_metric_sources(ctx->net.metric_sources);
    we_deinitialize_perflib_metric_specs(ctx->net.metric_specs);

    flb_free(ctx->net.metric_sources);
    flb_free(ctx->net.metric_specs);

    ctx->net.operational = FLB_FALSE;

    return 0;
}

static int net_regex_match(struct flb_regex *regex, char *instance_name)
{
    if (regex == NULL) {
        return 0;
    }
    return flb_regex_match(regex, instance_name, strlen(instance_name));
}

int we_net_instance_hook(char *instance_name, struct flb_we *ctx)
{
    if (strcasestr(instance_name, "Total") != NULL) {
        return 1;
    }

    if (!net_regex_match(ctx->allowing_nic_regex, instance_name)) {
        return 1;
    }

    return 0;
}

int we_net_label_prepend_hook(char                           **label_list,
                              size_t                           label_list_size,
                              size_t                          *label_count,
                              struct we_perflib_metric_source *metric_source,
                              char                            *instance_name,
                              struct we_perflib_counter       *counter)
{
    if (label_count == NULL) {
        return -1;
    }

    if (*label_count >= label_list_size) {
        return -2;
    }

    label_list[(*label_count)++] = instance_name;

    return 0;
}

int we_net_update(struct flb_we *ctx)
{
    if (!ctx->net.operational) {
        flb_plg_error(ctx->ins, "net collector not yet in operational state");

        return -1;
    }

    return we_perflib_update_counters(ctx,
                                      ctx->net.query,
                                      ctx->net.metric_sources,
                                      we_net_instance_hook,
                                      we_net_label_prepend_hook);
}
