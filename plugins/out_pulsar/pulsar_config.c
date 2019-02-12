/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include "./pulsar_config.h"

#include "../../include/fluent-bit/flb_utils.h"

static pulsar_compression_type convert_compression_setting_to_pulsar_enum(char
                                                                          const
                                                                          *const
                                                                          value)
{
    pulsar_compression_type result = pulsar_CompressionLZ4;

    if (!value) {
        return result;
    }

    if (strcasecmp(value, "none") == 0) {
        result = pulsar_CompressionNone;
    }
    else if (strcasecmp(value, "zlib") == 0) {
        result = pulsar_CompressionZLib;
    }
    else if (strcasecmp(value, "lz4") != 0) {
        flb_warn
            ("[out_pulsar] Invalid compression_type %s; defaulting to LZ4",
             value);
    }

    return result;
}

pulsar_producer_configuration_t
    *flb_pulsar_config_build_producer_config(struct flb_output_instance *
                                             const ins)
{
    pulsar_producer_configuration_t *cfg =
        pulsar_producer_configuration_create();

    char *producer_name = flb_output_get_property("producer_name", ins);
    if (producer_name) {
        pulsar_producer_configuration_set_producer_name(cfg, producer_name);
    }

    char *send_timeout = flb_output_get_property("send_timeout", ins);
    if (send_timeout) {
        int timeout = atoi(send_timeout);
        pulsar_producer_configuration_set_send_timeout(cfg, timeout);
    }

    char *compression_type = flb_output_get_property("compression_type", ins);
    pulsar_producer_configuration_set_compression_type
        (cfg, convert_compression_setting_to_pulsar_enum(compression_type));

    char *max_pending_messages =
        flb_output_get_property("max_pending_messages", ins);
    if (max_pending_messages) {
        int value = atoi(max_pending_messages);
        pulsar_producer_configuration_set_max_pending_messages(cfg, value);
    }

    char *batching_enabled = flb_output_get_property("batching_enabled", ins);
    if (batching_enabled) {
        int value = flb_utils_bool(batching_enabled);
        pulsar_producer_configuration_set_batching_enabled(cfg, value);
    }
    else {
        pulsar_producer_configuration_set_batching_enabled(cfg, 0);
    }

    char *batching_timeout =
        flb_output_get_property("batching_max_publish_delay_ms", ins);
    if (batching_timeout) {
        int value = atoi(batching_timeout);
        pulsar_producer_configuration_set_batching_max_publish_delay_ms(cfg,
                                                                        value);
    }

    pulsar_producer_configuration_set_block_if_queue_full(cfg, 1);

    return cfg;
}
