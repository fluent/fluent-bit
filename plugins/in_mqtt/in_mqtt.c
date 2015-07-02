/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include "in_mqtt.h"

/* Initialize plugin */
int in_mqtt_init(struct flb_config *config)
{
    int fd;
    int ret;
    struct flb_in_mqtt_config *ctx;

    /* Allocate space for the configuration */
    ctx = malloc(sizeof(struct flb_in_mqtt_config));
    if (!ctx) {
        return -1;
    }

    /* Set the context */
    ret = flb_input_set_context("mqtt", ctx, config);
    if (ret == -1) {
        flb_utils_error_c("Could not set configuration for MQTT input plugin");
    }

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_event("mqtt",
                                        in_mqtt_collect,
                                        ctx->server_fd,
                                        config);
    if (ret == -1) {
        flb_utils_error_c("Could not set collector for MQTT input plugin");
    }

    return 0;
}


int in_mqtt_collect(struct flb_config *config, void *in_context)
{
    int bytes;
    int out_size;
    char *pack;
    struct flb_in_mqtt_config *ctx = in_context;

    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_mqtt_plugin = {
    .name         = "mqtt",
    .description  = "MQTT, listen for Publish messages",
    .cb_init      = in_mqtt_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_mqtt_collect,
    .cb_flush_buf = NULL
};
