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

#include <stdlib.h>

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>

#include "mqtt.h"
#include "mqtt_config.h"

struct flb_in_mqtt_config *mqtt_config_init(struct flb_input_instance *ins)
{
    char tmp[16];
    struct flb_in_mqtt_config *config;

    config = flb_calloc(1, sizeof(struct flb_in_mqtt_config));
    if (!config) {
        flb_errno();
        return NULL;
    }

    /* Listen interface (if not set, defaults to 0.0.0.0) */
    flb_input_net_default_listener("0.0.0.0", 1883, ins);

    /* Map 'listen' and 'port' into the local context */
    config->listen = ins->host.listen;
    snprintf(tmp, sizeof(tmp) - 1, "%d", ins->host.port);
    config->tcp_port = flb_strdup(tmp);

    mk_list_init(&config->conns);
    return config;
}

void mqtt_config_free(struct flb_in_mqtt_config *config)
{
    if (config->server_fd > 0) {
        close(config->server_fd);
    }
    flb_free(config->tcp_port);
    flb_free(config);
}
