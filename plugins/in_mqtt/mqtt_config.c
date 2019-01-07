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

#include <stdlib.h>

#include <fluent-bit/flb_utils.h>

#include "mqtt.h"
#include "mqtt_config.h"

struct flb_in_mqtt_config *mqtt_config_init(struct flb_input_instance *i_ins)
{
    char tmp[16];
    char *listen;
    struct flb_in_mqtt_config *config;

    config = flb_malloc(sizeof(struct flb_in_mqtt_config));
    memset(config, '\0', sizeof(struct flb_in_mqtt_config));

    /* Listen interface (if not set, defaults to 0.0.0.0) */
    if (!i_ins->host.listen) {
        listen = flb_input_get_property("listen", i_ins);
        if (listen) {
            config->listen = flb_strdup(listen);
        }
        else {
            config->listen = flb_strdup("0.0.0.0");
        }
    }
    else {
        config->listen = i_ins->host.listen;
    }

    /* Listener TCP Port */
    if (i_ins->host.port == 0) {
        config->tcp_port = flb_strdup("1883");
    }
    else {
        snprintf(tmp, sizeof(tmp) - 1, "%d", i_ins->host.port);
        config->tcp_port = flb_strdup(tmp);
    }

    flb_debug("[in_mqtt] Listen='%s' TCP_Port=%s",
              config->listen, config->tcp_port);

    return config;
}

void mqtt_config_free(struct flb_in_mqtt_config *config)
{
    if (config->server_fd > 0) {
        close(config->server_fd);
    }
    flb_free(config->listen);
    flb_free(config->tcp_port);
    flb_free(config);
}
