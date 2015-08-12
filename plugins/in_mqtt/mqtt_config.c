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

#include <stdlib.h>
#include <mk_core/mk_core.h>

#include <fluent-bit/flb_utils.h>

#include "mqtt.h"
#include "mqtt_config.h"

struct flb_in_mqtt_config *mqtt_config_init(struct mk_rconf *conf)
{
    struct mk_rconf_section *section;
    struct flb_in_mqtt_config *config;

    config = malloc(sizeof(struct flb_in_mqtt_config));

    if (conf) {
      section = mk_rconf_section_get(conf, "MQTT");
      if (section) {
        /* Validate TD section keys */
        config->listen = mk_rconf_section_get_key(section, "Listen", MK_RCONF_STR);
        config->tcp_port = mk_rconf_section_get_key(section, "Port", MK_RCONF_STR);
      }
    }

    if (!config->listen) {
      config->listen = strdup("0.0.0.0");
    }
    if (!config->tcp_port) {
      config->tcp_port = strdup("1883");
    }

    flb_debug("MQTT Listen='%s' TCP_Port=%s",
              config->listen, config->tcp_port);

    return config;
}
