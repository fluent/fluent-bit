/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#include "fw.h"
#include "fw_conn.h"
#include "fw_config.h"

struct flb_in_fw_config *fw_config_init(struct mk_rconf *conf)
{
    struct mk_rconf_section *section;
    struct flb_in_fw_config *config;

    config = malloc(sizeof(struct flb_in_fw_config));
    memset(config, '\0', sizeof(struct flb_in_fw_config));

    if (conf) {
      section = mk_rconf_section_get(conf, "IN_FORWARD");
      if (section) {
        /* Validate TD section keys */
          config->listen = mk_rconf_section_get_key(section,
                                                    "Listen", MK_RCONF_STR);
          config->tcp_port = mk_rconf_section_get_key(section,
                                                      "Port", MK_RCONF_STR);
          config->buffer_size = (size_t) mk_rconf_section_get_key(section,
                                                                  "Buffer",
                                                                  MK_RCONF_NUM);
          config->buffer_size *= 1024;
      }
    }

    if (!config->listen) {
        config->listen = strdup("0.0.0.0");
    }
    if (!config->tcp_port) {
        config->tcp_port = strdup("24224");
    }
    if (config->buffer_size < FLB_IN_FW_CHUNK) {
        config->buffer_size = FLB_IN_FW_CHUNK;
    }

    flb_info("[in_fw] Listen='%s' TCP_Port=%s",
             config->listen, config->tcp_port);

    return config;
}

int fw_config_destroy(struct flb_in_fw_config *config)
{
    free(config->listen);
    free(config->tcp_port);
    free(config);

    return 0;
}
