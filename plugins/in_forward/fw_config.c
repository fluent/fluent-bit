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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_input_plugin.h>

#include "fw.h"
#include "fw_conn.h"
#include "fw_config.h"

struct flb_in_fw_config *fw_config_init(struct flb_input_instance *i_ins)
{
    char tmp[16];
    int ret = -1;
    const char *p;
    struct flb_in_fw_config *config;

    config = flb_calloc(1, sizeof(struct flb_in_fw_config));
    if (!config) {
        flb_errno();
        return NULL;
    }

    ret = flb_input_config_map_set(i_ins, (void *)config);
    if (ret == -1) {
        flb_plg_error(i_ins, "config map set error");
        flb_free(config);
        return NULL;
    }

    p = flb_input_get_property("unix_path", i_ins);
    if (p == NULL) {
        /* Listen interface (if not set, defaults to 0.0.0.0:24224) */
        flb_input_net_default_listener("0.0.0.0", 24224, i_ins);
        config->listen = i_ins->host.listen;
        snprintf(tmp, sizeof(tmp) - 1, "%d", i_ins->host.port);
        config->tcp_port = flb_strdup(tmp);
    }
    else {
        /* Unix socket mode */
        if (config->unix_perm_str) {
            config->unix_perm = strtol(config->unix_perm_str, NULL, 8) & 07777;
        }
    }

    if (!config->unix_path) {
        flb_debug("[in_fw] Listen='%s' TCP_Port=%s",
                  config->listen, config->tcp_port);
    }

    if (!config->data_type_str) {
      config->data_type = FLB_INPUT_LOGS;
    } else {
      if (strcmp(config->data_type_str, "logs") == 0) {
        config->data_type = FLB_INPUT_LOGS;
      } else if (strcmp(config->data_type_str, "traces") == 0) {
        config->data_type = FLB_INPUT_TRACES;
      } else {
        flb_plg_error(i_ins, "Invalid value provided for data_type. Expected 'logs' or 'traces'");
        return NULL;
      }
    }
    return config;
}

int fw_config_destroy(struct flb_in_fw_config *config)
{
    if (config->coll_fd != -1) {
        flb_input_collector_delete(config->coll_fd, config->ins);

        config->coll_fd = -1;
    }

    if (config->downstream != NULL) {
        flb_downstream_destroy(config->downstream);
    }

    if (config->unix_path) {
        unlink(config->unix_path);
    }
    else {
        flb_free(config->tcp_port);
    }

    flb_free(config);

    return 0;
}
