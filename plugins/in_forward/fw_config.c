/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

static void fw_destroy_shared_key(struct flb_in_fw_config *config)
{
    if (config->owns_shared_key && config->shared_key) {
        flb_sds_destroy(config->shared_key);
    }

    config->shared_key = NULL;
    config->owns_shared_key = FLB_FALSE;
}

static int fw_create_empty_shared_key(struct flb_in_fw_config *config,
                                      struct flb_input_instance *i_ins)
{
    flb_sds_t empty_key = flb_sds_create("");
    if (!empty_key) {
        flb_plg_error(i_ins, "empty shared_key alloc failed");
        return -1;
    }
    else {
        if (config->owns_shared_key && config->shared_key) {
            flb_sds_destroy(config->shared_key);
        }
        config->shared_key = empty_key;
        config->owns_shared_key = FLB_TRUE;
    }

    return 0;
}

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
    config->coll_fd = -1;

    config->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (config->log_encoder == NULL) {
        flb_plg_error(i_ins, "could not initialize event encoder");
        fw_config_destroy(config);

        return NULL;
    }

    config->log_decoder = flb_log_event_decoder_create(NULL, 0);

    if (config->log_decoder == NULL) {
        flb_plg_error(i_ins, "could not initialize event decoder");
        fw_config_destroy(config);

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

    /* Shared Key */
    if (config->empty_shared_key) {
        if (fw_create_empty_shared_key(config, i_ins) == -1) {
            return NULL;
        }
    }

    /* Self Hostname */
    p = flb_input_get_property("self_hostname", i_ins);
    if (p) {
        config->self_hostname = flb_sds_create(p);
    }
    else {
        config->self_hostname = flb_sds_create("localhost");
    }
    return config;
}

int fw_config_destroy(struct flb_in_fw_config *config)
{
    if (config->log_encoder != NULL) {
        flb_log_event_encoder_destroy(config->log_encoder);
    }

    if (config->log_decoder != NULL) {
        flb_log_event_decoder_destroy(config->log_decoder);
    }

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

    fw_destroy_shared_key(config);
    flb_sds_destroy(config->self_hostname);

    flb_free(config);

    return 0;
}
