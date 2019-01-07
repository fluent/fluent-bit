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
#include <fluent-bit.h>

#include "td_config.h"

struct flb_out_td_config *td_config_init(struct flb_output_instance *o_ins)
{
    char *tmp;
    char *api;
    char *db_name;
    char *db_table;
    struct flb_out_td_config *config;

    /* Validate TD section keys */
    api = flb_output_get_property("API", o_ins);
    db_name = flb_output_get_property("Database", o_ins);
    db_table = flb_output_get_property("Table", o_ins);

    if (!api) {
        flb_error("[out_td] error reading API key value");
        return NULL;
    }

    if (!db_name) {
        flb_error("[out_td] error reading Database name");
        return NULL;
    }

    if (!db_table) {
        flb_error("[out_td] error reading Table name");
        return NULL;
    }

    /* Allocate context */
    config = flb_calloc(1, sizeof(struct flb_out_td_config));
    if (!config) {
        flb_errno();
        return NULL;
    }

    config->fd       = -1;
    config->api      = api;
    config->db_name  = db_name;
    config->db_table = db_table;

    /* Lookup desired region */
    tmp = flb_output_get_property("region", o_ins);
    if (tmp) {
        if (strcasecmp(tmp, "us") == 0) {
            config->region = FLB_TD_REGION_US;
        }
        else if (strcasecmp(tmp, "jp") == 0) {
            config->region = FLB_TD_REGION_JP;
        }
        else {
            flb_error("[out_td] invalid region in configuration");
            flb_free(config);
            return NULL;
        }
    }
    else {
        config->region = FLB_TD_REGION_US;
    }

    flb_info("[out_td] Treasure Data / database='%s' table='%s'",
              config->db_name, config->db_table);

    return config;
}
