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

#include "td_config.h"

struct flb_out_td_config *td_config_init(struct mk_rconf *conf)
{
    char *api;
    char *db_name;
    char *db_table;
    struct mk_rconf_section *section;
    struct flb_out_td_config *config;

    section = mk_rconf_section_get(conf, "TD");
    if (!section) {
        return NULL;
    }

    /* Validate TD section keys */
    api = mk_rconf_section_get_key(section, "API", MK_RCONF_STR);
    db_name = mk_rconf_section_get_key(section, "Database", MK_RCONF_STR);
    db_table = mk_rconf_section_get_key(section, "Table", MK_RCONF_STR);

    if (!api) {
        flb_utils_error_c("[TD] error reading API key value");
    }

    if (!db_name) {
        flb_utils_error_c("[TD] error reading Database name");
    }

    if (!db_table) {
        flb_utils_error_c("[TD] error reading Table name");
    }

    config = malloc(sizeof(struct flb_out_td_config));
    config->fd       = -1;
    config->api      = api;
    config->db_name  = db_name;
    config->db_table = db_table;

    flb_debug("TreasureData / database='%s' table='%s'",
              config->db_name, config->db_table);

    return config;
}
