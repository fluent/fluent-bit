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
#include <fluent-bit/flb_utils.h>

#include "in_xbee_config.h"

int in_xbee_config_read_int(int *dest, struct mk_rconf_section *section, char *key, int default_val)
{
    char *val;

    val = mk_rconf_section_get_key(section, key, MK_RCONF_STR);
    *dest = val ? atoi(val) : default_val;

    return (val != NULL);
}

struct flb_in_xbee_config *xbee_config_read(struct flb_in_xbee_config *config, struct mk_rconf *conf)
{
    char *file = NULL;
    char *xbee_mode = NULL;

    struct mk_rconf_section *section;

    section = mk_rconf_section_get(conf, "xbee");
    if (!section) {
        return NULL;
    }

    /* Validate xbee section keys */
    file = mk_rconf_section_get_key(section, "file", MK_RCONF_STR);

    if (!file) {
        flb_utils_error_c("[xbee] error reading filename from "
                "configuration");
    }

    config->file      = file;
    in_xbee_config_read_int(&config->baudrate, section, "baudrate", 9600);
    in_xbee_config_read_int(&config->xbeeLogLevel, section, "xbeeloglevel", -1);
    in_xbee_config_read_int(&config->xbeeDisableAck, section, "xbeedisableack", 1);
    in_xbee_config_read_int(&config->xbeeCatchAll, section, "xbeecatchall", 1);
    config->xbeeMode  = xbee_mode ? xbee_mode : "xbeeZB";

    flb_debug("[xbee] / device='%s' baudrate=%d",
              config->file, config->baudrate);

    return config;
}
