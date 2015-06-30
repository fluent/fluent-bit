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

#include "in_xbee_config.h"

struct flb_in_xbee_config *xbee_config_read(struct flb_in_xbee_config *config, struct mk_rconf *conf)
{
    char *file;
    char *baudrate;
    char *xbee_loglevel;
    struct mk_rconf_section *section;

    section = mk_rconf_section_get(conf, "xbee");
    if (!section) {
        return NULL;
    }

    /* Validate xbee section keys */
    file = mk_rconf_section_get_key(section, "file", MK_RCONF_STR);
    baudrate = mk_rconf_section_get_key(section, "baudrate", MK_RCONF_STR);
    xbee_loglevel = mk_rconf_section_get_key(section, "XBeeLogLevel", MK_RCONF_STR);

    if (!file) {
        flb_utils_error_c("[xbee] error reading filename from "
                "configuration");
    }

    if (!baudrate) {
        flb_utils_error_c("[xbee] error reading baudrate from "
                "configuration");
    }

    config->fd       = -1;
    config->file     = file;
    config->baudrate  = baudrate;
    config->xbeeLogLevel = xbee_loglevel ? atoi(xbee_loglevel) : -1;

    flb_debug("[xbee] / device='%s' baudrate='%s'",
              config->file, config->baudrate);

    return config;
}
