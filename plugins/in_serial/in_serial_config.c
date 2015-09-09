/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Serial input plugin for Fluent Bit
 *  ==================================
 *  Copyright (C) 2015 Takeshi HASEGAWA
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

#include "in_serial_config.h"

struct flb_in_serial_config *serial_config_read(struct flb_in_serial_config *config,
                                                struct mk_rconf *conf)
{
    char *file;
    char *bitrate;
    struct mk_rconf_section *section;

    section = mk_rconf_section_get(conf, "serial");
    if (!section) {
        return NULL;
    }

    /* Validate serial section keys */
    file = mk_rconf_section_get_key(section, "file", MK_RCONF_STR);
    bitrate = mk_rconf_section_get_key(section, "bitrate", MK_RCONF_STR);

    if (!file) {
        flb_utils_error_c("[serial] error reading filename from "
                "configuration");
    }

    if (!bitrate) {
        flb_utils_error_c("[serial] error reading bitrate from "
                "configuration");
    }

    config->fd       = -1;
    config->file     = file;
    config->bitrate  = bitrate;

    flb_debug("Serial / file='%s' bitrate='%s'",
              config->file, config->bitrate);

    return config;
}
