/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Serial input plugin for Fluent Bit
 *  ==================================
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *  Copyright (C) 2015-2016 Takeshi HASEGAWA
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
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_error.h>

#include "in_serial_config.h"

struct flb_in_serial_config *serial_config_read(struct flb_in_serial_config *config,
                                                struct flb_input_instance *i_ins)
{
    int ret;

    /* Load the config map */
    ret = flb_input_config_map_set(i_ins, (void *)config);
    if (ret == -1) {
        flb_plg_error(i_ins, "unable to load configuration");
        return NULL;
    }

    if (!config->file) {
        flb_error("[serial] error reading filename from "
                  "configuration");
        return NULL;
    }

    if (!config->bitrate) {
        flb_error("[serial] error reading bitrate from "
                  "configuration");
        return NULL;
    }

    if (config->min_bytes <= 0) {
        config->min_bytes = 1;
    }

    config->fd        = -1;
    config->buf_len   = 0;

    if (config->format_str && config->separator) {
        flb_error("[in_serial] specify 'format' or 'separator', not both");
        return NULL;
    }

    if (config->separator) {
        config->sep_len = strlen(config->separator);
    }
    else {
        config->sep_len = 0;
    }

    if (config->format_str) {
        if (strcasecmp(config->format_str, "json") == 0) {
            config->format = FLB_SERIAL_FORMAT_JSON;
        }
    }

    flb_debug("[in_serial] file='%s' bitrate='%s' min_bytes=%i format=%i",
              config->file, config->bitrate, config->min_bytes, config->format);

    return config;
}
