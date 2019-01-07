/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Serial input plugin for Fluent Bit
 *  ==================================
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2016 Takeshi HASEGAWA
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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_input.h>

#include "in_serial_config.h"

struct flb_in_serial_config *serial_config_read(struct flb_in_serial_config *config,
                                                struct flb_input_instance *i_ins)
{
    uint64_t min_bytes;
    char *file;
    char *bitrate;
    char *separator;
    char *tmp;
    char *format;

    /* Get input properties */
    file      = flb_input_get_property("file", i_ins);
    bitrate   = flb_input_get_property("bitrate", i_ins);
    separator = flb_input_get_property("separator", i_ins);
    format    = flb_input_get_property("format", i_ins);

    tmp = flb_input_get_property("min_bytes", i_ins);
    if (!tmp) {
        min_bytes = 0;
    }
    else {
        min_bytes = atoi(tmp);
    }

    if (!file) {
        flb_error("[serial] error reading filename from "
                  "configuration");
        return NULL;
    }

    if (!bitrate) {
        flb_error("[serial] error reading bitrate from "
                  "configuration");
        return NULL;
    }

    if (min_bytes <= 0) {
        min_bytes = 1;
    }

    config->fd        = -1;
    config->buf_len   = 0;
    config->file      = file;
    config->bitrate   = bitrate;
    config->min_bytes = min_bytes;
    config->separator = separator;

    if (format && separator) {
        flb_error("[in_serial] specify 'format' or 'separator', not both");
        return NULL;
    }

    if (separator) {
        config->sep_len = strlen(separator);
    }
    else {
        config->sep_len = 0;
    }

    if (format) {
        if (strcasecmp(format, "json") == 0) {
            config->format = FLB_SERIAL_FORMAT_JSON;
        }
    }

    flb_debug("[in_serial] file='%s' bitrate='%s' min_bytes=%i format=%i",
              config->file, config->bitrate, config->min_bytes, config->format);

    return config;
}
