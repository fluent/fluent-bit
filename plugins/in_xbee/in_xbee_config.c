/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

static int config_read_int(int *dest,
                           struct flb_input_instance *i_ins,
                           char *key, int default_val)
{
    char *val;

    val = flb_input_get_property(key, i_ins);
    *dest = val ? atoi(val) : default_val;

    return (val != NULL);
}

int xbee_config_read(struct flb_input_instance *i_ins,
                     struct flb_in_xbee_config *config)
{
    char *file = NULL;
    char *xbee_mode = NULL;

    file = flb_input_get_property("file", i_ins);
    if (!file) {
        flb_error("[in_xbee] error reading filename from configuration");
        return -1;
    }

    config_read_int(&config->baudrate, i_ins, "baudrate", 9600);
    config_read_int(&config->xbeeLogLevel, i_ins, "xbeeloglevel", -1);
    config_read_int(&config->xbeeDisableAck, i_ins, "xbeedisableack", 1);
    config_read_int(&config->xbeeCatchAll, i_ins, "xbeecatchall", 1);

    xbee_mode = flb_input_get_property("mode", i_ins);
    config->xbeeMode  = xbee_mode ? xbee_mode : "xbeeZB";

    flb_debug("[in_xbee] device='%s' baudrate=%d",
              config->file, config->baudrate);

    return 0;
}
