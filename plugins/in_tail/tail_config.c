/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_input.h>

#include "tail_config.h"
#include "tail_scan.h"

struct flb_tail_config *flb_tail_config_create(struct flb_input_instance *i_ins)
{
    int ret;
    struct flb_tail_config *config;

    config = flb_malloc(sizeof(struct flb_tail_config));
    if (!config) {
        flb_errno();
        return NULL;
    }

    /* Create the communication pipe(2) */
    ret = pipe(config->ch_manager);
    if (ret == -1) {
        flb_errno();
        flb_free(config);
        return -1;
    }

    /* Read properties */
    config->path = flb_input_get_property("path", i_ins);
    if (!config->path) {
        flb_error("[in_tail] no input 'path' was given");
        flb_free(config);
        return NULL;
    }
    mk_list_init(&config->files);


    ret = flb_tail_scan(config->path, config);
    return config;
}

int flb_tail_config_destroy(struct flb_tail_config *config)
{
    /* Close pipe ends */
    close(config->ch_manager[0]);
    close(config->ch_manager[0]);

    flb_free(config);
    return 0;
}
