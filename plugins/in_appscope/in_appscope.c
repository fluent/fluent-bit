/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_input.h>

#include "in_appscope.h"

/* Initialize plugin */
static int in_appscope_init(struct flb_input_instance *in,
                         struct flb_config *config, void *data)
{
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
   {0}
};

struct flb_input_plugin in_appscope_plugin = {
    .name         = "appscope",
    .description  = "AppScope",
    .cb_init      = in_appscope_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL, //in_appscope_collect
    .cb_flush_buf = NULL,
    .config_map   = config_map,
    .cb_exit      = NULL  //in_appscope_exit
};
