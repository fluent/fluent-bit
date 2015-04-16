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


#include <fluent-bit/flb_output.h>

int cb_fluentd_init(struct flb_config *config)
{

}

/* Plugin reference */
struct flb_output_plugin out_fluentd_plugin = {
    .name         = "fluentd",
    .description  = "Fluentd log collector",
    .cb_init      = cb_fluentd_init,
    .cb_pre_run   = NULL,
    .flags        = FLB_OUTPUT_TCP | FLB_OUTPUT_SSL,
};
