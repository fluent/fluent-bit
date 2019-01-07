/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <fluent-bit/flb_output.h>

int cb_null_init(struct flb_output_instance *ins,
                 struct flb_config *config,
                 void *data)
{
    (void) ins;
    (void) config;
    (void) data;

    return 0;
}

void cb_null_flush(void *data, size_t bytes,
                   char *tag, int tag_len,
                   struct flb_input_instance *i_ins,
                   void *out_context,
                   struct flb_config *config)
{
    (void) data;
    (void) bytes;
    (void) tag;
    (void) tag_len;
    (void) i_ins;
    (void) out_context;
    (void) config;

    FLB_OUTPUT_RETURN(FLB_OK);
}

struct flb_output_plugin out_null_plugin = {
    .name         = "null",
    .description  = "Throws away events",
    .cb_init      = cb_null_init,
    .cb_flush     = cb_null_flush,
    .flags        = 0,
};
