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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <fluent-bit/flb_output.h>

int cb_counter_init(struct flb_output_instance *ins,
                 struct flb_config *config,
                 void *data)
{
    (void) ins;
    (void) config;
    (void) data;

    return 0;
}

void cb_counter_flush(void *data, size_t bytes,
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

    msgpack_unpacked result;
    size_t off = 0, cnt = 0;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        cnt++;
    }
    msgpack_unpacked_destroy(&result);

    time_t t = time(NULL);
    printf("%lu,%lu\n", t, cnt);

    FLB_OUTPUT_RETURN(FLB_OK);
}

struct flb_output_plugin out_counter_plugin = {
    .name         = "counter",
    .description  = "Records counter",
    .cb_init      = cb_counter_init,
    .cb_flush     = cb_counter_flush,
    .flags        = 0,
};
