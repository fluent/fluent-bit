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

#include <stdio.h>

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>

#include <msgpack.h>

#include "stdout.h"

int cb_stdout_init(struct flb_config *config)
{
    /* do nothing */
    return 0;
}

int cb_stdout_flush(void *data, size_t bytes, void *out_context,
                     struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0, cnt = 0;

    (void) out_context;
    (void) config;
    /* See: in_forward.rb of fluentd.
     *
     * message Entry {
     *   1: long time
     *   2: object record
     * }
     *
     * message Forward {
     *   1: string tag
     *   2: list<Entry> entries
     *   3: object option (optional)
     * }
     *
     * message PackedForward {
     *   1: string tag
     *   2: raw entries  # msgpack stream of Entry
     *   3: object option (optional)
     * }
     *
     * message Message {
     *   1: string tag
     *   2: long? time
     *   3: object record
     *   4: object option (optional)
     * }
     */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        /* FIXME: lazy output */
        printf("[%zd] ", cnt++);
        msgpack_object_print(stdout, result.data);
        printf("\n");
    }
    msgpack_unpacked_destroy(&result);
    return bytes;
}

struct flb_output_plugin out_stdout_plugin = {
    .name         = "stdout",
    .description  = "Prints events to STDOUT",
    .cb_init      = cb_stdout_init,
    .cb_flush     = cb_stdout_flush,
    .flags        = FLB_OUTPUT_NOPROT,
};
