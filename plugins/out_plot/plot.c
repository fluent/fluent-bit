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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <msgpack.h>

int cb_plot_init(struct flb_output_instance *ins, struct flb_config *config,
                   void *data)
{
    (void) ins;
    (void) config;
    (void) data;

    return 0;
}

int cb_plot_flush(void *data, size_t bytes,
                  char *tag, int tag_len,
                  struct flb_input_instance *i_ins,
                  void *out_context,
                  struct flb_config *config)
{
    int fd;
    time_t atime;
    msgpack_unpacked result;
    size_t off = 0, cnt = 0;
    msgpack_object root;
    msgpack_object map;
    msgpack_object *key;
    msgpack_object *val;
    (void) i_ins;
    (void) out_context;
    (void) config;

    /* Open output file with default name as the Tag */
    fd = open(tag, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd == -1) {
        flb_errno();
        flb_warn("[out_plot] switching to STDOUT");
        fd = STDOUT_FILENO;
    }

    /*
     * Upon flush, for each array, lookup the time and the first field
     * of the map to use as a data point.
     */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        root = result.data;
        atime = root.via.array.ptr[0].via.u64;
        map   = root.via.array.ptr[1];

        key = &map.via.map.ptr[0].key;
        val = &map.via.map.ptr[0].val;

        if (val->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            dprintf(fd, "%lu %" PRIu64 "\n", atime, val->via.u64);
        }
        else if (val->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            dprintf(fd, "%lu %" PRId64 "\n", atime, val->via.i64);
        }
        else if (val->type == MSGPACK_OBJECT_FLOAT) {
            dprintf(fd, "%lu %lf\n", atime, val->via.f64);
        }
    }
    msgpack_unpacked_destroy(&result);

    if (fd != STDOUT_FILENO) {
        close(fd);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

struct flb_output_plugin out_plot_plugin = {
    .name         = "plot",
    .description  = "Generate data file for GNU Plot",
    .cb_init      = cb_plot_init,
    .cb_flush     = cb_plot_flush,
    .flags        = 0,
};
