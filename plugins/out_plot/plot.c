/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>

struct flb_plot_conf {
    char *out_file;
    char *key_name;
    int key_len;
};

static int cb_plot_init(struct flb_output_instance *ins,
                        struct flb_config *config,
                        void *data)
{
    char *tmp;
    (void) config;
    (void) data;
    struct flb_plot_conf *conf;

    conf = flb_calloc(1, sizeof(struct flb_plot_conf));
    if (!conf) {
        flb_errno();
        return -1;
    }

    /* Optional 'key' field to obtain the datapoint value */
    tmp = flb_output_get_property("key", ins);
    if (tmp) {
        conf->key_name = tmp;
        conf->key_len  = strlen(tmp);
    }

    /* Optional output file name/path */
    tmp = flb_output_get_property("file", ins);
    if (tmp) {
        conf->out_file = tmp;
    }

    /* Set the context */
    flb_output_set_context(ins, conf);

    return 0;
}

static void cb_plot_flush(void *data, size_t bytes,
                          char *tag, int tag_len,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    int i;
    int fd;
    struct flb_time atime;
    msgpack_unpacked result;
    size_t off = 0;
    char *out_file;
    msgpack_object *map;
    msgpack_object *key = NULL;
    msgpack_object *val = NULL;
    struct flb_plot_conf *ctx = out_context;
    (void) i_ins;
    (void) config;

    /* Set the right output */
    if (!ctx->out_file) {
        out_file = tag;
    }
    else {
        out_file = ctx->out_file;
    }

    /* Open output file with default name as the Tag */
    fd = open(out_file, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd == -1) {
        flb_errno();
        flb_warn("[out_plot] could not open %s, switching to STDOUT", out_file);
        fd = STDOUT_FILENO;
    }

    /*
     * Upon flush, for each array, lookup the time and the first field
     * of the map to use as a data point.
     */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        flb_time_pop_from_msgpack(&atime, &result, &map);

        /*
         * Lookup key, we need to iterate the whole map as sometimes the
         * data that gets in can set the keys in different order (e.g: forward,
         * tcp, etc).
         */
        if (ctx->key_name) {
            for (i = 0; i < map->via.map.size; i++) {
                /* Get each key and compare */
                key = &(map->via.map.ptr[i].key);
                if (key->type == MSGPACK_OBJECT_BIN) {
                    if (ctx->key_len == key->via.bin.size &&
                        memcmp(key->via.bin.ptr, ctx->key_name, ctx->key_len) == 0) {
                        val = &(map->via.map.ptr[i].val);
                        break;
                    }
                    key = NULL;
                    val = NULL;
                }
                else if (key->type == MSGPACK_OBJECT_STR) {
                    if (ctx->key_len == key->via.str.size &&
                        memcmp(key->via.str.ptr, ctx->key_name, ctx->key_len) == 0) {
                        val = &(map->via.map.ptr[i].val);
                        break;
                    }
                    key = NULL;
                    val = NULL;
                }
                else {
                    if (fd != STDOUT_FILENO) {
                        close(fd);
                    }
                    FLB_OUTPUT_RETURN(FLB_ERROR);
                }
            }
        }
        else {
            val = &(map->via.map.ptr[0].val);
        }

        if (!val) {
            flb_error("[out_plot] unmatched key '%s'", ctx->key_name);
            if (fd != STDOUT_FILENO) {
                close(fd);
            }
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        if (val->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            dprintf(fd, "%f %" PRIu64 "\n",
                    flb_time_to_double(&atime), val->via.u64);
        }
        else if (val->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            dprintf(fd, "%f %" PRId64 "\n",
                    flb_time_to_double(&atime), val->via.i64);
        }
        else if (val->type == MSGPACK_OBJECT_FLOAT) {
            dprintf(fd, "%f %lf\n",
                    flb_time_to_double(&atime), val->via.f64);
        }
        else {
            flb_error("[out_plot] value must be integer, negative integer "
                      "or float");
        }
    }
    msgpack_unpacked_destroy(&result);

    if (fd != STDOUT_FILENO) {
        close(fd);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_plot_exit(void *data, struct flb_config *config)
{
    struct flb_plot_conf *ctx = data;

    flb_free(ctx);

    return 0;
}

struct flb_output_plugin out_plot_plugin = {
    .name         = "plot",
    .description  = "Generate data file for GNU Plot",
    .cb_init      = cb_plot_init,
    .cb_flush     = cb_plot_flush,
    .cb_exit      = cb_plot_exit,
    .flags        = 0,
};
