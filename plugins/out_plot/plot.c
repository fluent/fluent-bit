/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <msgpack.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

struct flb_plot {
    const char *out_file;
    flb_sds_t key;
    struct flb_output_instance *ins;
};

static int cb_plot_init(struct flb_output_instance *ins,
                        struct flb_config *config,
                        void *data)
{
    int ret;
    (void) config;
    (void) data;
    struct flb_plot *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_plot));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *)ctx);
    if (ret == -1) {
    	flb_free(ctx);
    	return -1;
    }

    /* Set the context */
    flb_output_set_context(ins, ctx);

    return 0;
}

static void cb_plot_flush(struct flb_event_chunk *event_chunk,
                          struct flb_output_flush *out_flush,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    int i;
    int written;
    int fd;
    const char *out_file;
    msgpack_object *map;
    msgpack_object *key = NULL;
    msgpack_object *val = NULL;
    struct flb_plot *ctx = out_context;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;

    (void) i_ins;
    (void) config;

    /* Set the right output */
    if (!ctx->out_file) {
        out_file = event_chunk->tag;
    }
    else {
        out_file = ctx->out_file;
    }

    /* Open output file with default name as the Tag */
    fd = open(out_file, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd == -1) {
        flb_errno();
        flb_plg_warn(ctx->ins, "could not open %s, switching to STDOUT",
                     out_file);
        fd = STDOUT_FILENO;
    }

    ret = flb_log_event_decoder_init(&log_decoder,
                                     (char *) event_chunk->data,
                                     event_chunk->size);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        close(fd);

        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /*
     * Upon flush, for each array, lookup the time and the first field
     * of the map to use as a data point.
     */
    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        map = log_event.body;

        /*
         * Lookup key, we need to iterate the whole map as sometimes the
         * data that gets in can set the keys in different order (e.g: forward,
         * tcp, etc).
         */
        if (ctx->key) {
            for (i = 0; i < map->via.map.size; i++) {
                /* Get each key and compare */
                key = &(map->via.map.ptr[i].key);
                if (key->type == MSGPACK_OBJECT_BIN) {
                    if (flb_sds_len(ctx->key) == key->via.bin.size &&
                        memcmp(key->via.bin.ptr, ctx->key,
                               flb_sds_len(ctx->key)) == 0) {
                        val = &(map->via.map.ptr[i].val);
                        break;
                    }
                    key = NULL;
                    val = NULL;
                }
                else if (key->type == MSGPACK_OBJECT_STR) {
                    if (flb_sds_len(ctx->key) == key->via.str.size &&
                        memcmp(key->via.str.ptr, ctx->key,
                               flb_sds_len(ctx->key)) == 0) {
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

                    flb_log_event_decoder_destroy(&log_decoder);

                    FLB_OUTPUT_RETURN(FLB_ERROR);
                }
            }
        }
        else {
            val = &(map->via.map.ptr[0].val);
        }

        if (!val) {
            flb_plg_error(ctx->ins, "unmatched key '%s'", ctx->key);

            if (fd != STDOUT_FILENO) {
                close(fd);
            }

            flb_log_event_decoder_destroy(&log_decoder);

            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        if (val->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            written = dprintf(fd, "%f %" PRIu64 "\n",
                              flb_time_to_double(&log_event.timestamp), val->via.u64);
        }
        else if (val->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            written = dprintf(fd, "%f %" PRId64 "\n",
                              flb_time_to_double(&log_event.timestamp), val->via.i64);
        }
        else if (val->type == MSGPACK_OBJECT_FLOAT) {
            written = dprintf(fd, "%f %lf\n",
                              flb_time_to_double(&log_event.timestamp), val->via.f64);
        }
        else {
            flb_plg_error(ctx->ins, "value must be integer, negative integer "
                          "or float");
            written = 0;
        }
        flb_plg_debug(ctx->ins, "%i bytes written to file '%s'",
                      written, out_file);
    }

    flb_log_event_decoder_destroy(&log_decoder);

    if (fd != STDOUT_FILENO) {
        close(fd);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_plot_exit(void *data, struct flb_config *config)
{
    struct flb_plot *ctx = data;

    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "key", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_plot, key),
     "set a number of times to generate event."
    },
    {
     FLB_CONFIG_MAP_STR, "file", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_plot, out_file),
     "set a number of times to generate event."
    },
    /* EOF */
    {0}
};

struct flb_output_plugin out_plot_plugin = {
    .name         = "plot",
    .description  = "Generate data file for GNU Plot",
    .cb_init      = cb_plot_init,
    .cb_flush     = cb_plot_flush,
    .cb_exit      = cb_plot_exit,
    .config_map   = config_map,
    .flags        = 0,
};
