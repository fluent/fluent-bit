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
#include <fcntl.h>

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <msgpack.h>

#include "file.h"

struct flb_file_conf {
    char *out_file;
};

static int cb_file_init(struct flb_output_instance *ins,
                        struct flb_config *config,
                        void *data)
{
    char *tmp;
    (void) config;
    (void) data;
    struct flb_file_conf *conf;

    conf = flb_calloc(1, sizeof(struct flb_file_conf));
    if (!conf) {
        flb_errno();
        return -1;
    }

    /* Optional output file name/path */
    tmp = flb_output_get_property("Path", ins);
    if (tmp) {
        conf->out_file = tmp;
    }

    /* Set the context */
    flb_output_set_context(ins, conf);

    return 0;
}

static void cb_file_flush(void *data, size_t bytes,
                          char *tag, int tag_len,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    FILE * fp;
    msgpack_unpacked result;
    size_t off = 0;
    char *out_file;
    struct flb_file_conf *ctx = out_context;
    (void) i_ins;
    (void) config;
    struct mk_list *list = NULL;
    struct mk_list *head = NULL;
    struct mk_list *tmp  = NULL;
    struct flb_pack_json_str *str = NULL;

    /* Set the right output */
    if (!ctx->out_file) {
        out_file = tag;
    }
    else {
        out_file = ctx->out_file;
    }

    /* Open output file with default name as the Tag */
    fp = fopen(out_file, "a+");
    if (fp == NULL) {
        flb_errno();
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /*
     * Upon flush, for each array, lookup the time and the first field
     * of the map to use as a data point.
     */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        list = flb_msgpack_to_json_str_list(&result);
        if (list == NULL) {
            continue;
        }
        fprintf(fp, "%s:", tag);
        mk_list_foreach_safe(head, tmp, list) {
            str = mk_list_entry(head, struct flb_pack_json_str, _head);
            fprintf(fp, "%s", str->buf);

            mk_list_del(&str->_head);
            flb_free(str->buf);
            flb_free(str);
        }
        fprintf(fp, "\n");
        flb_free(list);
    }
    msgpack_unpacked_destroy(&result);

    fclose(fp);

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_file_exit(void *data, struct flb_config *config)
{
    struct flb_file_conf *ctx = data;

    flb_free(ctx);

    return 0;
}

struct flb_output_plugin out_file_plugin = {
    .name         = "file",
    .description  = "Generate log file",
    .cb_init      = cb_file_init,
    .cb_flush     = cb_file_flush,
    .cb_exit      = cb_file_exit,
    .flags        = 0,
};
