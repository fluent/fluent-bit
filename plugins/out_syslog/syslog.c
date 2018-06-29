/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this syslog except in compliance with the License.
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

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "syslog.h"

static int cb_syslog_init(struct flb_output_instance *ins,
                        struct flb_config *config,
                        void *data)
{
    (void) config;
    (void) data;
    char *tmp;
    // struct flb_upstream *upstream;
    struct flb_syslog_conf *ctx;

    /* Allocate context */
    ctx = flb_calloc(1, sizeof(struct flb_syslog_conf));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    tmp = flb_output_get_property("addr", ins);
    if (tmp) {
        ctx->addr = flb_strdup(tmp);
    }
    flb_info("[out_syslog] addr=%s", ctx->addr);
    // TODO: connect to upstream
    /* Set the context */
    flb_output_set_context(ins, ctx);
    return 0;
}

static void cb_syslog_flush(void *data, size_t bytes,
                          char *tag, int tag_len,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    struct flb_syslog_conf *ctx = out_context;
    flb_info("[out_syslog] flush\n");
    flb_info("ctx: %p", ctx);
    flb_info("[out_syslog] flush addr=%s", ctx->addr);
    // TODO flush to syslog upstream
    FLB_OUTPUT_RETURN(FLB_OK);
    return;

//     FILE * fp;
// 
//     msgpack_unpacked result;
//     size_t off = 0;
//     size_t last_off = 0;
//     size_t alloc_size = 0;
//     char *out_syslog;
//     char *buf;
//     msgpack_object *obj;
//     struct flb_time tm;
//     (void) i_ins;
//     (void) config;
// 
//     /* Set the right output */
//     if (!ctx->out_syslog) {
//         out_syslog = tag;
//     }
//     else {
//         out_syslog = ctx->out_syslog;
//     }
// 
//     /* Open output syslog with default name as the Tag */
//     fp = fopen(out_syslog, "a+");
//     if (fp == NULL) {
//         flb_errno();
//         FLB_OUTPUT_RETURN(FLB_ERROR);
//     }
// 
//     /*
//      * Upon flush, for each array, lookup the time and the first field
//      * of the map to use as a data point.
//      */
//     msgpack_unpacked_init(&result);
//     while (msgpack_unpack_next(&result, data, bytes, &off)) {
//         alloc_size = (off - last_off) + 128; /* JSON is larger than msgpack */
//         last_off = off;
// 
//         flb_time_pop_from_msgpack(&tm, &result, &obj);
// 
//         switch (ctx->format){
//         case FLB_OUT_SYSLOG_FMT_JSON:
//             buf = flb_msgpack_to_json_str(alloc_size, obj);
//             if (buf) {
//                 fprintf(fp, "%s: [%f, %s]\n",
//                         tag,
//                         flb_time_to_double(&tm),
//                         buf);
//                 flb_free(buf);
//             }
//             else {
//                 msgpack_unpacked_destroy(&result);
//                 fclose(fp);
//                 FLB_OUTPUT_RETURN(FLB_RETRY);
//             }
//             break;
//         }
//     }
//     msgpack_unpacked_destroy(&result);
//     fclose(fp);
// 
//     FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_syslog_exit(void *data, struct flb_config *config)
{
    struct flb_syslog_conf *ctx = data;

    flb_free(ctx);

    return 0;
}

struct flb_output_plugin out_syslog_plugin = {
    .name         = "syslog",
    .description  = "Generate log syslog",
    .cb_init      = cb_syslog_init,
    .cb_flush     = cb_syslog_flush,
    .cb_exit      = cb_syslog_exit,
    .flags        = 0,
};
