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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>

#include "stdout.h"

static char *msgpack_to_json(struct flb_out_stdout_config *ctx,
                             char *data, uint64_t bytes,
                             uint64_t *out_size)
{
    int i;
    int ret;
    int len;
    int array_size = 0;
    int map_size;
    size_t off = 0;
    char *json_buf;
    size_t json_size;
    char time_formatted[32];
    size_t s;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_object *obj;
    struct tm tm;
    struct flb_time tms;

    /* Iterate the original buffer and perform adjustments */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        array_size++;
    }
    msgpack_unpacked_destroy(&result);
    msgpack_unpacked_init(&result);

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&tmp_pck, array_size);

    off = 0;
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        /* Each array must have two entries: time and record */
        root = result.data;
        if (root.via.array.size != 2) {
            continue;
        }

        flb_time_pop_from_msgpack(&tms, &result, &obj);
        map = root.via.array.ptr[1];

        map_size = map.via.map.size;
        msgpack_pack_map(&tmp_pck, map_size + 1);

        /* Append date key */
        msgpack_pack_str(&tmp_pck, ctx->json_date_key_len);
        msgpack_pack_str_body(&tmp_pck, ctx->json_date_key, ctx->json_date_key_len);

        /* Append date value */
        switch (ctx->json_date_format) {
            case FLB_STDOUT_JSON_DATE_DOUBLE:
                msgpack_pack_double(&tmp_pck, flb_time_to_double(&tms));
                break;

            case FLB_STDOUT_JSON_DATE_ISO8601:
                /* Format the time; use microsecond precision (not nanoseconds). */
                gmtime_r(&tms.tm.tv_sec, &tm);
                s = strftime(time_formatted, sizeof(time_formatted) - 1,
                             FLB_STDOUT_JSON_DATE_ISO8601_FMT, &tm);

                len = snprintf(time_formatted + s, sizeof(time_formatted) - 1 - s,
                               ".%06" PRIu64 "Z", (uint64_t) tms.tm.tv_nsec / 1000);
                s += len;

                msgpack_pack_str(&tmp_pck, s);
                msgpack_pack_str_body(&tmp_pck, time_formatted, s);
                break;
        }

        for (i = 0; i < map_size; i++) {
            msgpack_object *k = &map.via.map.ptr[i].key;
            msgpack_object *v = &map.via.map.ptr[i].val;

            msgpack_pack_object(&tmp_pck, *k);
            msgpack_pack_object(&tmp_pck, *v);
        }
    }

    /* Release msgpack */
    msgpack_unpacked_destroy(&result);

    /* Format to JSON */
    ret = flb_msgpack_raw_to_json_str(tmp_sbuf.data, tmp_sbuf.size,
                                      &json_buf, &json_size);

    /* Convert to JSON lines from JSON array */
    {
        char *p;
        char *end = json_buf + json_size;
        int level = 0;
        int in_string = FLB_FALSE;
        int in_escape = FLB_FALSE;
        char separator = '\n';

        for (p = json_buf; p!=end; p++) {
            if (in_escape)
                in_escape = FLB_FALSE;
            else if (*p == '\\')
                in_escape = FLB_TRUE;
            else if (*p == '"')
                in_string = !in_string;
            else if (!in_string) {
                if (*p == '{')
                    level++;
                else if (*p == '}')
                    level--;
                else if ((*p == '[' || *p == ']') && level == 0)
                    *p = ' ';
                else if (*p == ',' && level == 0)
                    *p = separator;
            }
        }
    }

    msgpack_sbuffer_destroy(&tmp_sbuf);
    if (ret != 0) {
        return NULL;
    }

    *out_size = json_size;
    return json_buf;
}


static int cb_stdout_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    char *tmp;
    struct flb_out_stdout_config *ctx = NULL;
    (void) ins;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_out_stdout_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->out_format = FLB_STDOUT_OUT_MSGPACK;
    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        if (strcasecmp(tmp, "msgpack") == 0) {
            ctx->out_format = FLB_STDOUT_OUT_MSGPACK;
        }
        else if (strcasecmp(tmp, "json_lines") == 0) {
            ctx->out_format = FLB_STDOUT_OUT_JSON_LINES;
        }
        else {
            flb_warn("[out_stdout] unrecognized 'format' option. Using 'msgpack'");
        }
    }

    /* Date format for JSON output */
    ctx->json_date_format = FLB_STDOUT_JSON_DATE_DOUBLE;
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        if (strcasecmp(tmp, "iso8601") == 0) {
            ctx->json_date_format = FLB_STDOUT_JSON_DATE_ISO8601;
        }
    }

    /* Date key for JSON output */
    tmp = flb_output_get_property("json_date_key", ins);
    ctx->json_date_key = flb_strdup(tmp ? tmp : "date");
    ctx->json_date_key_len = strlen(ctx->json_date_key);

    flb_output_set_context(ins, ctx);
    return 0;
}

static void cb_stdout_flush(void *data, size_t bytes,
                            char *tag, int tag_len,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0, cnt = 0;
    struct flb_out_stdout_config *ctx = out_context;
    char *json = NULL;
    char *buf = NULL;
    uint64_t json_len;

    (void) i_ins;
    (void) config;
    struct flb_time tmp;
    msgpack_object *p;

    if (ctx->out_format == FLB_STDOUT_OUT_JSON_LINES) {
        json = msgpack_to_json(ctx, data, bytes, &json_len);
        printf("%s\n", json);
        flb_free(json);
        fflush(stdout);
    }
    else {
        /* A tag might not contain a NULL byte */
        buf = flb_malloc(tag_len + 1);
        if (!buf) {
            flb_errno();
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        memcpy(buf, tag, tag_len);
        buf[tag_len] = '\0';
        msgpack_unpacked_init(&result);
        while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
            printf("[%zd] %s: [", cnt++, buf);
            flb_time_pop_from_msgpack(&tmp, &result, &p);
            printf("%"PRIu32".%09lu, ", (uint32_t)tmp.tm.tv_sec, tmp.tm.tv_nsec);
            msgpack_object_print(stdout, *p);
            printf("]\n");
        }
        msgpack_unpacked_destroy(&result);
        flb_free(buf);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_stdout_exit(void *data, struct flb_config *config)
{
    struct flb_out_stdout_config *ctx = data;

    if (!ctx) {
        return 0;
    }

    if (ctx->json_date_key) {
        flb_free(ctx->json_date_key);
    }
    flb_free(ctx);
    return 0;
}

struct flb_output_plugin out_stdout_plugin = {
    .name         = "stdout",
    .description  = "Prints events to STDOUT",
    .cb_init      = cb_stdout_init,
    .cb_flush     = cb_stdout_flush,
    .cb_exit      = cb_stdout_exit,
    .flags        = 0,
};
