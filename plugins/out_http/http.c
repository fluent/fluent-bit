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
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include "http.h"
#include "http_conf.h"

struct flb_output_plugin out_http_plugin;

static char *msgpack_to_json(struct flb_out_http *ctx, char *data, uint64_t bytes, uint64_t *out_size)
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
            case FLB_JSON_DATE_DOUBLE:
                msgpack_pack_double(&tmp_pck, flb_time_to_double(&tms));
                break;

            case FLB_JSON_DATE_ISO8601:
                /* Format the time; use microsecond precision (not nanoseconds). */
                gmtime_r(&tms.tm.tv_sec, &tm);
                s = strftime(time_formatted, sizeof(time_formatted) - 1,
                             FLB_JSON_DATE_ISO8601_FMT, &tm);

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
    if (ret != 0) {
        msgpack_sbuffer_destroy(&tmp_sbuf);
        return NULL;
    }

    /* Optionally convert to JSON stream from JSON array */
    if ((ctx->out_format == FLB_HTTP_OUT_JSON_STREAM) ||
        (ctx->out_format == FLB_HTTP_OUT_JSON_LINES)) {
        char *p;
        char *end = json_buf + json_size;
        int level = 0;
        int in_string = FLB_FALSE;
        int in_escape = FLB_FALSE;
        char separator = ' ';
        if (ctx->out_format == FLB_HTTP_OUT_JSON_LINES) {
            separator = '\n';
        }

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

    *out_size = json_size;
    return json_buf;
}

static int cb_http_init(struct flb_output_instance *ins,
                        struct flb_config *config, void *data)
{
    struct flb_out_http *ctx = NULL;
    (void) data;

    ctx = flb_http_conf_create(ins, config);
    if (!ctx) {
        return -1;
    }

    /* Set the plugin context */
    flb_output_set_context(ins, ctx);

    return 0;
}

static int http_post (struct flb_out_http *ctx,
                      void *body, size_t body_len,
                      char *tag, int tag_len)
{
    int ret;
    int out_ret = FLB_OK;
    size_t b_sent;
    struct flb_upstream *u;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;

    struct mk_list *tmp;
    struct mk_list *head;
    struct out_http_header *header;

    /* Get upstream context and connection */
    u = ctx->u;
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_error("[out_http] no upstream connections available to %s:%i",
                  u->tcp_host, u->tcp_port);
        return FLB_RETRY;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        body, body_len,
                        ctx->host, ctx->port,
                        ctx->proxy, 0);

    /* Append headers */
    if ((ctx->out_format == FLB_HTTP_OUT_JSON) ||
        (ctx->out_format == FLB_HTTP_OUT_JSON_STREAM) ||
        (ctx->out_format == FLB_HTTP_OUT_JSON_LINES) ||
        (ctx->out_format == FLB_HTTP_OUT_GELF)) {
        flb_http_add_header(c,
                            FLB_HTTP_CONTENT_TYPE,
                            sizeof(FLB_HTTP_CONTENT_TYPE) - 1,
                            FLB_HTTP_MIME_JSON,
                            sizeof(FLB_HTTP_MIME_JSON) - 1);
    }
    else {
        flb_http_add_header(c,
                            FLB_HTTP_CONTENT_TYPE,
                            sizeof(FLB_HTTP_CONTENT_TYPE) - 1,
                            FLB_HTTP_MIME_MSGPACK,
                            sizeof(FLB_HTTP_MIME_MSGPACK) - 1);
    }

    if (ctx->header_tag) {
        flb_http_add_header(c,
                        ctx->header_tag,
                        ctx->headertag_len,
                        tag, tag_len);
    }

    if (ctx->http_user && ctx->http_passwd) {
        flb_http_basic_auth(c, ctx->http_user, ctx->http_passwd);
    }

    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    mk_list_foreach_safe(head, tmp, &ctx->headers) {
        header = mk_list_entry(head, struct out_http_header, _head);
        flb_http_add_header(c,
                        header->key,
                        header->key_len,
                        header->val,
                        header->val_len);
    }

    ret = flb_http_do(c, &b_sent);
    if (ret == 0) {
        /*
         * Only allow the following HTTP status:
         *
         * - 200: OK
         * - 201: Created
         * - 202: Accepted
         * - 203: no authorative resp
         * - 204: No Content
         * - 205: Reset content
         *
         */
        if (c->resp.status < 200 || c->resp.status > 205) {
            flb_error("[out_http] %s:%i, HTTP status=%i",
                      ctx->host, ctx->port, c->resp.status);
            out_ret = FLB_RETRY;
        }
        else {
            if (c->resp.payload) {
                flb_info("[out_http] %s:%i, HTTP status=%i\n%s",
                         ctx->host, ctx->port,
                         c->resp.status, c->resp.payload);
            }
            else {
                flb_info("[out_http] %s:%i, HTTP status=%i",
                         ctx->host, ctx->port,
                         c->resp.status);
            }
        }
    }
    else {
        flb_error("[out_http] could not flush records to %s:%i (http_do=%i)",
                  ctx->host, ctx->port, ret);
        out_ret = FLB_RETRY;
    }

    flb_http_client_destroy(c);

    /* Release the connection */
    flb_upstream_conn_release(u_conn);

    return out_ret;
}

static int http_gelf(struct flb_out_http *ctx,
                     char *data, uint64_t bytes, char *tag, int tag_len)
{
    flb_sds_t s;
    flb_sds_t tmp;
    msgpack_unpacked result;
    size_t off = 0;
    size_t prev_off = 0;
    size_t size = 0;
    msgpack_object root;
    msgpack_object map;
    msgpack_object *obj;
    struct flb_time tm;
    int ret;

    msgpack_unpacked_init(&result);

    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        size = off - prev_off;
        prev_off = off;
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        root = result.data;
        if (root.via.array.size != 2) {
            continue;
        }

        flb_time_pop_from_msgpack(&tm, &result, &obj);
        map = root.via.array.ptr[1];

        size = (size * 1.4);
        s = flb_sds_create_size(size);
        if (s == NULL) {
            msgpack_unpacked_destroy(&result);
            return FLB_RETRY;
        }

        tmp = flb_msgpack_to_gelf(&s, &map, &tm, &(ctx->gelf_fields));
        if (tmp != NULL) {
            s = tmp;
            ret = http_post(ctx, s, flb_sds_len(s), tag, tag_len);
            if (ret != FLB_OK) {
                msgpack_unpacked_destroy(&result);
                flb_sds_destroy(s);
                return ret;
            }
        }
        else {
            flb_error("[out_http] error encoding to GELF");
        }

        flb_sds_destroy(s);
    }

    msgpack_unpacked_destroy(&result);

    return FLB_OK;
}

static void cb_http_flush(void *data, size_t bytes,
                          char *tag, int tag_len,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    int ret = FLB_ERROR;
    struct flb_out_http *ctx = out_context;
    void *body = NULL;
    uint64_t body_len;
    (void)i_ins;

    if ((ctx->out_format == FLB_HTTP_OUT_JSON) ||
        (ctx->out_format == FLB_HTTP_OUT_JSON_STREAM) ||
        (ctx->out_format == FLB_HTTP_OUT_JSON_LINES)) {
        body = msgpack_to_json(ctx, data, bytes, &body_len);
        if (body != NULL) {
            ret = http_post(ctx, body, body_len, tag, tag_len);
            flb_free(body);
        }
    }
    else if (ctx->out_format == FLB_HTTP_OUT_GELF) {
        ret = http_gelf(ctx, data, bytes, tag, tag_len);
    }
    else {
        ret = http_post(ctx, data, bytes, tag, tag_len);
    }

    FLB_OUTPUT_RETURN(ret);
}

static int cb_http_exit(void *data, struct flb_config *config)
{
    struct flb_out_http *ctx = data;

    flb_http_conf_destroy(ctx);
    return 0;
}

/* Plugin reference */
struct flb_output_plugin out_http_plugin = {
    .name = "http",
    .description = "HTTP Output",
    .cb_init = cb_http_init,
    .cb_pre_run = NULL,
    .cb_flush = cb_http_flush,
    .cb_exit = cb_http_exit,
    .flags = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
