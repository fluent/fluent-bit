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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>


#include "http.h"

struct flb_output_plugin out_http_plugin;

static char *msgpack_to_json(char *data, uint64_t bytes, uint64_t *out_size)
{
    int i;
    int ret;
    int array_size = 0;
    int map_size;
    size_t off = 0;
    char *json_buf;
    size_t json_size;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_object *obj;
    struct flb_time tm;

    /* Iterate the original buffer and perform adjustments */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        array_size++;
    }
    msgpack_unpacked_destroy(&result);
    msgpack_unpacked_init(&result);

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&tmp_pck, array_size);

    off = 0;
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        /* Each array must have two entries: time and record */
        root = result.data;
        if (root.via.array.size != 2) {
            continue;
        }

        flb_time_pop_from_msgpack(&tm, &result, &obj);
        map   = root.via.array.ptr[1];

        map_size = map.via.map.size;
        msgpack_pack_map(&tmp_pck, map_size + 1);

        /* Append date k/v */
        msgpack_pack_str(&tmp_pck, 4);
        msgpack_pack_str_body(&tmp_pck, "date", 4);
        msgpack_pack_double(&tmp_pck, flb_time_to_double(&tm));

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
    msgpack_sbuffer_destroy(&tmp_sbuf);
    if (ret != 0) {
        return NULL;
    }

    *out_size = json_size;
    return json_buf;
}

int cb_http_init(struct flb_output_instance *ins, struct flb_config *config,
               void *data)
{
    int ulen;
    int io_flags = 0;
    char *uri = NULL;
    char *tmp;
    struct flb_upstream *upstream;
    struct flb_out_http_config *ctx = NULL;
    (void) data;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_out_http_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    /*
     * Check if a Proxy have been set, if so the Upstream manager will use
     * the Proxy end-point and then we let the HTTP client know about it,
     * so it can adjust the HTTP requests.
     */
    tmp = flb_output_get_property("proxy", ins);
    if (tmp) {
        /*
         * Here we just want to lookup two things: host and port, we are
         * going to skip validations as most of them are handled by the
         * HTTP Client in a later stage.
         */
        char *p;
        char *addr;

        addr = strstr(tmp, "//");
        if (!addr) {
            flb_free(ctx);
            return -1;
        }
        addr += 2; /* get right to the host section */
        if (*addr == '[') { /* IPv6 */
            p = strchr(addr, ']');
            if (!p) {
                flb_free(ctx);
                return -1;
            }
            ctx->proxy_host = strndup(addr + 1, (p - addr - 1));
            p++;
            if (*p == ':') {
                p++;
                ctx->proxy_port = atoi(p);
            }
            else {
            }
        }
        else {
            /* Port lookup */
            p = strchr(addr, ':');
            if (p) {
                p++;
                ctx->proxy_port = atoi(p);
                ctx->proxy_host = strndup(addr, (p - addr) - 1);
            }
            else {
                ctx->proxy_host = flb_strdup(addr);
                ctx->proxy_port = 80;
            }
        }
        ctx->proxy = tmp;
    }
    else {
        if (!ins->host.name) {
            ins->host.name = flb_strdup("127.0.0.1");
        }
        if (ins->host.port == 0) {
            ins->host.port = 80;
        }
    }

    /* Check if SSL/TLS is enabled */
#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }
#else
    io_flags = FLB_IO_TCP;
#endif

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    if (ctx->proxy) {
        flb_trace("[out_http] Upstream Proxy=%s:%i",
                  ctx->proxy_host, ctx->proxy_port);
        upstream = flb_upstream_create(config,
                                       ctx->proxy_host,
                                       ctx->proxy_port,
                                       io_flags, (void *) &ins->tls);
    }
    else {
        upstream = flb_upstream_create(config,
                                       ins->host.name,
                                       ins->host.port,
                                       io_flags, (void *) &ins->tls);
    }

    if (!upstream) {
        flb_free(ctx);
        return -1;
    }

    if (ins->host.uri) {
        uri = flb_strdup(ins->host.uri->full);
    }
    else {
        tmp = flb_output_get_property("uri", ins);
        if (tmp) {
            uri = flb_strdup(tmp);
        }
    }

    if (!uri) {
        uri = flb_strdup("/");
    }
    else if (uri[0] != '/') {
        ulen = strlen(uri);
        tmp = flb_malloc(ulen + 2);
        tmp[0] = '/';
        memcpy(tmp + 1, uri, ulen);
        tmp[ulen + 1] = '\0';
        flb_free(uri);
        uri = tmp;
    }


    /* HTTP Auth */
    tmp = flb_output_get_property("http_user", ins);
    if (tmp) {
        ctx->http_user = flb_strdup(tmp);

        tmp = flb_output_get_property("http_passwd", ins);
        if (tmp) {
            ctx->http_passwd = flb_strdup(tmp);
        }
        else {
            ctx->http_passwd = flb_strdup("");
        }
    }

    /* Output format */
    ctx->out_format = FLB_HTTP_OUT_MSGPACK;
    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        if (strcasecmp(tmp, "msgpack") == 0) {
            ctx->out_format = FLB_HTTP_OUT_MSGPACK;
        }
        else if (strcasecmp(tmp, "json") == 0) {
            ctx->out_format = FLB_HTTP_OUT_JSON;
        }
        else {
            flb_warn("[out_http] unrecognized 'format' option. Using 'msgpack'");
        }
    }

    ctx->u = upstream;
    ctx->uri  = uri;
    ctx->host = ins->host.name;
    ctx->port = ins->host.port;

    /* Set the plugin context */
    flb_output_set_context(ins, ctx);
    return 0;
}

void cb_http_flush(void *data, size_t bytes,
                   char *tag, int tag_len,
                   struct flb_input_instance *i_ins,
                   void *out_context,
                   struct flb_config *config)
{
    int ret;
    int out_ret = FLB_OK;
    size_t b_sent;
    struct flb_out_http_config *ctx = out_context;
    struct flb_upstream *u;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;
    void *body = NULL;
    uint64_t body_len;
    (void) i_ins;

    if (ctx->out_format == FLB_HTTP_OUT_JSON) {
        body = msgpack_to_json(data, bytes, &body_len);
    }
    else {
        body = data;
        body_len = bytes;
    }

    /* Get upstream context and connection */
    u = ctx->u;
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        if (body != data) {
            flb_free(body);
        }
        flb_error("[out_http] no upstream connections available");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        body, body_len,
                        ctx->host, ctx->port,
                        ctx->proxy, 0);

    /* Append headers */
    if (ctx->out_format == FLB_HTTP_OUT_JSON) {
        flb_http_add_header(c,
                            FLB_HTTP_CONTENT_TYPE,
                            sizeof(FLB_HTTP_CONTENT_TYPE) - 1,
                            FLB_HTTP_MIME_JSON,
                            sizeof(FLB_HTTP_MIME_JSON) -1);
    }
    else {
        flb_http_add_header(c,
                            FLB_HTTP_CONTENT_TYPE,
                            sizeof(FLB_HTTP_CONTENT_TYPE) - 1,
                            FLB_HTTP_MIME_MSGPACK,
                            sizeof(FLB_HTTP_MIME_MSGPACK) -1);
    }

    if (ctx->http_user && ctx->http_passwd) {
        flb_http_basic_auth(c, ctx->http_user, ctx->http_passwd);
    }

    ret = flb_http_do(c, &b_sent);
    if (ret == 0) {
        /*
         * Only allow the following HTTP status:
         *
         *  - 200: OK
         *  - 201: Created
         *  - 202: Accepted
         *  - 203: no authorative resp
         *  - 204: No Content
         *  - 205: Reset content
         */
        if (c->resp.status < 200 || c->resp.status > 205) {
            flb_error("[out_http] HTTP STATUS=%i", c->resp.status);
            out_ret = FLB_RETRY;
        }
        else {
            if (c->resp.payload) {
                flb_info("[out_http] HTTP STATUS=%i\n%s",
                         c->resp.status, c->resp.payload);
            }
            else {
                flb_info("[out_http] HTTP STATUS=%i", c->resp.status);
            }
        }
    }
    else {
        flb_error("[out_http] could not flush records (http_do=%i)", ret);
        out_ret = FLB_RETRY;
    }

    flb_http_client_destroy(c);

    /* Release the connection */
    flb_upstream_conn_release(u_conn);

    if (ctx->out_format == FLB_HTTP_OUT_JSON) {
        flb_free(body);
    }

    FLB_OUTPUT_RETURN(out_ret);
}

int cb_http_exit(void *data, struct flb_config *config)
{
    struct flb_out_http_config *ctx = data;

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    flb_free(ctx->http_user);
    flb_free(ctx->http_passwd);
    flb_free(ctx->proxy_host);
    flb_free(ctx->uri);
    flb_free(ctx);

    return 0;
}

/* Plugin reference */
struct flb_output_plugin out_http_plugin = {
    .name           = "http",
    .description    = "HTTP Output",
    .cb_init        = cb_http_init,
    .cb_pre_run     = NULL,
    .cb_flush       = cb_http_flush,
    .cb_exit        = cb_http_exit,
    .flags          = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
