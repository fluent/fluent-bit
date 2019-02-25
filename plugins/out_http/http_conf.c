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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>

#include "http.h"
#include "http_conf.h"

struct flb_out_http *flb_http_conf_create(struct flb_output_instance *ins,
                                          struct flb_config *config)
{
    int ulen;
    int len;
    int io_flags = 0;
    char *uri = NULL;
    char *tmp;
    struct flb_upstream *upstream;
    struct flb_out_http *ctx = NULL;
    struct mk_list *head;
    struct mk_list *split = NULL;
    struct flb_split_entry *sentry;
    struct flb_config_prop *prop;
    struct out_http_header *header;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_out_http));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /*
     * Check if a Proxy have been set, if so the Upstream manager will use
     * the Proxy end-point and then we let the HTTP client know about it, so
     * it can adjust the HTTP requests.
     */
    tmp = flb_output_get_property("proxy", ins);
    if (tmp) {
        /*
         * Here we just want to lookup two things: host and port, we are
         * going to skip validations as most of them are handled by the HTTP
         * Client in a later stage.
         */
        char *p;
        char *addr;

        addr = strstr(tmp, "//");
        if (!addr) {
            flb_free(ctx);
            return NULL;
        }
        addr += 2;              /* get right to the host section */
        if (*addr == '[') {     /* IPv6 */
            p = strchr(addr, ']');
            if (!p) {
                flb_free(ctx);
                return NULL;
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
        flb_output_net_default("127.0.0.1", 80, ins);
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
                                       io_flags, (void *)&ins->tls);
    }
    else {
        upstream = flb_upstream_create(config,
                                       ins->host.name,
                                       ins->host.port,
                                       io_flags, (void *)&ins->tls);
    }

    if (!upstream) {
        flb_free(ctx);
        return NULL;
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

    /* Tag in header */
    tmp = flb_output_get_property("header_tag", ins);
    if (tmp) {
      ctx->header_tag = flb_strdup(tmp);
      ctx->headertag_len = strlen(ctx->header_tag);
      flb_info("[out_http] configure to pass tag in header: %s", ctx->header_tag);
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
        else if (strcasecmp(tmp, "json_stream") == 0) {
            ctx->out_format = FLB_HTTP_OUT_JSON_STREAM;
        }
        else if (strcasecmp(tmp, "json_lines") == 0) {
            ctx->out_format = FLB_HTTP_OUT_JSON_LINES;
        }
        else if (strcasecmp(tmp, "gelf") == 0) {
            ctx->out_format = FLB_HTTP_OUT_GELF;
        }
        else {
            flb_warn("[out_http] unrecognized 'format' option. Using 'msgpack'");
        }
    }

    /* Date format for JSON output */
    ctx->json_date_format = FLB_JSON_DATE_DOUBLE;
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        if (strcasecmp(tmp, "iso8601") == 0) {
            ctx->json_date_format = FLB_JSON_DATE_ISO8601;
        }
        if (strcasecmp(tmp, "epoch") == 0) {
            ctx->json_date_format = FLB_JSON_DATE_EPOCH;
        }
    }

    /* Date key for JSON output */
    tmp = flb_output_get_property("json_date_key", ins);
    ctx->json_date_key = flb_strdup(tmp ? tmp : "date");
    ctx->json_date_key_len = strlen(ctx->json_date_key);

    /* Config Gelf_Timestamp_Key */
    tmp = flb_output_get_property("gelf_timestamp_key", ins);
    if (tmp) {
        ctx->gelf_fields.timestamp_key = flb_sds_create(tmp);
    }

    /* Config Gelf_Host_Key */
    tmp = flb_output_get_property("gelf_host_key", ins);
    if (tmp) {
        ctx->gelf_fields.host_key = flb_sds_create(tmp);
    }

    /* Config Gelf_Short_Message_Key */
    tmp = flb_output_get_property("gelf_short_message_key", ins);
    if (tmp) {
        ctx->gelf_fields.short_message_key = flb_sds_create(tmp);
    }

    /* Config Gelf_Full_Message_Key */
    tmp = flb_output_get_property("gelf_full_message_key", ins);
    if (tmp) {
        ctx->gelf_fields.full_message_key = flb_sds_create(tmp);
    }

    /* Config Gelf_Level_Key */
    tmp = flb_output_get_property("gelf_level_key", ins);
    if (tmp) {
        ctx->gelf_fields.level_key = flb_sds_create(tmp);
    }

    ctx->u = upstream;
    ctx->uri = uri;
    ctx->host = ins->host.name;
    ctx->port = ins->host.port;

    /* Arbitrary HTTP headers to add */
    ctx->headers_cnt = 0;
    mk_list_init(&ctx->headers);

    mk_list_foreach(head, &ins->properties) {
        prop = mk_list_entry(head, struct flb_config_prop, _head);
        split = flb_utils_split(prop->val, ' ', 1);

        if (!split) {
            continue;
        }

        if (strcasecmp(prop->key, "header") == 0) {
            header = flb_malloc(sizeof(struct out_http_header));
            if (!header) {
                flb_errno();
                flb_utils_split_free(split);
                flb_http_conf_destroy(ctx);
                return NULL;
            }

            sentry = mk_list_entry_first(split, struct flb_split_entry,
                                         _head);

            len = strlen(prop->val);
            if (sentry->last_pos == len) {
                /* Missing value */
                flb_error("[out_http] missing header value");
                flb_free(header);
                flb_utils_split_free(split);
                flb_http_conf_destroy(ctx);
                return NULL;
            }

            /* Header Name */
            header->key_len = strlen(sentry->value);
            header->key = flb_strndup(sentry->value, header->key_len);

            /*
             * Header Value: compose using the offset value from
             * the first split entry.
             */
            header->val = flb_strndup(prop->val + sentry->last_pos,
                                      len - sentry->last_pos);
            header->val_len = strlen(header->val);
            mk_list_add(&header->_head, &ctx->headers);

            ctx->headers_cnt++;
        }
        flb_utils_split_free(split);
    }

    return ctx;
}

void flb_http_conf_destroy(struct flb_out_http *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct out_http_header *header;

    if (!ctx) {
        return;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    flb_free(ctx->http_user);
    flb_free(ctx->http_passwd);
    flb_free(ctx->proxy_host);
    flb_free(ctx->uri);
    flb_free(ctx->json_date_key);
    flb_free(ctx->header_tag);

    mk_list_foreach_safe(head, tmp, &ctx->headers) {
        header = mk_list_entry(head, struct out_http_header, _head);
        flb_free(header->key);
        flb_free(header->val);
        mk_list_del(&header->_head);
        flb_free(header);
    }

    flb_sds_destroy(ctx->gelf_fields.timestamp_key);
    flb_sds_destroy(ctx->gelf_fields.host_key);
    flb_sds_destroy(ctx->gelf_fields.short_message_key);
    flb_sds_destroy(ctx->gelf_fields.full_message_key);
    flb_sds_destroy(ctx->gelf_fields.level_key);

    flb_free(ctx);
    ctx = NULL;
}
