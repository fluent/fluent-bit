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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_http_client.h>

#define free_temporal_buffers()                 \
    if (prot) {                                 \
        flb_free(prot);                         \
    }                                           \
    if (host) {                                 \
        flb_free(host);                         \
    }                                           \
    if (port) {                                 \
        flb_free(port);                         \
    }                                           \
    if (uri) {                                  \
        flb_free(uri);                          \
    }

struct flb_oauth2 *flb_oauth2_create(char *auth_url, int expire_sec)
{
    int ret;
    char *prot = NULL;
    char *host = NULL;
    char *port = NULL;
    char *uri = NULL;
    struct flb_oauth2 *ctx;

    /* allocate context */
    ctx = flb_calloc(1, sizeof(struct flb_oauth2));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* register token url */
    ctx->auth_url = flb_sds_create(auth_url);
    if (!ctx->auth_url) {
        flb_errno();
        flb_free(ctx);
        return NULL;
    }

    /* default payload size to 1kb */
    ctx->payload = flb_sds_create_size(1024);
    if (!ctx->payload) {
        flb_errno();
        flb_oauth2_destroy(ctx);
        return NULL;
    }

    ctx->issued = time(NULL);
    ctx->expires = ctx->issued + expire_sec;

    /* Parse and split URL */
    ret = flb_utils_url_split(auth_url, &prot, &host, &port, &uri);
    if (ret == -1) {
        flb_error("[oauth2] invalid URL: %s", auth_url);
        goto error;
    }

    if (!prot || strcmp(prot, "https") != 0) {
        flb_error("[oauth2] invalid endpoint protocol: %s", auth_url);
        goto error;
    }

    if (!host) {
        flb_error("[oauth2] invalid URL host: %s", auth_url);
        goto error;
    }

    /* Populate context */
    ctx->host = flb_sds_create(host);
    if (!ctx->host) {
        flb_errno();
        goto error;
    }
    if (port) {
        ctx->port = flb_sds_create(port);
    }
    else {
        ctx->port = flb_sds_create(FLB_OAUTH2_PORT);
    }
    if (!ctx->port) {
        flb_errno();
        goto error;
    }
    ctx->uri = flb_sds_create(uri);
    if (!ctx->uri) {
        flb_errno();
        goto error;
    }

    free_temporal_buffers();
    return ctx;

 error:
    free_temporal_buffers();
    flb_oauth2_destroy(ctx);

    return NULL;
}

/* Append a key/value to the request body */
int flb_oauth2_payload_append(struct flb_oauth2 *ctx,
                              char *key_str, int key_len,
                              char *val_str, int val_len)
{
    int size;
    flb_sds_t tmp;

    if (key_len == -1) {
        key_len = strlen(key_str);
    }
    if (val_len == -1) {
        val_len = strlen(val_str);
    }

    /*
     * Make sure we have enough space in the sds buffer, otherwise
     * add more capacity (so further flb_sds_cat calls do not
     * realloc().
     */
    size = key_len + val_len + 2;
    if (flb_sds_avail(ctx->payload) < size) {
        tmp = flb_sds_increase(ctx->payload, size);
        if (!tmp) {
            flb_errno();
            return -1;
        }

        if (tmp != ctx->payload) {
            ctx->payload = tmp;
        }
    }

    if (flb_sds_len(ctx->payload) > 0) {
        flb_sds_cat(ctx->payload, "&", 1);
    }

    /* Append key and value */
    flb_sds_cat(ctx->payload, key_str, key_len);
    flb_sds_cat(ctx->payload, "=", 1);
    flb_sds_cat(ctx->payload, val_str, val_len);

    return 0;
}

void flb_oauth2_destroy(struct flb_oauth2 *ctx)
{
    if (ctx->auth_token) {
        flb_sds_destroy(ctx->auth_token);
    }

    if (ctx->auth_url) {
        flb_sds_destroy(ctx->auth_url);
    }

    if (ctx->payload) {
        flb_sds_destroy(ctx->payload);
    }

    flb_free(ctx);
}

char *flb_oauth2_token_get(struct flb_oauth2 *ctx)
{
    if (ctx->auth_token) {
        return ctx->auth_token;
    }

    /* Get Token and store it in the context */
    return NULL;
}

int flb_oauth2_token_len(struct flb_oauth2 *ctx)
{
    if (!ctx->auth_token) {
        return -1;
    }

    return flb_sds_len(ctx->auth_token);
}
