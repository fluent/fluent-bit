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
#include <fluent-bit/flb_sds.h>

#include "azure_blob.h"

static inline int to_encode(char c)
{
    if ((c >= 48 && c <= 57)  ||  /* 0-9 */
        (c >= 65 && c <= 90)  ||  /* A-Z */
        (c >= 97 && c <= 122) ||  /* a-z */
        (c == '?' || c == '&' || c == '-' || c == '_' || c == '.' ||
         c == '~' || c == '/')) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

flb_sds_t azb_uri_encode(const char *uri, size_t len)
{
    int i;
    flb_sds_t buf = NULL;
    flb_sds_t tmp = NULL;

    buf = flb_sds_create_size(len * 2);
    if (!buf) {
        flb_error("[uri] cannot allocate buffer for URI encoding");
        return NULL;
    }

    for (i = 0; i < len; i++) {
        if (to_encode(uri[i]) == FLB_TRUE) {
            tmp = flb_sds_printf(&buf, "%%%02X", (unsigned char) *(uri + i));
            if (!tmp) {
                flb_sds_destroy(buf);
                return NULL;
            }
            continue;
        }

        /* Direct assignment, just copy the character */
        if (buf) {
            tmp = flb_sds_cat(buf, uri + i, 1);
            if (!tmp) {
                flb_sds_destroy(buf);
                return NULL;
            }
            buf = tmp;
        }
    }

    return buf;
}

flb_sds_t azb_uri_decode(const char *uri, size_t len)
{
    int i;
    int hex_result;
    int c = 0;
    char hex[3];
    flb_sds_t out;

    out = flb_sds_create_size(len);
    if (!out) {
        return NULL;
    }

    for (i = 0; i < len; i++) {
        if (uri[i] == '%') {
            hex[0] = uri[i + 1];
            hex[1] = uri[i + 2];
            hex[2] = '\0';

            hex_result = flb_utils_hex2int(hex, 2);
            out[c++] = hex_result;
            i += 2;
        }
        else {
            out[c++] = uri[i];
        }
    }
    out[c++] = '\0';

    return out;
}

flb_sds_t azb_uri_container(struct flb_azure_blob *ctx)
{
    flb_sds_t uri;

    uri = flb_sds_create_size(256);
    if (!uri) {
        return NULL;
    }

    if (flb_sds_printf(&uri, "%s%s", ctx->base_uri, ctx->container_name) == NULL) {
        flb_sds_destroy(uri);
        return NULL;
    }
    return uri;
}

flb_sds_t azb_uri_ensure_or_create_container(struct flb_azure_blob *ctx)
{
    flb_sds_t uri;

    uri = azb_uri_container(ctx);
    if (!uri) {
        return NULL;
    }

    flb_sds_printf(&uri, "?restype=container");
    if (uri == NULL) {
        return NULL;
    }

    if (ctx->atype == AZURE_BLOB_AUTH_SAS && ctx->sas_token) {
        if (flb_sds_printf(&uri, "&%s", ctx->sas_token) == NULL) {
            flb_sds_destroy(uri);
            return NULL;
        }
    }

    return uri;
}

const char *azb_effective_path(struct flb_azure_blob *ctx,
                               const char *path_prefix)
{
    if (!ctx) {
        return path_prefix;
    }

    if (ctx->path_templating_enabled == FLB_TRUE) {
        if (path_prefix == NULL) {
            return ctx->path;
        }
        return azb_commit_prefix_with_fallback(ctx, path_prefix);
    }

    if (path_prefix && path_prefix[0] != '\0') {
        return path_prefix;
    }

    return ctx->path;
}

flb_sds_t azb_uri_create_blob(struct flb_azure_blob *ctx,
                              const char *path_prefix,
                              const char *tag)
{
    flb_sds_t uri;
    const char *effective_path;

    uri = azb_uri_container(ctx);
    if (!uri) {
        return NULL;
    }

    effective_path = azb_effective_path(ctx, path_prefix);

    if (effective_path && effective_path[0] != '\0') {
        if (flb_sds_printf(&uri, "/%s/%s", effective_path, tag) == NULL) {
            flb_sds_destroy(uri);
            return NULL;
        }
    }
    else {
        if (flb_sds_printf(&uri, "/%s", tag) == NULL) {
            flb_sds_destroy(uri);
            return NULL;
        }
    }

    if (ctx->atype == AZURE_BLOB_AUTH_SAS && ctx->sas_token) {
        if (flb_sds_printf(&uri, "?%s", ctx->sas_token) == NULL) {
            flb_sds_destroy(uri);
            return NULL;
        }
    }

    return uri;
}
