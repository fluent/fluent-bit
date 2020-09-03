/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include <mbedtls/base64.h>

#include "azure_blob.h"
#include "azure_blob_conf.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static int set_shared_key(struct flb_azure_blob *ctx)
{
    int s;
    int ret;
    size_t o_len = 0;

    s = flb_sds_len(ctx->shared_key);

    /* buffer for final hex key */
    ctx->decoded_sk = flb_malloc(s * 2);
    if (!ctx->decoded_sk) {
        return -1;
    }

    /* decode base64 */
    ret = mbedtls_base64_decode(ctx->decoded_sk, s * 2,
                                &o_len,
                                (unsigned char *)ctx->shared_key,
                                flb_sds_len(ctx->shared_key));
    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot decode shared_key");
        return -1;
    }

    ctx->decoded_sk_size = o_len;
    return 0;
}

struct flb_azure_blob *flb_azure_blob_conf_create(struct flb_output_instance *ins,
                                                  struct flb_config *config)
{
    int ret;
    int port;
    int io_flags = 0;
    struct flb_azure_blob *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_azure_blob));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    /* Set context */
    flb_output_set_context(ins, ctx);

    /* Load config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        return NULL;
    }

    if (!ctx->container_name) {
        flb_plg_error(ctx->ins, "'container_name' has not been set");
        return NULL;
    }

    /* If the shared key is set decode it */
    if (ctx->shared_key) {
        ret = set_shared_key(ctx);
        if (ret == -1) {
            return NULL;
        }
    }

    /*
     * Setting up the real endpoint:
     *
     * If the user provided a custom endpoint, just parse it. Here we need to
     * discover if a TLS connection is required, just use the protocol prefix.
     */
    if (ctx->endpoint) {
        if (strncmp(ctx->endpoint, "https", 5) == 0) {
            io_flags |= FLB_IO_TLS;
        }
        else {
            io_flags |= FLB_IO_TCP;
        }

        ctx->u = flb_upstream_create_url(config, ctx->endpoint,
                                         io_flags, &ins->tls);
        if (!ctx->u) {
            flb_plg_error(ctx->ins, "invalid endpoint '%s'", ctx->endpoint);
            return NULL;
        }

        ctx->real_endpoint = flb_sds_create(ctx->endpoint);
    }
    else {
        ctx->real_endpoint = flb_sds_create_size(256);
        if (!ctx->real_endpoint) {
            flb_plg_error(ctx->ins, "cannot create endpoint");
            return NULL;
        }
        flb_sds_printf(&ctx->real_endpoint, "%s%s",
                       ctx->account_name,
                       AZURE_ENDPOINT_PREFIX);

        /* use TLS ? */
        if (ins->use_tls == FLB_TRUE) {
            port = 443;
            io_flags = FLB_IO_TLS;
        }
        else {
            port = 80;
            io_flags = FLB_IO_TCP;
        }

        ctx->u = flb_upstream_create(config, ctx->real_endpoint, port, io_flags,
                                     &ins->tls);
        if (!ctx->u) {
            flb_plg_error(ctx->ins, "cannot create upstream for endpoint '%s'",
                          ctx->real_endpoint);
            return NULL;
        }
    }

    /* Compose base uri */
    ctx->base_uri = flb_sds_create_size(256);
    if (!ctx->base_uri) {
        flb_plg_error(ctx->ins, "cannot create base_uri for endpoint '%s'",
                      ctx->real_endpoint);
        return NULL;
    }

    if (ctx->emulator_mode == FLB_TRUE) {
        flb_sds_printf(&ctx->base_uri, "/%s/", ctx->account_name);
    }
    else {
        flb_sds_printf(&ctx->base_uri, "/");
    }

    /* Prepare shared key buffer */
    ctx->shared_key_prefix = flb_sds_create_size(256);
    if (!ctx->shared_key_prefix) {
        flb_plg_error(ctx->ins, "cannot create shared key prefix");
        return NULL;
    }
    flb_sds_printf(&ctx->shared_key_prefix, "SharedKey %s:", ctx->account_name);

    /* Sanitize path: remove any ending slash */
    if (ctx->path) {
        if (ctx->path[flb_sds_len(ctx->path) - 1] == '/') {
            ctx->path[flb_sds_len(ctx->path) - 1] = '\0';
        }
    }

    flb_plg_info(ctx->ins,
                 "account_name=%s, container_name=%s, emulator_mode=%s, endpoint=%s",
                 ctx->account_name, ctx->container_name,
                 ctx->emulator_mode ? "yes": "no", ctx->real_endpoint);
    return ctx;
}

void flb_azure_blob_conf_destroy(struct flb_azure_blob *ctx)
{
    if (ctx->decoded_sk) {
        flb_free(ctx->decoded_sk);
    }

    if (ctx->base_uri) {
        flb_sds_destroy(ctx->base_uri);
    }

    if (ctx->real_endpoint) {
        flb_sds_destroy(ctx->real_endpoint);
    }

    if (ctx->shared_key_prefix) {
        flb_sds_destroy(ctx->shared_key_prefix);
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    flb_free(ctx);
}
