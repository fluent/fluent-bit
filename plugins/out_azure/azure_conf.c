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

#include "azure.h"
#include "azure_conf.h"

#include <mbedtls/base64.h>

struct flb_azure *flb_azure_conf_create(struct flb_output_instance *ins,
                                        struct flb_config *config)
{
    int ret;
    size_t size;
    size_t olen;
    char *tmp;
    char *cid = NULL;
    struct flb_upstream *upstream;
    struct flb_azure *ctx;

    /* Allocate config context */
    ctx = flb_calloc(1, sizeof(struct flb_azure));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* config: 'customer_id' */
    cid = flb_output_get_property("customer_id", ins);
    if (cid) {
        ctx->customer_id = flb_sds_create(cid);
        if (!ctx->customer_id) {
            flb_errno();
            flb_free(ctx);
            return NULL;
        }
    }

    /* config: 'shared_key' */
    tmp = flb_output_get_property("shared_key", ins);
    if (tmp) {
        ctx->shared_key = flb_sds_create(tmp);
    }
    else {
        flb_error("[out_azure] property 'shared_key' is not defined");
        flb_azure_conf_destroy(ctx);
        return NULL;
    }

    /* decode shared key */
    size = flb_sds_len(ctx->shared_key) * 1.2;
    ctx->dec_shared_key = flb_sds_create_size(size);
    if (!ctx->dec_shared_key) {
        flb_errno();
        flb_azure_conf_destroy(ctx);
        return NULL;
    }
    ret = mbedtls_base64_decode((unsigned char *) ctx->dec_shared_key, size,
                                &olen,
                                (unsigned char *) ctx->shared_key,
                                flb_sds_len(ctx->shared_key));
    if (ret != 0) {
        flb_error("[out_azure] error decoding shared_key");
        flb_azure_conf_destroy(ctx);
        return NULL;
    }
    flb_sds_len_set(ctx->dec_shared_key, olen);

    /* config: 'log_type' */
    tmp = flb_output_get_property("log_type", ins);
    if (tmp) {
        ctx->log_type = flb_sds_create(tmp);
    }
    else {
        ctx->log_type = flb_sds_create(FLB_AZURE_LOG_TYPE);
    }
    if (!ctx->log_type) {
        flb_azure_conf_destroy(ctx);
        return NULL;
    }

    /* config: 'time_key' */
    tmp = flb_output_get_property("time_key", ins);
    if (tmp) {
        ctx->time_key = flb_sds_create(tmp);
    }
    else {
        ctx->time_key = flb_sds_create(FLB_AZURE_TIME_KEY);
    }
    if (!ctx->time_key) {
        flb_azure_conf_destroy(ctx);
        return NULL;
    }

    /* Validate hostname given by command line or 'Host' property */
    if (!ins->host.name && !cid) {
        flb_error("[out_azure] property 'customer_id' is not defined");
        flb_free(ctx);
        return NULL;
    }


    /* Lookup customer id from given host name */
    if (!cid) {
        tmp = strchr(ins->host.name, '.');
        if (!tmp) {
            flb_error("[out_azure] invalid hostname");
            flb_free(ctx);
            return NULL;
        }
        else {
            ctx->customer_id = flb_sds_create_len(ins->host.name,
                                                  tmp - ins->host.name);
            if (!ctx->customer_id) {
                flb_errno();
                flb_free(ctx);
                return NULL;
            }
        }
    }

    /* Compose real host */
    ctx->host = flb_sds_create_size(256);
    if (!ctx->host) {
        flb_errno();
        flb_free(ctx);
        return NULL;
    }

    if (!ins->host.name) {
        flb_sds_cat(ctx->host, ctx->customer_id,
                    flb_sds_len(ctx->customer_id));
        flb_sds_cat(ctx->host, FLB_AZURE_HOST, sizeof(FLB_AZURE_HOST) - 1);
    }
    else {
        if (!strstr(ins->host.name, ctx->customer_id)) {
            flb_sds_cat(ctx->host, ctx->customer_id,
                        flb_sds_len(ctx->customer_id));
            if (ins->host.name[0] != '.') {
                flb_sds_cat(ctx->host, ".", 1);
            }
        }
        flb_sds_cat(ctx->host, ins->host.name, strlen(ins->host.name));
    }


    /* TCP Port */
    if (ins->host.port == 0) {
        ctx->port = FLB_AZURE_PORT;
    }
    else {
        ctx->port = ins->host.port;
    }

    /* Prepare an upstream handler */
    upstream = flb_upstream_create(config,
                                   ctx->host,
                                   ctx->port,
                                   FLB_IO_TLS,
                                   &ins->tls);
    if (!upstream) {
        flb_error("[out_azure] cannot create Upstream context");
        flb_azure_conf_destroy(ctx);
        return NULL;
    }
    ctx->u = upstream;

    /* Compose uri */
    ctx->uri = flb_sds_create_size(1024);
    if (!ctx->uri) {
        flb_errno();
        flb_azure_conf_destroy(ctx);
        return NULL;
    }
    flb_sds_cat(ctx->uri, FLB_AZURE_RESOURCE, sizeof(FLB_AZURE_RESOURCE) - 1);
    flb_sds_cat(ctx->uri, FLB_AZURE_API_VERSION,
                sizeof(FLB_AZURE_API_VERSION) - 1);

    flb_info("[out_azure] customer_id='%s' host='%s:%i'",
             ctx->customer_id, ctx->host, ctx->port);

    return ctx;
}


int flb_azure_conf_destroy(struct flb_azure *ctx)
{
    if (!ctx) {
        return -1;
    }

    if (ctx->customer_id) {
        flb_sds_destroy(ctx->customer_id);
    }
    if (ctx->dec_shared_key) {
        flb_sds_destroy(ctx->dec_shared_key);
    }
    if (ctx->shared_key) {
        flb_sds_destroy(ctx->shared_key);
    }
    if (ctx->log_type) {
        flb_sds_destroy(ctx->log_type);
    }
    if (ctx->time_key) {
        flb_sds_destroy(ctx->time_key);
    }
    if (ctx->host) {
        flb_sds_destroy(ctx->host);
    }
    if (ctx->uri) {
        flb_sds_destroy(ctx->uri);
    }
    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }
    flb_free(ctx);

    return 0;
}
