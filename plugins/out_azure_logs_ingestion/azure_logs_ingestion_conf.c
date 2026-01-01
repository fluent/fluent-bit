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
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_oauth2.h>

#include "azure_logs_ingestion.h"
#include "azure_logs_ingestion_conf.h"

struct flb_az_li* flb_az_li_ctx_create(struct flb_output_instance *ins,
                                        struct flb_config *config)
{
    int ret;
    struct flb_az_li *ctx;
    (void) ins;
    (void) config;

    /* Allocate a new context object for this output instance */
    ctx = flb_calloc(1, sizeof(struct flb_az_li));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* Set the conext in output_instance so that we can retrieve it later */
    ctx->ins = ins;
    ctx->config = config;
    /* Set context */
    flb_output_set_context(ins, ctx);

    /* Load config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to load configuration");
        return NULL;
    }

    /* config: 'client_id' */
    if (!ctx->client_id) {
        flb_plg_error(ins, "property 'client_id' is not defined");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }
    /* config: 'tenant_id' */
    if (!ctx->tenant_id) {
        flb_plg_error(ins, "property 'tenant_id' is not defined");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }
    /* config: 'client_secret' */
    if (!ctx->client_secret) {
        flb_plg_error(ins, "property 'client_secret' is not defined");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }
    /* config: 'dce_url' */
    if (!ctx->dce_url) {
        flb_plg_error(ins, "property 'dce_url' is not defined");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }
    /* config: 'dcr_id' */
    if (!ctx->dcr_id) {
        flb_plg_error(ins, "property 'dcr_id' is not defined");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }
    /* config: 'table_name' */
    if (!ctx->table_name) {
        flb_plg_error(ins, "property 'table_name' is not defined");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }

    /* Allocate and set auth url */
    ctx->auth_url = flb_sds_create_size(sizeof(FLB_AZ_LI_AUTH_URL_TMPLT) - 1 +
                                        flb_sds_len(ctx->tenant_id));
    if (!ctx->auth_url) {
        flb_errno();
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }
    flb_sds_snprintf(&ctx->auth_url, flb_sds_alloc(ctx->auth_url),
                    FLB_AZ_LI_AUTH_URL_TMPLT, ctx->tenant_id);

    /* Allocate and set dce full url */
    ctx->dce_u_url = flb_sds_create_size(sizeof(FLB_AZ_LI_DCE_URL_TMPLT) - 1 +
                                        flb_sds_len(ctx->dce_url) +
                                        flb_sds_len(ctx->dcr_id) +
                                        flb_sds_len(ctx->table_name));
    if (!ctx->dce_u_url) {
        flb_errno();
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }
    flb_sds_snprintf(&ctx->dce_u_url, flb_sds_alloc(ctx->dce_u_url),
                    FLB_AZ_LI_DCE_URL_TMPLT, ctx->dce_url, 
                    ctx->dcr_id, ctx->table_name);

    /* Initialize the auth mutex */
    pthread_mutex_init(&ctx->token_mutex, NULL);

    /* Create oauth2 context */
    ctx->u_auth = flb_oauth2_create(config, ctx->auth_url,
                                    FLB_AZ_LI_TOKEN_TIMEOUT);
    if (!ctx->u_auth) {
        flb_plg_error(ins, "cannot create oauth2 context");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }

    /* Create upstream context for Log Ingsetion endpoint */
    ctx->u_dce = flb_upstream_create_url(config, ctx->dce_url,
                                        FLB_AZ_LI_TLS_MODE, ins->tls);
    if (!ctx->u_dce) {
        flb_plg_error(ins, "upstream creation failed");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }
    flb_output_upstream_set(ctx->u_dce, ins);

    flb_plg_info(ins, "dce_url='%s', dcr='%s', table='%s', stream='Custom-%s'",
                ctx->dce_url, ctx->dcr_id, ctx->table_name, ctx->table_name);

    return ctx;
}

/* Free the context and created memory */
int flb_az_li_ctx_destroy(struct flb_az_li *ctx)
{
    if (!ctx) {
        return -1;
    }

    if (ctx->auth_url) {
        flb_sds_destroy(ctx->auth_url);
    }

    if (ctx->dce_u_url) {
        flb_sds_destroy(ctx->dce_u_url);
    }

    if (ctx->u_auth) {
        flb_oauth2_destroy(ctx->u_auth);
    }

    if (ctx->u_dce) {
        flb_upstream_destroy(ctx->u_dce);
    }
    flb_free(ctx);

    return 0;
}
