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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_aws_credentials.h>

#include "es.h"
#include "es_conf.h"

struct flb_elasticsearch *flb_es_conf_create(struct flb_output_instance *ins,
                                             struct flb_config *config)
{

    int io_flags = 0;
    ssize_t ret;
    const char *tmp;
    const char *path;
#ifdef FLB_HAVE_AWS
    char *aws_role_arn = NULL;
    char *aws_external_id = NULL;
    char *aws_session_name = NULL;
#endif
    struct flb_uri *uri = ins->host.uri;
    struct flb_uri_field *f_index = NULL;
    struct flb_uri_field *f_type = NULL;
    struct flb_upstream *upstream;
    struct flb_elasticsearch *ctx;

    /* Allocate context */
    ctx = flb_calloc(1, sizeof(struct flb_elasticsearch));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    if (uri) {
        if (uri->count >= 2) {
            f_index = flb_uri_get(uri, 0);
            f_type  = flb_uri_get(uri, 1);
        }
    }

    /* Set default network configuration */
    flb_output_net_default("127.0.0.1", 9200, ins);

    /* Populate context with config map defaults and incoming properties */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        flb_es_conf_destroy(ctx);
        return NULL;
    }

    /* use TLS ? */
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Prepare an upstream handler */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   io_flags,
                                   &ins->tls);
    if (!upstream) {
        flb_plg_error(ctx->ins, "cannot create Upstream context");
        flb_es_conf_destroy(ctx);
        return NULL;
    }
    ctx->u = upstream;

    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);

    /* Set manual Index and Type */
    if (f_index) {
        ctx->index = flb_strdup(f_index->value); /* FIXME */
    }

    if (f_type) {
        ctx->type = flb_strdup(f_type->value); /* FIXME */
    }

    /* HTTP Payload (response) maximum buffer size (0 == unlimited) */
    if (ctx->buffer_size == -1) {
        ctx->buffer_size = 0;
    }

    /* Elasticsearch: Path */
    path = flb_output_get_property("path", ins);
    if (!path) {
        path = "";
    }

    /* Elasticsearch: Pipeline */
    tmp = flb_output_get_property("pipeline", ins);
    if (tmp) {
        snprintf(ctx->uri, sizeof(ctx->uri) - 1, "%s/_bulk/?pipeline=%s", path, tmp);
    }
    else {
        snprintf(ctx->uri, sizeof(ctx->uri) - 1, "%s/_bulk", path);
    }

#ifdef FLB_HAVE_AWS
    /* AWS Auth */
    ctx->has_aws_auth = FLB_FALSE;
    tmp = flb_output_get_property("aws_auth", ins);
    if (tmp) {
        if (strncasecmp(tmp, "On", 2) == 0) {
            ctx->has_aws_auth = FLB_TRUE;
            flb_debug("[out_es] Enabled AWS Auth");

            /* AWS provider needs a separate TLS instance */
            ctx->aws_tls.context = flb_tls_context_new(FLB_TRUE,
                                                       ins->tls_debug,
                                                       ins->tls_vhost,
                                                       ins->tls_ca_path,
                                                       ins->tls_ca_file,
                                                       ins->tls_crt_file,
                                                       ins->tls_key_file,
                                                       ins->tls_key_passwd);
            if (!ctx->aws_tls.context) {
                flb_errno();
                flb_es_conf_destroy(ctx);
                return NULL;
            }

            tmp = flb_output_get_property("aws_region", ins);
            if (!tmp) {
                flb_error("[out_es] aws_auth enabled but aws_region not set");
                flb_es_conf_destroy(ctx);
                return NULL;
            }
            ctx->aws_region = (char *) tmp;

            tmp = flb_output_get_property("aws_sts_endpoint", ins);
            if (!tmp) {
                flb_error("[out_es] aws_sts_endpoint not set");
                flb_es_conf_destroy(ctx);
                return NULL;
            }
            ctx->aws_sts_endpoint = (char *) tmp;

            ctx->aws_provider = flb_standard_chain_provider_create(config,
                                                                   &ctx->aws_tls,
                                                                   ctx->aws_region,
                                                                   ctx->aws_sts_endpoint,
                                                                   NULL,
                                                                   flb_aws_client_generator());
            if (!ctx->aws_provider) {
                flb_error("[out_es] Failed to create AWS Credential Provider");
                flb_es_conf_destroy(ctx);
                return NULL;
            }

            tmp = flb_output_get_property("aws_role_arn", ins);
            if (tmp) {
                /* Use the STS Provider */
                ctx->base_aws_provider = ctx->aws_provider;
                aws_role_arn = (char *) tmp;
                aws_external_id = NULL;
                tmp = flb_output_get_property("aws_external_id", ins);
                if (tmp) {
                    aws_external_id = (char *) tmp;
                }

                aws_session_name = flb_sts_session_name();
                if (!aws_session_name) {
                    flb_error("[out_es] Failed to create aws iam role "
                              "session name");
                    flb_es_conf_destroy(ctx);
                    return NULL;
                }

                /* STS provider needs yet another separate TLS instance */
                ctx->aws_sts_tls.context = flb_tls_context_new(FLB_TRUE,
                                                               ins->tls_debug,
                                                               ins->tls_vhost,
                                                               ins->tls_ca_path,
                                                               ins->tls_ca_file,
                                                               ins->tls_crt_file,
                                                               ins->tls_key_file,
                                                               ins->tls_key_passwd);
                if (!ctx->aws_sts_tls.context) {
                    flb_errno();
                    flb_es_conf_destroy(ctx);
                    return NULL;
                }

                ctx->aws_provider = flb_sts_provider_create(config,
                                                            &ctx->aws_sts_tls,
                                                            ctx->
                                                            base_aws_provider,
                                                            aws_external_id,
                                                            aws_role_arn,
                                                            aws_session_name,
                                                            ctx->aws_region,
                                                            ctx->aws_sts_endpoint,
                                                            NULL,
                                                            flb_aws_client_generator());
                /* Session name can be freed once provider is created */
                flb_free(aws_session_name);
                if (!ctx->aws_provider) {
                    flb_error("[out_es] Failed to create AWS STS Credential "
                              "Provider");
                    flb_es_conf_destroy(ctx);
                    return NULL;
                }

            }

            /* initialize credentials in sync mode */
            ctx->aws_provider->provider_vtable->sync(ctx->aws_provider);
            ctx->aws_provider->provider_vtable->init(ctx->aws_provider);
            /* set back to async */
            ctx->aws_provider->provider_vtable->async(ctx->aws_provider);
        }
    }
#endif

    return ctx;
}

int flb_es_conf_destroy(struct flb_elasticsearch *ctx)
{
    if (!ctx) {
        return 0;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

#ifdef FLB_HAVE_AWS
    if (ctx->base_aws_provider) {
        flb_aws_provider_destroy(ctx->base_aws_provider);
    }

    if (ctx->aws_provider) {
        flb_aws_provider_destroy(ctx->aws_provider);
    }

    if (ctx->aws_tls.context) {
        flb_tls_context_destroy(ctx->aws_tls.context);
    }

    if (ctx->aws_sts_tls.context) {
        flb_tls_context_destroy(ctx->aws_sts_tls.context);
    }
#endif

    flb_free(ctx);

    return 0;
}
