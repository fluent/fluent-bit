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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_aws_credentials.h>

#include "opensearch.h"
#include "os_conf.h"

struct flb_opensearch *flb_os_conf_create(struct flb_output_instance *ins,
                                          struct flb_config *config)
{
    int len;
    int io_flags = 0;
    ssize_t ret;
    char *buf;
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
    struct flb_opensearch *ctx;

    /* Allocate context */
    ctx = flb_calloc(1, sizeof(struct flb_opensearch));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    /* only used if the config has been set from the command line */
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
        flb_os_conf_destroy(ctx);
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
                                   ins->tls);
    if (!upstream) {
        flb_plg_error(ctx->ins, "cannot create Upstream context");
        flb_os_conf_destroy(ctx);
        return NULL;
    }
    ctx->u = upstream;

    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);

    /* Set manual Index and Type */
    if (f_index) {
        ctx->index = flb_strdup(f_index->value);
    }
    else {
        /* Check if the index has been set in the configuration */
        if (ctx->index) {
            /* do we have a record accessor pattern ? */
            if (strchr(ctx->index, '$') != NULL) {
                ctx->ra_index = flb_ra_create(ctx->index, FLB_TRUE);
                if (!ctx->ra_index) {
                    flb_plg_error(ctx->ins, "invalid record accessor pattern set for 'index' property");
                    flb_os_conf_destroy(ctx);
                    return NULL;
                }
            }
        }
    }

    if(ctx->data_stream_name) {
        if(strchr(ctx->data_stream_name, '$') != NULL) {
            ctx->ra_data_stream = flb_ra_create(ctx->data_stream_name, FLB_TRUE);
            if(!ctx->ra_data_stream) {
                flb_plg_error(ctx->ins, "invalid record accessor pattern set for 'data_stream_name' property");
                flb_os_conf_destroy(ctx);
                return NULL;
            }
        }
    }

    if (f_type) {
        ctx->type = flb_strdup(f_type->value); /* FIXME */
    }

    /* HTTP Payload (response) maximum buffer size (0 == unlimited) */
    if (ctx->buffer_size == -1) {
        ctx->buffer_size = 0;
    }

    /* Path */
    path = flb_output_get_property("path", ins);
    if (!path) {
        path = "";
    }

    /* Pipeline */
    tmp = flb_output_get_property("pipeline", ins);
    if (tmp) {
        snprintf(ctx->uri, sizeof(ctx->uri) - 1, "%s/_bulk/?pipeline=%s", path, tmp);
    }
    else {
        snprintf(ctx->uri, sizeof(ctx->uri) - 1, "%s/_bulk", path);
    }

    snprintf(ctx->template_uri,
             sizeof(ctx->template_uri) - 1,
             "%s/_index_template/%s",
             path, ctx->data_stream_template_name);
    snprintf(ctx->ds_uri,
             sizeof(ctx->ds_uri) - 1,
             "%s/_data_stream/%s",
             path, ctx->data_stream_name);

    if (ctx->id_key) {
        ctx->ra_id_key = flb_ra_create(ctx->id_key, FLB_FALSE);
        if (ctx->ra_id_key == NULL) {
            flb_plg_error(ins, "could not create record accessor for Id Key");
        }
        if (ctx->generate_id == FLB_TRUE) {
            flb_plg_warn(ins, "Generate_ID is ignored when ID_key is set");
            ctx->generate_id = FLB_FALSE;
        }
    }

    if (ctx->write_operation) {
        if (strcasecmp(ctx->write_operation, FLB_OS_WRITE_OP_INDEX) == 0) {
            ctx->action = FLB_OS_WRITE_OP_INDEX;
        }
        else if (strcasecmp(ctx->write_operation, FLB_OS_WRITE_OP_CREATE) == 0) {
            ctx->action = FLB_OS_WRITE_OP_CREATE;
        }
        else if (strcasecmp(ctx->write_operation, FLB_OS_WRITE_OP_UPDATE) == 0
            || strcasecmp(ctx->write_operation, FLB_OS_WRITE_OP_UPSERT) == 0) {
            ctx->action = FLB_OS_WRITE_OP_UPDATE;
        }
        else {
            flb_plg_error(ins,
                          "wrong Write_Operation (should be one of index, "
                          "create, update, upsert)");
            flb_os_conf_destroy(ctx);
            return NULL;
        }

        if (strcasecmp(ctx->action, FLB_OS_WRITE_OP_UPDATE) == 0
            && !ctx->ra_id_key && ctx->generate_id == FLB_FALSE) {
            flb_plg_error(ins,
                          "id_key or generate_id must be set when Write_Operation "
                          "update or upsert");
            flb_os_conf_destroy(ctx);
            return NULL;
        }
    }

    if (ctx->logstash_prefix_key) {
        if (ctx->logstash_prefix_key[0] != '$') {
            len = flb_sds_len(ctx->logstash_prefix_key);
            buf = flb_malloc(len + 2);
            if (!buf) {
                flb_errno();
                flb_os_conf_destroy(ctx);
                return NULL;
            }
            buf[0] = '$';
            memcpy(buf + 1, ctx->logstash_prefix_key, len);
            buf[len + 1] = '\0';

            ctx->ra_prefix_key = flb_ra_create(buf, FLB_TRUE);
            flb_free(buf);
        }
        else {
            ctx->ra_prefix_key = flb_ra_create(ctx->logstash_prefix_key, FLB_TRUE);
        }

        if (!ctx->ra_prefix_key) {
            flb_plg_error(ins, "invalid logstash_prefix_key pattern '%s'", tmp);
            flb_os_conf_destroy(ctx);
            return NULL;
        }
    }

    if (ctx->compression_str) {
        if (strcasecmp(ctx->compression_str, "gzip") == 0) {
            ctx->compression = FLB_OS_COMPRESSION_GZIP;
        }
        else {
            ctx->compression = FLB_OS_COMPRESSION_NONE;
        }
    }
    else {
        ctx->compression = FLB_OS_COMPRESSION_NONE;
    }

#ifdef FLB_HAVE_AWS
    /* AWS Auth Unsigned Headers */
    ctx->aws_unsigned_headers = flb_malloc(sizeof(struct mk_list));
    if (!ctx->aws_unsigned_headers) {
        flb_os_conf_destroy(ctx);
        return NULL;
    }
    flb_slist_create(ctx->aws_unsigned_headers);
    ret = flb_slist_add(ctx->aws_unsigned_headers, "Content-Length");
    if (ret != 0) {
        flb_os_conf_destroy(ctx);
        return NULL;
    }

    /* AWS Auth */
    ctx->has_aws_auth = FLB_FALSE;
    tmp = flb_output_get_property("aws_auth", ins);
    if (tmp) {
        if (strncasecmp(tmp, "On", 2) == 0) {
            ctx->has_aws_auth = FLB_TRUE;
            flb_debug("[out_es] Enabled AWS Auth");

            /* AWS provider needs a separate TLS instance */
            ctx->aws_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                          FLB_TRUE,
                                          ins->tls_debug,
                                          ins->tls_vhost,
                                          ins->tls_ca_path,
                                          ins->tls_ca_file,
                                          ins->tls_crt_file,
                                          ins->tls_key_file,
                                          ins->tls_key_passwd);
            if (!ctx->aws_tls) {
                flb_errno();
                flb_os_conf_destroy(ctx);
                return NULL;
            }

            tmp = flb_output_get_property("aws_region", ins);
            if (!tmp) {
                flb_error("[out_es] aws_auth enabled but aws_region not set");
                flb_os_conf_destroy(ctx);
                return NULL;
            }
            ctx->aws_region = (char *) tmp;

            tmp = flb_output_get_property("aws_sts_endpoint", ins);
            if (tmp) {
                ctx->aws_sts_endpoint = (char *) tmp;
            }

            ctx->aws_provider = flb_standard_chain_provider_create(config,
                                                                   ctx->aws_tls,
                                                                   ctx->aws_region,
                                                                   ctx->aws_sts_endpoint,
                                                                   NULL,
                                                                   flb_aws_client_generator(),
                                                                   ctx->aws_profile);
            if (!ctx->aws_provider) {
                flb_error("[out_es] Failed to create AWS Credential Provider");
                flb_os_conf_destroy(ctx);
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
                    flb_os_conf_destroy(ctx);
                    return NULL;
                }

                /* STS provider needs yet another separate TLS instance */
                ctx->aws_sts_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                                  FLB_TRUE,
                                                  ins->tls_debug,
                                                  ins->tls_vhost,
                                                  ins->tls_ca_path,
                                                  ins->tls_ca_file,
                                                  ins->tls_crt_file,
                                                  ins->tls_key_file,
                                                  ins->tls_key_passwd);
                if (!ctx->aws_sts_tls) {
                    flb_errno();
                    flb_os_conf_destroy(ctx);
                    return NULL;
                }

                ctx->aws_provider = flb_sts_provider_create(config,
                                                            ctx->aws_sts_tls,
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
                    flb_os_conf_destroy(ctx);
                    return NULL;
                }

            }

            /* initialize credentials in sync mode */
            ctx->aws_provider->provider_vtable->sync(ctx->aws_provider);
            ctx->aws_provider->provider_vtable->init(ctx->aws_provider);
            /* set back to async */
            ctx->aws_provider->provider_vtable->async(ctx->aws_provider);
            ctx->aws_provider->provider_vtable->upstream_set(ctx->aws_provider, ctx->ins);
        }
    }
#endif

    return ctx;
}

int flb_os_conf_destroy(struct flb_opensearch *ctx)
{
    if (!ctx) {
        return 0;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }
    if (ctx->ra_id_key) {
        flb_ra_destroy(ctx->ra_id_key);
        ctx->ra_id_key = NULL;
    }

#ifdef FLB_HAVE_AWS
    if (ctx->base_aws_provider) {
        flb_aws_provider_destroy(ctx->base_aws_provider);
    }

    if (ctx->aws_provider) {
        flb_aws_provider_destroy(ctx->aws_provider);
    }

    if (ctx->aws_tls) {
        flb_tls_destroy(ctx->aws_tls);
    }

    if (ctx->aws_sts_tls) {
        flb_tls_destroy(ctx->aws_sts_tls);
    }

    if (ctx->aws_unsigned_headers) {
        flb_slist_destroy(ctx->aws_unsigned_headers);
        flb_free(ctx->aws_unsigned_headers);
    }
#endif

    if (ctx->ra_prefix_key) {
        flb_ra_destroy(ctx->ra_prefix_key);
    }

    if (ctx->ra_index) {
        flb_ra_destroy(ctx->ra_index);
    }

    if (ctx->ra_data_stream != NULL) {
        flb_ra_destroy(ctx->ra_data_stream);
        ctx->ra_data_stream = NULL;
    }

    flb_free(ctx);

    return 0;
}
