/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_aws_credentials.h>

#include "remote_write.h"
#include "remote_write_conf.h"

static int config_add_labels(struct flb_output_instance *ins,
                             struct prometheus_remote_write_context *ctx)
{
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *k = NULL;
    struct flb_slist_entry *v = NULL;
    struct flb_kv *kv;

    if (!ctx->add_labels || mk_list_size(ctx->add_labels) == 0) {
        return 0;
    }

    /* iterate all 'add_label' definitions */
    flb_config_map_foreach(head, mv, ctx->add_labels) {
        if (mk_list_size(mv->val.list) != 2) {
            flb_plg_error(ins, "'add_label' expects a key and a value, "
                          "e.g: 'add_label version 1.8.0'");
            return -1;
        }

        k = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        v = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        kv = flb_kv_item_create(&ctx->kv_labels, k->str, v->str);
        if (!kv) {
            flb_plg_error(ins, "could not append label %s=%s\n", k->str, v->str);
            return -1;
        }
    }

    return 0;
}

struct prometheus_remote_write_context *flb_prometheus_remote_write_context_create(
    struct flb_output_instance *ins, struct flb_config *config)
{
    int ret;
    int ulen;
    int io_flags = 0;
    char *protocol = NULL;
    char *host = NULL;
    char *port = NULL;
    char *uri = NULL;
    char *tmp_uri = NULL;
    const char *tmp;
    struct flb_upstream *upstream;
    struct prometheus_remote_write_context *ctx = NULL;
#ifdef FLB_HAVE_AWS
    char *aws_role_arn = NULL;
    char *aws_external_id = NULL;
    char *aws_session_name = NULL;
#endif

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct prometheus_remote_write_context));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    mk_list_init(&ctx->kv_labels);

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* Parse 'add_label' */
    ret = config_add_labels(ins, ctx);
    if (ret == -1) {
        return NULL;
    }

    /*
     * Check if a Proxy have been set, if so the Upstream manager will use
     * the Proxy end-point and then we let the HTTP client know about it, so
     * it can adjust the HTTP requests.
     */
    tmp = flb_output_get_property("proxy", ins);
    if (tmp) {
        ret = flb_utils_url_split(tmp, &protocol, &host, &port, &uri);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not parse proxy parameter: '%s'", tmp);
            flb_free(ctx);
            return NULL;
        }

        ctx->proxy_host = host;
        ctx->proxy_port = atoi(port);
        ctx->proxy = tmp;
        flb_free(protocol);
        flb_free(port);
        flb_free(uri);
        uri = NULL;
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
        flb_plg_trace(ctx->ins, "Upstream Proxy=%s:%i",
                      ctx->proxy_host, ctx->proxy_port);
        upstream = flb_upstream_create(config,
                                       ctx->proxy_host,
                                       ctx->proxy_port,
                                       io_flags, ins->tls);
    }
    else {
        upstream = flb_upstream_create(config,
                                       ins->host.name,
                                       ins->host.port,
                                       io_flags, ins->tls);
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
        tmp_uri = flb_malloc(ulen + 2);
        tmp_uri[0] = '/';
        memcpy(tmp_uri + 1, uri, ulen);
        tmp_uri[ulen + 1] = '\0';
        flb_free(uri);
        uri = tmp_uri;
    }

    ctx->u = upstream;
    ctx->uri = uri;
    ctx->host = ins->host.name;
    ctx->port = ins->host.port;

    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);


#ifdef FLB_HAVE_AWS
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
                return NULL;
            }

            tmp = flb_output_get_property("aws_region", ins);
            if (!tmp) {
                flb_error("[out_es] aws_auth enabled but aws_region not set");
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
                                                                   flb_aws_client_generator());
            if (!ctx->aws_provider) {
                flb_error("[out_es] Failed to create AWS Credential Provider");
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
                    flb_plg_error(ctx->ins, "failed to create aws iam role "
                              "session name");
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

void flb_prometheus_remote_write_context_destroy(
    struct prometheus_remote_write_context *ctx)
{
    if (!ctx) {
        return;
    }

    flb_kv_release(&ctx->kv_labels);

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    flb_free(ctx->proxy_host);
    flb_free(ctx->uri);
    flb_free(ctx);
}
