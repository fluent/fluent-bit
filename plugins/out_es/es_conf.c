/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_base64.h>

#include "es.h"
#include "es_conf.h"

/*
 * extract_cloud_host extracts the public hostname
 * of a deployment from a Cloud ID string.
 *
 * The Cloud ID string has the format "<deployment_name>:<base64_info>".
 * Once decoded, the "base64_info" string has the format "<deployment_region>$<elasticsearch_hostname>$<kibana_hostname>"
 * and the function returns "<elasticsearch_hostname>.<deployment_region>" token.
 */
static flb_sds_t extract_cloud_host(struct flb_elasticsearch *ctx,
                                    const char *cloud_id)
{

    char *colon;
    char *region;
    char *host;
    char *port = NULL;
    char buf[256] = {0};
    char cloud_host_buf[256] = {0};
    const char dollar[2] = "$";
    size_t len;
    int ret;

    /* keep only part after first ":" */
    colon = strchr(cloud_id, ':');
    if (colon == NULL) {
        return NULL;
    }
    colon++;

    /* decode base64 */
    ret = flb_base64_decode((unsigned char *)buf, sizeof(buf), &len, (unsigned char *)colon, strlen(colon));
    if (ret) {
        flb_plg_error(ctx->ins, "cannot decode cloud_id");
        return NULL;
    }
    region = strtok(buf, dollar);
    if (region == NULL) {
        return NULL;
    }
    host = strtok(NULL, dollar);
    if (host == NULL) {
        return NULL;
    }

    /*
     * Some cloud id format is "<deployment_region>$<elasticsearch_hostname>:<port>$<kibana_hostname>" .
     *   e.g. https://github.com/elastic/beats/blob/v8.4.1/libbeat/cloudid/cloudid_test.go#L60
     *
     * It means the variable "host" can contains ':' and port number.
     */
    colon = strchr(host, ':');
    if (colon != NULL) {
        /* host contains host number */
        *colon = '\0'; /* remove port number from host */
        port = colon+1;
    }

    strcpy(cloud_host_buf, host);
    strcat(cloud_host_buf, ".");
    strcat(cloud_host_buf, region);
    if (port != NULL) {
        strcat(cloud_host_buf, ":");
        strcat(cloud_host_buf, port);
    }
    return flb_sds_create(cloud_host_buf);
}

/*
 * set_cloud_credentials gets a cloud_auth
 * and sets the context's cloud_user and cloud_passwd.
 * Example:
 *   cloud_auth = elastic:ZXVyb3BxxxxxxZTA1Ng
 *   ---->
 *   cloud_user = elastic
 *   cloud_passwd = ZXVyb3BxxxxxxZTA1Ng
 */
static void set_cloud_credentials(struct flb_elasticsearch *ctx,
                                  const char *cloud_auth)
{
    /* extract strings */
    int items = 0;
    struct mk_list *toks;
    struct mk_list *head;
    struct flb_split_entry *entry;
    toks = flb_utils_split((const char *)cloud_auth, ':', -1);
    mk_list_foreach(head, toks) {
        items++;
        entry = mk_list_entry(head, struct flb_split_entry, _head);
        if (items == 1) {
          ctx->cloud_user = flb_strdup(entry->value);
        }
        if (items == 2) {
          ctx->cloud_passwd = flb_strdup(entry->value);
        }
    }
    flb_utils_split_free(toks);
}

struct flb_elasticsearch *flb_es_conf_create(struct flb_output_instance *ins,
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
    char *cloud_port_char;
    char *cloud_host = NULL;
    int cloud_host_port = 0;
    int cloud_port = FLB_ES_DEFAULT_HTTPS_PORT;
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

    /* handle cloud_id */
    tmp = flb_output_get_property("cloud_id", ins);
    if (tmp) {
        cloud_host = extract_cloud_host(ctx, tmp);
        if (cloud_host == NULL) {
            flb_plg_error(ctx->ins, "cannot extract cloud_host");
            flb_es_conf_destroy(ctx);
            return NULL;
        }
        flb_plg_debug(ctx->ins, "extracted cloud_host: '%s'", cloud_host);

        cloud_port_char = strchr(cloud_host, ':');

	if (cloud_port_char == NULL) {
            flb_plg_debug(ctx->ins, "cloud_host: '%s' does not contain a port: '%s'", cloud_host, cloud_host);
        }
        else {
            cloud_port_char[0] = '\0';
            cloud_port_char = &cloud_port_char[1];
            flb_plg_debug(ctx->ins, "extracted cloud_port_char: '%s'", cloud_port_char);
            cloud_host_port = (int) strtol(cloud_port_char, (char **) NULL, 10);
            flb_plg_debug(ctx->ins, "converted cloud_port_char to port int: '%i'", cloud_host_port);
	}

        if (cloud_host_port == 0) {
            cloud_host_port = cloud_port;
        }

        flb_plg_debug(ctx->ins,
                      "checked whether extracted port was null and set it to "
                      "default https port or not. Outcome: '%i' and cloud_host: '%s'.",
                      cloud_host_port, cloud_host);

        if (ins->host.name != NULL) {
            flb_sds_destroy(ins->host.name);
        }

        ins->host.name = cloud_host;
        ins->host.port = cloud_host_port;
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

    /* handle cloud_auth */
    tmp = flb_output_get_property("cloud_auth", ins);
    if (tmp) {
        set_cloud_credentials(ctx, tmp);
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

    /* Compress (gzip) */
    tmp = flb_output_get_property("compress", ins);
    ctx->compress_gzip = FLB_FALSE;
    if (tmp) {
        if (strcasecmp(tmp, "gzip") == 0) {
            ctx->compress_gzip = FLB_TRUE;
        }
    }

    /* Prepare an upstream handler */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   io_flags,
                                   ins->tls);
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
        if (strcasecmp(ctx->write_operation, FLB_ES_WRITE_OP_INDEX) == 0) {
            ctx->es_action = flb_strdup(FLB_ES_WRITE_OP_INDEX);
        }
        else if (strcasecmp(ctx->write_operation, FLB_ES_WRITE_OP_CREATE) == 0) {
            ctx->es_action = flb_strdup(FLB_ES_WRITE_OP_CREATE);
        }
        else if (strcasecmp(ctx->write_operation, FLB_ES_WRITE_OP_UPDATE) == 0
            || strcasecmp(ctx->write_operation, FLB_ES_WRITE_OP_UPSERT) == 0) {
            ctx->es_action = flb_strdup(FLB_ES_WRITE_OP_UPDATE);
        }
        else {
            flb_plg_error(ins, "wrong Write_Operation (should be one of index, create, update, upsert)");
            flb_es_conf_destroy(ctx);
            return NULL;
        }
        if (strcasecmp(ctx->es_action, FLB_ES_WRITE_OP_UPDATE) == 0
            && !ctx->ra_id_key && ctx->generate_id == FLB_FALSE) {
            flb_plg_error(ins, "Id_Key or Generate_Id must be set when Write_Operation update or upsert");
            flb_es_conf_destroy(ctx);
            return NULL;
        }
    }

    if (ctx->logstash_prefix_key) {
        if (ctx->logstash_prefix_key[0] != '$') {
            len = flb_sds_len(ctx->logstash_prefix_key);
            buf = flb_malloc(len + 2);
            if (!buf) {
                flb_errno();
                flb_es_conf_destroy(ctx);
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
            flb_es_conf_destroy(ctx);
            return NULL;
        }
    }

#ifdef FLB_HAVE_AWS
    /* AWS Auth Unsigned Headers */
    ctx->aws_unsigned_headers = flb_malloc(sizeof(struct mk_list));
    if (ret != 0) {
        flb_es_conf_destroy(ctx);
    }
    flb_slist_create(ctx->aws_unsigned_headers);
    ret = flb_slist_add(ctx->aws_unsigned_headers, "Content-Length");
    if (ret != 0) {
        flb_es_conf_destroy(ctx);
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
                    flb_es_conf_destroy(ctx);
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
                    flb_es_conf_destroy(ctx);
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

int flb_es_conf_destroy(struct flb_elasticsearch *ctx)
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
    if (ctx->es_action) {
        flb_free(ctx->es_action);
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

    flb_free(ctx->cloud_passwd);
    flb_free(ctx->cloud_user);
    flb_free(ctx);

    return 0;
}
